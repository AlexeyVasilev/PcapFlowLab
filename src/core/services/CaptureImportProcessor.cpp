#include "core/services/CaptureImportProcessor.h"

#include <algorithm>
#include <span>
#include <string>
#include <system_error>

#include "../../../core/open_context.h"
#include "core/index/CaptureIndex.h"
#include "core/decode/PacketDecodeSupport.h"
#include "core/io/LinkType.h"
#include "core/services/PacketIngestor.h"
#include "core/services/PacketDetailsService.h"

namespace pfl {

namespace {

constexpr std::uint64_t kOpenProgressReportPacketInterval = 1000U;
constexpr std::size_t kMinCapturedLengthForStagedImportBytes = 16U * 1024U;
constexpr std::size_t kInitialImportHeaderPrefixBytes = 192U;
constexpr std::size_t kImportHeaderPrefixGrowthQuantumBytes = 64U;
constexpr std::size_t kMaxAdaptiveImportHeaderPrefixBytes = 4096U;

enum class ImportPrefixDecisionKind : std::uint8_t {
    sufficient,
    need_more,
};

struct ImportPrefixDecision {
    ImportPrefixDecisionKind kind {ImportPrefixDecisionKind::sufficient};
    std::size_t required_bytes {0};
};

[[nodiscard]] ImportPrefixDecision import_prefix_sufficient() noexcept {
    return {};
}

[[nodiscard]] ImportPrefixDecision import_prefix_need_more(const std::size_t required_bytes) noexcept {
    return ImportPrefixDecision {
        .kind = ImportPrefixDecisionKind::need_more,
        .required_bytes = required_bytes,
    };
}

[[nodiscard]] ImportPrefixDecision require_more_bytes_if_prefix_limited(
    const std::size_t available_bytes,
    const std::size_t captured_length,
    const std::size_t required_bytes
) noexcept {
    if (available_bytes < required_bytes && captured_length >= required_bytes) {
        return import_prefix_need_more(required_bytes);
    }

    return import_prefix_sufficient();
}

[[nodiscard]] std::size_t align_up_to_import_growth_quantum(const std::size_t value) noexcept {
    return ((value + kImportHeaderPrefixGrowthQuantumBytes - 1U) / kImportHeaderPrefixGrowthQuantumBytes) *
           kImportHeaderPrefixGrowthQuantumBytes;
}

[[nodiscard]] std::size_t grow_adaptive_import_header_prefix(
    const std::size_t current_prefix_bytes,
    const std::size_t required_bytes
) noexcept {
    const auto aligned_required = align_up_to_import_growth_quantum(required_bytes);
    return std::min(kMaxAdaptiveImportHeaderPrefixBytes, std::max(current_prefix_bytes, aligned_required));
}

[[nodiscard]] std::size_t captured_packet_end(
    const std::size_t nominal_packet_end,
    const std::size_t captured_length
) noexcept {
    return std::min(nominal_packet_end, captured_length);
}

[[nodiscard]] ImportPrefixDecision inspect_ipv6_import_prefix(
    const std::span<const std::uint8_t> packet_bytes,
    const std::size_t captured_length,
    const std::size_t ipv6_offset
) {
    const auto header_decision =
        require_more_bytes_if_prefix_limited(packet_bytes.size(), captured_length, ipv6_offset + detail::kIpv6HeaderSize);
    if (header_decision.kind == ImportPrefixDecisionKind::need_more) {
        return header_decision;
    }

    if (packet_bytes.size() < ipv6_offset + detail::kIpv6HeaderSize) {
        return import_prefix_sufficient();
    }

    if (static_cast<std::uint8_t>(packet_bytes[ipv6_offset] >> 4U) != 6U) {
        return import_prefix_sufficient();
    }

    const auto ipv6_payload_length = static_cast<std::size_t>(detail::read_be16(packet_bytes, ipv6_offset + 4U));
    const auto nominal_packet_end = ipv6_offset + detail::kIpv6HeaderSize + ipv6_payload_length;
    const auto packet_captured_end = captured_packet_end(nominal_packet_end, captured_length);

    auto next_header = packet_bytes[ipv6_offset + 6U];
    auto payload_offset = ipv6_offset + detail::kIpv6HeaderSize;

    for (std::size_t extension_count = 0; extension_count < detail::kMaxIpv6ExtensionHeaders; ++extension_count) {
        if (!detail::is_ipv6_extension_header(next_header)) {
            if (next_header == detail::kIpProtocolTcp) {
                const auto tcp_minimum_decision = require_more_bytes_if_prefix_limited(
                    packet_bytes.size(), packet_captured_end, payload_offset + detail::kTcpMinimumHeaderSize);
                if (tcp_minimum_decision.kind == ImportPrefixDecisionKind::need_more) {
                    return tcp_minimum_decision;
                }

                if (packet_captured_end < payload_offset + detail::kTcpMinimumHeaderSize ||
                    packet_bytes.size() < payload_offset + detail::kTcpMinimumHeaderSize) {
                    return import_prefix_sufficient();
                }

                const auto tcp_header_length =
                    static_cast<std::size_t>((packet_bytes[payload_offset + 12U] >> 4U) * 4U);
                const auto tcp_header_decision =
                    require_more_bytes_if_prefix_limited(packet_bytes.size(), packet_captured_end, payload_offset + tcp_header_length);
                if (tcp_header_decision.kind == ImportPrefixDecisionKind::need_more) {
                    return tcp_header_decision;
                }

                return import_prefix_sufficient();
            }

            if (next_header == detail::kIpProtocolUdp) {
                return require_more_bytes_if_prefix_limited(
                    packet_bytes.size(), packet_captured_end, payload_offset + detail::kUdpHeaderSize);
            }

            if (next_header == detail::kIpProtocolIcmpV6) {
                return require_more_bytes_if_prefix_limited(packet_bytes.size(), packet_captured_end, payload_offset + 2U);
            }

            return import_prefix_sufficient();
        }

        const auto extension_tag_decision =
            require_more_bytes_if_prefix_limited(packet_bytes.size(), packet_captured_end, payload_offset + 2U);
        if (extension_tag_decision.kind == ImportPrefixDecisionKind::need_more) {
            return extension_tag_decision;
        }

        if (packet_captured_end < payload_offset + 2U || packet_bytes.size() < payload_offset + 2U) {
            return import_prefix_sufficient();
        }

        if (next_header == detail::kIpProtocolFragment) {
            const auto fragment_decision =
                require_more_bytes_if_prefix_limited(packet_bytes.size(), packet_captured_end, payload_offset + 8U);
            if (fragment_decision.kind == ImportPrefixDecisionKind::need_more) {
                return fragment_decision;
            }

            return import_prefix_sufficient();
        }

        const auto header_length = (next_header == detail::kIpProtocolAh)
            ? static_cast<std::size_t>(packet_bytes[payload_offset + 1U] + 2U) * 4U
            : static_cast<std::size_t>(packet_bytes[payload_offset + 1U] + 1U) * 8U;
        if (header_length < 8U) {
            return import_prefix_sufficient();
        }

        const auto extension_decision =
            require_more_bytes_if_prefix_limited(packet_bytes.size(), packet_captured_end, payload_offset + header_length);
        if (extension_decision.kind == ImportPrefixDecisionKind::need_more) {
            return extension_decision;
        }

        if (packet_captured_end < payload_offset + header_length || packet_bytes.size() < payload_offset + header_length) {
            return import_prefix_sufficient();
        }

        next_header = packet_bytes[payload_offset];
        payload_offset += header_length;
    }

    return import_prefix_sufficient();
}

[[nodiscard]] ImportPrefixDecision inspect_classic_import_prefix(const RawPcapPacket& packet) {
    const auto packet_bytes = std::span<const std::uint8_t>(packet.bytes.data(), packet.bytes.size());
    const auto available_bytes = packet_bytes.size();
    const auto captured_length = static_cast<std::size_t>(packet.captured_length);

    detail::LinkLayerPayloadView envelope {};
    if (packet.data_link_type == kLinkTypeEthernet) {
        auto decision = require_more_bytes_if_prefix_limited(available_bytes, captured_length, detail::kEthernetHeaderSize);
        if (decision.kind == ImportPrefixDecisionKind::need_more) {
            return decision;
        }
        if (available_bytes < detail::kEthernetHeaderSize) {
            return import_prefix_sufficient();
        }

        envelope.protocol_type = detail::read_be16(packet_bytes, 12U);
        envelope.payload_offset = detail::kEthernetHeaderSize;
        envelope.is_ethernet = true;

        std::size_t vlan_count = 0U;
        while (detail::is_vlan_ether_type(envelope.protocol_type)) {
            if (vlan_count == detail::kMaxVlanTags) {
                return import_prefix_sufficient();
            }

            decision = require_more_bytes_if_prefix_limited(
                available_bytes, captured_length, envelope.payload_offset + detail::kVlanHeaderSize);
            if (decision.kind == ImportPrefixDecisionKind::need_more) {
                return decision;
            }
            if (available_bytes < envelope.payload_offset + detail::kVlanHeaderSize) {
                return import_prefix_sufficient();
            }

            envelope.protocol_type = detail::read_be16(packet_bytes, envelope.payload_offset + 2U);
            envelope.payload_offset += detail::kVlanHeaderSize;
            ++vlan_count;
        }
    } else if (packet.data_link_type == kLinkTypeLinuxSll) {
        const auto decision =
            require_more_bytes_if_prefix_limited(available_bytes, captured_length, detail::kLinuxSllHeaderSize);
        if (decision.kind == ImportPrefixDecisionKind::need_more) {
            return decision;
        }
        if (available_bytes < detail::kLinuxSllHeaderSize) {
            return import_prefix_sufficient();
        }

        envelope.protocol_type = detail::read_be16(packet_bytes, 14U);
        envelope.payload_offset = detail::kLinuxSllHeaderSize;
        envelope.is_linux_cooked = true;
        envelope.cooked_packet_type = detail::read_be16(packet_bytes, 0U);
        envelope.cooked_hardware_type = detail::read_be16(packet_bytes, 2U);
    } else if (packet.data_link_type == kLinkTypeLinuxSll2) {
        const auto decision =
            require_more_bytes_if_prefix_limited(available_bytes, captured_length, detail::kLinuxSll2HeaderSize);
        if (decision.kind == ImportPrefixDecisionKind::need_more) {
            return decision;
        }
        if (available_bytes < detail::kLinuxSll2HeaderSize) {
            return import_prefix_sufficient();
        }

        envelope.protocol_type = detail::read_be16(packet_bytes, 0U);
        envelope.payload_offset = detail::kLinuxSll2HeaderSize;
        envelope.is_linux_cooked = true;
        envelope.cooked_packet_type = packet_bytes[10U];
        envelope.cooked_hardware_type = detail::read_be16(packet_bytes, 8U);
    } else {
        return import_prefix_sufficient();
    }

    auto protocol_type = envelope.protocol_type;
    auto payload_offset = envelope.payload_offset;
    if (detail::is_mpls_ether_type(protocol_type)) {
        for (std::size_t label_index = 0U; label_index < detail::kMaxMplsLabels; ++label_index) {
            const auto label_decision =
                require_more_bytes_if_prefix_limited(available_bytes, captured_length, payload_offset + detail::kMplsLabelSize);
            if (label_decision.kind == ImportPrefixDecisionKind::need_more) {
                return label_decision;
            }
            if (available_bytes < payload_offset + detail::kMplsLabelSize) {
                return import_prefix_sufficient();
            }

            const auto entry = detail::read_be32(packet_bytes, payload_offset);
            payload_offset += detail::kMplsLabelSize;
            const auto bottom_of_stack = ((entry >> 8U) & 0x1U) != 0U;
            if (!bottom_of_stack) {
                continue;
            }

            const auto inner_payload_decision =
                require_more_bytes_if_prefix_limited(available_bytes, captured_length, payload_offset + 1U);
            if (inner_payload_decision.kind == ImportPrefixDecisionKind::need_more) {
                return inner_payload_decision;
            }
            if (available_bytes <= payload_offset) {
                return import_prefix_sufficient();
            }

            const auto version_nibble = static_cast<std::uint8_t>(packet_bytes[payload_offset] >> 4U);
            if (version_nibble == 4U) {
                protocol_type = detail::kEtherTypeIpv4;
                break;
            }
            if (version_nibble == 6U) {
                protocol_type = detail::kEtherTypeIpv6;
                break;
            }

            return import_prefix_sufficient();
        }
    }

    if (protocol_type == detail::kEtherTypeArp) {
        auto decision = require_more_bytes_if_prefix_limited(available_bytes, captured_length, payload_offset + 8U);
        if (decision.kind == ImportPrefixDecisionKind::need_more) {
            return decision;
        }
        if (available_bytes < payload_offset + 8U) {
            return import_prefix_sufficient();
        }

        const auto hardware_size = static_cast<std::size_t>(packet_bytes[payload_offset + 4U]);
        const auto protocol_size = static_cast<std::size_t>(packet_bytes[payload_offset + 5U]);
        const auto arp_length = payload_offset + 8U + (2U * hardware_size) + (2U * protocol_size);
        decision = require_more_bytes_if_prefix_limited(available_bytes, captured_length, arp_length);
        if (decision.kind == ImportPrefixDecisionKind::need_more) {
            return decision;
        }
        return import_prefix_sufficient();
    }

    if (protocol_type == detail::kEtherTypeIpv4) {
        auto decision =
            require_more_bytes_if_prefix_limited(available_bytes, captured_length, payload_offset + detail::kIpv4MinimumHeaderSize);
        if (decision.kind == ImportPrefixDecisionKind::need_more) {
            return decision;
        }
        if (available_bytes < payload_offset + detail::kIpv4MinimumHeaderSize) {
            return import_prefix_sufficient();
        }

        const auto version = static_cast<std::uint8_t>(packet_bytes[payload_offset] >> 4U);
        const auto ihl = static_cast<std::size_t>((packet_bytes[payload_offset] & 0x0FU) * 4U);
        if (version != 4U || ihl < detail::kIpv4MinimumHeaderSize) {
            return import_prefix_sufficient();
        }

        decision = require_more_bytes_if_prefix_limited(available_bytes, captured_length, payload_offset + ihl);
        if (decision.kind == ImportPrefixDecisionKind::need_more) {
            return decision;
        }
        if (available_bytes < payload_offset + ihl) {
            return import_prefix_sufficient();
        }

        const auto total_length = detail::read_be16(packet_bytes, payload_offset + 2U);
        const auto nominal_packet_end =
            (total_length == 0U) ? captured_length : payload_offset + static_cast<std::size_t>(total_length);
        const auto packet_captured_end = captured_packet_end(nominal_packet_end, captured_length);
        if (packet_captured_end < payload_offset + ihl) {
            return import_prefix_sufficient();
        }

        const auto protocol = packet_bytes[payload_offset + 9U];
        const auto transport_offset = payload_offset + ihl;
        const auto flags_fragment = detail::read_be16(packet_bytes, payload_offset + 6U);
        if ((flags_fragment & 0x3FFFU) != 0U) {
            return import_prefix_sufficient();
        }

        if (protocol == detail::kIpProtocolTcp) {
            decision = require_more_bytes_if_prefix_limited(
                available_bytes, packet_captured_end, transport_offset + detail::kTcpMinimumHeaderSize);
            if (decision.kind == ImportPrefixDecisionKind::need_more) {
                return decision;
            }
            if (packet_captured_end < transport_offset + detail::kTcpMinimumHeaderSize ||
                available_bytes < transport_offset + detail::kTcpMinimumHeaderSize) {
                return import_prefix_sufficient();
            }

            const auto tcp_header_length =
                static_cast<std::size_t>((packet_bytes[transport_offset + 12U] >> 4U) * 4U);
            decision = require_more_bytes_if_prefix_limited(
                available_bytes, packet_captured_end, transport_offset + tcp_header_length);
            if (decision.kind == ImportPrefixDecisionKind::need_more) {
                return decision;
            }
            return import_prefix_sufficient();
        }

        if (protocol == detail::kIpProtocolUdp) {
            return require_more_bytes_if_prefix_limited(
                available_bytes, packet_captured_end, transport_offset + detail::kUdpHeaderSize);
        }

        if (protocol == detail::kIpProtocolIcmp) {
            return require_more_bytes_if_prefix_limited(available_bytes, packet_captured_end, transport_offset + 2U);
        }

        if (protocol == detail::kIpProtocolIgmp) {
            return require_more_bytes_if_prefix_limited(
                available_bytes, packet_captured_end, transport_offset + detail::kIgmpMinimumHeaderSize);
        }

        return import_prefix_sufficient();
    }

    if (protocol_type == detail::kEtherTypeIpv6) {
        return inspect_ipv6_import_prefix(packet_bytes, captured_length, payload_offset);
    }

    return import_prefix_sufficient();
}

PacketRef packet_ref_from_raw_packet(const RawPcapPacket& packet) {
    return PacketRef {
        .packet_index = packet.packet_index,
        .byte_offset = packet.data_offset,
        .data_link_type = packet.data_link_type,
        .captured_length = packet.captured_length,
        .original_length = packet.original_length,
        .ts_sec = packet.ts_sec,
        .ts_usec = packet.ts_usec,
    };
}

std::string classify_unrecognized_packet_reason(
    const RawPcapPacket& packet,
    const std::span<const std::uint8_t> packet_bytes
) {
    const auto network = detail::parse_network_payload(packet_bytes, packet.data_link_type);
    if (!network.has_value()) {
        return "Link-layer header truncated";
    }

    if (network->has_mpls) {
        switch (network->mpls.status) {
        case detail::MplsParseStatus::label_truncated:
            return "MPLS label header truncated";
        case detail::MplsParseStatus::bottom_of_stack_not_found:
            return "MPLS bottom-of-stack not found";
        case detail::MplsParseStatus::missing_inner_payload:
            return "Missing MPLS inner payload";
        case detail::MplsParseStatus::unknown_payload:
            return "Unknown MPLS payload";
        default:
            break;
        }
    }

    if (network->protocol_type == detail::kEtherTypeArp) {
        const auto arp_offset = network->payload_offset;
        if (packet_bytes.size() < arp_offset + 8U) {
            return "ARP header truncated";
        }

        const auto hardware_size = packet_bytes[arp_offset + 4U];
        const auto protocol_size = packet_bytes[arp_offset + 5U];
        const auto arp_length = static_cast<std::size_t>(8U + (2U * hardware_size) + (2U * protocol_size));
        if (packet_bytes.size() < arp_offset + arp_length) {
            return "ARP header truncated";
        }

        return "Unsupported or malformed packet";
    }

    if (network->protocol_type == detail::kEtherTypeIpv4) {
        const auto ipv4_offset = network->payload_offset;
        if (packet_bytes.size() < ipv4_offset + detail::kIpv4MinimumHeaderSize) {
            return network->has_mpls ? "Inner IPv4 header truncated" : "IPv4 header truncated";
        }

        const auto ipv4_bounds = detail::parse_ipv4_packet_bounds(packet_bytes, ipv4_offset);
        if (!ipv4_bounds.has_value()) {
            return network->has_mpls ? "Inner IPv4 header truncated" : "Unsupported or malformed packet";
        }

        const auto protocol = packet_bytes[ipv4_offset + 9U];
        const auto transport_offset = ipv4_offset + ipv4_bounds->header_length;
        const auto packet_end = ipv4_bounds->packet_end;
        const auto flags_fragment = detail::read_be16(packet_bytes, ipv4_offset + 6U);
        const bool is_fragmented = (flags_fragment & 0x3FFFU) != 0U;
        if (is_fragmented) {
            return "Could not extract flow key";
        }

        if (protocol == detail::kIpProtocolTcp) {
            if (transport_offset + detail::kTcpMinimumHeaderSize > packet_end ||
                packet_bytes.size() < transport_offset + detail::kTcpMinimumHeaderSize) {
                return network->has_mpls ? "Inner TCP header truncated" : "TCP header truncated";
            }

            const auto tcp_header_length = static_cast<std::size_t>((packet_bytes[transport_offset + 12U] >> 4U) * 4U);
            if (tcp_header_length < detail::kTcpMinimumHeaderSize ||
                transport_offset + tcp_header_length > packet_end ||
                packet_bytes.size() < transport_offset + tcp_header_length) {
                return "Could not extract flow key";
            }

            return "Could not extract flow key";
        }

        if (protocol == detail::kIpProtocolUdp) {
            if (transport_offset + detail::kUdpHeaderSize > packet_end) {
                return "UDP header truncated";
            }

            return detail::parse_udp_payload_bounds(packet_bytes, transport_offset, ipv4_bounds->nominal_packet_end).has_value()
                ? "Could not extract flow key"
                : "Unsupported or malformed packet";
        }

        if (protocol == detail::kIpProtocolIcmp) {
            return packet_bytes.size() < transport_offset + 2U
                ? "Unsupported or malformed packet"
                : "Could not extract flow key";
        }

        if (protocol == detail::kIpProtocolIgmp) {
            if (transport_offset >= packet_end || transport_offset >= packet_bytes.size()) {
                return "Missing IGMP payload";
            }

            const auto igmp = detail::parse_igmp_header(packet_bytes, transport_offset, packet_end);
            if (!igmp.has_value() || igmp->available_length < detail::kIgmpMinimumHeaderSize) {
                return "IGMP header truncated";
            }

            return "Could not extract flow key";
        }

        return "Could not extract flow key";
    }

    if (network->protocol_type == detail::kEtherTypeIpv6) {
        const auto ipv6_offset = network->payload_offset;
        if (packet_bytes.size() < ipv6_offset + detail::kIpv6HeaderSize) {
            return network->has_mpls ? "Inner IPv6 header truncated" : "IPv6 header truncated";
        }

        if (static_cast<std::uint8_t>(packet_bytes[ipv6_offset] >> 4U) != 6U) {
            return "Unsupported or malformed packet";
        }

        const auto ipv6_payload = detail::parse_ipv6_payload(packet_bytes, ipv6_offset);
        if (!ipv6_payload.has_value()) {
            return network->has_mpls ? "Inner IPv6 header truncated" : "Unsupported or malformed packet";
        }

        const auto ipv6_payload_length = static_cast<std::size_t>(detail::read_be16(packet_bytes, ipv6_offset + 4U));
        const auto packet_end = std::min(ipv6_offset + detail::kIpv6HeaderSize + ipv6_payload_length, packet_bytes.size());
        if (ipv6_payload->payload_offset > packet_end) {
            return "Could not extract flow key";
        }

        if (ipv6_payload->has_fragment_header) {
            return "Could not extract flow key";
        }

        if (ipv6_payload->next_header == detail::kIpProtocolTcp) {
            if (ipv6_payload->payload_offset + detail::kTcpMinimumHeaderSize > packet_end ||
                packet_bytes.size() < ipv6_payload->payload_offset + detail::kTcpMinimumHeaderSize) {
                return network->has_mpls ? "Inner TCP header truncated" : "TCP header truncated";
            }

            const auto tcp_header_length =
                static_cast<std::size_t>((packet_bytes[ipv6_payload->payload_offset + 12U] >> 4U) * 4U);
            if (tcp_header_length < detail::kTcpMinimumHeaderSize ||
                ipv6_payload->payload_offset + tcp_header_length > packet_end ||
                packet_bytes.size() < ipv6_payload->payload_offset + tcp_header_length) {
                return "Could not extract flow key";
            }

            return "Could not extract flow key";
        }

        if (ipv6_payload->next_header == detail::kIpProtocolUdp) {
            if (ipv6_payload->payload_offset + detail::kUdpHeaderSize > packet_end) {
                return "UDP header truncated";
            }

            return detail::parse_udp_payload_bounds(
                packet_bytes,
                ipv6_payload->payload_offset,
                ipv6_offset + detail::kIpv6HeaderSize + ipv6_payload_length
            ).has_value()
                ? "Could not extract flow key"
                : "Unsupported or malformed packet";
        }

        if (ipv6_payload->next_header == detail::kIpProtocolIcmpV6) {
            return packet_bytes.size() < ipv6_payload->payload_offset + 2U
                ? "Unsupported or malformed packet"
                : "Could not extract flow key";
        }

        return "Could not extract flow key";
    }

    return "Unsupported or malformed packet";
}

bool ingest_fallback_arp_packet(
    const RawPcapPacket& packet,
    const std::span<const std::uint8_t> packet_bytes,
    CaptureState& state,
    PacketIngestor& ingestor,
    const FlowHintService& hint_service
) {
    PacketDetailsService details_service {};
    const auto details = details_service.decode(packet_bytes, packet_ref_from_raw_packet(packet));
    if (!details.has_value() || !details->has_arp) {
        return false;
    }

    FlowKeyV4 flow_key {
        .protocol = ProtocolId::arp,
    };

    if (details->arp.sender_protocol_address.size() == 4U) {
        flow_key.src_addr =
            (static_cast<std::uint32_t>(details->arp.sender_protocol_address[0]) << 24U) |
            (static_cast<std::uint32_t>(details->arp.sender_protocol_address[1]) << 16U) |
            (static_cast<std::uint32_t>(details->arp.sender_protocol_address[2]) << 8U) |
            static_cast<std::uint32_t>(details->arp.sender_protocol_address[3]);
    }

    if (details->arp.target_protocol_address.size() == 4U) {
        flow_key.dst_addr =
            (static_cast<std::uint32_t>(details->arp.target_protocol_address[0]) << 24U) |
            (static_cast<std::uint32_t>(details->arp.target_protocol_address[1]) << 16U) |
            (static_cast<std::uint32_t>(details->arp.target_protocol_address[2]) << 8U) |
            static_cast<std::uint32_t>(details->arp.target_protocol_address[3]);
    }

    ingestor.ingest(IngestedPacketV4 {
        .flow_key = flow_key,
        .packet_ref = packet_ref_from_raw_packet(packet),
    });

    auto& connection = state.ipv4_connections.get_or_create(make_connection_key(flow_key));
    connection.apply_hints(hint_service.detect(packet_bytes, packet.data_link_type, flow_key));
    return true;
}

void report_open_progress(OpenContext* ctx) {
    if (ctx != nullptr && ctx->on_progress) {
        ctx->on_progress(ctx->progress);
    }
}

[[nodiscard]] bool should_cancel(const OpenContext* ctx) noexcept {
    return ctx != nullptr && ctx->is_cancel_requested();
}

[[nodiscard]] bool requires_full_packet_for_hint_detection(const PacketRef& packet_ref, const ProtocolId protocol) noexcept {
    return (protocol == ProtocolId::tcp || protocol == ProtocolId::udp) && packet_ref.payload_length > 0U;
}

[[nodiscard]] std::optional<std::uint32_t> derive_captured_transport_payload_length_from_prefix(
    const RawPcapPacket& packet,
    const ProtocolId protocol
) {
    if (protocol != ProtocolId::tcp && protocol != ProtocolId::udp) {
        return std::nullopt;
    }

    const auto packet_bytes = std::span<const std::uint8_t>(packet.bytes.data(), packet.bytes.size());
    const auto network = detail::parse_network_payload(packet_bytes, packet.data_link_type);
    if (!network.has_value()) {
        return std::nullopt;
    }

    if (network->protocol_type == detail::kEtherTypeIpv4) {
        const auto ipv4_offset = network->payload_offset;
        const auto ipv4_bounds = detail::parse_ipv4_packet_bounds(packet_bytes, ipv4_offset);
        if (!ipv4_bounds.has_value()) {
            return std::nullopt;
        }

        const auto transport_offset = ipv4_offset + ipv4_bounds->header_length;
        const auto packet_end = std::min(
            ipv4_bounds->nominal_packet_end,
            static_cast<std::size_t>(packet.captured_length));
        if (packet_end < transport_offset) {
            return 0U;
        }

        if (protocol == ProtocolId::tcp) {
            if (packet_bytes.size() < transport_offset + detail::kTcpMinimumHeaderSize) {
                return std::nullopt;
            }

            const auto tcp_header_length =
                static_cast<std::size_t>((packet_bytes[transport_offset + 12U] >> 4U) * 4U);
            if (tcp_header_length < detail::kTcpMinimumHeaderSize ||
                packet_end < transport_offset + tcp_header_length ||
                packet_bytes.size() < transport_offset + tcp_header_length) {
                return std::nullopt;
            }

            return static_cast<std::uint32_t>(packet_end - (transport_offset + tcp_header_length));
        }

        if (packet_bytes.size() < transport_offset + detail::kUdpHeaderSize) {
            return std::nullopt;
        }

        const auto udp_length = static_cast<std::size_t>(detail::read_be16(packet_bytes, transport_offset + 4U));
        if (udp_length < detail::kUdpHeaderSize ||
            transport_offset + udp_length > ipv4_bounds->nominal_packet_end) {
            return std::nullopt;
        }

        const auto payload_offset = transport_offset + detail::kUdpHeaderSize;
        const auto available_payload_length = packet_end > payload_offset ? (packet_end - payload_offset) : 0U;
        return static_cast<std::uint32_t>(std::min(udp_length - detail::kUdpHeaderSize, available_payload_length));
    }

    if (network->protocol_type == detail::kEtherTypeIpv6) {
        const auto ipv6_offset = network->payload_offset;
        if (packet_bytes.size() < ipv6_offset + detail::kIpv6HeaderSize) {
            return std::nullopt;
        }

        if (static_cast<std::uint8_t>(packet_bytes[ipv6_offset] >> 4U) != 6U) {
            return std::nullopt;
        }

        const auto ipv6_payload_length =
            static_cast<std::size_t>(detail::read_be16(packet_bytes, ipv6_offset + 4U));
        const auto payload = detail::parse_ipv6_payload(packet_bytes, ipv6_offset);
        if (!payload.has_value()) {
            return std::nullopt;
        }

        const auto packet_end = std::min(
            ipv6_offset + detail::kIpv6HeaderSize + ipv6_payload_length,
            static_cast<std::size_t>(packet.captured_length));
        if (packet_end < payload->payload_offset) {
            return 0U;
        }

        if (protocol == ProtocolId::tcp) {
            if (packet_bytes.size() < payload->payload_offset + detail::kTcpMinimumHeaderSize) {
                return std::nullopt;
            }

            const auto tcp_header_length =
                static_cast<std::size_t>((packet_bytes[payload->payload_offset + 12U] >> 4U) * 4U);
            if (tcp_header_length < detail::kTcpMinimumHeaderSize ||
                packet_end < payload->payload_offset + tcp_header_length ||
                packet_bytes.size() < payload->payload_offset + tcp_header_length) {
                return std::nullopt;
            }

            return static_cast<std::uint32_t>(packet_end - (payload->payload_offset + tcp_header_length));
        }

        if (packet_bytes.size() < payload->payload_offset + detail::kUdpHeaderSize) {
            return std::nullopt;
        }

        const auto udp_length = static_cast<std::size_t>(detail::read_be16(packet_bytes, payload->payload_offset + 4U));
        if (udp_length < detail::kUdpHeaderSize ||
            payload->payload_offset + udp_length > ipv6_offset + detail::kIpv6HeaderSize + ipv6_payload_length) {
            return std::nullopt;
        }

        const auto payload_offset = payload->payload_offset + detail::kUdpHeaderSize;
        const auto available_payload_length = packet_end > payload_offset ? (packet_end - payload_offset) : 0U;
        return static_cast<std::uint32_t>(std::min(udp_length - detail::kUdpHeaderSize, available_payload_length));
    }

    return std::nullopt;
}

template <typename Connection, typename FlowKey>
void apply_import_hints_if_needed(const RawPcapPacket& packet,
                                  const std::span<const std::uint8_t> packet_bytes,
                                  const PacketRef& packet_ref,
                                  Connection& connection,
                                  const FlowKey& flow_key,
                                  const FlowHintService& hint_service) {
    if (packet_ref.is_ip_fragmented || !connection.should_attempt_hint_detection(packet_ref, flow_key.protocol)) {
        return;
    }

    connection.apply_hints(hint_service.detect(packet_bytes, packet.data_link_type, flow_key));
    connection.note_hint_detection_attempt(packet_ref, flow_key.protocol);
}

[[nodiscard]] bool is_safe_partial_import(const CaptureState& state, const OpenContext* ctx) noexcept {
    return !should_cancel(ctx) && state.summary.packet_count > 0U;
}

template <typename Reader>
void capture_reader_failure(OpenContext* ctx, const Reader& reader) {
    if (ctx != nullptr && reader.last_error().has_details()) {
        ctx->set_failure(reader.last_error());
    }
}

CaptureImportResult import_classic_packets(PcapReader& reader,
                                           CaptureState& state,
                                           const CaptureImportProcessor& processor,
                                           OpenContext* ctx) {
    auto adaptive_header_prefix_bytes = kInitialImportHeaderPrefixBytes;

    while (true) {
        auto packet = reader.read_next_import_packet(
            adaptive_header_prefix_bytes,
            kMinCapturedLengthForStagedImportBytes
        );
        if (!packet.has_value()) {
            break;
        }

        if (should_cancel(ctx)) {
            report_open_progress(ctx);
            return CaptureImportResult::failure;
        }

        if (ctx != nullptr) {
            ++ctx->progress.packets_processed;
            ctx->progress.bytes_processed += packet->captured_length;

            if (ctx->on_progress && (ctx->progress.packets_processed % kOpenProgressReportPacketInterval) == 0U) {
                ctx->on_progress(ctx->progress);
            }
        }

        if (!processor.process_classic_import_packet(reader, *packet, state, adaptive_header_prefix_bytes)) {
            break;
        }

        if (should_cancel(ctx)) {
            report_open_progress(ctx);
            return CaptureImportResult::failure;
        }
    }

    if (ctx != nullptr && ctx->on_progress &&
        (ctx->progress.packets_processed > 0U || ctx->progress.bytes_processed > 0U || ctx->progress.has_total())) {
        ctx->on_progress(ctx->progress);
    }

    if (should_cancel(ctx)) {
        return CaptureImportResult::failure;
    }

    if (reader.has_error()) {
        capture_reader_failure(ctx, reader);
        return is_safe_partial_import(state, ctx)
            ? CaptureImportResult::partial_success_with_warning
            : CaptureImportResult::failure;
    }

    return CaptureImportResult::success;
}

template <typename Reader>
CaptureImportResult import_full_packets(Reader& reader, CaptureState& state, const CaptureImportProcessor& processor, OpenContext* ctx) {
    while (const auto packet = reader.read_next()) {
        if (should_cancel(ctx)) {
            report_open_progress(ctx);
            return CaptureImportResult::failure;
        }

        if (ctx != nullptr) {
            ++ctx->progress.packets_processed;
            ctx->progress.bytes_processed += static_cast<std::uint64_t>(packet->bytes.size());

            if (ctx->on_progress && (ctx->progress.packets_processed % kOpenProgressReportPacketInterval) == 0U) {
                ctx->on_progress(ctx->progress);
            }
        }

        processor.process_packet(*packet, state);

        if (should_cancel(ctx)) {
            report_open_progress(ctx);
            return CaptureImportResult::failure;
        }
    }

    if (ctx != nullptr && ctx->on_progress &&
        (ctx->progress.packets_processed > 0U || ctx->progress.bytes_processed > 0U || ctx->progress.has_total())) {
        ctx->on_progress(ctx->progress);
    }

    if (should_cancel(ctx)) {
        return CaptureImportResult::failure;
    }

    if (reader.has_error()) {
        capture_reader_failure(ctx, reader);
        return is_safe_partial_import(state, ctx)
            ? CaptureImportResult::partial_success_with_warning
            : CaptureImportResult::failure;
    }

    return CaptureImportResult::success;
}

}  // namespace

CaptureImportProcessor::CaptureImportProcessor(const AnalysisSettings settings, const bool enable_quic_initial_sni)
    : hint_service_(settings, enable_quic_initial_sni) {
}

bool CaptureImportProcessor::process_classic_import_packet(PcapReader& reader,
                                                           RawPcapPacket& packet,
                                                           CaptureState& state,
                                                           std::size_t& adaptive_header_prefix_bytes) const {
    const auto finalize_prefix_packet = [&reader, &packet]() {
        return reader.finish_prefix_packet(packet);
    };

    const auto prefix_decision = inspect_classic_import_prefix(packet);
    if (prefix_decision.kind == ImportPrefixDecisionKind::need_more) {
        if (!reader.materialize_packet_bytes(packet)) {
            return false;
        }

        adaptive_header_prefix_bytes =
            grow_adaptive_import_header_prefix(adaptive_header_prefix_bytes, prefix_decision.required_bytes);
        process_packet(packet, state);
        return true;
    }

    PacketIngestor ingestor {state};

    auto decoded = decoder_.decode(packet);
    auto packet_bytes = std::span<const std::uint8_t>(packet.bytes.data(), packet.bytes.size());

    if (decoded.ipv4.has_value()) {
        if (const auto payload_length =
                derive_captured_transport_payload_length_from_prefix(packet, decoded.ipv4->flow_key.protocol);
            payload_length.has_value()) {
            decoded.ipv4->packet_ref.payload_length = *payload_length;
        }

        ingestor.ingest(*decoded.ipv4);
        auto& connection = state.ipv4_connections.get_or_create(make_connection_key(decoded.ipv4->flow_key));
        if (!decoded.ipv4->packet_ref.is_ip_fragmented &&
            connection.should_attempt_hint_detection(decoded.ipv4->packet_ref, decoded.ipv4->flow_key.protocol) &&
            requires_full_packet_for_hint_detection(decoded.ipv4->packet_ref, decoded.ipv4->flow_key.protocol)) {
            if (!reader.materialize_packet_bytes(packet)) {
                return false;
            }

            packet_bytes = std::span<const std::uint8_t>(packet.bytes.data(), packet.bytes.size());
            connection.apply_hints(hint_service_.detect(packet_bytes, packet.data_link_type, decoded.ipv4->flow_key));
            connection.note_hint_detection_attempt(decoded.ipv4->packet_ref, decoded.ipv4->flow_key.protocol);
        } else {
            apply_import_hints_if_needed(
                packet,
                packet_bytes,
                decoded.ipv4->packet_ref,
                connection,
                decoded.ipv4->flow_key,
                hint_service_);
        }
        return finalize_prefix_packet();
    }

    if (decoded.ipv6.has_value()) {
        if (const auto payload_length =
                derive_captured_transport_payload_length_from_prefix(packet, decoded.ipv6->flow_key.protocol);
            payload_length.has_value()) {
            decoded.ipv6->packet_ref.payload_length = *payload_length;
        }

        ingestor.ingest(*decoded.ipv6);
        auto& connection = state.ipv6_connections.get_or_create(make_connection_key(decoded.ipv6->flow_key));
        if (!decoded.ipv6->packet_ref.is_ip_fragmented &&
            connection.should_attempt_hint_detection(decoded.ipv6->packet_ref, decoded.ipv6->flow_key.protocol) &&
            requires_full_packet_for_hint_detection(decoded.ipv6->packet_ref, decoded.ipv6->flow_key.protocol)) {
            if (!reader.materialize_packet_bytes(packet)) {
                return false;
            }

            packet_bytes = std::span<const std::uint8_t>(packet.bytes.data(), packet.bytes.size());
            connection.apply_hints(hint_service_.detect(packet_bytes, packet.data_link_type, decoded.ipv6->flow_key));
            connection.note_hint_detection_attempt(decoded.ipv6->packet_ref, decoded.ipv6->flow_key.protocol);
        } else {
            apply_import_hints_if_needed(
                packet,
                packet_bytes,
                decoded.ipv6->packet_ref,
                connection,
                decoded.ipv6->flow_key,
                hint_service_);
        }
        return finalize_prefix_packet();
    }

    if (packet.bytes.size() < packet.captured_length) {
        if (!reader.materialize_packet_bytes(packet)) {
            return false;
        }

        process_packet(packet, state);
        return true;
    }

    if (!ingest_fallback_arp_packet(packet, packet_bytes, state, ingestor, hint_service_)) {
        state.unrecognized_packets.push_back(UnrecognizedPacketRecord {
            .packet = packet_ref_from_raw_packet(packet),
            .reason_text = classify_unrecognized_packet_reason(packet, packet_bytes),
        });
    }

    return finalize_prefix_packet();
}

void CaptureImportProcessor::process_packet(const RawPcapPacket& packet, CaptureState& state) const {
    PacketIngestor ingestor {state};

    const auto decoded = decoder_.decode(packet);
    const auto packet_bytes = std::span<const std::uint8_t>(packet.bytes.data(), packet.bytes.size());

    if (decoded.ipv4.has_value()) {
        ingestor.ingest(*decoded.ipv4);
        auto& connection = state.ipv4_connections.get_or_create(make_connection_key(decoded.ipv4->flow_key));
        apply_import_hints_if_needed(
            packet,
            packet_bytes,
            decoded.ipv4->packet_ref,
            connection,
            decoded.ipv4->flow_key,
            hint_service_);
        return;
    }

    if (decoded.ipv6.has_value()) {
        ingestor.ingest(*decoded.ipv6);
        auto& connection = state.ipv6_connections.get_or_create(make_connection_key(decoded.ipv6->flow_key));
        apply_import_hints_if_needed(
            packet,
            packet_bytes,
            decoded.ipv6->packet_ref,
            connection,
            decoded.ipv6->flow_key,
            hint_service_);
        return;
    }

    if (!ingest_fallback_arp_packet(packet, packet_bytes, state, ingestor, hint_service_)) {
        state.unrecognized_packets.push_back(UnrecognizedPacketRecord {
            .packet = packet_ref_from_raw_packet(packet),
            .reason_text = classify_unrecognized_packet_reason(packet, packet_bytes),
        });
    }
}

CaptureImportResult import_capture_from_reader(PcapReader& reader, CaptureState& state, const CaptureImportProcessor& processor, OpenContext* ctx) {
    if (!is_supported_capture_link_type(reader.data_link_type())) {
        if (ctx != nullptr) {
            OpenFailureInfo failure {};
            failure.reason = "unsupported capture link type";
            ctx->set_failure(std::move(failure));
        }
        return CaptureImportResult::failure;
    }

    return import_classic_packets(reader, state, processor, ctx);
}

CaptureImportResult import_capture_from_reader(PcapNgReader& reader, CaptureState& state, const CaptureImportProcessor& processor, OpenContext* ctx) {
    return import_full_packets(reader, state, processor, ctx);
}

CaptureImportResult import_capture_from_path(const std::filesystem::path& path, CaptureState& state, const CaptureImportProcessor& processor, OpenContext* ctx) {
    if (ctx != nullptr) {
        ctx->progress = {};
        ctx->clear_failure();
        std::error_code error {};
        const auto size = std::filesystem::file_size(path, error);
        if (!error) {
            ctx->progress.total_bytes = static_cast<std::uint64_t>(size);
        }
    }

    if (should_cancel(ctx)) {
        report_open_progress(ctx);
        return CaptureImportResult::failure;
    }

    switch (detect_capture_source_format(path)) {
    case CaptureSourceFormat::classic_pcap: {
        PcapReader reader {};
        if (!reader.open(path)) {
            capture_reader_failure(ctx, reader);
            return CaptureImportResult::failure;
        }

        return import_capture_from_reader(reader, state, processor, ctx);
    }
    case CaptureSourceFormat::pcapng: {
        PcapNgReader reader {};
        if (!reader.open(path)) {
            capture_reader_failure(ctx, reader);
            return CaptureImportResult::failure;
        }

        return import_capture_from_reader(reader, state, processor, ctx);
    }
    default:
        if (ctx != nullptr) {
            OpenFailureInfo failure {};
            std::error_code exists_error {};
            if (!std::filesystem::exists(path, exists_error) || exists_error) {
                failure.reason = "file access failed";
            } else {
                failure.reason = "unsupported or unreadable capture format";
            }
            ctx->set_failure(std::move(failure));
        }
        return CaptureImportResult::failure;
    }
}

}  // namespace pfl



