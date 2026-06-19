#include "core/services/CaptureImportProcessor.h"

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

[[nodiscard]] bool is_safe_partial_import(const CaptureState& state, const OpenContext* ctx) noexcept {
    return !should_cancel(ctx) && state.summary.packet_count > 0U;
}

template <typename Reader>
void capture_reader_failure(OpenContext* ctx, const Reader& reader) {
    if (ctx != nullptr && reader.last_error().has_details()) {
        ctx->set_failure(reader.last_error());
    }
}

template <typename Reader>
CaptureImportResult import_packets(Reader& reader, CaptureState& state, const CaptureImportProcessor& processor, OpenContext* ctx) {
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

void CaptureImportProcessor::process_packet(const RawPcapPacket& packet, CaptureState& state) const {
    PacketIngestor ingestor {state};

    const auto decoded = decoder_.decode(packet);
    const auto packet_bytes = std::span<const std::uint8_t>(packet.bytes.data(), packet.bytes.size());

    if (decoded.ipv4.has_value()) {
        ingestor.ingest(*decoded.ipv4);
        auto& connection = state.ipv4_connections.get_or_create(make_connection_key(decoded.ipv4->flow_key));
        if (!decoded.ipv4->packet_ref.is_ip_fragmented) {
            connection.apply_hints(hint_service_.detect(packet_bytes, packet.data_link_type, decoded.ipv4->flow_key));
        }
        return;
    }

    if (decoded.ipv6.has_value()) {
        ingestor.ingest(*decoded.ipv6);
        auto& connection = state.ipv6_connections.get_or_create(make_connection_key(decoded.ipv6->flow_key));
        if (!decoded.ipv6->packet_ref.is_ip_fragmented) {
            connection.apply_hints(hint_service_.detect(packet_bytes, packet.data_link_type, decoded.ipv6->flow_key));
        }
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

    return import_packets(reader, state, processor, ctx);
}

CaptureImportResult import_capture_from_reader(PcapNgReader& reader, CaptureState& state, const CaptureImportProcessor& processor, OpenContext* ctx) {
    return import_packets(reader, state, processor, ctx);
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



