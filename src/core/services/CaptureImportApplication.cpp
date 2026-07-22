#include "core/services/CaptureImportApplication.h"

#include <algorithm>
#include <vector>

#include "core/decode/PacketDecodeSupport.h"
#include "core/services/PacketDetailsService.h"

namespace pfl {

namespace {

[[nodiscard]] ProtocolPathId intern_protocol_path_id(CaptureState& state, const ProtocolPathView path) {
    if (path.empty()) {
        return kInvalidProtocolPathId;
    }

    return state.protocol_path_registry.intern(path);
}

[[nodiscard]] bool omit_protocol_layer_from_flow_identity(const LayerKey& layer) noexcept {
    return layer.kind == ProtocolLayerKind::vlan &&
        layer.identifier.kind == ProtocolLayerIdentifierKind::vlan_vid &&
        layer.identifier.value == 0U;
}

[[nodiscard]] std::optional<ProtocolPath> normalize_protocol_path_for_flow_identity(const ProtocolPathView path) {
    std::vector<LayerKey> normalized_layers {};
    normalized_layers.reserve(path.size());
    bool changed = false;
    for (const auto& layer : path) {
        if (omit_protocol_layer_from_flow_identity(layer)) {
            changed = true;
            continue;
        }

        normalized_layers.push_back(layer);
    }

    if (!changed) {
        return std::nullopt;
    }

    return ProtocolPath {std::move(normalized_layers)};
}

}  // namespace

ProtocolPathId intern_protocol_path_id_for_flow_identity(
    CaptureState& state,
    const ProtocolPathBuilder& decoded_protocol_path
) {
    if (decoded_protocol_path.empty() || decoded_protocol_path.overflowed()) {
        return kInvalidProtocolPathId;
    }

    const auto decoded_protocol_path_view = decoded_protocol_path.view();
    const auto normalized_protocol_path = normalize_protocol_path_for_flow_identity(decoded_protocol_path_view);
    if (!normalized_protocol_path.has_value()) {
        return intern_protocol_path_id(state, decoded_protocol_path_view);
    }

    return state.protocol_path_registry.intern(std::move(*normalized_protocol_path));
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
        case detail::MplsParseStatus::pseudowire_control_word_truncated:
            return "MPLS pseudowire control word truncated";
        case detail::MplsParseStatus::inner_ethernet_truncated:
            return "Inner Ethernet header truncated";
        case detail::MplsParseStatus::unknown_inner_ether_type:
            return "Unknown MPLS pseudowire inner EtherType";
        case detail::MplsParseStatus::unknown_payload:
            return "Unknown MPLS payload";
        default:
            break;
        }
    }

    if (network->has_pbb) {
        switch (network->pbb.status) {
        case detail::PbbParseStatus::itag_truncated:
            return "PBB I-TAG truncated";
        case detail::PbbParseStatus::inner_ethernet_truncated:
            return "Inner Ethernet header truncated";
        case detail::PbbParseStatus::unknown_inner_ether_type:
            return "Unknown PBB inner EtherType";
        case detail::PbbParseStatus::unknown_payload:
            return "Unsupported or malformed packet";
        default:
            break;
        }
    }

    if (network->has_macsec) {
        switch (network->macsec.status) {
        case detail::MacsecParseStatus::sectag_truncated:
            return "MACsec SecTAG truncated";
        case detail::MacsecParseStatus::packet_number_truncated:
            return "MACsec packet number truncated";
        case detail::MacsecParseStatus::sci_truncated:
            return "MACsec SCI truncated";
        case detail::MacsecParseStatus::icv_truncated:
            return "MACsec ICV truncated";
        case detail::MacsecParseStatus::complete:
            return "MACsec protected payload not decrypted";
        default:
            break;
        }
    }

    const auto effective_packet_end = network->bounded_packet_end.value_or(packet_bytes.size());
    const auto bounded_packet_bytes = packet_bytes.subspan(0U, std::min(effective_packet_end, packet_bytes.size()));

    if (network->link_layer.is_ieee_802_3) {
        const auto llc_snap = detail::parse_llc_snap_payload(
            bounded_packet_bytes,
            network->link_layer.payload_offset,
            network->link_layer.declared_payload_length
        );

        if (llc_snap.llc_header_truncated) {
            return "LLC header truncated";
        }

        if (llc_snap.has_llc && !llc_snap.has_snap) {
            return "Non-SNAP LLC frame";
        }

        if (llc_snap.snap_header_truncated) {
            return "SNAP header truncated";
        }

        if (llc_snap.has_snap && !detail::is_supported_snap_pid(llc_snap.pid)) {
            return "Unknown SNAP PID";
        }
    }

    if (network->protocol_type == detail::kEtherTypePppoeDiscovery) {
        const auto pppoe_offset = network->payload_offset;
        if (bounded_packet_bytes.size() < pppoe_offset + 6U) {
            return "PPPoE Discovery header truncated";
        }

        switch (bounded_packet_bytes[pppoe_offset + 1U]) {
        case 0x09U:
            return "PPPoE Discovery PADI";
        case 0x07U:
            return "PPPoE Discovery PADO";
        case 0x19U:
            return "PPPoE Discovery PADR";
        case 0x65U:
            return "PPPoE Discovery PADS";
        case 0xA7U:
            return "PPPoE Discovery PADT";
        default:
            return "PPPoE Discovery packet";
        }
    }

    if (network->protocol_type == detail::kEtherTypePppoeSession) {
        const auto pppoe_offset = network->payload_offset;
        if (bounded_packet_bytes.size() < pppoe_offset + 6U) {
            return "PPPoE Session header truncated";
        }

        const auto payload_length = static_cast<std::size_t>(detail::read_be16(bounded_packet_bytes, pppoe_offset + 4U));
        const auto pppoe_payload_offset = pppoe_offset + 6U;
        const auto pppoe_payload_end = std::min(pppoe_payload_offset + payload_length, bounded_packet_bytes.size());
        const auto available_payload_length = bounded_packet_bytes.size() - pppoe_payload_offset;
        if (pppoe_payload_offset + 2U > pppoe_payload_end || bounded_packet_bytes.size() < pppoe_payload_offset + 2U) {
            return "PPP protocol field truncated";
        }

        if (available_payload_length < payload_length) {
            return "Unsupported or malformed packet";
        }

        switch (detail::read_be16(bounded_packet_bytes, pppoe_payload_offset)) {
        case detail::kPppProtocolIpv4:
        case detail::kPppProtocolIpv6:
            return "Unsupported or malformed packet";
        case 0xc021U:
            return "PPP LCP control packet";
        case 0x8021U:
            return "PPP IPCP control packet";
        case 0x8057U:
            return "PPP IPv6CP control packet";
        default:
            return "Unknown PPP protocol";
        }
    }

    if (network->protocol_type == detail::kEtherTypeArp) {
        const auto arp_offset = network->payload_offset;
        if (bounded_packet_bytes.size() < arp_offset + 8U) {
            return "ARP header truncated";
        }

        const auto hardware_size = bounded_packet_bytes[arp_offset + 4U];
        const auto protocol_size = bounded_packet_bytes[arp_offset + 5U];
        const auto arp_length = static_cast<std::size_t>(8U + (2U * hardware_size) + (2U * protocol_size));
        if (bounded_packet_bytes.size() < arp_offset + arp_length) {
            return "ARP header truncated";
        }

        return "Unsupported or malformed packet";
    }

    if (network->protocol_type == detail::kEtherTypeIpv4) {
        const auto ipv4_offset = network->payload_offset;
        if (bounded_packet_bytes.size() < ipv4_offset + detail::kIpv4MinimumHeaderSize) {
            return network->has_mpls ? "Inner IPv4 header truncated" : "IPv4 header truncated";
        }

        const auto ipv4_bounds = detail::parse_ipv4_packet_bounds(bounded_packet_bytes, ipv4_offset);
        if (!ipv4_bounds.has_value()) {
            return network->has_mpls ? "Inner IPv4 header truncated" : "Unsupported or malformed packet";
        }
        if (network->has_pppoe &&
            network->bounded_packet_end.has_value() &&
            ipv4_bounds->nominal_packet_end > bounded_packet_bytes.size()) {
            return "Unsupported or malformed packet";
        }

        const auto protocol = bounded_packet_bytes[ipv4_offset + 9U];
        const auto transport_offset = ipv4_offset + ipv4_bounds->header_length;
        const auto packet_end = ipv4_bounds->packet_end;
        const auto flags_fragment = detail::read_be16(bounded_packet_bytes, ipv4_offset + 6U);
        const bool is_fragmented = (flags_fragment & 0x3FFFU) != 0U;
        if (is_fragmented) {
            return "Could not extract flow key";
        }

        if (protocol == detail::kIpProtocolTcp) {
            if (transport_offset + detail::kTcpMinimumHeaderSize > packet_end ||
                bounded_packet_bytes.size() < transport_offset + detail::kTcpMinimumHeaderSize) {
                return network->has_mpls ? "Inner TCP header truncated" : "TCP header truncated";
            }

            const auto tcp_header_length = static_cast<std::size_t>((bounded_packet_bytes[transport_offset + 12U] >> 4U) * 4U);
            if (tcp_header_length < detail::kTcpMinimumHeaderSize ||
                transport_offset + tcp_header_length > packet_end ||
                bounded_packet_bytes.size() < transport_offset + tcp_header_length) {
                return "Could not extract flow key";
            }

            return "Could not extract flow key";
        }

        if (protocol == detail::kIpProtocolUdp) {
            if (transport_offset + detail::kUdpHeaderSize > packet_end) {
                return "UDP header truncated";
            }

            return detail::parse_udp_payload_bounds(bounded_packet_bytes, transport_offset, ipv4_bounds->nominal_packet_end).has_value()
                ? "Could not extract flow key"
                : "Unsupported or malformed packet";
        }

        if (protocol == detail::kIpProtocolIcmp) {
            return bounded_packet_bytes.size() < transport_offset + 2U
                ? "Unsupported or malformed packet"
                : "Could not extract flow key";
        }

        if (protocol == detail::kIpProtocolIgmp) {
            if (transport_offset >= packet_end || transport_offset >= bounded_packet_bytes.size()) {
                return "Missing IGMP payload";
            }

            const auto igmp = detail::parse_igmp_header(bounded_packet_bytes, transport_offset, packet_end);
            if (!igmp.has_value() || igmp->available_length < detail::kIgmpMinimumHeaderSize) {
                return "IGMP header truncated";
            }

            return "Could not extract flow key";
        }

        return "Could not extract flow key";
    }

    if (network->protocol_type == detail::kEtherTypeIpv6) {
        const auto ipv6_offset = network->payload_offset;
        if (bounded_packet_bytes.size() < ipv6_offset + detail::kIpv6HeaderSize) {
            return network->has_mpls ? "Inner IPv6 header truncated" : "IPv6 header truncated";
        }

        if (static_cast<std::uint8_t>(bounded_packet_bytes[ipv6_offset] >> 4U) != 6U) {
            return "Unsupported or malformed packet";
        }

        const auto ipv6_payload = detail::parse_ipv6_payload(bounded_packet_bytes, ipv6_offset);
        if (!ipv6_payload.has_value()) {
            return network->has_mpls ? "Inner IPv6 header truncated" : "Unsupported or malformed packet";
        }

        const auto ipv6_payload_length = static_cast<std::size_t>(detail::read_be16(bounded_packet_bytes, ipv6_offset + 4U));
        const auto packet_end = std::min(ipv6_offset + detail::kIpv6HeaderSize + ipv6_payload_length, bounded_packet_bytes.size());
        if (network->has_pppoe &&
            network->bounded_packet_end.has_value() &&
            ipv6_offset + detail::kIpv6HeaderSize + ipv6_payload_length > bounded_packet_bytes.size()) {
            return "Unsupported or malformed packet";
        }
        if (ipv6_payload->payload_offset > packet_end) {
            return "Could not extract flow key";
        }

        if (ipv6_payload->has_fragment_header) {
            return "Could not extract flow key";
        }

        if (ipv6_payload->next_header == detail::kIpProtocolTcp) {
            if (ipv6_payload->payload_offset + detail::kTcpMinimumHeaderSize > packet_end ||
                bounded_packet_bytes.size() < ipv6_payload->payload_offset + detail::kTcpMinimumHeaderSize) {
                return network->has_mpls ? "Inner TCP header truncated" : "TCP header truncated";
            }

            const auto tcp_header_length =
                static_cast<std::size_t>((bounded_packet_bytes[ipv6_payload->payload_offset + 12U] >> 4U) * 4U);
            if (tcp_header_length < detail::kTcpMinimumHeaderSize ||
                ipv6_payload->payload_offset + tcp_header_length > packet_end ||
                bounded_packet_bytes.size() < ipv6_payload->payload_offset + tcp_header_length) {
                return "Could not extract flow key";
            }

            return "Could not extract flow key";
        }

        if (ipv6_payload->next_header == detail::kIpProtocolUdp) {
            if (ipv6_payload->payload_offset + detail::kUdpHeaderSize > packet_end) {
                return "UDP header truncated";
            }

            return detail::parse_udp_payload_bounds(
                       bounded_packet_bytes,
                       ipv6_payload->payload_offset,
                       ipv6_offset + detail::kIpv6HeaderSize + ipv6_payload_length
                   ).has_value()
                ? "Could not extract flow key"
                : "Unsupported or malformed packet";
        }

        if (ipv6_payload->next_header == detail::kIpProtocolIcmpV6) {
            return bounded_packet_bytes.size() < ipv6_payload->payload_offset + 2U
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

    auto& connection = ingestor.ingest(IngestedPacketV4 {
        .flow_key = flow_key,
        .packet_ref = packet_ref_from_raw_packet(packet),
    });
    connection.apply_hints(hint_service.detect(packet_bytes, packet.data_link_type, flow_key));
    return true;
}

bool requires_full_packet_for_hint_detection(const PacketRef& packet_ref, const ProtocolId protocol) noexcept {
    return (protocol == ProtocolId::tcp || protocol == ProtocolId::udp) && packet_ref.payload_length > 0U;
}

std::optional<std::uint32_t> derive_captured_transport_payload_length_from_prefix(
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
    const auto bounded_bytes = network->bounded_packet_end.has_value()
        ? packet_bytes.first(std::min(*network->bounded_packet_end, packet_bytes.size()))
        : packet_bytes;

    if (network->protocol_type == detail::kEtherTypeIpv4) {
        const auto ipv4_offset = network->payload_offset;
        const auto ipv4_bounds = detail::parse_ipv4_packet_bounds(bounded_bytes, ipv4_offset);
        if (!ipv4_bounds.has_value()) {
            return std::nullopt;
        }

        const auto outer_protocol = bounded_bytes[ipv4_offset + 9U];
        if ((protocol == ProtocolId::tcp && outer_protocol != detail::kIpProtocolTcp) ||
            (protocol == ProtocolId::udp && outer_protocol != detail::kIpProtocolUdp)) {
            return std::nullopt;
        }

        const auto transport_offset = ipv4_offset + ipv4_bounds->header_length;
        auto packet_end = std::min(
            ipv4_bounds->nominal_packet_end,
            static_cast<std::size_t>(packet.captured_length));
        if (network->bounded_packet_end.has_value()) {
            packet_end = std::min(packet_end, *network->bounded_packet_end);
        }
        if (packet_end < transport_offset) {
            return 0U;
        }

        if (protocol == ProtocolId::tcp) {
            if (bounded_bytes.size() < transport_offset + detail::kTcpMinimumHeaderSize) {
                return std::nullopt;
            }

            const auto tcp_header_length =
                static_cast<std::size_t>((bounded_bytes[transport_offset + 12U] >> 4U) * 4U);
            if (tcp_header_length < detail::kTcpMinimumHeaderSize ||
                packet_end < transport_offset + tcp_header_length ||
                bounded_bytes.size() < transport_offset + tcp_header_length) {
                return std::nullopt;
            }

            return static_cast<std::uint32_t>(packet_end - (transport_offset + tcp_header_length));
        }

        if (bounded_bytes.size() < transport_offset + detail::kUdpHeaderSize) {
            return std::nullopt;
        }

        const auto udp_length = static_cast<std::size_t>(detail::read_be16(bounded_bytes, transport_offset + 4U));
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
        if (bounded_bytes.size() < ipv6_offset + detail::kIpv6HeaderSize) {
            return std::nullopt;
        }

        if (static_cast<std::uint8_t>(bounded_bytes[ipv6_offset] >> 4U) != 6U) {
            return std::nullopt;
        }

        const auto ipv6_payload_length =
            static_cast<std::size_t>(detail::read_be16(bounded_bytes, ipv6_offset + 4U));
        const auto payload = detail::parse_ipv6_payload(bounded_bytes, ipv6_offset);
        if (!payload.has_value()) {
            return std::nullopt;
        }

        if ((protocol == ProtocolId::tcp && payload->next_header != detail::kIpProtocolTcp) ||
            (protocol == ProtocolId::udp && payload->next_header != detail::kIpProtocolUdp)) {
            return std::nullopt;
        }

        auto packet_end = std::min(
            ipv6_offset + detail::kIpv6HeaderSize + ipv6_payload_length,
            static_cast<std::size_t>(packet.captured_length));
        if (network->bounded_packet_end.has_value()) {
            packet_end = std::min(packet_end, *network->bounded_packet_end);
        }
        if (packet_end < payload->payload_offset) {
            return 0U;
        }

        if (protocol == ProtocolId::tcp) {
            if (bounded_bytes.size() < payload->payload_offset + detail::kTcpMinimumHeaderSize) {
                return std::nullopt;
            }

            const auto tcp_header_length =
                static_cast<std::size_t>((bounded_bytes[payload->payload_offset + 12U] >> 4U) * 4U);
            if (tcp_header_length < detail::kTcpMinimumHeaderSize ||
                packet_end < payload->payload_offset + tcp_header_length ||
                bounded_bytes.size() < payload->payload_offset + tcp_header_length) {
                return std::nullopt;
            }

            return static_cast<std::uint32_t>(packet_end - (payload->payload_offset + tcp_header_length));
        }

        if (bounded_bytes.size() < payload->payload_offset + detail::kUdpHeaderSize) {
            return std::nullopt;
        }

        const auto udp_length = static_cast<std::size_t>(detail::read_be16(bounded_bytes, payload->payload_offset + 4U));
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

void apply_decoded_packet_import(
    const RawPcapPacket& packet,
    DecodedPacket& decoded,
    CaptureState& state,
    const FlowHintService& hint_service
) {
    PacketIngestor ingestor {state};
    const auto packet_bytes = std::span<const std::uint8_t>(packet.bytes.data(), packet.bytes.size());

    if (decoded.ipv4.has_value()) {
        auto packet_ref = packet_ref_from_raw_packet(packet);
        packet_ref.payload_length = decoded.ipv4->packet_ref.payload_length;
        packet_ref.tcp_flags = decoded.ipv4->packet_ref.tcp_flags;
        packet_ref.is_ip_fragmented = decoded.ipv4->packet_ref.is_ip_fragmented;
        decoded.ipv4->packet_ref = packet_ref;
        decoded.ipv4->flow_key.protocol_path_id =
            intern_protocol_path_id_for_flow_identity(state, decoded.protocol_path_builder);
        auto& connection = ingestor.ingest(*decoded.ipv4);
        apply_import_hints_if_needed(
            packet,
            packet_bytes,
            decoded.ipv4->packet_ref,
            connection,
            decoded.ipv4->flow_key,
            hint_service
        );
        return;
    }

    if (decoded.ipv6.has_value()) {
        auto packet_ref = packet_ref_from_raw_packet(packet);
        packet_ref.payload_length = decoded.ipv6->packet_ref.payload_length;
        packet_ref.tcp_flags = decoded.ipv6->packet_ref.tcp_flags;
        packet_ref.is_ip_fragmented = decoded.ipv6->packet_ref.is_ip_fragmented;
        decoded.ipv6->packet_ref = packet_ref;
        decoded.ipv6->flow_key.protocol_path_id =
            intern_protocol_path_id_for_flow_identity(state, decoded.protocol_path_builder);
        auto& connection = ingestor.ingest(*decoded.ipv6);
        apply_import_hints_if_needed(
            packet,
            packet_bytes,
            decoded.ipv6->packet_ref,
            connection,
            decoded.ipv6->flow_key,
            hint_service
        );
    }
}

void apply_unrecognized_packet_import(
    const RawPcapPacket& packet,
    const std::span<const std::uint8_t> packet_bytes,
    CaptureState& state,
    const FlowHintService& hint_service
) {
    PacketIngestor ingestor {state};
    if (!ingest_fallback_arp_packet(packet, packet_bytes, ingestor, hint_service)) {
        state.unrecognized_packets.push_back(UnrecognizedPacketRecord {
            .packet = packet_ref_from_raw_packet(packet),
            .reason_text = classify_unrecognized_packet_reason(packet, packet_bytes),
        });
    }
}

}  // namespace pfl
