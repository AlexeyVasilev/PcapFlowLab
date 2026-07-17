#include "app/session/SelectedFlowPacketSemantics.h"

#include <algorithm>

#include "app/session/CaptureSession.h"
#include "core/decode/PacketDecodeSupport.h"

namespace pfl::session_detail {

namespace {

std::optional<std::uint32_t> derive_transport_payload_length_from_ipv4_packet(
    const std::span<const std::uint8_t> bounded_bytes,
    const PacketRef& packet,
    const std::size_t ipv4_offset
);

std::optional<std::uint32_t> derive_transport_payload_length_from_ipv6_packet(
    const std::span<const std::uint8_t> bounded_bytes,
    const PacketRef& packet,
    const std::size_t ipv6_offset
);

std::optional<std::uint32_t> derive_original_transport_payload_length_from_metadata(
    const std::uint32_t captured_length,
    const std::uint32_t original_length,
    const std::uint32_t captured_transport_payload_length,
    const bool is_ip_fragmented
) {
    if (is_ip_fragmented) {
        return std::nullopt;
    }

    if (captured_length < captured_transport_payload_length || original_length < captured_length) {
        return std::nullopt;
    }

    if (original_length == captured_length) {
        return captured_transport_payload_length;
    }

    if (captured_transport_payload_length == 0U) {
        return std::nullopt;
    }

    const auto transport_payload_offset =
        static_cast<std::size_t>(captured_length) - static_cast<std::size_t>(captured_transport_payload_length);
    if (static_cast<std::size_t>(original_length) < transport_payload_offset) {
        return std::nullopt;
    }

    return static_cast<std::uint32_t>(static_cast<std::size_t>(original_length) - transport_payload_offset);
}

std::optional<std::uint32_t> derive_original_transport_payload_length_from_row_metadata(const PacketRow& row) {
    return derive_original_transport_payload_length_from_metadata(
        row.captured_length,
        row.original_length,
        row.payload_length,
        row.is_ip_fragmented
    );
}

std::optional<std::uint32_t> derive_transport_payload_length_from_ah_payload(
    const std::span<const std::uint8_t> bounded_bytes,
    const PacketRef& packet,
    const std::size_t ah_offset,
    const std::size_t nominal_packet_end
) {
    const auto ah = detail::parse_ah_header(bounded_bytes, ah_offset, nominal_packet_end);
    if (!ah.has_value()) {
        return std::nullopt;
    }

    if (ah->next_header == detail::kIpProtocolTcp) {
        if (ah->payload_offset + detail::kTcpMinimumHeaderSize > bounded_bytes.size()) {
            return std::nullopt;
        }

        const auto tcp_header_length = static_cast<std::size_t>((bounded_bytes[ah->payload_offset + 12U] >> 4U) * 4U);
        if (tcp_header_length < detail::kTcpMinimumHeaderSize ||
            ah->payload_offset + tcp_header_length > bounded_bytes.size() ||
            ah->payload_offset + tcp_header_length > nominal_packet_end) {
            return std::nullopt;
        }

        return static_cast<std::uint32_t>(nominal_packet_end - (ah->payload_offset + tcp_header_length));
    }

    if (ah->next_header == detail::kIpProtocolUdp) {
        if (ah->payload_offset + detail::kUdpHeaderSize > bounded_bytes.size()) {
            return std::nullopt;
        }

        const auto udp_length = static_cast<std::size_t>(detail::read_be16(bounded_bytes, ah->payload_offset + 4U));
        if (udp_length < detail::kUdpHeaderSize || ah->payload_offset + udp_length > nominal_packet_end) {
            return std::nullopt;
        }

        return static_cast<std::uint32_t>(udp_length - detail::kUdpHeaderSize);
    }

    if (ah->next_header == detail::kIpProtocolIpv4Encapsulation) {
        return derive_transport_payload_length_from_ipv4_packet(bounded_bytes, packet, ah->payload_offset);
    }

    if (ah->next_header == detail::kIpProtocolIpv6Encapsulation) {
        return derive_transport_payload_length_from_ipv6_packet(bounded_bytes, packet, ah->payload_offset);
    }

    return std::nullopt;
}

std::optional<std::uint32_t> derive_transport_payload_length_from_gre_payload(
    const std::span<const std::uint8_t> bounded_bytes,
    const PacketRef& packet,
    const std::size_t gre_offset,
    const std::size_t nominal_packet_end,
    const bool allow_eoip
) {
    const auto gre = detail::parse_gre_payload(bounded_bytes, gre_offset, nominal_packet_end, allow_eoip);
    if (!gre.has_value() || !gre->resolved_supported_protocol) {
        return std::nullopt;
    }

    if (gre->resolved_protocol_type == detail::kEtherTypeIpv4) {
        return derive_transport_payload_length_from_ipv4_packet(bounded_bytes, packet, gre->resolved_payload_offset);
    }

    if (gre->resolved_protocol_type == detail::kEtherTypeIpv6) {
        return derive_transport_payload_length_from_ipv6_packet(bounded_bytes, packet, gre->resolved_payload_offset);
    }

    return std::nullopt;
}

std::optional<std::uint32_t> derive_transport_payload_length_from_ipv4_packet(
    const std::span<const std::uint8_t> bounded_bytes,
    const PacketRef& packet,
    const std::size_t ipv4_offset
) {
    const auto ipv4_bounds = detail::parse_ipv4_packet_bounds(bounded_bytes, ipv4_offset);
    if (!ipv4_bounds.has_value()) {
        return std::nullopt;
    }

    const auto flags_fragment = detail::read_be16(bounded_bytes, ipv4_offset + 6U);
    if ((flags_fragment & 0x3FFFU) != 0U) {
        return std::nullopt;
    }

    const auto protocol = bounded_bytes[ipv4_offset + 9U];
    const auto transport_offset = ipv4_offset + ipv4_bounds->header_length;
    if (protocol == detail::kIpProtocolTcp) {
        if (transport_offset + detail::kTcpMinimumHeaderSize > bounded_bytes.size()) {
            return std::nullopt;
        }

        const auto tcp_header_length = static_cast<std::size_t>((bounded_bytes[transport_offset + 12U] >> 4U) * 4U);
        if (tcp_header_length < detail::kTcpMinimumHeaderSize ||
            transport_offset + tcp_header_length > bounded_bytes.size()) {
            return std::nullopt;
        }

        if (!ipv4_bounds->bounds_from_captured_bytes) {
            if (ipv4_bounds->total_length < ipv4_bounds->header_length + tcp_header_length) {
                return std::nullopt;
            }

            return static_cast<std::uint32_t>(
                static_cast<std::size_t>(ipv4_bounds->total_length) - ipv4_bounds->header_length - tcp_header_length
            );
        }

        const auto transport_payload_offset = transport_offset + tcp_header_length;
        if (packet.original_length < transport_payload_offset) {
            return std::nullopt;
        }

        return static_cast<std::uint32_t>(packet.original_length - transport_payload_offset);
    }

    if (protocol == detail::kIpProtocolUdp) {
        if (transport_offset + detail::kUdpHeaderSize > bounded_bytes.size()) {
            return std::nullopt;
        }

        const auto udp_length = static_cast<std::size_t>(detail::read_be16(bounded_bytes, transport_offset + 4U));
        if (udp_length < detail::kUdpHeaderSize) {
            return std::nullopt;
        }

        if (!ipv4_bounds->bounds_from_captured_bytes && transport_offset + udp_length > ipv4_bounds->nominal_packet_end) {
            return std::nullopt;
        }

        return static_cast<std::uint32_t>(udp_length - detail::kUdpHeaderSize);
    }

    if (protocol == detail::kIpProtocolAh) {
        return derive_transport_payload_length_from_ah_payload(
            bounded_bytes,
            packet,
            transport_offset,
            ipv4_bounds->nominal_packet_end
        );
    }

    if (protocol == detail::kIpProtocolGre) {
        return derive_transport_payload_length_from_gre_payload(
            bounded_bytes,
            packet,
            transport_offset,
            ipv4_bounds->nominal_packet_end,
            true
        );
    }

    return std::nullopt;
}

std::optional<std::uint32_t> derive_transport_payload_length_from_ipv6_packet(
    const std::span<const std::uint8_t> bounded_bytes,
    const PacketRef& packet,
    const std::size_t ipv6_offset
) {
    if (bounded_bytes.size() < ipv6_offset + detail::kIpv6HeaderSize) {
        return std::nullopt;
    }

    const auto version = static_cast<std::uint8_t>(bounded_bytes[ipv6_offset] >> 4U);
    if (version != 6U) {
        return std::nullopt;
    }

    const auto ipv6_payload_length = static_cast<std::size_t>(detail::read_be16(bounded_bytes, ipv6_offset + 4U));
    const auto nominal_packet_end = ipv6_offset + detail::kIpv6HeaderSize + ipv6_payload_length;
    const auto payload = detail::parse_ipv6_payload(bounded_bytes, ipv6_offset);
    if (!payload.has_value() || payload->has_fragment_header) {
        return std::nullopt;
    }

    if (const auto ah_payload = detail::parse_ipv6_authentication_payload(bounded_bytes, ipv6_offset);
        ah_payload.has_value() && !ah_payload->has_fragment_header) {
        return derive_transport_payload_length_from_ah_payload(
            bounded_bytes,
            packet,
            ah_payload->ah_offset,
            nominal_packet_end
        );
    }

    if (payload->next_header == detail::kIpProtocolTcp) {
        if (payload->payload_offset + detail::kTcpMinimumHeaderSize > bounded_bytes.size()) {
            return std::nullopt;
        }

        const auto tcp_header_length = static_cast<std::size_t>((bounded_bytes[payload->payload_offset + 12U] >> 4U) * 4U);
        if (tcp_header_length < detail::kTcpMinimumHeaderSize ||
            payload->payload_offset + tcp_header_length > bounded_bytes.size() ||
            payload->payload_offset + tcp_header_length > nominal_packet_end) {
            return std::nullopt;
        }

        return static_cast<std::uint32_t>(nominal_packet_end - (payload->payload_offset + tcp_header_length));
    }

    if (payload->next_header == detail::kIpProtocolUdp) {
        if (payload->payload_offset + detail::kUdpHeaderSize > bounded_bytes.size()) {
            return std::nullopt;
        }

        const auto udp_length = static_cast<std::size_t>(detail::read_be16(bounded_bytes, payload->payload_offset + 4U));
        if (udp_length < detail::kUdpHeaderSize || payload->payload_offset + udp_length > nominal_packet_end) {
            return std::nullopt;
        }

        return static_cast<std::uint32_t>(udp_length - detail::kUdpHeaderSize);
    }

    if (payload->next_header == detail::kIpProtocolIpv4Encapsulation) {
        return derive_transport_payload_length_from_ipv4_packet(bounded_bytes, packet, payload->payload_offset);
    }

    if (payload->next_header == detail::kIpProtocolIpv6Encapsulation) {
        return derive_transport_payload_length_from_ipv6_packet(bounded_bytes, packet, payload->payload_offset);
    }

    if (payload->next_header == detail::kIpProtocolGre) {
        return derive_transport_payload_length_from_gre_payload(
            bounded_bytes,
            packet,
            payload->payload_offset,
            nominal_packet_end,
            false
        );
    }

    return std::nullopt;
}

}  // namespace

std::optional<std::uint32_t> derive_transport_payload_length_from_headers(
    const std::span<const std::uint8_t> packet_bytes,
    const PacketRef& packet
) {
    const auto network = detail::parse_network_payload(packet_bytes, packet.data_link_type);
    if (!network.has_value()) {
        return std::nullopt;
    }
    const auto bounded_bytes = network->bounded_packet_end.has_value()
        ? packet_bytes.first(std::min(*network->bounded_packet_end, packet_bytes.size()))
        : packet_bytes;

    if (network->protocol_type == detail::kEtherTypeIpv4) {
        return derive_transport_payload_length_from_ipv4_packet(bounded_bytes, packet, network->payload_offset);
    }

    if (network->protocol_type == detail::kEtherTypeIpv6) {
        return derive_transport_payload_length_from_ipv6_packet(bounded_bytes, packet, network->payload_offset);
    }

    return std::nullopt;
}

std::optional<std::uint32_t> derive_transport_payload_length_from_headers(
    const CaptureSession& session,
    const PacketRef& packet
) {
    const auto packet_bytes = session.read_packet_data(packet);
    if (packet_bytes.empty()) {
        return std::nullopt;
    }

    return derive_transport_payload_length_from_headers(
        std::span<const std::uint8_t>(packet_bytes.data(), packet_bytes.size()),
        packet
    );
}

void apply_original_transport_payload_lengths(CaptureSession& session, std::vector<PacketRow>& rows) {
    for (auto& row : rows) {
        std::optional<PacketRef> packet {};
        if (!row.is_ip_fragmented) {
            packet = session.find_packet(row.packet_index);
        }

        if (row.original_length == row.captured_length && packet.has_value()) {
            const auto exact_transport_payload_length = derive_transport_payload_length_from_headers(session, *packet);
            if (exact_transport_payload_length.has_value()) {
                row.payload_length = *exact_transport_payload_length;
                continue;
            }
        }

        if (const auto original_transport_payload_length =
                derive_original_transport_payload_length_from_row_metadata(row);
            original_transport_payload_length.has_value()) {
            row.payload_length = *original_transport_payload_length;
            continue;
        }

        if (row.is_ip_fragmented) {
            continue;
        }

        if (!packet.has_value()) {
            continue;
        }

        const auto original_transport_payload_length = derive_transport_payload_length_from_headers(session, *packet);
        if (original_transport_payload_length.has_value()) {
            row.payload_length = *original_transport_payload_length;
        }
    }
}

}  // namespace pfl::session_detail
