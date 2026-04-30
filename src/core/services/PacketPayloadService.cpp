#include "core/services/PacketPayloadService.h"

#include <optional>
#include <span>

#include "core/decode/PacketDecodeSupport.h"
#include "core/io/LinkType.h"

namespace pfl {

namespace {

std::vector<std::uint8_t> copy_payload(std::span<const std::uint8_t> bytes, const std::size_t offset, const std::size_t length) {
    if (length == 0U) {
        return {};
    }

    const auto begin = bytes.begin() + static_cast<std::ptrdiff_t>(offset);
    const auto end = begin + static_cast<std::ptrdiff_t>(length);
    return std::vector<std::uint8_t>(begin, end);
}

}  // namespace

std::vector<std::uint8_t> PacketPayloadService::extract_transport_payload(std::span<const std::uint8_t> packet_bytes) const {
    return extract_transport_payload(packet_bytes, kLinkTypeEthernet);
}

std::vector<std::uint8_t> PacketPayloadService::extract_transport_payload(std::span<const std::uint8_t> packet_bytes,
                                                                          const std::uint32_t data_link_type) const {
    const auto envelope = detail::parse_link_layer_payload(packet_bytes, data_link_type);
    if (!envelope.has_value()) {
        return {};
    }

    if (envelope->protocol_type == detail::kEtherTypeIpv4) {
        const auto ipv4_offset = envelope->payload_offset;
        if (packet_bytes.size() < ipv4_offset + detail::kIpv4MinimumHeaderSize) {
            return {};
        }

        const auto version = static_cast<std::uint8_t>(packet_bytes[ipv4_offset] >> 4U);
        const auto ihl = static_cast<std::size_t>((packet_bytes[ipv4_offset] & 0x0FU) * 4U);
        const auto total_length = static_cast<std::size_t>(detail::read_be16(packet_bytes, ipv4_offset + 2U));
        if (version != 4U || ihl < detail::kIpv4MinimumHeaderSize || total_length < ihl) {
            return {};
        }

        const auto nominal_packet_end = ipv4_offset + total_length;
        if (packet_bytes.size() < ipv4_offset + ihl) {
            return {};
        }

        const auto flags_fragment = detail::read_be16(packet_bytes, ipv4_offset + 6U);
        if ((flags_fragment & 0x3FFFU) != 0U) {
            return {};
        }

        const auto protocol = packet_bytes[ipv4_offset + 9U];
        const auto transport_offset = ipv4_offset + ihl;
        const auto packet_end = nominal_packet_end;

        if (protocol == detail::kIpProtocolTcp) {
            if (packet_bytes.size() < nominal_packet_end) {
                return {};
            }
            if (transport_offset + detail::kTcpMinimumHeaderSize > packet_end) {
                return {};
            }

            const auto tcp_header_length = static_cast<std::size_t>((packet_bytes[transport_offset + 12U] >> 4U) * 4U);
            if (tcp_header_length < detail::kTcpMinimumHeaderSize || transport_offset + tcp_header_length > packet_end) {
                return {};
            }

            return copy_payload(packet_bytes, transport_offset + tcp_header_length, packet_end - (transport_offset + tcp_header_length));
        }

        if (protocol == detail::kIpProtocolUdp) {
            const auto udp_payload = detail::parse_udp_payload_bounds(packet_bytes, transport_offset, nominal_packet_end);
            if (!udp_payload.has_value()) {
                return {};
            }

            return copy_payload(packet_bytes, udp_payload->payload_offset, udp_payload->payload_length);
        }

        return {};
    }

    if (envelope->protocol_type == detail::kEtherTypeIpv6) {
        const auto ipv6_offset = envelope->payload_offset;
        if (packet_bytes.size() < ipv6_offset + detail::kIpv6HeaderSize) {
            return {};
        }

        const auto version = static_cast<std::uint8_t>(packet_bytes[ipv6_offset] >> 4U);
        if (version != 6U) {
            return {};
        }

        const auto ipv6_payload_length = static_cast<std::size_t>(detail::read_be16(packet_bytes, ipv6_offset + 4U));
        const auto nominal_packet_end = ipv6_offset + detail::kIpv6HeaderSize + ipv6_payload_length;

        const auto payload = detail::parse_ipv6_payload(packet_bytes, ipv6_offset);
        const auto packet_end = std::min(nominal_packet_end, packet_bytes.size());
        if (!payload.has_value() || payload->payload_offset > packet_end || payload->has_fragment_header) {
            return {};
        }

        if (payload->next_header == detail::kIpProtocolTcp) {
            if (packet_bytes.size() < nominal_packet_end) {
                return {};
            }
            if (payload->payload_offset + detail::kTcpMinimumHeaderSize > packet_end) {
                return {};
            }

            const auto tcp_header_length = static_cast<std::size_t>((packet_bytes[payload->payload_offset + 12U] >> 4U) * 4U);
            if (tcp_header_length < detail::kTcpMinimumHeaderSize || payload->payload_offset + tcp_header_length > packet_end) {
                return {};
            }

            return copy_payload(packet_bytes, payload->payload_offset + tcp_header_length,
                                packet_end - (payload->payload_offset + tcp_header_length));
        }

        if (payload->next_header == detail::kIpProtocolUdp) {
            const auto udp_payload = detail::parse_udp_payload_bounds(packet_bytes, payload->payload_offset, nominal_packet_end);
            if (!udp_payload.has_value()) {
                return {};
            }

            return copy_payload(packet_bytes, udp_payload->payload_offset, udp_payload->payload_length);
        }

        return {};
    }

    return {};
}

}  // namespace pfl
