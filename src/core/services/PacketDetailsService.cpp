#include "core/services/PacketDetailsService.h"

namespace pfl {

namespace {

constexpr std::size_t kEthernetHeaderSize = 14;
constexpr std::uint16_t kEtherTypeIpv4 = 0x0800U;
constexpr std::uint16_t kEtherTypeIpv6 = 0x86DDU;
constexpr std::uint8_t kIpProtocolTcp = 6;
constexpr std::uint8_t kIpProtocolUdp = 17;
constexpr std::size_t kIpv4MinimumHeaderSize = 20;
constexpr std::size_t kIpv6HeaderSize = 40;
constexpr std::size_t kTransportMinimumSize = 4;

std::uint16_t read_be16(std::span<const std::uint8_t> bytes, std::size_t offset) {
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(bytes[offset]) << 8U) |
                                      static_cast<std::uint16_t>(bytes[offset + 1]));
}

std::uint32_t read_be32(std::span<const std::uint8_t> bytes, std::size_t offset) {
    return (static_cast<std::uint32_t>(bytes[offset]) << 24U) |
           (static_cast<std::uint32_t>(bytes[offset + 1]) << 16U) |
           (static_cast<std::uint32_t>(bytes[offset + 2]) << 8U) |
           static_cast<std::uint32_t>(bytes[offset + 3]);
}

}  // namespace

std::optional<PacketDetails> PacketDetailsService::decode(
    std::span<const std::uint8_t> packet_bytes,
    const PacketRef& packet_ref
) const {
    if (packet_bytes.size() < kEthernetHeaderSize) {
        return std::nullopt;
    }

    PacketDetails details {
        .packet_index = packet_ref.packet_index,
        .captured_length = packet_ref.captured_length,
        .original_length = packet_ref.original_length,
        .has_ethernet = true,
        .ethernet = EthernetDetails {
            .ether_type = read_be16(packet_bytes, 12),
        },
    };

    if (details.ethernet.ether_type == kEtherTypeIpv4) {
        if (packet_bytes.size() < kEthernetHeaderSize + kIpv4MinimumHeaderSize) {
            return std::nullopt;
        }

        const auto ipv4_offset = kEthernetHeaderSize;
        const auto version = static_cast<std::uint8_t>(packet_bytes[ipv4_offset] >> 4U);
        const auto ihl = static_cast<std::size_t>((packet_bytes[ipv4_offset] & 0x0FU) * 4U);
        if (version != 4 || ihl < kIpv4MinimumHeaderSize) {
            return std::nullopt;
        }

        if (packet_bytes.size() < kEthernetHeaderSize + ihl + kTransportMinimumSize) {
            return std::nullopt;
        }

        details.address_family = NetworkAddressFamily::ipv4;
        details.has_ipv4 = true;
        details.ipv4 = IPv4Details {
            .src_addr = read_be32(packet_bytes, ipv4_offset + 12),
            .dst_addr = read_be32(packet_bytes, ipv4_offset + 16),
            .protocol = packet_bytes[ipv4_offset + 9],
            .ttl = packet_bytes[ipv4_offset + 8],
            .total_length = read_be16(packet_bytes, ipv4_offset + 2),
        };

        const auto transport_offset = kEthernetHeaderSize + ihl;
        if (details.ipv4.protocol == kIpProtocolTcp) {
            if (packet_bytes.size() < transport_offset + 20) {
                return std::nullopt;
            }

            details.has_tcp = true;
            details.tcp = TcpDetails {
                .src_port = read_be16(packet_bytes, transport_offset),
                .dst_port = read_be16(packet_bytes, transport_offset + 2),
                .flags = packet_bytes[transport_offset + 13],
                .seq_number = read_be32(packet_bytes, transport_offset + 4),
                .ack_number = read_be32(packet_bytes, transport_offset + 8),
            };
            return details;
        }

        if (details.ipv4.protocol == kIpProtocolUdp) {
            if (packet_bytes.size() < transport_offset + 8) {
                return std::nullopt;
            }

            details.has_udp = true;
            details.udp = UdpDetails {
                .src_port = read_be16(packet_bytes, transport_offset),
                .dst_port = read_be16(packet_bytes, transport_offset + 2),
                .length = read_be16(packet_bytes, transport_offset + 4),
            };
            return details;
        }

        return std::nullopt;
    }

    if (details.ethernet.ether_type == kEtherTypeIpv6) {
        if (packet_bytes.size() < kEthernetHeaderSize + kIpv6HeaderSize + kTransportMinimumSize) {
            return std::nullopt;
        }

        const auto ipv6_offset = kEthernetHeaderSize;
        const auto version = static_cast<std::uint8_t>(packet_bytes[ipv6_offset] >> 4U);
        if (version != 6) {
            return std::nullopt;
        }

        details.address_family = NetworkAddressFamily::ipv6;
        details.has_ipv6 = true;
        details.ipv6.next_header = packet_bytes[ipv6_offset + 6];
        details.ipv6.hop_limit = packet_bytes[ipv6_offset + 7];
        details.ipv6.payload_length = read_be16(packet_bytes, ipv6_offset + 4);
        for (std::size_t index = 0; index < 16; ++index) {
            details.ipv6.src_addr[index] = packet_bytes[ipv6_offset + 8 + index];
            details.ipv6.dst_addr[index] = packet_bytes[ipv6_offset + 24 + index];
        }

        const auto transport_offset = kEthernetHeaderSize + kIpv6HeaderSize;
        if (details.ipv6.next_header == kIpProtocolTcp) {
            if (packet_bytes.size() < transport_offset + 20) {
                return std::nullopt;
            }

            details.has_tcp = true;
            details.tcp = TcpDetails {
                .src_port = read_be16(packet_bytes, transport_offset),
                .dst_port = read_be16(packet_bytes, transport_offset + 2),
                .flags = packet_bytes[transport_offset + 13],
                .seq_number = read_be32(packet_bytes, transport_offset + 4),
                .ack_number = read_be32(packet_bytes, transport_offset + 8),
            };
            return details;
        }

        if (details.ipv6.next_header == kIpProtocolUdp) {
            if (packet_bytes.size() < transport_offset + 8) {
                return std::nullopt;
            }

            details.has_udp = true;
            details.udp = UdpDetails {
                .src_port = read_be16(packet_bytes, transport_offset),
                .dst_port = read_be16(packet_bytes, transport_offset + 2),
                .length = read_be16(packet_bytes, transport_offset + 4),
            };
            return details;
        }

        return std::nullopt;
    }

    return std::nullopt;
}

}  // namespace pfl
