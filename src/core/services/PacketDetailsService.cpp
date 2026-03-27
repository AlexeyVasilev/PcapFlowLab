#include "core/services/PacketDetailsService.h"

#include <algorithm>

namespace pfl {

namespace {

constexpr std::size_t kEthernetHeaderSize = 14;
constexpr std::size_t kVlanHeaderSize = 4;
constexpr std::size_t kMaxVlanTags = 2;
constexpr std::size_t kMaxIpv6ExtensionHeaders = 8;
constexpr std::uint16_t kEtherTypeArp = 0x0806U;
constexpr std::uint16_t kEtherTypeIpv4 = 0x0800U;
constexpr std::uint16_t kEtherTypeIpv6 = 0x86DDU;
constexpr std::uint16_t kEtherTypeVlan = 0x8100U;
constexpr std::uint16_t kEtherTypeQinq = 0x88A8U;
constexpr std::uint16_t kArpProtocolTypeIpv4 = 0x0800U;
constexpr std::uint8_t kIpProtocolIcmp = 1;
constexpr std::uint8_t kIpProtocolTcp = 6;
constexpr std::uint8_t kIpProtocolUdp = 17;
constexpr std::uint8_t kIpProtocolRouting = 43;
constexpr std::uint8_t kIpProtocolFragment = 44;
constexpr std::uint8_t kIpProtocolAh = 51;
constexpr std::uint8_t kIpProtocolIcmpV6 = 58;
constexpr std::uint8_t kIpProtocolDestinationOptions = 60;
constexpr std::uint8_t kIpProtocolHopByHop = 0;
constexpr std::size_t kIpv4MinimumHeaderSize = 20;
constexpr std::size_t kIpv6HeaderSize = 40;
constexpr std::size_t kTcpMinimumHeaderSize = 20;
constexpr std::size_t kUdpHeaderSize = 8;

struct EthernetPayloadView {
    std::uint16_t ether_type {0};
    std::size_t payload_offset {0};
};

struct Ipv6PayloadView {
    std::uint8_t next_header {0};
    std::size_t payload_offset {0};
};

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

bool is_vlan_ether_type(std::uint16_t ether_type) noexcept {
    return ether_type == kEtherTypeVlan || ether_type == kEtherTypeQinq;
}

bool is_ipv6_extension_header(std::uint8_t next_header) noexcept {
    return next_header == kIpProtocolHopByHop ||
           next_header == kIpProtocolRouting ||
           next_header == kIpProtocolFragment ||
           next_header == kIpProtocolDestinationOptions ||
           next_header == kIpProtocolAh;
}

std::optional<EthernetPayloadView> parse_ethernet_envelope(
    std::span<const std::uint8_t> packet_bytes,
    PacketDetails& details
) {
    if (packet_bytes.size() < kEthernetHeaderSize) {
        return std::nullopt;
    }

    details.has_ethernet = true;
    details.ethernet.ether_type = read_be16(packet_bytes, 12);

    EthernetPayloadView view {
        .ether_type = details.ethernet.ether_type,
        .payload_offset = kEthernetHeaderSize,
    };

    details.vlan_tags.clear();
    details.vlan_tags.reserve(kMaxVlanTags);

    std::size_t vlan_count = 0;
    while (is_vlan_ether_type(view.ether_type)) {
        if (vlan_count == kMaxVlanTags) {
            return std::nullopt;
        }

        if (packet_bytes.size() < view.payload_offset + kVlanHeaderSize) {
            return std::nullopt;
        }

        const VlanTagDetails tag {
            .tci = read_be16(packet_bytes, view.payload_offset),
            .encapsulated_ether_type = read_be16(packet_bytes, view.payload_offset + 2),
        };
        details.vlan_tags.push_back(tag);
        view.ether_type = tag.encapsulated_ether_type;
        view.payload_offset += kVlanHeaderSize;
        ++vlan_count;
    }

    details.has_vlan = !details.vlan_tags.empty();
    return view;
}

std::optional<Ipv6PayloadView> parse_ipv6_payload(std::span<const std::uint8_t> packet_bytes, std::size_t ipv6_offset) {
    if (packet_bytes.size() < ipv6_offset + kIpv6HeaderSize) {
        return std::nullopt;
    }

    std::uint8_t next_header = packet_bytes[ipv6_offset + 6];
    std::size_t payload_offset = ipv6_offset + kIpv6HeaderSize;

    for (std::size_t extension_count = 0; extension_count < kMaxIpv6ExtensionHeaders; ++extension_count) {
        if (!is_ipv6_extension_header(next_header)) {
            return Ipv6PayloadView {
                .next_header = next_header,
                .payload_offset = payload_offset,
            };
        }

        if (packet_bytes.size() < payload_offset + 2) {
            return std::nullopt;
        }

        if (next_header == kIpProtocolFragment) {
            if (packet_bytes.size() < payload_offset + 8) {
                return std::nullopt;
            }

            const auto fragment_offset_and_flags = read_be16(packet_bytes, payload_offset + 2);
            if ((fragment_offset_and_flags & 0xFFF8U) != 0U) {
                return std::nullopt;
            }

            next_header = packet_bytes[payload_offset];
            payload_offset += 8;
            continue;
        }

        std::size_t header_length = 0;
        if (next_header == kIpProtocolAh) {
            header_length = static_cast<std::size_t>(packet_bytes[payload_offset + 1] + 2U) * 4U;
        } else {
            header_length = static_cast<std::size_t>(packet_bytes[payload_offset + 1] + 1U) * 8U;
        }

        if (header_length < 8 || packet_bytes.size() < payload_offset + header_length) {
            return std::nullopt;
        }

        next_header = packet_bytes[payload_offset];
        payload_offset += header_length;
    }

    return std::nullopt;
}

std::array<std::uint8_t, 4> ipv4_bytes(std::span<const std::uint8_t> packet_bytes, std::size_t offset) {
    return {
        packet_bytes[offset],
        packet_bytes[offset + 1],
        packet_bytes[offset + 2],
        packet_bytes[offset + 3],
    };
}

}  // namespace

std::optional<PacketDetails> PacketDetailsService::decode(
    std::span<const std::uint8_t> packet_bytes,
    const PacketRef& packet_ref
) const {
    PacketDetails details {
        .packet_index = packet_ref.packet_index,
        .captured_length = packet_ref.captured_length,
        .original_length = packet_ref.original_length,
    };

    const auto ethernet = parse_ethernet_envelope(packet_bytes, details);
    if (!ethernet.has_value()) {
        return std::nullopt;
    }

    if (ethernet->ether_type == kEtherTypeArp) {
        const auto arp_offset = ethernet->payload_offset;
        if (packet_bytes.size() < arp_offset + 8) {
            return std::nullopt;
        }

        const auto hardware_size = packet_bytes[arp_offset + 4];
        const auto protocol_size = packet_bytes[arp_offset + 5];
        if (packet_bytes.size() < arp_offset + static_cast<std::size_t>(8 + (2U * hardware_size) + (2U * protocol_size))) {
            return std::nullopt;
        }

        details.has_arp = true;
        details.arp.hardware_type = read_be16(packet_bytes, arp_offset);
        details.arp.protocol_type = read_be16(packet_bytes, arp_offset + 2);
        details.arp.opcode = read_be16(packet_bytes, arp_offset + 6);

        if (details.arp.protocol_type == kArpProtocolTypeIpv4 && protocol_size == 4 && hardware_size > 0) {
            const auto sender_protocol_offset = arp_offset + 8 + hardware_size;
            const auto target_protocol_offset = arp_offset + 8 + (2U * hardware_size) + protocol_size;
            details.arp.sender_ipv4 = ipv4_bytes(packet_bytes, sender_protocol_offset);
            details.arp.target_ipv4 = ipv4_bytes(packet_bytes, target_protocol_offset);
        }

        return details;
    }

    if (ethernet->ether_type == kEtherTypeIpv4) {
        const auto ipv4_offset = ethernet->payload_offset;
        if (packet_bytes.size() < ipv4_offset + kIpv4MinimumHeaderSize) {
            return std::nullopt;
        }

        const auto version = static_cast<std::uint8_t>(packet_bytes[ipv4_offset] >> 4U);
        const auto ihl = static_cast<std::size_t>((packet_bytes[ipv4_offset] & 0x0FU) * 4U);
        const auto total_length = static_cast<std::size_t>(read_be16(packet_bytes, ipv4_offset + 2));
        if (version != 4 || ihl < kIpv4MinimumHeaderSize || total_length < ihl) {
            return std::nullopt;
        }

        if (packet_bytes.size() < ipv4_offset + ihl) {
            return std::nullopt;
        }

        const auto flags_fragment = read_be16(packet_bytes, ipv4_offset + 6);
        if ((flags_fragment & 0x3FFFU) != 0U) {
            return std::nullopt;
        }

        const auto packet_end = std::min(ipv4_offset + total_length, packet_bytes.size());

        details.address_family = NetworkAddressFamily::ipv4;
        details.has_ipv4 = true;
        details.ipv4 = IPv4Details {
            .src_addr = read_be32(packet_bytes, ipv4_offset + 12),
            .dst_addr = read_be32(packet_bytes, ipv4_offset + 16),
            .protocol = packet_bytes[ipv4_offset + 9],
            .ttl = packet_bytes[ipv4_offset + 8],
            .total_length = static_cast<std::uint16_t>(total_length),
        };

        const auto transport_offset = ipv4_offset + ihl;
        if (details.ipv4.protocol == kIpProtocolTcp) {
            if (transport_offset + kTcpMinimumHeaderSize > packet_end || packet_bytes.size() < transport_offset + kTcpMinimumHeaderSize) {
                return std::nullopt;
            }

            const auto tcp_header_length = static_cast<std::size_t>((packet_bytes[transport_offset + 12] >> 4U) * 4U);
            if (tcp_header_length < kTcpMinimumHeaderSize || transport_offset + tcp_header_length > packet_end ||
                packet_bytes.size() < transport_offset + tcp_header_length) {
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
            if (transport_offset + kUdpHeaderSize > packet_end || packet_bytes.size() < transport_offset + kUdpHeaderSize) {
                return std::nullopt;
            }

            const auto udp_length = static_cast<std::size_t>(read_be16(packet_bytes, transport_offset + 4));
            if (udp_length < kUdpHeaderSize || transport_offset + udp_length > packet_end) {
                return std::nullopt;
            }

            details.has_udp = true;
            details.udp = UdpDetails {
                .src_port = read_be16(packet_bytes, transport_offset),
                .dst_port = read_be16(packet_bytes, transport_offset + 2),
                .length = static_cast<std::uint16_t>(udp_length),
            };
            return details;
        }

        if (details.ipv4.protocol == kIpProtocolIcmp) {
            if (transport_offset + 2U > packet_end || packet_bytes.size() < transport_offset + 2U) {
                return std::nullopt;
            }

            details.has_icmp = true;
            details.icmp = IcmpDetails {
                .type = packet_bytes[transport_offset],
                .code = packet_bytes[transport_offset + 1],
            };
            return details;
        }

        return std::nullopt;
    }

    if (ethernet->ether_type == kEtherTypeIpv6) {
        const auto ipv6_offset = ethernet->payload_offset;
        if (packet_bytes.size() < ipv6_offset + kIpv6HeaderSize) {
            return std::nullopt;
        }

        const auto version = static_cast<std::uint8_t>(packet_bytes[ipv6_offset] >> 4U);
        if (version != 6) {
            return std::nullopt;
        }

        details.address_family = NetworkAddressFamily::ipv6;
        details.has_ipv6 = true;
        details.ipv6.hop_limit = packet_bytes[ipv6_offset + 7];
        details.ipv6.payload_length = read_be16(packet_bytes, ipv6_offset + 4);
        for (std::size_t index = 0; index < 16; ++index) {
            details.ipv6.src_addr[index] = packet_bytes[ipv6_offset + 8 + index];
            details.ipv6.dst_addr[index] = packet_bytes[ipv6_offset + 24 + index];
        }

        const auto payload = parse_ipv6_payload(packet_bytes, ipv6_offset);
        const auto packet_end = std::min(ipv6_offset + kIpv6HeaderSize + static_cast<std::size_t>(details.ipv6.payload_length), packet_bytes.size());
        if (!payload.has_value() || payload->payload_offset > packet_end) {
            return std::nullopt;
        }

        details.ipv6.next_header = payload->next_header;

        if (payload->next_header == kIpProtocolTcp) {
            if (payload->payload_offset + kTcpMinimumHeaderSize > packet_end || packet_bytes.size() < payload->payload_offset + kTcpMinimumHeaderSize) {
                return std::nullopt;
            }

            const auto tcp_header_length = static_cast<std::size_t>((packet_bytes[payload->payload_offset + 12] >> 4U) * 4U);
            if (tcp_header_length < kTcpMinimumHeaderSize || payload->payload_offset + tcp_header_length > packet_end ||
                packet_bytes.size() < payload->payload_offset + tcp_header_length) {
                return std::nullopt;
            }

            details.has_tcp = true;
            details.tcp = TcpDetails {
                .src_port = read_be16(packet_bytes, payload->payload_offset),
                .dst_port = read_be16(packet_bytes, payload->payload_offset + 2),
                .flags = packet_bytes[payload->payload_offset + 13],
                .seq_number = read_be32(packet_bytes, payload->payload_offset + 4),
                .ack_number = read_be32(packet_bytes, payload->payload_offset + 8),
            };
            return details;
        }

        if (payload->next_header == kIpProtocolUdp) {
            if (payload->payload_offset + kUdpHeaderSize > packet_end || packet_bytes.size() < payload->payload_offset + kUdpHeaderSize) {
                return std::nullopt;
            }

            const auto udp_length = static_cast<std::size_t>(read_be16(packet_bytes, payload->payload_offset + 4));
            if (udp_length < kUdpHeaderSize || payload->payload_offset + udp_length > packet_end) {
                return std::nullopt;
            }

            details.has_udp = true;
            details.udp = UdpDetails {
                .src_port = read_be16(packet_bytes, payload->payload_offset),
                .dst_port = read_be16(packet_bytes, payload->payload_offset + 2),
                .length = static_cast<std::uint16_t>(udp_length),
            };
            return details;
        }

        if (payload->next_header == kIpProtocolIcmpV6) {
            if (payload->payload_offset + 2U > packet_end || packet_bytes.size() < payload->payload_offset + 2U) {
                return std::nullopt;
            }

            details.has_icmpv6 = true;
            details.icmpv6 = IcmpV6Details {
                .type = packet_bytes[payload->payload_offset],
                .code = packet_bytes[payload->payload_offset + 1],
            };
            return details;
        }

        return std::nullopt;
    }

    return std::nullopt;
}

}  // namespace pfl
