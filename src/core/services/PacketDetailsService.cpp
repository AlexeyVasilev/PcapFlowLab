#include "core/services/PacketDetailsService.h"

#include <algorithm>
#include <span>

#include "core/decode/PacketDecodeSupport.h"

namespace pfl {

namespace {

struct LinkLayerView {
    std::uint16_t protocol_type {0};
    std::size_t payload_offset {0};
};

std::optional<LinkLayerView> parse_link_layer_envelope(std::span<const std::uint8_t> packet_bytes,
                                                       const PacketRef& packet_ref,
                                                       PacketDetails& details) {
    details.vlan_tags.clear();
    details.vlan_tags.reserve(detail::kMaxVlanTags);

    if (packet_ref.data_link_type == kLinkTypeEthernet) {
        if (packet_bytes.size() < detail::kEthernetHeaderSize) {
            return std::nullopt;
        }

        details.has_ethernet = true;
        details.ethernet.ether_type = detail::read_be16(packet_bytes, 12U);

        LinkLayerView view {
            .protocol_type = details.ethernet.ether_type,
            .payload_offset = detail::kEthernetHeaderSize,
        };

        std::size_t vlan_count = 0;
        while (detail::is_vlan_ether_type(view.protocol_type)) {
            if (vlan_count == detail::kMaxVlanTags) {
                return std::nullopt;
            }

            if (packet_bytes.size() < view.payload_offset + detail::kVlanHeaderSize) {
                return std::nullopt;
            }

            const VlanTagDetails tag {
                .tci = detail::read_be16(packet_bytes, view.payload_offset),
                .encapsulated_ether_type = detail::read_be16(packet_bytes, view.payload_offset + 2U),
            };
            details.vlan_tags.push_back(tag);
            view.protocol_type = tag.encapsulated_ether_type;
            view.payload_offset += detail::kVlanHeaderSize;
            ++vlan_count;
        }

        details.has_vlan = !details.vlan_tags.empty();
        return view;
    }

    details.has_ethernet = false;
    details.has_vlan = false;

    if (packet_ref.data_link_type == kLinkTypeLinuxSll) {
        if (packet_bytes.size() < detail::kLinuxSllHeaderSize) {
            return std::nullopt;
        }

        details.has_linux_cooked = true;
        details.linux_cooked = LinuxCookedDetails {
            .link_type = packet_ref.data_link_type,
            .protocol_type = detail::read_be16(packet_bytes, 14U),
            .packet_type = detail::read_be16(packet_bytes, 0U),
            .hardware_type = detail::read_be16(packet_bytes, 2U),
        };

        return LinkLayerView {
            .protocol_type = details.linux_cooked.protocol_type,
            .payload_offset = detail::kLinuxSllHeaderSize,
        };
    }

    if (packet_ref.data_link_type == kLinkTypeLinuxSll2) {
        if (packet_bytes.size() < detail::kLinuxSll2HeaderSize) {
            return std::nullopt;
        }

        details.has_linux_cooked = true;
        details.linux_cooked = LinuxCookedDetails {
            .link_type = packet_ref.data_link_type,
            .protocol_type = detail::read_be16(packet_bytes, 0U),
            .packet_type = packet_bytes[10U],
            .hardware_type = detail::read_be16(packet_bytes, 8U),
        };

        return LinkLayerView {
            .protocol_type = details.linux_cooked.protocol_type,
            .payload_offset = detail::kLinuxSll2HeaderSize,
        };
    }

    return std::nullopt;
}

std::array<std::uint8_t, 4> ipv4_bytes(std::span<const std::uint8_t> packet_bytes, const std::size_t offset) {
    return {
        packet_bytes[offset],
        packet_bytes[offset + 1U],
        packet_bytes[offset + 2U],
        packet_bytes[offset + 3U],
    };
}

}  // namespace

std::optional<PacketDetails> PacketDetailsService::decode(std::span<const std::uint8_t> packet_bytes,
                                                          const PacketRef& packet_ref) const {
    PacketDetails details {
        .packet_index = packet_ref.packet_index,
        .captured_length = packet_ref.captured_length,
        .original_length = packet_ref.original_length,
    };

    const auto envelope = parse_link_layer_envelope(packet_bytes, packet_ref, details);
    if (!envelope.has_value()) {
        return std::nullopt;
    }

    if (envelope->protocol_type == detail::kEtherTypeArp) {
        const auto arp_offset = envelope->payload_offset;
        if (packet_bytes.size() < arp_offset + 8U) {
            return std::nullopt;
        }

        const auto hardware_size = packet_bytes[arp_offset + 4U];
        const auto protocol_size = packet_bytes[arp_offset + 5U];
        if (packet_bytes.size() < arp_offset + static_cast<std::size_t>(8U + (2U * hardware_size) + (2U * protocol_size))) {
            return std::nullopt;
        }

        details.has_arp = true;
        details.arp.hardware_type = detail::read_be16(packet_bytes, arp_offset);
        details.arp.protocol_type = detail::read_be16(packet_bytes, arp_offset + 2U);
        details.arp.opcode = detail::read_be16(packet_bytes, arp_offset + 6U);

        if (details.arp.protocol_type == detail::kArpProtocolTypeIpv4 && protocol_size == 4U && hardware_size > 0U) {
            const auto sender_protocol_offset = arp_offset + 8U + hardware_size;
            const auto target_protocol_offset = arp_offset + 8U + (2U * hardware_size) + protocol_size;
            details.arp.sender_ipv4 = ipv4_bytes(packet_bytes, sender_protocol_offset);
            details.arp.target_ipv4 = ipv4_bytes(packet_bytes, target_protocol_offset);
        }

        return details;
    }

    if (envelope->protocol_type == detail::kEtherTypeIpv4) {
        const auto ipv4_offset = envelope->payload_offset;
        if (packet_bytes.size() < ipv4_offset + detail::kIpv4MinimumHeaderSize) {
            return std::nullopt;
        }

        const auto version = static_cast<std::uint8_t>(packet_bytes[ipv4_offset] >> 4U);
        const auto ihl = static_cast<std::size_t>((packet_bytes[ipv4_offset] & 0x0FU) * 4U);
        const auto total_length = static_cast<std::size_t>(detail::read_be16(packet_bytes, ipv4_offset + 2U));
        if (version != 4U || ihl < detail::kIpv4MinimumHeaderSize || total_length < ihl) {
            return std::nullopt;
        }

        if (packet_bytes.size() < ipv4_offset + ihl) {
            return std::nullopt;
        }

        const auto flags_fragment = detail::read_be16(packet_bytes, ipv4_offset + 6U);
        const bool is_fragmented = (flags_fragment & 0x3FFFU) != 0U;
        const auto packet_end = std::min(ipv4_offset + total_length, packet_bytes.size());

        details.address_family = NetworkAddressFamily::ipv4;
        details.has_ipv4 = true;
        details.ipv4 = IPv4Details {
            .src_addr = detail::read_be32(packet_bytes, ipv4_offset + 12U),
            .dst_addr = detail::read_be32(packet_bytes, ipv4_offset + 16U),
            .protocol = packet_bytes[ipv4_offset + 9U],
            .ttl = packet_bytes[ipv4_offset + 8U],
            .total_length = static_cast<std::uint16_t>(total_length),
        };

        if (is_fragmented) {
            return details;
        }

        const auto transport_offset = ipv4_offset + ihl;
        if (details.ipv4.protocol == detail::kIpProtocolTcp) {
            if (transport_offset + detail::kTcpMinimumHeaderSize > packet_end ||
                packet_bytes.size() < transport_offset + detail::kTcpMinimumHeaderSize) {
                return std::nullopt;
            }

            const auto tcp_header_length = static_cast<std::size_t>((packet_bytes[transport_offset + 12U] >> 4U) * 4U);
            if (tcp_header_length < detail::kTcpMinimumHeaderSize ||
                transport_offset + tcp_header_length > packet_end ||
                packet_bytes.size() < transport_offset + tcp_header_length) {
                return std::nullopt;
            }

            details.has_tcp = true;
            details.tcp = TcpDetails {
                .src_port = detail::read_be16(packet_bytes, transport_offset),
                .dst_port = detail::read_be16(packet_bytes, transport_offset + 2U),
                .flags = packet_bytes[transport_offset + 13U],
                .seq_number = detail::read_be32(packet_bytes, transport_offset + 4U),
                .ack_number = detail::read_be32(packet_bytes, transport_offset + 8U),
            };
            return details;
        }

        if (details.ipv4.protocol == detail::kIpProtocolUdp) {
            const auto udp_payload = detail::parse_udp_payload_bounds(packet_bytes, transport_offset, ipv4_offset + total_length);
            if (!udp_payload.has_value()) {
                return std::nullopt;
            }

            details.has_udp = true;
            details.udp = UdpDetails {
                .src_port = detail::read_be16(packet_bytes, transport_offset),
                .dst_port = detail::read_be16(packet_bytes, transport_offset + 2U),
                .length = udp_payload->datagram_length,
            };
            return details;
        }

        if (details.ipv4.protocol == detail::kIpProtocolIcmp) {
            if (transport_offset + 2U > packet_end || packet_bytes.size() < transport_offset + 2U) {
                return std::nullopt;
            }

            details.has_icmp = true;
            details.icmp = IcmpDetails {
                .type = packet_bytes[transport_offset],
                .code = packet_bytes[transport_offset + 1U],
            };
            return details;
        }

        return std::nullopt;
    }

    if (envelope->protocol_type == detail::kEtherTypeIpv6) {
        const auto ipv6_offset = envelope->payload_offset;
        if (packet_bytes.size() < ipv6_offset + detail::kIpv6HeaderSize) {
            return std::nullopt;
        }

        const auto version = static_cast<std::uint8_t>(packet_bytes[ipv6_offset] >> 4U);
        if (version != 6U) {
            return std::nullopt;
        }

        details.address_family = NetworkAddressFamily::ipv6;
        details.has_ipv6 = true;
        details.ipv6.hop_limit = packet_bytes[ipv6_offset + 7U];
        details.ipv6.payload_length = detail::read_be16(packet_bytes, ipv6_offset + 4U);
        for (std::size_t index = 0; index < 16U; ++index) {
            details.ipv6.src_addr[index] = packet_bytes[ipv6_offset + 8U + index];
            details.ipv6.dst_addr[index] = packet_bytes[ipv6_offset + 24U + index];
        }

        const auto payload = detail::parse_ipv6_payload(packet_bytes, ipv6_offset);
        const auto packet_end = std::min(ipv6_offset + detail::kIpv6HeaderSize + static_cast<std::size_t>(details.ipv6.payload_length),
                                         packet_bytes.size());
        if (!payload.has_value() || payload->payload_offset > packet_end) {
            return std::nullopt;
        }

        details.ipv6.next_header = payload->next_header;
        if (payload->has_fragment_header) {
            return details;
        }

        if (payload->next_header == detail::kIpProtocolTcp) {
            if (payload->payload_offset + detail::kTcpMinimumHeaderSize > packet_end ||
                packet_bytes.size() < payload->payload_offset + detail::kTcpMinimumHeaderSize) {
                return std::nullopt;
            }

            const auto tcp_header_length = static_cast<std::size_t>((packet_bytes[payload->payload_offset + 12U] >> 4U) * 4U);
            if (tcp_header_length < detail::kTcpMinimumHeaderSize ||
                payload->payload_offset + tcp_header_length > packet_end ||
                packet_bytes.size() < payload->payload_offset + tcp_header_length) {
                return std::nullopt;
            }

            details.has_tcp = true;
            details.tcp = TcpDetails {
                .src_port = detail::read_be16(packet_bytes, payload->payload_offset),
                .dst_port = detail::read_be16(packet_bytes, payload->payload_offset + 2U),
                .flags = packet_bytes[payload->payload_offset + 13U],
                .seq_number = detail::read_be32(packet_bytes, payload->payload_offset + 4U),
                .ack_number = detail::read_be32(packet_bytes, payload->payload_offset + 8U),
            };
            return details;
        }

        if (payload->next_header == detail::kIpProtocolUdp) {
            const auto udp_payload = detail::parse_udp_payload_bounds(
                packet_bytes,
                payload->payload_offset,
                ipv6_offset + detail::kIpv6HeaderSize + static_cast<std::size_t>(details.ipv6.payload_length)
            );
            if (!udp_payload.has_value()) {
                return std::nullopt;
            }

            details.has_udp = true;
            details.udp = UdpDetails {
                .src_port = detail::read_be16(packet_bytes, payload->payload_offset),
                .dst_port = detail::read_be16(packet_bytes, payload->payload_offset + 2U),
                .length = udp_payload->datagram_length,
            };
            return details;
        }

        if (payload->next_header == detail::kIpProtocolIcmpV6) {
            if (payload->payload_offset + 2U > packet_end || packet_bytes.size() < payload->payload_offset + 2U) {
                return std::nullopt;
            }

            details.has_icmpv6 = true;
            details.icmpv6 = IcmpV6Details {
                .type = packet_bytes[payload->payload_offset],
                .code = packet_bytes[payload->payload_offset + 1U],
            };
            return details;
        }

        return std::nullopt;
    }

    return std::nullopt;
}

}  // namespace pfl
