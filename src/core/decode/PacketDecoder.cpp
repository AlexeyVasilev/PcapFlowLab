#include "core/decode/PacketDecoder.h"

#include <array>
#include <optional>

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
constexpr std::uint8_t kIpProtocolEsp = 50;
constexpr std::uint8_t kIpProtocolAh = 51;
constexpr std::uint8_t kIpProtocolIcmpV6 = 58;
constexpr std::uint8_t kIpProtocolNoNextHeader = 59;
constexpr std::uint8_t kIpProtocolDestinationOptions = 60;
constexpr std::uint8_t kIpProtocolHopByHop = 0;
constexpr std::size_t kIpv4MinimumHeaderSize = 20;
constexpr std::size_t kIpv6HeaderSize = 40;
constexpr std::size_t kTransportPortsSize = 4;

struct EthernetPayloadView {
    std::uint16_t ether_type {0};
    std::size_t payload_offset {0};
};

struct Ipv6PayloadView {
    std::uint8_t next_header {0};
    std::size_t payload_offset {0};
};

std::uint16_t read_be16(const std::vector<std::uint8_t>& bytes, std::size_t offset) {
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(bytes[offset]) << 8U) |
                                      static_cast<std::uint16_t>(bytes[offset + 1]));
}

std::uint32_t read_be32(const std::vector<std::uint8_t>& bytes, std::size_t offset) {
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

std::optional<EthernetPayloadView> parse_ethernet_payload(const std::vector<std::uint8_t>& bytes) {
    if (bytes.size() < kEthernetHeaderSize) {
        return std::nullopt;
    }

    EthernetPayloadView view {
        .ether_type = read_be16(bytes, 12),
        .payload_offset = kEthernetHeaderSize,
    };

    std::size_t vlan_count = 0;
    while (is_vlan_ether_type(view.ether_type)) {
        if (vlan_count == kMaxVlanTags) {
            return std::nullopt;
        }

        if (bytes.size() < view.payload_offset + kVlanHeaderSize) {
            return std::nullopt;
        }

        view.ether_type = read_be16(bytes, view.payload_offset + 2);
        view.payload_offset += kVlanHeaderSize;
        ++vlan_count;
    }

    return view;
}

std::optional<Ipv6PayloadView> parse_ipv6_payload(const std::vector<std::uint8_t>& bytes, std::size_t ipv6_offset) {
    if (bytes.size() < ipv6_offset + kIpv6HeaderSize) {
        return std::nullopt;
    }

    std::uint8_t next_header = bytes[ipv6_offset + 6];
    std::size_t payload_offset = ipv6_offset + kIpv6HeaderSize;

    for (std::size_t extension_count = 0; extension_count < kMaxIpv6ExtensionHeaders; ++extension_count) {
        if (!is_ipv6_extension_header(next_header)) {
            return Ipv6PayloadView {
                .next_header = next_header,
                .payload_offset = payload_offset,
            };
        }

        if (bytes.size() < payload_offset + 2) {
            return std::nullopt;
        }

        if (next_header == kIpProtocolFragment) {
            if (bytes.size() < payload_offset + 8) {
                return std::nullopt;
            }

            const auto fragment_offset_and_flags = read_be16(bytes, payload_offset + 2);
            if ((fragment_offset_and_flags & 0xFFF8U) != 0U) {
                return std::nullopt;
            }

            next_header = bytes[payload_offset];
            payload_offset += 8;
            continue;
        }

        std::size_t header_length = 0;
        if (next_header == kIpProtocolAh) {
            header_length = static_cast<std::size_t>(bytes[payload_offset + 1] + 2U) * 4U;
        } else {
            header_length = static_cast<std::size_t>(bytes[payload_offset + 1] + 1U) * 8U;
        }

        if (header_length < 8 || bytes.size() < payload_offset + header_length) {
            return std::nullopt;
        }

        next_header = bytes[payload_offset];
        payload_offset += header_length;
    }

    return std::nullopt;
}

PacketRef make_packet_ref(const RawPcapPacket& packet) {
    return PacketRef {
        .packet_index = packet.packet_index,
        .byte_offset = packet.data_offset,
        .captured_length = packet.captured_length,
        .original_length = packet.original_length,
        .ts_sec = packet.ts_sec,
        .ts_usec = packet.ts_usec,
    };
}

}  // namespace

DecodedPacket PacketDecoder::decode_ethernet(const RawPcapPacket& packet) const noexcept {
    const auto ethernet = parse_ethernet_payload(packet.bytes);
    if (!ethernet.has_value()) {
        return {};
    }

    if (ethernet->ether_type == kEtherTypeArp) {
        const auto arp_offset = ethernet->payload_offset;
        if (packet.bytes.size() < arp_offset + 8) {
            return {};
        }

        const auto hardware_type = read_be16(packet.bytes, arp_offset);
        const auto protocol_type = read_be16(packet.bytes, arp_offset + 2);
        const auto hardware_size = packet.bytes[arp_offset + 4];
        const auto protocol_size = packet.bytes[arp_offset + 5];
        static_cast<void>(hardware_type);
        if (protocol_type != kArpProtocolTypeIpv4 || protocol_size != 4 || hardware_size == 0) {
            return {};
        }

        const auto arp_length = static_cast<std::size_t>(8 + (2U * hardware_size) + (2U * protocol_size));
        if (packet.bytes.size() < arp_offset + arp_length) {
            return {};
        }

        const auto sender_protocol_offset = arp_offset + 8 + hardware_size;
        const auto target_protocol_offset = arp_offset + 8 + (2U * hardware_size) + protocol_size;
        const auto flow_key = FlowKeyV4 {
            .src_addr = read_be32(packet.bytes, sender_protocol_offset),
            .dst_addr = read_be32(packet.bytes, target_protocol_offset),
            .src_port = 0,
            .dst_port = 0,
            .protocol = ProtocolId::arp,
        };

        return DecodedPacket {
            .ipv4 = IngestedPacketV4 {
                .flow_key = flow_key,
                .packet_ref = make_packet_ref(packet),
            },
        };
    }

    if (ethernet->ether_type == kEtherTypeIpv4) {
        const auto ipv4_offset = ethernet->payload_offset;
        if (packet.bytes.size() < ipv4_offset + kIpv4MinimumHeaderSize) {
            return {};
        }

        const auto version = static_cast<std::uint8_t>(packet.bytes[ipv4_offset] >> 4U);
        const auto ihl = static_cast<std::size_t>((packet.bytes[ipv4_offset] & 0x0FU) * 4U);
        if (version != 4 || ihl < kIpv4MinimumHeaderSize) {
            return {};
        }

        if (packet.bytes.size() < ipv4_offset + ihl) {
            return {};
        }

        const auto flags_fragment = read_be16(packet.bytes, ipv4_offset + 6);
        if ((flags_fragment & 0x3FFFU) != 0U) {
            return {};
        }

        const auto protocol = packet.bytes[ipv4_offset + 9];
        const auto transport_offset = ipv4_offset + ihl;
        const auto flow_base = FlowKeyV4 {
            .src_addr = read_be32(packet.bytes, ipv4_offset + 12),
            .dst_addr = read_be32(packet.bytes, ipv4_offset + 16),
        };

        if (protocol == kIpProtocolTcp || protocol == kIpProtocolUdp) {
            if (packet.bytes.size() < transport_offset + kTransportPortsSize) {
                return {};
            }

            auto flow_key = flow_base;
            flow_key.src_port = read_be16(packet.bytes, transport_offset);
            flow_key.dst_port = read_be16(packet.bytes, transport_offset + 2);
            flow_key.protocol = (protocol == kIpProtocolTcp) ? ProtocolId::tcp : ProtocolId::udp;

            return DecodedPacket {
                .ipv4 = IngestedPacketV4 {
                    .flow_key = flow_key,
                    .packet_ref = make_packet_ref(packet),
                },
            };
        }

        if (protocol == kIpProtocolIcmp) {
            if (packet.bytes.size() < transport_offset + 2) {
                return {};
            }

            auto flow_key = flow_base;
            flow_key.protocol = ProtocolId::icmp;

            return DecodedPacket {
                .ipv4 = IngestedPacketV4 {
                    .flow_key = flow_key,
                    .packet_ref = make_packet_ref(packet),
                },
            };
        }

        return {};
    }

    if (ethernet->ether_type == kEtherTypeIpv6) {
        const auto ipv6_offset = ethernet->payload_offset;
        if (packet.bytes.size() < ipv6_offset + kIpv6HeaderSize) {
            return {};
        }

        const auto version = static_cast<std::uint8_t>(packet.bytes[ipv6_offset] >> 4U);
        if (version != 6) {
            return {};
        }

        const auto payload = parse_ipv6_payload(packet.bytes, ipv6_offset);
        if (!payload.has_value()) {
            return {};
        }

        FlowKeyV6 flow_key {};
        for (std::size_t index = 0; index < 16; ++index) {
            flow_key.src_addr[index] = packet.bytes[ipv6_offset + 8 + index];
            flow_key.dst_addr[index] = packet.bytes[ipv6_offset + 24 + index];
        }

        if (payload->next_header == kIpProtocolTcp || payload->next_header == kIpProtocolUdp) {
            if (packet.bytes.size() < payload->payload_offset + kTransportPortsSize) {
                return {};
            }

            flow_key.src_port = read_be16(packet.bytes, payload->payload_offset);
            flow_key.dst_port = read_be16(packet.bytes, payload->payload_offset + 2);
            flow_key.protocol = (payload->next_header == kIpProtocolTcp) ? ProtocolId::tcp : ProtocolId::udp;

            return DecodedPacket {
                .ipv6 = IngestedPacketV6 {
                    .flow_key = flow_key,
                    .packet_ref = make_packet_ref(packet),
                },
            };
        }

        if (payload->next_header == kIpProtocolIcmpV6) {
            if (packet.bytes.size() < payload->payload_offset + 2) {
                return {};
            }

            flow_key.protocol = ProtocolId::icmpv6;
            return DecodedPacket {
                .ipv6 = IngestedPacketV6 {
                    .flow_key = flow_key,
                    .packet_ref = make_packet_ref(packet),
                },
            };
        }

        return {};
    }

    return {};
}

}  // namespace pfl
