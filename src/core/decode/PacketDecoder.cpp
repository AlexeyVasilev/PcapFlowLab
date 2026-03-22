#include "core/decode/PacketDecoder.h"

#include <optional>

namespace pfl {

namespace {

constexpr std::size_t kEthernetHeaderSize = 14;
constexpr std::size_t kVlanHeaderSize = 4;
constexpr std::size_t kMaxVlanTags = 2;
constexpr std::uint16_t kEtherTypeIpv4 = 0x0800U;
constexpr std::uint16_t kEtherTypeIpv6 = 0x86DDU;
constexpr std::uint16_t kEtherTypeVlan = 0x8100U;
constexpr std::uint16_t kEtherTypeQinq = 0x88A8U;
constexpr std::uint8_t kIpProtocolTcp = 6;
constexpr std::uint8_t kIpProtocolUdp = 17;
constexpr std::size_t kIpv4MinimumHeaderSize = 20;
constexpr std::size_t kIpv6HeaderSize = 40;
constexpr std::size_t kTransportPortsSize = 4;

struct EthernetPayloadView {
    std::uint16_t ether_type {0};
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

        if (packet.bytes.size() < ipv4_offset + ihl + kTransportPortsSize) {
            return {};
        }

        const auto flags_fragment = read_be16(packet.bytes, ipv4_offset + 6);
        if ((flags_fragment & 0x3FFFU) != 0U) {
            return {};
        }

        const auto protocol = packet.bytes[ipv4_offset + 9];
        if (protocol != kIpProtocolTcp && protocol != kIpProtocolUdp) {
            return {};
        }

        const auto transport_offset = ipv4_offset + ihl;
        const auto flow_key = FlowKeyV4 {
            .src_addr = read_be32(packet.bytes, ipv4_offset + 12),
            .dst_addr = read_be32(packet.bytes, ipv4_offset + 16),
            .src_port = read_be16(packet.bytes, transport_offset),
            .dst_port = read_be16(packet.bytes, transport_offset + 2),
            .protocol = (protocol == kIpProtocolTcp) ? ProtocolId::tcp : ProtocolId::udp,
        };

        return DecodedPacket {
            .ipv4 = IngestedPacketV4 {
                .flow_key = flow_key,
                .packet_ref = make_packet_ref(packet),
            },
        };
    }

    if (ethernet->ether_type == kEtherTypeIpv6) {
        const auto ipv6_offset = ethernet->payload_offset;
        if (packet.bytes.size() < ipv6_offset + kIpv6HeaderSize + kTransportPortsSize) {
            return {};
        }

        const auto version = static_cast<std::uint8_t>(packet.bytes[ipv6_offset] >> 4U);
        if (version != 6) {
            return {};
        }

        const auto next_header = packet.bytes[ipv6_offset + 6];
        if (next_header != kIpProtocolTcp && next_header != kIpProtocolUdp) {
            return {};
        }

        FlowKeyV6 flow_key {};
        for (std::size_t index = 0; index < 16; ++index) {
            flow_key.src_addr[index] = packet.bytes[ipv6_offset + 8 + index];
            flow_key.dst_addr[index] = packet.bytes[ipv6_offset + 24 + index];
        }

        const auto transport_offset = ipv6_offset + kIpv6HeaderSize;
        flow_key.src_port = read_be16(packet.bytes, transport_offset);
        flow_key.dst_port = read_be16(packet.bytes, transport_offset + 2);
        flow_key.protocol = (next_header == kIpProtocolTcp) ? ProtocolId::tcp : ProtocolId::udp;

        return DecodedPacket {
            .ipv6 = IngestedPacketV6 {
                .flow_key = flow_key,
                .packet_ref = make_packet_ref(packet),
            },
        };
    }

    return {};
}

}  // namespace pfl
