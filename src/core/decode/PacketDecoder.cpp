#include "core/decode/PacketDecoder.h"

#include <algorithm>
#include <array>
#include <optional>
#include <span>

#include "core/decode/PacketDecodeSupport.h"

namespace pfl {

namespace {

PacketRef make_packet_ref(const RawPcapPacket& packet) {
    return PacketRef {
        .packet_index = packet.packet_index,
        .byte_offset = packet.data_offset,
        .data_link_type = packet.data_link_type,
        .captured_length = packet.captured_length,
        .original_length = packet.original_length,
        .ts_sec = packet.ts_sec,
        .ts_usec = packet.ts_usec,
        .payload_length = 0,
        .tcp_flags = 0,
    };
}

}  // namespace

DecodedPacket PacketDecoder::decode_ethernet(const RawPcapPacket& packet) const noexcept {
    auto ethernet_packet = packet;
    ethernet_packet.data_link_type = kLinkTypeEthernet;
    return decode(ethernet_packet);
}

DecodedPacket PacketDecoder::decode(const RawPcapPacket& packet) const noexcept {
    const auto packet_bytes = std::span<const std::uint8_t>(packet.bytes.data(), packet.bytes.size());
    const auto envelope = detail::parse_link_layer_payload(packet_bytes, packet.data_link_type);
    if (!envelope.has_value()) {
        return {};
    }

    if (envelope->protocol_type == detail::kEtherTypeArp) {
        const auto arp_offset = envelope->payload_offset;
        if (packet_bytes.size() < arp_offset + 8U) {
            return {};
        }

        const auto hardware_type = detail::read_be16(packet_bytes, arp_offset);
        const auto protocol_type = detail::read_be16(packet_bytes, arp_offset + 2U);
        const auto hardware_size = packet_bytes[arp_offset + 4U];
        const auto protocol_size = packet_bytes[arp_offset + 5U];
        static_cast<void>(hardware_type);
        if (protocol_type != detail::kArpProtocolTypeIpv4 || protocol_size != 4U || hardware_size == 0U) {
            return {};
        }

        const auto arp_length = static_cast<std::size_t>(8U + (2U * hardware_size) + (2U * protocol_size));
        if (packet_bytes.size() < arp_offset + arp_length) {
            return {};
        }

        const auto sender_protocol_offset = arp_offset + 8U + hardware_size;
        const auto target_protocol_offset = arp_offset + 8U + (2U * hardware_size) + protocol_size;
        const auto flow_key = FlowKeyV4 {
            .src_addr = detail::read_be32(packet_bytes, sender_protocol_offset),
            .dst_addr = detail::read_be32(packet_bytes, target_protocol_offset),
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

        if (packet_bytes.size() < ipv4_offset + ihl) {
            return {};
        }

        const auto flags_fragment = detail::read_be16(packet_bytes, ipv4_offset + 6U);
        if ((flags_fragment & 0x3FFFU) != 0U) {
            return {};
        }

        const auto protocol = packet_bytes[ipv4_offset + 9U];
        const auto transport_offset = ipv4_offset + ihl;
        const auto packet_end = std::min(ipv4_offset + total_length, packet_bytes.size());
        const auto flow_base = FlowKeyV4 {
            .src_addr = detail::read_be32(packet_bytes, ipv4_offset + 12U),
            .dst_addr = detail::read_be32(packet_bytes, ipv4_offset + 16U),
        };

        if (protocol == detail::kIpProtocolTcp) {
            if (transport_offset + detail::kTcpMinimumHeaderSize > packet_end ||
                packet_bytes.size() < transport_offset + detail::kTcpMinimumHeaderSize) {
                return {};
            }

            const auto tcp_header_length = static_cast<std::size_t>((packet_bytes[transport_offset + 12U] >> 4U) * 4U);
            if (tcp_header_length < detail::kTcpMinimumHeaderSize ||
                transport_offset + tcp_header_length > packet_end ||
                packet_bytes.size() < transport_offset + tcp_header_length) {
                return {};
            }

            auto flow_key = flow_base;
            flow_key.src_port = detail::read_be16(packet_bytes, transport_offset);
            flow_key.dst_port = detail::read_be16(packet_bytes, transport_offset + 2U);
            flow_key.protocol = ProtocolId::tcp;

            auto packet_ref = make_packet_ref(packet);
            packet_ref.payload_length = static_cast<std::uint32_t>(packet_end - (transport_offset + tcp_header_length));
            packet_ref.tcp_flags = packet_bytes[transport_offset + 13U];

            return DecodedPacket {
                .ipv4 = IngestedPacketV4 {
                    .flow_key = flow_key,
                    .packet_ref = packet_ref,
                },
            };
        }

        if (protocol == detail::kIpProtocolUdp) {
            if (transport_offset + detail::kUdpHeaderSize > packet_end ||
                packet_bytes.size() < transport_offset + detail::kUdpHeaderSize) {
                return {};
            }

            const auto udp_length = static_cast<std::size_t>(detail::read_be16(packet_bytes, transport_offset + 4U));
            if (udp_length < detail::kUdpHeaderSize || transport_offset + udp_length > packet_end) {
                return {};
            }

            auto flow_key = flow_base;
            flow_key.src_port = detail::read_be16(packet_bytes, transport_offset);
            flow_key.dst_port = detail::read_be16(packet_bytes, transport_offset + 2U);
            flow_key.protocol = ProtocolId::udp;

            auto packet_ref = make_packet_ref(packet);
            packet_ref.payload_length = static_cast<std::uint32_t>(udp_length - detail::kUdpHeaderSize);

            return DecodedPacket {
                .ipv4 = IngestedPacketV4 {
                    .flow_key = flow_key,
                    .packet_ref = packet_ref,
                },
            };
        }

        if (protocol == detail::kIpProtocolIcmp) {
            if (packet_bytes.size() < transport_offset + 2U) {
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
        const auto packet_end = std::min(ipv6_offset + detail::kIpv6HeaderSize + ipv6_payload_length, packet_bytes.size());

        const auto payload = detail::parse_ipv6_payload(packet_bytes, ipv6_offset);
        if (!payload.has_value() || payload->payload_offset > packet_end) {
            return {};
        }

        FlowKeyV6 flow_key {};
        for (std::size_t index = 0; index < 16U; ++index) {
            flow_key.src_addr[index] = packet_bytes[ipv6_offset + 8U + index];
            flow_key.dst_addr[index] = packet_bytes[ipv6_offset + 24U + index];
        }

        if (payload->next_header == detail::kIpProtocolTcp) {
            if (payload->payload_offset + detail::kTcpMinimumHeaderSize > packet_end ||
                packet_bytes.size() < payload->payload_offset + detail::kTcpMinimumHeaderSize) {
                return {};
            }

            const auto tcp_header_length = static_cast<std::size_t>((packet_bytes[payload->payload_offset + 12U] >> 4U) * 4U);
            if (tcp_header_length < detail::kTcpMinimumHeaderSize ||
                payload->payload_offset + tcp_header_length > packet_end ||
                packet_bytes.size() < payload->payload_offset + tcp_header_length) {
                return {};
            }

            flow_key.src_port = detail::read_be16(packet_bytes, payload->payload_offset);
            flow_key.dst_port = detail::read_be16(packet_bytes, payload->payload_offset + 2U);
            flow_key.protocol = ProtocolId::tcp;

            auto packet_ref = make_packet_ref(packet);
            packet_ref.payload_length = static_cast<std::uint32_t>(packet_end - (payload->payload_offset + tcp_header_length));
            packet_ref.tcp_flags = packet_bytes[payload->payload_offset + 13U];

            return DecodedPacket {
                .ipv6 = IngestedPacketV6 {
                    .flow_key = flow_key,
                    .packet_ref = packet_ref,
                },
            };
        }

        if (payload->next_header == detail::kIpProtocolUdp) {
            if (payload->payload_offset + detail::kUdpHeaderSize > packet_end ||
                packet_bytes.size() < payload->payload_offset + detail::kUdpHeaderSize) {
                return {};
            }

            const auto udp_length = static_cast<std::size_t>(detail::read_be16(packet_bytes, payload->payload_offset + 4U));
            if (udp_length < detail::kUdpHeaderSize || payload->payload_offset + udp_length > packet_end) {
                return {};
            }

            flow_key.src_port = detail::read_be16(packet_bytes, payload->payload_offset);
            flow_key.dst_port = detail::read_be16(packet_bytes, payload->payload_offset + 2U);
            flow_key.protocol = ProtocolId::udp;

            auto packet_ref = make_packet_ref(packet);
            packet_ref.payload_length = static_cast<std::uint32_t>(udp_length - detail::kUdpHeaderSize);

            return DecodedPacket {
                .ipv6 = IngestedPacketV6 {
                    .flow_key = flow_key,
                    .packet_ref = packet_ref,
                },
            };
        }

        if (payload->next_header == detail::kIpProtocolIcmpV6) {
            if (packet_bytes.size() < payload->payload_offset + 2U) {
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

