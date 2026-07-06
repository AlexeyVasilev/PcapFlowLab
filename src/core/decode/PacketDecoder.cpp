#include "core/decode/PacketDecoder.h"

#include <algorithm>
#include <array>
#include <optional>
#include <span>

#include "core/decode/PacketDecodeSupport.h"

namespace pfl {

namespace {

PacketRef make_packet_ref(const RawPcapPacket& packet, const bool is_ip_fragmented = false) {
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
        .is_ip_fragmented = is_ip_fragmented,
    };
}

std::optional<DecodedPacket> decode_ipv4_transport_payload(
    std::span<const std::uint8_t> packet_bytes,
    const std::size_t ipv4_offset,
    const std::optional<std::size_t> bounded_packet_end,
    const RawPcapPacket& packet
) {
    const auto bounded_bytes = bounded_packet_end.has_value()
        ? packet_bytes.first(std::min(*bounded_packet_end, packet_bytes.size()))
        : packet_bytes;
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
    const auto packet_end = ipv4_bounds->packet_end;

    if (protocol == detail::kIpProtocolTcp) {
        if (transport_offset + detail::kTcpMinimumHeaderSize > packet_end ||
            bounded_bytes.size() < transport_offset + detail::kTcpMinimumHeaderSize) {
            return std::nullopt;
        }

        const auto tcp_header_length = static_cast<std::size_t>((bounded_bytes[transport_offset + 12U] >> 4U) * 4U);
        if (tcp_header_length < detail::kTcpMinimumHeaderSize ||
            transport_offset + tcp_header_length > packet_end ||
            bounded_bytes.size() < transport_offset + tcp_header_length) {
            return std::nullopt;
        }

        FlowKeyV4 flow_key {
            .src_addr = detail::read_be32(bounded_bytes, ipv4_offset + 12U),
            .dst_addr = detail::read_be32(bounded_bytes, ipv4_offset + 16U),
            .src_port = detail::read_be16(bounded_bytes, transport_offset),
            .dst_port = detail::read_be16(bounded_bytes, transport_offset + 2U),
            .protocol = ProtocolId::tcp,
        };

        auto packet_ref = make_packet_ref(packet);
        packet_ref.payload_length = static_cast<std::uint32_t>(packet_end - (transport_offset + tcp_header_length));
        packet_ref.tcp_flags = bounded_bytes[transport_offset + 13U];

        return DecodedPacket {
            .ipv4 = IngestedPacketV4 {
                .flow_key = flow_key,
                .packet_ref = packet_ref,
            },
        };
    }

    if (protocol == detail::kIpProtocolUdp) {
        if (transport_offset + detail::kUdpHeaderSize > packet_end ||
            bounded_bytes.size() < transport_offset + detail::kUdpHeaderSize) {
            return std::nullopt;
        }

        const auto udp_payload =
            detail::parse_udp_payload_bounds(bounded_bytes, transport_offset, ipv4_bounds->nominal_packet_end);
        if (!udp_payload.has_value()) {
            return std::nullopt;
        }

        FlowKeyV4 flow_key {
            .src_addr = detail::read_be32(bounded_bytes, ipv4_offset + 12U),
            .dst_addr = detail::read_be32(bounded_bytes, ipv4_offset + 16U),
            .src_port = detail::read_be16(bounded_bytes, transport_offset),
            .dst_port = detail::read_be16(bounded_bytes, transport_offset + 2U),
            .protocol = ProtocolId::udp,
        };

        auto packet_ref = make_packet_ref(packet);
        packet_ref.payload_length = static_cast<std::uint32_t>(udp_payload->payload_length);

        return DecodedPacket {
            .ipv4 = IngestedPacketV4 {
                .flow_key = flow_key,
                .packet_ref = packet_ref,
            },
        };
    }

    if (protocol == detail::kIpProtocolSctp) {
        const auto sctp = detail::parse_sctp_common_header(bounded_bytes, transport_offset, packet_end);
        if (!sctp.has_value()) {
            return std::nullopt;
        }

        FlowKeyV4 flow_key {
            .src_addr = detail::read_be32(bounded_bytes, ipv4_offset + 12U),
            .dst_addr = detail::read_be32(bounded_bytes, ipv4_offset + 16U),
            .src_port = sctp->src_port,
            .dst_port = sctp->dst_port,
            .protocol = ProtocolId::sctp,
        };

        auto packet_ref = make_packet_ref(packet);
        packet_ref.payload_length = static_cast<std::uint32_t>(sctp->payload_length);

        return DecodedPacket {
            .ipv4 = IngestedPacketV4 {
                .flow_key = flow_key,
                .packet_ref = packet_ref,
            },
        };
    }

    return std::nullopt;
}

std::optional<DecodedPacket> decode_ipv6_transport_payload(
    std::span<const std::uint8_t> packet_bytes,
    const std::size_t ipv6_offset,
    const std::optional<std::size_t> bounded_packet_end,
    const RawPcapPacket& packet
) {
    const auto bounded_bytes = bounded_packet_end.has_value()
        ? packet_bytes.first(std::min(*bounded_packet_end, packet_bytes.size()))
        : packet_bytes;
    if (bounded_bytes.size() < ipv6_offset + detail::kIpv6HeaderSize) {
        return std::nullopt;
    }

    const auto version = static_cast<std::uint8_t>(bounded_bytes[ipv6_offset] >> 4U);
    if (version != 6U) {
        return std::nullopt;
    }

    const auto ipv6_payload_length = static_cast<std::size_t>(detail::read_be16(bounded_bytes, ipv6_offset + 4U));
    const auto packet_end = std::min(ipv6_offset + detail::kIpv6HeaderSize + ipv6_payload_length, bounded_bytes.size());

    const auto payload = detail::parse_ipv6_payload(bounded_bytes, ipv6_offset);
    if (!payload.has_value() || payload->payload_offset > packet_end || payload->has_fragment_header) {
        return std::nullopt;
    }

    FlowKeyV6 flow_key {};
    for (std::size_t index = 0; index < 16U; ++index) {
        flow_key.src_addr[index] = bounded_bytes[ipv6_offset + 8U + index];
        flow_key.dst_addr[index] = bounded_bytes[ipv6_offset + 24U + index];
    }

    if (payload->next_header == detail::kIpProtocolTcp) {
        if (payload->payload_offset + detail::kTcpMinimumHeaderSize > packet_end ||
            bounded_bytes.size() < payload->payload_offset + detail::kTcpMinimumHeaderSize) {
            return std::nullopt;
        }

        const auto tcp_header_length = static_cast<std::size_t>((bounded_bytes[payload->payload_offset + 12U] >> 4U) * 4U);
        if (tcp_header_length < detail::kTcpMinimumHeaderSize ||
            payload->payload_offset + tcp_header_length > packet_end ||
            bounded_bytes.size() < payload->payload_offset + tcp_header_length) {
            return std::nullopt;
        }

        flow_key.src_port = detail::read_be16(bounded_bytes, payload->payload_offset);
        flow_key.dst_port = detail::read_be16(bounded_bytes, payload->payload_offset + 2U);
        flow_key.protocol = ProtocolId::tcp;

        auto packet_ref = make_packet_ref(packet);
        packet_ref.payload_length = static_cast<std::uint32_t>(packet_end - (payload->payload_offset + tcp_header_length));
        packet_ref.tcp_flags = bounded_bytes[payload->payload_offset + 13U];

        return DecodedPacket {
            .ipv6 = IngestedPacketV6 {
                .flow_key = flow_key,
                .packet_ref = packet_ref,
            },
        };
    }

    if (payload->next_header == detail::kIpProtocolUdp) {
        if (payload->payload_offset + detail::kUdpHeaderSize > packet_end ||
            bounded_bytes.size() < payload->payload_offset + detail::kUdpHeaderSize) {
            return std::nullopt;
        }

        const auto udp_payload = detail::parse_udp_payload_bounds(
            bounded_bytes,
            payload->payload_offset,
            ipv6_offset + detail::kIpv6HeaderSize + ipv6_payload_length
        );
        if (!udp_payload.has_value()) {
            return std::nullopt;
        }

        flow_key.src_port = detail::read_be16(bounded_bytes, payload->payload_offset);
        flow_key.dst_port = detail::read_be16(bounded_bytes, payload->payload_offset + 2U);
        flow_key.protocol = ProtocolId::udp;

        auto packet_ref = make_packet_ref(packet);
        packet_ref.payload_length = static_cast<std::uint32_t>(udp_payload->payload_length);

        return DecodedPacket {
            .ipv6 = IngestedPacketV6 {
                .flow_key = flow_key,
                .packet_ref = packet_ref,
            },
        };
    }

    if (payload->next_header == detail::kIpProtocolSctp) {
        const auto sctp = detail::parse_sctp_common_header(
            bounded_bytes,
            payload->payload_offset,
            packet_end
        );
        if (!sctp.has_value()) {
            return std::nullopt;
        }

        flow_key.src_port = sctp->src_port;
        flow_key.dst_port = sctp->dst_port;
        flow_key.protocol = ProtocolId::sctp;

        auto packet_ref = make_packet_ref(packet);
        packet_ref.payload_length = static_cast<std::uint32_t>(sctp->payload_length);

        return DecodedPacket {
            .ipv6 = IngestedPacketV6 {
                .flow_key = flow_key,
                .packet_ref = packet_ref,
            },
        };
    }

    return std::nullopt;
}

std::optional<DecodedPacket> decode_supported_ip_transport_payload(
    std::span<const std::uint8_t> packet_bytes,
    const std::uint16_t protocol_type,
    const std::size_t payload_offset,
    const std::optional<std::size_t> bounded_packet_end,
    const RawPcapPacket& packet
) {
    if (protocol_type == detail::kEtherTypeIpv4) {
        return decode_ipv4_transport_payload(packet_bytes, payload_offset, bounded_packet_end, packet);
    }
    if (protocol_type == detail::kEtherTypeIpv6) {
        return decode_ipv6_transport_payload(packet_bytes, payload_offset, bounded_packet_end, packet);
    }
    return std::nullopt;
}

std::optional<DecodedPacket> try_decode_vxlan_inner_packet(
    std::span<const std::uint8_t> packet_bytes,
    const std::size_t udp_payload_offset,
    const std::size_t udp_payload_length,
    const RawPcapPacket& packet
) {
    const auto udp_payload_end = udp_payload_offset + udp_payload_length;
    const auto vxlan = detail::parse_vxlan_payload(packet_bytes, udp_payload_offset, udp_payload_end);
    if (!vxlan.has_value() || !vxlan->resolved_supported_protocol) {
        return std::nullopt;
    }

    return decode_supported_ip_transport_payload(
        packet_bytes,
        vxlan->resolved_protocol_type,
        vxlan->resolved_payload_offset,
        vxlan->bounded_packet_end,
        packet
    );
}

std::optional<DecodedPacket> try_decode_geneve_inner_packet(
    std::span<const std::uint8_t> packet_bytes,
    const std::size_t udp_payload_offset,
    const std::size_t udp_payload_length,
    const RawPcapPacket& packet
) {
    const auto udp_payload_end = udp_payload_offset + udp_payload_length;
    const auto geneve = detail::parse_geneve_payload(packet_bytes, udp_payload_offset, udp_payload_end);
    if (!geneve.has_value() || !geneve->resolved_supported_protocol) {
        return std::nullopt;
    }

    return decode_supported_ip_transport_payload(
        packet_bytes,
        geneve->resolved_protocol_type,
        geneve->resolved_payload_offset,
        geneve->bounded_packet_end,
        packet
    );
}

std::optional<DecodedPacket> try_decode_gtpu_inner_packet(
    std::span<const std::uint8_t> packet_bytes,
    const std::size_t udp_payload_offset,
    const std::size_t udp_payload_length,
    const RawPcapPacket& packet
) {
    const auto udp_payload_end = udp_payload_offset + udp_payload_length;
    const auto gtpu = detail::parse_gtpu_payload(packet_bytes, udp_payload_offset, udp_payload_end);
    if (!gtpu.has_value() || !gtpu->resolved_supported_protocol) {
        return std::nullopt;
    }

    return decode_supported_ip_transport_payload(
        packet_bytes,
        gtpu->resolved_protocol_type,
        gtpu->resolved_payload_offset,
        gtpu->bounded_packet_end,
        packet
    );
}

}  // namespace

DecodedPacket PacketDecoder::decode_ethernet(const RawPcapPacket& packet) const noexcept {
    auto ethernet_packet = packet;
    ethernet_packet.data_link_type = kLinkTypeEthernet;
    return decode(ethernet_packet);
}

DecodedPacket PacketDecoder::decode(const RawPcapPacket& packet) const noexcept {
    const auto packet_bytes = std::span<const std::uint8_t>(packet.bytes.data(), packet.bytes.size());
    const auto network = detail::parse_network_payload(packet_bytes, packet.data_link_type);
    if (!network.has_value()) {
        return {};
    }
    const auto bounded_bytes = network->bounded_packet_end.has_value()
        ? packet_bytes.first(std::min(*network->bounded_packet_end, packet_bytes.size()))
        : packet_bytes;

    if (network->protocol_type == detail::kEtherTypeArp) {
        const auto arp_offset = network->payload_offset;
        if (bounded_bytes.size() < arp_offset + 8U) {
            return {};
        }

        const auto hardware_type = detail::read_be16(bounded_bytes, arp_offset);
        const auto protocol_type = detail::read_be16(bounded_bytes, arp_offset + 2U);
        const auto hardware_size = bounded_bytes[arp_offset + 4U];
        const auto protocol_size = bounded_bytes[arp_offset + 5U];
        static_cast<void>(hardware_type);
        if (protocol_type != detail::kArpProtocolTypeIpv4 || protocol_size != 4U || hardware_size == 0U) {
            return {};
        }

        const auto arp_length = static_cast<std::size_t>(8U + (2U * hardware_size) + (2U * protocol_size));
        if (bounded_bytes.size() < arp_offset + arp_length) {
            return {};
        }

        const auto sender_protocol_offset = arp_offset + 8U + hardware_size;
        const auto target_protocol_offset = arp_offset + 8U + (2U * hardware_size) + protocol_size;
        const auto flow_key = FlowKeyV4 {
            .src_addr = detail::read_be32(bounded_bytes, sender_protocol_offset),
            .dst_addr = detail::read_be32(bounded_bytes, target_protocol_offset),
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

    if (network->protocol_type == detail::kEtherTypeIpv4) {
        const auto ipv4_offset = network->payload_offset;
        const auto ipv4_bounds = detail::parse_ipv4_packet_bounds(bounded_bytes, ipv4_offset);
        if (!ipv4_bounds.has_value()) {
            return {};
        }

        const auto flags_fragment = detail::read_be16(bounded_bytes, ipv4_offset + 6U);
        const bool is_fragmented = (flags_fragment & 0x3FFFU) != 0U;

        const auto protocol = bounded_bytes[ipv4_offset + 9U];
        const auto transport_offset = ipv4_offset + ipv4_bounds->header_length;
        const auto packet_end = ipv4_bounds->packet_end;
        auto flow_base = FlowKeyV4 {
            .src_addr = detail::read_be32(bounded_bytes, ipv4_offset + 12U),
            .dst_addr = detail::read_be32(bounded_bytes, ipv4_offset + 16U),
        };

        if (is_fragmented) {
            switch (protocol) {
            case detail::kIpProtocolTcp:
                flow_base.protocol = ProtocolId::tcp;
                break;
            case detail::kIpProtocolUdp:
                flow_base.protocol = ProtocolId::udp;
                break;
            case detail::kIpProtocolSctp:
                flow_base.protocol = ProtocolId::sctp;
                break;
            case detail::kIpProtocolIcmp:
                flow_base.protocol = ProtocolId::icmp;
                break;
            case detail::kIpProtocolIgmp:
                flow_base.protocol = ProtocolId::igmp;
                break;
            default:
                return {};
            }

            return DecodedPacket {
                .ipv4 = IngestedPacketV4 {
                    .flow_key = flow_base,
                    .packet_ref = make_packet_ref(packet, true),
                },
            };
        }

        if (protocol == detail::kIpProtocolTcp) {
            if (transport_offset + detail::kTcpMinimumHeaderSize > packet_end ||
                bounded_bytes.size() < transport_offset + detail::kTcpMinimumHeaderSize) {
                return {};
            }

            const auto tcp_header_length = static_cast<std::size_t>((bounded_bytes[transport_offset + 12U] >> 4U) * 4U);
            if (tcp_header_length < detail::kTcpMinimumHeaderSize ||
                transport_offset + tcp_header_length > packet_end ||
                bounded_bytes.size() < transport_offset + tcp_header_length) {
                return {};
            }

            auto flow_key = flow_base;
            flow_key.src_port = detail::read_be16(bounded_bytes, transport_offset);
            flow_key.dst_port = detail::read_be16(bounded_bytes, transport_offset + 2U);
            flow_key.protocol = ProtocolId::tcp;

            auto packet_ref = make_packet_ref(packet);
            packet_ref.payload_length = static_cast<std::uint32_t>(packet_end - (transport_offset + tcp_header_length));
            packet_ref.tcp_flags = bounded_bytes[transport_offset + 13U];

            return DecodedPacket {
                .ipv4 = IngestedPacketV4 {
                    .flow_key = flow_key,
                    .packet_ref = packet_ref,
                },
            };
        }

        if (protocol == detail::kIpProtocolUdp) {
            if (transport_offset + detail::kUdpHeaderSize > packet_end ||
                bounded_bytes.size() < transport_offset + detail::kUdpHeaderSize) {
                return {};
            }

            const auto udp_length = detail::read_be16(bounded_bytes, transport_offset + 4U);
            if (udp_length < detail::kUdpHeaderSize) {
                return {};
            }

            auto flow_key = flow_base;
            flow_key.src_port = detail::read_be16(bounded_bytes, transport_offset);
            flow_key.dst_port = detail::read_be16(bounded_bytes, transport_offset + 2U);
            flow_key.protocol = ProtocolId::udp;
            const auto udp_payload =
                detail::parse_udp_payload_bounds(bounded_bytes, transport_offset, ipv4_bounds->nominal_packet_end);

            if (flow_key.dst_port == detail::kUdpPortVxlan ||
                flow_key.dst_port == detail::kUdpPortGeneve ||
                flow_key.dst_port == detail::kUdpPortGtpu) {
                if (udp_payload.has_value()) {
                    if (flow_key.dst_port == detail::kUdpPortVxlan) {
                        if (const auto vxlan_packet = try_decode_vxlan_inner_packet(
                                bounded_bytes,
                                udp_payload->payload_offset,
                                udp_payload->payload_length,
                                packet
                            );
                            vxlan_packet.has_value()) {
                            return *vxlan_packet;
                        }
                    } else if (flow_key.dst_port == detail::kUdpPortGeneve) {
                        if (const auto geneve_packet = try_decode_geneve_inner_packet(
                                bounded_bytes,
                                udp_payload->payload_offset,
                                udp_payload->payload_length,
                                packet
                            );
                            geneve_packet.has_value()) {
                            return *geneve_packet;
                        }
                    } else if (flow_key.dst_port == detail::kUdpPortGtpu) {
                        if (const auto gtpu_packet = try_decode_gtpu_inner_packet(
                                bounded_bytes,
                                udp_payload->payload_offset,
                                udp_payload->payload_length,
                                packet
                            );
                            gtpu_packet.has_value()) {
                            return *gtpu_packet;
                        }
                    }
                }
            }

            auto packet_ref = make_packet_ref(packet);
            if (udp_payload.has_value()) {
                packet_ref.payload_length = static_cast<std::uint32_t>(udp_payload->payload_length);
            } else {
                // Allow best-effort tuple extraction only when a higher-level bounded shim
                // has already constrained the visible packet bytes.
                if (!network->bounded_packet_end.has_value()) {
                    return {};
                }
                const auto payload_offset = transport_offset + detail::kUdpHeaderSize;
                packet_ref.payload_length = static_cast<std::uint32_t>(
                    packet_end > payload_offset ? (packet_end - payload_offset) : 0U);
            }

            return DecodedPacket {
                .ipv4 = IngestedPacketV4 {
                    .flow_key = flow_key,
                    .packet_ref = packet_ref,
                },
            };
        }

        if (protocol == detail::kIpProtocolSctp) {
            const auto sctp = detail::parse_sctp_common_header(
                bounded_bytes,
                transport_offset,
                ipv4_bounds->nominal_packet_end
            );
            if (!sctp.has_value()) {
                return {};
            }

            auto flow_key = flow_base;
            flow_key.src_port = sctp->src_port;
            flow_key.dst_port = sctp->dst_port;
            flow_key.protocol = ProtocolId::sctp;

            auto packet_ref = make_packet_ref(packet);
            packet_ref.payload_length = static_cast<std::uint32_t>(sctp->payload_length);

            return DecodedPacket {
                .ipv4 = IngestedPacketV4 {
                    .flow_key = flow_key,
                    .packet_ref = packet_ref,
                },
            };
        }

        if (protocol == detail::kIpProtocolIcmp) {
            if (bounded_bytes.size() < transport_offset + 2U) {
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

        if (protocol == detail::kIpProtocolIgmp) {
            const auto igmp = detail::parse_igmp_header(bounded_bytes, transport_offset, packet_end);
            if (!igmp.has_value() || igmp->available_length < detail::kIgmpMinimumHeaderSize) {
                return {};
            }

            auto flow_key = flow_base;
            flow_key.dst_addr = detail::igmp_effective_group_address(*igmp, flow_base.dst_addr);
            flow_key.protocol = ProtocolId::igmp;

            return DecodedPacket {
                .ipv4 = IngestedPacketV4 {
                    .flow_key = flow_key,
                    .packet_ref = make_packet_ref(packet),
                },
            };
        }

        return {};
    }

    if (network->protocol_type == detail::kEtherTypeIpv6) {
        const auto ipv6_offset = network->payload_offset;
        if (bounded_bytes.size() < ipv6_offset + detail::kIpv6HeaderSize) {
            return {};
        }

        const auto version = static_cast<std::uint8_t>(bounded_bytes[ipv6_offset] >> 4U);
        if (version != 6U) {
            return {};
        }

        const auto ipv6_payload_length = static_cast<std::size_t>(detail::read_be16(bounded_bytes, ipv6_offset + 4U));
        const auto packet_end = std::min(ipv6_offset + detail::kIpv6HeaderSize + ipv6_payload_length, bounded_bytes.size());

        const auto payload = detail::parse_ipv6_payload(bounded_bytes, ipv6_offset);
        if (!payload.has_value() || payload->payload_offset > packet_end) {
            return {};
        }

        FlowKeyV6 flow_key {};
        for (std::size_t index = 0; index < 16U; ++index) {
            flow_key.src_addr[index] = bounded_bytes[ipv6_offset + 8U + index];
            flow_key.dst_addr[index] = bounded_bytes[ipv6_offset + 24U + index];
        }

        if (payload->has_fragment_header) {
            switch (payload->next_header) {
            case detail::kIpProtocolTcp:
                flow_key.protocol = ProtocolId::tcp;
                break;
            case detail::kIpProtocolUdp:
                flow_key.protocol = ProtocolId::udp;
                break;
            case detail::kIpProtocolSctp:
                flow_key.protocol = ProtocolId::sctp;
                break;
            case detail::kIpProtocolIcmpV6:
                flow_key.protocol = ProtocolId::icmpv6;
                break;
            default:
                return {};
            }

            return DecodedPacket {
                .ipv6 = IngestedPacketV6 {
                    .flow_key = flow_key,
                    .packet_ref = make_packet_ref(packet, true),
                },
            };
        }

        if (payload->next_header == detail::kIpProtocolTcp) {
            if (payload->payload_offset + detail::kTcpMinimumHeaderSize > packet_end ||
                bounded_bytes.size() < payload->payload_offset + detail::kTcpMinimumHeaderSize) {
                return {};
            }

            const auto tcp_header_length = static_cast<std::size_t>((bounded_bytes[payload->payload_offset + 12U] >> 4U) * 4U);
            if (tcp_header_length < detail::kTcpMinimumHeaderSize ||
                payload->payload_offset + tcp_header_length > packet_end ||
                bounded_bytes.size() < payload->payload_offset + tcp_header_length) {
                return {};
            }

            flow_key.src_port = detail::read_be16(bounded_bytes, payload->payload_offset);
            flow_key.dst_port = detail::read_be16(bounded_bytes, payload->payload_offset + 2U);
            flow_key.protocol = ProtocolId::tcp;

            auto packet_ref = make_packet_ref(packet);
            packet_ref.payload_length = static_cast<std::uint32_t>(packet_end - (payload->payload_offset + tcp_header_length));
            packet_ref.tcp_flags = bounded_bytes[payload->payload_offset + 13U];

            return DecodedPacket {
                .ipv6 = IngestedPacketV6 {
                    .flow_key = flow_key,
                    .packet_ref = packet_ref,
                },
            };
        }

        if (payload->next_header == detail::kIpProtocolUdp) {
            if (payload->payload_offset + detail::kUdpHeaderSize > packet_end ||
                bounded_bytes.size() < payload->payload_offset + detail::kUdpHeaderSize) {
                return {};
            }

            const auto udp_length = detail::read_be16(bounded_bytes, payload->payload_offset + 4U);
            if (udp_length < detail::kUdpHeaderSize) {
                return {};
            }

            flow_key.src_port = detail::read_be16(bounded_bytes, payload->payload_offset);
            flow_key.dst_port = detail::read_be16(bounded_bytes, payload->payload_offset + 2U);
            flow_key.protocol = ProtocolId::udp;
            const auto udp_payload = detail::parse_udp_payload_bounds(
                bounded_bytes,
                payload->payload_offset,
                ipv6_offset + detail::kIpv6HeaderSize + ipv6_payload_length
            );

            if (flow_key.dst_port == detail::kUdpPortVxlan ||
                flow_key.dst_port == detail::kUdpPortGeneve ||
                flow_key.dst_port == detail::kUdpPortGtpu) {
                if (udp_payload.has_value()) {
                    if (flow_key.dst_port == detail::kUdpPortVxlan) {
                        if (const auto vxlan_packet = try_decode_vxlan_inner_packet(
                                bounded_bytes,
                                udp_payload->payload_offset,
                                udp_payload->payload_length,
                                packet
                            );
                            vxlan_packet.has_value()) {
                            return *vxlan_packet;
                        }
                    } else if (flow_key.dst_port == detail::kUdpPortGeneve) {
                        if (const auto geneve_packet = try_decode_geneve_inner_packet(
                                bounded_bytes,
                                udp_payload->payload_offset,
                                udp_payload->payload_length,
                                packet
                            );
                            geneve_packet.has_value()) {
                            return *geneve_packet;
                        }
                    } else if (flow_key.dst_port == detail::kUdpPortGtpu) {
                        if (const auto gtpu_packet = try_decode_gtpu_inner_packet(
                                bounded_bytes,
                                udp_payload->payload_offset,
                                udp_payload->payload_length,
                                packet
                            );
                            gtpu_packet.has_value()) {
                            return *gtpu_packet;
                        }
                    }
                }
            }

            auto packet_ref = make_packet_ref(packet);
            if (udp_payload.has_value()) {
                packet_ref.payload_length = static_cast<std::uint32_t>(udp_payload->payload_length);
            } else {
                if (!network->bounded_packet_end.has_value()) {
                    return {};
                }
                const auto payload_offset = payload->payload_offset + detail::kUdpHeaderSize;
                packet_ref.payload_length = static_cast<std::uint32_t>(
                    packet_end > payload_offset ? (packet_end - payload_offset) : 0U);
            }

            return DecodedPacket {
                .ipv6 = IngestedPacketV6 {
                    .flow_key = flow_key,
                    .packet_ref = packet_ref,
                },
            };
        }

        if (payload->next_header == detail::kIpProtocolSctp) {
            const auto sctp = detail::parse_sctp_common_header(
                bounded_bytes,
                payload->payload_offset,
                ipv6_offset + detail::kIpv6HeaderSize + ipv6_payload_length
            );
            if (!sctp.has_value()) {
                return {};
            }

            flow_key.src_port = sctp->src_port;
            flow_key.dst_port = sctp->dst_port;
            flow_key.protocol = ProtocolId::sctp;

            auto packet_ref = make_packet_ref(packet);
            packet_ref.payload_length = static_cast<std::uint32_t>(sctp->payload_length);

            return DecodedPacket {
                .ipv6 = IngestedPacketV6 {
                    .flow_key = flow_key,
                    .packet_ref = packet_ref,
                },
            };
        }

        if (payload->next_header == detail::kIpProtocolIcmpV6) {
            if (bounded_bytes.size() < payload->payload_offset + 2U) {
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
