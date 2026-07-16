#include "core/decode/PacketDecoder.h"

#include <algorithm>
#include <array>
#include <optional>
#include <span>
#include <utility>

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

DecodedPacket make_decoded_packet(const IngestedPacketV4& packet, const ProtocolPathBuilder& builder) {
    return DecodedPacket {
        .ipv4 = packet,
        .protocol_path_builder = builder,
    };
}

DecodedPacket make_decoded_packet(const IngestedPacketV6& packet, const ProtocolPathBuilder& builder) {
    return DecodedPacket {
        .ipv6 = packet,
        .protocol_path_builder = builder,
    };
}

void push_link_layer_path(
    ProtocolPathBuilder& builder,
    std::span<const std::uint8_t> packet_bytes,
    const std::uint32_t data_link_type,
    const std::size_t link_layer_offset
) {
    if (data_link_type == kLinkTypeEthernet) {
        if (packet_bytes.size() < link_layer_offset + detail::kEthernetHeaderSize) {
            return;
        }

        std::uint16_t protocol_type = detail::read_be16(packet_bytes, link_layer_offset + 12U);
        auto payload_offset = link_layer_offset + detail::kEthernetHeaderSize;
        static_cast<void>(
            builder.push(protocol_type < detail::kIeee8023LengthCutoff ? LayerKey::ieee8023() : LayerKey::ethernet_ii()));

        std::size_t vlan_count = 0U;
        while (detail::is_vlan_ether_type(protocol_type)) {
            if (vlan_count == detail::kMaxVlanTags ||
                packet_bytes.size() < payload_offset + detail::kVlanHeaderSize) {
                return;
            }

            const auto tci = detail::read_be16(packet_bytes, payload_offset);
            static_cast<void>(builder.push(LayerKey::vlan(static_cast<std::uint16_t>(tci & 0x0FFFU))));
            protocol_type = detail::read_be16(packet_bytes, payload_offset + 2U);
            payload_offset += detail::kVlanHeaderSize;
            ++vlan_count;
        }
        return;
    }

    if (data_link_type == kLinkTypeLinuxSll) {
        static_cast<void>(builder.push(LayerKey::linux_sll()));
        return;
    }

    if (data_link_type == kLinkTypeLinuxSll2) {
        static_cast<void>(builder.push(LayerKey::linux_sll2()));
    }
}

void push_llc_snap_path_if_resolved(
    ProtocolPathBuilder& builder,
    const detail::LinkLayerPayloadView& link_layer,
    const std::uint16_t resolved_protocol_type
) {
    if (link_layer.is_ieee_802_3 &&
        (resolved_protocol_type == detail::kEtherTypeArp ||
         resolved_protocol_type == detail::kEtherTypeIpv4 ||
         resolved_protocol_type == detail::kEtherTypeIpv6)) {
        static_cast<void>(builder.push(LayerKey::llc_snap()));
    }
}

void push_outer_protocol_path(
    ProtocolPathBuilder& builder,
    std::span<const std::uint8_t> packet_bytes,
    const detail::NetworkPayloadView& network,
    const std::uint32_t data_link_type
) {
    push_link_layer_path(builder, packet_bytes, data_link_type, 0U);
    push_llc_snap_path_if_resolved(builder, network.link_layer, network.protocol_type);

    if (network.has_pppoe &&
        (network.ppp_protocol == detail::kPppProtocolIpv4 ||
         network.ppp_protocol == detail::kPppProtocolIpv6)) {
        static_cast<void>(builder.push(LayerKey::pppoe()));
        static_cast<void>(builder.push(LayerKey::ppp()));
    }

    if (network.has_mpls) {
        for (std::size_t index = 0U; index < network.mpls.label_count; ++index) {
            static_cast<void>(builder.push(LayerKey::mpls(network.mpls.labels[index].label)));
        }

        if (network.mpls.has_inner_ethernet) {
            static_cast<void>(builder.push(LayerKey::mpls_pw()));
            push_link_layer_path(builder, packet_bytes, kLinkTypeEthernet, network.mpls.inner_ethernet_offset);
            push_llc_snap_path_if_resolved(builder, network.mpls.inner_ethernet, network.mpls.inner_protocol_type);
        }
    }

    if (network.has_pbb && detail::pbb_has_resolved_inner_payload(network.pbb.status)) {
        static_cast<void>(builder.push(LayerKey::pbb(network.pbb.isid)));
        if (network.pbb.has_inner_ethernet) {
            push_link_layer_path(builder, packet_bytes, kLinkTypeEthernet, network.pbb.inner_ethernet_offset);
            push_llc_snap_path_if_resolved(builder, network.pbb.inner_ethernet, network.pbb.inner_protocol_type);
        }
    }
}

std::optional<DecodedPacket> decode_ipv4_transport_payload(
    std::span<const std::uint8_t> packet_bytes,
    const std::size_t ipv4_offset,
    const std::optional<std::size_t> bounded_packet_end,
    const RawPcapPacket& packet,
    ProtocolPathBuilder builder
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
        static_cast<void>(builder.push(LayerKey::ipv4()));
        static_cast<void>(builder.push(LayerKey::tcp()));

        return make_decoded_packet(
            IngestedPacketV4 {
                .flow_key = flow_key,
                .packet_ref = packet_ref,
            },
            builder
        );
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
        static_cast<void>(builder.push(LayerKey::ipv4()));
        static_cast<void>(builder.push(LayerKey::udp()));

        return make_decoded_packet(
            IngestedPacketV4 {
                .flow_key = flow_key,
                .packet_ref = packet_ref,
            },
            builder
        );
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
        static_cast<void>(builder.push(LayerKey::ipv4()));
        static_cast<void>(builder.push(LayerKey::sctp()));

        return make_decoded_packet(
            IngestedPacketV4 {
                .flow_key = flow_key,
                .packet_ref = packet_ref,
            },
            builder
        );
    }

    return std::nullopt;
}

std::optional<DecodedPacket> decode_ipv6_transport_payload(
    std::span<const std::uint8_t> packet_bytes,
    const std::size_t ipv6_offset,
    const std::optional<std::size_t> bounded_packet_end,
    const RawPcapPacket& packet,
    ProtocolPathBuilder builder
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
    if (detail::parse_ipv6_authentication_payload(bounded_bytes, ipv6_offset).has_value()) {
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
        static_cast<void>(builder.push(LayerKey::ipv6()));
        static_cast<void>(builder.push(LayerKey::tcp()));

        return make_decoded_packet(
            IngestedPacketV6 {
                .flow_key = flow_key,
                .packet_ref = packet_ref,
            },
            builder
        );
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
        static_cast<void>(builder.push(LayerKey::ipv6()));
        static_cast<void>(builder.push(LayerKey::udp()));

        return make_decoded_packet(
            IngestedPacketV6 {
                .flow_key = flow_key,
                .packet_ref = packet_ref,
            },
            builder
        );
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
        static_cast<void>(builder.push(LayerKey::ipv6()));
        static_cast<void>(builder.push(LayerKey::sctp()));

        return make_decoded_packet(
            IngestedPacketV6 {
                .flow_key = flow_key,
                .packet_ref = packet_ref,
            },
            builder
        );
    }

    return std::nullopt;
}

std::optional<DecodedPacket> try_decode_direct_ipv4_ah_transport_packet(
    std::span<const std::uint8_t> bounded_bytes,
    const detail::Ipv4PacketBounds& ipv4_bounds,
    const std::size_t ah_offset,
    const FlowKeyV4& flow_base,
    const RawPcapPacket& packet,
    ProtocolPathBuilder ipv4_builder
) {
    const auto ah = detail::parse_ah_header(
        bounded_bytes,
        ah_offset,
        ipv4_bounds.nominal_packet_end
    );
    if (!ah.has_value()) {
        return std::nullopt;
    }

    auto builder = ipv4_builder;
    static_cast<void>(builder.push(LayerKey::ah(ah->spi)));

    if (ah->next_header == detail::kIpProtocolIpv4Encapsulation) {
        return decode_ipv4_transport_payload(
            bounded_bytes,
            ah->payload_offset,
            ipv4_bounds.nominal_packet_end,
            packet,
            builder
        );
    }

    if (ah->next_header == detail::kIpProtocolIpv6Encapsulation) {
        return decode_ipv6_transport_payload(
            bounded_bytes,
            ah->payload_offset,
            ipv4_bounds.nominal_packet_end,
            packet,
            builder
        );
    }

    if (ah->next_header == detail::kIpProtocolTcp) {
        if (ah->payload_offset + detail::kTcpMinimumHeaderSize > ipv4_bounds.packet_end ||
            bounded_bytes.size() < ah->payload_offset + detail::kTcpMinimumHeaderSize) {
            return std::nullopt;
        }

        const auto tcp_header_length =
            static_cast<std::size_t>((bounded_bytes[ah->payload_offset + 12U] >> 4U) * 4U);
        if (tcp_header_length < detail::kTcpMinimumHeaderSize ||
            ah->payload_offset + tcp_header_length > ipv4_bounds.packet_end ||
            bounded_bytes.size() < ah->payload_offset + tcp_header_length) {
            return std::nullopt;
        }

        auto flow_key = flow_base;
        flow_key.src_port = detail::read_be16(bounded_bytes, ah->payload_offset);
        flow_key.dst_port = detail::read_be16(bounded_bytes, ah->payload_offset + 2U);
        flow_key.protocol = ProtocolId::tcp;

        auto packet_ref = make_packet_ref(packet);
        packet_ref.payload_length = static_cast<std::uint32_t>(
            ipv4_bounds.packet_end - (ah->payload_offset + tcp_header_length)
        );
        packet_ref.tcp_flags = bounded_bytes[ah->payload_offset + 13U];
        static_cast<void>(builder.push(LayerKey::tcp()));

        return make_decoded_packet(
            IngestedPacketV4 {
                .flow_key = flow_key,
                .packet_ref = packet_ref,
            },
            builder
        );
    }

    if (ah->next_header == detail::kIpProtocolUdp) {
        if (ah->payload_offset + detail::kUdpHeaderSize > ipv4_bounds.packet_end ||
            bounded_bytes.size() < ah->payload_offset + detail::kUdpHeaderSize) {
            return std::nullopt;
        }

        const auto udp_payload = detail::parse_udp_payload_bounds(
            bounded_bytes,
            ah->payload_offset,
            ipv4_bounds.nominal_packet_end
        );
        if (!udp_payload.has_value()) {
            return std::nullopt;
        }

        auto flow_key = flow_base;
        flow_key.src_port = detail::read_be16(bounded_bytes, ah->payload_offset);
        flow_key.dst_port = detail::read_be16(bounded_bytes, ah->payload_offset + 2U);
        flow_key.protocol = ProtocolId::udp;

        auto packet_ref = make_packet_ref(packet);
        packet_ref.payload_length = static_cast<std::uint32_t>(udp_payload->payload_length);
        static_cast<void>(builder.push(LayerKey::udp()));

        return make_decoded_packet(
            IngestedPacketV4 {
                .flow_key = flow_key,
                .packet_ref = packet_ref,
            },
            builder
        );
    }

    return std::nullopt;
}

std::optional<DecodedPacket> try_decode_direct_ipv6_ah_transport_packet(
    std::span<const std::uint8_t> bounded_bytes,
    const std::size_t nominal_packet_end,
    const std::size_t packet_end,
    const std::size_t ah_offset,
    const FlowKeyV6& flow_base,
    const RawPcapPacket& packet,
    ProtocolPathBuilder ipv6_builder
) {
    const auto ah = detail::parse_ah_header(
        bounded_bytes,
        ah_offset,
        nominal_packet_end
    );
    if (!ah.has_value()) {
        return std::nullopt;
    }

    auto builder = ipv6_builder;
    static_cast<void>(builder.push(LayerKey::ah(ah->spi)));

    if (ah->next_header == detail::kIpProtocolIpv4Encapsulation) {
        return decode_ipv4_transport_payload(
            bounded_bytes,
            ah->payload_offset,
            nominal_packet_end,
            packet,
            builder
        );
    }

    if (ah->next_header == detail::kIpProtocolIpv6Encapsulation) {
        return decode_ipv6_transport_payload(
            bounded_bytes,
            ah->payload_offset,
            nominal_packet_end,
            packet,
            builder
        );
    }

    if (ah->next_header == detail::kIpProtocolTcp) {
        if (ah->payload_offset + detail::kTcpMinimumHeaderSize > packet_end ||
            bounded_bytes.size() < ah->payload_offset + detail::kTcpMinimumHeaderSize) {
            return std::nullopt;
        }

        const auto tcp_header_length =
            static_cast<std::size_t>((bounded_bytes[ah->payload_offset + 12U] >> 4U) * 4U);
        if (tcp_header_length < detail::kTcpMinimumHeaderSize ||
            ah->payload_offset + tcp_header_length > packet_end ||
            bounded_bytes.size() < ah->payload_offset + tcp_header_length) {
            return std::nullopt;
        }

        auto flow_key = flow_base;
        flow_key.src_port = detail::read_be16(bounded_bytes, ah->payload_offset);
        flow_key.dst_port = detail::read_be16(bounded_bytes, ah->payload_offset + 2U);
        flow_key.protocol = ProtocolId::tcp;

        auto packet_ref = make_packet_ref(packet);
        packet_ref.payload_length = static_cast<std::uint32_t>(
            packet_end - (ah->payload_offset + tcp_header_length)
        );
        packet_ref.tcp_flags = bounded_bytes[ah->payload_offset + 13U];
        static_cast<void>(builder.push(LayerKey::tcp()));

        return make_decoded_packet(
            IngestedPacketV6 {
                .flow_key = flow_key,
                .packet_ref = packet_ref,
            },
            builder
        );
    }

    if (ah->next_header == detail::kIpProtocolUdp) {
        if (ah->payload_offset + detail::kUdpHeaderSize > packet_end ||
            bounded_bytes.size() < ah->payload_offset + detail::kUdpHeaderSize) {
            return std::nullopt;
        }

        const auto udp_payload = detail::parse_udp_payload_bounds(
            bounded_bytes,
            ah->payload_offset,
            nominal_packet_end
        );
        if (!udp_payload.has_value()) {
            return std::nullopt;
        }

        auto flow_key = flow_base;
        flow_key.src_port = detail::read_be16(bounded_bytes, ah->payload_offset);
        flow_key.dst_port = detail::read_be16(bounded_bytes, ah->payload_offset + 2U);
        flow_key.protocol = ProtocolId::udp;

        auto packet_ref = make_packet_ref(packet);
        packet_ref.payload_length = static_cast<std::uint32_t>(udp_payload->payload_length);
        static_cast<void>(builder.push(LayerKey::udp()));

        return make_decoded_packet(
            IngestedPacketV6 {
                .flow_key = flow_key,
                .packet_ref = packet_ref,
            },
            builder
        );
    }

    return std::nullopt;
}

std::optional<DecodedPacket> decode_supported_ip_transport_payload(
    std::span<const std::uint8_t> packet_bytes,
    const std::uint16_t protocol_type,
    const std::size_t payload_offset,
    const std::optional<std::size_t> bounded_packet_end,
    const RawPcapPacket& packet,
    ProtocolPathBuilder builder
) {
    if (protocol_type == detail::kEtherTypeIpv4) {
        return decode_ipv4_transport_payload(packet_bytes, payload_offset, bounded_packet_end, packet, std::move(builder));
    }
    if (protocol_type == detail::kEtherTypeIpv6) {
        return decode_ipv6_transport_payload(packet_bytes, payload_offset, bounded_packet_end, packet, std::move(builder));
    }
    return std::nullopt;
}

std::optional<DecodedPacket> try_decode_ipv4_encapsulated_inner_packet(
    std::span<const std::uint8_t> packet_bytes,
    const std::size_t inner_ipv4_offset,
    const std::size_t outer_ipv4_packet_end,
    const RawPcapPacket& packet,
    ProtocolPathBuilder builder
) {
    const auto decoded = decode_ipv4_transport_payload(
        packet_bytes,
        inner_ipv4_offset,
        outer_ipv4_packet_end,
        packet,
        std::move(builder)
    );
    if (!decoded.has_value() || !decoded->ipv4.has_value()) {
        return std::nullopt;
    }

    const auto protocol = decoded->ipv4->flow_key.protocol;
    if (protocol != ProtocolId::tcp && protocol != ProtocolId::udp) {
        return std::nullopt;
    }

    return decoded;
}

std::optional<DecodedPacket> try_decode_plain_ipv4_encapsulated_inner_packet(
    std::span<const std::uint8_t> packet_bytes,
    const std::size_t inner_ipv4_offset,
    const std::size_t outer_ipv4_packet_end,
    const RawPcapPacket& packet,
    ProtocolPathBuilder builder
) {
    if (const auto direct = try_decode_ipv4_encapsulated_inner_packet(
            packet_bytes,
            inner_ipv4_offset,
            outer_ipv4_packet_end,
            packet,
            builder
        );
        direct.has_value()) {
        return direct;
    }

    const auto bounded_bytes = packet_bytes.first(std::min(outer_ipv4_packet_end, packet_bytes.size()));
    const auto middle_ipv4_bounds = detail::parse_ipv4_packet_bounds(bounded_bytes, inner_ipv4_offset);
    if (!middle_ipv4_bounds.has_value() ||
        middle_ipv4_bounds->nominal_packet_end > bounded_bytes.size()) {
        return std::nullopt;
    }

    const auto middle_flags_fragment = detail::read_be16(bounded_bytes, inner_ipv4_offset + 6U);
    if ((middle_flags_fragment & 0x3FFFU) != 0U) {
        return std::nullopt;
    }

    const auto inner_protocol = bounded_bytes[inner_ipv4_offset + 9U];
    if (inner_protocol == detail::kIpProtocolIcmp) {
        const auto transport_offset = inner_ipv4_offset + middle_ipv4_bounds->header_length;
        if (transport_offset + 2U > middle_ipv4_bounds->packet_end ||
            bounded_bytes.size() < transport_offset + 2U) {
            return std::nullopt;
        }

        auto builder_with_inner_ipv4 = builder;
        static_cast<void>(builder_with_inner_ipv4.push(LayerKey::ipv4()));

        return make_decoded_packet(
            IngestedPacketV4 {
                .flow_key = FlowKeyV4 {
                    .src_addr = detail::read_be32(bounded_bytes, inner_ipv4_offset + 12U),
                    .dst_addr = detail::read_be32(bounded_bytes, inner_ipv4_offset + 16U),
                    .src_port = 0U,
                    .dst_port = 0U,
                    .protocol = ProtocolId::icmp,
                },
                .packet_ref = make_packet_ref(packet),
            },
            builder_with_inner_ipv4
        );
    }

    const auto middle_protocol = bounded_bytes[inner_ipv4_offset + 9U];
    if (middle_protocol != detail::kIpProtocolIpv4Encapsulation) {
        return std::nullopt;
    }

    const auto inner_ipv4_nested_offset = inner_ipv4_offset + middle_ipv4_bounds->header_length;
    if (inner_ipv4_nested_offset >= middle_ipv4_bounds->packet_end) {
        return std::nullopt;
    }

    const auto middle_bounded_bytes = bounded_bytes.first(middle_ipv4_bounds->packet_end);
    const auto inner_ipv4_bounds = detail::parse_ipv4_packet_bounds(middle_bounded_bytes, inner_ipv4_nested_offset);
    if (!inner_ipv4_bounds.has_value() ||
        inner_ipv4_bounds->nominal_packet_end > middle_ipv4_bounds->packet_end) {
        return std::nullopt;
    }

    auto nested_builder = builder;
    static_cast<void>(nested_builder.push(LayerKey::ipv4()));

    const auto decoded = decode_ipv4_transport_payload(
        packet_bytes,
        inner_ipv4_nested_offset,
        middle_ipv4_bounds->packet_end,
        packet,
        std::move(nested_builder)
    );
    if (!decoded.has_value() || !decoded->ipv4.has_value()) {
        return std::nullopt;
    }

    const auto protocol = decoded->ipv4->flow_key.protocol;
    if (protocol != ProtocolId::tcp && protocol != ProtocolId::udp) {
        return std::nullopt;
    }

    return decoded;
}

std::optional<DecodedPacket> try_decode_ipv6_encapsulated_inner_packet(
    std::span<const std::uint8_t> packet_bytes,
    const std::size_t inner_ipv6_offset,
    const std::size_t outer_ipv4_packet_end,
    const RawPcapPacket& packet,
    ProtocolPathBuilder builder
) {
    const auto decoded = decode_ipv6_transport_payload(
        packet_bytes,
        inner_ipv6_offset,
        outer_ipv4_packet_end,
        packet,
        std::move(builder)
    );
    if (!decoded.has_value() || !decoded->ipv6.has_value()) {
        return std::nullopt;
    }

    const auto protocol = decoded->ipv6->flow_key.protocol;
    if (protocol != ProtocolId::tcp && protocol != ProtocolId::udp) {
        return std::nullopt;
    }

    return decoded;
}

std::optional<DecodedPacket> try_decode_plain_ipv6_encapsulated_inner_packet(
    std::span<const std::uint8_t> packet_bytes,
    const std::size_t inner_ipv6_offset,
    const std::size_t outer_ipv4_packet_end,
    const RawPcapPacket& packet,
    ProtocolPathBuilder builder
) {
    if (const auto direct = try_decode_ipv6_encapsulated_inner_packet(
            packet_bytes,
            inner_ipv6_offset,
            outer_ipv4_packet_end,
            packet,
            builder
        );
        direct.has_value()) {
        return direct;
    }

    const auto bounded_bytes = packet_bytes.first(std::min(outer_ipv4_packet_end, packet_bytes.size()));
    if (bounded_bytes.size() < inner_ipv6_offset + detail::kIpv6HeaderSize) {
        return std::nullopt;
    }

    const auto version = static_cast<std::uint8_t>(bounded_bytes[inner_ipv6_offset] >> 4U);
    if (version != 6U) {
        return std::nullopt;
    }

    const auto ipv6_payload_length = static_cast<std::size_t>(detail::read_be16(bounded_bytes, inner_ipv6_offset + 4U));
    const auto packet_end =
        std::min(inner_ipv6_offset + detail::kIpv6HeaderSize + ipv6_payload_length, bounded_bytes.size());

    const auto payload = detail::parse_ipv6_payload(bounded_bytes, inner_ipv6_offset);
    if (!payload.has_value() ||
        payload->payload_offset > packet_end ||
        payload->has_fragment_header ||
        payload->next_header != detail::kIpProtocolIcmpV6 ||
        payload->payload_offset + 2U > packet_end ||
        bounded_bytes.size() < payload->payload_offset + 2U) {
        return std::nullopt;
    }

    FlowKeyV6 flow_key {};
    for (std::size_t index = 0; index < 16U; ++index) {
        flow_key.src_addr[index] = bounded_bytes[inner_ipv6_offset + 8U + index];
        flow_key.dst_addr[index] = bounded_bytes[inner_ipv6_offset + 24U + index];
    }
    flow_key.protocol = ProtocolId::icmpv6;

    auto builder_with_inner_ipv6 = builder;
    static_cast<void>(builder_with_inner_ipv6.push(LayerKey::ipv6()));

    return make_decoded_packet(
        IngestedPacketV6 {
            .flow_key = flow_key,
            .packet_ref = make_packet_ref(packet),
        },
        builder_with_inner_ipv6
    );
}

std::optional<DecodedPacket> try_decode_vxlan_inner_packet(
    std::span<const std::uint8_t> packet_bytes,
    const std::size_t udp_payload_offset,
    const std::size_t udp_payload_length,
    const RawPcapPacket& packet,
    ProtocolPathBuilder builder
) {
    const auto udp_payload_end = udp_payload_offset + udp_payload_length;
    const auto vxlan = detail::parse_vxlan_payload(packet_bytes, udp_payload_offset, udp_payload_end);
    if (!vxlan.has_value() || !vxlan->resolved_supported_protocol) {
        return std::nullopt;
    }

    static_cast<void>(builder.push(LayerKey::vxlan(vxlan->vni)));
    if (vxlan->has_inner_ethernet) {
        push_link_layer_path(builder, packet_bytes, kLinkTypeEthernet, vxlan->inner_ethernet_offset);
        push_llc_snap_path_if_resolved(builder, vxlan->inner_ethernet, vxlan->resolved_protocol_type);
    }

    return decode_supported_ip_transport_payload(
        packet_bytes,
        vxlan->resolved_protocol_type,
        vxlan->resolved_payload_offset,
        vxlan->bounded_packet_end,
        packet,
        std::move(builder)
    );
}

std::optional<DecodedPacket> try_decode_geneve_inner_packet(
    std::span<const std::uint8_t> packet_bytes,
    const std::size_t udp_payload_offset,
    const std::size_t udp_payload_length,
    const RawPcapPacket& packet,
    ProtocolPathBuilder builder
) {
    const auto udp_payload_end = udp_payload_offset + udp_payload_length;
    const auto geneve = detail::parse_geneve_payload(packet_bytes, udp_payload_offset, udp_payload_end);
    if (!geneve.has_value() || !geneve->resolved_supported_protocol) {
        return std::nullopt;
    }

    static_cast<void>(builder.push(LayerKey::geneve(geneve->vni)));
    if (geneve->has_inner_ethernet) {
        push_link_layer_path(builder, packet_bytes, kLinkTypeEthernet, geneve->inner_ethernet_offset);
        push_llc_snap_path_if_resolved(builder, geneve->inner_ethernet, geneve->resolved_protocol_type);
    }

    return decode_supported_ip_transport_payload(
        packet_bytes,
        geneve->resolved_protocol_type,
        geneve->resolved_payload_offset,
        geneve->bounded_packet_end,
        packet,
        std::move(builder)
    );
}

std::optional<DecodedPacket> try_decode_gtpu_inner_packet(
    std::span<const std::uint8_t> packet_bytes,
    const std::size_t udp_payload_offset,
    const std::size_t udp_payload_length,
    const RawPcapPacket& packet,
    ProtocolPathBuilder builder
) {
    const auto udp_payload_end = udp_payload_offset + udp_payload_length;
    const auto gtpu = detail::parse_gtpu_payload(packet_bytes, udp_payload_offset, udp_payload_end);
    if (!gtpu.has_value() || !gtpu->resolved_supported_protocol) {
        return std::nullopt;
    }

    static_cast<void>(builder.push(LayerKey::gtpu(gtpu->teid)));

    return decode_supported_ip_transport_payload(
        packet_bytes,
        gtpu->resolved_protocol_type,
        gtpu->resolved_payload_offset,
        gtpu->bounded_packet_end,
        packet,
        std::move(builder)
    );
}

std::optional<DecodedPacket> try_decode_gre_inner_packet(
    std::span<const std::uint8_t> packet_bytes,
    const std::size_t gre_offset,
    const std::size_t gre_payload_end,
    const RawPcapPacket& packet,
    ProtocolPathBuilder builder
) {
    const auto gre = detail::parse_gre_payload(packet_bytes, gre_offset, gre_payload_end);
    if (!gre.has_value() || !gre->resolved_supported_protocol) {
        return std::nullopt;
    }

    static_cast<void>(builder.push(gre->has_key ? LayerKey::gre(gre->key) : LayerKey::gre()));
    if (gre->has_inner_ethernet) {
        push_link_layer_path(builder, packet_bytes, kLinkTypeEthernet, gre->inner_ethernet_offset);
        push_llc_snap_path_if_resolved(builder, gre->inner_ethernet, gre->resolved_protocol_type);
    } else if (gre->protocol_type == detail::kEtherTypeMplsUnicast) {
        const auto mpls = detail::parse_mpls_stack(packet_bytes, gre->payload_offset);
        if (!detail::mpls_has_resolved_inner_payload(mpls.status)) {
            return std::nullopt;
        }

        for (std::size_t index = 0U; index < mpls.label_count; ++index) {
            static_cast<void>(builder.push(LayerKey::mpls(mpls.labels[index].label)));
        }

        if (mpls.has_inner_ethernet) {
            static_cast<void>(builder.push(LayerKey::mpls_pw()));
            push_link_layer_path(builder, packet_bytes, kLinkTypeEthernet, mpls.inner_ethernet_offset);
            push_llc_snap_path_if_resolved(builder, mpls.inner_ethernet, mpls.inner_protocol_type);
        }
    }
    return decode_supported_ip_transport_payload(
        packet_bytes,
        gre->resolved_protocol_type,
        gre->resolved_payload_offset,
        gre->bounded_packet_end,
        packet,
        std::move(builder)
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
    ProtocolPathBuilder base_builder {};
    push_outer_protocol_path(base_builder, packet_bytes, *network, packet.data_link_type);
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
        auto builder = base_builder;
        return make_decoded_packet(
            IngestedPacketV4 {
                .flow_key = flow_key,
                .packet_ref = make_packet_ref(packet),
            },
            builder
        );
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
        auto ipv4_builder = base_builder;
        static_cast<void>(ipv4_builder.push(LayerKey::ipv4()));

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

            return make_decoded_packet(
                IngestedPacketV4 {
                    .flow_key = flow_base,
                    .packet_ref = make_packet_ref(packet, true),
                },
                ipv4_builder
            );
        }

        if (protocol == detail::kIpProtocolIpv4Encapsulation) {
            if (const auto inner_packet = try_decode_plain_ipv4_encapsulated_inner_packet(
                    bounded_bytes,
                    transport_offset,
                    packet_end,
                    packet,
                    ipv4_builder
                );
                inner_packet.has_value()) {
                return *inner_packet;
            }
            return {};
        }

        if (protocol == detail::kIpProtocolIpv6Encapsulation) {
            if (const auto inner_packet = try_decode_plain_ipv6_encapsulated_inner_packet(
                    bounded_bytes,
                    transport_offset,
                    packet_end,
                    packet,
                    ipv4_builder
                );
                inner_packet.has_value()) {
                return *inner_packet;
            }
            return {};
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
            auto builder = ipv4_builder;
            static_cast<void>(builder.push(LayerKey::tcp()));
            return make_decoded_packet(
                IngestedPacketV4 {
                    .flow_key = flow_key,
                    .packet_ref = packet_ref,
                },
                builder
            );
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
            auto udp_builder = ipv4_builder;
            static_cast<void>(udp_builder.push(LayerKey::udp()));
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
                                packet,
                                udp_builder
                            );
                            vxlan_packet.has_value()) {
                            return *vxlan_packet;
                        }
                    } else if (flow_key.dst_port == detail::kUdpPortGeneve) {
                        if (const auto geneve_packet = try_decode_geneve_inner_packet(
                                bounded_bytes,
                                udp_payload->payload_offset,
                                udp_payload->payload_length,
                                packet,
                                udp_builder
                            );
                            geneve_packet.has_value()) {
                            return *geneve_packet;
                        }
                    } else if (flow_key.dst_port == detail::kUdpPortGtpu) {
                        if (const auto gtpu_packet = try_decode_gtpu_inner_packet(
                                bounded_bytes,
                                udp_payload->payload_offset,
                                udp_payload->payload_length,
                                packet,
                                udp_builder
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

            return make_decoded_packet(
                IngestedPacketV4 {
                    .flow_key = flow_key,
                    .packet_ref = packet_ref,
                },
                udp_builder
            );
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
            auto builder = ipv4_builder;
            static_cast<void>(builder.push(LayerKey::sctp()));
            return make_decoded_packet(
                IngestedPacketV4 {
                    .flow_key = flow_key,
                    .packet_ref = packet_ref,
                },
                builder
            );
        }

        if (protocol == detail::kIpProtocolAh) {
            if (const auto ah_packet = try_decode_direct_ipv4_ah_transport_packet(
                    bounded_bytes,
                    *ipv4_bounds,
                    transport_offset,
                    flow_base,
                    packet,
                    ipv4_builder
                );
                ah_packet.has_value()) {
                return *ah_packet;
            }
            return {};
        }

        if (protocol == detail::kIpProtocolEsp) {
            const auto esp = detail::parse_esp_header(
                bounded_bytes,
                transport_offset,
                ipv4_bounds->nominal_packet_end
            );
            if (!esp.has_value()) {
                return {};
            }

            auto flow_key = flow_base;
            flow_key.protocol = ProtocolId::esp;

            auto packet_ref = make_packet_ref(packet);
            packet_ref.payload_length = static_cast<std::uint32_t>(esp->payload_length);
            auto builder = ipv4_builder;
            static_cast<void>(builder.push(LayerKey::esp(esp->spi)));
            return make_decoded_packet(
                IngestedPacketV4 {
                    .flow_key = flow_key,
                    .packet_ref = packet_ref,
                },
                builder
            );
        }

        if (protocol == detail::kIpProtocolGre) {
            if (const auto gre_packet = try_decode_gre_inner_packet(
                    bounded_bytes,
                    transport_offset,
                    packet_end,
                    packet,
                    ipv4_builder
                );
                gre_packet.has_value()) {
                return *gre_packet;
            }
            return {};
        }

        if (protocol == detail::kIpProtocolIcmp) {
            if (bounded_bytes.size() < transport_offset + 2U) {
                return {};
            }

            auto flow_key = flow_base;
            flow_key.protocol = ProtocolId::icmp;
            auto builder = ipv4_builder;
            return make_decoded_packet(
                IngestedPacketV4 {
                    .flow_key = flow_key,
                    .packet_ref = make_packet_ref(packet),
                },
                builder
            );
        }

        if (protocol == detail::kIpProtocolIgmp) {
            const auto igmp = detail::parse_igmp_header(bounded_bytes, transport_offset, packet_end);
            if (!igmp.has_value() || igmp->available_length < detail::kIgmpMinimumHeaderSize) {
                return {};
            }

            auto flow_key = flow_base;
            flow_key.dst_addr = detail::igmp_effective_group_address(*igmp, flow_base.dst_addr);
            flow_key.protocol = ProtocolId::igmp;
            return make_decoded_packet(
                IngestedPacketV4 {
                    .flow_key = flow_key,
                    .packet_ref = make_packet_ref(packet),
                },
                ipv4_builder
            );
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
        const auto ah_payload = detail::parse_ipv6_authentication_payload(bounded_bytes, ipv6_offset);

        FlowKeyV6 flow_key {};
        for (std::size_t index = 0; index < 16U; ++index) {
            flow_key.src_addr[index] = bounded_bytes[ipv6_offset + 8U + index];
            flow_key.dst_addr[index] = bounded_bytes[ipv6_offset + 24U + index];
        }
        auto ipv6_builder = base_builder;
        static_cast<void>(ipv6_builder.push(LayerKey::ipv6()));

        if (payload->has_fragment_header) {
            if (ah_payload.has_value() && ah_payload->has_fragment_header) {
                return {};
            }
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

            return make_decoded_packet(
                IngestedPacketV6 {
                    .flow_key = flow_key,
                    .packet_ref = make_packet_ref(packet, true),
                },
                ipv6_builder
            );
        }

        if (ah_payload.has_value()) {
            if (const auto ah_packet = try_decode_direct_ipv6_ah_transport_packet(
                    bounded_bytes,
                    ipv6_offset + detail::kIpv6HeaderSize + ipv6_payload_length,
                    packet_end,
                    ah_payload->ah_offset,
                    flow_key,
                    packet,
                    ipv6_builder
                );
                ah_packet.has_value()) {
                return *ah_packet;
            }
            return {};
        }

        if (payload->next_header == detail::kIpProtocolIpv4Encapsulation) {
            if (const auto inner_packet = try_decode_ipv4_encapsulated_inner_packet(
                    bounded_bytes,
                    payload->payload_offset,
                    packet_end,
                    packet,
                    ipv6_builder
                );
                inner_packet.has_value()) {
                return *inner_packet;
            }
            return {};
        }

        if (payload->next_header == detail::kIpProtocolIpv6Encapsulation) {
            if (const auto inner_packet = try_decode_ipv6_encapsulated_inner_packet(
                    bounded_bytes,
                    payload->payload_offset,
                    packet_end,
                    packet,
                    ipv6_builder
                );
                inner_packet.has_value()) {
                return *inner_packet;
            }
            return {};
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
            auto builder = ipv6_builder;
            static_cast<void>(builder.push(LayerKey::tcp()));
            return make_decoded_packet(
                IngestedPacketV6 {
                    .flow_key = flow_key,
                    .packet_ref = packet_ref,
                },
                builder
            );
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
            auto udp_builder = ipv6_builder;
            static_cast<void>(udp_builder.push(LayerKey::udp()));
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
                                packet,
                                udp_builder
                            );
                            vxlan_packet.has_value()) {
                            return *vxlan_packet;
                        }
                    } else if (flow_key.dst_port == detail::kUdpPortGeneve) {
                        if (const auto geneve_packet = try_decode_geneve_inner_packet(
                                bounded_bytes,
                                udp_payload->payload_offset,
                                udp_payload->payload_length,
                                packet,
                                udp_builder
                            );
                            geneve_packet.has_value()) {
                            return *geneve_packet;
                        }
                    } else if (flow_key.dst_port == detail::kUdpPortGtpu) {
                        if (const auto gtpu_packet = try_decode_gtpu_inner_packet(
                                bounded_bytes,
                                udp_payload->payload_offset,
                                udp_payload->payload_length,
                                packet,
                                udp_builder
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

            return make_decoded_packet(
                IngestedPacketV6 {
                    .flow_key = flow_key,
                    .packet_ref = packet_ref,
                },
                udp_builder
            );
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
            auto builder = ipv6_builder;
            static_cast<void>(builder.push(LayerKey::sctp()));
            return make_decoded_packet(
                IngestedPacketV6 {
                    .flow_key = flow_key,
                    .packet_ref = packet_ref,
                },
                builder
            );
        }

        if (payload->next_header == detail::kIpProtocolEsp) {
            const auto esp = detail::parse_esp_header(
                bounded_bytes,
                payload->payload_offset,
                ipv6_offset + detail::kIpv6HeaderSize + ipv6_payload_length
            );
            if (!esp.has_value()) {
                return {};
            }

            flow_key.protocol = ProtocolId::esp;

            auto packet_ref = make_packet_ref(packet);
            packet_ref.payload_length = static_cast<std::uint32_t>(esp->payload_length);
            auto builder = ipv6_builder;
            static_cast<void>(builder.push(LayerKey::esp(esp->spi)));
            return make_decoded_packet(
                IngestedPacketV6 {
                    .flow_key = flow_key,
                    .packet_ref = packet_ref,
                },
                builder
            );
        }

        if (payload->next_header == detail::kIpProtocolGre) {
            if (const auto gre_packet = try_decode_gre_inner_packet(
                    bounded_bytes,
                    payload->payload_offset,
                    packet_end,
                    packet,
                    ipv6_builder
                );
                gre_packet.has_value()) {
                return *gre_packet;
            }
            return {};
        }

        if (payload->next_header == detail::kIpProtocolIcmpV6) {
            if (bounded_bytes.size() < payload->payload_offset + 2U) {
                return {};
            }

            flow_key.protocol = ProtocolId::icmpv6;
            auto builder = ipv6_builder;
            return make_decoded_packet(
                IngestedPacketV6 {
                    .flow_key = flow_key,
                    .packet_ref = make_packet_ref(packet),
                },
                builder
            );
        }

        return {};
    }

    return {};
}

}  // namespace pfl
