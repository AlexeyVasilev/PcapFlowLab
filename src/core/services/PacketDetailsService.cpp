#include "core/services/PacketDetailsService.h"

#include <algorithm>
#include <span>

#include "core/decode/PacketDecodeSupport.h"

namespace pfl {

namespace {

enum class DecodeMode : std::uint8_t {
    strict,
    best_effort,
};

struct LinkLayerView {
    std::uint16_t protocol_type {0};
    std::size_t payload_offset {0};
};

std::optional<LinkLayerView> parse_link_layer_envelope(std::span<const std::uint8_t> packet_bytes,
                                                       const PacketRef& packet_ref,
                                                       PacketDetails& details,
                                                       const DecodeMode mode) {
    details.vlan_tags.clear();
    details.vlan_tags.reserve(detail::kMaxVlanTags);
    details.vlan_tag_truncated = false;
    details.truncated_vlan_tpid = 0U;

    if (packet_ref.data_link_type == kLinkTypeEthernet) {
        if (packet_bytes.size() < detail::kEthernetHeaderSize) {
            return std::nullopt;
        }

        details.has_ethernet = true;
        std::copy_n(packet_bytes.begin(), 6U, details.ethernet.dst_mac.begin());
        std::copy_n(packet_bytes.begin() + 6, 6U, details.ethernet.src_mac.begin());
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
                details.has_vlan = true;
                details.vlan_tag_truncated = true;
                details.truncated_vlan_tpid = view.protocol_type;
                if (mode == DecodeMode::best_effort) {
                    return view;
                }
                return std::nullopt;
            }

            const VlanTagDetails tag {
                .tpid = view.protocol_type,
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

std::vector<std::uint8_t> copy_partial_field(
    std::span<const std::uint8_t> packet_bytes,
    const std::size_t offset,
    const std::size_t expected_size
) {
    if (offset >= packet_bytes.size() || expected_size == 0U) {
        return {};
    }

    const auto available = std::min(expected_size, packet_bytes.size() - offset);
    return std::vector<std::uint8_t>(
        packet_bytes.begin() + static_cast<std::ptrdiff_t>(offset),
        packet_bytes.begin() + static_cast<std::ptrdiff_t>(offset + available)
    );
}

std::optional<PacketDetails> decode_packet_details(
    std::span<const std::uint8_t> packet_bytes,
    const PacketRef& packet_ref,
    const DecodeMode mode
) {
    PacketDetails details {
        .packet_index = packet_ref.packet_index,
        .captured_length = packet_ref.captured_length,
        .original_length = packet_ref.original_length,
    };

    const auto envelope = parse_link_layer_envelope(packet_bytes, packet_ref, details, mode);
    if (!envelope.has_value()) {
        return std::nullopt;
    }

    details.has_mpls = false;
    details.mpls_ether_type = 0U;
    details.mpls_labels.clear();
    details.has_pppoe = false;
    details.pppoe = {};

    auto network_protocol_type = envelope->protocol_type;
    auto network_payload_offset = envelope->payload_offset;
    if (detail::is_mpls_ether_type(envelope->protocol_type)) {
        const auto mpls = detail::parse_mpls_stack(packet_bytes, envelope->payload_offset);
        details.has_mpls = true;
        details.mpls_ether_type = envelope->protocol_type;
        details.mpls_labels.reserve(mpls.label_count);
        for (std::size_t index = 0; index < mpls.label_count; ++index) {
            const auto& label = mpls.labels[index];
            details.mpls_labels.push_back(MplsLabelDetails {
                .label = label.label,
                .traffic_class = label.traffic_class,
                .bottom_of_stack = label.bottom_of_stack,
                .ttl = label.ttl,
            });
        }

        if (!detail::mpls_has_resolved_inner_payload(mpls.status)) {
            return mode == DecodeMode::best_effort ? std::optional<PacketDetails> {details} : std::nullopt;
        }

        network_protocol_type = mpls.inner_protocol_type;
        network_payload_offset = mpls.inner_payload_offset;
    }

    if (network_protocol_type == detail::kEtherTypePppoeSession) {
        details.has_pppoe = true;
        if (packet_bytes.size() < network_payload_offset + detail::kPppoeHeaderSize) {
            details.pppoe.header_truncated = true;
            return mode == DecodeMode::best_effort ? std::optional<PacketDetails> {details} : std::nullopt;
        }

        const auto version_type = packet_bytes[network_payload_offset];
        details.pppoe.version = static_cast<std::uint8_t>(version_type >> 4U);
        details.pppoe.type = static_cast<std::uint8_t>(version_type & 0x0FU);
        details.pppoe.code = packet_bytes[network_payload_offset + 1U];
        details.pppoe.session_id = detail::read_be16(packet_bytes, network_payload_offset + 2U);
        details.pppoe.payload_length = detail::read_be16(packet_bytes, network_payload_offset + 4U);

        const auto payload_offset = network_payload_offset + detail::kPppoeHeaderSize;
        const auto available_payload_length = packet_bytes.size() - payload_offset;
        details.pppoe.payload_length_mismatch =
            available_payload_length != static_cast<std::size_t>(details.pppoe.payload_length);

        if (available_payload_length < detail::kPppProtocolFieldSize ||
            details.pppoe.payload_length < detail::kPppProtocolFieldSize) {
            details.pppoe.protocol_field_truncated = true;
            return mode == DecodeMode::best_effort ? std::optional<PacketDetails> {details} : std::nullopt;
        }

        details.pppoe.ppp_protocol = detail::read_be16(packet_bytes, payload_offset);

        if (details.pppoe.version != 1U ||
            details.pppoe.type != 1U ||
            details.pppoe.code != 0U ||
            details.pppoe.payload_length_mismatch) {
            return mode == DecodeMode::best_effort ? std::optional<PacketDetails> {details} : std::nullopt;
        }

        if (details.pppoe.ppp_protocol == detail::kPppProtocolIpv4) {
            network_protocol_type = detail::kEtherTypeIpv4;
            network_payload_offset = payload_offset + detail::kPppProtocolFieldSize;
        } else if (details.pppoe.ppp_protocol == detail::kPppProtocolIpv6) {
            network_protocol_type = detail::kEtherTypeIpv6;
            network_payload_offset = payload_offset + detail::kPppProtocolFieldSize;
        } else {
            return mode == DecodeMode::best_effort ? std::optional<PacketDetails> {details} : std::nullopt;
        }
    }

    if (network_protocol_type == detail::kEtherTypeArp) {
        const auto arp_offset = network_payload_offset;
        details.has_arp = true;
        if (packet_bytes.size() <= arp_offset) {
            details.arp.fixed_header_truncated = true;
            return details;
        }

        const auto available_bytes = packet_bytes.size() - arp_offset;
        if (available_bytes < 8U) {
            details.arp.fixed_header_truncated = true;
            if (available_bytes >= 2U) {
                details.arp.hardware_type = detail::read_be16(packet_bytes, arp_offset);
            }
            if (available_bytes >= 4U) {
                details.arp.protocol_type = detail::read_be16(packet_bytes, arp_offset + 2U);
            }
            if (available_bytes >= 5U) {
                details.arp.hardware_size = packet_bytes[arp_offset + 4U];
            }
            if (available_bytes >= 6U) {
                details.arp.protocol_size = packet_bytes[arp_offset + 5U];
            }
            return details;
        }

        details.arp.hardware_type = detail::read_be16(packet_bytes, arp_offset);
        details.arp.protocol_type = detail::read_be16(packet_bytes, arp_offset + 2U);
        details.arp.hardware_size = packet_bytes[arp_offset + 4U];
        details.arp.protocol_size = packet_bytes[arp_offset + 5U];
        details.arp.opcode = detail::read_be16(packet_bytes, arp_offset + 6U);

        const auto hardware_size = static_cast<std::size_t>(details.arp.hardware_size);
        const auto protocol_size = static_cast<std::size_t>(details.arp.protocol_size);
        const auto declared_length = static_cast<std::size_t>(8U + (2U * hardware_size) + (2U * protocol_size));
        details.arp.address_section_truncated = available_bytes < declared_length;

        auto cursor = arp_offset + 8U;
        details.arp.sender_hardware_address = copy_partial_field(packet_bytes, cursor, hardware_size);
        cursor += hardware_size;
        details.arp.sender_protocol_address = copy_partial_field(packet_bytes, cursor, protocol_size);
        cursor += protocol_size;
        details.arp.target_hardware_address = copy_partial_field(packet_bytes, cursor, hardware_size);
        cursor += hardware_size;
        details.arp.target_protocol_address = copy_partial_field(packet_bytes, cursor, protocol_size);

        if (details.arp.protocol_type == detail::kArpProtocolTypeIpv4 && protocol_size == 4U) {
            if (details.arp.sender_protocol_address.size() == 4U) {
                details.arp.sender_ipv4 = ipv4_bytes(
                    std::span<const std::uint8_t>(details.arp.sender_protocol_address.data(), details.arp.sender_protocol_address.size()),
                    0U
                );
            }
            if (details.arp.target_protocol_address.size() == 4U) {
                details.arp.target_ipv4 = ipv4_bytes(
                    std::span<const std::uint8_t>(details.arp.target_protocol_address.data(), details.arp.target_protocol_address.size()),
                    0U
                );
            }
        }

        return details;
    }

    if (network_protocol_type == detail::kEtherTypeIpv4) {
        const auto ipv4_offset = network_payload_offset;
        if (packet_bytes.size() < ipv4_offset + detail::kIpv4MinimumHeaderSize) {
            return mode == DecodeMode::best_effort ? std::optional<PacketDetails> {details} : std::nullopt;
        }

        const auto version = static_cast<std::uint8_t>(packet_bytes[ipv4_offset] >> 4U);
        if (version != 4U) {
            return mode == DecodeMode::best_effort ? std::optional<PacketDetails> {details} : std::nullopt;
        }

        const auto claimed_header_length = static_cast<std::size_t>((packet_bytes[ipv4_offset] & 0x0FU) * 4U);
        const auto total_length = detail::read_be16(packet_bytes, ipv4_offset + 2U);
        const auto flags_fragment = detail::read_be16(packet_bytes, ipv4_offset + 6U);
        const bool is_fragmented = (flags_fragment & 0x3FFFU) != 0U;

        details.address_family = NetworkAddressFamily::ipv4;
        details.has_ipv4 = true;
        details.ipv4_bounds_from_captured_bytes = total_length == 0U;
        details.ipv4 = IPv4Details {
            .src_addr = detail::read_be32(packet_bytes, ipv4_offset + 12U),
            .dst_addr = detail::read_be32(packet_bytes, ipv4_offset + 16U),
            .header_length_bytes = static_cast<std::uint8_t>(claimed_header_length),
            .differentiated_services_field = packet_bytes[ipv4_offset + 1U],
            .protocol = packet_bytes[ipv4_offset + 9U],
            .ttl = packet_bytes[ipv4_offset + 8U],
            .identification = detail::read_be16(packet_bytes, ipv4_offset + 4U),
            .flags = static_cast<std::uint8_t>((flags_fragment >> 13U) & 0x7U),
            .fragment_offset = static_cast<std::uint16_t>(flags_fragment & 0x1FFFU),
            .total_length = total_length,
            .header_checksum = detail::read_be16(packet_bytes, ipv4_offset + 10U),
        };

        const auto claimed_options_length = claimed_header_length > detail::kIpv4MinimumHeaderSize
            ? (claimed_header_length - detail::kIpv4MinimumHeaderSize)
            : 0U;
        if (claimed_options_length > 0U && packet_bytes.size() > ipv4_offset + detail::kIpv4MinimumHeaderSize) {
            const auto available_options_length = std::min(
                claimed_options_length,
                packet_bytes.size() - (ipv4_offset + detail::kIpv4MinimumHeaderSize)
            );
            details.ipv4.options_bytes.assign(
                packet_bytes.begin() + static_cast<std::ptrdiff_t>(ipv4_offset + detail::kIpv4MinimumHeaderSize),
                packet_bytes.begin() + static_cast<std::ptrdiff_t>(
                    ipv4_offset + detail::kIpv4MinimumHeaderSize + available_options_length
                )
            );
            details.ipv4.options_truncated = available_options_length < claimed_options_length;
        }

        if (claimed_header_length < detail::kIpv4MinimumHeaderSize) {
            details.ipv4.invalid_header_length = true;
            return mode == DecodeMode::best_effort ? std::optional<PacketDetails> {details} : std::nullopt;
        }

        if (total_length != 0U && total_length < claimed_header_length) {
            details.ipv4.total_length_invalid = true;
            return mode == DecodeMode::best_effort ? std::optional<PacketDetails> {details} : std::nullopt;
        }

        if (packet_bytes.size() < ipv4_offset + claimed_header_length) {
            details.ipv4.header_truncated = true;
            details.ipv4.options_truncated = claimed_options_length > details.ipv4.options_bytes.size();
            return mode == DecodeMode::best_effort ? std::optional<PacketDetails> {details} : std::nullopt;
        }

        const auto ipv4_bounds = detail::parse_ipv4_packet_bounds(packet_bytes, ipv4_offset);
        if (!ipv4_bounds.has_value()) {
            return mode == DecodeMode::best_effort ? std::optional<PacketDetails> {details} : std::nullopt;
        }

        const auto packet_end = ipv4_bounds->packet_end;

        if (is_fragmented) {
            return details;
        }

        const auto transport_offset = ipv4_offset + claimed_header_length;
        if (details.ipv4.protocol == detail::kIpProtocolTcp) {
            if (transport_offset + detail::kTcpMinimumHeaderSize > packet_end ||
                packet_bytes.size() < transport_offset + detail::kTcpMinimumHeaderSize) {
                return mode == DecodeMode::best_effort ? std::optional<PacketDetails> {details} : std::nullopt;
            }

            const auto tcp_header_length = static_cast<std::size_t>((packet_bytes[transport_offset + 12U] >> 4U) * 4U);
            if (tcp_header_length < detail::kTcpMinimumHeaderSize ||
                transport_offset + tcp_header_length > packet_end ||
                packet_bytes.size() < transport_offset + tcp_header_length) {
                return mode == DecodeMode::best_effort ? std::optional<PacketDetails> {details} : std::nullopt;
            }

            details.has_tcp = true;
            details.tcp = TcpDetails {
                .src_port = detail::read_be16(packet_bytes, transport_offset),
                .dst_port = detail::read_be16(packet_bytes, transport_offset + 2U),
                .seq_number = detail::read_be32(packet_bytes, transport_offset + 4U),
                .ack_number = detail::read_be32(packet_bytes, transport_offset + 8U),
                .header_length_bytes = static_cast<std::uint8_t>(tcp_header_length),
                .flags = packet_bytes[transport_offset + 13U],
                .window = detail::read_be16(packet_bytes, transport_offset + 14U),
                .checksum = detail::read_be16(packet_bytes, transport_offset + 16U),
                .urgent_pointer = detail::read_be16(packet_bytes, transport_offset + 18U),
            };
            if (tcp_header_length > detail::kTcpMinimumHeaderSize) {
                details.tcp.options_bytes.assign(
                    packet_bytes.begin() + static_cast<std::ptrdiff_t>(transport_offset + detail::kTcpMinimumHeaderSize),
                    packet_bytes.begin() + static_cast<std::ptrdiff_t>(transport_offset + tcp_header_length)
                );
            }
            return details;
        }

        if (details.ipv4.protocol == detail::kIpProtocolUdp) {
            const auto udp_payload = detail::parse_udp_payload_bounds(packet_bytes, transport_offset, ipv4_bounds->nominal_packet_end);
            if (!udp_payload.has_value()) {
                return mode == DecodeMode::best_effort ? std::optional<PacketDetails> {details} : std::nullopt;
            }

            details.has_udp = true;
            details.udp = UdpDetails {
                .src_port = detail::read_be16(packet_bytes, transport_offset),
                .dst_port = detail::read_be16(packet_bytes, transport_offset + 2U),
                .length = udp_payload->datagram_length,
                .checksum = detail::read_be16(packet_bytes, transport_offset + 6U),
            };
            return details;
        }

        if (details.ipv4.protocol == detail::kIpProtocolIcmp) {
            if (transport_offset + 2U > packet_end || packet_bytes.size() < transport_offset + 2U) {
                return mode == DecodeMode::best_effort ? std::optional<PacketDetails> {details} : std::nullopt;
            }

            details.has_icmp = true;
            details.icmp = IcmpDetails {
                .type = packet_bytes[transport_offset],
                .code = packet_bytes[transport_offset + 1U],
            };
            return details;
        }

        if (details.ipv4.protocol == detail::kIpProtocolIgmp) {
            const auto igmp = detail::parse_igmp_header(packet_bytes, transport_offset, packet_end);
            if (!igmp.has_value()) {
                return mode == DecodeMode::best_effort ? std::optional<PacketDetails> {details} : std::nullopt;
            }

            details.has_igmp = true;
            details.igmp = IgmpDetails {
                .type = igmp->type,
                .max_resp_code = igmp->max_resp_code,
                .checksum = igmp->checksum,
                .group_address = igmp->group_address,
                .group_record_count = igmp->group_record_count,
                .has_group_address = igmp->has_group_address,
                .is_v3_membership_report = igmp->is_v3_membership_report,
                .header_truncated = igmp->header_truncated,
            };

            if (igmp->available_length < detail::kIgmpMinimumHeaderSize && mode == DecodeMode::strict) {
                return std::nullopt;
            }

            return details;
        }

        return mode == DecodeMode::best_effort ? std::optional<PacketDetails> {details} : std::nullopt;
    }

    if (network_protocol_type == detail::kEtherTypeIpv6) {
        const auto ipv6_offset = network_payload_offset;
        if (packet_bytes.size() < ipv6_offset + detail::kIpv6HeaderSize) {
            return mode == DecodeMode::best_effort ? std::optional<PacketDetails> {details} : std::nullopt;
        }

        const auto version = static_cast<std::uint8_t>(packet_bytes[ipv6_offset] >> 4U);
        if (version != 6U) {
            return mode == DecodeMode::best_effort ? std::optional<PacketDetails> {details} : std::nullopt;
        }

        details.address_family = NetworkAddressFamily::ipv6;
        details.has_ipv6 = true;
        const auto version_traffic_flow = detail::read_be32(packet_bytes, ipv6_offset);
        details.ipv6.traffic_class = static_cast<std::uint8_t>((version_traffic_flow >> 20U) & 0xFFU);
        details.ipv6.hop_limit = packet_bytes[ipv6_offset + 7U];
        details.ipv6.flow_label = version_traffic_flow & 0x000FFFFFU;
        details.ipv6.payload_length = detail::read_be16(packet_bytes, ipv6_offset + 4U);
        for (std::size_t index = 0; index < 16U; ++index) {
            details.ipv6.src_addr[index] = packet_bytes[ipv6_offset + 8U + index];
            details.ipv6.dst_addr[index] = packet_bytes[ipv6_offset + 24U + index];
        }

        const auto payload = detail::parse_ipv6_payload(packet_bytes, ipv6_offset);
        const auto packet_end = std::min(ipv6_offset + detail::kIpv6HeaderSize + static_cast<std::size_t>(details.ipv6.payload_length),
                                         packet_bytes.size());
        if (!payload.has_value() || payload->payload_offset > packet_end) {
            return mode == DecodeMode::best_effort ? std::optional<PacketDetails> {details} : std::nullopt;
        }

        details.ipv6.next_header = payload->next_header;
        if (payload->has_fragment_header) {
            return details;
        }

        if (payload->next_header == detail::kIpProtocolTcp) {
            if (payload->payload_offset + detail::kTcpMinimumHeaderSize > packet_end ||
                packet_bytes.size() < payload->payload_offset + detail::kTcpMinimumHeaderSize) {
                return mode == DecodeMode::best_effort ? std::optional<PacketDetails> {details} : std::nullopt;
            }

            const auto tcp_header_length = static_cast<std::size_t>((packet_bytes[payload->payload_offset + 12U] >> 4U) * 4U);
            if (tcp_header_length < detail::kTcpMinimumHeaderSize ||
                payload->payload_offset + tcp_header_length > packet_end ||
                packet_bytes.size() < payload->payload_offset + tcp_header_length) {
                return mode == DecodeMode::best_effort ? std::optional<PacketDetails> {details} : std::nullopt;
            }

            details.has_tcp = true;
            details.tcp = TcpDetails {
                .src_port = detail::read_be16(packet_bytes, payload->payload_offset),
                .dst_port = detail::read_be16(packet_bytes, payload->payload_offset + 2U),
                .seq_number = detail::read_be32(packet_bytes, payload->payload_offset + 4U),
                .ack_number = detail::read_be32(packet_bytes, payload->payload_offset + 8U),
                .header_length_bytes = static_cast<std::uint8_t>(tcp_header_length),
                .flags = packet_bytes[payload->payload_offset + 13U],
                .window = detail::read_be16(packet_bytes, payload->payload_offset + 14U),
                .checksum = detail::read_be16(packet_bytes, payload->payload_offset + 16U),
                .urgent_pointer = detail::read_be16(packet_bytes, payload->payload_offset + 18U),
            };
            if (tcp_header_length > detail::kTcpMinimumHeaderSize) {
                details.tcp.options_bytes.assign(
                    packet_bytes.begin() + static_cast<std::ptrdiff_t>(payload->payload_offset + detail::kTcpMinimumHeaderSize),
                    packet_bytes.begin() + static_cast<std::ptrdiff_t>(payload->payload_offset + tcp_header_length)
                );
            }
            return details;
        }

        if (payload->next_header == detail::kIpProtocolUdp) {
            const auto udp_payload = detail::parse_udp_payload_bounds(
                packet_bytes,
                payload->payload_offset,
                ipv6_offset + detail::kIpv6HeaderSize + static_cast<std::size_t>(details.ipv6.payload_length)
            );
            if (!udp_payload.has_value()) {
                return mode == DecodeMode::best_effort ? std::optional<PacketDetails> {details} : std::nullopt;
            }

            details.has_udp = true;
            details.udp = UdpDetails {
                .src_port = detail::read_be16(packet_bytes, payload->payload_offset),
                .dst_port = detail::read_be16(packet_bytes, payload->payload_offset + 2U),
                .length = udp_payload->datagram_length,
                .checksum = detail::read_be16(packet_bytes, payload->payload_offset + 6U),
            };
            return details;
        }

        if (payload->next_header == detail::kIpProtocolIcmpV6) {
            if (payload->payload_offset + 2U > packet_end || packet_bytes.size() < payload->payload_offset + 2U) {
                return mode == DecodeMode::best_effort ? std::optional<PacketDetails> {details} : std::nullopt;
            }

            details.has_icmpv6 = true;
            details.icmpv6 = IcmpV6Details {
                .type = packet_bytes[payload->payload_offset],
                .code = packet_bytes[payload->payload_offset + 1U],
            };
            return details;
        }

        return mode == DecodeMode::best_effort ? std::optional<PacketDetails> {details} : std::nullopt;
    }

    return mode == DecodeMode::best_effort ? std::optional<PacketDetails> {details} : std::nullopt;
}

}  // namespace

std::optional<PacketDetails> PacketDetailsService::decode(
    std::span<const std::uint8_t> packet_bytes,
    const PacketRef& packet_ref
) const {
    return decode_packet_details(packet_bytes, packet_ref, DecodeMode::strict);
}

std::optional<PacketDetails> PacketDetailsService::decode_best_effort(
    std::span<const std::uint8_t> packet_bytes,
    const PacketRef& packet_ref
) const {
    return decode_packet_details(packet_bytes, packet_ref, DecodeMode::best_effort);
}

}  // namespace pfl
