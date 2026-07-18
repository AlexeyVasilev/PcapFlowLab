#include "core/dissection/modules/CommonDirectModules.h"

#include <algorithm>
#include <optional>

#include "core/decode/PacketDecodeSupport.h"

namespace pfl::dissection {

namespace {

std::size_t slice_declared_length(const PacketSlice& slice) noexcept {
    return slice.declared_end() - slice.source_offset();
}

std::span<const std::uint8_t> visible_captured_bytes(const PacketSlice& slice) noexcept {
    return slice.captured_bytes().first(std::min(slice.captured_bytes().size(), slice_declared_length(slice)));
}

ByteRange require_relative_range(const PacketSlice& slice, const std::size_t begin, const std::size_t end) {
    const auto range = ByteRange::from_begin_end(slice.source_offset() + begin, slice.source_offset() + end);
    return range.value_or(ByteRange {});
}

std::optional<ByteRange> payload_range_if_any(
    const PacketSlice& slice,
    const std::size_t payload_offset,
    const std::size_t payload_end
) {
    if (payload_end <= payload_offset) {
        return std::nullopt;
    }

    return require_relative_range(slice, payload_offset, payload_end);
}

ProtocolId direct_ipv4_protocol_id(const std::uint8_t protocol) noexcept {
    if (protocol == detail::kIpProtocolTcp) {
        return ProtocolId::tcp;
    }
    if (protocol == detail::kIpProtocolUdp) {
        return ProtocolId::udp;
    }

    return ProtocolId::unknown;
}

DissectionStep make_error_step(
    const PacketSlice& slice,
    const LayerKey layer_key,
    const ParseStatus status,
    const StopReason stop_reason,
    const std::size_t header_length = 0U
) {
    const auto full_end = slice_declared_length(slice);
    const auto header_end = std::min(header_length, full_end);
    return DissectionStep {
        .layer_key = layer_key,
        .full_range = require_relative_range(slice, 0U, full_end),
        .header_range = require_relative_range(slice, 0U, header_end),
        .status = status,
        .stop_reason = stop_reason,
    };
}

}  // namespace

ParsedEthernetFrame parse_ethernet_frame(const PacketSlice& slice) noexcept {
    const auto bytes = visible_captured_bytes(slice);
    if (bytes.size() < detail::kEthernetHeaderSize) {
        return ParsedEthernetFrame {
            .status = ParseStatus::truncated,
        };
    }

    const auto ethernet = detail::parse_ethernet_header_at(bytes, 0U);
    if (!ethernet.has_value()) {
        return ParsedEthernetFrame {
            .status = ParseStatus::truncated,
        };
    }

    return ParsedEthernetFrame {
        .status = ParseStatus::complete,
        .protocol_type = ethernet->protocol_type,
        .header_length = detail::kEthernetHeaderSize,
        .declared_payload_length = slice_declared_length(slice) - detail::kEthernetHeaderSize,
        .is_ieee_802_3 = ethernet->is_ieee_802_3,
    };
}

ParsedVlanTag parse_vlan_tag(const PacketSlice& slice) noexcept {
    const auto bytes = visible_captured_bytes(slice);
    if (slice_declared_length(slice) < detail::kVlanHeaderSize) {
        return ParsedVlanTag {
            .status = ParseStatus::malformed,
        };
    }

    const auto vlan = detail::parse_vlan_header_at(bytes, 0U);
    if (!vlan.has_value()) {
        return ParsedVlanTag {
            .status = ParseStatus::truncated,
        };
    }

    return ParsedVlanTag {
        .status = ParseStatus::complete,
        .tci = vlan->tci,
        .encapsulated_ether_type = vlan->encapsulated_ether_type,
        .header_length = detail::kVlanHeaderSize,
        .declared_payload_length = slice_declared_length(slice) - detail::kVlanHeaderSize,
    };
}

ParsedIpv4Packet parse_ipv4_packet(const PacketSlice& slice) noexcept {
    const auto bytes = visible_captured_bytes(slice);
    if (bytes.size() < detail::kIpv4MinimumHeaderSize) {
        return ParsedIpv4Packet {
            .status = ParseStatus::truncated,
        };
    }

    const auto version = static_cast<std::uint8_t>(bytes[0U] >> 4U);
    const auto ihl = static_cast<std::size_t>((bytes[0U] & 0x0FU) * 4U);
    if (version != 4U || ihl < detail::kIpv4MinimumHeaderSize) {
        return ParsedIpv4Packet {
            .status = ParseStatus::malformed,
        };
    }

    if (bytes.size() < ihl) {
        return ParsedIpv4Packet {
            .status = ParseStatus::truncated,
        };
    }

    const auto total_length = detail::read_be16(bytes, 2U);
    if (total_length != 0U && total_length < ihl) {
        return ParsedIpv4Packet {
            .status = ParseStatus::malformed,
        };
    }

    const auto bounds = detail::parse_ipv4_packet_bounds(bytes, 0U);
    if (!bounds.has_value()) {
        return ParsedIpv4Packet {
            .status = ParseStatus::malformed,
        };
    }

    const auto flags_fragment = detail::read_be16(bytes, 6U);
    const auto fragment_offset_units = static_cast<std::uint16_t>(flags_fragment & 0x1FFFU);
    return ParsedIpv4Packet {
        .status = ParseStatus::complete,
        .protocol = bytes[9U],
        .total_length = bounds->total_length,
        .header_length = bounds->header_length,
        .nominal_packet_end = bounds->nominal_packet_end,
        .packet_end = bounds->packet_end,
        .src_addr = detail::read_be32(bytes, 12U),
        .dst_addr = detail::read_be32(bytes, 16U),
        .flags_fragment = flags_fragment,
        .bounds_from_captured_bytes = bounds->bounds_from_captured_bytes,
        .is_fragmented = (flags_fragment & 0x3FFFU) != 0U,
        .more_fragments = (flags_fragment & 0x2000U) != 0U,
        .fragment_offset_units = fragment_offset_units,
    };
}

ParsedTcpSegment parse_tcp_segment(const PacketSlice& slice) noexcept {
    const auto bytes = visible_captured_bytes(slice);
    const auto nominal_packet_end = slice_declared_length(slice);
    if (nominal_packet_end < detail::kTcpMinimumHeaderSize) {
        return ParsedTcpSegment {
            .status = ParseStatus::malformed,
        };
    }

    if (bytes.size() < detail::kTcpMinimumHeaderSize) {
        return ParsedTcpSegment {
            .status = ParseStatus::truncated,
        };
    }

    const auto header_length = static_cast<std::size_t>((bytes[12U] >> 4U) * 4U);
    if (header_length < detail::kTcpMinimumHeaderSize || header_length > nominal_packet_end) {
        return ParsedTcpSegment {
            .status = ParseStatus::malformed,
        };
    }

    if (bytes.size() < header_length) {
        return ParsedTcpSegment {
            .status = ParseStatus::truncated,
        };
    }

    const auto packet_end = std::min(nominal_packet_end, bytes.size());
    return ParsedTcpSegment {
        .status = ParseStatus::complete,
        .src_port = detail::read_be16(bytes, 0U),
        .dst_port = detail::read_be16(bytes, 2U),
        .header_length = header_length,
        .captured_payload_length = static_cast<std::uint32_t>(packet_end - header_length),
        .flags = bytes[13U],
    };
}

ParsedUdpDatagram parse_udp_datagram(const PacketSlice& slice) noexcept {
    const auto bytes = visible_captured_bytes(slice);
    const auto nominal_packet_end = slice_declared_length(slice);
    if (nominal_packet_end < detail::kUdpHeaderSize) {
        return ParsedUdpDatagram {
            .status = ParseStatus::malformed,
        };
    }

    if (bytes.size() < detail::kUdpHeaderSize) {
        return ParsedUdpDatagram {
            .status = ParseStatus::truncated,
        };
    }

    const auto udp_payload = detail::parse_udp_payload_bounds(bytes, 0U, nominal_packet_end);
    if (!udp_payload.has_value()) {
        return ParsedUdpDatagram {
            .status = ParseStatus::malformed,
        };
    }

    return ParsedUdpDatagram {
        .status = ParseStatus::complete,
        .src_port = detail::read_be16(bytes, 0U),
        .dst_port = detail::read_be16(bytes, 2U),
        .datagram_length = udp_payload->datagram_length,
        .captured_payload_length = static_cast<std::uint32_t>(udp_payload->payload_length),
    };
}

ParsedArpPacket parse_arp_packet(const PacketSlice& slice) noexcept {
    ParsedArpPacket parsed {};
    const auto bytes = visible_captured_bytes(slice);
    const auto available_bytes = bytes.size();
    if (available_bytes < 8U) {
        parsed.status = ParseStatus::truncated;
        parsed.fixed_header_truncated = true;
        if (available_bytes >= 2U) {
            parsed.hardware_type = detail::read_be16(bytes, 0U);
        }
        if (available_bytes >= 4U) {
            parsed.protocol_type = detail::read_be16(bytes, 2U);
        }
        if (available_bytes >= 5U) {
            parsed.hardware_size = bytes[4U];
        }
        if (available_bytes >= 6U) {
            parsed.protocol_size = bytes[5U];
        }
        return parsed;
    }

    parsed.hardware_type = detail::read_be16(bytes, 0U);
    parsed.protocol_type = detail::read_be16(bytes, 2U);
    parsed.hardware_size = bytes[4U];
    parsed.protocol_size = bytes[5U];
    parsed.opcode = detail::read_be16(bytes, 6U);

    const auto hardware_size = static_cast<std::size_t>(parsed.hardware_size);
    const auto protocol_size = static_cast<std::size_t>(parsed.protocol_size);
    const auto declared_length = static_cast<std::size_t>(8U + (2U * hardware_size) + (2U * protocol_size));
    if (available_bytes < declared_length) {
        parsed.status = ParseStatus::truncated;
        parsed.address_section_truncated = true;
        return parsed;
    }

    auto cursor = 8U + hardware_size;
    const auto sender_protocol_offset = cursor;
    cursor += protocol_size + hardware_size;
    const auto target_protocol_offset = cursor;
    if (parsed.protocol_type == detail::kArpProtocolTypeIpv4 && protocol_size == 4U) {
        parsed.has_sender_ipv4 = true;
        parsed.sender_ipv4 = detail::read_be32(bytes, sender_protocol_offset);
        parsed.has_target_ipv4 = true;
        parsed.target_ipv4 = detail::read_be32(bytes, target_protocol_offset);
    }

    parsed.status = ParseStatus::complete;
    return parsed;
}

DissectionStep dissect_ethernet(const PacketSlice& slice) {
    const auto parsed = parse_ethernet_frame(slice);
    if (parsed.status != ParseStatus::complete) {
        return make_error_step(
            slice,
            LayerKey::unknown(),
            parsed.status,
            parsed.status == ParseStatus::truncated ? StopReason::truncated : StopReason::malformed,
            detail::kEthernetHeaderSize
        );
    }

    const auto layer_key = parsed.is_ieee_802_3 ? LayerKey::ieee8023() : LayerKey::ethernet_ii();
    if (parsed.is_ieee_802_3) {
        return DissectionStep {
            .layer_key = layer_key,
            .full_range = require_relative_range(slice, 0U, slice_declared_length(slice)),
            .header_range = require_relative_range(slice, 0U, parsed.header_length),
            .payload_range = payload_range_if_any(slice, parsed.header_length, slice_declared_length(slice)),
            .status = ParseStatus::complete,
            .stop_reason = StopReason::unrecognized_payload,
        };
    }

    const auto child = make_child_slice(slice, parsed.header_length, parsed.declared_payload_length);
    if (!child.has_slice()) {
        return make_error_step(slice, layer_key, ParseStatus::malformed, StopReason::malformed, parsed.header_length);
    }

    return DissectionStep {
        .layer_key = layer_key,
        .full_range = require_relative_range(slice, 0U, slice_declared_length(slice)),
        .header_range = require_relative_range(slice, 0U, parsed.header_length),
        .payload_range = payload_range_if_any(slice, parsed.header_length, slice_declared_length(slice)),
        .next = NextDissection {
            .selector = ProtocolSelector {
                .domain = SelectorDomain::ether_type,
                .value = parsed.protocol_type,
            },
            .slice = *child.slice,
        },
        .status = ParseStatus::complete,
        .stop_reason = StopReason::none,
    };
}

DissectionStep dissect_vlan(const PacketSlice& slice) {
    const auto parsed = parse_vlan_tag(slice);
    if (parsed.status != ParseStatus::complete) {
        return make_error_step(
            slice,
            LayerKey::vlan(0U),
            parsed.status,
            parsed.status == ParseStatus::truncated ? StopReason::truncated : StopReason::malformed,
            detail::kVlanHeaderSize
        );
    }

    const auto layer_key = LayerKey::vlan(static_cast<std::uint16_t>(parsed.tci & 0x0FFFU));
    const auto child = make_child_slice(slice, parsed.header_length, parsed.declared_payload_length);
    if (!child.has_slice()) {
        return make_error_step(slice, layer_key, ParseStatus::malformed, StopReason::malformed, parsed.header_length);
    }

    return DissectionStep {
        .layer_key = layer_key,
        .full_range = require_relative_range(slice, 0U, slice_declared_length(slice)),
        .header_range = require_relative_range(slice, 0U, parsed.header_length),
        .payload_range = payload_range_if_any(slice, parsed.header_length, slice_declared_length(slice)),
        .next = NextDissection {
            .selector = ProtocolSelector {
                .domain = SelectorDomain::ether_type,
                .value = parsed.encapsulated_ether_type,
            },
            .slice = *child.slice,
        },
        .identity_contribution = layer_key,
        .status = ParseStatus::complete,
        .stop_reason = StopReason::none,
    };
}

DissectionStep dissect_ipv4(const PacketSlice& slice) {
    const auto parsed = parse_ipv4_packet(slice);
    if (parsed.status != ParseStatus::complete) {
        return make_error_step(
            slice,
            LayerKey::ipv4(),
            parsed.status,
            parsed.status == ParseStatus::truncated ? StopReason::truncated : StopReason::malformed,
            detail::kIpv4MinimumHeaderSize
        );
    }

    const auto bounded_full_end = std::min(parsed.nominal_packet_end, slice_declared_length(slice));
    DissectionStep step {
        .layer_key = LayerKey::ipv4(),
        .full_range = require_relative_range(slice, 0U, bounded_full_end),
        .header_range = require_relative_range(slice, 0U, parsed.header_length),
        .payload_range = payload_range_if_any(slice, parsed.header_length, bounded_full_end),
        .status = ParseStatus::complete,
        .stop_reason = StopReason::none,
    };

    step.ipv4_fragmentation = Ipv4FragmentationFact {
        .is_fragmented = parsed.is_fragmented,
        .more_fragments = parsed.more_fragments,
        .fragment_offset_units = parsed.fragment_offset_units,
    };

    const auto protocol = direct_ipv4_protocol_id(parsed.protocol);
    if (protocol == ProtocolId::unknown) {
        step.stop_reason = StopReason::unknown_next_protocol;
        return step;
    }

    step.terminal_flow = TerminalFlowFact {
        .family = DissectionAddressFamily::ipv4,
        .protocol = protocol,
        .has_addresses = true,
        .src_addr_v4 = parsed.src_addr,
        .dst_addr_v4 = parsed.dst_addr,
        .src_port = 0U,
        .dst_port = 0U,
        .has_ports = false,
    };

    if (parsed.is_fragmented) {
        step.stop_reason = StopReason::needs_reassembly;
        return step;
    }

    const auto child = make_child_slice(slice, parsed.header_length, parsed.nominal_packet_end - parsed.header_length);
    if (!child.has_slice()) {
        return make_error_step(slice, LayerKey::ipv4(), ParseStatus::malformed, StopReason::malformed, parsed.header_length);
    }

    step.next = NextDissection {
        .selector = ProtocolSelector {
            .domain = SelectorDomain::ip_protocol,
            .value = parsed.protocol,
        },
        .slice = *child.slice,
    };
    return step;
}

DissectionStep dissect_tcp(const PacketSlice& slice) {
    const auto parsed = parse_tcp_segment(slice);
    if (parsed.status != ParseStatus::complete) {
        return make_error_step(
            slice,
            LayerKey::tcp(),
            parsed.status,
            parsed.status == ParseStatus::truncated ? StopReason::truncated : StopReason::malformed,
            detail::kTcpMinimumHeaderSize
        );
    }

    return DissectionStep {
        .layer_key = LayerKey::tcp(),
        .full_range = require_relative_range(slice, 0U, slice_declared_length(slice)),
        .header_range = require_relative_range(slice, 0U, parsed.header_length),
        .payload_range = payload_range_if_any(slice, parsed.header_length, slice_declared_length(slice)),
        .terminal_flow = TerminalFlowFact {
            .protocol = ProtocolId::tcp,
            .src_port = parsed.src_port,
            .dst_port = parsed.dst_port,
            .has_ports = true,
        },
        .transport_payload = TransportPayloadFact {
            .captured_payload_length = parsed.captured_payload_length,
        },
        .tcp_control = TcpControlFact {
            .flags = parsed.flags,
        },
        .status = ParseStatus::complete,
        .stop_reason = StopReason::terminal_protocol,
    };
}

DissectionStep dissect_udp(const PacketSlice& slice) {
    const auto parsed = parse_udp_datagram(slice);
    if (parsed.status != ParseStatus::complete) {
        return make_error_step(
            slice,
            LayerKey::udp(),
            parsed.status,
            parsed.status == ParseStatus::truncated ? StopReason::truncated : StopReason::malformed,
            detail::kUdpHeaderSize
        );
    }

    return DissectionStep {
        .layer_key = LayerKey::udp(),
        .full_range = require_relative_range(slice, 0U, slice_declared_length(slice)),
        .header_range = require_relative_range(slice, 0U, detail::kUdpHeaderSize),
        .payload_range = payload_range_if_any(slice, detail::kUdpHeaderSize, slice_declared_length(slice)),
        .terminal_flow = TerminalFlowFact {
            .protocol = ProtocolId::udp,
            .src_port = parsed.src_port,
            .dst_port = parsed.dst_port,
            .has_ports = true,
        },
        .transport_payload = TransportPayloadFact {
            .captured_payload_length = parsed.captured_payload_length,
        },
        .status = ParseStatus::complete,
        .stop_reason = StopReason::terminal_protocol,
    };
}

DissectionStep dissect_arp(const PacketSlice& slice) {
    const auto parsed = parse_arp_packet(slice);
    if (parsed.status != ParseStatus::complete) {
        return DissectionStep {
            .layer_key = LayerKey::arp(),
            .full_range = require_relative_range(slice, 0U, slice_declared_length(slice)),
            .header_range = require_relative_range(slice, 0U, std::min<std::size_t>(8U, slice_declared_length(slice))),
            .payload_range = payload_range_if_any(slice, 8U, slice_declared_length(slice)),
            .status = parsed.status,
            .stop_reason = parsed.status == ParseStatus::truncated ? StopReason::truncated : StopReason::malformed,
        };
    }

    return DissectionStep {
        .layer_key = LayerKey::arp(),
        .full_range = require_relative_range(slice, 0U, slice_declared_length(slice)),
        .header_range = require_relative_range(slice, 0U, std::min<std::size_t>(8U, slice_declared_length(slice))),
        .payload_range = payload_range_if_any(slice, 8U, slice_declared_length(slice)),
        .arp_addresses = ArpAddressFact {
            .has_sender_ipv4 = parsed.has_sender_ipv4,
            .has_target_ipv4 = parsed.has_target_ipv4,
            .sender_ipv4 = parsed.sender_ipv4,
            .target_ipv4 = parsed.target_ipv4,
        },
        .status = ParseStatus::complete,
        .stop_reason = StopReason::terminal_protocol,
    };
}

}  // namespace pfl::dissection
