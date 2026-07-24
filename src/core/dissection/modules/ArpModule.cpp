#include "core/dissection/modules/ArpModule.h"

#include "core/decode/PacketDecodeSupport.h"
#include "core/dissection/modules/CommonDirectModuleSupport.h"

namespace pfl::dissection {

namespace {

LayerBounds make_exact_arp_bounds(const PacketSlice& slice, const std::size_t declared_length) {
    const auto bounded_declared_length = std::min(declared_length, direct::slice_declared_length(slice));
    const auto bounded_header_length = std::min<std::size_t>(8U, bounded_declared_length);
    LayerBounds bounds {
        .source_id = slice.source_id(),
        .full = direct::make_bounded_relative_range(slice, 0U, bounded_declared_length),
        .header = direct::make_bounded_relative_range(slice, 0U, bounded_header_length),
        .payload = std::optional<BoundedByteRange> {
            direct::make_bounded_relative_range(slice, bounded_header_length, bounded_declared_length),
        },
    };
    return bounds;
}

}  // namespace

ParsedArpPacket parse_arp_packet(const PacketSlice& slice) noexcept {
    ParsedArpPacket parsed {};
    const auto bytes = direct::visible_captured_bytes(slice);
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
    const auto enclosing_declared_length = direct::slice_declared_length(slice);
    parsed.declared_length = static_cast<std::size_t>(8U + (2U * hardware_size) + (2U * protocol_size));
    if (parsed.declared_length > enclosing_declared_length) {
        parsed.status = ParseStatus::malformed;
        return parsed;
    }

    if (available_bytes < parsed.declared_length) {
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

DissectionStep dissect_arp(const PacketSlice& slice) {
    const auto parsed = parse_arp_packet(slice);
    if (parsed.status != ParseStatus::complete) {
        const auto bounds = parsed.fixed_header_truncated
            ? direct::make_layer_bounds(
                slice,
                direct::slice_declared_length(slice),
                std::min<std::size_t>(8U, direct::slice_declared_length(slice))
            )
            : make_exact_arp_bounds(slice, parsed.declared_length);
        return DissectionStep {
            .layer = DissectionLayerKind::arp,
            .bounds = bounds,
            .facts = std::monostate {},
            .terminal_disposition = TerminalDisposition::none,
            .status = parsed.status,
            .stop_reason = parsed.status == ParseStatus::truncated ? StopReason::truncated : StopReason::malformed,
        };
    }

    return DissectionStep {
        .layer = DissectionLayerKind::arp,
        .bounds = make_exact_arp_bounds(slice, parsed.declared_length),
        .facts = ArpFacts {
            .hardware_type = parsed.hardware_type,
            .protocol_type = parsed.protocol_type,
            .hardware_size = parsed.hardware_size,
            .protocol_size = parsed.protocol_size,
            .opcode = parsed.opcode,
            .has_sender_ipv4 = parsed.has_sender_ipv4,
            .has_target_ipv4 = parsed.has_target_ipv4,
            .sender_ipv4 = parsed.sender_ipv4,
            .target_ipv4 = parsed.target_ipv4,
        },
        .terminal_disposition = TerminalDisposition::flow_candidate,
        .status = ParseStatus::complete,
        .stop_reason = StopReason::terminal_protocol,
    };
}

}  // namespace pfl::dissection
