#include "core/dissection/modules/LinuxCookedModules.h"

#include <algorithm>

#include "core/decode/PacketDecodeSupport.h"
#include "core/dissection/modules/ArpModule.h"
#include "core/dissection/modules/CommonDirectModuleSupport.h"

namespace pfl::dissection {

namespace {

LayerBounds make_exact_arp_bounds(const PacketSlice& slice, const std::size_t declared_length) {
    const auto bounded_declared_length = std::min(declared_length, direct::slice_declared_length(slice));
    const auto bounded_header_length = std::min<std::size_t>(8U, bounded_declared_length);
    return LayerBounds {
        .source_id = slice.source_id(),
        .full = direct::make_bounded_relative_range(slice, 0U, bounded_declared_length),
        .header = direct::make_bounded_relative_range(slice, 0U, bounded_header_length),
        .payload = std::optional<BoundedByteRange> {
            direct::make_bounded_relative_range(slice, bounded_header_length, bounded_declared_length),
        },
    };
}

DissectionStep make_linux_cooked_step(
    const PacketSlice& slice,
    const ParsedLinuxCookedFrame& parsed,
    const DissectionLayerKind layer_kind,
    const LayerKey layer_key
) {
    const auto handoff = direct::make_protocol_handoff(
        slice,
        parsed.header_length,
        parsed.declared_payload_length,
        ProtocolSelector {
            .domain = SelectorDomain::linux_cooked_protocol,
            .value = parsed.protocol_type,
        }
    );
    if (!handoff.has_value()) {
        return direct::make_error_step(
            slice,
            layer_kind,
            ParseStatus::malformed,
            StopReason::malformed,
            parsed.header_length
        );
    }

    return DissectionStep {
        .layer = layer_kind,
        .path_contribution = layer_key,
        .path_commit_policy = PathCommitPolicy::recognized_flow_or_recognized_non_flow,
        .bounds = direct::make_layer_bounds(
            slice,
            direct::slice_declared_length(slice),
            parsed.header_length,
            direct::RelativeRange {.begin = parsed.header_length, .end = direct::slice_declared_length(slice)},
            true
        ),
        .handoff = *handoff,
        .facts = LinuxCookedFacts {
            .is_sll2 = parsed.is_sll2,
            .protocol_type = parsed.protocol_type,
            .packet_type = parsed.packet_type,
            .hardware_type = parsed.hardware_type,
            .address_length = parsed.address_length,
            .reserved = parsed.reserved,
            .interface_index = parsed.interface_index,
        },
        .terminal_disposition = TerminalDisposition::none,
        .status = ParseStatus::complete,
        .stop_reason = StopReason::none,
    };
}

}  // namespace

ParsedLinuxCookedFrame parse_linux_sll_frame(const PacketSlice& slice) noexcept {
    const auto bytes = direct::visible_captured_bytes(slice);
    if (bytes.size() < detail::kLinuxSllHeaderSize) {
        return ParsedLinuxCookedFrame {
            .status = ParseStatus::truncated,
            .is_sll2 = false,
        };
    }

    return ParsedLinuxCookedFrame {
        .status = ParseStatus::complete,
        .is_sll2 = false,
        .protocol_type = detail::read_be16(bytes, 14U),
        .packet_type = detail::read_be16(bytes, 0U),
        .hardware_type = detail::read_be16(bytes, 2U),
        .address_length = detail::read_be16(bytes, 4U),
        .header_length = detail::kLinuxSllHeaderSize,
        .declared_payload_length = direct::slice_declared_length(slice) - detail::kLinuxSllHeaderSize,
    };
}

ParsedLinuxCookedFrame parse_linux_sll2_frame(const PacketSlice& slice) noexcept {
    const auto bytes = direct::visible_captured_bytes(slice);
    if (bytes.size() < detail::kLinuxSll2HeaderSize) {
        return ParsedLinuxCookedFrame {
            .status = ParseStatus::truncated,
            .is_sll2 = true,
        };
    }

    return ParsedLinuxCookedFrame {
        .status = ParseStatus::complete,
        .is_sll2 = true,
        .protocol_type = detail::read_be16(bytes, 0U),
        .packet_type = bytes[10U],
        .hardware_type = detail::read_be16(bytes, 8U),
        .address_length = bytes[11U],
        .reserved = detail::read_be16(bytes, 2U),
        .interface_index = detail::read_be32(bytes, 4U),
        .header_length = detail::kLinuxSll2HeaderSize,
        .declared_payload_length = direct::slice_declared_length(slice) - detail::kLinuxSll2HeaderSize,
    };
}

DissectionStep dissect_linux_sll(const PacketSlice& slice) {
    const auto parsed = parse_linux_sll_frame(slice);
    if (parsed.status != ParseStatus::complete) {
        return direct::make_error_step(
            slice,
            DissectionLayerKind::linux_sll,
            parsed.status,
            StopReason::truncated,
            std::min<std::size_t>(detail::kLinuxSllHeaderSize, direct::slice_declared_length(slice))
        );
    }

    return make_linux_cooked_step(slice, parsed, DissectionLayerKind::linux_sll, LayerKey::linux_sll());
}

DissectionStep dissect_linux_sll2(const PacketSlice& slice) {
    const auto parsed = parse_linux_sll2_frame(slice);
    if (parsed.status != ParseStatus::complete) {
        return direct::make_error_step(
            slice,
            DissectionLayerKind::linux_sll2,
            parsed.status,
            StopReason::truncated,
            std::min<std::size_t>(detail::kLinuxSll2HeaderSize, direct::slice_declared_length(slice))
        );
    }

    return make_linux_cooked_step(slice, parsed, DissectionLayerKind::linux_sll2, LayerKey::linux_sll2());
}

DissectionStep dissect_linux_cooked_arp(const PacketSlice& slice) {
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
        .terminal_disposition = TerminalDisposition::recognized_non_flow,
        .status = ParseStatus::complete,
        .stop_reason = StopReason::terminal_protocol,
    };
}

}  // namespace pfl::dissection
