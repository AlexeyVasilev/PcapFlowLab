#include "core/dissection/modules/Ipv6ExtensionModules.h"

#include "core/decode/PacketDecodeSupport.h"
#include "core/dissection/modules/CommonDirectModuleSupport.h"

namespace pfl::dissection {

namespace {

ProtocolSelector make_ipv6_next_header_selector(const std::uint8_t next_header) noexcept {
    return ProtocolSelector {
        .domain = SelectorDomain::ipv6_next_header,
        .value = next_header,
    };
}

DissectionLayerKind layer_kind_from_extension_kind(const Ipv6ExtensionHeaderKind kind) noexcept {
    switch (kind) {
    case Ipv6ExtensionHeaderKind::routing:
        return DissectionLayerKind::ipv6_routing;
    case Ipv6ExtensionHeaderKind::destination_options:
        return DissectionLayerKind::ipv6_destination_options;
    case Ipv6ExtensionHeaderKind::hop_by_hop:
    default:
        return DissectionLayerKind::ipv6_hop_by_hop;
    }
}

ParseStatus step_error_status_from_child_build(const PacketSliceBuildStatus status) noexcept {
    return status == PacketSliceBuildStatus::captured_truncated ? ParseStatus::truncated : ParseStatus::malformed;
}

StopReason step_error_stop_reason_from_child_build(const PacketSliceBuildStatus status) noexcept {
    return status == PacketSliceBuildStatus::captured_truncated ? StopReason::truncated : StopReason::malformed;
}

DissectionStep make_ipv6_extension_step(
    const PacketSlice& slice,
    const ParsedIpv6ExtensionHeader& parsed
) {
    DissectionStep step {
        .layer = layer_kind_from_extension_kind(parsed.kind),
        .bounds = direct::make_layer_bounds(slice, parsed.header_length, parsed.header_length),
        .facts = Ipv6ExtensionFacts {
            .kind = layer_kind_from_extension_kind(parsed.kind),
            .next_header = parsed.next_header,
            .header_length = parsed.header_length,
        },
        .terminal_disposition = TerminalDisposition::none,
        .status = ParseStatus::complete,
        .stop_reason = StopReason::none,
    };

    const auto child_result = make_child_slice(
        slice,
        parsed.header_length,
        direct::slice_declared_length(slice) - parsed.header_length
    );
    if (!child_result.has_slice()) {
        step.status = step_error_status_from_child_build(child_result.status);
        step.stop_reason = step_error_stop_reason_from_child_build(child_result.status);
        return step;
    }

    step.handoff = ProtocolHandoff {
        .selector = make_ipv6_next_header_selector(parsed.next_header),
        .child = *child_result.slice,
    };
    return step;
}

DissectionStep make_ipv6_fragment_step(
    const PacketSlice& slice,
    const ParsedIpv6FragmentHeader& parsed
) {
    DissectionStep step {
        .layer = DissectionLayerKind::ipv6_fragment,
        .bounds = direct::make_layer_bounds(slice, parsed.header_length, parsed.header_length),
        .facts = Ipv6FragmentFacts {
            .next_header = parsed.next_header,
            .header_length = parsed.header_length,
            .fragment_offset_units = parsed.fragment_offset_units,
            .more_fragments = parsed.more_fragments,
            .is_atomic_fragment = parsed.is_atomic_fragment,
        },
        .terminal_disposition = TerminalDisposition::none,
        .status = ParseStatus::complete,
        .stop_reason = StopReason::none,
    };

    step.handoff = direct::make_selector_handoff(make_ipv6_next_header_selector(parsed.next_header));
    step.stop_reason = StopReason::needs_reassembly;
    return step;
}

DissectionStep dissect_ipv6_extension(const PacketSlice& slice, const Ipv6ExtensionHeaderKind kind) {
    const auto parsed = parse_ipv6_extension_header(slice, kind);
    if (parsed.status != ParseStatus::complete) {
        return direct::make_error_step(
            slice,
            layer_kind_from_extension_kind(kind),
            parsed.status,
            parsed.status == ParseStatus::truncated ? StopReason::truncated : StopReason::malformed,
            2U
        );
    }

    return make_ipv6_extension_step(slice, parsed);
}

}  // namespace

ParsedIpv6ExtensionHeader parse_ipv6_extension_header(
    const PacketSlice& slice,
    const Ipv6ExtensionHeaderKind kind
) noexcept {
    const auto declared_length = direct::slice_declared_length(slice);
    if (declared_length < 8U) {
        return ParsedIpv6ExtensionHeader {
            .status = ParseStatus::malformed,
            .kind = kind,
        };
    }

    const auto bytes = direct::visible_captured_bytes(slice);
    if (bytes.size() < 2U) {
        return ParsedIpv6ExtensionHeader {
            .status = ParseStatus::truncated,
            .kind = kind,
        };
    }

    const auto header_length = static_cast<std::size_t>(bytes[1U] + 1U) * 8U;
    if (header_length < 8U || header_length > declared_length) {
        return ParsedIpv6ExtensionHeader {
            .status = ParseStatus::malformed,
            .kind = kind,
        };
    }

    if (bytes.size() < header_length) {
        return ParsedIpv6ExtensionHeader {
            .status = ParseStatus::truncated,
            .kind = kind,
        };
    }

    return ParsedIpv6ExtensionHeader {
        .status = ParseStatus::complete,
        .kind = kind,
        .next_header = bytes[0U],
        .header_length = header_length,
    };
}

ParsedIpv6FragmentHeader parse_ipv6_fragment_header(const PacketSlice& slice) noexcept {
    const auto declared_length = direct::slice_declared_length(slice);
    if (declared_length < 8U) {
        return ParsedIpv6FragmentHeader {
            .status = ParseStatus::malformed,
        };
    }

    const auto bytes = direct::visible_captured_bytes(slice);
    if (bytes.size() < 8U) {
        return ParsedIpv6FragmentHeader {
            .status = ParseStatus::truncated,
        };
    }

    const auto offset_and_flags = detail::read_be16(bytes, 2U);
    const auto fragment_offset_units = static_cast<std::uint16_t>((offset_and_flags & 0xFFF8U) >> 3U);
    const auto more_fragments = (offset_and_flags & 0x0001U) != 0U;
    return ParsedIpv6FragmentHeader {
        .status = ParseStatus::complete,
        .next_header = bytes[0U],
        .header_length = 8U,
        .fragment_offset_units = fragment_offset_units,
        .more_fragments = more_fragments,
        .is_atomic_fragment = fragment_offset_units == 0U && !more_fragments,
    };
}

DissectionStep dissect_ipv6_hop_by_hop(const PacketSlice& slice) {
    return dissect_ipv6_extension(slice, Ipv6ExtensionHeaderKind::hop_by_hop);
}

DissectionStep dissect_ipv6_routing(const PacketSlice& slice) {
    return dissect_ipv6_extension(slice, Ipv6ExtensionHeaderKind::routing);
}

DissectionStep dissect_ipv6_destination_options(const PacketSlice& slice) {
    return dissect_ipv6_extension(slice, Ipv6ExtensionHeaderKind::destination_options);
}

DissectionStep dissect_ipv6_fragment(const PacketSlice& slice) {
    const auto parsed = parse_ipv6_fragment_header(slice);
    if (parsed.status != ParseStatus::complete) {
        return direct::make_error_step(
            slice,
            DissectionLayerKind::ipv6_fragment,
            parsed.status,
            parsed.status == ParseStatus::truncated ? StopReason::truncated : StopReason::malformed,
            8U
        );
    }

    return make_ipv6_fragment_step(slice, parsed);
}

}  // namespace pfl::dissection
