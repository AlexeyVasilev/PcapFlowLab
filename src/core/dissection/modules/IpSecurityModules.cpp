#include "core/dissection/modules/IpSecurityModules.h"

#include <algorithm>

#include "core/decode/PacketDecodeSupport.h"
#include "core/dissection/modules/CommonDirectModuleSupport.h"

namespace pfl::dissection {

namespace {

ParseStatus status_from_child_build_result(const PacketSliceBuildStatus status) noexcept {
    return status == PacketSliceBuildStatus::captured_truncated ? ParseStatus::truncated : ParseStatus::malformed;
}

StopReason stop_reason_from_child_build_result(const PacketSliceBuildStatus status) noexcept {
    return status == PacketSliceBuildStatus::captured_truncated ? StopReason::truncated : StopReason::malformed;
}

ProtocolSelector make_ah_next_selector(
    const SelectorDomain domain,
    const std::uint8_t next_header
) noexcept {
    return ProtocolSelector {
        .domain = domain,
        .value = next_header,
    };
}

DissectionStep dissect_ah(
    const PacketSlice& slice,
    const SelectorDomain next_selector_domain
) {
    const auto parsed = parse_ah_header(slice);
    if (parsed.status != ParseStatus::complete) {
        return direct::make_error_step(
            slice,
            DissectionLayerKind::ah,
            parsed.status,
            parsed.status == ParseStatus::truncated ? StopReason::truncated : StopReason::malformed,
            12U
        );
    }

    DissectionStep step {
        .layer = DissectionLayerKind::ah,
        .path_contribution = LayerKey::ah(parsed.spi),
        .bounds = direct::make_layer_bounds(
            slice,
            parsed.header_length,
            parsed.header_length,
            direct::RelativeRange {.begin = parsed.header_length, .end = direct::slice_declared_length(slice)},
            true
        ),
        .facts = AhFacts {
            .next_header = parsed.next_header,
            .payload_length_field = parsed.payload_length_field,
            .reserved = parsed.reserved,
            .spi = parsed.spi,
            .sequence_number = parsed.sequence_number,
            .header_length = static_cast<std::uint16_t>(parsed.header_length),
            .icv_length = static_cast<std::uint16_t>(parsed.icv_length),
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
        step.status = status_from_child_build_result(child_result.status);
        step.stop_reason = stop_reason_from_child_build_result(child_result.status);
        return step;
    }

    step.handoff = ProtocolHandoff {
        .selector = make_ah_next_selector(next_selector_domain, parsed.next_header),
        .child = *child_result.slice,
    };
    return step;
}

}  // namespace

ParsedAhHeader parse_ah_header(const PacketSlice& slice) noexcept {
    const auto declared_length = direct::slice_declared_length(slice);
    if (declared_length < 12U) {
        return ParsedAhHeader {
            .status = ParseStatus::malformed,
        };
    }

    const auto bytes = direct::visible_captured_bytes(slice);
    if (bytes.size() < 12U) {
        return ParsedAhHeader {
            .status = ParseStatus::truncated,
        };
    }

    const auto payload_length_field = bytes[1U];
    const auto header_length = static_cast<std::size_t>(payload_length_field + 2U) * 4U;
    if (header_length < 12U || header_length > declared_length) {
        return ParsedAhHeader {
            .status = ParseStatus::malformed,
        };
    }

    if (bytes.size() < header_length) {
        return ParsedAhHeader {
            .status = ParseStatus::truncated,
        };
    }

    return ParsedAhHeader {
        .status = ParseStatus::complete,
        .next_header = bytes[0U],
        .payload_length_field = payload_length_field,
        .reserved = detail::read_be16(bytes, 2U),
        .spi = detail::read_be32(bytes, 4U),
        .sequence_number = detail::read_be32(bytes, 8U),
        .header_length = header_length,
        .icv_length = header_length - 12U,
    };
}

ParsedEspHeader parse_esp_header(const PacketSlice& slice) noexcept {
    const auto declared_length = direct::slice_declared_length(slice);
    if (declared_length < detail::kEspBaseHeaderSize) {
        return ParsedEspHeader {
            .status = ParseStatus::malformed,
        };
    }

    const auto bytes = direct::visible_captured_bytes(slice);
    if (bytes.size() < detail::kEspBaseHeaderSize) {
        return ParsedEspHeader {
            .status = ParseStatus::truncated,
        };
    }

    return ParsedEspHeader {
        .status = ParseStatus::complete,
        .spi = detail::read_be32(bytes, 0U),
        .sequence_number = detail::read_be32(bytes, 4U),
        .header_length = detail::kEspBaseHeaderSize,
    };
}

DissectionStep dissect_ipv4_ah(const PacketSlice& slice) {
    return dissect_ah(slice, SelectorDomain::ip_protocol);
}

DissectionStep dissect_ipv6_ah(const PacketSlice& slice) {
    return dissect_ah(slice, SelectorDomain::ipv6_next_header);
}

DissectionStep dissect_esp(const PacketSlice& slice) {
    const auto parsed = parse_esp_header(slice);
    if (parsed.status != ParseStatus::complete) {
        return direct::make_error_step(
            slice,
            DissectionLayerKind::esp,
            parsed.status,
            parsed.status == ParseStatus::truncated ? StopReason::truncated : StopReason::malformed,
            detail::kEspBaseHeaderSize
        );
    }

    return DissectionStep {
        .layer = DissectionLayerKind::esp,
        .path_contribution = LayerKey::esp(parsed.spi),
        .bounds = direct::make_layer_bounds(
            slice,
            direct::slice_declared_length(slice),
            parsed.header_length,
            direct::RelativeRange {.begin = parsed.header_length, .end = direct::slice_declared_length(slice)},
            true
        ),
        .facts = EspFacts {
            .spi = parsed.spi,
            .sequence_number = parsed.sequence_number,
        },
        .terminal_disposition = TerminalDisposition::flow_candidate,
        .status = ParseStatus::complete,
        .stop_reason = StopReason::terminal_protocol,
    };
}

}  // namespace pfl::dissection
