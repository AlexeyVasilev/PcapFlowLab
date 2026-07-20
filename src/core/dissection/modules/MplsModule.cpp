#include "core/dissection/modules/MplsModule.h"

#include "core/decode/PacketDecodeSupport.h"
#include "core/dissection/modules/CommonDirectModuleSupport.h"

namespace pfl::dissection {

namespace {

ProtocolSelector make_mpls_stack_selector() noexcept {
    return ProtocolSelector {
        .domain = SelectorDomain::mpls_stack,
        .value = kMplsStackContinueSelectorValue,
    };
}

ProtocolSelector make_mpls_payload_selector(const std::uint16_t protocol_type) noexcept {
    return ProtocolSelector {
        .domain = SelectorDomain::mpls_payload,
        .value = protocol_type,
    };
}

}  // namespace

ParsedMplsLabel parse_mpls_label(const PacketSlice& slice) noexcept {
    const auto declared_length = direct::slice_declared_length(slice);
    if (declared_length < detail::kMplsLabelSize) {
        return ParsedMplsLabel {
            .status = ParseStatus::malformed,
            .header_length = detail::kMplsLabelSize,
        };
    }

    const auto bytes = direct::visible_captured_bytes(slice);
    if (bytes.size() < detail::kMplsLabelSize) {
        return ParsedMplsLabel {
            .status = ParseStatus::truncated,
            .header_length = detail::kMplsLabelSize,
        };
    }

    const auto entry = detail::read_be32(bytes, 0U);
    return ParsedMplsLabel {
        .status = ParseStatus::complete,
        .label = static_cast<std::uint32_t>((entry >> 12U) & 0x000FFFFFU),
        .traffic_class = static_cast<std::uint8_t>((entry >> 9U) & 0x7U),
        .bottom_of_stack = ((entry >> 8U) & 0x1U) != 0U,
        .ttl = static_cast<std::uint8_t>(entry & 0xFFU),
        .header_length = detail::kMplsLabelSize,
        .declared_payload_length = declared_length - detail::kMplsLabelSize,
    };
}

DissectionStep dissect_mpls_label(const PacketSlice& slice) {
    const auto parsed = parse_mpls_label(slice);
    if (parsed.status != ParseStatus::complete) {
        return direct::make_error_step(
            slice,
            DissectionLayerKind::mpls,
            parsed.status,
            parsed.status == ParseStatus::truncated ? StopReason::truncated : StopReason::malformed,
            detail::kMplsLabelSize
        );
    }

    DissectionStep step {
        .layer = DissectionLayerKind::mpls,
        .path_contribution = LayerKey::mpls(parsed.label),
        .bounds = direct::make_layer_bounds(
            slice,
            direct::slice_declared_length(slice),
            parsed.header_length,
            direct::RelativeRange {.begin = parsed.header_length, .end = direct::slice_declared_length(slice)},
            true
        ),
        .facts = MplsFacts {
            .label = parsed.label,
            .traffic_class = parsed.traffic_class,
            .bottom_of_stack = parsed.bottom_of_stack,
            .ttl = parsed.ttl,
        },
        .terminal_disposition = TerminalDisposition::none,
        .status = ParseStatus::complete,
        .stop_reason = StopReason::none,
    };

    if (!parsed.bottom_of_stack) {
        step.handoff = direct::make_protocol_handoff(
            slice,
            parsed.header_length,
            parsed.declared_payload_length,
            make_mpls_stack_selector()
        );
        if (!step.handoff.has_value()) {
            step.status = ParseStatus::malformed;
            step.stop_reason = StopReason::malformed;
        }
        return step;
    }

    if (parsed.declared_payload_length == 0U) {
        step.stop_reason = StopReason::no_payload;
        return step;
    }

    const auto bytes = direct::visible_captured_bytes(slice);
    if (bytes.size() <= parsed.header_length) {
        step.stop_reason = StopReason::truncated;
        return step;
    }

    const auto version_nibble = static_cast<std::uint8_t>(bytes[parsed.header_length] >> 4U);
    std::optional<ProtocolSelector> next_selector {};
    if (version_nibble == 4U) {
        next_selector = make_mpls_payload_selector(detail::kEtherTypeIpv4);
    } else if (version_nibble == 6U) {
        next_selector = make_mpls_payload_selector(detail::kEtherTypeIpv6);
    } else {
        step.stop_reason = StopReason::unrecognized_payload;
        return step;
    }

    step.handoff = direct::make_protocol_handoff(
        slice,
        parsed.header_length,
        parsed.declared_payload_length,
        *next_selector
    );
    if (!step.handoff.has_value()) {
        step.status = ParseStatus::malformed;
        step.stop_reason = StopReason::malformed;
    }
    return step;
}

}  // namespace pfl::dissection
