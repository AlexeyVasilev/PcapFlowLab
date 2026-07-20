#include "core/dissection/modules/PppoePppModules.h"

#include <algorithm>

#include "core/decode/PacketDecodeSupport.h"
#include "core/dissection/modules/CommonDirectModuleSupport.h"

namespace pfl::dissection {

namespace {

LayerBounds make_pppoe_bounds(const PacketSlice& slice, const ParsedPppoeFrame& parsed) noexcept {
    const auto full_end = parsed.header_length + parsed.declared_payload_length;
    return direct::make_layer_bounds(
        slice,
        full_end,
        parsed.header_length,
        direct::RelativeRange {.begin = parsed.header_length, .end = full_end},
        true
    );
}

LayerBounds make_ppp_bounds(const PacketSlice& slice, const std::size_t header_length) noexcept {
    const auto declared_length = direct::slice_declared_length(slice);
    return direct::make_layer_bounds(
        slice,
        declared_length,
        std::min(header_length, declared_length),
        direct::RelativeRange {.begin = std::min(header_length, declared_length), .end = declared_length},
        true
    );
}

PppoeFacts make_pppoe_facts(const ParsedPppoeFrame& parsed) noexcept {
    return PppoeFacts {
        .version = parsed.version,
        .type = parsed.type,
        .code = parsed.code,
        .session_id = parsed.session_id,
        .payload_length = parsed.payload_length,
        .is_discovery = parsed.is_discovery,
    };
}

DissectionStep make_complete_pppoe_terminal_step(
    const PacketSlice& slice,
    const ParsedPppoeFrame& parsed,
    const ParseStatus status,
    const StopReason stop_reason
) {
    return DissectionStep {
        .layer = DissectionLayerKind::pppoe,
        .bounds = make_pppoe_bounds(slice, parsed),
        .facts = make_pppoe_facts(parsed),
        .terminal_disposition = TerminalDisposition::none,
        .status = status,
        .stop_reason = stop_reason,
    };
}

}  // namespace

ParsedPppoeFrame parse_pppoe_frame(const PacketSlice& slice, const bool discovery_entry) noexcept {
    ParsedPppoeFrame parsed {
        .is_discovery = discovery_entry,
        .header_length = detail::kPppoeHeaderSize,
    };

    const auto bytes = direct::visible_captured_bytes(slice);
    if (bytes.size() < detail::kPppoeHeaderSize) {
        parsed.status = ParseStatus::truncated;
        return parsed;
    }

    parsed.version = static_cast<std::uint8_t>(bytes[0] >> 4U);
    parsed.type = static_cast<std::uint8_t>(bytes[0] & 0x0FU);
    parsed.code = bytes[1];
    parsed.session_id = detail::read_be16(bytes, 2U);
    parsed.payload_length = detail::read_be16(bytes, 4U);
    const auto advertised_payload_length = static_cast<std::size_t>(parsed.payload_length);
    const auto remaining_declared_payload_length = direct::slice_declared_length(slice) - detail::kPppoeHeaderSize;
    parsed.declared_payload_length = std::min(advertised_payload_length, remaining_declared_payload_length);

    const auto captured_payload_length = bytes.size() - detail::kPppoeHeaderSize;
    parsed.logical_payload_length = std::min<std::size_t>(parsed.declared_payload_length, captured_payload_length);
    parsed.declared_payload_exceeds_capture = advertised_payload_length > captured_payload_length;
    parsed.captured_payload_exceeds_declared = captured_payload_length > advertised_payload_length;
    parsed.status = ParseStatus::complete;
    return parsed;
}

ParsedPppFrame parse_ppp_frame(const PacketSlice& slice) noexcept {
    ParsedPppFrame parsed {
        .header_length = detail::kPppProtocolFieldSize,
    };

    const auto bytes = direct::visible_captured_bytes(slice);
    if (bytes.size() < detail::kPppProtocolFieldSize) {
        parsed.status = ParseStatus::truncated;
        return parsed;
    }

    parsed.protocol = detail::read_be16(bytes, 0U);
    parsed.declared_payload_length = direct::slice_declared_length(slice) - detail::kPppProtocolFieldSize;
    parsed.status = ParseStatus::complete;
    return parsed;
}

DissectionStep dissect_pppoe_discovery(const PacketSlice& slice) {
    const auto parsed = parse_pppoe_frame(slice, true);
    if (parsed.status != ParseStatus::complete) {
        return direct::make_error_step(
            slice,
            DissectionLayerKind::pppoe,
            parsed.status,
            StopReason::truncated,
            std::min(parsed.header_length, direct::slice_declared_length(slice))
        );
    }

    return make_complete_pppoe_terminal_step(
        slice,
        parsed,
        ParseStatus::complete,
        StopReason::terminal_protocol
    );
}

DissectionStep dissect_pppoe_session(const PacketSlice& slice) {
    const auto parsed = parse_pppoe_frame(slice, false);
    if (parsed.status != ParseStatus::complete) {
        return direct::make_error_step(
            slice,
            DissectionLayerKind::pppoe,
            parsed.status,
            StopReason::truncated,
            std::min(parsed.header_length, direct::slice_declared_length(slice))
        );
    }

    if (parsed.version != 1U || parsed.type != 1U || parsed.code != 0U) {
        return make_complete_pppoe_terminal_step(
            slice,
            parsed,
            ParseStatus::unsupported_variant,
            StopReason::unsupported_variant
        );
    }

    const auto handoff = direct::make_protocol_handoff(
        slice,
        parsed.header_length,
        parsed.declared_payload_length,
        ProtocolSelector {
            .domain = SelectorDomain::ppp_frame,
            .value = kPppFrameContinueSelectorValue,
        }
    );
    if (!handoff.has_value()) {
        return make_complete_pppoe_terminal_step(
            slice,
            parsed,
            ParseStatus::malformed,
            StopReason::malformed
        );
    }

    return DissectionStep {
        .layer = DissectionLayerKind::pppoe,
        .path_contribution = LayerKey::pppoe(),
        .path_contribution_policy = PathContributionPolicy::terminal_success,
        .bounds = make_pppoe_bounds(slice, parsed),
        .handoff = *handoff,
        .facts = make_pppoe_facts(parsed),
        .terminal_disposition = TerminalDisposition::none,
        .status = ParseStatus::complete,
        .stop_reason = StopReason::none,
    };
}

DissectionStep dissect_ppp(const PacketSlice& slice) {
    const auto parsed = parse_ppp_frame(slice);
    if (parsed.status != ParseStatus::complete) {
        return direct::make_error_step(
            slice,
            DissectionLayerKind::ppp,
            parsed.status,
            StopReason::truncated,
            std::min(parsed.header_length, direct::slice_declared_length(slice))
        );
    }

    const auto facts = PppFacts {
        .protocol = parsed.protocol,
    };

    const auto next = ProtocolSelector {
        .domain = SelectorDomain::ppp_protocol,
        .value = parsed.protocol,
    };
    const auto handoff = direct::make_protocol_handoff(
        slice,
        parsed.header_length,
        parsed.declared_payload_length,
        next
    );

    if (!handoff.has_value()) {
        return DissectionStep {
            .layer = DissectionLayerKind::ppp,
            .bounds = make_ppp_bounds(slice, parsed.header_length),
            .facts = facts,
            .terminal_disposition = TerminalDisposition::none,
            .status = ParseStatus::malformed,
            .stop_reason = StopReason::malformed,
        };
    }

    return DissectionStep {
        .layer = DissectionLayerKind::ppp,
        .path_contribution = LayerKey::ppp(),
        .path_contribution_policy = PathContributionPolicy::terminal_success,
        .bounds = make_ppp_bounds(slice, parsed.header_length),
        .handoff = *handoff,
        .facts = facts,
        .terminal_disposition = TerminalDisposition::none,
        .status = ParseStatus::complete,
        .stop_reason = StopReason::none,
    };
}

DissectionStep dissect_ppp_control(const PacketSlice& slice) {
    const auto declared_length = direct::slice_declared_length(slice);
    return DissectionStep {
        .layer = DissectionLayerKind::ppp_control,
        .bounds = direct::make_layer_bounds(
            slice,
            declared_length,
            0U,
            direct::RelativeRange {.begin = 0U, .end = declared_length},
            true
        ),
        .facts = std::monostate {},
        .terminal_disposition = TerminalDisposition::none,
        .status = ParseStatus::complete,
        .stop_reason = StopReason::terminal_protocol,
    };
}

}  // namespace pfl::dissection
