#include "core/dissection/modules/LlcSnapModule.h"

#include <array>

#include "core/decode/PacketDecodeSupport.h"
#include "core/dissection/modules/CommonDirectModuleSupport.h"

namespace pfl::dissection {

namespace {

std::uint32_t compact_oui(const std::array<std::uint8_t, 3>& oui) noexcept {
    return (static_cast<std::uint32_t>(oui[0]) << 16U) |
        (static_cast<std::uint32_t>(oui[1]) << 8U) |
        static_cast<std::uint32_t>(oui[2]);
}

LayerBounds make_llc_snap_bounds(
    const PacketSlice& slice,
    const std::size_t full_end,
    const std::size_t header_end,
    const bool expose_payload
) noexcept {
    return direct::make_layer_bounds(
        slice,
        full_end,
        header_end,
        expose_payload
            ? std::optional<direct::RelativeRange> {direct::RelativeRange {.begin = header_end, .end = full_end}}
            : std::nullopt,
        true
    );
}

}  // namespace

ParsedLlcSnapPayload parse_llc_snap_payload(const PacketSlice& slice) noexcept {
    const auto bounded_bytes = direct::visible_captured_bytes(slice);
    const auto view = detail::parse_llc_snap_payload(bounded_bytes, 0U, direct::slice_declared_length(slice));

    ParsedLlcSnapPayload parsed {};
    parsed.dsap = view.dsap;
    parsed.ssap = view.ssap;
    parsed.control = view.control;

    if (view.llc_header_truncated) {
        parsed.status = ParseStatus::truncated;
        parsed.header_length = std::min<std::size_t>(detail::kLlcHeaderSize, direct::slice_declared_length(slice));
        return parsed;
    }

    if (!view.has_llc) {
        parsed.status = ParseStatus::malformed;
        return parsed;
    }

    if (!view.has_snap) {
        parsed.status = ParseStatus::complete;
        parsed.header_length = detail::kLlcHeaderSize;
        return parsed;
    }

    if (view.snap_header_truncated) {
        parsed.status = ParseStatus::truncated;
        parsed.header_length = std::min<std::size_t>(detail::kLlcSnapHeaderSize, direct::slice_declared_length(slice));
        return parsed;
    }

    parsed.status = ParseStatus::complete;
    parsed.has_snap = true;
    parsed.oui = compact_oui(view.oui);
    parsed.pid = view.pid;
    parsed.pid_supported = view.resolved_supported_protocol;
    parsed.header_length = detail::kLlcSnapHeaderSize;
    return parsed;
}

DissectionStep dissect_llc_snap(const PacketSlice& slice) {
    const auto parsed = parse_llc_snap_payload(slice);
    const auto declared_length = direct::slice_declared_length(slice);

    if (parsed.status == ParseStatus::truncated) {
        return DissectionStep {
            .layer = DissectionLayerKind::llc_snap,
            .bounds = make_llc_snap_bounds(slice, declared_length, parsed.header_length, false),
            .facts = std::monostate {},
            .terminal_disposition = TerminalDisposition::none,
            .status = ParseStatus::truncated,
            .stop_reason = StopReason::truncated,
        };
    }

    if (parsed.status != ParseStatus::complete) {
        return DissectionStep {
            .layer = DissectionLayerKind::llc_snap,
            .bounds = make_llc_snap_bounds(slice, declared_length, 0U, false),
            .facts = std::monostate {},
            .terminal_disposition = TerminalDisposition::none,
            .status = ParseStatus::malformed,
            .stop_reason = StopReason::malformed,
        };
    }

    const auto facts = LlcSnapFacts {
        .dsap = parsed.dsap,
        .ssap = parsed.ssap,
        .control = parsed.control,
        .has_snap = parsed.has_snap,
        .oui = parsed.oui,
        .pid = parsed.pid,
    };

    if (!parsed.has_snap) {
        return DissectionStep {
            .layer = DissectionLayerKind::llc_snap,
            .bounds = make_llc_snap_bounds(slice, detail::kLlcHeaderSize, detail::kLlcHeaderSize, false),
            .facts = facts,
            .terminal_disposition = TerminalDisposition::none,
            .status = ParseStatus::complete,
            .stop_reason = StopReason::unrecognized_payload,
        };
    }

    if (!parsed.pid_supported) {
        return DissectionStep {
            .layer = DissectionLayerKind::llc_snap,
            .bounds = make_llc_snap_bounds(slice, detail::kLlcSnapHeaderSize, detail::kLlcSnapHeaderSize, false),
            .facts = facts,
            .terminal_disposition = TerminalDisposition::none,
            .status = ParseStatus::complete,
            .stop_reason = StopReason::unrecognized_payload,
        };
    }

    const auto handoff = direct::make_protocol_handoff(
        slice,
        detail::kLlcSnapHeaderSize,
        declared_length - detail::kLlcSnapHeaderSize,
        ProtocolSelector {
            .domain = SelectorDomain::llc_snap_pid,
            .value = parsed.pid,
        }
    );
    if (!handoff.has_value()) {
        return DissectionStep {
            .layer = DissectionLayerKind::llc_snap,
            .bounds = make_llc_snap_bounds(slice, declared_length, detail::kLlcSnapHeaderSize, true),
            .facts = facts,
            .terminal_disposition = TerminalDisposition::none,
            .status = ParseStatus::malformed,
            .stop_reason = StopReason::malformed,
        };
    }

    return DissectionStep {
        .layer = DissectionLayerKind::llc_snap,
        .path_contribution = LayerKey::llc_snap(),
        .path_contribution_policy = PathContributionPolicy::terminal_success,
        .bounds = make_llc_snap_bounds(slice, declared_length, detail::kLlcSnapHeaderSize, true),
        .handoff = *handoff,
        .facts = facts,
        .terminal_disposition = TerminalDisposition::none,
        .status = ParseStatus::complete,
        .stop_reason = StopReason::none,
    };
}

}  // namespace pfl::dissection
