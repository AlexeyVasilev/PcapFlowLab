#pragma once

#include <algorithm>
#include <optional>
#include <span>
#include <utility>

#include "core/dissection/DissectionRegistry.h"

namespace pfl::dissection::direct {

struct RelativeRange {
    std::size_t begin {0U};
    std::size_t end {0U};
};

inline std::size_t slice_declared_length(const PacketSlice& slice) noexcept {
    return slice.declared_end() - slice.source_offset();
}

inline std::span<const std::uint8_t> visible_captured_bytes(const PacketSlice& slice) noexcept {
    return slice.captured_bytes().first(std::min(slice.captured_bytes().size(), slice_declared_length(slice)));
}

inline ByteRange require_absolute_range(const std::size_t begin, const std::size_t end) noexcept {
    return ByteRange::from_begin_end(begin, end).value_or(ByteRange {});
}

inline BoundedByteRange make_bounded_relative_range(
    const PacketSlice& slice,
    const std::size_t begin,
    const std::size_t end
) noexcept {
    const auto absolute_begin = slice.source_offset() + begin;
    const auto absolute_end = slice.source_offset() + end;
    const auto captured_absolute_end = std::min(slice.captured_end(), absolute_end);
    const auto captured_absolute_begin = std::min(absolute_begin, captured_absolute_end);
    return BoundedByteRange {
        .declared = require_absolute_range(absolute_begin, absolute_end),
        .captured = require_absolute_range(captured_absolute_begin, captured_absolute_end),
    };
}

inline LayerBounds make_layer_bounds(
    const PacketSlice& slice,
    const std::size_t full_end,
    const std::size_t header_end,
    const std::optional<RelativeRange>& payload = std::nullopt,
    const bool keep_empty_payload = false
) noexcept {
    const auto bounded_full_end = std::min(full_end, slice_declared_length(slice));
    const auto bounded_header_end = std::min(header_end, bounded_full_end);

    LayerBounds bounds {
        .source_id = slice.source_id(),
        .full = make_bounded_relative_range(slice, 0U, bounded_full_end),
        .header = make_bounded_relative_range(slice, 0U, bounded_header_end),
        .payload = std::nullopt,
    };

    if (payload.has_value() && (keep_empty_payload || payload->end > payload->begin)) {
        const auto payload_begin = std::min(payload->begin, bounded_full_end);
        const auto payload_end = std::min(payload->end, bounded_full_end);
        bounds.payload = make_bounded_relative_range(slice, payload_begin, std::max(payload_begin, payload_end));
    }

    return bounds;
}

inline DissectionStep make_error_step(
    const PacketSlice& slice,
    const LayerKey& layer,
    const ParseStatus status,
    const StopReason stop_reason,
    const std::size_t header_length = 0U
) noexcept {
    return DissectionStep {
        .layer = layer,
        .bounds = make_layer_bounds(slice, slice_declared_length(slice), header_length),
        .facts = std::monostate {},
        .terminal_disposition = TerminalDisposition::none,
        .status = status,
        .stop_reason = stop_reason,
    };
}

inline std::optional<ProtocolHandoff> make_protocol_handoff(
    const PacketSlice& slice,
    const std::size_t payload_offset,
    const std::size_t declared_payload_length,
    const ProtocolSelector selector
) noexcept {
    const auto child = make_child_slice(slice, payload_offset, declared_payload_length);
    if (!child.has_slice()) {
        return std::nullopt;
    }

    return ProtocolHandoff {
        .selector = selector,
        .child = *child.slice,
    };
}

}  // namespace pfl::dissection::direct
