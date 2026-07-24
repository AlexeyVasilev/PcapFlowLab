#include "core/dissection/PacketSlice.h"

#include <algorithm>

namespace pfl::dissection {

namespace {

bool addition_overflows(const std::size_t left, const std::size_t right) noexcept {
    return right > (static_cast<std::size_t>(-1) - left);
}

}  // namespace

PacketSlice make_root_packet_slice(
    const ByteSourceId source_id,
    const std::span<const std::uint8_t> captured_bytes,
    const std::size_t captured_length,
    const std::size_t reported_length
) noexcept {
    const auto visible_captured_length = std::min(captured_length, captured_bytes.size());
    return PacketSlice {
        source_id,
        captured_bytes.first(visible_captured_length),
        0U,
        visible_captured_length,
        reported_length,
        reported_length,
    };
}

PacketSliceBuildResult make_child_slice(
    const PacketSlice& parent,
    const std::size_t payload_offset,
    const std::size_t declared_payload_length
) noexcept {
    if (addition_overflows(parent.source_offset(), payload_offset)) {
        return PacketSliceBuildResult {
            .status = PacketSliceBuildStatus::offset_overflow,
        };
    }

    const auto child_offset = parent.source_offset() + payload_offset;
    if (child_offset > parent.reported_end()) {
        return PacketSliceBuildResult {
            .status = PacketSliceBuildStatus::offset_outside_reported_range,
        };
    }
    if (child_offset > parent.declared_end()) {
        return PacketSliceBuildResult {
            .status = PacketSliceBuildStatus::offset_outside_declared_range,
        };
    }

    if (addition_overflows(child_offset, declared_payload_length)) {
        return PacketSliceBuildResult {
            .status = PacketSliceBuildStatus::offset_overflow,
        };
    }

    const auto child_declared_end = child_offset + declared_payload_length;
    if (child_declared_end > parent.reported_end()) {
        return PacketSliceBuildResult {
            .status = PacketSliceBuildStatus::child_range_outside_reported_range,
        };
    }
    if (child_declared_end > parent.declared_end()) {
        return PacketSliceBuildResult {
            .status = PacketSliceBuildStatus::child_range_outside_declared_range,
        };
    }

    const auto clamped_captured_end = std::min(parent.captured_end(), child_declared_end);
    const auto child_captured_end = std::max(child_offset, clamped_captured_end);
    const auto captured_offset_in_parent = child_offset - parent.source_offset();
    const auto span_offset = std::min(captured_offset_in_parent, parent.captured_bytes().size());
    const auto captured_length = child_captured_end - child_offset;
    const auto child_bytes = parent.captured_bytes().subspan(span_offset, captured_length);

    const auto status = child_captured_end < child_declared_end
        ? PacketSliceBuildStatus::captured_truncated
        : PacketSliceBuildStatus::success;

    return PacketSliceBuildResult {
        .status = status,
        .slice = PacketSlice {
            parent.source_id(),
            child_bytes,
            child_offset,
            child_captured_end,
            parent.reported_end(),
            child_declared_end,
        },
    };
}

}  // namespace pfl::dissection
