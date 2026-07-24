#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

#include "core/dissection/DissectionTypes.h"

namespace pfl::dissection {

struct PacketSliceBuildResult;

class PacketSlice {
public:
    constexpr PacketSlice() noexcept = default;

    [[nodiscard]] friend constexpr bool operator==(const PacketSlice& left, const PacketSlice& right) noexcept {
        return left.source_id_ == right.source_id_ &&
               left.captured_bytes_.data() == right.captured_bytes_.data() &&
               left.captured_bytes_.size() == right.captured_bytes_.size() &&
               left.source_offset_ == right.source_offset_ &&
               left.captured_end_ == right.captured_end_ &&
               left.reported_end_ == right.reported_end_ &&
               left.declared_end_ == right.declared_end_;
    }

    [[nodiscard]] constexpr ByteSourceId source_id() const noexcept {
        return source_id_;
    }

    [[nodiscard]] constexpr std::span<const std::uint8_t> captured_bytes() const noexcept {
        return captured_bytes_;
    }

    [[nodiscard]] constexpr std::size_t source_offset() const noexcept {
        return source_offset_;
    }

    [[nodiscard]] constexpr std::size_t captured_end() const noexcept {
        return captured_end_;
    }

    [[nodiscard]] constexpr std::size_t reported_end() const noexcept {
        return reported_end_;
    }

    [[nodiscard]] constexpr std::size_t declared_end() const noexcept {
        return declared_end_;
    }

    [[nodiscard]] constexpr std::size_t captured_size() const noexcept {
        return captured_bytes_.size();
    }

    [[nodiscard]] constexpr bool empty() const noexcept {
        return captured_bytes_.empty();
    }

private:
    friend PacketSlice make_root_packet_slice(
        ByteSourceId source_id,
        std::span<const std::uint8_t> captured_bytes,
        std::size_t captured_length,
        std::size_t reported_length
    ) noexcept;
    friend PacketSliceBuildResult make_child_slice(
        const PacketSlice& parent,
        std::size_t payload_offset,
        std::size_t declared_payload_length
    ) noexcept;

    constexpr PacketSlice(
        const ByteSourceId source_id,
        const std::span<const std::uint8_t> captured_bytes,
        const std::size_t source_offset,
        const std::size_t captured_end,
        const std::size_t reported_end,
        const std::size_t declared_end
    ) noexcept
        : source_id_(source_id)
        , captured_bytes_(captured_bytes)
        , source_offset_(source_offset)
        , captured_end_(captured_end)
        , reported_end_(reported_end)
        , declared_end_(declared_end) {}

    ByteSourceId source_id_ {};
    std::span<const std::uint8_t> captured_bytes_ {};
    std::size_t source_offset_ {0U};
    std::size_t captured_end_ {0U};
    std::size_t reported_end_ {0U};
    std::size_t declared_end_ {0U};
};

enum class PacketSliceBuildStatus : std::uint8_t {
    success = 0,
    captured_truncated,
    offset_overflow,
    offset_outside_reported_range,
    offset_outside_declared_range,
    child_range_outside_reported_range,
    child_range_outside_declared_range,
};

struct PacketSliceBuildResult {
    PacketSliceBuildStatus status {PacketSliceBuildStatus::success};
    std::optional<PacketSlice> slice {};

    [[nodiscard]] bool has_slice() const noexcept {
        return slice.has_value();
    }

    [[nodiscard]] bool success() const noexcept {
        return status == PacketSliceBuildStatus::success;
    }

    [[nodiscard]] bool truncated() const noexcept {
        return status == PacketSliceBuildStatus::captured_truncated;
    }
};

[[nodiscard]] PacketSlice make_root_packet_slice(
    ByteSourceId source_id,
    std::span<const std::uint8_t> captured_bytes,
    std::size_t captured_length,
    std::size_t reported_length
) noexcept;

[[nodiscard]] PacketSliceBuildResult make_child_slice(
    const PacketSlice& parent,
    std::size_t payload_offset,
    std::size_t declared_payload_length
) noexcept;

}  // namespace pfl::dissection
