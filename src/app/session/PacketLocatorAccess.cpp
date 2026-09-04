#include "app/session/PacketLocatorAccess.h"

#include <algorithm>
#include <fstream>
#include <limits>
#include <optional>
#include <utility>

#include "core/index/Serialization.h"

namespace pfl::session_detail {

namespace {

[[nodiscard]] bool checked_add_u64(
    const std::uint64_t left,
    const std::uint64_t right,
    std::uint64_t& result
) noexcept {
    if (left > (std::numeric_limits<std::uint64_t>::max)() - right) {
        return false;
    }
    result = left + right;
    return true;
}

[[nodiscard]] PacketLocatorAccessStatus map_lookup_status(
    const detail::CaptureIndexV16PacketLocatorLookupReadStatus status
) noexcept {
    switch (status) {
    case detail::CaptureIndexV16PacketLocatorLookupReadStatus::ok:
        return PacketLocatorAccessStatus::ok;
    case detail::CaptureIndexV16PacketLocatorLookupReadStatus::not_found:
        return PacketLocatorAccessStatus::not_found;
    case detail::CaptureIndexV16PacketLocatorLookupReadStatus::section_seek_failed:
        return PacketLocatorAccessStatus::source_read_failed;
    case detail::CaptureIndexV16PacketLocatorLookupReadStatus::invalid_locator_section_occurrence:
    case detail::CaptureIndexV16PacketLocatorLookupReadStatus::section_range_overflow:
    case detail::CaptureIndexV16PacketLocatorLookupReadStatus::truncated_packet_locator_payload:
    case detail::CaptureIndexV16PacketLocatorLookupReadStatus::malformed_packet_locator_payload:
        return PacketLocatorAccessStatus::malformed_locator;
    }
    return PacketLocatorAccessStatus::malformed_locator;
}

[[nodiscard]] bool entry_order_is_strictly_after(
    const CapturePacketLocatorEntry& entry,
    const CapturePacketLocatorEntry& prior
) noexcept {
    return entry.packet_index > prior.packet_index && entry.file_offset > prior.file_offset;
}

[[nodiscard]] bool section_boundary_is_strictly_after(
    const CaptureIndexV16PacketLocatorSectionInfo& section,
    const CaptureIndexV16PacketLocatorSectionInfo& prior
) noexcept {
    if (section.entry_count == 0U || prior.entry_count == 0U) {
        return section.entry_count == 0U && prior.entry_count == 0U;
    }
    if (!section.first_packet_index.has_value() ||
        !section.first_file_offset.has_value() ||
        !prior.last_packet_index.has_value() ||
        !prior.last_file_offset.has_value()) {
        return false;
    }
    return *section.first_packet_index > *prior.last_packet_index &&
        *section.first_file_offset > *prior.last_file_offset;
}

}  // namespace

ResidentPacketLocatorAccessSource::ResidentPacketLocatorAccessSource(
    const std::span<const CapturePacketLocatorEntry> entries
)
    : entries_(entries) {}

PacketLocatorAccessLookupResult ResidentPacketLocatorAccessSource::lookup(
    const std::uint64_t packet_index
) const {
    PacketLocatorAccessLookupResult result {};
    const auto upper = std::upper_bound(
        entries_.begin(),
        entries_.end(),
        packet_index,
        [](const std::uint64_t value, const CapturePacketLocatorEntry& entry) {
            return value < entry.packet_index;
        }
    );
    if (upper == entries_.begin()) {
        result.status = PacketLocatorAccessStatus::not_found;
        result.error_detail = "packet index precedes the first available resident locator anchor";
        return result;
    }

    const auto found = upper - 1;
    if (found != entries_.begin()) {
        const auto previous = found - 1;
        if (!entry_order_is_strictly_after(*found, *previous)) {
            result.status = PacketLocatorAccessStatus::malformed_locator;
            result.error_detail = "resident packet locator anchors touched by lookup are not strictly increasing";
            return result;
        }
    }
    const auto next = found + 1;
    if (next != entries_.end() && !entry_order_is_strictly_after(*next, *found)) {
        result.status = PacketLocatorAccessStatus::malformed_locator;
        result.error_detail = "resident packet locator anchors touched by lookup are not strictly increasing";
        return result;
    }

    result.entry = *found;
    return result;
}

CaptureIndexV16PacketLocatorAccessSource::CaptureIndexV16PacketLocatorAccessSource(
    std::filesystem::path index_path,
    const CaptureIndexV16MetadataTier& metadata
)
    : index_path_(std::move(index_path)),
      locator_sections_(metadata.packet_locator_sections) {
    std::uint64_t expected_logical_entry_start {0};
    bool has_empty_section {false};
    bool has_non_empty_section {false};
    for (std::size_t index = 0U; index < locator_sections_.size(); ++index) {
        const auto& section = locator_sections_[index];
        has_empty_section = has_empty_section || section.entry_count == 0U;
        has_non_empty_section = has_non_empty_section || section.entry_count > 0U;
        if (section.section_occurrence_index != static_cast<std::uint32_t>(index) ||
            section.logical_entry_start != expected_logical_entry_start) {
            initialization_status_ = PacketLocatorAccessStatus::malformed_locator;
            initialization_error_detail_ =
                "v16 packet locator catalog did not preserve stable occurrence ordering";
            return;
        }
        if (section.entry_count > 0U &&
            (!section.first_packet_index.has_value() ||
             !section.last_packet_index.has_value() ||
             !section.first_file_offset.has_value() ||
             !section.last_file_offset.has_value())) {
            initialization_status_ = PacketLocatorAccessStatus::malformed_locator;
            initialization_error_detail_ =
                "v16 packet locator catalog is missing non-empty section boundary metadata";
            return;
        }
        if (index > 0U && !section_boundary_is_strictly_after(section, locator_sections_[index - 1U])) {
            initialization_status_ = PacketLocatorAccessStatus::malformed_locator;
            initialization_error_detail_ =
                "v16 packet locator section boundaries are not strictly increasing";
            return;
        }
        if (!checked_add_u64(expected_logical_entry_start, section.entry_count, expected_logical_entry_start)) {
            initialization_status_ = PacketLocatorAccessStatus::malformed_locator;
            initialization_error_detail_ = "v16 packet locator logical entry count overflowed";
            return;
        }
    }

    if (has_empty_section && has_non_empty_section) {
        initialization_status_ = PacketLocatorAccessStatus::malformed_locator;
        initialization_error_detail_ = "v16 packet locator topology cannot mix empty and non-empty sections";
        return;
    }
}

PacketLocatorAccessLookupResult CaptureIndexV16PacketLocatorAccessSource::lookup(
    const std::uint64_t packet_index
) const {
    PacketLocatorAccessLookupResult result {
        .status = initialization_status_,
        .error_detail = initialization_error_detail_,
    };
    if (initialization_status_ != PacketLocatorAccessStatus::ok) {
        return result;
    }

    std::ifstream stream(index_path_, std::ios::binary);
    if (!stream.is_open()) {
        result.status = PacketLocatorAccessStatus::source_read_failed;
        result.error_detail = "failed to open the v16 index for lazy packet locator access";
        return result;
    }

    const auto lookup_result = detail::lookup_v16_packet_locator(stream, locator_sections_, packet_index);
    if (!lookup_result) {
        result.status = map_lookup_status(lookup_result.status);
        result.error_detail = lookup_result.error_detail;
        return result;
    }

    result.entry = lookup_result.entry;
    return result;
}

}  // namespace pfl::session_detail
