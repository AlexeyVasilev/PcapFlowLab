#include "app/session/UnrecognizedPacketAccess.h"

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

[[nodiscard]] UnrecognizedPacketAccessStatus map_directory_status(
    const detail::CaptureIndexV16UnrecognizedDirectoryRangeReadStatus status
) noexcept {
    switch (status) {
    case detail::CaptureIndexV16UnrecognizedDirectoryRangeReadStatus::ok:
        return UnrecognizedPacketAccessStatus::ok;
    case detail::CaptureIndexV16UnrecognizedDirectoryRangeReadStatus::invalid_offset:
        return UnrecognizedPacketAccessStatus::invalid_offset;
    case detail::CaptureIndexV16UnrecognizedDirectoryRangeReadStatus::invalid_requested_length:
        return UnrecognizedPacketAccessStatus::invalid_requested_length;
    case detail::CaptureIndexV16UnrecognizedDirectoryRangeReadStatus::section_seek_failed:
        return UnrecognizedPacketAccessStatus::source_read_failed;
    case detail::CaptureIndexV16UnrecognizedDirectoryRangeReadStatus::invalid_directory_section_occurrence:
    case detail::CaptureIndexV16UnrecognizedDirectoryRangeReadStatus::section_range_overflow:
    case detail::CaptureIndexV16UnrecognizedDirectoryRangeReadStatus::truncated_directory_payload:
    case detail::CaptureIndexV16UnrecognizedDirectoryRangeReadStatus::malformed_directory_payload:
    case detail::CaptureIndexV16UnrecognizedDirectoryRangeReadStatus::row_number_inconsistency:
    case detail::CaptureIndexV16UnrecognizedDirectoryRangeReadStatus::packet_index_not_strictly_increasing:
        return UnrecognizedPacketAccessStatus::malformed_directory;
    }
    return UnrecognizedPacketAccessStatus::malformed_directory;
}

[[nodiscard]] UnrecognizedPacketAccessStatus map_reason_status(
    const detail::CaptureIndexV16UnrecognizedReasonReadStatus status
) noexcept {
    switch (status) {
    case detail::CaptureIndexV16UnrecognizedReasonReadStatus::ok:
        return UnrecognizedPacketAccessStatus::ok;
    case detail::CaptureIndexV16UnrecognizedReasonReadStatus::section_seek_failed:
        return UnrecognizedPacketAccessStatus::source_read_failed;
    case detail::CaptureIndexV16UnrecognizedReasonReadStatus::invalid_reason_section_occurrence:
    case detail::CaptureIndexV16UnrecognizedReasonReadStatus::invalid_reason_range:
    case detail::CaptureIndexV16UnrecognizedReasonReadStatus::reason_length_too_large:
    case detail::CaptureIndexV16UnrecognizedReasonReadStatus::truncated_reason_payload:
        return UnrecognizedPacketAccessStatus::malformed_reason_reference;
    }
    return UnrecognizedPacketAccessStatus::malformed_reason_reference;
}

}  // namespace

ResidentUnrecognizedPacketAccessSource::ResidentUnrecognizedPacketAccessSource(
    const std::span<const UnrecognizedPacketRecord> records
)
    : records_(records) {}

UnrecognizedPacketAccessCountResult ResidentUnrecognizedPacketAccessSource::row_count() const {
    return UnrecognizedPacketAccessCountResult {
        .row_count = static_cast<std::uint64_t>(records_.size()),
    };
}

UnrecognizedPacketAccessReadResult ResidentUnrecognizedPacketAccessSource::read_range(
    const std::uint64_t offset,
    const std::uint64_t limit
) const {
    UnrecognizedPacketAccessReadResult result {
        .total_row_count = static_cast<std::uint64_t>(records_.size()),
    };

    if (offset > result.total_row_count) {
        result.status = UnrecognizedPacketAccessStatus::invalid_offset;
        result.error_detail = "requested resident unrecognized row offset is past the end of the logical row space";
        return result;
    }
    if (limit == 0U || offset == result.total_row_count) {
        return result;
    }

    std::uint64_t requested_end {0};
    if (!checked_add_u64(offset, limit, requested_end)) {
        result.status = UnrecognizedPacketAccessStatus::invalid_requested_length;
        result.error_detail = "requested resident unrecognized row range overflowed";
        return result;
    }

    const auto effective_end = std::min(requested_end, result.total_row_count);
    result.rows.reserve(static_cast<std::size_t>(effective_end - offset));

    std::optional<std::uint64_t> prior_packet_index {};
    for (std::uint64_t index = offset; index < effective_end; ++index) {
        const auto& record = records_[static_cast<std::size_t>(index)];
        if (prior_packet_index.has_value() && record.packet.packet_index <= *prior_packet_index) {
            result.status = UnrecognizedPacketAccessStatus::malformed_directory;
            result.error_detail =
                "resident unrecognized packet sequence is not strictly increasing by packet_index";
            result.rows.clear();
            return result;
        }
        prior_packet_index = record.packet.packet_index;

        result.rows.push_back(UnrecognizedPacketAccessRow {
            .row_number = index + 1U,
            .packet_index = record.packet.packet_index,
            .ts_sec = record.packet.ts_sec,
            .ts_usec = record.packet.ts_usec,
            .captured_length = record.packet.captured_length,
            .original_length = record.packet.original_length,
            .reason_text = record.reason_text,
        });
    }

    return result;
}

CaptureIndexV16UnrecognizedPacketAccessSource::CaptureIndexV16UnrecognizedPacketAccessSource(
    std::filesystem::path index_path,
    const CaptureIndexV16MetadataTier& metadata
)
    : index_path_(std::move(index_path)),
      directory_sections_(metadata.unrecognized_directory_sections),
      reason_sections_(metadata.unrecognized_reason_sections) {
    std::uint64_t expected_logical_row_start {0};
    for (std::size_t index = 0U; index < directory_sections_.size(); ++index) {
        const auto& section = directory_sections_[index];
        if (section.section_occurrence_index != static_cast<std::uint32_t>(index) ||
            section.logical_row_start != expected_logical_row_start) {
            initialization_status_ = UnrecognizedPacketAccessStatus::malformed_directory;
            initialization_error_detail =
                "v16 unrecognized directory catalog did not preserve stable occurrence ordering";
            return;
        }
        if (!checked_add_u64(expected_logical_row_start, section.row_count, expected_logical_row_start)) {
            initialization_status_ = UnrecognizedPacketAccessStatus::malformed_directory;
            initialization_error_detail = "v16 unrecognized directory logical row count overflowed";
            return;
        }
    }
    total_row_count_ = expected_logical_row_start;

    for (std::size_t index = 0U; index < reason_sections_.size(); ++index) {
        if (reason_sections_[index].section_occurrence_index != static_cast<std::uint32_t>(index)) {
            initialization_status_ = UnrecognizedPacketAccessStatus::malformed_reason_reference;
            initialization_error_detail =
                "v16 unrecognized reason section catalog did not preserve stable occurrence ordering";
            return;
        }
    }
}

UnrecognizedPacketAccessCountResult CaptureIndexV16UnrecognizedPacketAccessSource::row_count() const {
    return UnrecognizedPacketAccessCountResult {
        .status = initialization_status_,
        .row_count = total_row_count_,
        .error_detail = initialization_error_detail,
    };
}

UnrecognizedPacketAccessReadResult CaptureIndexV16UnrecognizedPacketAccessSource::read_range(
    const std::uint64_t offset,
    const std::uint64_t limit
) const {
    UnrecognizedPacketAccessReadResult result {
        .status = initialization_status_,
        .total_row_count = total_row_count_,
        .error_detail = initialization_error_detail,
    };
    if (initialization_status_ != UnrecognizedPacketAccessStatus::ok) {
        return result;
    }

    std::ifstream stream(index_path_, std::ios::binary);
    if (!stream.is_open()) {
        result.status = UnrecognizedPacketAccessStatus::source_read_failed;
        result.error_detail = "failed to open the v16 index for lazy unrecognized row access";
        return result;
    }

    const auto directory_rows = detail::read_v16_unrecognized_directory_range(
        stream,
        directory_sections_,
        offset,
        limit
    );
    result.total_row_count = directory_rows.total_row_count;
    if (!directory_rows) {
        result.status = map_directory_status(directory_rows.status);
        result.error_detail = directory_rows.error_detail;
        return result;
    }

    result.rows.reserve(directory_rows.rows.size());
    for (const auto& row : directory_rows.rows) {
        const auto reason = detail::read_v16_unrecognized_reason(
            stream,
            reason_sections_,
            row.reason_section_occurrence_index,
            row.reason_payload_offset,
            row.reason_byte_length
        );
        if (!reason) {
            result.status = map_reason_status(reason.status);
            result.error_detail = reason.error_detail;
            result.rows.clear();
            return result;
        }

        result.rows.push_back(UnrecognizedPacketAccessRow {
            .row_number = row.row_number,
            .packet_index = row.packet_index,
            .ts_sec = row.ts_sec,
            .ts_usec = row.ts_usec,
            .captured_length = row.captured_length,
            .original_length = row.original_length,
            .reason_text = reason.reason_text,
        });
    }

    return result;
}

}  // namespace pfl::session_detail
