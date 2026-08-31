#pragma once

#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <vector>

#include "core/domain/CaptureState.h"
#include "core/index/CaptureIndexV16.h"

namespace pfl::session_detail {

enum class UnrecognizedPacketAccessStatus : std::uint8_t {
    ok = 0,
    invalid_offset,
    invalid_requested_length,
    numeric_overflow,
    malformed_directory,
    malformed_reason_reference,
    unsupported_schema,
    source_read_failed,
};

struct UnrecognizedPacketAccessRow {
    std::uint64_t row_number {0};
    std::uint64_t packet_index {0};
    std::uint32_t ts_sec {0};
    std::uint32_t ts_usec {0};
    std::uint32_t captured_length {0};
    std::uint32_t original_length {0};
    std::string reason_text {};

    [[nodiscard]] friend bool operator==(
        const UnrecognizedPacketAccessRow&,
        const UnrecognizedPacketAccessRow&
    ) = default;
};

struct UnrecognizedPacketAccessCountResult {
    UnrecognizedPacketAccessStatus status {UnrecognizedPacketAccessStatus::ok};
    std::uint64_t row_count {0};
    std::string error_detail {};

    [[nodiscard]] explicit operator bool() const noexcept {
        return status == UnrecognizedPacketAccessStatus::ok;
    }
};

struct UnrecognizedPacketAccessReadResult {
    UnrecognizedPacketAccessStatus status {UnrecognizedPacketAccessStatus::ok};
    std::vector<UnrecognizedPacketAccessRow> rows {};
    std::uint64_t total_row_count {0};
    std::string error_detail {};

    [[nodiscard]] explicit operator bool() const noexcept {
        return status == UnrecognizedPacketAccessStatus::ok;
    }
};

class UnrecognizedPacketAccessSource {
public:
    virtual ~UnrecognizedPacketAccessSource() = default;

    [[nodiscard]] virtual UnrecognizedPacketAccessCountResult row_count() const = 0;
    [[nodiscard]] virtual UnrecognizedPacketAccessReadResult read_range(
        std::uint64_t offset,
        std::uint64_t limit
    ) const = 0;
};

class ResidentUnrecognizedPacketAccessSource final : public UnrecognizedPacketAccessSource {
public:
    explicit ResidentUnrecognizedPacketAccessSource(
        std::span<const UnrecognizedPacketRecord> records
    );

    [[nodiscard]] UnrecognizedPacketAccessCountResult row_count() const override;
    [[nodiscard]] UnrecognizedPacketAccessReadResult read_range(
        std::uint64_t offset,
        std::uint64_t limit
    ) const override;

private:
    std::span<const UnrecognizedPacketRecord> records_ {};
};

class CaptureIndexV16UnrecognizedPacketAccessSource final : public UnrecognizedPacketAccessSource {
public:
    CaptureIndexV16UnrecognizedPacketAccessSource(
        std::filesystem::path index_path,
        const CaptureIndexV16MetadataTier& metadata
    );

    [[nodiscard]] UnrecognizedPacketAccessCountResult row_count() const override;
    [[nodiscard]] UnrecognizedPacketAccessReadResult read_range(
        std::uint64_t offset,
        std::uint64_t limit
    ) const override;

private:
    std::filesystem::path index_path_ {};
    std::vector<CaptureIndexV16UnrecognizedDirectorySectionInfo> directory_sections_ {};
    std::vector<CaptureIndexV16UnrecognizedReasonSectionInfo> reason_sections_ {};
    std::uint64_t total_row_count_ {0};
    UnrecognizedPacketAccessStatus initialization_status_ {UnrecognizedPacketAccessStatus::ok};
    std::string initialization_error_detail {};
};

}  // namespace pfl::session_detail
