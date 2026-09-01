#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace pfl {

enum class CaptureSourceFormat : std::uint8_t {
    unknown = 0,
    classic_pcap = 1,
    pcapng = 2,
};

struct CaptureSourceInfo {
    std::filesystem::path capture_path {};
    CaptureSourceFormat format {CaptureSourceFormat::unknown};
    std::uint64_t file_size {0};
    std::int64_t last_write_time {0};
    std::uint64_t content_fingerprint {0};
};

inline constexpr std::uint64_t kLegacyCaptureIndexMagic = 0x315844494c465050ULL; // "PPFLIDX1"
inline constexpr std::uint64_t kStableCaptureIndexMagic = 0x31565844494c4650ULL; // "PFLIDXV1"
inline constexpr std::uint64_t kCaptureIndexMagic = kStableCaptureIndexMagic;
inline constexpr std::uint16_t kLegacyCaptureIndexVersion = 14U;
inline constexpr std::uint16_t kCaptureIndexStableContainerFormatVersion = 1U;
inline constexpr std::uint32_t kCaptureIndexPreviousStableV15Revision = 15U;
inline constexpr std::uint32_t kCaptureIndexStableIndexRevision = 16U;
inline constexpr std::uint32_t kCaptureIndexVersion = kCaptureIndexStableIndexRevision;

enum class CaptureIndexFormatFamily : std::uint8_t {
    unknown = 0,
    legacy = 1,
    stable = 2,
};

struct CaptureIndexInspectionSection {
    std::uint32_t section_id {0};
    std::uint16_t section_schema_version {0};
    std::uint16_t section_flags {0};
    std::uint64_t payload_size {0};
    std::uint64_t file_offset {0};
};

struct CaptureIndexInspection {
    CaptureIndexFormatFamily format_family {CaptureIndexFormatFamily::unknown};
    std::uint64_t magic {0};
    std::uint16_t legacy_version {0};
    std::uint16_t legacy_reserved {0};
    std::uint16_t stable_container_format_version {0};
    std::uint16_t stable_header_flags {0};
    std::uint32_t stable_header_size {0};
    std::uint32_t stable_index_revision {0};
    std::string writer_application_version {};
    CaptureSourceInfo source_info {};
    std::vector<CaptureIndexInspectionSection> sections {};
};

[[nodiscard]] CaptureSourceFormat detect_capture_source_format(const std::filesystem::path& path);
[[nodiscard]] bool validate_index_magic(const std::filesystem::path& index_path);
[[nodiscard]] bool looks_like_index_file(const std::filesystem::path& path);
[[nodiscard]] bool read_capture_source_info(const std::filesystem::path& capture_path, CaptureSourceInfo& out_info);
[[nodiscard]] bool validate_capture_source(const CaptureSourceInfo& expected, const std::filesystem::path& capture_path);
[[nodiscard]] bool validate_capture_source(const CaptureSourceInfo& expected);

}  // namespace pfl


