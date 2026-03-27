#pragma once

#include <cstdint>
#include <filesystem>

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

inline constexpr std::uint64_t kCaptureIndexMagic = 0x315844494c465050ULL;
inline constexpr std::uint16_t kCaptureIndexVersion = 5;

[[nodiscard]] CaptureSourceFormat detect_capture_source_format(const std::filesystem::path& path);
[[nodiscard]] bool validate_index_magic(const std::filesystem::path& index_path);
[[nodiscard]] bool looks_like_index_file(const std::filesystem::path& path);
[[nodiscard]] bool read_capture_source_info(const std::filesystem::path& capture_path, CaptureSourceInfo& out_info);
[[nodiscard]] bool validate_capture_source(const CaptureSourceInfo& expected, const std::filesystem::path& capture_path);
[[nodiscard]] bool validate_capture_source(const CaptureSourceInfo& expected);

}  // namespace pfl
