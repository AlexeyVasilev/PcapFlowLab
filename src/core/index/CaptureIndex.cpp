#include "core/index/CaptureIndex.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <fstream>
#include <string>

namespace pfl {

namespace {

constexpr std::array<std::uint8_t, 4> kClassicPcapLittleEndianMagicBytes {0xd4U, 0xc3U, 0xb2U, 0xa1U};
constexpr std::array<std::uint8_t, 4> kPcapNgSectionHeaderMagicBytes {0x0aU, 0x0dU, 0x0dU, 0x0aU};

CaptureSourceFormat detect_capture_source_format(const std::filesystem::path& path) {
    std::ifstream stream(path, std::ios::binary);
    if (!stream.is_open()) {
        return CaptureSourceFormat::unknown;
    }

    std::array<std::uint8_t, 4> header {};
    stream.read(reinterpret_cast<char*>(header.data()), static_cast<std::streamsize>(header.size()));
    if (stream.gcount() != static_cast<std::streamsize>(header.size())) {
        return CaptureSourceFormat::unknown;
    }

    if (header == kClassicPcapLittleEndianMagicBytes) {
        return CaptureSourceFormat::classic_pcap;
    }

    if (header == kPcapNgSectionHeaderMagicBytes) {
        return CaptureSourceFormat::pcapng;
    }

    return CaptureSourceFormat::unknown;
}

[[nodiscard]] std::int64_t to_serialized_file_time(const std::filesystem::file_time_type& value) {
    return static_cast<std::int64_t>(value.time_since_epoch().count());
}

[[nodiscard]] std::string lowercase_extension(const std::filesystem::path& path) {
    auto extension = path.extension().string();
    std::transform(extension.begin(), extension.end(), extension.begin(), [](unsigned char character) {
        return static_cast<char>(std::tolower(character));
    });
    return extension;
}

}  // namespace

bool validate_index_magic(const std::filesystem::path& index_path) {
    std::ifstream stream(index_path, std::ios::binary);
    if (!stream.is_open()) {
        return false;
    }

    std::array<std::uint8_t, 8> bytes {};
    stream.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    if (stream.gcount() != static_cast<std::streamsize>(bytes.size())) {
        return false;
    }

    const auto magic = static_cast<std::uint64_t>(bytes[0]) |
                       (static_cast<std::uint64_t>(bytes[1]) << 8U) |
                       (static_cast<std::uint64_t>(bytes[2]) << 16U) |
                       (static_cast<std::uint64_t>(bytes[3]) << 24U) |
                       (static_cast<std::uint64_t>(bytes[4]) << 32U) |
                       (static_cast<std::uint64_t>(bytes[5]) << 40U) |
                       (static_cast<std::uint64_t>(bytes[6]) << 48U) |
                       (static_cast<std::uint64_t>(bytes[7]) << 56U);
    return magic == kCaptureIndexMagic;
}

bool looks_like_index_file(const std::filesystem::path& path) {
    const auto extension = lowercase_extension(path);
    if (extension == ".pflidx" || extension == ".idx") {
        return true;
    }

    return validate_index_magic(path);
}

bool read_capture_source_info(const std::filesystem::path& capture_path, CaptureSourceInfo& out_info) {
    std::error_code error {};
    const auto file_size = std::filesystem::file_size(capture_path, error);
    if (error) {
        return false;
    }

    const auto last_write_time = std::filesystem::last_write_time(capture_path, error);
    if (error) {
        return false;
    }

    out_info = CaptureSourceInfo {
        .capture_path = capture_path,
        .format = detect_capture_source_format(capture_path),
        .file_size = file_size,
        .last_write_time = to_serialized_file_time(last_write_time),
    };
    return true;
}

bool validate_capture_source(const CaptureSourceInfo& expected, const std::filesystem::path& capture_path) {
    CaptureSourceInfo current {};
    if (!read_capture_source_info(capture_path, current)) {
        return false;
    }

    return current.format == expected.format &&
           current.file_size == expected.file_size &&
           current.last_write_time == expected.last_write_time;
}

bool validate_capture_source(const CaptureSourceInfo& expected) {
    if (expected.capture_path.empty()) {
        return false;
    }

    return validate_capture_source(expected, expected.capture_path);
}

}  // namespace pfl
