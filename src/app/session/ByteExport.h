#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace pfl {

class HexDumpService;

namespace session_detail {

enum class ByteExportFormat : std::uint8_t {
    hex_dump_ascii = 0,
    raw_binary,
    c_cpp_byte_list,
    continuous_hex,
    base64,
};

struct ByteExportFormatDescriptor {
    ByteExportFormat format {ByteExportFormat::hex_dump_ascii};
    std::string stable_id {};
    std::string label {};
    std::string suggested_extension {};
    bool binary_output {false};
};

[[nodiscard]] std::vector<ByteExportFormatDescriptor> byte_export_format_descriptors();
[[nodiscard]] std::optional<ByteExportFormat> parse_byte_export_format_id(std::string_view stable_id) noexcept;
[[nodiscard]] std::string format_byte_export_format_id(ByteExportFormat format);
[[nodiscard]] std::string byte_export_format_label(ByteExportFormat format);
[[nodiscard]] std::string byte_export_format_suggested_extension(ByteExportFormat format);
[[nodiscard]] bool byte_export_format_is_binary(ByteExportFormat format) noexcept;

[[nodiscard]] std::string format_byte_export_text(
    std::span<const std::uint8_t> bytes,
    ByteExportFormat format,
    const HexDumpService& hex_dump_service
);

[[nodiscard]] std::vector<std::uint8_t> encode_byte_export_payload(
    std::span<const std::uint8_t> bytes,
    ByteExportFormat format,
    const HexDumpService& hex_dump_service
);

[[nodiscard]] bool write_byte_export_file(
    const std::filesystem::path& output_path,
    std::span<const std::uint8_t> bytes,
    ByteExportFormat format,
    const HexDumpService& hex_dump_service,
    std::string* out_error_text = nullptr
);

}  // namespace session_detail
}  // namespace pfl
