#include "app/session/ByteExport.h"

#include <array>
#include <fstream>
#include <sstream>

#include "core/services/HexDumpService.h"

namespace pfl::session_detail {
namespace {

const std::array<ByteExportFormatDescriptor, 5> kByteExportFormatDescriptors {{
    {
        .format = ByteExportFormat::hex_dump_ascii,
        .stable_id = "hex_dump_ascii",
        .label = "Hex dump + ASCII",
        .suggested_extension = "txt",
        .binary_output = false,
    },
    {
        .format = ByteExportFormat::raw_binary,
        .stable_id = "raw_binary",
        .label = "Raw binary",
        .suggested_extension = "bin",
        .binary_output = true,
    },
    {
        .format = ByteExportFormat::c_cpp_byte_list,
        .stable_id = "c_cpp_byte_list",
        .label = "C/C++ byte list",
        .suggested_extension = "txt",
        .binary_output = false,
    },
    {
        .format = ByteExportFormat::continuous_hex,
        .stable_id = "continuous_hex",
        .label = "Continuous hex",
        .suggested_extension = "txt",
        .binary_output = false,
    },
    {
        .format = ByteExportFormat::base64,
        .stable_id = "base64",
        .label = "Base64",
        .suggested_extension = "txt",
        .binary_output = false,
    },
}};

constexpr char kUpperHexDigits[] = "0123456789ABCDEF";
constexpr char kBase64Alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
constexpr std::size_t kWrappedByteListColumns = 16U;

const ByteExportFormatDescriptor* find_descriptor(const ByteExportFormat format) noexcept {
    for (const auto& descriptor : kByteExportFormatDescriptors) {
        if (descriptor.format == format) {
            return &descriptor;
        }
    }
    return nullptr;
}

std::string format_wrapped_c_byte_list(const std::span<const std::uint8_t> bytes) {
    std::ostringstream out {};
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        if (index != 0U) {
            if (index % kWrappedByteListColumns == 0U) {
                out << '\n';
            } else {
                out << ", ";
            }
        }
        out << "0x"
            << kUpperHexDigits[(bytes[index] >> 4U) & 0x0FU]
            << kUpperHexDigits[bytes[index] & 0x0FU];
    }
    return out.str();
}

std::string format_continuous_hex(const std::span<const std::uint8_t> bytes) {
    std::string output {};
    output.reserve(bytes.size() * 2U);
    for (const auto byte : bytes) {
        output.push_back(kUpperHexDigits[(byte >> 4U) & 0x0FU]);
        output.push_back(kUpperHexDigits[byte & 0x0FU]);
    }
    return output;
}

std::string encode_base64(const std::span<const std::uint8_t> bytes) {
    std::string output {};
    output.reserve(((bytes.size() + 2U) / 3U) * 4U);

    for (std::size_t index = 0; index < bytes.size(); index += 3U) {
        const auto first = bytes[index];
        const auto second = index + 1U < bytes.size() ? bytes[index + 1U] : static_cast<std::uint8_t>(0U);
        const auto third = index + 2U < bytes.size() ? bytes[index + 2U] : static_cast<std::uint8_t>(0U);

        const auto packed = static_cast<std::uint32_t>(first) << 16U
            | static_cast<std::uint32_t>(second) << 8U
            | static_cast<std::uint32_t>(third);

        output.push_back(kBase64Alphabet[(packed >> 18U) & 0x3FU]);
        output.push_back(kBase64Alphabet[(packed >> 12U) & 0x3FU]);
        output.push_back(index + 1U < bytes.size() ? kBase64Alphabet[(packed >> 6U) & 0x3FU] : '=');
        output.push_back(index + 2U < bytes.size() ? kBase64Alphabet[packed & 0x3FU] : '=');
    }

    return output;
}

}  // namespace

std::vector<ByteExportFormatDescriptor> byte_export_format_descriptors() {
    return {kByteExportFormatDescriptors.begin(), kByteExportFormatDescriptors.end()};
}

std::optional<ByteExportFormat> parse_byte_export_format_id(const std::string_view stable_id) noexcept {
    for (const auto& descriptor : kByteExportFormatDescriptors) {
        if (descriptor.stable_id == stable_id) {
            return descriptor.format;
        }
    }
    return std::nullopt;
}

std::string format_byte_export_format_id(const ByteExportFormat format) {
    if (const auto* descriptor = find_descriptor(format); descriptor != nullptr) {
        return descriptor->stable_id;
    }
    return "hex_dump_ascii";
}

std::string byte_export_format_label(const ByteExportFormat format) {
    if (const auto* descriptor = find_descriptor(format); descriptor != nullptr) {
        return descriptor->label;
    }
    return "Hex dump + ASCII";
}

std::string byte_export_format_suggested_extension(const ByteExportFormat format) {
    if (const auto* descriptor = find_descriptor(format); descriptor != nullptr) {
        return descriptor->suggested_extension;
    }
    return "txt";
}

bool byte_export_format_is_binary(const ByteExportFormat format) noexcept {
    if (const auto* descriptor = find_descriptor(format); descriptor != nullptr) {
        return descriptor->binary_output;
    }
    return false;
}

std::string format_byte_export_text(
    const std::span<const std::uint8_t> bytes,
    const ByteExportFormat format,
    const HexDumpService& hex_dump_service
) {
    switch (format) {
    case ByteExportFormat::hex_dump_ascii:
        return hex_dump_service.format(bytes);
    case ByteExportFormat::c_cpp_byte_list:
        return format_wrapped_c_byte_list(bytes);
    case ByteExportFormat::continuous_hex:
        return format_continuous_hex(bytes);
    case ByteExportFormat::base64:
        return encode_base64(bytes);
    case ByteExportFormat::raw_binary:
    default:
        return {};
    }
}

std::vector<std::uint8_t> encode_byte_export_payload(
    const std::span<const std::uint8_t> bytes,
    const ByteExportFormat format,
    const HexDumpService& hex_dump_service
) {
    if (format == ByteExportFormat::raw_binary) {
        return {bytes.begin(), bytes.end()};
    }

    auto text = format_byte_export_text(bytes, format, hex_dump_service);
    if (!text.empty()) {
        text.push_back('\n');
    }
    return {text.begin(), text.end()};
}

bool write_byte_export_file(
    const std::filesystem::path& output_path,
    const std::span<const std::uint8_t> bytes,
    const ByteExportFormat format,
    const HexDumpService& hex_dump_service,
    std::string* out_error_text
) {
    if (output_path.empty()) {
        if (out_error_text != nullptr) {
            *out_error_text = "No output file selected.";
        }
        return false;
    }

    std::ofstream stream {output_path, std::ios::binary | std::ios::trunc};
    if (!stream) {
        if (out_error_text != nullptr) {
            *out_error_text = "Failed to open the export destination.";
        }
        return false;
    }

    const auto payload = encode_byte_export_payload(bytes, format, hex_dump_service);
    stream.write(reinterpret_cast<const char*>(payload.data()), static_cast<std::streamsize>(payload.size()));

    if (!stream) {
        if (out_error_text != nullptr) {
            *out_error_text = byte_export_format_is_binary(format)
                ? "Failed to write raw byte export."
                : "Failed to write byte export text.";
        }
        return false;
    }

    return true;
}

}  // namespace pfl::session_detail
