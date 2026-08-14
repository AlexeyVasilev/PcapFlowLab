#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "TestSupport.h"
#include "app/session/ByteExport.h"
#include "core/services/HexDumpService.h"

namespace pfl::tests {

void run_byte_export_tests() {
    const HexDumpService hex_dump_service {};
    const std::array<std::uint8_t, 5> bytes {0x00U, 0x01U, 0x0AU, 0xABU, 0xFFU};

    PFL_EXPECT(
        session_detail::format_byte_export_text(
            std::span<const std::uint8_t>(bytes.data(), bytes.size()),
            session_detail::ByteExportFormat::c_cpp_byte_list,
            hex_dump_service
        ) == "0x00, 0x01, 0x0A, 0xAB, 0xFF");

    PFL_EXPECT(
        session_detail::format_byte_export_text(
            std::span<const std::uint8_t>(bytes.data(), bytes.size()),
            session_detail::ByteExportFormat::continuous_hex,
            hex_dump_service
        ) == "00010AABFF");

    PFL_EXPECT(
        session_detail::format_byte_export_text(
            std::span<const std::uint8_t>(bytes.data(), bytes.size()),
            session_detail::ByteExportFormat::base64,
            hex_dump_service
        ) == "AAEKq/8=");

    PFL_EXPECT(
        session_detail::encode_byte_export_payload(
            std::span<const std::uint8_t>(bytes.data(), bytes.size()),
            session_detail::ByteExportFormat::raw_binary,
            hex_dump_service
        ) == std::vector<std::uint8_t>(bytes.begin(), bytes.end()));

    const std::array<std::uint8_t, 0> empty_bytes {};
    PFL_EXPECT(
        session_detail::format_byte_export_text(
            std::span<const std::uint8_t>(empty_bytes.data(), empty_bytes.size()),
            session_detail::ByteExportFormat::c_cpp_byte_list,
            hex_dump_service
        ).empty());
    PFL_EXPECT(
        session_detail::format_byte_export_text(
            std::span<const std::uint8_t>(empty_bytes.data(), empty_bytes.size()),
            session_detail::ByteExportFormat::continuous_hex,
            hex_dump_service
        ).empty());
    PFL_EXPECT(
        session_detail::format_byte_export_text(
            std::span<const std::uint8_t>(empty_bytes.data(), empty_bytes.size()),
            session_detail::ByteExportFormat::base64,
            hex_dump_service
        ).empty());
    PFL_EXPECT(
        session_detail::encode_byte_export_payload(
            std::span<const std::uint8_t>(empty_bytes.data(), empty_bytes.size()),
            session_detail::ByteExportFormat::raw_binary,
            hex_dump_service
        ).empty());

    std::vector<std::uint8_t> wrapped_bytes {};
    for (std::uint8_t value = 0U; value < 17U; ++value) {
        wrapped_bytes.push_back(value);
    }

    PFL_EXPECT(
        session_detail::format_byte_export_text(
            std::span<const std::uint8_t>(wrapped_bytes.data(), wrapped_bytes.size()),
            session_detail::ByteExportFormat::c_cpp_byte_list,
            hex_dump_service
        ) == "0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F\n0x10");
}

}  // namespace pfl::tests
