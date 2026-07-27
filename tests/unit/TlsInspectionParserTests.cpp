#include <array>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "TestSupport.h"
#include "app/session/CaptureSession.h"
#include "core/services/PacketPayloadService.h"
#include "core/services/TlsInspectionParser.h"

namespace pfl::tests {

namespace {

std::filesystem::path fixture_path(const std::filesystem::path& relative_path) {
    return std::filesystem::path(__FILE__).parent_path().parent_path() / "data" / relative_path;
}

void append_be16(std::vector<std::uint8_t>& bytes, const std::uint16_t value) {
    bytes.push_back(static_cast<std::uint8_t>((value >> 8U) & 0xFFU));
    bytes.push_back(static_cast<std::uint8_t>(value & 0xFFU));
}

void append_be24(std::vector<std::uint8_t>& bytes, const std::uint32_t value) {
    bytes.push_back(static_cast<std::uint8_t>((value >> 16U) & 0xFFU));
    bytes.push_back(static_cast<std::uint8_t>((value >> 8U) & 0xFFU));
    bytes.push_back(static_cast<std::uint8_t>(value & 0xFFU));
}

std::vector<std::uint8_t> require_tls_fixture_transport_payload(
    const std::filesystem::path& relative_path,
    const std::uint64_t packet_index = 0U
) {
    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(fixture_path(relative_path), CaptureImportOptions {}));
    const auto packet = session.find_packet(packet_index);
    PFL_REQUIRE(packet.has_value());

    const auto packet_bytes = session.read_packet_data(*packet);
    PacketPayloadService payload_service {};
    const auto payload = payload_service.extract_transport_payload(packet_bytes, packet->data_link_type);
    PFL_REQUIRE(!payload.empty());
    return payload;
}

std::vector<std::uint8_t> make_tls_record(
    const std::uint8_t content_type,
    const std::uint16_t legacy_version,
    const std::vector<std::uint8_t>& body
) {
    std::vector<std::uint8_t> record {};
    record.reserve(5U + body.size());
    record.push_back(content_type);
    append_be16(record, legacy_version);
    append_be16(record, static_cast<std::uint16_t>(body.size()));
    record.insert(record.end(), body.begin(), body.end());
    return record;
}

std::vector<std::uint8_t> make_tls_handshake_message(
    const std::uint8_t handshake_type,
    const std::vector<std::uint8_t>& body
) {
    std::vector<std::uint8_t> handshake {};
    handshake.reserve(4U + body.size());
    handshake.push_back(handshake_type);
    append_be24(handshake, static_cast<std::uint32_t>(body.size()));
    handshake.insert(handshake.end(), body.begin(), body.end());
    return handshake;
}

std::vector<std::uint8_t> make_zero_filled(const std::size_t count) {
    return std::vector<std::uint8_t>(count, 0x00U);
}

void expect_supported_versions(
    const std::vector<std::uint16_t>& actual,
    const std::vector<std::uint16_t>& expected
) {
    PFL_EXPECT(actual == expected);
}

struct ExpectedTlsExtension {
    std::uint16_t type {0U};
    std::optional<std::string> known_name {};
    std::size_t declared_length {0U};
    std::vector<std::string> server_names {};
    std::vector<std::string> alpn_protocols {};
    std::vector<std::uint16_t> supported_versions {};
};

void expect_tls_extensions(
    const std::vector<TlsExtensionModel>& actual,
    const std::vector<ExpectedTlsExtension>& expected
) {
    PFL_EXPECT(actual.size() == expected.size());
    if (actual.size() != expected.size()) {
        return;
    }

    for (std::size_t index = 0U; index < expected.size(); ++index) {
        const auto& actual_extension = actual[index];
        const auto& expected_extension = expected[index];
        PFL_EXPECT(actual_extension.order_index == index);
        PFL_EXPECT(actual_extension.type == expected_extension.type);
        PFL_EXPECT(actual_extension.known_name == expected_extension.known_name);
        PFL_EXPECT(actual_extension.declared_length == expected_extension.declared_length);
        PFL_EXPECT(actual_extension.server_names == expected_extension.server_names);
        PFL_EXPECT(actual_extension.alpn_protocols == expected_extension.alpn_protocols);
        PFL_EXPECT(actual_extension.supported_versions == expected_extension.supported_versions);
    }
}

}  // namespace

void run_tls_inspection_parser_tests() {
    TlsInspectionParser parser {};

    {
        ScopedTestContext context {"fixture=parsing/tls/tls_client_hello_1.pcap"};
        const auto payload = require_tls_fixture_transport_payload("parsing/tls/tls_client_hello_1.pcap");
        const auto result = parser.inspect(payload);
        const std::vector<std::string> expected_sni {"auth.split.io"};
        const std::vector<std::string> expected_alpn {"h2", "http/1.1"};
        const std::vector<std::uint16_t> expected_cipher_suites {
            0x8A8AU, 0x1301U, 0x1302U, 0x1303U, 0xC02BU, 0xC02FU, 0xC02CU, 0xC030U,
            0xCCA9U, 0xCCA8U, 0xC013U, 0xC014U, 0x009CU, 0x009DU, 0x002FU, 0x0035U
        };
        const std::vector<std::uint8_t> expected_compression_methods {0x00U};
        const std::vector<ExpectedTlsExtension> expected_extensions {
            {.type = 0xFAFAU, .declared_length = 0U},
            {.type = 0x0000U, .known_name = std::optional<std::string> {"server_name"}, .declared_length = 18U, .server_names = {"auth.split.io"}},
            {.type = 0x0017U, .known_name = std::optional<std::string> {"extended_master_secret"}, .declared_length = 0U},
            {.type = 0xFF01U, .known_name = std::optional<std::string> {"renegotiation_info"}, .declared_length = 1U},
            {.type = 0x000AU, .known_name = std::optional<std::string> {"supported_groups"}, .declared_length = 10U},
            {.type = 0x000BU, .known_name = std::optional<std::string> {"ec_point_formats"}, .declared_length = 2U},
            {.type = 0x0023U, .known_name = std::optional<std::string> {"session_ticket"}, .declared_length = 138U},
            {.type = 0x0010U, .known_name = std::optional<std::string> {"application_layer_protocol_negotiation"}, .declared_length = 14U, .alpn_protocols = {"h2", "http/1.1"}},
            {.type = 0x0005U, .known_name = std::optional<std::string> {"status_request"}, .declared_length = 5U},
            {.type = 0x000DU, .known_name = std::optional<std::string> {"signature_algorithms"}, .declared_length = 18U},
            {.type = 0x0012U, .known_name = std::optional<std::string> {"signed_certificate_timestamp"}, .declared_length = 0U},
            {.type = 0x0033U, .known_name = std::optional<std::string> {"key_share"}, .declared_length = 43U},
            {.type = 0x002DU, .known_name = std::optional<std::string> {"psk_key_exchange_modes"}, .declared_length = 2U},
            {.type = 0x002BU, .known_name = std::optional<std::string> {"supported_versions"}, .declared_length = 7U, .supported_versions = {0x5A5AU, 0x0304U, 0x0303U}},
            {.type = 0x001BU, .declared_length = 3U},
            {.type = 0x4469U, .declared_length = 5U},
            {.type = 0x9A9AU, .declared_length = 1U},
            {.type = 0x0015U, .known_name = std::optional<std::string> {"padding"}, .declared_length = 64U},
        };

        PFL_EXPECT(result.total_input_bytes == 517U);
        PFL_EXPECT(result.consumed_bytes == 517U);
        PFL_EXPECT(result.records.size() == 1U);
        PFL_EXPECT(result.records[0].status == TlsRecordStatus::complete);
        PFL_EXPECT(result.records[0].content_type == std::optional<std::uint8_t> {22U});
        PFL_EXPECT(result.records[0].content_type_kind == TlsRecordContentTypeKind::handshake);
        PFL_EXPECT(result.records[0].legacy_version == std::optional<std::uint16_t> {0x0301U});
        PFL_EXPECT(result.records[0].declared_payload_length == std::optional<std::size_t> {512U});
        PFL_EXPECT(result.records[0].handshake_messages.size() == 1U);

        const auto& handshake = result.records[0].handshake_messages[0];
        PFL_EXPECT(handshake.status == TlsHandshakeStatus::complete);
        PFL_EXPECT(handshake.type == std::optional<std::uint8_t> {1U});
        PFL_EXPECT(handshake.kind == TlsHandshakeKind::client_hello);
        PFL_EXPECT(handshake.declared_body_length == std::optional<std::size_t> {508U});
        PFL_EXPECT(handshake.structured_parse_status == TlsStructuredParseStatus::parsed);
        PFL_REQUIRE(handshake.client_hello.has_value());
        PFL_EXPECT(handshake.client_hello->legacy_version == 0x0303U);
        PFL_EXPECT(handshake.client_hello->session_id.size() == 32U);
        PFL_EXPECT(handshake.client_hello->cipher_suites == expected_cipher_suites);
        PFL_EXPECT(handshake.client_hello->compression_methods == expected_compression_methods);
        expect_tls_extensions(handshake.client_hello->extensions, expected_extensions);
        PFL_EXPECT(handshake.client_hello->sni_names == expected_sni);
        PFL_EXPECT(handshake.client_hello->alpn_protocols == expected_alpn);
        expect_supported_versions(
            handshake.client_hello->supported_versions,
            std::vector<std::uint16_t> {0x5A5AU, 0x0304U, 0x0303U}
        );
    }

    {
        ScopedTestContext context {"fixture=parsing/tls/tls_1_3_client_hello_5.pcap"};
        const auto payload = require_tls_fixture_transport_payload("parsing/tls/tls_1_3_client_hello_5.pcap");
        const auto result = parser.inspect(payload);
        const std::vector<std::string> expected_sni {"p101-fmf.icloud.com"};
        const std::vector<std::string> expected_alpn {"h2", "http/1.1"};
        const std::vector<std::uint16_t> expected_cipher_suites {
            0x8A8AU, 0x1301U, 0x1302U, 0x1303U, 0xC02CU, 0xC02BU, 0xCCA9U, 0xC030U,
            0xC02FU, 0xCCA8U, 0xC00AU, 0xC009U, 0xC014U, 0xC013U, 0x009DU, 0x009CU,
            0x0035U, 0x002FU, 0xC008U, 0xC012U, 0x000AU
        };
        const std::vector<std::uint8_t> expected_compression_methods {0x00U};
        const std::vector<ExpectedTlsExtension> expected_extensions {
            {.type = 0x9A9AU, .declared_length = 0U},
            {.type = 0x0000U, .known_name = std::optional<std::string> {"server_name"}, .declared_length = 24U, .server_names = {"p101-fmf.icloud.com"}},
            {.type = 0x0017U, .known_name = std::optional<std::string> {"extended_master_secret"}, .declared_length = 0U},
            {.type = 0xFF01U, .known_name = std::optional<std::string> {"renegotiation_info"}, .declared_length = 1U},
            {.type = 0x000AU, .known_name = std::optional<std::string> {"supported_groups"}, .declared_length = 12U},
            {.type = 0x000BU, .known_name = std::optional<std::string> {"ec_point_formats"}, .declared_length = 2U},
            {.type = 0x0010U, .known_name = std::optional<std::string> {"application_layer_protocol_negotiation"}, .declared_length = 14U, .alpn_protocols = {"h2", "http/1.1"}},
            {.type = 0x0005U, .known_name = std::optional<std::string> {"status_request"}, .declared_length = 5U},
            {.type = 0x000DU, .known_name = std::optional<std::string> {"signature_algorithms"}, .declared_length = 22U},
            {.type = 0x0012U, .known_name = std::optional<std::string> {"signed_certificate_timestamp"}, .declared_length = 0U},
            {.type = 0x0033U, .known_name = std::optional<std::string> {"key_share"}, .declared_length = 43U},
            {.type = 0x002DU, .known_name = std::optional<std::string> {"psk_key_exchange_modes"}, .declared_length = 2U},
            {.type = 0x002BU, .known_name = std::optional<std::string> {"supported_versions"}, .declared_length = 11U, .supported_versions = {0x3A3AU, 0x0304U, 0x0303U, 0x0302U, 0x0301U}},
            {.type = 0x001BU, .declared_length = 3U},
            {.type = 0x0A0AU, .declared_length = 1U},
            {.type = 0x0015U, .known_name = std::optional<std::string> {"padding"}, .declared_length = 189U},
        };

        PFL_EXPECT(result.total_input_bytes == 517U);
        PFL_EXPECT(result.consumed_bytes == 517U);
        PFL_EXPECT(result.records.size() == 1U);
        PFL_EXPECT(result.records[0].status == TlsRecordStatus::complete);
        PFL_EXPECT(result.records[0].legacy_version == std::optional<std::uint16_t> {0x0301U});
        PFL_EXPECT(result.records[0].declared_payload_length == std::optional<std::size_t> {512U});
        PFL_REQUIRE(result.records[0].handshake_messages.size() == 1U);

        const auto& handshake = result.records[0].handshake_messages[0];
        PFL_EXPECT(handshake.kind == TlsHandshakeKind::client_hello);
        PFL_EXPECT(handshake.declared_body_length == std::optional<std::size_t> {508U});
        PFL_EXPECT(handshake.structured_parse_status == TlsStructuredParseStatus::parsed);
        PFL_REQUIRE(handshake.client_hello.has_value());
        PFL_EXPECT(handshake.client_hello->legacy_version == 0x0303U);
        PFL_EXPECT(handshake.client_hello->session_id.size() == 32U);
        PFL_EXPECT(handshake.client_hello->cipher_suites == expected_cipher_suites);
        PFL_EXPECT(handshake.client_hello->compression_methods == expected_compression_methods);
        expect_tls_extensions(handshake.client_hello->extensions, expected_extensions);
        PFL_EXPECT(handshake.client_hello->sni_names == expected_sni);
        PFL_EXPECT(handshake.client_hello->alpn_protocols == expected_alpn);
        expect_supported_versions(
            handshake.client_hello->supported_versions,
            std::vector<std::uint16_t> {0x3A3AU, 0x0304U, 0x0303U, 0x0302U, 0x0301U}
        );
    }

    {
        ScopedTestContext context {"fixture=parsing/tls/tls_1_2_server_hello_4.pcap"};
        const auto payload = require_tls_fixture_transport_payload("parsing/tls/tls_1_2_server_hello_4.pcap");
        const auto result = parser.inspect(payload);
        const std::vector<ExpectedTlsExtension> expected_extensions {
            {.type = 0x000BU, .known_name = std::optional<std::string> {"ec_point_formats"}, .declared_length = 2U},
            {.type = 0xFF01U, .known_name = std::optional<std::string> {"renegotiation_info"}, .declared_length = 1U},
            {.type = 0x0017U, .known_name = std::optional<std::string> {"extended_master_secret"}, .declared_length = 0U},
        };

        PFL_EXPECT(result.total_input_bytes == 96U);
        PFL_EXPECT(result.consumed_bytes == 96U);
        PFL_EXPECT(result.records.size() == 1U);
        PFL_EXPECT(result.records[0].status == TlsRecordStatus::complete);
        PFL_EXPECT(result.records[0].legacy_version == std::optional<std::uint16_t> {0x0303U});
        PFL_EXPECT(result.records[0].declared_payload_length == std::optional<std::size_t> {91U});
        PFL_REQUIRE(result.records[0].handshake_messages.size() == 1U);

        const auto& handshake = result.records[0].handshake_messages[0];
        PFL_EXPECT(handshake.kind == TlsHandshakeKind::server_hello);
        PFL_EXPECT(handshake.declared_body_length == std::optional<std::size_t> {87U});
        PFL_EXPECT(handshake.structured_parse_status == TlsStructuredParseStatus::parsed);
        PFL_REQUIRE(handshake.server_hello.has_value());
        PFL_EXPECT(handshake.server_hello->legacy_version == 0x0303U);
        PFL_EXPECT(handshake.server_hello->session_id.size() == 32U);
        PFL_EXPECT(handshake.server_hello->selected_cipher_suite == 0xC02FU);
        PFL_EXPECT(handshake.server_hello->compression_method == 0U);
        expect_tls_extensions(handshake.server_hello->extensions, expected_extensions);
        PFL_EXPECT(handshake.server_hello->selected_tls_version == 0x0303U);
    }

    {
        ScopedTestContext context {"fixture=parsing/tls/tls_1_3_server_hello_6.pcap"};
        const auto payload = require_tls_fixture_transport_payload("parsing/tls/tls_1_3_server_hello_6.pcap");
        const auto result = parser.inspect(payload);
        const std::vector<ExpectedTlsExtension> expected_extensions {
            {.type = 0x0033U, .known_name = std::optional<std::string> {"key_share"}, .declared_length = 1124U},
            {.type = 0x002BU, .known_name = std::optional<std::string> {"supported_versions"}, .declared_length = 2U, .supported_versions = {0x0304U}},
        };

        PFL_EXPECT(result.total_input_bytes == 1400U);
        PFL_EXPECT(result.consumed_bytes == 1400U);
        PFL_EXPECT(result.records.size() == 3U);

        const auto& server_hello_record = result.records[0];
        PFL_EXPECT(server_hello_record.source_offset == 0U);
        PFL_EXPECT(server_hello_record.status == TlsRecordStatus::complete);
        PFL_EXPECT(server_hello_record.total_size == std::optional<std::size_t> {1215U});
        PFL_EXPECT(server_hello_record.declared_payload_length == std::optional<std::size_t> {1210U});
        PFL_EXPECT(server_hello_record.legacy_version == std::optional<std::uint16_t> {0x0303U});
        PFL_REQUIRE(server_hello_record.handshake_messages.size() == 1U);
        const auto& server_hello_handshake = server_hello_record.handshake_messages[0];
        PFL_EXPECT(server_hello_handshake.status == TlsHandshakeStatus::complete);
        PFL_EXPECT(server_hello_handshake.kind == TlsHandshakeKind::server_hello);
        PFL_EXPECT(server_hello_handshake.declared_body_length == std::optional<std::size_t> {1206U});
        PFL_EXPECT(server_hello_handshake.structured_parse_status == TlsStructuredParseStatus::parsed);
        PFL_REQUIRE(server_hello_handshake.server_hello.has_value());
        PFL_EXPECT(server_hello_handshake.server_hello->legacy_version == 0x0303U);
        PFL_EXPECT(server_hello_handshake.server_hello->session_id.size() == 32U);
        PFL_EXPECT(server_hello_handshake.server_hello->selected_cipher_suite == 0x1301U);
        PFL_EXPECT(server_hello_handshake.server_hello->compression_method == 0U);
        expect_tls_extensions(server_hello_handshake.server_hello->extensions, expected_extensions);
        PFL_EXPECT(server_hello_handshake.server_hello->selected_tls_version == 0x0304U);

        const auto& ccs_record = result.records[1];
        PFL_EXPECT(ccs_record.source_offset == 1215U);
        PFL_EXPECT(ccs_record.status == TlsRecordStatus::complete);
        PFL_EXPECT(ccs_record.total_size == std::optional<std::size_t> {6U});
        PFL_EXPECT(ccs_record.declared_payload_length == std::optional<std::size_t> {1U});
        PFL_EXPECT(ccs_record.legacy_version == std::optional<std::uint16_t> {0x0303U});
        PFL_EXPECT(ccs_record.handshake_messages.empty());

        const auto& partial_record = result.records[2];
        PFL_EXPECT(partial_record.source_offset == 1221U);
        PFL_EXPECT(partial_record.available_bytes == 179U);
        PFL_EXPECT(partial_record.status == TlsRecordStatus::partial_body);
        PFL_EXPECT(partial_record.handshake_messages.empty());
    }

    {
        ScopedTestContext context {"synthetic=empty_input"};
        const auto result = parser.inspect({});
        PFL_EXPECT(result.total_input_bytes == 0U);
        PFL_EXPECT(result.consumed_bytes == 0U);
        PFL_EXPECT(result.records.empty());
        PFL_EXPECT(!result.stopped_after_partial_record);
    }

    for (std::size_t size = 1U; size <= 4U; ++size) {
        const auto test_name = std::string {"synthetic=incomplete_header_"} + std::to_string(size);
        ScopedTestContext context {test_name};
        const auto bytes = std::vector<std::uint8_t>(size, 0x16U);
        const auto result = parser.inspect(bytes);
        PFL_EXPECT(result.records.size() == 1U);
        PFL_EXPECT(result.records[0].status == TlsRecordStatus::partial_header);
        PFL_EXPECT(result.records[0].available_bytes == size);
        PFL_EXPECT(result.stopped_after_partial_record);
        PFL_EXPECT(result.consumed_bytes == size);
    }

    {
        ScopedTestContext context {"synthetic=zero_length_record"};
        const auto bytes = make_tls_record(0x17U, 0x0303U, {});
        const auto result = parser.inspect(bytes);
        PFL_EXPECT(result.records.size() == 1U);
        PFL_EXPECT(result.records[0].status == TlsRecordStatus::complete);
        PFL_EXPECT(result.records[0].total_size == std::optional<std::size_t> {5U});
        PFL_EXPECT(result.records[0].declared_payload_length == std::optional<std::size_t> {0U});
        PFL_EXPECT(result.consumed_bytes == 5U);
    }

    {
        ScopedTestContext context {"synthetic=declared_body_larger_than_available"};
        auto bytes = make_tls_record(0x17U, 0x0303U, {0x01U, 0x02U, 0x03U});
        bytes.pop_back();
        const auto result = parser.inspect(bytes);
        PFL_EXPECT(result.records.size() == 1U);
        PFL_EXPECT(result.records[0].status == TlsRecordStatus::partial_body);
        PFL_EXPECT(result.records[0].declared_payload_length == std::optional<std::size_t> {3U});
        PFL_EXPECT(result.stopped_after_partial_record);
        PFL_EXPECT(result.consumed_bytes == bytes.size());
    }

    {
        ScopedTestContext context {"synthetic=two_complete_records"};
        auto first = make_tls_record(0x14U, 0x0303U, {0x01U});
        auto second = make_tls_record(0x17U, 0x0303U, {});
        first.insert(first.end(), second.begin(), second.end());

        const auto result = parser.inspect(first);
        PFL_EXPECT(result.records.size() == 2U);
        PFL_EXPECT(result.records[0].source_offset == 0U);
        PFL_EXPECT(result.records[1].source_offset == 6U);
        PFL_EXPECT(result.records[0].status == TlsRecordStatus::complete);
        PFL_EXPECT(result.records[1].status == TlsRecordStatus::complete);
    }

    {
        ScopedTestContext context {"synthetic=unknown_content_type_retained"};
        const auto bytes = make_tls_record(0x99U, 0x0303U, {0xAAU, 0xBBU});
        const auto result = parser.inspect(bytes);
        PFL_EXPECT(result.records.size() == 1U);
        PFL_EXPECT(result.records[0].content_type == std::optional<std::uint8_t> {0x99U});
        PFL_EXPECT(result.records[0].content_type_kind == TlsRecordContentTypeKind::unknown);
        PFL_EXPECT(result.records[0].status == TlsRecordStatus::complete);
    }

    {
        ScopedTestContext context {"synthetic=unknown_handshake_type"};
        const auto handshake = make_tls_handshake_message(0x7FU, {0x00U, 0x01U});
        const auto bytes = make_tls_record(0x16U, 0x0303U, handshake);
        const auto result = parser.inspect(bytes);
        PFL_REQUIRE(result.records.size() == 1U);
        PFL_REQUIRE(result.records[0].handshake_messages.size() == 1U);
        PFL_EXPECT(result.records[0].handshake_messages[0].type == std::optional<std::uint8_t> {0x7FU});
        PFL_EXPECT(result.records[0].handshake_messages[0].kind == TlsHandshakeKind::unknown);
        PFL_EXPECT(result.records[0].handshake_messages[0].status == TlsHandshakeStatus::complete);
    }

    {
        ScopedTestContext context {"synthetic=malformed_client_hello_variable_length_section"};
        std::vector<std::uint8_t> body {};
        append_be16(body, 0x0303U);
        const auto random = make_zero_filled(32U);
        body.insert(body.end(), random.begin(), random.end());
        body.push_back(0x00U);
        append_be16(body, 0x0002U);
        append_be16(body, 0x1301U);
        body.push_back(0x01U);
        body.push_back(0x00U);
        append_be16(body, 0x0004U);
        append_be16(body, 0x0000U);
        append_be16(body, 0x0008U);
        const auto bytes = make_tls_record(0x16U, 0x0303U, make_tls_handshake_message(0x01U, body));

        const auto result = parser.inspect(bytes);
        PFL_REQUIRE(result.records.size() == 1U);
        PFL_REQUIRE(result.records[0].handshake_messages.size() == 1U);
        PFL_EXPECT(result.records[0].handshake_messages[0].status == TlsHandshakeStatus::complete);
        PFL_EXPECT(result.records[0].handshake_messages[0].structured_parse_status == TlsStructuredParseStatus::malformed);
        PFL_EXPECT(!result.records[0].handshake_messages[0].client_hello.has_value());
    }

    {
        ScopedTestContext context {"synthetic=malformed_server_hello_extension_list"};
        std::vector<std::uint8_t> body {};
        append_be16(body, 0x0303U);
        const auto random = make_zero_filled(32U);
        body.insert(body.end(), random.begin(), random.end());
        body.push_back(0x00U);
        append_be16(body, 0x1301U);
        body.push_back(0x00U);
        append_be16(body, 0x0004U);
        append_be16(body, 0x002BU);
        append_be16(body, 0x0008U);
        const auto bytes = make_tls_record(0x16U, 0x0303U, make_tls_handshake_message(0x02U, body));

        const auto result = parser.inspect(bytes);
        PFL_REQUIRE(result.records.size() == 1U);
        PFL_REQUIRE(result.records[0].handshake_messages.size() == 1U);
        PFL_EXPECT(result.records[0].handshake_messages[0].status == TlsHandshakeStatus::complete);
        PFL_EXPECT(result.records[0].handshake_messages[0].structured_parse_status == TlsStructuredParseStatus::malformed);
        PFL_EXPECT(!result.records[0].handshake_messages[0].server_hello.has_value());
    }
}

}  // namespace pfl::tests
