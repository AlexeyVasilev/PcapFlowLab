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

void append_extension(
    std::vector<std::uint8_t>& bytes,
    const std::uint16_t extension_type,
    const std::vector<std::uint8_t>& body
) {
    append_be16(bytes, extension_type);
    append_be16(bytes, static_cast<std::uint16_t>(body.size()));
    bytes.insert(bytes.end(), body.begin(), body.end());
}

std::vector<std::uint8_t> make_minimal_client_hello_body_with_extensions(
    const std::vector<std::uint8_t>& extensions
) {
    std::vector<std::uint8_t> body {};
    append_be16(body, 0x0303U);
    const auto random = make_zero_filled(32U);
    body.insert(body.end(), random.begin(), random.end());
    body.push_back(0x00U);
    append_be16(body, 0x0002U);
    append_be16(body, 0x1301U);
    body.push_back(0x01U);
    body.push_back(0x00U);
    append_be16(body, static_cast<std::uint16_t>(extensions.size()));
    body.insert(body.end(), extensions.begin(), extensions.end());
    return body;
}

std::vector<std::uint8_t> make_minimal_server_hello_body_with_extensions(
    const std::vector<std::uint8_t>& extensions
) {
    std::vector<std::uint8_t> body {};
    append_be16(body, 0x0303U);
    const auto random = make_zero_filled(32U);
    body.insert(body.end(), random.begin(), random.end());
    body.push_back(0x00U);
    append_be16(body, 0x1301U);
    body.push_back(0x00U);
    append_be16(body, static_cast<std::uint16_t>(extensions.size()));
    body.insert(body.end(), extensions.begin(), extensions.end());
    return body;
}

std::vector<std::uint8_t> make_client_hello_record_with_extensions(const std::vector<std::uint8_t>& extensions) {
    return make_tls_record(0x16U, 0x0303U, make_tls_handshake_message(0x01U, make_minimal_client_hello_body_with_extensions(extensions)));
}

std::vector<std::uint8_t> make_server_hello_record_with_extensions(const std::vector<std::uint8_t>& extensions) {
    return make_tls_record(0x16U, 0x0303U, make_tls_handshake_message(0x02U, make_minimal_server_hello_body_with_extensions(extensions)));
}

void expect_supported_versions(
    const std::vector<std::uint16_t>& actual,
    const std::vector<std::uint16_t>& expected
) {
    PFL_EXPECT(actual == expected);
}

struct ExpectedTlsKeyShareEntry {
    std::size_t order_index {0U};
    std::uint16_t group_id {0U};
    std::size_t key_exchange_length {0U};
};

struct ExpectedTlsStatusRequest {
    std::uint8_t status_type {0U};
    std::size_t responder_id_list_length {0U};
    std::size_t request_extensions_length {0U};
};

struct ExpectedTlsExtension {
    std::uint16_t type {0U};
    std::optional<std::string> known_name {};
    std::size_t declared_length {0U};
    TlsStructuredParseStatus structured_parse_status {TlsStructuredParseStatus::not_attempted};
    std::vector<std::string> server_names {};
    std::vector<std::string> alpn_protocols {};
    std::vector<std::uint16_t> supported_versions {};
    std::vector<std::uint16_t> supported_group_ids {};
    std::vector<std::uint16_t> signature_scheme_ids {};
    std::vector<ExpectedTlsKeyShareEntry> key_share_entries {};
    std::vector<std::uint8_t> psk_key_exchange_mode_ids {};
    std::optional<ExpectedTlsStatusRequest> status_request {};
    std::vector<std::uint16_t> certificate_compression_algorithm_ids {};
    std::optional<std::size_t> padding_length {};
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
        PFL_EXPECT(actual_extension.structured_parse_status == expected_extension.structured_parse_status);
        PFL_EXPECT(actual_extension.server_names == expected_extension.server_names);
        PFL_EXPECT(actual_extension.alpn_protocols == expected_extension.alpn_protocols);
        PFL_EXPECT(actual_extension.supported_versions == expected_extension.supported_versions);
        PFL_EXPECT(actual_extension.supported_group_ids == expected_extension.supported_group_ids);
        PFL_EXPECT(actual_extension.signature_scheme_ids == expected_extension.signature_scheme_ids);
        PFL_EXPECT(actual_extension.psk_key_exchange_mode_ids == expected_extension.psk_key_exchange_mode_ids);
        PFL_EXPECT(actual_extension.certificate_compression_algorithm_ids == expected_extension.certificate_compression_algorithm_ids);
        PFL_EXPECT(actual_extension.padding_length == expected_extension.padding_length);
        PFL_EXPECT(actual_extension.status_request.has_value() == expected_extension.status_request.has_value());
        if (actual_extension.status_request.has_value() && expected_extension.status_request.has_value()) {
            PFL_EXPECT(actual_extension.status_request->status_type == expected_extension.status_request->status_type);
            PFL_EXPECT(
                actual_extension.status_request->responder_id_list_length ==
                expected_extension.status_request->responder_id_list_length
            );
            PFL_EXPECT(
                actual_extension.status_request->request_extensions_length ==
                expected_extension.status_request->request_extensions_length
            );
        }

        PFL_EXPECT(actual_extension.key_share_entries.size() == expected_extension.key_share_entries.size());
        if (actual_extension.key_share_entries.size() == expected_extension.key_share_entries.size()) {
            for (std::size_t key_share_index = 0U; key_share_index < expected_extension.key_share_entries.size(); ++key_share_index) {
                const auto& actual_entry = actual_extension.key_share_entries[key_share_index];
                const auto& expected_entry = expected_extension.key_share_entries[key_share_index];
                PFL_EXPECT(actual_entry.order_index == expected_entry.order_index);
                PFL_EXPECT(actual_entry.group_id == expected_entry.group_id);
                PFL_EXPECT(actual_entry.key_exchange_length == expected_entry.key_exchange_length);
            }
        }
    }
}

const TlsExtensionModel& require_single_client_hello_extension(const TlsInspectionResult& result) {
    PFL_REQUIRE(result.records.size() == 1U);
    PFL_REQUIRE(result.records[0].handshake_messages.size() == 1U);
    const auto& handshake = result.records[0].handshake_messages[0];
    PFL_EXPECT(handshake.structured_parse_status == TlsStructuredParseStatus::parsed);
    PFL_REQUIRE(handshake.client_hello.has_value());
    PFL_REQUIRE(handshake.client_hello->extensions.size() == 1U);
    return handshake.client_hello->extensions[0];
}

const TlsExtensionModel& require_single_server_hello_extension(const TlsInspectionResult& result) {
    PFL_REQUIRE(result.records.size() == 1U);
    PFL_REQUIRE(result.records[0].handshake_messages.size() == 1U);
    const auto& handshake = result.records[0].handshake_messages[0];
    PFL_EXPECT(handshake.structured_parse_status == TlsStructuredParseStatus::parsed);
    PFL_REQUIRE(handshake.server_hello.has_value());
    PFL_REQUIRE(handshake.server_hello->extensions.size() == 1U);
    return handshake.server_hello->extensions[0];
}

const TlsHandshakeModel& require_single_handshake(const TlsInspectionResult& result) {
    PFL_REQUIRE(result.records.size() == 1U);
    PFL_REQUIRE(result.records[0].handshake_messages.size() == 1U);
    return result.records[0].handshake_messages[0];
}

const TlsClientHelloModel& require_parsed_client_hello(const TlsInspectionResult& result) {
    const auto& handshake = require_single_handshake(result);
    PFL_EXPECT(handshake.structured_parse_status == TlsStructuredParseStatus::parsed);
    PFL_REQUIRE(handshake.client_hello.has_value());
    return *handshake.client_hello;
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
            {
                .type = 0x0000U,
                .known_name = std::optional<std::string> {"server_name"},
                .declared_length = 18U,
                .structured_parse_status = TlsStructuredParseStatus::parsed,
                .server_names = {"auth.split.io"},
            },
            {.type = 0x0017U, .known_name = std::optional<std::string> {"extended_master_secret"}, .declared_length = 0U},
            {.type = 0xFF01U, .known_name = std::optional<std::string> {"renegotiation_info"}, .declared_length = 1U},
            {
                .type = 0x000AU,
                .known_name = std::optional<std::string> {"supported_groups"},
                .declared_length = 10U,
                .structured_parse_status = TlsStructuredParseStatus::parsed,
                .supported_group_ids = {0x5A5AU, 0x001DU, 0x0017U, 0x0018U},
            },
            {.type = 0x000BU, .known_name = std::optional<std::string> {"ec_point_formats"}, .declared_length = 2U},
            {.type = 0x0023U, .known_name = std::optional<std::string> {"session_ticket"}, .declared_length = 138U},
            {
                .type = 0x0010U,
                .known_name = std::optional<std::string> {"application_layer_protocol_negotiation"},
                .declared_length = 14U,
                .structured_parse_status = TlsStructuredParseStatus::parsed,
                .alpn_protocols = {"h2", "http/1.1"},
            },
            {
                .type = 0x0005U,
                .known_name = std::optional<std::string> {"status_request"},
                .declared_length = 5U,
                .structured_parse_status = TlsStructuredParseStatus::parsed,
                .status_request = ExpectedTlsStatusRequest {
                    .status_type = 1U,
                    .responder_id_list_length = 0U,
                    .request_extensions_length = 0U,
                },
            },
            {
                .type = 0x000DU,
                .known_name = std::optional<std::string> {"signature_algorithms"},
                .declared_length = 18U,
                .structured_parse_status = TlsStructuredParseStatus::parsed,
                .signature_scheme_ids = {
                    0x0403U, 0x0804U, 0x0401U, 0x0503U,
                    0x0805U, 0x0501U, 0x0806U, 0x0601U,
                },
            },
            {.type = 0x0012U, .known_name = std::optional<std::string> {"signed_certificate_timestamp"}, .declared_length = 0U},
            {
                .type = 0x0033U,
                .known_name = std::optional<std::string> {"key_share"},
                .declared_length = 43U,
                .structured_parse_status = TlsStructuredParseStatus::parsed,
                .key_share_entries = {
                    {.order_index = 0U, .group_id = 0x5A5AU, .key_exchange_length = 1U},
                    {.order_index = 1U, .group_id = 0x001DU, .key_exchange_length = 32U},
                },
            },
            {
                .type = 0x002DU,
                .known_name = std::optional<std::string> {"psk_key_exchange_modes"},
                .declared_length = 2U,
                .structured_parse_status = TlsStructuredParseStatus::parsed,
                .psk_key_exchange_mode_ids = {0x01U},
            },
            {
                .type = 0x002BU,
                .known_name = std::optional<std::string> {"supported_versions"},
                .declared_length = 7U,
                .structured_parse_status = TlsStructuredParseStatus::parsed,
                .supported_versions = {0x5A5AU, 0x0304U, 0x0303U},
            },
            {
                .type = 0x001BU,
                .known_name = std::optional<std::string> {"compress_certificate"},
                .declared_length = 3U,
                .structured_parse_status = TlsStructuredParseStatus::parsed,
                .certificate_compression_algorithm_ids = {0x0002U},
            },
            {.type = 0x4469U, .declared_length = 5U},
            {.type = 0x9A9AU, .declared_length = 1U},
            {
                .type = 0x0015U,
                .known_name = std::optional<std::string> {"padding"},
                .declared_length = 64U,
                .structured_parse_status = TlsStructuredParseStatus::parsed,
                .padding_length = 64U,
            },
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
            {
                .type = 0x0000U,
                .known_name = std::optional<std::string> {"server_name"},
                .declared_length = 24U,
                .structured_parse_status = TlsStructuredParseStatus::parsed,
                .server_names = {"p101-fmf.icloud.com"},
            },
            {.type = 0x0017U, .known_name = std::optional<std::string> {"extended_master_secret"}, .declared_length = 0U},
            {.type = 0xFF01U, .known_name = std::optional<std::string> {"renegotiation_info"}, .declared_length = 1U},
            {
                .type = 0x000AU,
                .known_name = std::optional<std::string> {"supported_groups"},
                .declared_length = 12U,
                .structured_parse_status = TlsStructuredParseStatus::parsed,
                .supported_group_ids = {0x4A4AU, 0x001DU, 0x0017U, 0x0018U, 0x0019U},
            },
            {.type = 0x000BU, .known_name = std::optional<std::string> {"ec_point_formats"}, .declared_length = 2U},
            {
                .type = 0x0010U,
                .known_name = std::optional<std::string> {"application_layer_protocol_negotiation"},
                .declared_length = 14U,
                .structured_parse_status = TlsStructuredParseStatus::parsed,
                .alpn_protocols = {"h2", "http/1.1"},
            },
            {
                .type = 0x0005U,
                .known_name = std::optional<std::string> {"status_request"},
                .declared_length = 5U,
                .structured_parse_status = TlsStructuredParseStatus::parsed,
                .status_request = ExpectedTlsStatusRequest {
                    .status_type = 1U,
                    .responder_id_list_length = 0U,
                    .request_extensions_length = 0U,
                },
            },
            {
                .type = 0x000DU,
                .known_name = std::optional<std::string> {"signature_algorithms"},
                .declared_length = 22U,
                .structured_parse_status = TlsStructuredParseStatus::parsed,
                .signature_scheme_ids = {
                    0x0403U, 0x0804U, 0x0401U, 0x0503U, 0x0805U,
                    0x0805U, 0x0501U, 0x0806U, 0x0601U, 0x0201U,
                },
            },
            {.type = 0x0012U, .known_name = std::optional<std::string> {"signed_certificate_timestamp"}, .declared_length = 0U},
            {
                .type = 0x0033U,
                .known_name = std::optional<std::string> {"key_share"},
                .declared_length = 43U,
                .structured_parse_status = TlsStructuredParseStatus::parsed,
                .key_share_entries = {
                    {.order_index = 0U, .group_id = 0x4A4AU, .key_exchange_length = 1U},
                    {.order_index = 1U, .group_id = 0x001DU, .key_exchange_length = 32U},
                },
            },
            {
                .type = 0x002DU,
                .known_name = std::optional<std::string> {"psk_key_exchange_modes"},
                .declared_length = 2U,
                .structured_parse_status = TlsStructuredParseStatus::parsed,
                .psk_key_exchange_mode_ids = {0x01U},
            },
            {
                .type = 0x002BU,
                .known_name = std::optional<std::string> {"supported_versions"},
                .declared_length = 11U,
                .structured_parse_status = TlsStructuredParseStatus::parsed,
                .supported_versions = {0x3A3AU, 0x0304U, 0x0303U, 0x0302U, 0x0301U},
            },
            {
                .type = 0x001BU,
                .known_name = std::optional<std::string> {"compress_certificate"},
                .declared_length = 3U,
                .structured_parse_status = TlsStructuredParseStatus::parsed,
                .certificate_compression_algorithm_ids = {0x0001U},
            },
            {.type = 0x0A0AU, .declared_length = 1U},
            {
                .type = 0x0015U,
                .known_name = std::optional<std::string> {"padding"},
                .declared_length = 189U,
                .structured_parse_status = TlsStructuredParseStatus::parsed,
                .padding_length = 189U,
            },
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
            {
                .type = 0x0033U,
                .known_name = std::optional<std::string> {"key_share"},
                .declared_length = 1124U,
                .structured_parse_status = TlsStructuredParseStatus::parsed,
                .key_share_entries = {
                    {.order_index = 0U, .group_id = 4588U, .key_exchange_length = 1120U},
                },
            },
            {
                .type = 0x002BU,
                .known_name = std::optional<std::string> {"supported_versions"},
                .declared_length = 2U,
                .structured_parse_status = TlsStructuredParseStatus::parsed,
                .supported_versions = {0x0304U},
            },
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
        ScopedTestContext context {"fixture=parsing/tls/tls_1_2_app_data_3.pcap"};
        const auto payload = require_tls_fixture_transport_payload("parsing/tls/tls_1_2_app_data_3.pcap");
        const auto result = parser.inspect(payload);
        PFL_EXPECT(result.total_input_bytes == 657U);
        PFL_EXPECT(result.consumed_bytes == 657U);
        PFL_EXPECT(result.records.size() == 1U);
        PFL_EXPECT(result.records[0].status == TlsRecordStatus::complete);
        PFL_EXPECT(result.records[0].content_type_kind == TlsRecordContentTypeKind::application_data);
        PFL_EXPECT(result.records[0].legacy_version == std::optional<std::uint16_t> {0x0303U});
        PFL_EXPECT(result.records[0].declared_payload_length == std::optional<std::size_t> {652U});
        PFL_EXPECT(result.records[0].total_size == std::optional<std::size_t> {657U});
        PFL_EXPECT(result.records[0].handshake_payload_kind == TlsHandshakePayloadKind::none);
        PFL_EXPECT(result.records[0].handshake_messages.empty());
    }

    {
        ScopedTestContext context {"fixture=parsing/tls/tls_1_3_app_data_7.pcap"};
        const auto payload = require_tls_fixture_transport_payload("parsing/tls/tls_1_3_app_data_7.pcap");
        const auto result = parser.inspect(payload);
        PFL_EXPECT(result.total_input_bytes == 978U);
        PFL_EXPECT(result.consumed_bytes == 978U);
        PFL_EXPECT(result.records.size() == 2U);
        PFL_EXPECT(result.records[0].status == TlsRecordStatus::complete);
        PFL_EXPECT(result.records[0].content_type_kind == TlsRecordContentTypeKind::application_data);
        PFL_EXPECT(result.records[0].legacy_version == std::optional<std::uint16_t> {0x0303U});
        PFL_EXPECT(result.records[0].declared_payload_length == std::optional<std::size_t> {911U});
        PFL_EXPECT(result.records[0].total_size == std::optional<std::size_t> {916U});
        PFL_EXPECT(result.records[0].handshake_payload_kind == TlsHandshakePayloadKind::none);
        PFL_EXPECT(result.records[1].status == TlsRecordStatus::complete);
        PFL_EXPECT(result.records[1].content_type_kind == TlsRecordContentTypeKind::application_data);
        PFL_EXPECT(result.records[1].legacy_version == std::optional<std::uint16_t> {0x0303U});
        PFL_EXPECT(result.records[1].declared_payload_length == std::optional<std::size_t> {57U});
        PFL_EXPECT(result.records[1].total_size == std::optional<std::size_t> {62U});
        PFL_EXPECT(result.records[1].handshake_payload_kind == TlsHandshakePayloadKind::none);
    }

    {
        ScopedTestContext context {"fixture=parsing/tls/tls_1_2_change_cipher_spec_2.pcap"};
        const auto payload = require_tls_fixture_transport_payload("parsing/tls/tls_1_2_change_cipher_spec_2.pcap");
        const auto result = parser.inspect(payload);
        PFL_EXPECT(result.total_input_bytes == 51U);
        PFL_EXPECT(result.consumed_bytes == 51U);
        PFL_EXPECT(result.records.size() == 2U);
        PFL_EXPECT(result.records[0].status == TlsRecordStatus::complete);
        PFL_EXPECT(result.records[0].content_type_kind == TlsRecordContentTypeKind::change_cipher_spec);
        PFL_EXPECT(result.records[0].legacy_version == std::optional<std::uint16_t> {0x0303U});
        PFL_EXPECT(result.records[0].declared_payload_length == std::optional<std::size_t> {1U});
        PFL_EXPECT(result.records[0].total_size == std::optional<std::size_t> {6U});
        PFL_EXPECT(result.records[1].status == TlsRecordStatus::complete);
        PFL_EXPECT(result.records[1].content_type_kind == TlsRecordContentTypeKind::handshake);
        PFL_EXPECT(result.records[1].legacy_version == std::optional<std::uint16_t> {0x0303U});
        PFL_EXPECT(result.records[1].declared_payload_length == std::optional<std::size_t> {40U});
        PFL_EXPECT(result.records[1].total_size == std::optional<std::size_t> {45U});
        PFL_EXPECT(result.records[1].handshake_payload_kind == TlsHandshakePayloadKind::encrypted_opaque);
        PFL_EXPECT(result.records[1].handshake_messages.empty());
    }

    {
        ScopedTestContext context {"fixture=parsing/tls/tls_1_3_change_cipher_spec_8.pcap"};
        const auto payload = require_tls_fixture_transport_payload("parsing/tls/tls_1_3_change_cipher_spec_8.pcap");
        const auto result = parser.inspect(payload);
        PFL_EXPECT(result.total_input_bytes == 80U);
        PFL_EXPECT(result.consumed_bytes == 80U);
        PFL_EXPECT(result.records.size() == 2U);
        PFL_EXPECT(result.records[0].status == TlsRecordStatus::complete);
        PFL_EXPECT(result.records[0].content_type_kind == TlsRecordContentTypeKind::change_cipher_spec);
        PFL_EXPECT(result.records[0].legacy_version == std::optional<std::uint16_t> {0x0303U});
        PFL_EXPECT(result.records[0].declared_payload_length == std::optional<std::size_t> {1U});
        PFL_EXPECT(result.records[0].total_size == std::optional<std::size_t> {6U});
        PFL_EXPECT(result.records[1].status == TlsRecordStatus::complete);
        PFL_EXPECT(result.records[1].content_type_kind == TlsRecordContentTypeKind::application_data);
        PFL_EXPECT(result.records[1].legacy_version == std::optional<std::uint16_t> {0x0303U});
        PFL_EXPECT(result.records[1].declared_payload_length == std::optional<std::size_t> {69U});
        PFL_EXPECT(result.records[1].total_size == std::optional<std::size_t> {74U});
        PFL_EXPECT(result.records[1].handshake_payload_kind == TlsHandshakePayloadKind::none);
    }

    {
        ScopedTestContext context {"fixture=parsing/tls/tls_1_2_new_session_ticket_9.pcap"};
        const auto payload = require_tls_fixture_transport_payload("parsing/tls/tls_1_2_new_session_ticket_9.pcap");
        const auto result = parser.inspect(payload);
        PFL_EXPECT(result.total_input_bytes == 242U);
        PFL_EXPECT(result.consumed_bytes == 242U);
        PFL_EXPECT(result.records.size() == 3U);
        PFL_EXPECT(result.records[0].status == TlsRecordStatus::complete);
        PFL_EXPECT(result.records[0].content_type_kind == TlsRecordContentTypeKind::handshake);
        PFL_EXPECT(result.records[0].legacy_version == std::optional<std::uint16_t> {0x0303U});
        PFL_EXPECT(result.records[0].declared_payload_length == std::optional<std::size_t> {186U});
        PFL_EXPECT(result.records[0].total_size == std::optional<std::size_t> {191U});
        PFL_EXPECT(result.records[0].handshake_payload_kind == TlsHandshakePayloadKind::plaintext);
        PFL_REQUIRE(result.records[0].handshake_messages.size() == 1U);
        PFL_EXPECT(result.records[0].handshake_messages[0].status == TlsHandshakeStatus::complete);
        PFL_EXPECT(result.records[0].handshake_messages[0].type == std::optional<std::uint8_t> {4U});
        PFL_EXPECT(result.records[0].handshake_messages[0].kind == TlsHandshakeKind::new_session_ticket);
        PFL_EXPECT(result.records[0].handshake_messages[0].declared_body_length == std::optional<std::size_t> {182U});
        PFL_EXPECT(result.records[0].handshake_messages[0].structured_parse_status == TlsStructuredParseStatus::not_attempted);
        PFL_EXPECT(result.records[1].status == TlsRecordStatus::complete);
        PFL_EXPECT(result.records[1].content_type_kind == TlsRecordContentTypeKind::change_cipher_spec);
        PFL_EXPECT(result.records[1].declared_payload_length == std::optional<std::size_t> {1U});
        PFL_EXPECT(result.records[1].total_size == std::optional<std::size_t> {6U});
        PFL_EXPECT(result.records[2].status == TlsRecordStatus::complete);
        PFL_EXPECT(result.records[2].content_type_kind == TlsRecordContentTypeKind::handshake);
        PFL_EXPECT(result.records[2].legacy_version == std::optional<std::uint16_t> {0x0303U});
        PFL_EXPECT(result.records[2].declared_payload_length == std::optional<std::size_t> {40U});
        PFL_EXPECT(result.records[2].total_size == std::optional<std::size_t> {45U});
        PFL_EXPECT(result.records[2].handshake_payload_kind == TlsHandshakePayloadKind::encrypted_opaque);
        PFL_EXPECT(result.records[2].handshake_messages.empty());
    }

    {
        ScopedTestContext context {"synthetic=input_relative_offsets_and_complete_available_bytes"};
        std::vector<std::uint8_t> extensions {};
        append_extension(extensions, 0xFAFAU, {});
        const auto client_hello = make_tls_handshake_message(
            0x01U,
            make_minimal_client_hello_body_with_extensions(extensions)
        );
        const auto unknown_handshake = make_tls_handshake_message(0x7FU, {0xAAU, 0xBBU});
        std::vector<std::uint8_t> record_body = client_hello;
        record_body.insert(record_body.end(), unknown_handshake.begin(), unknown_handshake.end());

        const auto result = parser.inspect(make_tls_record(0x16U, 0x0303U, record_body));
        PFL_REQUIRE(result.records.size() == 1U);
        PFL_EXPECT(result.records[0].source_offset == 0U);
        PFL_EXPECT(result.records[0].total_size == std::optional<std::size_t> {62U});
        PFL_EXPECT(result.records[0].available_bytes == 62U);
        PFL_REQUIRE(result.records[0].handshake_messages.size() == 2U);
        PFL_EXPECT(result.records[0].handshake_messages[0].source_offset == 5U);
        PFL_EXPECT(result.records[0].handshake_messages[0].total_size == std::optional<std::size_t> {51U});
        PFL_EXPECT(result.records[0].handshake_messages[0].available_bytes == 51U);
        PFL_EXPECT(result.records[0].handshake_messages[1].source_offset == 56U);
        PFL_EXPECT(result.records[0].handshake_messages[1].total_size == std::optional<std::size_t> {6U});
        PFL_EXPECT(result.records[0].handshake_messages[1].available_bytes == 6U);
        PFL_REQUIRE(result.records[0].handshake_messages[0].client_hello.has_value());
        PFL_REQUIRE(result.records[0].handshake_messages[0].client_hello->extensions.size() == 1U);
        PFL_EXPECT(result.records[0].handshake_messages[0].client_hello->extensions[0].source_offset == 52U);
    }

    {
        ScopedTestContext context {"synthetic=partial_handshake_body_available_bytes"};
        const auto result = parser.inspect(make_tls_record(
            0x16U,
            0x0303U,
            {0x01U, 0x00U, 0x00U, 0x08U, 0xAAU, 0xBBU}
        ));
        PFL_REQUIRE(result.records.size() == 1U);
        PFL_EXPECT(result.records[0].status == TlsRecordStatus::complete);
        PFL_EXPECT(result.records[0].total_size == std::optional<std::size_t> {11U});
        PFL_EXPECT(result.records[0].available_bytes == 11U);
        PFL_REQUIRE(result.records[0].handshake_messages.size() == 1U);
        PFL_EXPECT(result.records[0].handshake_messages[0].source_offset == 5U);
        PFL_EXPECT(result.records[0].handshake_messages[0].status == TlsHandshakeStatus::partial_body);
        PFL_EXPECT(result.records[0].handshake_messages[0].declared_body_length == std::optional<std::size_t> {8U});
        PFL_EXPECT(result.records[0].handshake_messages[0].total_size == std::optional<std::size_t> {12U});
        PFL_EXPECT(result.records[0].handshake_messages[0].available_bytes == 6U);
    }

    {
        ScopedTestContext context {"synthetic=state_resets_between_invocations_after_complete_ccs"};
        auto encrypted_bytes = make_tls_record(0x14U, 0x0303U, {0x01U});
        const auto encrypted_handshake = make_tls_record(0x16U, 0x0303U, make_tls_handshake_message(0x7FU, {0xAAU, 0xBBU}));
        encrypted_bytes.insert(encrypted_bytes.end(), encrypted_handshake.begin(), encrypted_handshake.end());
        const auto encrypted_result = parser.inspect(encrypted_bytes);
        PFL_REQUIRE(encrypted_result.records.size() == 2U);
        PFL_EXPECT(encrypted_result.records[1].handshake_payload_kind == TlsHandshakePayloadKind::encrypted_opaque);
        PFL_EXPECT(encrypted_result.records[1].handshake_messages.empty());

        std::vector<std::uint8_t> plaintext_bytes = make_tls_record(
            0x16U,
            0x0303U,
            make_tls_handshake_message(0x7FU, {0xAAU, 0xBBU})
        );
        const auto plaintext_result = parser.inspect(plaintext_bytes);
        PFL_REQUIRE(plaintext_result.records.size() == 1U);
        PFL_EXPECT(plaintext_result.records[0].handshake_payload_kind == TlsHandshakePayloadKind::plaintext);
        PFL_REQUIRE(plaintext_result.records[0].handshake_messages.size() == 1U);
        PFL_EXPECT(plaintext_result.records[0].handshake_messages[0].type == std::optional<std::uint8_t> {0x7FU});
    }

    {
        ScopedTestContext context {"synthetic=partial_ccs_does_not_switch_later_invocation"};
        auto partial_ccs = make_tls_record(0x14U, 0x0303U, {0x01U});
        partial_ccs.pop_back();
        const auto partial_result = parser.inspect(partial_ccs);
        PFL_REQUIRE(partial_result.records.size() == 1U);
        PFL_EXPECT(partial_result.records[0].status == TlsRecordStatus::partial_body);

        const auto plaintext_result = parser.inspect(make_tls_record(
            0x16U,
            0x0303U,
            make_tls_handshake_message(0x7FU, {0xAAU, 0xBBU})
        ));
        PFL_REQUIRE(plaintext_result.records.size() == 1U);
        PFL_EXPECT(plaintext_result.records[0].handshake_payload_kind == TlsHandshakePayloadKind::plaintext);
        PFL_REQUIRE(plaintext_result.records[0].handshake_messages.size() == 1U);
    }

    {
        ScopedTestContext context {"synthetic=client_hello_server_name_trailing_byte_malformed_and_sibling_preserved"};
        std::vector<std::uint8_t> extensions {};
        append_extension(extensions, 0x0000U, {0x00U, 0x04U, 0x00U, 0x00U, 0x01U, 'a', 0xFFU});
        append_extension(extensions, 0x0015U, {});
        const auto result = parser.inspect(make_client_hello_record_with_extensions(extensions));
        const auto& hello = require_parsed_client_hello(result);
        PFL_REQUIRE(hello.extensions.size() == 2U);
        PFL_EXPECT(hello.extensions[0].known_name == std::optional<std::string> {"server_name"});
        PFL_EXPECT(hello.extensions[0].structured_parse_status == TlsStructuredParseStatus::malformed);
        PFL_EXPECT(hello.extensions[0].server_names.empty());
        PFL_EXPECT(hello.extensions[1].known_name == std::optional<std::string> {"padding"});
        PFL_EXPECT(hello.extensions[1].structured_parse_status == TlsStructuredParseStatus::parsed);
        PFL_EXPECT(hello.extensions[1].padding_length == std::optional<std::size_t> {0U});
        PFL_EXPECT(hello.sni_names.empty());
    }

    {
        ScopedTestContext context {"synthetic=client_hello_alpn_trailing_byte_malformed_and_sibling_preserved"};
        std::vector<std::uint8_t> extensions {};
        append_extension(extensions, 0x0010U, {0x00U, 0x03U, 0x02U, 'h', '2', 0xFFU});
        append_extension(extensions, 0x0015U, {});
        const auto result = parser.inspect(make_client_hello_record_with_extensions(extensions));
        const auto& hello = require_parsed_client_hello(result);
        PFL_REQUIRE(hello.extensions.size() == 2U);
        PFL_EXPECT(hello.extensions[0].known_name == std::optional<std::string> {"application_layer_protocol_negotiation"});
        PFL_EXPECT(hello.extensions[0].structured_parse_status == TlsStructuredParseStatus::malformed);
        PFL_EXPECT(hello.extensions[0].alpn_protocols.empty());
        PFL_EXPECT(hello.extensions[1].structured_parse_status == TlsStructuredParseStatus::parsed);
        PFL_EXPECT(hello.alpn_protocols.empty());
    }

    {
        ScopedTestContext context {"synthetic=client_hello_supported_versions_trailing_byte_malformed_and_sibling_preserved"};
        std::vector<std::uint8_t> extensions {};
        append_extension(extensions, 0x002BU, {0x04U, 0x03U, 0x04U, 0x03U, 0x03U, 0xFFU});
        append_extension(extensions, 0x0015U, {});
        const auto result = parser.inspect(make_client_hello_record_with_extensions(extensions));
        const auto& hello = require_parsed_client_hello(result);
        PFL_REQUIRE(hello.extensions.size() == 2U);
        PFL_EXPECT(hello.extensions[0].known_name == std::optional<std::string> {"supported_versions"});
        PFL_EXPECT(hello.extensions[0].structured_parse_status == TlsStructuredParseStatus::malformed);
        PFL_EXPECT(hello.extensions[0].supported_versions.empty());
        PFL_EXPECT(hello.extensions[1].structured_parse_status == TlsStructuredParseStatus::parsed);
        PFL_EXPECT(hello.supported_versions.empty());
    }

    {
        ScopedTestContext context {"synthetic=client_hello_supported_groups_trailing_byte_malformed_and_sibling_preserved"};
        std::vector<std::uint8_t> extensions {};
        append_extension(extensions, 0x000AU, {0x00U, 0x04U, 0x00U, 0x1DU, 0x00U, 0x17U, 0xFFU});
        append_extension(extensions, 0x0015U, {});
        const auto result = parser.inspect(make_client_hello_record_with_extensions(extensions));
        const auto& hello = require_parsed_client_hello(result);
        PFL_REQUIRE(hello.extensions.size() == 2U);
        PFL_EXPECT(hello.extensions[0].known_name == std::optional<std::string> {"supported_groups"});
        PFL_EXPECT(hello.extensions[0].structured_parse_status == TlsStructuredParseStatus::malformed);
        PFL_EXPECT(hello.extensions[0].supported_group_ids.empty());
        PFL_EXPECT(hello.extensions[1].structured_parse_status == TlsStructuredParseStatus::parsed);
    }

    {
        ScopedTestContext context {"synthetic=client_hello_key_share_trailing_byte_malformed_and_sibling_preserved"};
        std::vector<std::uint8_t> extensions {};
        append_extension(extensions, 0x0033U, {0x00U, 0x05U, 0x00U, 0x1DU, 0x00U, 0x01U, 0xAAU, 0xFFU});
        append_extension(extensions, 0x0015U, {});
        const auto result = parser.inspect(make_client_hello_record_with_extensions(extensions));
        const auto& hello = require_parsed_client_hello(result);
        PFL_REQUIRE(hello.extensions.size() == 2U);
        PFL_EXPECT(hello.extensions[0].known_name == std::optional<std::string> {"key_share"});
        PFL_EXPECT(hello.extensions[0].structured_parse_status == TlsStructuredParseStatus::malformed);
        PFL_EXPECT(hello.extensions[0].key_share_entries.empty());
        PFL_EXPECT(hello.extensions[1].structured_parse_status == TlsStructuredParseStatus::parsed);
    }

    {
        ScopedTestContext context {"synthetic=client_hello_psk_modes_trailing_byte_malformed_and_sibling_preserved"};
        std::vector<std::uint8_t> extensions {};
        append_extension(extensions, 0x002DU, {0x01U, 0x01U, 0xFFU});
        append_extension(extensions, 0x0015U, {});
        const auto result = parser.inspect(make_client_hello_record_with_extensions(extensions));
        const auto& hello = require_parsed_client_hello(result);
        PFL_REQUIRE(hello.extensions.size() == 2U);
        PFL_EXPECT(hello.extensions[0].known_name == std::optional<std::string> {"psk_key_exchange_modes"});
        PFL_EXPECT(hello.extensions[0].structured_parse_status == TlsStructuredParseStatus::malformed);
        PFL_EXPECT(hello.extensions[0].psk_key_exchange_mode_ids.empty());
        PFL_EXPECT(hello.extensions[1].structured_parse_status == TlsStructuredParseStatus::parsed);
    }

    {
        ScopedTestContext context {"synthetic=client_hello_status_request_trailing_byte_malformed_and_sibling_preserved"};
        std::vector<std::uint8_t> extensions {};
        append_extension(extensions, 0x0005U, {0x01U, 0x00U, 0x00U, 0x00U, 0x00U, 0xFFU});
        append_extension(extensions, 0x0015U, {});
        const auto result = parser.inspect(make_client_hello_record_with_extensions(extensions));
        const auto& hello = require_parsed_client_hello(result);
        PFL_REQUIRE(hello.extensions.size() == 2U);
        PFL_EXPECT(hello.extensions[0].known_name == std::optional<std::string> {"status_request"});
        PFL_EXPECT(hello.extensions[0].structured_parse_status == TlsStructuredParseStatus::malformed);
        PFL_EXPECT(!hello.extensions[0].status_request.has_value());
        PFL_EXPECT(hello.extensions[1].structured_parse_status == TlsStructuredParseStatus::parsed);
    }

    {
        ScopedTestContext context {"synthetic=client_hello_compress_certificate_trailing_byte_malformed_and_sibling_preserved"};
        std::vector<std::uint8_t> extensions {};
        append_extension(extensions, 0x001BU, {0x02U, 0x00U, 0x02U, 0xFFU});
        append_extension(extensions, 0x0015U, {});
        const auto result = parser.inspect(make_client_hello_record_with_extensions(extensions));
        const auto& hello = require_parsed_client_hello(result);
        PFL_REQUIRE(hello.extensions.size() == 2U);
        PFL_EXPECT(hello.extensions[0].known_name == std::optional<std::string> {"compress_certificate"});
        PFL_EXPECT(hello.extensions[0].structured_parse_status == TlsStructuredParseStatus::malformed);
        PFL_EXPECT(hello.extensions[0].certificate_compression_algorithm_ids.empty());
        PFL_EXPECT(hello.extensions[1].structured_parse_status == TlsStructuredParseStatus::parsed);
    }

    {
        ScopedTestContext context {"synthetic=client_hello_extension_block_trailing_bytes_malformed"};
        std::vector<std::uint8_t> body {};
        append_be16(body, 0x0303U);
        const auto random = make_zero_filled(32U);
        body.insert(body.end(), random.begin(), random.end());
        body.push_back(0x00U);
        append_be16(body, 0x0002U);
        append_be16(body, 0x1301U);
        body.push_back(0x01U);
        body.push_back(0x00U);
        append_be16(body, 0x0000U);
        body.push_back(0xFFU);
        const auto result = parser.inspect(make_tls_record(0x16U, 0x0303U, make_tls_handshake_message(0x01U, body)));
        const auto& handshake = require_single_handshake(result);
        PFL_EXPECT(handshake.status == TlsHandshakeStatus::complete);
        PFL_EXPECT(handshake.structured_parse_status == TlsStructuredParseStatus::malformed);
        PFL_EXPECT(!handshake.client_hello.has_value());
    }

    {
        ScopedTestContext context {"synthetic=server_hello_extension_block_trailing_bytes_malformed"};
        std::vector<std::uint8_t> body {};
        append_be16(body, 0x0303U);
        const auto random = make_zero_filled(32U);
        body.insert(body.end(), random.begin(), random.end());
        body.push_back(0x00U);
        append_be16(body, 0x1301U);
        body.push_back(0x00U);
        append_be16(body, 0x0000U);
        body.push_back(0xFFU);
        const auto result = parser.inspect(make_tls_record(0x16U, 0x0303U, make_tls_handshake_message(0x02U, body)));
        const auto& handshake = require_single_handshake(result);
        PFL_EXPECT(handshake.status == TlsHandshakeStatus::complete);
        PFL_EXPECT(handshake.structured_parse_status == TlsStructuredParseStatus::malformed);
        PFL_EXPECT(!handshake.server_hello.has_value());
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
        PFL_EXPECT(result.records[0].available_bytes == 5U);
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
        PFL_EXPECT(result.records[0].available_bytes == bytes.size());
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
        PFL_EXPECT(result.records[0].available_bytes == 6U);
        PFL_EXPECT(result.records[1].available_bytes == 5U);
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
        ScopedTestContext context {"synthetic=client_hello_supported_groups_complete"};
        std::vector<std::uint8_t> extensions {};
        append_extension(
            extensions,
            0x000AU,
            {0x00U, 0x08U, 0xFAU, 0xFAU, 0x00U, 0x1DU, 0x00U, 0x17U, 0x00U, 0x18U}
        );
        const auto result = parser.inspect(make_client_hello_record_with_extensions(extensions));
        const auto& extension = require_single_client_hello_extension(result);
        PFL_EXPECT(extension.known_name == std::optional<std::string> {"supported_groups"});
        PFL_EXPECT(extension.structured_parse_status == TlsStructuredParseStatus::parsed);
        PFL_EXPECT(extension.supported_group_ids == std::vector<std::uint16_t>({0xFAFAU, 0x001DU, 0x0017U, 0x0018U}));
    }

    {
        ScopedTestContext context {"synthetic=client_hello_supported_groups_malformed_body_preserves_handshake"};
        std::vector<std::uint8_t> extensions {};
        append_extension(extensions, 0x000AU, {0x00U, 0x03U, 0x00U, 0x1DU, 0x00U});
        const auto result = parser.inspect(make_client_hello_record_with_extensions(extensions));
        const auto& extension = require_single_client_hello_extension(result);
        PFL_EXPECT(extension.known_name == std::optional<std::string> {"supported_groups"});
        PFL_EXPECT(extension.structured_parse_status == TlsStructuredParseStatus::malformed);
        PFL_EXPECT(extension.supported_group_ids.empty());
    }

    {
        ScopedTestContext context {"synthetic=client_hello_signature_algorithms_complete"};
        std::vector<std::uint8_t> extensions {};
        append_extension(extensions, 0x000DU, {0x00U, 0x06U, 0x04U, 0x03U, 0xFAU, 0xFAU, 0x08U, 0x04U});
        const auto result = parser.inspect(make_client_hello_record_with_extensions(extensions));
        const auto& extension = require_single_client_hello_extension(result);
        PFL_EXPECT(extension.known_name == std::optional<std::string> {"signature_algorithms"});
        PFL_EXPECT(extension.structured_parse_status == TlsStructuredParseStatus::parsed);
        PFL_EXPECT(extension.signature_scheme_ids == std::vector<std::uint16_t>({0x0403U, 0xFAFAU, 0x0804U}));
    }

    {
        ScopedTestContext context {"synthetic=client_hello_signature_algorithms_malformed"};
        std::vector<std::uint8_t> extensions {};
        append_extension(extensions, 0x000DU, {0x00U, 0x03U, 0x04U, 0x03U, 0x08U});
        const auto result = parser.inspect(make_client_hello_record_with_extensions(extensions));
        const auto& extension = require_single_client_hello_extension(result);
        PFL_EXPECT(extension.structured_parse_status == TlsStructuredParseStatus::malformed);
        PFL_EXPECT(extension.signature_scheme_ids.empty());
    }

    {
        ScopedTestContext context {"synthetic=client_hello_key_share_complete"};
        std::vector<std::uint8_t> extensions {};
        std::vector<std::uint8_t> body {};
        append_be16(body, 41U);
        append_be16(body, 0xFAFAU);
        append_be16(body, 1U);
        body.push_back(0xABU);
        append_be16(body, 0x001DU);
        append_be16(body, 32U);
        const auto key_exchange = make_zero_filled(32U);
        body.insert(body.end(), key_exchange.begin(), key_exchange.end());
        append_extension(extensions, 0x0033U, body);
        const auto result = parser.inspect(make_client_hello_record_with_extensions(extensions));
        const auto& extension = require_single_client_hello_extension(result);
        PFL_EXPECT(extension.known_name == std::optional<std::string> {"key_share"});
        PFL_EXPECT(extension.structured_parse_status == TlsStructuredParseStatus::parsed);
        PFL_EXPECT(extension.key_share_entries.size() == 2U);
        PFL_EXPECT(extension.key_share_entries[0].order_index == 0U);
        PFL_EXPECT(extension.key_share_entries[0].group_id == 0xFAFAU);
        PFL_EXPECT(extension.key_share_entries[0].key_exchange_length == 1U);
        PFL_EXPECT(extension.key_share_entries[1].order_index == 1U);
        PFL_EXPECT(extension.key_share_entries[1].group_id == 0x001DU);
        PFL_EXPECT(extension.key_share_entries[1].key_exchange_length == 32U);
    }

    {
        ScopedTestContext context {"synthetic=client_hello_key_share_malformed"};
        std::vector<std::uint8_t> extensions {};
        std::vector<std::uint8_t> body {};
        append_be16(body, 5U);
        append_be16(body, 0x001DU);
        append_be16(body, 2U);
        body.push_back(0xAAU);
        append_extension(extensions, 0x0033U, body);
        const auto result = parser.inspect(make_client_hello_record_with_extensions(extensions));
        const auto& extension = require_single_client_hello_extension(result);
        PFL_EXPECT(extension.structured_parse_status == TlsStructuredParseStatus::malformed);
        PFL_EXPECT(extension.key_share_entries.empty());
    }

    {
        ScopedTestContext context {"synthetic=client_hello_psk_modes_complete"};
        std::vector<std::uint8_t> extensions {};
        append_extension(extensions, 0x002DU, {0x02U, 0x01U, 0xAAU});
        const auto result = parser.inspect(make_client_hello_record_with_extensions(extensions));
        const auto& extension = require_single_client_hello_extension(result);
        PFL_EXPECT(extension.known_name == std::optional<std::string> {"psk_key_exchange_modes"});
        PFL_EXPECT(extension.structured_parse_status == TlsStructuredParseStatus::parsed);
        PFL_EXPECT(extension.psk_key_exchange_mode_ids == std::vector<std::uint8_t>({0x01U, 0xAAU}));
    }

    {
        ScopedTestContext context {"synthetic=client_hello_psk_modes_malformed"};
        std::vector<std::uint8_t> extensions {};
        append_extension(extensions, 0x002DU, {0x02U, 0x01U});
        const auto result = parser.inspect(make_client_hello_record_with_extensions(extensions));
        const auto& extension = require_single_client_hello_extension(result);
        PFL_EXPECT(extension.structured_parse_status == TlsStructuredParseStatus::malformed);
        PFL_EXPECT(extension.psk_key_exchange_mode_ids.empty());
    }

    {
        ScopedTestContext context {"synthetic=client_hello_status_request_complete"};
        std::vector<std::uint8_t> extensions {};
        append_extension(extensions, 0x0005U, {0x01U, 0x00U, 0x00U, 0x00U, 0x00U});
        const auto result = parser.inspect(make_client_hello_record_with_extensions(extensions));
        const auto& extension = require_single_client_hello_extension(result);
        PFL_EXPECT(extension.known_name == std::optional<std::string> {"status_request"});
        PFL_EXPECT(extension.structured_parse_status == TlsStructuredParseStatus::parsed);
        PFL_REQUIRE(extension.status_request.has_value());
        PFL_EXPECT(extension.status_request->status_type == 1U);
        PFL_EXPECT(extension.status_request->responder_id_list_length == 0U);
        PFL_EXPECT(extension.status_request->request_extensions_length == 0U);
    }

    {
        ScopedTestContext context {"synthetic=client_hello_status_request_malformed"};
        std::vector<std::uint8_t> extensions {};
        append_extension(extensions, 0x0005U, {0x01U, 0x00U, 0x02U, 0xAAU});
        const auto result = parser.inspect(make_client_hello_record_with_extensions(extensions));
        const auto& extension = require_single_client_hello_extension(result);
        PFL_EXPECT(extension.structured_parse_status == TlsStructuredParseStatus::malformed);
        PFL_EXPECT(!extension.status_request.has_value());
    }

    {
        ScopedTestContext context {"synthetic=client_hello_compress_certificate_complete"};
        std::vector<std::uint8_t> extensions {};
        append_extension(extensions, 0x001BU, {0x04U, 0x00U, 0x02U, 0xFAU, 0xFAU});
        const auto result = parser.inspect(make_client_hello_record_with_extensions(extensions));
        const auto& extension = require_single_client_hello_extension(result);
        PFL_EXPECT(extension.known_name == std::optional<std::string> {"compress_certificate"});
        PFL_EXPECT(extension.structured_parse_status == TlsStructuredParseStatus::parsed);
        PFL_EXPECT(extension.certificate_compression_algorithm_ids == std::vector<std::uint16_t>({0x0002U, 0xFAFAU}));
    }

    {
        ScopedTestContext context {"synthetic=client_hello_compress_certificate_malformed"};
        std::vector<std::uint8_t> extensions {};
        append_extension(extensions, 0x001BU, {0x03U, 0x00U, 0x02U, 0x00U});
        const auto result = parser.inspect(make_client_hello_record_with_extensions(extensions));
        const auto& extension = require_single_client_hello_extension(result);
        PFL_EXPECT(extension.structured_parse_status == TlsStructuredParseStatus::malformed);
        PFL_EXPECT(extension.certificate_compression_algorithm_ids.empty());
    }

    {
        ScopedTestContext context {"synthetic=client_hello_padding_zero_length"};
        std::vector<std::uint8_t> extensions {};
        append_extension(extensions, 0x0015U, {});
        const auto result = parser.inspect(make_client_hello_record_with_extensions(extensions));
        const auto& extension = require_single_client_hello_extension(result);
        PFL_EXPECT(extension.known_name == std::optional<std::string> {"padding"});
        PFL_EXPECT(extension.structured_parse_status == TlsStructuredParseStatus::parsed);
        PFL_EXPECT(extension.padding_length == std::optional<std::size_t> {0U});
    }

    {
        ScopedTestContext context {"synthetic=client_hello_padding_non_zero_length"};
        std::vector<std::uint8_t> extensions {};
        append_extension(extensions, 0x0015U, {0x00U, 0x00U, 0x00U});
        const auto result = parser.inspect(make_client_hello_record_with_extensions(extensions));
        const auto& extension = require_single_client_hello_extension(result);
        PFL_EXPECT(extension.structured_parse_status == TlsStructuredParseStatus::parsed);
        PFL_EXPECT(extension.padding_length == std::optional<std::size_t> {3U});
    }

    {
        ScopedTestContext context {"synthetic=server_hello_key_share_complete"};
        std::vector<std::uint8_t> extensions {};
        std::vector<std::uint8_t> body {};
        append_be16(body, 0x11ECU);
        append_be16(body, 4U);
        body.insert(body.end(), {0x00U, 0x01U, 0x02U, 0x03U});
        append_extension(extensions, 0x0033U, body);
        const auto result = parser.inspect(make_server_hello_record_with_extensions(extensions));
        const auto& extension = require_single_server_hello_extension(result);
        PFL_EXPECT(extension.known_name == std::optional<std::string> {"key_share"});
        PFL_EXPECT(extension.structured_parse_status == TlsStructuredParseStatus::parsed);
        PFL_EXPECT(extension.key_share_entries.size() == 1U);
        PFL_EXPECT(extension.key_share_entries[0].group_id == 0x11ECU);
        PFL_EXPECT(extension.key_share_entries[0].key_exchange_length == 4U);
    }

    {
        ScopedTestContext context {"synthetic=server_hello_key_share_hrr_selected_group_not_attempted"};
        std::vector<std::uint8_t> extensions {};
        append_extension(extensions, 0x0033U, {0x00U, 0x1DU});
        const auto result = parser.inspect(make_server_hello_record_with_extensions(extensions));
        const auto& extension = require_single_server_hello_extension(result);
        PFL_EXPECT(extension.structured_parse_status == TlsStructuredParseStatus::not_attempted);
        PFL_EXPECT(extension.key_share_entries.empty());
    }

    {
        ScopedTestContext context {"synthetic=server_hello_key_share_malformed_body_preserves_handshake"};
        std::vector<std::uint8_t> extensions {};
        append_extension(extensions, 0x0033U, {0x00U, 0x1DU, 0x00U, 0x02U, 0xAAU});
        const auto result = parser.inspect(make_server_hello_record_with_extensions(extensions));
        const auto& extension = require_single_server_hello_extension(result);
        PFL_EXPECT(extension.structured_parse_status == TlsStructuredParseStatus::malformed);
        PFL_EXPECT(extension.key_share_entries.empty());
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
