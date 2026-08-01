#include <algorithm>
#include <array>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <string_view>
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

void append_be32(std::vector<std::uint8_t>& bytes, const std::uint32_t value) {
    bytes.push_back(static_cast<std::uint8_t>((value >> 24U) & 0xFFU));
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

std::vector<std::uint8_t> make_tls_certificate_body(
    const std::vector<std::vector<std::uint8_t>>& certificate_entries
) {
    std::vector<std::uint8_t> list_bytes {};
    for (const auto& entry : certificate_entries) {
        append_be24(list_bytes, static_cast<std::uint32_t>(entry.size()));
        list_bytes.insert(list_bytes.end(), entry.begin(), entry.end());
    }

    std::vector<std::uint8_t> body {};
    append_be24(body, static_cast<std::uint32_t>(list_bytes.size()));
    body.insert(body.end(), list_bytes.begin(), list_bytes.end());
    return body;
}

std::vector<std::uint8_t> make_tls12_certificate_request_body(
    const std::vector<std::uint8_t>& certificate_type_ids,
    const std::vector<std::uint16_t>& signature_scheme_ids,
    const std::vector<std::vector<std::uint8_t>>& certificate_authorities
) {
    std::vector<std::uint8_t> body {};
    body.push_back(static_cast<std::uint8_t>(certificate_type_ids.size()));
    body.insert(body.end(), certificate_type_ids.begin(), certificate_type_ids.end());

    append_be16(body, static_cast<std::uint16_t>(signature_scheme_ids.size() * 2U));
    for (const auto signature_scheme_id : signature_scheme_ids) {
        append_be16(body, signature_scheme_id);
    }

    std::vector<std::uint8_t> authorities_bytes {};
    for (const auto& authority : certificate_authorities) {
        append_be16(authorities_bytes, static_cast<std::uint16_t>(authority.size()));
        authorities_bytes.insert(authorities_bytes.end(), authority.begin(), authority.end());
    }

    append_be16(body, static_cast<std::uint16_t>(authorities_bytes.size()));
    body.insert(body.end(), authorities_bytes.begin(), authorities_bytes.end());
    return body;
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

const TlsNewSessionTicketModel& require_parsed_new_session_ticket(const TlsInspectionResult& result) {
    const auto& handshake = require_single_handshake(result);
    PFL_EXPECT(handshake.kind == TlsHandshakeKind::new_session_ticket);
    PFL_EXPECT(handshake.structured_parse_status == TlsStructuredParseStatus::parsed);
    PFL_REQUIRE(handshake.new_session_ticket.has_value());
    return *handshake.new_session_ticket;
}

const TlsCertificateModel& require_parsed_certificate(const TlsInspectionResult& result) {
    const auto& handshake = require_single_handshake(result);
    PFL_EXPECT(handshake.kind == TlsHandshakeKind::certificate);
    PFL_EXPECT(handshake.structured_parse_status == TlsStructuredParseStatus::parsed);
    PFL_REQUIRE(handshake.certificate.has_value());
    return *handshake.certificate;
}

const TlsCertificateRequestModel& require_parsed_certificate_request(const TlsInspectionResult& result) {
    const auto& handshake = require_single_handshake(result);
    PFL_EXPECT(handshake.kind == TlsHandshakeKind::certificate_request);
    PFL_EXPECT(handshake.structured_parse_status == TlsStructuredParseStatus::parsed);
    PFL_REQUIRE(handshake.certificate_request.has_value());
    return *handshake.certificate_request;
}

const TlsEcdheServerKeyExchangeModel& require_parsed_ecdhe_server_key_exchange(
    const TlsInspectionResult& result
) {
    const auto& handshake = require_single_handshake(result);
    PFL_EXPECT(handshake.kind == TlsHandshakeKind::server_key_exchange);
    PFL_EXPECT(handshake.structured_parse_status == TlsStructuredParseStatus::parsed);
    PFL_REQUIRE(handshake.ecdhe_server_key_exchange.has_value());
    return *handshake.ecdhe_server_key_exchange;
}

const TlsEcdheClientKeyExchangeModel& require_parsed_ecdhe_client_key_exchange(
    const TlsInspectionResult& result
) {
    const auto& handshake = require_single_handshake(result);
    PFL_EXPECT(handshake.kind == TlsHandshakeKind::client_key_exchange);
    PFL_EXPECT(handshake.structured_parse_status == TlsStructuredParseStatus::parsed);
    PFL_REQUIRE(handshake.ecdhe_client_key_exchange.has_value());
    return *handshake.ecdhe_client_key_exchange;
}

void expect_tls_alert_entry(
    const TlsAlertEntryModel& entry,
    const std::uint8_t expected_level,
    const std::uint8_t expected_description
) {
    PFL_EXPECT(entry.level == expected_level);
    PFL_EXPECT(entry.description == expected_description);
}

std::vector<std::uint8_t> require_tls_fixture_transport_payload_matching_record(
    const std::filesystem::path& relative_path,
    const std::function<bool(const TlsInspectionResult&)>& predicate
) {
    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(fixture_path(relative_path), CaptureImportOptions {}));
    const auto packet_count = session.summary().packet_count;

    PacketPayloadService payload_service {};
    TlsInspectionParser parser {};
    for (std::uint64_t packet_index = 0U; packet_index < packet_count; ++packet_index) {
        const auto packet = session.find_packet(packet_index);
        PFL_REQUIRE(packet.has_value());

        const auto packet_bytes = session.read_packet_data(*packet);
        const auto payload = payload_service.extract_transport_payload(packet_bytes, packet->data_link_type);
        if (payload.empty()) {
            continue;
        }

        const auto result = parser.inspect(payload);
        if (predicate(result)) {
            return payload;
        }
    }

    record_failure_message(
        "fixture=" + relative_path.string() + " did not contain a transport payload matching the requested TLS predicate"
    );
    PFL_REQUIRE(false);
    return {};
}

const TlsExtensionModel* find_extension_by_type(
    const std::vector<TlsExtensionModel>& extensions,
    const std::uint16_t type
) {
    const auto it = std::find_if(extensions.begin(), extensions.end(), [&](const TlsExtensionModel& extension) {
        return extension.type == type;
    });
    return it == extensions.end() ? nullptr : &(*it);
}

std::vector<std::size_t> collect_certificate_entry_lengths(const TlsCertificateModel& certificate) {
    std::vector<std::size_t> lengths {};
    lengths.reserve(certificate.certificate_entries.size());
    for (const auto& entry : certificate.certificate_entries) {
        lengths.push_back(entry.declared_der_length);
    }
    return lengths;
}

std::vector<std::size_t> collect_certificate_authority_lengths(const TlsCertificateRequestModel& request) {
    std::vector<std::size_t> lengths {};
    lengths.reserve(request.certificate_authority_entries.size());
    for (const auto& entry : request.certificate_authority_entries) {
        lengths.push_back(entry.declared_length);
    }
    return lengths;
}

std::vector<std::uint8_t> make_repeating_bytes(const std::size_t count, const std::uint8_t seed = 0x01U) {
    std::vector<std::uint8_t> bytes {};
    bytes.reserve(count);
    for (std::size_t index = 0U; index < count; ++index) {
        bytes.push_back(static_cast<std::uint8_t>(seed + static_cast<std::uint8_t>(index & 0x3FU)));
    }
    return bytes;
}

std::vector<std::uint8_t> make_minimal_server_hello_body_with_cipher_suite(
    const std::uint16_t version,
    const std::uint16_t cipher_suite
) {
    std::vector<std::uint8_t> body {};
    append_be16(body, version);
    const auto random = make_zero_filled(32U);
    body.insert(body.end(), random.begin(), random.end());
    body.push_back(0x00U);
    append_be16(body, cipher_suite);
    body.push_back(0x00U);
    return body;
}

std::vector<std::uint8_t> make_ecdhe_server_key_exchange_body_tls10_or_tls11(
    const std::uint16_t named_group_id,
    const std::size_t public_key_length,
    const std::size_t signature_length
) {
    std::vector<std::uint8_t> body {0x03U};
    append_be16(body, named_group_id);
    body.push_back(static_cast<std::uint8_t>(public_key_length));
    const auto public_key = make_repeating_bytes(public_key_length, 0x41U);
    body.insert(body.end(), public_key.begin(), public_key.end());
    append_be16(body, static_cast<std::uint16_t>(signature_length));
    const auto signature = make_repeating_bytes(signature_length, 0x80U);
    body.insert(body.end(), signature.begin(), signature.end());
    return body;
}

std::vector<std::uint8_t> make_ecdhe_server_key_exchange_body_tls12(
    const std::uint16_t named_group_id,
    const std::size_t public_key_length,
    const std::uint16_t signature_scheme_id,
    const std::size_t signature_length
) {
    auto body = make_ecdhe_server_key_exchange_body_tls10_or_tls11(
        named_group_id,
        public_key_length,
        0U
    );
    body.resize(4U + public_key_length);
    append_be16(body, signature_scheme_id);
    append_be16(body, static_cast<std::uint16_t>(signature_length));
    const auto signature = make_repeating_bytes(signature_length, 0x80U);
    body.insert(body.end(), signature.begin(), signature.end());
    return body;
}

std::vector<std::uint8_t> make_ecdhe_client_key_exchange_body(const std::size_t public_key_length) {
    std::vector<std::uint8_t> body {
        static_cast<std::uint8_t>(public_key_length)
    };
    const auto public_key = make_repeating_bytes(public_key_length, 0x21U);
    body.insert(body.end(), public_key.begin(), public_key.end());
    return body;
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
        PFL_EXPECT(partial_record.content_type_kind == TlsRecordContentTypeKind::application_data);
        PFL_EXPECT(partial_record.handshake_payload_kind == TlsHandshakePayloadKind::none);
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
        PFL_EXPECT(result.records[0].source_offset == 0U);
        PFL_EXPECT(result.records[0].handshake_payload_kind == TlsHandshakePayloadKind::plaintext);
        PFL_REQUIRE(result.records[0].handshake_messages.size() == 1U);
        PFL_EXPECT(result.records[0].handshake_messages[0].source_offset == 5U);
        PFL_EXPECT(result.records[0].handshake_messages[0].status == TlsHandshakeStatus::complete);
        PFL_EXPECT(result.records[0].handshake_messages[0].type == std::optional<std::uint8_t> {4U});
        PFL_EXPECT(result.records[0].handshake_messages[0].kind == TlsHandshakeKind::new_session_ticket);
        PFL_EXPECT(result.records[0].handshake_messages[0].declared_body_length == std::optional<std::size_t> {182U});
        PFL_EXPECT(result.records[0].handshake_messages[0].total_size == std::optional<std::size_t> {186U});
        PFL_EXPECT(result.records[0].handshake_messages[0].available_bytes == 186U);
        PFL_EXPECT(result.records[0].handshake_messages[0].structured_parse_status == TlsStructuredParseStatus::parsed);
        PFL_REQUIRE(result.records[0].handshake_messages[0].new_session_ticket.has_value());
        PFL_EXPECT(result.records[0].handshake_messages[0].new_session_ticket->ticket_lifetime_hint_seconds == 7200U);
        PFL_EXPECT(result.records[0].handshake_messages[0].new_session_ticket->ticket_length == 176U);
        PFL_EXPECT(result.records[1].status == TlsRecordStatus::complete);
        PFL_EXPECT(result.records[1].content_type_kind == TlsRecordContentTypeKind::change_cipher_spec);
        PFL_EXPECT(result.records[1].declared_payload_length == std::optional<std::size_t> {1U});
        PFL_EXPECT(result.records[1].total_size == std::optional<std::size_t> {6U});
        PFL_EXPECT(result.records[1].source_offset == 191U);
        PFL_EXPECT(result.records[2].status == TlsRecordStatus::complete);
        PFL_EXPECT(result.records[2].content_type_kind == TlsRecordContentTypeKind::handshake);
        PFL_EXPECT(result.records[2].legacy_version == std::optional<std::uint16_t> {0x0303U});
        PFL_EXPECT(result.records[2].declared_payload_length == std::optional<std::size_t> {40U});
        PFL_EXPECT(result.records[2].total_size == std::optional<std::size_t> {45U});
        PFL_EXPECT(result.records[2].source_offset == 197U);
        PFL_EXPECT(result.records[2].handshake_payload_kind == TlsHandshakePayloadKind::encrypted_opaque);
        PFL_EXPECT(result.records[2].handshake_messages.empty());
    }

    {
        struct ClientHelloFixtureExpectation {
            const char* relative_path;
            std::uint64_t packet_index;
            std::size_t expected_total_input_bytes;
            std::size_t expected_record_length;
            std::size_t expected_handshake_length;
            std::uint16_t expected_record_version;
            std::uint16_t expected_client_hello_version;
            const char* expected_sni;
            std::size_t expected_cipher_suite_count;
            std::size_t expected_extension_count;
            bool expect_signature_algorithms;
        };

        const std::vector<ClientHelloFixtureExpectation> expectations {
            {
                .relative_path = "parsing/tls/tls_1_0_badssl_baseline_12.pcap",
                .packet_index = 3U,
                .expected_total_input_bytes = 132U,
                .expected_record_length = 127U,
                .expected_handshake_length = 123U,
                .expected_record_version = 0x0301U,
                .expected_client_hello_version = 0x0301U,
                .expected_sni = "tls-v1-0.badssl.com",
                .expected_cipher_suite_count = 9U,
                .expected_extension_count = 6U,
                .expect_signature_algorithms = false,
            },
            {
                .relative_path = "parsing/tls/tls_1_1_badssl_baseline_13.pcap",
                .packet_index = 3U,
                .expected_total_input_bytes = 132U,
                .expected_record_length = 127U,
                .expected_handshake_length = 123U,
                .expected_record_version = 0x0301U,
                .expected_client_hello_version = 0x0302U,
                .expected_sni = "tls-v1-1.badssl.com",
                .expected_cipher_suite_count = 9U,
                .expected_extension_count = 6U,
                .expect_signature_algorithms = false,
            },
            {
                .relative_path = "parsing/tls/tls_1_2_badssl_baseline_14.pcap",
                .packet_index = 3U,
                .expected_total_input_bytes = 222U,
                .expected_record_length = 217U,
                .expected_handshake_length = 213U,
                .expected_record_version = 0x0301U,
                .expected_client_hello_version = 0x0303U,
                .expected_sni = "tls-v1-2.badssl.com",
                .expected_cipher_suite_count = 28U,
                .expected_extension_count = 7U,
                .expect_signature_algorithms = true,
            },
            {
                .relative_path = "parsing/tls/tls_1_2_status_request_alpn_19.pcap",
                .packet_index = 3U,
                .expected_total_input_bytes = 246U,
                .expected_record_length = 241U,
                .expected_handshake_length = 237U,
                .expected_record_version = 0x0301U,
                .expected_client_hello_version = 0x0303U,
                .expected_sni = "tls-v1-2.badssl.com",
                .expected_cipher_suite_count = 28U,
                .expected_extension_count = 9U,
                .expect_signature_algorithms = true,
            },
        };

        for (const auto& expectation : expectations) {
            ScopedTestContext context {
                std::string {"fixture="} + expectation.relative_path +
                " | packet=" + std::to_string(expectation.packet_index + 1U)
            };
            const auto payload = require_tls_fixture_transport_payload(expectation.relative_path, expectation.packet_index);
            const auto result = parser.inspect(payload);

            PFL_EXPECT(result.total_input_bytes == expectation.expected_total_input_bytes);
            PFL_EXPECT(result.consumed_bytes == expectation.expected_total_input_bytes);
            PFL_REQUIRE(result.records.size() == 1U);
            PFL_EXPECT(result.records[0].status == TlsRecordStatus::complete);
            PFL_EXPECT(result.records[0].content_type_kind == TlsRecordContentTypeKind::handshake);
            PFL_EXPECT(result.records[0].legacy_version == std::optional<std::uint16_t> {expectation.expected_record_version});
            PFL_EXPECT(result.records[0].declared_payload_length == std::optional<std::size_t> {expectation.expected_record_length});
            PFL_REQUIRE(result.records[0].handshake_messages.size() == 1U);

            const auto& handshake = result.records[0].handshake_messages[0];
            PFL_EXPECT(handshake.status == TlsHandshakeStatus::complete);
            PFL_EXPECT(handshake.kind == TlsHandshakeKind::client_hello);
            PFL_EXPECT(handshake.declared_body_length == std::optional<std::size_t> {expectation.expected_handshake_length});
            PFL_EXPECT(handshake.structured_parse_status == TlsStructuredParseStatus::parsed);
            PFL_REQUIRE(handshake.client_hello.has_value());

            const auto& hello = *handshake.client_hello;
            PFL_EXPECT(hello.legacy_version == expectation.expected_client_hello_version);
            PFL_EXPECT(hello.session_id.empty());
            PFL_EXPECT(hello.cipher_suites.size() == expectation.expected_cipher_suite_count);
            PFL_EXPECT(hello.extensions.size() == expectation.expected_extension_count);
            PFL_EXPECT(hello.sni_names == std::vector<std::string> {expectation.expected_sni});
            PFL_EXPECT(hello.alpn_protocols == (expectation.expected_extension_count == 9U
                ? std::vector<std::string> {"http/1.1"}
                : std::vector<std::string> {}));
            PFL_EXPECT(hello.supported_versions.empty());

            const auto* server_name = find_extension_by_type(hello.extensions, 0x0000U);
            PFL_REQUIRE(server_name != nullptr);
            PFL_EXPECT(server_name->server_names == std::vector<std::string> {expectation.expected_sni});

            const auto* supported_groups = find_extension_by_type(hello.extensions, 0x000AU);
            PFL_REQUIRE(supported_groups != nullptr);
            PFL_EXPECT(supported_groups->structured_parse_status == TlsStructuredParseStatus::parsed);
            PFL_EXPECT(!supported_groups->supported_group_ids.empty());

            const auto* signature_algorithms = find_extension_by_type(hello.extensions, 0x000DU);
            if (expectation.expect_signature_algorithms) {
                PFL_REQUIRE(signature_algorithms != nullptr);
                PFL_EXPECT(signature_algorithms->structured_parse_status == TlsStructuredParseStatus::parsed);
                PFL_EXPECT(!signature_algorithms->signature_scheme_ids.empty());
            } else {
                PFL_EXPECT(signature_algorithms == nullptr);
            }

            const auto* status_request = find_extension_by_type(hello.extensions, 0x0005U);
            if (std::string_view {expectation.relative_path} == "parsing/tls/tls_1_2_status_request_alpn_19.pcap") {
                PFL_REQUIRE(status_request != nullptr);
                PFL_REQUIRE(status_request->status_request.has_value());
                PFL_EXPECT(status_request->status_request->status_type == 1U);
                PFL_EXPECT(status_request->status_request->responder_id_list_length == 0U);
                PFL_EXPECT(status_request->status_request->request_extensions_length == 0U);
                const auto* alpn = find_extension_by_type(hello.extensions, 0x0010U);
                PFL_REQUIRE(alpn != nullptr);
                PFL_EXPECT(alpn->alpn_protocols == std::vector<std::string> {"http/1.1"});
            } else {
                PFL_EXPECT(status_request == nullptr);
            }
        }
    }

    {
        struct AlertFixtureExpectation {
            const char* relative_path;
            std::uint64_t packet_index;
            std::uint8_t expected_level;
            std::uint8_t expected_description;
        };

        const std::vector<AlertFixtureExpectation> expectations {
            {
                .relative_path = "parsing/tls/tls_1_2_client_to_tls_1_0_protocol_version_15.pcap",
                .packet_index = 13U,
                .expected_level = 2U,
                .expected_description = 70U,
            },
            {
                .relative_path = "parsing/tls/tls_1_2_expired_certificate_alert_16.pcap",
                .packet_index = 13U,
                .expected_level = 2U,
                .expected_description = 45U,
            },
            {
                .relative_path = "parsing/tls/tls_1_2_self_signed_unknown_ca_17.pcap",
                .packet_index = 7U,
                .expected_level = 2U,
                .expected_description = 48U,
            },
        };

        for (const auto& expectation : expectations) {
            ScopedTestContext context {
                std::string {"fixture="} + expectation.relative_path +
                " | packet=" + std::to_string(expectation.packet_index + 1U)
            };
            const auto payload = require_tls_fixture_transport_payload(expectation.relative_path, expectation.packet_index);
            const auto result = parser.inspect(payload);
            PFL_EXPECT(result.total_input_bytes == 7U);
            PFL_EXPECT(result.consumed_bytes == 7U);
            PFL_REQUIRE(result.records.size() == 1U);
            PFL_EXPECT(result.records[0].status == TlsRecordStatus::complete);
            PFL_EXPECT(result.records[0].content_type_kind == TlsRecordContentTypeKind::alert);
            PFL_EXPECT(result.records[0].legacy_version == std::optional<std::uint16_t> {0x0303U});
            PFL_EXPECT(result.records[0].declared_payload_length == std::optional<std::size_t> {2U});
            PFL_EXPECT(result.records[0].total_size == std::optional<std::size_t> {7U});
            PFL_EXPECT(result.records[0].handshake_payload_kind == TlsHandshakePayloadKind::none);
            PFL_EXPECT(result.records[0].alert_payload_kind == TlsAlertPayloadKind::plaintext);
            PFL_EXPECT(result.records[0].alert_parse_status == TlsAlertParseStatus::parsed);
            PFL_REQUIRE(result.records[0].alert_entries.size() == 1U);
            expect_tls_alert_entry(
                result.records[0].alert_entries[0],
                expectation.expected_level,
                expectation.expected_description
            );
            PFL_EXPECT(result.records[0].handshake_messages.empty());
        }
    }

    {
        ScopedTestContext context {"fixture=parsing/tls/tls_1_2_status_request_alpn_19.pcap | server_hello"};
        const auto payload = require_tls_fixture_transport_payload(
            "parsing/tls/tls_1_2_status_request_alpn_19.pcap",
            5U
        );
        const auto result = parser.inspect(payload);
        PFL_REQUIRE(result.records.size() >= 1U);
        PFL_EXPECT(result.records[0].status == TlsRecordStatus::complete);
        PFL_EXPECT(result.records[0].content_type_kind == TlsRecordContentTypeKind::handshake);
        PFL_REQUIRE(result.records[0].handshake_messages.size() == 1U);
        PFL_EXPECT(result.records[0].handshake_messages[0].kind == TlsHandshakeKind::server_hello);
        PFL_EXPECT(result.records[0].handshake_messages[0].structured_parse_status == TlsStructuredParseStatus::parsed);
        PFL_REQUIRE(result.records[0].handshake_messages[0].server_hello.has_value());
        const auto& hello = *result.records[0].handshake_messages[0].server_hello;
        PFL_EXPECT(hello.selected_tls_version == 0x0303U);
        PFL_EXPECT(hello.selected_cipher_suite == 0xC030U);
        PFL_EXPECT(hello.selected_alpn_protocol == std::optional<std::string> {"http/1.1"});
        const auto* alpn_extension = find_extension_by_type(hello.extensions, 0x0010U);
        PFL_REQUIRE(alpn_extension != nullptr);
        PFL_EXPECT(alpn_extension->structured_parse_status == TlsStructuredParseStatus::parsed);
        PFL_EXPECT(alpn_extension->alpn_protocols == std::vector<std::string> {"http/1.1"});
    }

    {
        ScopedTestContext context {"synthetic=ecdhe_server_key_exchange_tls10_complete"};
        const auto result = parser.inspect(
            make_tls_record(
                0x16U,
                0x0301U,
                make_tls_handshake_message(
                    0x0CU,
                    make_ecdhe_server_key_exchange_body_tls10_or_tls11(0x0017U, 65U, 256U)
                )
            ),
            TlsInspectionParserContext {
                .semantic_state = TlsInspectionSemanticState::plaintext,
                .negotiated_cipher_suite = 0xC014U,
                .negotiated_version = 0x0301U,
            }
        );
        const auto& server_key_exchange = require_parsed_ecdhe_server_key_exchange(result);
        PFL_EXPECT(server_key_exchange.curve_type == std::optional<std::uint8_t> {3U});
        PFL_EXPECT(server_key_exchange.named_group_id == std::optional<std::uint16_t> {0x0017U});
        PFL_EXPECT(server_key_exchange.declared_public_key_length == std::optional<std::size_t> {65U});
        PFL_EXPECT(server_key_exchange.available_public_key_length == 65U);
        PFL_EXPECT(server_key_exchange.public_key_complete);
        PFL_EXPECT(server_key_exchange.signature_authentication_kind == TlsCipherSuiteAuthenticationKind::rsa);
        PFL_EXPECT(!server_key_exchange.signature_scheme_id.has_value());
        PFL_EXPECT(server_key_exchange.declared_signature_length == std::optional<std::size_t> {256U});
        PFL_EXPECT(server_key_exchange.available_signature_length == 256U);
        PFL_EXPECT(server_key_exchange.signature_complete);
        PFL_EXPECT(server_key_exchange.status == TlsStructuredBodyStatus::complete);
    }

    {
        ScopedTestContext context {"synthetic=ecdhe_server_key_exchange_tls12_complete"};
        const auto result = parser.inspect(
            make_tls_record(
                0x16U,
                0x0303U,
                make_tls_handshake_message(
                    0x0CU,
                    make_ecdhe_server_key_exchange_body_tls12(0x0017U, 65U, 0x0601U, 256U)
                )
            ),
            TlsInspectionParserContext {
                .semantic_state = TlsInspectionSemanticState::plaintext,
                .negotiated_cipher_suite = 0xC030U,
                .negotiated_version = 0x0303U,
            }
        );
        const auto& server_key_exchange = require_parsed_ecdhe_server_key_exchange(result);
        PFL_EXPECT(server_key_exchange.curve_type == std::optional<std::uint8_t> {3U});
        PFL_EXPECT(server_key_exchange.named_group_id == std::optional<std::uint16_t> {0x0017U});
        PFL_EXPECT(server_key_exchange.declared_public_key_length == std::optional<std::size_t> {65U});
        PFL_EXPECT(server_key_exchange.available_public_key_length == 65U);
        PFL_EXPECT(server_key_exchange.public_key_complete);
        PFL_EXPECT(server_key_exchange.signature_authentication_kind == TlsCipherSuiteAuthenticationKind::rsa);
        PFL_EXPECT(server_key_exchange.signature_scheme_id == std::optional<std::uint16_t> {0x0601U});
        PFL_EXPECT(server_key_exchange.declared_signature_length == std::optional<std::size_t> {256U});
        PFL_EXPECT(server_key_exchange.available_signature_length == 256U);
        PFL_EXPECT(server_key_exchange.signature_complete);
        PFL_EXPECT(server_key_exchange.status == TlsStructuredBodyStatus::complete);
    }

    {
        ScopedTestContext context {"synthetic=ecdhe_server_key_exchange_tls12_negotiated_version_independent_from_record_legacy_version"};
        const auto result = parser.inspect(
            make_tls_record(
                0x16U,
                0x0301U,
                make_tls_handshake_message(
                    0x0CU,
                    make_ecdhe_server_key_exchange_body_tls12(0x0017U, 65U, 0x0601U, 256U)
                )
            ),
            TlsInspectionParserContext {
                .semantic_state = TlsInspectionSemanticState::plaintext,
                .negotiated_cipher_suite = 0xC030U,
                .negotiated_version = 0x0303U,
            }
        );
        const auto& server_key_exchange = require_parsed_ecdhe_server_key_exchange(result);
        PFL_EXPECT(server_key_exchange.signature_scheme_id == std::optional<std::uint16_t> {0x0601U});
        PFL_EXPECT(server_key_exchange.status == TlsStructuredBodyStatus::complete);
    }

    {
        ScopedTestContext context {"synthetic=ecdhe_server_key_exchange_tls11_negotiated_version_independent_from_record_legacy_version"};
        const auto result = parser.inspect(
            make_tls_record(
                0x16U,
                0x0303U,
                make_tls_handshake_message(
                    0x0CU,
                    make_ecdhe_server_key_exchange_body_tls10_or_tls11(0x0017U, 65U, 256U)
                )
            ),
            TlsInspectionParserContext {
                .semantic_state = TlsInspectionSemanticState::plaintext,
                .negotiated_cipher_suite = 0xC014U,
                .negotiated_version = 0x0302U,
            }
        );
        const auto& server_key_exchange = require_parsed_ecdhe_server_key_exchange(result);
        PFL_EXPECT(!server_key_exchange.signature_scheme_id.has_value());
        PFL_EXPECT(server_key_exchange.status == TlsStructuredBodyStatus::complete);
    }

    {
        ScopedTestContext context {"synthetic=ecdhe_server_key_exchange_unknown_negotiated_version_does_not_guess_tls12_layout"};
        const auto result = parser.inspect(
            make_tls_record(
                0x16U,
                0x0303U,
                make_tls_handshake_message(
                    0x0CU,
                    make_ecdhe_server_key_exchange_body_tls12(0x0017U, 65U, 0x0601U, 256U)
                )
            ),
            TlsInspectionParserContext {
                .semantic_state = TlsInspectionSemanticState::plaintext,
                .negotiated_cipher_suite = 0xC030U,
                .negotiated_version = 0x7A7AU,
            }
        );
        const auto& handshake = require_single_handshake(result);
        PFL_EXPECT(handshake.kind == TlsHandshakeKind::server_key_exchange);
        PFL_EXPECT(handshake.structured_parse_status == TlsStructuredParseStatus::not_attempted);
        PFL_EXPECT(!handshake.ecdhe_server_key_exchange.has_value());
    }

    {
        ScopedTestContext context {"synthetic=server_hello_establishes_ecdhe_context_for_following_server_key_exchange"};
        auto bytes = make_tls_record(
            0x16U,
            0x0303U,
            make_tls_handshake_message(
                0x02U,
                make_minimal_server_hello_body_with_cipher_suite(0x0303U, 0xC030U)
            )
        );
        const auto server_key_exchange_record = make_tls_record(
            0x16U,
            0x0303U,
            make_tls_handshake_message(
                0x0CU,
                make_ecdhe_server_key_exchange_body_tls12(0x0017U, 65U, 0x0601U, 256U)
            )
        );
        bytes.insert(bytes.end(), server_key_exchange_record.begin(), server_key_exchange_record.end());

        const auto result = parser.inspect(bytes);
        PFL_REQUIRE(result.records.size() == 2U);
        PFL_REQUIRE(result.records[1].handshake_messages.size() == 1U);
        PFL_EXPECT(result.records[1].handshake_messages[0].kind == TlsHandshakeKind::server_key_exchange);
        PFL_EXPECT(result.records[1].handshake_messages[0].structured_parse_status == TlsStructuredParseStatus::parsed);
        PFL_REQUIRE(result.records[1].handshake_messages[0].ecdhe_server_key_exchange.has_value());
        PFL_EXPECT(
            result.records[1].handshake_messages[0].ecdhe_server_key_exchange->signature_scheme_id ==
            std::optional<std::uint16_t> {0x0601U}
        );
        PFL_EXPECT(result.final_context.negotiated_cipher_suite == std::optional<std::uint16_t> {0xC030U});
        PFL_EXPECT(result.final_context.negotiated_version == std::optional<std::uint16_t> {0x0303U});
    }

    {
        ScopedTestContext context {"synthetic=ecdhe_server_key_exchange_incomplete_and_malformed_cases"};

        const auto truncated_curve_type = parser.inspect(
            make_tls_record(0x16U, 0x0301U, make_tls_handshake_message(0x0CU, {})),
            TlsInspectionParserContext {
                .semantic_state = TlsInspectionSemanticState::plaintext,
                .negotiated_cipher_suite = 0xC014U,
                .negotiated_version = 0x0301U,
            }
        );
        PFL_EXPECT(require_parsed_ecdhe_server_key_exchange(truncated_curve_type).status == TlsStructuredBodyStatus::incomplete);

        const auto truncated_named_group = parser.inspect(
            make_tls_record(0x16U, 0x0301U, make_tls_handshake_message(0x0CU, {0x03U, 0x00U})),
            TlsInspectionParserContext {
                .semantic_state = TlsInspectionSemanticState::plaintext,
                .negotiated_cipher_suite = 0xC014U,
                .negotiated_version = 0x0301U,
            }
        );
        PFL_EXPECT(require_parsed_ecdhe_server_key_exchange(truncated_named_group).status == TlsStructuredBodyStatus::incomplete);

        const auto truncated_point_length = parser.inspect(
            make_tls_record(0x16U, 0x0301U, make_tls_handshake_message(0x0CU, {0x03U, 0x00U, 0x17U})),
            TlsInspectionParserContext {
                .semantic_state = TlsInspectionSemanticState::plaintext,
                .negotiated_cipher_suite = 0xC014U,
                .negotiated_version = 0x0301U,
            }
        );
        PFL_EXPECT(require_parsed_ecdhe_server_key_exchange(truncated_point_length).status == TlsStructuredBodyStatus::incomplete);

        auto short_point_body = make_ecdhe_server_key_exchange_body_tls10_or_tls11(0x0017U, 65U, 256U);
        short_point_body.resize(4U + 64U);
        const auto short_point = parser.inspect(
            make_tls_record(0x16U, 0x0301U, make_tls_handshake_message(0x0CU, short_point_body)),
            TlsInspectionParserContext {
                .semantic_state = TlsInspectionSemanticState::plaintext,
                .negotiated_cipher_suite = 0xC014U,
                .negotiated_version = 0x0301U,
            }
        );
        const auto& short_point_model = require_parsed_ecdhe_server_key_exchange(short_point);
        PFL_EXPECT(short_point_model.declared_public_key_length == std::optional<std::size_t> {65U});
        PFL_EXPECT(short_point_model.available_public_key_length == 64U);
        PFL_EXPECT(!short_point_model.public_key_complete);
        PFL_EXPECT(short_point_model.status == TlsStructuredBodyStatus::incomplete);

        auto truncated_signature_length_body = make_ecdhe_server_key_exchange_body_tls10_or_tls11(0x0017U, 65U, 256U);
        truncated_signature_length_body.resize(4U + 65U + 1U);
        const auto truncated_signature_length = parser.inspect(
            make_tls_record(0x16U, 0x0301U, make_tls_handshake_message(0x0CU, truncated_signature_length_body)),
            TlsInspectionParserContext {
                .semantic_state = TlsInspectionSemanticState::plaintext,
                .negotiated_cipher_suite = 0xC014U,
                .negotiated_version = 0x0301U,
            }
        );
        PFL_EXPECT(
            require_parsed_ecdhe_server_key_exchange(truncated_signature_length).status ==
            TlsStructuredBodyStatus::incomplete
        );

        auto short_signature_body = make_ecdhe_server_key_exchange_body_tls10_or_tls11(0x0017U, 65U, 256U);
        short_signature_body.resize(4U + 65U + 2U + 255U);
        const auto short_signature = parser.inspect(
            make_tls_record(0x16U, 0x0301U, make_tls_handshake_message(0x0CU, short_signature_body)),
            TlsInspectionParserContext {
                .semantic_state = TlsInspectionSemanticState::plaintext,
                .negotiated_cipher_suite = 0xC014U,
                .negotiated_version = 0x0301U,
            }
        );
        const auto& short_signature_model = require_parsed_ecdhe_server_key_exchange(short_signature);
        PFL_EXPECT(short_signature_model.declared_signature_length == std::optional<std::size_t> {256U});
        PFL_EXPECT(short_signature_model.available_signature_length == 255U);
        PFL_EXPECT(!short_signature_model.signature_complete);
        PFL_EXPECT(short_signature_model.status == TlsStructuredBodyStatus::incomplete);

        const auto unknown_group = parser.inspect(
            make_tls_record(
                0x16U,
                0x0301U,
                make_tls_handshake_message(
                    0x0CU,
                    make_ecdhe_server_key_exchange_body_tls10_or_tls11(0xBEEFU, 65U, 256U)
                )
            ),
            TlsInspectionParserContext {
                .semantic_state = TlsInspectionSemanticState::plaintext,
                .negotiated_cipher_suite = 0xC014U,
                .negotiated_version = 0x0301U,
            }
        );
        PFL_EXPECT(
            require_parsed_ecdhe_server_key_exchange(unknown_group).named_group_id ==
            std::optional<std::uint16_t> {0xBEEFU}
        );

        auto trailing_bytes_body = make_ecdhe_server_key_exchange_body_tls10_or_tls11(0x0017U, 65U, 256U);
        trailing_bytes_body.push_back(0xAAU);
        const auto trailing_bytes = parser.inspect(
            make_tls_record(0x16U, 0x0301U, make_tls_handshake_message(0x0CU, trailing_bytes_body)),
            TlsInspectionParserContext {
                .semantic_state = TlsInspectionSemanticState::plaintext,
                .negotiated_cipher_suite = 0xC014U,
                .negotiated_version = 0x0301U,
            }
        );
        PFL_EXPECT(require_parsed_ecdhe_server_key_exchange(trailing_bytes).status == TlsStructuredBodyStatus::malformed);

        auto truncated_signature_scheme_body = make_ecdhe_server_key_exchange_body_tls12(0x0017U, 65U, 0x0601U, 256U);
        truncated_signature_scheme_body.resize(4U + 65U + 1U);
        const auto truncated_signature_scheme = parser.inspect(
            make_tls_record(0x16U, 0x0303U, make_tls_handshake_message(0x0CU, truncated_signature_scheme_body)),
            TlsInspectionParserContext {
                .semantic_state = TlsInspectionSemanticState::plaintext,
                .negotiated_cipher_suite = 0xC030U,
                .negotiated_version = 0x0303U,
            }
        );
        PFL_EXPECT(
            require_parsed_ecdhe_server_key_exchange(truncated_signature_scheme).status ==
            TlsStructuredBodyStatus::incomplete
        );

        const auto unknown_signature_scheme = parser.inspect(
            make_tls_record(
                0x16U,
                0x0303U,
                make_tls_handshake_message(
                    0x0CU,
                    make_ecdhe_server_key_exchange_body_tls12(0x0017U, 65U, 0xBEEFU, 256U)
                )
            ),
            TlsInspectionParserContext {
                .semantic_state = TlsInspectionSemanticState::plaintext,
                .negotiated_cipher_suite = 0xC030U,
                .negotiated_version = 0x0303U,
            }
        );
        PFL_EXPECT(
            require_parsed_ecdhe_server_key_exchange(unknown_signature_scheme).signature_scheme_id ==
            std::optional<std::uint16_t> {0xBEEFU}
        );
    }

    {
        ScopedTestContext context {"synthetic=ecdhe_server_key_exchange_context_gating_and_isolation"};
        const auto body = make_ecdhe_server_key_exchange_body_tls12(0x0017U, 65U, 0x0601U, 256U);
        const auto record = make_tls_record(0x16U, 0x0303U, make_tls_handshake_message(0x0CU, body));

        const auto without_context = parser.inspect(record);
        const auto& generic_handshake = require_single_handshake(without_context);
        PFL_EXPECT(generic_handshake.kind == TlsHandshakeKind::server_key_exchange);
        PFL_EXPECT(generic_handshake.structured_parse_status == TlsStructuredParseStatus::not_attempted);
        PFL_EXPECT(!generic_handshake.ecdhe_server_key_exchange.has_value());

        const auto non_ecdhe_context = parser.inspect(
            record,
            TlsInspectionParserContext {
                .semantic_state = TlsInspectionSemanticState::plaintext,
                .negotiated_cipher_suite = 0x0035U,
            }
        );
        const auto& non_ecdhe_handshake = require_single_handshake(non_ecdhe_context);
        PFL_EXPECT(non_ecdhe_handshake.structured_parse_status == TlsStructuredParseStatus::not_attempted);
        PFL_EXPECT(!non_ecdhe_handshake.ecdhe_server_key_exchange.has_value());

        const auto ecdhe_context = parser.inspect(
            record,
            TlsInspectionParserContext {
                .semantic_state = TlsInspectionSemanticState::plaintext,
                .negotiated_cipher_suite = 0xC030U,
                .negotiated_version = 0x0303U,
            }
        );
        PFL_EXPECT(require_parsed_ecdhe_server_key_exchange(ecdhe_context).status == TlsStructuredBodyStatus::complete);

        const auto unknown_version_context = parser.inspect(
            record,
            TlsInspectionParserContext {
                .semantic_state = TlsInspectionSemanticState::plaintext,
                .negotiated_cipher_suite = 0xC030U,
                .negotiated_version = 0x7A7AU,
            }
        );
        const auto& unknown_version_handshake = require_single_handshake(unknown_version_context);
        PFL_EXPECT(unknown_version_handshake.structured_parse_status == TlsStructuredParseStatus::not_attempted);
        PFL_EXPECT(!unknown_version_handshake.ecdhe_server_key_exchange.has_value());

        const auto repeated_without_context = parser.inspect(record);
        const auto& repeated_generic_handshake = require_single_handshake(repeated_without_context);
        PFL_EXPECT(repeated_generic_handshake.structured_parse_status == TlsStructuredParseStatus::not_attempted);
        PFL_EXPECT(!repeated_generic_handshake.ecdhe_server_key_exchange.has_value());
    }

    {
        ScopedTestContext context {"synthetic=ecdhe_client_key_exchange_cases"};
        const auto complete = parser.inspect(
            make_tls_record(
                0x16U,
                0x0303U,
                make_tls_handshake_message(0x10U, make_ecdhe_client_key_exchange_body(65U))
            ),
            TlsInspectionParserContext {
                .semantic_state = TlsInspectionSemanticState::plaintext,
                .negotiated_cipher_suite = 0xC030U,
            }
        );
        const auto& complete_model = require_parsed_ecdhe_client_key_exchange(complete);
        PFL_EXPECT(complete_model.declared_public_key_length == std::optional<std::size_t> {65U});
        PFL_EXPECT(complete_model.available_public_key_length == 65U);
        PFL_EXPECT(complete_model.public_key_complete);
        PFL_EXPECT(complete_model.status == TlsStructuredBodyStatus::complete);

        const auto zero_length = parser.inspect(
            make_tls_record(0x16U, 0x0303U, make_tls_handshake_message(0x10U, {0x00U})),
            TlsInspectionParserContext {
                .semantic_state = TlsInspectionSemanticState::plaintext,
                .negotiated_cipher_suite = 0xC030U,
            }
        );
        PFL_EXPECT(require_parsed_ecdhe_client_key_exchange(zero_length).status == TlsStructuredBodyStatus::malformed);

        const auto truncated_length = parser.inspect(
            make_tls_record(0x16U, 0x0303U, make_tls_handshake_message(0x10U, {})),
            TlsInspectionParserContext {
                .semantic_state = TlsInspectionSemanticState::plaintext,
                .negotiated_cipher_suite = 0xC030U,
            }
        );
        PFL_EXPECT(require_parsed_ecdhe_client_key_exchange(truncated_length).status == TlsStructuredBodyStatus::incomplete);

        auto short_point = make_ecdhe_client_key_exchange_body(65U);
        short_point.resize(65U);
        const auto truncated_point = parser.inspect(
            make_tls_record(0x16U, 0x0303U, make_tls_handshake_message(0x10U, short_point)),
            TlsInspectionParserContext {
                .semantic_state = TlsInspectionSemanticState::plaintext,
                .negotiated_cipher_suite = 0xC030U,
            }
        );
        const auto& truncated_point_model = require_parsed_ecdhe_client_key_exchange(truncated_point);
        PFL_EXPECT(truncated_point_model.declared_public_key_length == std::optional<std::size_t> {65U});
        PFL_EXPECT(truncated_point_model.available_public_key_length == 64U);
        PFL_EXPECT(!truncated_point_model.public_key_complete);
        PFL_EXPECT(truncated_point_model.status == TlsStructuredBodyStatus::incomplete);

        auto trailing_bytes = make_ecdhe_client_key_exchange_body(65U);
        trailing_bytes.push_back(0xAAU);
        const auto malformed_trailing = parser.inspect(
            make_tls_record(0x16U, 0x0303U, make_tls_handshake_message(0x10U, trailing_bytes)),
            TlsInspectionParserContext {
                .semantic_state = TlsInspectionSemanticState::plaintext,
                .negotiated_cipher_suite = 0xC030U,
            }
        );
        PFL_EXPECT(require_parsed_ecdhe_client_key_exchange(malformed_trailing).status == TlsStructuredBodyStatus::malformed);

        const auto without_context = parser.inspect(
            make_tls_record(0x16U, 0x0303U, make_tls_handshake_message(0x10U, make_ecdhe_client_key_exchange_body(65U)))
        );
        const auto& generic_handshake = require_single_handshake(without_context);
        PFL_EXPECT(generic_handshake.kind == TlsHandshakeKind::client_key_exchange);
        PFL_EXPECT(generic_handshake.structured_parse_status == TlsStructuredParseStatus::not_attempted);
        PFL_EXPECT(!generic_handshake.ecdhe_client_key_exchange.has_value());

        const auto non_ecdhe_context = parser.inspect(
            make_tls_record(0x16U, 0x0303U, make_tls_handshake_message(0x10U, make_ecdhe_client_key_exchange_body(65U))),
            TlsInspectionParserContext {
                .semantic_state = TlsInspectionSemanticState::plaintext,
                .negotiated_cipher_suite = 0x0035U,
            }
        );
        const auto& non_ecdhe_handshake = require_single_handshake(non_ecdhe_context);
        PFL_EXPECT(non_ecdhe_handshake.structured_parse_status == TlsStructuredParseStatus::not_attempted);
        PFL_EXPECT(!non_ecdhe_handshake.ecdhe_client_key_exchange.has_value());
    }

    {
        const std::vector<const char*> baseline_alert_fixtures {
            "parsing/tls/tls_1_0_badssl_baseline_12.pcap",
            "parsing/tls/tls_1_1_badssl_baseline_13.pcap",
            "parsing/tls/tls_1_2_badssl_baseline_14.pcap",
        };

        for (const auto* relative_path : baseline_alert_fixtures) {
            ScopedTestContext context {std::string {"fixture="} + relative_path + " | encrypted_alert"};
            const auto payload = require_tls_fixture_transport_payload_matching_record(
                relative_path,
                [](const TlsInspectionResult& result) {
                    return result.records.size() == 1U &&
                        result.records[0].status == TlsRecordStatus::complete &&
                        result.records[0].content_type_kind == TlsRecordContentTypeKind::alert;
                }
            );
            const auto result = parser.inspect(payload, TlsInspectionSemanticState::post_change_cipher_spec);
            PFL_REQUIRE(result.records.size() == 1U);
            PFL_EXPECT(result.records[0].content_type_kind == TlsRecordContentTypeKind::alert);
            PFL_EXPECT(result.records[0].alert_payload_kind == TlsAlertPayloadKind::encrypted_opaque);
            PFL_EXPECT(result.records[0].alert_parse_status == TlsAlertParseStatus::not_attempted);
            PFL_EXPECT(result.records[0].alert_entries.empty());
        }
    }

    {
        ScopedTestContext context {"synthetic | alert_initial_semantic_state"};
        const auto alert_record = make_tls_record(0x15U, 0x0303U, {0x02U, 0x30U});

        const auto plaintext_result = parser.inspect(alert_record, TlsInspectionSemanticState::plaintext);
        PFL_REQUIRE(plaintext_result.records.size() == 1U);
        PFL_EXPECT(plaintext_result.records[0].alert_payload_kind == TlsAlertPayloadKind::plaintext);
        PFL_EXPECT(plaintext_result.records[0].alert_parse_status == TlsAlertParseStatus::parsed);
        PFL_REQUIRE(plaintext_result.records[0].alert_entries.size() == 1U);
        expect_tls_alert_entry(plaintext_result.records[0].alert_entries[0], 2U, 48U);

        const auto encrypted_result = parser.inspect(
            alert_record,
            TlsInspectionSemanticState::post_change_cipher_spec
        );
        PFL_REQUIRE(encrypted_result.records.size() == 1U);
        PFL_EXPECT(encrypted_result.records[0].alert_payload_kind == TlsAlertPayloadKind::encrypted_opaque);
        PFL_EXPECT(encrypted_result.records[0].alert_parse_status == TlsAlertParseStatus::not_attempted);
        PFL_EXPECT(encrypted_result.records[0].alert_entries.empty());

        const auto unknown_result = parser.inspect(alert_record, TlsInspectionSemanticState::unknown);
        PFL_REQUIRE(unknown_result.records.size() == 1U);
        PFL_EXPECT(unknown_result.records[0].alert_payload_kind == TlsAlertPayloadKind::encrypted_opaque);
        PFL_EXPECT(unknown_result.records[0].alert_parse_status == TlsAlertParseStatus::not_attempted);
        PFL_EXPECT(unknown_result.records[0].alert_entries.empty());

        const auto plaintext_repeat = parser.inspect(alert_record, TlsInspectionSemanticState::plaintext);
        PFL_REQUIRE(plaintext_repeat.records.size() == 1U);
        PFL_EXPECT(plaintext_repeat.records[0].alert_payload_kind == TlsAlertPayloadKind::plaintext);
        PFL_EXPECT(plaintext_repeat.records[0].alert_parse_status == TlsAlertParseStatus::parsed);
        PFL_REQUIRE(plaintext_repeat.records[0].alert_entries.size() == 1U);
        expect_tls_alert_entry(plaintext_repeat.records[0].alert_entries[0], 2U, 48U);
    }

    {
        ScopedTestContext context {"synthetic | same_packet_ccs_then_alert"};
        std::vector<std::uint8_t> payload = make_tls_record(0x14U, 0x0303U, {0x01U});
        const auto alert_record = make_tls_record(0x15U, 0x0303U, {0x02U, 0x30U});
        payload.insert(payload.end(), alert_record.begin(), alert_record.end());

        const auto result = parser.inspect(payload, TlsInspectionSemanticState::plaintext);
        PFL_REQUIRE(result.records.size() == 2U);
        PFL_EXPECT(result.records[0].content_type_kind == TlsRecordContentTypeKind::change_cipher_spec);
        PFL_EXPECT(result.records[1].content_type_kind == TlsRecordContentTypeKind::alert);
        PFL_EXPECT(result.records[1].alert_payload_kind == TlsAlertPayloadKind::encrypted_opaque);
        PFL_EXPECT(result.records[1].alert_parse_status == TlsAlertParseStatus::not_attempted);
        PFL_EXPECT(result.records[1].alert_entries.empty());
    }

    {
        ScopedTestContext context {"fixture=parsing/tls/tls_1_2_self_signed_unknown_ca_17.pcap | packet=6"};
        const auto payload = require_tls_fixture_transport_payload(
            "parsing/tls/tls_1_2_self_signed_unknown_ca_17.pcap",
            5U
        );
        const auto result = parser.inspect(payload);
        PFL_EXPECT(result.total_input_bytes == 1325U);
        PFL_EXPECT(result.consumed_bytes == 1325U);
        PFL_REQUIRE(result.records.size() == 4U);
        PFL_EXPECT(result.records[0].content_type_kind == TlsRecordContentTypeKind::handshake);
        PFL_EXPECT(result.records[0].handshake_messages.size() == 1U);
        PFL_EXPECT(result.records[0].handshake_messages[0].kind == TlsHandshakeKind::server_hello);

        const auto& certificate_record = result.records[1];
        PFL_EXPECT(certificate_record.status == TlsRecordStatus::complete);
        PFL_EXPECT(certificate_record.content_type_kind == TlsRecordContentTypeKind::handshake);
        PFL_EXPECT(certificate_record.declared_payload_length == std::optional<std::size_t> {903U});
        PFL_REQUIRE(certificate_record.handshake_messages.size() == 1U);
        PFL_EXPECT(certificate_record.handshake_messages[0].kind == TlsHandshakeKind::certificate);
        PFL_EXPECT(certificate_record.handshake_messages[0].declared_body_length == std::optional<std::size_t> {899U});
        PFL_EXPECT(certificate_record.handshake_messages[0].structured_parse_status == TlsStructuredParseStatus::parsed);
        PFL_REQUIRE(certificate_record.handshake_messages[0].certificate.has_value());
        const auto& certificate = *certificate_record.handshake_messages[0].certificate;
        PFL_EXPECT(certificate.declared_certificate_list_length == 896U);
        PFL_EXPECT(certificate.complete_certificate_list);
        PFL_EXPECT(certificate.certificate_entries.size() == 1U);
        PFL_EXPECT(collect_certificate_entry_lengths(certificate) == std::vector<std::size_t> {893U});
        PFL_EXPECT(certificate.certificate_entries[0].available_der_length == 893U);
        PFL_EXPECT(certificate.certificate_entries[0].complete);
        PFL_EXPECT(result.records[2].handshake_messages.size() == 1U);
        PFL_EXPECT(result.records[2].handshake_messages[0].kind == TlsHandshakeKind::server_key_exchange);
        PFL_EXPECT(result.records[3].handshake_messages.size() == 1U);
        PFL_EXPECT(result.records[3].handshake_messages[0].kind == TlsHandshakeKind::server_hello_done);
    }

    {
        ScopedTestContext context {"fixture=parsing/tls/tls_1_2_client_certificate_missing_18.pcap | packet=11"};
        const auto payload = require_tls_fixture_transport_payload(
            "parsing/tls/tls_1_2_client_certificate_missing_18.pcap",
            10U
        );
        const auto result = parser.inspect(payload);
        PFL_EXPECT(result.total_input_bytes == 399U);
        PFL_EXPECT(result.consumed_bytes == 399U);
        PFL_REQUIRE(result.records.size() == 1U);
        PFL_EXPECT(result.records[0].status == TlsRecordStatus::partial_body);
        PFL_EXPECT(result.records[0].content_type_kind == TlsRecordContentTypeKind::unknown);
        PFL_EXPECT(result.records[0].handshake_payload_kind == TlsHandshakePayloadKind::none);
        PFL_EXPECT(result.records[0].declared_payload_length == std::optional<std::size_t> {11350U});
        PFL_EXPECT(result.records[0].handshake_messages.empty());
    }

    {
        ScopedTestContext context {"fixture=parsing/tls/tls_1_2_client_certificate_missing_18.pcap | packet=13"};
        const auto payload = require_tls_fixture_transport_payload(
            "parsing/tls/tls_1_2_client_certificate_missing_18.pcap",
            12U
        );
        const auto result = parser.inspect(payload);
        PFL_EXPECT(result.total_input_bytes == 138U);
        PFL_EXPECT(result.consumed_bytes == 138U);
        PFL_REQUIRE(result.records.size() == 4U);

        PFL_EXPECT(result.records[0].status == TlsRecordStatus::complete);
        PFL_EXPECT(result.records[0].content_type_kind == TlsRecordContentTypeKind::handshake);
        PFL_EXPECT(result.records[0].declared_payload_length == std::optional<std::size_t> {7U});
        PFL_REQUIRE(result.records[0].handshake_messages.size() == 1U);
        PFL_EXPECT(result.records[0].handshake_messages[0].kind == TlsHandshakeKind::certificate);
        PFL_EXPECT(result.records[0].handshake_messages[0].declared_body_length == std::optional<std::size_t> {3U});
        PFL_EXPECT(result.records[0].handshake_messages[0].structured_parse_status == TlsStructuredParseStatus::parsed);
        PFL_REQUIRE(result.records[0].handshake_messages[0].certificate.has_value());
        PFL_EXPECT(result.records[0].handshake_messages[0].certificate->declared_certificate_list_length == 0U);
        PFL_EXPECT(result.records[0].handshake_messages[0].certificate->complete_certificate_list);
        PFL_EXPECT(result.records[0].handshake_messages[0].certificate->certificate_entries.empty());

        PFL_EXPECT(result.records[1].status == TlsRecordStatus::complete);
        PFL_EXPECT(result.records[1].content_type_kind == TlsRecordContentTypeKind::handshake);
        PFL_EXPECT(result.records[1].declared_payload_length == std::optional<std::size_t> {70U});
        PFL_REQUIRE(result.records[1].handshake_messages.size() == 1U);
        PFL_EXPECT(result.records[1].handshake_messages[0].kind == TlsHandshakeKind::client_key_exchange);
        PFL_EXPECT(result.records[1].handshake_messages[0].declared_body_length == std::optional<std::size_t> {66U});

        PFL_EXPECT(result.records[2].status == TlsRecordStatus::complete);
        PFL_EXPECT(result.records[2].content_type_kind == TlsRecordContentTypeKind::change_cipher_spec);
        PFL_EXPECT(result.records[2].declared_payload_length == std::optional<std::size_t> {1U});

        PFL_EXPECT(result.records[3].status == TlsRecordStatus::complete);
        PFL_EXPECT(result.records[3].content_type_kind == TlsRecordContentTypeKind::handshake);
        PFL_EXPECT(result.records[3].declared_payload_length == std::optional<std::size_t> {40U});
        PFL_EXPECT(result.records[3].handshake_payload_kind == TlsHandshakePayloadKind::encrypted_opaque);
        PFL_EXPECT(result.records[3].handshake_messages.empty());
    }

    {
        struct ClientKeyExchangeFixtureExpectation {
            const char* relative_path;
            std::uint64_t packet_index;
            std::uint16_t negotiated_cipher_suite;
            std::size_t expected_record_count;
            std::size_t client_key_exchange_record_index;
        };

        const std::vector<ClientKeyExchangeFixtureExpectation> expectations {
            {
                .relative_path = "parsing/tls/tls_1_0_badssl_baseline_12.pcap",
                .packet_index = 13U,
                .negotiated_cipher_suite = 0xC014U,
                .expected_record_count = 3U,
                .client_key_exchange_record_index = 0U,
            },
            {
                .relative_path = "parsing/tls/tls_1_1_badssl_baseline_13.pcap",
                .packet_index = 13U,
                .negotiated_cipher_suite = 0xC014U,
                .expected_record_count = 3U,
                .client_key_exchange_record_index = 0U,
            },
            {
                .relative_path = "parsing/tls/tls_1_2_badssl_baseline_14.pcap",
                .packet_index = 13U,
                .negotiated_cipher_suite = 0xC030U,
                .expected_record_count = 3U,
                .client_key_exchange_record_index = 0U,
            },
            {
                .relative_path = "parsing/tls/tls_1_2_client_certificate_missing_18.pcap",
                .packet_index = 12U,
                .negotiated_cipher_suite = 0xC030U,
                .expected_record_count = 4U,
                .client_key_exchange_record_index = 1U,
            },
        };

        for (const auto& expectation : expectations) {
            ScopedTestContext context {
                std::string {"fixture="} + expectation.relative_path +
                " | packet=" + std::to_string(expectation.packet_index + 1U) +
                " | ecdhe_client_key_exchange"
            };
            const auto payload = require_tls_fixture_transport_payload(expectation.relative_path, expectation.packet_index);
            const auto result = parser.inspect(
                payload,
                TlsInspectionParserContext {
                    .semantic_state = TlsInspectionSemanticState::plaintext,
                    .negotiated_cipher_suite = expectation.negotiated_cipher_suite,
                }
            );

            PFL_REQUIRE(result.records.size() == expectation.expected_record_count);
            PFL_REQUIRE(result.records[expectation.client_key_exchange_record_index].handshake_messages.size() == 1U);
            const auto& handshake =
                result.records[expectation.client_key_exchange_record_index].handshake_messages[0];
            PFL_EXPECT(handshake.kind == TlsHandshakeKind::client_key_exchange);
            PFL_EXPECT(handshake.status == TlsHandshakeStatus::complete);
            PFL_EXPECT(handshake.declared_body_length == std::optional<std::size_t> {66U});
            PFL_EXPECT(handshake.structured_parse_status == TlsStructuredParseStatus::parsed);
            PFL_REQUIRE(handshake.ecdhe_client_key_exchange.has_value());

            const auto& client_key_exchange = *handshake.ecdhe_client_key_exchange;
            PFL_EXPECT(client_key_exchange.declared_public_key_length == std::optional<std::size_t> {65U});
            PFL_EXPECT(client_key_exchange.available_public_key_length == 65U);
            PFL_EXPECT(client_key_exchange.public_key_complete);
            PFL_EXPECT(client_key_exchange.status == TlsStructuredBodyStatus::complete);
        }
    }

    {
        ScopedTestContext context {"synthetic=certificate_empty_list"};
        const auto result = parser.inspect(make_tls_record(
            0x16U,
            0x0303U,
            make_tls_handshake_message(0x0BU, make_tls_certificate_body({}))
        ));
        const auto& certificate = require_parsed_certificate(result);
        PFL_EXPECT(certificate.declared_certificate_list_length == 0U);
        PFL_EXPECT(certificate.complete_certificate_list);
        PFL_EXPECT(certificate.certificate_entries.empty());
    }

    {
        ScopedTestContext context {"synthetic=certificate_single_entry"};
        const auto result = parser.inspect(make_tls_record(
            0x16U,
            0x0303U,
            make_tls_handshake_message(0x0BU, make_tls_certificate_body({{0x01U, 0x02U, 0x03U, 0x04U}}))
        ));
        const auto& certificate = require_parsed_certificate(result);
        PFL_EXPECT(certificate.declared_certificate_list_length == 7U);
        PFL_EXPECT(collect_certificate_entry_lengths(certificate) == std::vector<std::size_t>({4U}));
        PFL_EXPECT(certificate.certificate_entries[0].available_der_length == 4U);
        PFL_EXPECT(certificate.certificate_entries[0].complete);
    }

    {
        ScopedTestContext context {"synthetic=certificate_multiple_entries"};
        const auto result = parser.inspect(make_tls_record(
            0x16U,
            0x0303U,
            make_tls_handshake_message(0x0BU, make_tls_certificate_body({
                {0xAAU, 0xBBU},
                {0x11U, 0x22U, 0x33U},
                {0x44U},
            }))
        ));
        const auto& certificate = require_parsed_certificate(result);
        PFL_EXPECT(certificate.declared_certificate_list_length == 15U);
        PFL_EXPECT(collect_certificate_entry_lengths(certificate) == std::vector<std::size_t>({2U, 3U, 1U}));
    }

    {
        ScopedTestContext context {"synthetic=certificate_truncated_list_length"};
        const auto result = parser.inspect(make_tls_record(
            0x16U,
            0x0303U,
            make_tls_handshake_message(0x0BU, {0x00U, 0x00U})
        ));
        const auto& handshake = require_single_handshake(result);
        PFL_EXPECT(handshake.kind == TlsHandshakeKind::certificate);
        PFL_EXPECT(handshake.structured_parse_status == TlsStructuredParseStatus::malformed);
        PFL_EXPECT(!handshake.certificate.has_value());
    }

    {
        ScopedTestContext context {"synthetic=certificate_declared_list_longer_than_body"};
        const auto result = parser.inspect(make_tls_record(
            0x16U,
            0x0303U,
            make_tls_handshake_message(0x0BU, {0x00U, 0x00U, 0x05U, 0xAAU, 0xBBU})
        ));
        const auto& handshake = require_single_handshake(result);
        PFL_EXPECT(handshake.structured_parse_status == TlsStructuredParseStatus::malformed);
        PFL_EXPECT(!handshake.certificate.has_value());
    }

    {
        ScopedTestContext context {"synthetic=certificate_truncated_entry_length"};
        const auto result = parser.inspect(make_tls_record(
            0x16U,
            0x0303U,
            make_tls_handshake_message(0x0BU, {0x00U, 0x00U, 0x03U, 0x00U, 0x00U})
        ));
        const auto& handshake = require_single_handshake(result);
        PFL_EXPECT(handshake.structured_parse_status == TlsStructuredParseStatus::malformed);
        PFL_EXPECT(!handshake.certificate.has_value());
    }

    {
        ScopedTestContext context {"synthetic=certificate_entry_exceeds_declared_list"};
        const auto result = parser.inspect(make_tls_record(
            0x16U,
            0x0303U,
            make_tls_handshake_message(0x0BU, {0x00U, 0x00U, 0x04U, 0x00U, 0x00U, 0x02U, 0xAAU})
        ));
        const auto& handshake = require_single_handshake(result);
        PFL_EXPECT(handshake.structured_parse_status == TlsStructuredParseStatus::malformed);
        PFL_EXPECT(!handshake.certificate.has_value());
    }

    {
        ScopedTestContext context {"synthetic=certificate_trailing_bytes_in_declared_list"};
        const auto result = parser.inspect(make_tls_record(
            0x16U,
            0x0303U,
            make_tls_handshake_message(0x0BU, {0x00U, 0x00U, 0x05U, 0x00U, 0x00U, 0x01U, 0xAAU, 0xBBU})
        ));
        const auto& handshake = require_single_handshake(result);
        PFL_EXPECT(handshake.structured_parse_status == TlsStructuredParseStatus::malformed);
        PFL_EXPECT(!handshake.certificate.has_value());
    }

    {
        ScopedTestContext context {"synthetic=certificate_entry_limit_enforced"};
        std::vector<std::vector<std::uint8_t>> entries {};
        entries.reserve(1025U);
        for (std::size_t index = 0U; index < 1025U; ++index) {
            entries.push_back({static_cast<std::uint8_t>(index & 0xFFU)});
        }
        const auto result = parser.inspect(make_tls_record(
            0x16U,
            0x0303U,
            make_tls_handshake_message(0x0BU, make_tls_certificate_body(entries))
        ));
        const auto& handshake = require_single_handshake(result);
        PFL_EXPECT(handshake.structured_parse_status == TlsStructuredParseStatus::malformed);
        PFL_EXPECT(!handshake.certificate.has_value());
    }

    {
        ScopedTestContext context {"synthetic=certificate_request_tls12_valid"};
        const auto result = parser.inspect(
            make_tls_record(
                0x16U,
                0x0301U,
                make_tls_handshake_message(0x0DU, make_tls12_certificate_request_body(
                    {1U, 2U, 64U},
                    {0x0401U, 0x0501U, 0x0601U},
                    {{0x30U, 0x31U}, {0x41U, 0x42U, 0x43U}}
                ))
            ),
            TlsInspectionParserContext {
                .semantic_state = TlsInspectionSemanticState::plaintext,
                .negotiated_version = 0x0303U,
            }
        );
        const auto& request = require_parsed_certificate_request(result);
        PFL_EXPECT(request.certificate_type_ids == std::vector<std::uint8_t>({1U, 2U, 64U}));
        PFL_EXPECT(request.signature_scheme_bytes_length == 6U);
        PFL_EXPECT(request.signature_scheme_ids == std::vector<std::uint16_t>({0x0401U, 0x0501U, 0x0601U}));
        PFL_EXPECT(request.certificate_authorities_bytes_length == 9U);
        PFL_EXPECT(request.complete_certificate_authorities_vector);
        PFL_EXPECT(collect_certificate_authority_lengths(request) == std::vector<std::size_t>({2U, 3U}));
    }

    {
        ScopedTestContext context {"synthetic=certificate_request_zero_types_is_malformed"};
        const auto result = parser.inspect(
            make_tls_record(
                0x16U,
                0x0303U,
                make_tls_handshake_message(0x0DU, {0x00U, 0x00U, 0x02U, 0x04U, 0x01U, 0x00U, 0x00U})
            ),
            TlsInspectionParserContext {
                .semantic_state = TlsInspectionSemanticState::plaintext,
                .negotiated_version = 0x0303U,
            }
        );
        const auto& handshake = require_single_handshake(result);
        PFL_EXPECT(handshake.structured_parse_status == TlsStructuredParseStatus::malformed);
        PFL_EXPECT(!handshake.certificate_request.has_value());
    }

    {
        ScopedTestContext context {"synthetic=certificate_request_odd_signature_scheme_vector"};
        const auto result = parser.inspect(
            make_tls_record(
                0x16U,
                0x0303U,
                make_tls_handshake_message(0x0DU, {0x01U, 0x01U, 0x00U, 0x03U, 0x04U, 0x01U, 0x02U, 0x00U, 0x00U})
            ),
            TlsInspectionParserContext {
                .semantic_state = TlsInspectionSemanticState::plaintext,
                .negotiated_version = 0x0303U,
            }
        );
        const auto& handshake = require_single_handshake(result);
        PFL_EXPECT(handshake.structured_parse_status == TlsStructuredParseStatus::malformed);
        PFL_EXPECT(!handshake.certificate_request.has_value());
    }

    {
        ScopedTestContext context {"synthetic=certificate_request_truncated_signature_scheme_vector"};
        const auto result = parser.inspect(
            make_tls_record(
                0x16U,
                0x0303U,
                make_tls_handshake_message(0x0DU, {0x01U, 0x01U, 0x00U, 0x04U, 0x04U, 0x01U, 0x00U, 0x00U})
            ),
            TlsInspectionParserContext {
                .semantic_state = TlsInspectionSemanticState::plaintext,
                .negotiated_version = 0x0303U,
            }
        );
        const auto& handshake = require_single_handshake(result);
        PFL_EXPECT(handshake.structured_parse_status == TlsStructuredParseStatus::malformed);
        PFL_EXPECT(!handshake.certificate_request.has_value());
    }

    {
        ScopedTestContext context {"synthetic=certificate_request_zero_authorities_is_valid"};
        const auto result = parser.inspect(
            make_tls_record(
                0x16U,
                0x0303U,
                make_tls_handshake_message(0x0DU, make_tls12_certificate_request_body(
                    {1U},
                    {0x0401U},
                    {}
                ))
            ),
            TlsInspectionParserContext {
                .semantic_state = TlsInspectionSemanticState::plaintext,
                .negotiated_version = 0x0303U,
            }
        );
        const auto& request = require_parsed_certificate_request(result);
        PFL_EXPECT(request.certificate_authorities_bytes_length == 0U);
        PFL_EXPECT(request.complete_certificate_authorities_vector);
        PFL_EXPECT(request.certificate_authority_entries.empty());
    }

    {
        ScopedTestContext context {"synthetic=certificate_request_truncated_authority_length"};
        const auto result = parser.inspect(
            make_tls_record(
                0x16U,
                0x0303U,
                make_tls_handshake_message(0x0DU, {0x01U, 0x01U, 0x00U, 0x02U, 0x04U, 0x01U, 0x00U, 0x01U, 0x00U})
            ),
            TlsInspectionParserContext {
                .semantic_state = TlsInspectionSemanticState::plaintext,
                .negotiated_version = 0x0303U,
            }
        );
        const auto& handshake = require_single_handshake(result);
        PFL_EXPECT(handshake.structured_parse_status == TlsStructuredParseStatus::malformed);
        PFL_EXPECT(!handshake.certificate_request.has_value());
    }

    {
        ScopedTestContext context {"synthetic=certificate_request_authority_exceeds_declared_vector"};
        const auto result = parser.inspect(
            make_tls_record(
                0x16U,
                0x0303U,
                make_tls_handshake_message(0x0DU, {0x01U, 0x01U, 0x00U, 0x02U, 0x04U, 0x01U, 0x00U, 0x03U, 0x00U, 0x02U, 0xAAU})
            ),
            TlsInspectionParserContext {
                .semantic_state = TlsInspectionSemanticState::plaintext,
                .negotiated_version = 0x0303U,
            }
        );
        const auto& handshake = require_single_handshake(result);
        PFL_EXPECT(handshake.structured_parse_status == TlsStructuredParseStatus::malformed);
        PFL_EXPECT(!handshake.certificate_request.has_value());
    }

    {
        ScopedTestContext context {"synthetic=certificate_request_trailing_bytes_after_authorities"};
        const auto result = parser.inspect(
            make_tls_record(
                0x16U,
                0x0303U,
                make_tls_handshake_message(0x0DU, {0x01U, 0x01U, 0x00U, 0x02U, 0x04U, 0x01U, 0x00U, 0x02U, 0x00U, 0x00U, 0xFFU})
            ),
            TlsInspectionParserContext {
                .semantic_state = TlsInspectionSemanticState::plaintext,
                .negotiated_version = 0x0303U,
            }
        );
        const auto& handshake = require_single_handshake(result);
        PFL_EXPECT(handshake.structured_parse_status == TlsStructuredParseStatus::malformed);
        PFL_EXPECT(!handshake.certificate_request.has_value());
    }

    {
        ScopedTestContext context {"synthetic=certificate_request_tls11_not_attempted"};
        const auto result = parser.inspect(
            make_tls_record(
                0x16U,
                0x0303U,
                make_tls_handshake_message(0x0DU, make_tls12_certificate_request_body(
                    {1U},
                    {0x0401U},
                    {}
                ))
            ),
            TlsInspectionParserContext {
                .semantic_state = TlsInspectionSemanticState::plaintext,
                .negotiated_version = 0x0302U,
            }
        );
        const auto& handshake = require_single_handshake(result);
        PFL_EXPECT(handshake.kind == TlsHandshakeKind::certificate_request);
        PFL_EXPECT(handshake.status == TlsHandshakeStatus::complete);
        PFL_EXPECT(handshake.structured_parse_status == TlsStructuredParseStatus::not_attempted);
        PFL_EXPECT(!handshake.certificate_request.has_value());
    }

    {
        ScopedTestContext context {"synthetic=certificate_request_unknown_negotiated_version_not_attempted"};
        const auto result = parser.inspect(
            make_tls_record(
                0x16U,
                0x0303U,
                make_tls_handshake_message(0x0DU, make_tls12_certificate_request_body(
                    {1U},
                    {0x0401U},
                    {}
                ))
            ),
            TlsInspectionParserContext {
                .semantic_state = TlsInspectionSemanticState::plaintext,
                .negotiated_version = 0x7A7AU,
            }
        );
        const auto& handshake = require_single_handshake(result);
        PFL_EXPECT(handshake.kind == TlsHandshakeKind::certificate_request);
        PFL_EXPECT(handshake.status == TlsHandshakeStatus::complete);
        PFL_EXPECT(handshake.structured_parse_status == TlsStructuredParseStatus::not_attempted);
        PFL_EXPECT(!handshake.certificate_request.has_value());
    }

    {
        ScopedTestContext context {"synthetic=server_hello_establishes_negotiated_version_for_following_certificate_request"};
        auto bytes = make_tls_record(
            0x16U,
            0x0301U,
            make_tls_handshake_message(
                0x02U,
                make_minimal_server_hello_body_with_cipher_suite(0x0303U, 0xC030U)
            )
        );
        const auto certificate_request_record = make_tls_record(
            0x16U,
            0x0301U,
            make_tls_handshake_message(0x0DU, make_tls12_certificate_request_body(
                {1U},
                {0x0401U},
                {}
            ))
        );
        bytes.insert(bytes.end(), certificate_request_record.begin(), certificate_request_record.end());

        const auto result = parser.inspect(bytes);
        PFL_EXPECT(result.records.size() == 2U);
        PFL_REQUIRE(result.records[1].handshake_messages.size() == 1U);
        const auto& certificate_request_handshake = result.records[1].handshake_messages[0];
        PFL_EXPECT(certificate_request_handshake.kind == TlsHandshakeKind::certificate_request);
        PFL_EXPECT(certificate_request_handshake.structured_parse_status == TlsStructuredParseStatus::parsed);
        PFL_REQUIRE(certificate_request_handshake.certificate_request.has_value());
        PFL_EXPECT(result.final_context.negotiated_version == std::optional<std::uint16_t> {0x0303U});
    }

    {
        ScopedTestContext context {"synthetic=new_session_ticket_zero_length_ticket"};
        std::vector<std::uint8_t> body {};
        append_be32(body, 0U);
        append_be16(body, 0U);
        const auto result = parser.inspect(make_tls_record(0x16U, 0x0303U, make_tls_handshake_message(0x04U, body)));
        const auto& new_session_ticket = require_parsed_new_session_ticket(result);
        PFL_EXPECT(new_session_ticket.ticket_lifetime_hint_seconds == 0U);
        PFL_EXPECT(new_session_ticket.ticket_length == 0U);
    }

    {
        ScopedTestContext context {"synthetic=new_session_ticket_short_ticket"};
        std::vector<std::uint8_t> body {};
        append_be32(body, 42U);
        append_be16(body, 3U);
        body.insert(body.end(), {0xAAU, 0xBBU, 0xCCU});
        const auto result = parser.inspect(make_tls_record(0x16U, 0x0303U, make_tls_handshake_message(0x04U, body)));
        const auto& new_session_ticket = require_parsed_new_session_ticket(result);
        PFL_EXPECT(new_session_ticket.ticket_lifetime_hint_seconds == 42U);
        PFL_EXPECT(new_session_ticket.ticket_length == 3U);
    }

    {
        ScopedTestContext context {"synthetic=new_session_ticket_unknown_ticket_bytes_do_not_affect_parsing"};
        std::vector<std::uint8_t> body {};
        append_be32(body, 1234U);
        append_be16(body, 4U);
        body.insert(body.end(), {0x00U, 0xFFU, 0x5AU, 0xA5U});
        const auto result = parser.inspect(make_tls_record(0x16U, 0x0303U, make_tls_handshake_message(0x04U, body)));
        const auto& new_session_ticket = require_parsed_new_session_ticket(result);
        PFL_EXPECT(new_session_ticket.ticket_lifetime_hint_seconds == 1234U);
        PFL_EXPECT(new_session_ticket.ticket_length == 4U);
    }

    {
        ScopedTestContext context {"synthetic=new_session_ticket_fixed_header_truncated"};
        std::vector<std::uint8_t> body {};
        append_be32(body, 1234U);
        body.push_back(0x00U);
        const auto result = parser.inspect(make_tls_record(0x16U, 0x0303U, make_tls_handshake_message(0x04U, body)));
        const auto& handshake = require_single_handshake(result);
        PFL_EXPECT(handshake.status == TlsHandshakeStatus::complete);
        PFL_EXPECT(handshake.kind == TlsHandshakeKind::new_session_ticket);
        PFL_EXPECT(handshake.structured_parse_status == TlsStructuredParseStatus::malformed);
        PFL_EXPECT(!handshake.new_session_ticket.has_value());
    }

    {
        ScopedTestContext context {"synthetic=new_session_ticket_declared_ticket_length_exceeds_body"};
        std::vector<std::uint8_t> body {};
        append_be32(body, 99U);
        append_be16(body, 4U);
        body.insert(body.end(), {0xAAU, 0xBBU, 0xCCU});
        const auto result = parser.inspect(make_tls_record(0x16U, 0x0303U, make_tls_handshake_message(0x04U, body)));
        const auto& handshake = require_single_handshake(result);
        PFL_EXPECT(handshake.status == TlsHandshakeStatus::complete);
        PFL_EXPECT(handshake.kind == TlsHandshakeKind::new_session_ticket);
        PFL_EXPECT(handshake.structured_parse_status == TlsStructuredParseStatus::malformed);
        PFL_EXPECT(!handshake.new_session_ticket.has_value());
    }

    {
        ScopedTestContext context {"synthetic=new_session_ticket_trailing_garbage_after_ticket"};
        std::vector<std::uint8_t> body {};
        append_be32(body, 99U);
        append_be16(body, 2U);
        body.insert(body.end(), {0xAAU, 0xBBU, 0xCCU});
        const auto result = parser.inspect(make_tls_record(0x16U, 0x0303U, make_tls_handshake_message(0x04U, body)));
        const auto& handshake = require_single_handshake(result);
        PFL_EXPECT(handshake.status == TlsHandshakeStatus::complete);
        PFL_EXPECT(handshake.kind == TlsHandshakeKind::new_session_ticket);
        PFL_EXPECT(handshake.structured_parse_status == TlsStructuredParseStatus::malformed);
        PFL_EXPECT(!handshake.new_session_ticket.has_value());
    }

    {
        ScopedTestContext context {"synthetic=new_session_ticket_before_ccs_remains_parsed"};
        std::vector<std::uint8_t> ticket_body {};
        append_be32(ticket_body, 7200U);
        append_be16(ticket_body, 1U);
        ticket_body.push_back(0xABU);
        auto bytes = make_tls_record(0x16U, 0x0303U, make_tls_handshake_message(0x04U, ticket_body));
        const auto ccs = make_tls_record(0x14U, 0x0303U, {0x01U});
        bytes.insert(bytes.end(), ccs.begin(), ccs.end());
        const auto result = parser.inspect(bytes);
        PFL_REQUIRE(result.records.size() == 2U);
        PFL_REQUIRE(result.records[0].handshake_messages.size() == 1U);
        PFL_EXPECT(result.records[0].handshake_messages[0].structured_parse_status == TlsStructuredParseStatus::parsed);
        PFL_REQUIRE(result.records[0].handshake_messages[0].new_session_ticket.has_value());
        PFL_EXPECT(result.records[0].handshake_messages[0].new_session_ticket->ticket_length == 1U);
        PFL_EXPECT(result.records[1].content_type_kind == TlsRecordContentTypeKind::change_cipher_spec);
    }

    {
        ScopedTestContext context {"synthetic=new_session_ticket_after_ccs_not_parsed_as_plaintext"};
        const auto ccs = make_tls_record(0x14U, 0x0303U, {0x01U});
        std::vector<std::uint8_t> ticket_body {};
        append_be32(ticket_body, 7200U);
        append_be16(ticket_body, 1U);
        ticket_body.push_back(0xABU);
        auto bytes = ccs;
        const auto handshake_record = make_tls_record(0x16U, 0x0303U, make_tls_handshake_message(0x04U, ticket_body));
        bytes.insert(bytes.end(), handshake_record.begin(), handshake_record.end());
        const auto result = parser.inspect(bytes);
        PFL_REQUIRE(result.records.size() == 2U);
        PFL_EXPECT(result.records[1].handshake_payload_kind == TlsHandshakePayloadKind::encrypted_opaque);
        PFL_EXPECT(result.records[1].handshake_messages.empty());
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
        ScopedTestContext context {"synthetic=partial_record_with_partial_client_hello_envelope"};
        const std::array<std::uint8_t, 11> bytes {
            0x16U, 0x03U, 0x01U, 0x00U, 0x0CU,
            0x01U, 0x00U, 0x00U, 0x08U, 0xAAU, 0xBBU
        };
        const auto result = parser.inspect(bytes);
        PFL_REQUIRE(result.records.size() == 1U);
        PFL_EXPECT(result.total_input_bytes == 11U);
        PFL_EXPECT(result.consumed_bytes == 11U);
        PFL_EXPECT(result.stopped_after_partial_record);
        PFL_EXPECT(result.records[0].source_offset == 0U);
        PFL_EXPECT(result.records[0].status == TlsRecordStatus::partial_body);
        PFL_EXPECT(result.records[0].content_type == std::optional<std::uint8_t> {22U});
        PFL_EXPECT(result.records[0].content_type_kind == TlsRecordContentTypeKind::handshake);
        PFL_EXPECT(result.records[0].legacy_version == std::optional<std::uint16_t> {0x0301U});
        PFL_EXPECT(result.records[0].declared_payload_length == std::optional<std::size_t> {12U});
        PFL_EXPECT(result.records[0].total_size == std::optional<std::size_t> {17U});
        PFL_EXPECT(result.records[0].available_bytes == 11U);
        PFL_EXPECT(result.records[0].handshake_payload_kind == TlsHandshakePayloadKind::plaintext);
        PFL_REQUIRE(result.records[0].handshake_messages.size() == 1U);

        const auto& handshake = result.records[0].handshake_messages[0];
        PFL_EXPECT(handshake.source_offset == 5U);
        PFL_EXPECT(handshake.type == std::optional<std::uint8_t> {1U});
        PFL_EXPECT(handshake.kind == TlsHandshakeKind::client_hello);
        PFL_EXPECT(handshake.declared_body_length == std::optional<std::size_t> {8U});
        PFL_EXPECT(handshake.total_size == std::optional<std::size_t> {12U});
        PFL_EXPECT(handshake.available_bytes == 6U);
        PFL_EXPECT(handshake.status == TlsHandshakeStatus::partial_body);
        PFL_EXPECT(handshake.structured_parse_status == TlsStructuredParseStatus::not_attempted);
        PFL_EXPECT(!handshake.client_hello.has_value());
    }

    {
        ScopedTestContext context {"synthetic=raw_handshake_offsets_start_at_zero"};
        std::vector<std::uint8_t> extensions {};
        append_extension(extensions, 0xFAFAU, {});
        const auto client_hello = make_tls_handshake_message(
            0x01U,
            make_minimal_client_hello_body_with_extensions(extensions)
        );
        const auto unknown_handshake = make_tls_handshake_message(0x7FU, {0xAAU, 0xBBU});
        std::vector<std::uint8_t> handshake_bytes = client_hello;
        handshake_bytes.insert(handshake_bytes.end(), unknown_handshake.begin(), unknown_handshake.end());

        const auto handshakes = parser.inspect_handshake_messages(
            handshake_bytes,
            TlsInspectionParserContext {
                .semantic_state = TlsInspectionSemanticState::plaintext,
            }
        );
        PFL_REQUIRE(handshakes.size() == 2U);
        PFL_EXPECT(handshakes[0].source_offset == 0U);
        PFL_EXPECT(handshakes[0].total_size == std::optional<std::size_t> {51U});
        PFL_EXPECT(handshakes[1].source_offset == 51U);
        PFL_EXPECT(handshakes[1].total_size == std::optional<std::size_t> {6U});
    }

    {
        ScopedTestContext context {"synthetic=raw_handshake_partial_body_offsets_are_input_relative"};
        const std::array<std::uint8_t, 6> handshake_bytes {
            0x01U, 0x00U, 0x00U, 0x08U, 0xAAU, 0xBBU
        };
        const auto handshakes = parser.inspect_handshake_messages(
            handshake_bytes,
            TlsInspectionParserContext {
                .semantic_state = TlsInspectionSemanticState::plaintext,
            }
        );
        PFL_REQUIRE(handshakes.size() == 1U);
        PFL_EXPECT(handshakes[0].source_offset == 0U);
        PFL_EXPECT(handshakes[0].status == TlsHandshakeStatus::partial_body);
        PFL_EXPECT(handshakes[0].available_bytes == 6U);
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
        ScopedTestContext context {"synthetic=plaintext_alert_warning_complete"};
        const auto result = parser.inspect(make_tls_record(0x15U, 0x0303U, {0x01U, 0x00U}));
        PFL_REQUIRE(result.records.size() == 1U);
        PFL_EXPECT(result.records[0].status == TlsRecordStatus::complete);
        PFL_EXPECT(result.records[0].content_type_kind == TlsRecordContentTypeKind::alert);
        PFL_EXPECT(result.records[0].alert_payload_kind == TlsAlertPayloadKind::plaintext);
        PFL_EXPECT(result.records[0].alert_parse_status == TlsAlertParseStatus::parsed);
        PFL_REQUIRE(result.records[0].alert_entries.size() == 1U);
        expect_tls_alert_entry(result.records[0].alert_entries[0], 1U, 0U);
    }

    {
        ScopedTestContext context {"synthetic=plaintext_alert_fatal_complete"};
        const auto result = parser.inspect(make_tls_record(0x15U, 0x0303U, {0x02U, 0x46U}));
        PFL_REQUIRE(result.records.size() == 1U);
        PFL_EXPECT(result.records[0].alert_payload_kind == TlsAlertPayloadKind::plaintext);
        PFL_EXPECT(result.records[0].alert_parse_status == TlsAlertParseStatus::parsed);
        PFL_REQUIRE(result.records[0].alert_entries.size() == 1U);
        expect_tls_alert_entry(result.records[0].alert_entries[0], 2U, 70U);
    }

    {
        ScopedTestContext context {"synthetic=plaintext_alert_multiple_entries_complete"};
        const auto result = parser.inspect(make_tls_record(0x15U, 0x0303U, {0x01U, 0x00U, 0x02U, 0x30U}));
        PFL_REQUIRE(result.records.size() == 1U);
        PFL_EXPECT(result.records[0].alert_parse_status == TlsAlertParseStatus::parsed);
        PFL_REQUIRE(result.records[0].alert_entries.size() == 2U);
        expect_tls_alert_entry(result.records[0].alert_entries[0], 1U, 0U);
        expect_tls_alert_entry(result.records[0].alert_entries[1], 2U, 48U);
    }

    {
        ScopedTestContext context {"synthetic=plaintext_alert_unknown_level_and_description_preserved"};
        const auto result = parser.inspect(make_tls_record(0x15U, 0x0303U, {0x07U, 0xF0U}));
        PFL_REQUIRE(result.records.size() == 1U);
        PFL_EXPECT(result.records[0].alert_parse_status == TlsAlertParseStatus::parsed);
        PFL_REQUIRE(result.records[0].alert_entries.size() == 1U);
        expect_tls_alert_entry(result.records[0].alert_entries[0], 7U, 240U);
    }

    {
        ScopedTestContext context {"synthetic=plaintext_alert_empty_body_malformed"};
        const auto result = parser.inspect(make_tls_record(0x15U, 0x0303U, {}));
        PFL_REQUIRE(result.records.size() == 1U);
        PFL_EXPECT(result.records[0].alert_payload_kind == TlsAlertPayloadKind::plaintext);
        PFL_EXPECT(result.records[0].alert_parse_status == TlsAlertParseStatus::malformed);
        PFL_EXPECT(result.records[0].alert_entries.empty());
    }

    {
        ScopedTestContext context {"synthetic=plaintext_alert_single_byte_incomplete"};
        const auto result = parser.inspect(make_tls_record(0x15U, 0x0303U, {0x02U}));
        PFL_REQUIRE(result.records.size() == 1U);
        PFL_EXPECT(result.records[0].alert_payload_kind == TlsAlertPayloadKind::plaintext);
        PFL_EXPECT(result.records[0].alert_parse_status == TlsAlertParseStatus::incomplete);
        PFL_EXPECT(result.records[0].alert_entries.empty());
    }

    {
        ScopedTestContext context {"synthetic=plaintext_alert_odd_trailing_byte_incomplete_without_partial_commit"};
        const auto result = parser.inspect(make_tls_record(0x15U, 0x0303U, {0x01U, 0x00U, 0x02U}));
        PFL_REQUIRE(result.records.size() == 1U);
        PFL_EXPECT(result.records[0].alert_parse_status == TlsAlertParseStatus::incomplete);
        PFL_EXPECT(result.records[0].alert_entries.empty());
    }

    {
        ScopedTestContext context {"synthetic=plaintext_alert_entry_count_bound_malformed"};
        std::vector<std::uint8_t> alert_body {};
        alert_body.resize((1024U * 2U) + 2U, 0x00U);
        const auto result = parser.inspect(make_tls_record(0x15U, 0x0303U, alert_body));
        PFL_REQUIRE(result.records.size() == 1U);
        PFL_EXPECT(result.records[0].alert_parse_status == TlsAlertParseStatus::malformed);
        PFL_EXPECT(result.records[0].alert_entries.empty());
    }

    {
        ScopedTestContext context {"synthetic=post_ccs_alert_is_encrypted_opaque"};
        auto bytes = make_tls_record(0x14U, 0x0303U, {0x01U});
        const auto alert_record = make_tls_record(0x15U, 0x0303U, {0x02U, 0x30U});
        bytes.insert(bytes.end(), alert_record.begin(), alert_record.end());
        const auto result = parser.inspect(bytes);
        PFL_REQUIRE(result.records.size() == 2U);
        PFL_EXPECT(result.records[1].content_type_kind == TlsRecordContentTypeKind::alert);
        PFL_EXPECT(result.records[1].alert_payload_kind == TlsAlertPayloadKind::encrypted_opaque);
        PFL_EXPECT(result.records[1].alert_parse_status == TlsAlertParseStatus::not_attempted);
        PFL_EXPECT(result.records[1].alert_entries.empty());
    }

    {
        ScopedTestContext context {"synthetic=ccs_state_is_direction_local_for_alerts"};
        auto encrypted_direction = make_tls_record(0x14U, 0x0303U, {0x01U});
        const auto alert_record = make_tls_record(0x15U, 0x0303U, {0x02U, 0x2DU});
        encrypted_direction.insert(encrypted_direction.end(), alert_record.begin(), alert_record.end());
        const auto encrypted_result = parser.inspect(encrypted_direction);
        PFL_REQUIRE(encrypted_result.records.size() == 2U);
        PFL_EXPECT(encrypted_result.records[1].alert_payload_kind == TlsAlertPayloadKind::encrypted_opaque);
        PFL_EXPECT(encrypted_result.records[1].alert_entries.empty());

        const auto plaintext_result = parser.inspect(alert_record);
        PFL_REQUIRE(plaintext_result.records.size() == 1U);
        PFL_EXPECT(plaintext_result.records[0].alert_payload_kind == TlsAlertPayloadKind::plaintext);
        PFL_EXPECT(plaintext_result.records[0].alert_parse_status == TlsAlertParseStatus::parsed);
        PFL_REQUIRE(plaintext_result.records[0].alert_entries.size() == 1U);
        expect_tls_alert_entry(plaintext_result.records[0].alert_entries[0], 2U, 45U);
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
        ScopedTestContext context {"synthetic=client_hello_compress_certificate_single_algorithm"};
        std::vector<std::uint8_t> extensions {};
        append_extension(extensions, 0x001BU, {0x02U, 0x00U, 0x01U});
        const auto result = parser.inspect(make_client_hello_record_with_extensions(extensions));
        const auto& extension = require_single_client_hello_extension(result);
        PFL_EXPECT(extension.known_name == std::optional<std::string> {"compress_certificate"});
        PFL_EXPECT(extension.structured_parse_status == TlsStructuredParseStatus::parsed);
        PFL_EXPECT(extension.certificate_compression_algorithm_ids == std::vector<std::uint16_t>({0x0001U}));
    }

    {
        ScopedTestContext context {"synthetic=client_hello_compress_certificate_two_algorithms_wire_order"};
        std::vector<std::uint8_t> extensions {};
        append_extension(extensions, 0x001BU, {0x04U, 0x00U, 0x01U, 0x00U, 0x02U});
        const auto result = parser.inspect(make_client_hello_record_with_extensions(extensions));
        const auto& extension = require_single_client_hello_extension(result);
        PFL_EXPECT(extension.known_name == std::optional<std::string> {"compress_certificate"});
        PFL_EXPECT(extension.structured_parse_status == TlsStructuredParseStatus::parsed);
        PFL_EXPECT(extension.certificate_compression_algorithm_ids == std::vector<std::uint16_t>({0x0001U, 0x0002U}));
    }

    {
        ScopedTestContext context {"synthetic=client_hello_compress_certificate_empty_body_malformed"};
        std::vector<std::uint8_t> extensions {};
        append_extension(extensions, 0x001BU, {});
        const auto result = parser.inspect(make_client_hello_record_with_extensions(extensions));
        const auto& extension = require_single_client_hello_extension(result);
        PFL_EXPECT(extension.structured_parse_status == TlsStructuredParseStatus::malformed);
        PFL_EXPECT(extension.certificate_compression_algorithm_ids.empty());
    }

    {
        ScopedTestContext context {"synthetic=client_hello_compress_certificate_zero_declared_length_malformed"};
        std::vector<std::uint8_t> extensions {};
        append_extension(extensions, 0x001BU, {0x00U});
        const auto result = parser.inspect(make_client_hello_record_with_extensions(extensions));
        const auto& extension = require_single_client_hello_extension(result);
        PFL_EXPECT(extension.structured_parse_status == TlsStructuredParseStatus::malformed);
        PFL_EXPECT(extension.certificate_compression_algorithm_ids.empty());
    }

    {
        ScopedTestContext context {"synthetic=client_hello_compress_certificate_odd_declared_length_malformed"};
        std::vector<std::uint8_t> extensions {};
        append_extension(extensions, 0x001BU, {0x03U, 0x00U, 0x02U, 0x00U});
        const auto result = parser.inspect(make_client_hello_record_with_extensions(extensions));
        const auto& extension = require_single_client_hello_extension(result);
        PFL_EXPECT(extension.structured_parse_status == TlsStructuredParseStatus::malformed);
        PFL_EXPECT(extension.certificate_compression_algorithm_ids.empty());
    }

    {
        ScopedTestContext context {"synthetic=client_hello_compress_certificate_declared_length_mismatch_malformed"};
        std::vector<std::uint8_t> extensions {};
        append_extension(extensions, 0x001BU, {0x04U, 0x00U, 0x01U});
        const auto result = parser.inspect(make_client_hello_record_with_extensions(extensions));
        const auto& extension = require_single_client_hello_extension(result);
        PFL_EXPECT(extension.structured_parse_status == TlsStructuredParseStatus::malformed);
        PFL_EXPECT(extension.certificate_compression_algorithm_ids.empty());
    }

    {
        ScopedTestContext context {"synthetic=client_hello_compress_certificate_truncated_uint16_malformed"};
        std::vector<std::uint8_t> extensions {};
        append_extension(extensions, 0x001BU, {0x02U, 0x00U});
        const auto result = parser.inspect(make_client_hello_record_with_extensions(extensions));
        const auto& extension = require_single_client_hello_extension(result);
        PFL_EXPECT(extension.structured_parse_status == TlsStructuredParseStatus::malformed);
        PFL_EXPECT(extension.certificate_compression_algorithm_ids.empty());
    }

    {
        ScopedTestContext context {"synthetic=client_hello_compress_certificate_transactional_no_partial_ids"};
        std::vector<std::uint8_t> extensions {};
        append_extension(extensions, 0x001BU, {0x04U, 0x00U, 0x01U, 0x00U});
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
