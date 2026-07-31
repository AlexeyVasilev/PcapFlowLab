#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace pfl {

enum class TlsRecordContentTypeKind : std::uint8_t {
    change_cipher_spec,
    alert,
    handshake,
    application_data,
    unknown,
};

enum class TlsRecordStatus : std::uint8_t {
    complete,
    partial_header,
    partial_body,
};

enum class TlsHandshakePayloadKind : std::uint8_t {
    none,
    plaintext,
    encrypted_opaque,
};

enum class TlsAlertPayloadKind : std::uint8_t {
    none,
    plaintext,
    encrypted_opaque,
};

enum class TlsHandshakeKind : std::uint8_t {
    client_hello,
    server_hello,
    new_session_ticket,
    encrypted_extensions,
    certificate,
    server_key_exchange,
    certificate_request,
    server_hello_done,
    certificate_verify,
    client_key_exchange,
    finished,
    unknown,
};

enum class TlsHandshakeStatus : std::uint8_t {
    complete,
    partial_header,
    partial_body,
};

enum class TlsStructuredParseStatus : std::uint8_t {
    not_attempted,
    parsed,
    malformed,
};

enum class TlsAlertParseStatus : std::uint8_t {
    not_attempted,
    parsed,
    incomplete,
    malformed,
};

enum class TlsInspectionSemanticState : std::uint8_t {
    unknown,
    plaintext,
    post_change_cipher_spec,
};

[[nodiscard]] inline std::optional<std::string_view> tls_alert_level_name(const std::uint8_t level) noexcept {
    switch (level) {
    case 1U:
        return std::string_view {"Warning"};
    case 2U:
        return std::string_view {"Fatal"};
    default:
        return std::nullopt;
    }
}

[[nodiscard]] inline std::optional<std::string_view> tls_alert_description_name(
    const std::uint8_t description
) noexcept {
    switch (description) {
    case 0U:
        return std::string_view {"Close Notify"};
    case 10U:
        return std::string_view {"Unexpected Message"};
    case 20U:
        return std::string_view {"Bad Record MAC"};
    case 21U:
        return std::string_view {"Decryption Failed"};
    case 22U:
        return std::string_view {"Record Overflow"};
    case 40U:
        return std::string_view {"Handshake Failure"};
    case 42U:
        return std::string_view {"Bad Certificate"};
    case 43U:
        return std::string_view {"Unsupported Certificate"};
    case 44U:
        return std::string_view {"Certificate Revoked"};
    case 45U:
        return std::string_view {"Certificate Expired"};
    case 46U:
        return std::string_view {"Certificate Unknown"};
    case 47U:
        return std::string_view {"Illegal Parameter"};
    case 48U:
        return std::string_view {"Unknown CA"};
    case 49U:
        return std::string_view {"Access Denied"};
    case 50U:
        return std::string_view {"Decode Error"};
    case 51U:
        return std::string_view {"Decrypt Error"};
    case 70U:
        return std::string_view {"Protocol Version"};
    case 71U:
        return std::string_view {"Insufficient Security"};
    case 80U:
        return std::string_view {"Internal Error"};
    case 86U:
        return std::string_view {"Inappropriate Fallback"};
    case 90U:
        return std::string_view {"User Canceled"};
    case 109U:
        return std::string_view {"Missing Extension"};
    case 110U:
        return std::string_view {"Unsupported Extension"};
    case 112U:
        return std::string_view {"Unrecognized Name"};
    case 116U:
        return std::string_view {"Certificate Required"};
    case 120U:
        return std::string_view {"No Application Protocol"};
    default:
        return std::nullopt;
    }
}

struct TlsAlertEntryModel {
    std::size_t order_index {0U};
    std::uint8_t level {0U};
    std::uint8_t description {0U};
};

struct TlsKeyShareEntryModel {
    std::size_t order_index {0U};
    std::uint16_t group_id {0U};
    std::size_t key_exchange_length {0U};
};

struct TlsStatusRequestModel {
    std::uint8_t status_type {0U};
    std::size_t responder_id_list_length {0U};
    std::size_t request_extensions_length {0U};
};

struct TlsExtensionModel {
    std::size_t source_offset {0U};
    std::size_t order_index {0U};
    std::uint16_t type {0U};
    std::optional<std::string> known_name {};
    std::size_t declared_length {0U};
    TlsStructuredParseStatus structured_parse_status {TlsStructuredParseStatus::not_attempted};
    std::vector<std::string> server_names {};
    std::vector<std::string> alpn_protocols {};
    std::vector<std::uint16_t> supported_versions {};
    std::vector<std::uint16_t> supported_group_ids {};
    std::vector<std::uint16_t> signature_scheme_ids {};
    std::vector<TlsKeyShareEntryModel> key_share_entries {};
    std::vector<std::uint8_t> psk_key_exchange_mode_ids {};
    std::optional<TlsStatusRequestModel> status_request {};
    std::vector<std::uint16_t> certificate_compression_algorithm_ids {};
    std::optional<std::size_t> padding_length {};
};

struct TlsClientHelloModel {
    std::uint16_t legacy_version {0U};
    std::array<std::uint8_t, 32> random {};
    std::vector<std::uint8_t> session_id {};
    std::vector<std::uint16_t> cipher_suites {};
    std::vector<std::uint8_t> compression_methods {};
    std::vector<TlsExtensionModel> extensions {};
    std::vector<std::string> sni_names {};
    std::vector<std::string> alpn_protocols {};
    std::vector<std::uint16_t> supported_versions {};
};

struct TlsServerHelloModel {
    std::uint16_t legacy_version {0U};
    std::array<std::uint8_t, 32> random {};
    std::vector<std::uint8_t> session_id {};
    std::uint16_t selected_cipher_suite {0U};
    std::uint8_t compression_method {0U};
    std::vector<TlsExtensionModel> extensions {};
    std::uint16_t selected_tls_version {0U};
    std::optional<std::string> selected_alpn_protocol {};
};

struct TlsNewSessionTicketModel {
    std::uint32_t ticket_lifetime_hint_seconds {0U};
    std::size_t ticket_length {0U};
};

struct TlsCertificateEntryModel {
    std::size_t declared_der_length {0U};
    std::size_t available_der_length {0U};
    bool complete {false};
};

struct TlsCertificateModel {
    std::size_t declared_certificate_list_length {0U};
    bool complete_certificate_list {false};
    std::vector<TlsCertificateEntryModel> certificate_entries {};
};

struct TlsCertificateAuthorityEntryModel {
    std::size_t declared_length {0U};
    std::size_t available_length {0U};
    bool complete {false};
};

struct TlsCertificateRequestModel {
    std::vector<std::uint8_t> certificate_type_ids {};
    std::size_t signature_scheme_bytes_length {0U};
    std::vector<std::uint16_t> signature_scheme_ids {};
    std::size_t certificate_authorities_bytes_length {0U};
    bool complete_certificate_authorities_vector {false};
    std::vector<TlsCertificateAuthorityEntryModel> certificate_authority_entries {};
};

struct TlsHandshakeModel {
    std::size_t source_offset {0U};
    std::optional<std::uint8_t> type {};
    TlsHandshakeKind kind {TlsHandshakeKind::unknown};
    std::optional<std::size_t> declared_body_length {};
    std::optional<std::size_t> total_size {};
    std::size_t available_bytes {0U};
    TlsHandshakeStatus status {TlsHandshakeStatus::partial_header};
    TlsStructuredParseStatus structured_parse_status {TlsStructuredParseStatus::not_attempted};
    std::optional<TlsClientHelloModel> client_hello {};
    std::optional<TlsServerHelloModel> server_hello {};
    std::optional<TlsNewSessionTicketModel> new_session_ticket {};
    std::optional<TlsCertificateModel> certificate {};
    std::optional<TlsCertificateRequestModel> certificate_request {};
};

struct TlsRecordModel {
    std::size_t source_offset {0U};
    std::optional<std::uint8_t> content_type {};
    TlsRecordContentTypeKind content_type_kind {TlsRecordContentTypeKind::unknown};
    std::optional<std::uint16_t> legacy_version {};
    std::optional<std::size_t> declared_payload_length {};
    std::optional<std::size_t> total_size {};
    std::size_t available_bytes {0U};
    TlsRecordStatus status {TlsRecordStatus::partial_header};
    TlsHandshakePayloadKind handshake_payload_kind {TlsHandshakePayloadKind::none};
    TlsAlertPayloadKind alert_payload_kind {TlsAlertPayloadKind::none};
    TlsAlertParseStatus alert_parse_status {TlsAlertParseStatus::not_attempted};
    std::vector<TlsAlertEntryModel> alert_entries {};
    std::vector<TlsHandshakeModel> handshake_messages {};
};

struct TlsInspectionResult {
    std::size_t total_input_bytes {0U};
    std::size_t consumed_bytes {0U};
    bool stopped_after_partial_record {false};
    std::size_t unparsed_trailing_bytes {0U};
    std::vector<TlsRecordModel> records {};
};

}  // namespace pfl
