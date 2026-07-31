#include "core/services/TlsInspectionParser.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace pfl {

namespace {

constexpr std::size_t kTlsRecordHeaderSize = 5U;
constexpr std::size_t kTlsHandshakeHeaderSize = 4U;
constexpr std::size_t kTlsCertificateEntryLimit = 1024U;
constexpr std::size_t kTlsCertificateTypeLimit = 255U;
constexpr std::size_t kTlsSignatureSchemeLimit = 1024U;
constexpr std::size_t kTlsCertificateAuthorityEntryLimit = 1024U;

std::optional<std::uint16_t> read_be16(std::span<const std::uint8_t> bytes, const std::size_t offset) {
    if (offset + 2U > bytes.size()) {
        return std::nullopt;
    }

    return static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(bytes[offset]) << 8U) |
        static_cast<std::uint16_t>(bytes[offset + 1U])
    );
}

std::optional<std::uint32_t> read_be24(std::span<const std::uint8_t> bytes, const std::size_t offset) {
    if (offset + 3U > bytes.size()) {
        return std::nullopt;
    }

    return (static_cast<std::uint32_t>(bytes[offset]) << 16U) |
           (static_cast<std::uint32_t>(bytes[offset + 1U]) << 8U) |
           static_cast<std::uint32_t>(bytes[offset + 2U]);
}

std::optional<std::uint32_t> read_be32(std::span<const std::uint8_t> bytes, const std::size_t offset) {
    if (offset + 4U > bytes.size()) {
        return std::nullopt;
    }

    return (static_cast<std::uint32_t>(bytes[offset]) << 24U) |
           (static_cast<std::uint32_t>(bytes[offset + 1U]) << 16U) |
           (static_cast<std::uint32_t>(bytes[offset + 2U]) << 8U) |
           static_cast<std::uint32_t>(bytes[offset + 3U]);
}

bool add_overflows(const std::size_t left, const std::size_t right) {
    return right > (static_cast<std::size_t>(-1) - left);
}

std::optional<std::size_t> checked_add(const std::size_t left, const std::size_t right) {
    if (add_overflows(left, right)) {
        return std::nullopt;
    }
    return left + right;
}

std::optional<std::size_t> make_input_relative_offset(
    const std::size_t base_offset,
    const std::size_t relative_offset
) {
    return checked_add(base_offset, relative_offset);
}

TlsRecordContentTypeKind classify_record_content_type(const std::uint8_t content_type) noexcept {
    switch (content_type) {
    case 20U:
        return TlsRecordContentTypeKind::change_cipher_spec;
    case 21U:
        return TlsRecordContentTypeKind::alert;
    case 22U:
        return TlsRecordContentTypeKind::handshake;
    case 23U:
        return TlsRecordContentTypeKind::application_data;
    default:
        return TlsRecordContentTypeKind::unknown;
    }
}

TlsHandshakeKind classify_handshake_type(const std::uint8_t handshake_type) noexcept {
    switch (handshake_type) {
    case 1U:
        return TlsHandshakeKind::client_hello;
    case 2U:
        return TlsHandshakeKind::server_hello;
    case 4U:
        return TlsHandshakeKind::new_session_ticket;
    case 8U:
        return TlsHandshakeKind::encrypted_extensions;
    case 11U:
        return TlsHandshakeKind::certificate;
    case 12U:
        return TlsHandshakeKind::server_key_exchange;
    case 13U:
        return TlsHandshakeKind::certificate_request;
    case 14U:
        return TlsHandshakeKind::server_hello_done;
    case 15U:
        return TlsHandshakeKind::certificate_verify;
    case 16U:
        return TlsHandshakeKind::client_key_exchange;
    case 20U:
        return TlsHandshakeKind::finished;
    default:
        return TlsHandshakeKind::unknown;
    }
}

std::optional<std::string> known_extension_name(const std::uint16_t extension_type) {
    switch (extension_type) {
    case 0x0000U:
        return std::string {"server_name"};
    case 0x0005U:
        return std::string {"status_request"};
    case 0x000AU:
        return std::string {"supported_groups"};
    case 0x000BU:
        return std::string {"ec_point_formats"};
    case 0x000DU:
        return std::string {"signature_algorithms"};
    case 0x0010U:
        return std::string {"application_layer_protocol_negotiation"};
    case 0x0012U:
        return std::string {"signed_certificate_timestamp"};
    case 0x0015U:
        return std::string {"padding"};
    case 0x0017U:
        return std::string {"extended_master_secret"};
    case 0x001BU:
        return std::string {"compress_certificate"};
    case 0x0023U:
        return std::string {"session_ticket"};
    case 0x002BU:
        return std::string {"supported_versions"};
    case 0x002DU:
        return std::string {"psk_key_exchange_modes"};
    case 0x0033U:
        return std::string {"key_share"};
    case 0xFF01U:
        return std::string {"renegotiation_info"};
    default:
        return std::nullopt;
    }
}

std::string bytes_to_text(std::span<const std::uint8_t> bytes) {
    return std::string(reinterpret_cast<const char*>(bytes.data()), bytes.size());
}

bool parse_server_name_extension(
    std::span<const std::uint8_t> extension_bytes,
    std::vector<std::string>& out_server_names
) {
    const auto server_name_list_length = read_be16(extension_bytes, 0U);
    if (!server_name_list_length.has_value()) {
        return false;
    }

    const auto names_end = checked_add(2U, static_cast<std::size_t>(*server_name_list_length));
    if (!names_end.has_value() || *names_end != extension_bytes.size()) {
        return false;
    }

    std::vector<std::string> parsed_server_names {};
    std::size_t offset = 2U;
    while (offset < *names_end) {
        const auto name_header_end = checked_add(offset, 3U);
        if (!name_header_end.has_value() || *name_header_end > *names_end) {
            return false;
        }

        const auto name_type = extension_bytes[offset];
        const auto name_length = read_be16(extension_bytes, offset + 1U);
        if (!name_length.has_value()) {
            return false;
        }

        offset += 3U;
        const auto name_end = checked_add(offset, static_cast<std::size_t>(*name_length));
        if (!name_end.has_value() || *name_end > *names_end) {
            return false;
        }

        if (name_type == 0U) {
            parsed_server_names.push_back(bytes_to_text(extension_bytes.subspan(offset, *name_length)));
        }
        offset = *name_end;
    }

    if (offset != *names_end) {
        return false;
    }

    out_server_names = std::move(parsed_server_names);
    return true;
}

bool parse_alpn_extension(
    std::span<const std::uint8_t> extension_bytes,
    std::vector<std::string>& out_alpn_protocols
) {
    const auto alpn_length = read_be16(extension_bytes, 0U);
    if (!alpn_length.has_value()) {
        return false;
    }

    const auto protocols_end = checked_add(2U, static_cast<std::size_t>(*alpn_length));
    if (!protocols_end.has_value() || *protocols_end != extension_bytes.size()) {
        return false;
    }

    std::vector<std::string> parsed_alpn_protocols {};
    std::size_t offset = 2U;
    while (offset < *protocols_end) {
        const auto protocol_length_offset = checked_add(offset, 1U);
        if (!protocol_length_offset.has_value() || *protocol_length_offset > *protocols_end) {
            return false;
        }

        const auto protocol_length = static_cast<std::size_t>(extension_bytes[offset]);
        ++offset;
        const auto protocol_end = checked_add(offset, protocol_length);
        if (!protocol_end.has_value() || *protocol_end > *protocols_end) {
            return false;
        }

        parsed_alpn_protocols.push_back(bytes_to_text(extension_bytes.subspan(offset, protocol_length)));
        offset = *protocol_end;
    }

    if (offset != *protocols_end) {
        return false;
    }

    out_alpn_protocols = std::move(parsed_alpn_protocols);
    return true;
}

bool parse_supported_versions_client_extension(
    std::span<const std::uint8_t> extension_bytes,
    std::vector<std::uint16_t>& out_supported_versions
) {
    if (extension_bytes.empty()) {
        return false;
    }

    const auto versions_length = static_cast<std::size_t>(extension_bytes[0]);
    if ((versions_length % 2U) != 0U) {
        return false;
    }

    const auto versions_end = checked_add(1U, versions_length);
    if (!versions_end.has_value() || *versions_end != extension_bytes.size()) {
        return false;
    }

    std::vector<std::uint16_t> parsed_supported_versions {};
    for (std::size_t offset = 1U; offset < *versions_end; offset += 2U) {
        const auto version = read_be16(extension_bytes, offset);
        if (!version.has_value()) {
            return false;
        }
        parsed_supported_versions.push_back(*version);
    }

    out_supported_versions = std::move(parsed_supported_versions);
    return true;
}

bool parse_supported_versions_server_extension(
    std::span<const std::uint8_t> extension_bytes,
    std::vector<std::uint16_t>& out_supported_versions,
    std::uint16_t& out_selected_tls_version
) {
    const auto version = read_be16(extension_bytes, 0U);
    if (!version.has_value() || extension_bytes.size() != 2U) {
        return false;
    }

    out_supported_versions = std::vector<std::uint16_t> {*version};
    out_selected_tls_version = *version;
    return true;
}

bool parse_u16_vector_payload(
    std::span<const std::uint8_t> extension_bytes,
    std::vector<std::uint16_t>& out_values
) {
    const auto vector_length = read_be16(extension_bytes, 0U);
    if (!vector_length.has_value()) {
        return false;
    }

    if ((vector_length.value() % 2U) != 0U) {
        return false;
    }

    if (2U + static_cast<std::size_t>(*vector_length) != extension_bytes.size()) {
        return false;
    }

    std::vector<std::uint16_t> parsed_values {};
    for (std::size_t offset = 2U; offset < extension_bytes.size(); offset += 2U) {
        const auto value = read_be16(extension_bytes, offset);
        if (!value.has_value()) {
            return false;
        }
        parsed_values.push_back(*value);
    }

    out_values = std::move(parsed_values);
    return true;
}

bool parse_supported_groups_extension(
    std::span<const std::uint8_t> extension_bytes,
    std::vector<std::uint16_t>& out_supported_group_ids
) {
    return parse_u16_vector_payload(extension_bytes, out_supported_group_ids);
}

bool parse_signature_algorithms_extension(
    std::span<const std::uint8_t> extension_bytes,
    std::vector<std::uint16_t>& out_signature_scheme_ids
) {
    return parse_u16_vector_payload(extension_bytes, out_signature_scheme_ids);
}

bool parse_client_key_share_extension(
    std::span<const std::uint8_t> extension_bytes,
    std::vector<TlsKeyShareEntryModel>& out_key_share_entries
) {
    const auto shares_length = read_be16(extension_bytes, 0U);
    if (!shares_length.has_value()) {
        return false;
    }

    if (2U + static_cast<std::size_t>(*shares_length) != extension_bytes.size()) {
        return false;
    }

    std::size_t offset = 2U;
    std::size_t order_index = 0U;
    std::vector<TlsKeyShareEntryModel> parsed_entries {};
    while (offset < extension_bytes.size()) {
        const auto group_id = read_be16(extension_bytes, offset);
        const auto key_exchange_length = read_be16(extension_bytes, offset + 2U);
        if (!group_id.has_value() || !key_exchange_length.has_value()) {
            return false;
        }

        offset += 4U;
        const auto key_exchange_end = checked_add(offset, static_cast<std::size_t>(*key_exchange_length));
        if (!key_exchange_end.has_value() || *key_exchange_end > extension_bytes.size()) {
            return false;
        }

        parsed_entries.push_back(TlsKeyShareEntryModel {
            .order_index = order_index,
            .group_id = *group_id,
            .key_exchange_length = *key_exchange_length,
        });
        offset = *key_exchange_end;
        ++order_index;
    }

    if (offset != extension_bytes.size()) {
        return false;
    }

    out_key_share_entries = std::move(parsed_entries);
    return true;
}

bool parse_server_key_share_extension(
    std::span<const std::uint8_t> extension_bytes,
    std::vector<TlsKeyShareEntryModel>& out_key_share_entries
) {
    const auto group_id = read_be16(extension_bytes, 0U);
    const auto key_exchange_length = read_be16(extension_bytes, 2U);
    if (!group_id.has_value() || !key_exchange_length.has_value()) {
        return false;
    }

    if (4U + static_cast<std::size_t>(*key_exchange_length) != extension_bytes.size()) {
        return false;
    }

    out_key_share_entries = std::vector<TlsKeyShareEntryModel> {TlsKeyShareEntryModel {
        .order_index = 0U,
        .group_id = *group_id,
        .key_exchange_length = *key_exchange_length,
    }};
    return true;
}

bool parse_psk_key_exchange_modes_extension(
    std::span<const std::uint8_t> extension_bytes,
    std::vector<std::uint8_t>& out_psk_key_exchange_mode_ids
) {
    if (extension_bytes.empty()) {
        return false;
    }

    const auto modes_length = static_cast<std::size_t>(extension_bytes[0]);
    if (1U + modes_length != extension_bytes.size()) {
        return false;
    }

    out_psk_key_exchange_mode_ids.assign(extension_bytes.begin() + 1, extension_bytes.end());
    return true;
}

bool parse_status_request_extension(
    std::span<const std::uint8_t> extension_bytes,
    TlsStatusRequestModel& out_status_request
) {
    if (extension_bytes.size() < 5U) {
        return false;
    }

    const auto responder_id_list_length = read_be16(extension_bytes, 1U);
    if (!responder_id_list_length.has_value()) {
        return false;
    }

    const auto request_extensions_length_offset = 3U + static_cast<std::size_t>(*responder_id_list_length);
    const auto request_extensions_length = read_be16(extension_bytes, request_extensions_length_offset);
    if (!request_extensions_length.has_value()) {
        return false;
    }

    if (request_extensions_length_offset + 2U + static_cast<std::size_t>(*request_extensions_length) != extension_bytes.size()) {
        return false;
    }

    out_status_request = TlsStatusRequestModel {
        .status_type = extension_bytes[0],
        .responder_id_list_length = *responder_id_list_length,
        .request_extensions_length = *request_extensions_length,
    };
    return true;
}

bool parse_compress_certificate_extension(
    std::span<const std::uint8_t> extension_bytes,
    std::vector<std::uint16_t>& out_certificate_compression_algorithm_ids
) {
    if (extension_bytes.empty()) {
        return false;
    }

    // RFC 8879 algorithms<2..2^8-2> uses a one-byte vector-length
    // prefix; each following algorithm identifier is uint16.
    const auto algorithms_byte_length = static_cast<std::size_t>(extension_bytes[0]);
    if (algorithms_byte_length < 2U || (algorithms_byte_length % 2U) != 0U) {
        return false;
    }

    if (1U + algorithms_byte_length != extension_bytes.size()) {
        return false;
    }

    std::vector<std::uint16_t> parsed_algorithm_ids {};
    for (std::size_t offset = 1U; offset < extension_bytes.size(); offset += 2U) {
        const auto algorithm_id = read_be16(extension_bytes, offset);
        if (!algorithm_id.has_value()) {
            return false;
        }
        parsed_algorithm_ids.push_back(*algorithm_id);
    }

    out_certificate_compression_algorithm_ids = std::move(parsed_algorithm_ids);
    return true;
}

std::size_t parse_padding_extension(std::span<const std::uint8_t> extension_bytes) {
    return extension_bytes.size();
}

std::optional<TlsNewSessionTicketModel> parse_new_session_ticket_body(
    std::span<const std::uint8_t> handshake_body
) {
    if (handshake_body.size() < 6U) {
        return std::nullopt;
    }

    const auto ticket_lifetime_hint_seconds = read_be32(handshake_body, 0U);
    const auto ticket_length = read_be16(handshake_body, 4U);
    if (!ticket_lifetime_hint_seconds.has_value() || !ticket_length.has_value()) {
        return std::nullopt;
    }

    const auto ticket_end = checked_add(6U, static_cast<std::size_t>(*ticket_length));
    if (!ticket_end.has_value() || *ticket_end != handshake_body.size()) {
        return std::nullopt;
    }

    return TlsNewSessionTicketModel {
        .ticket_lifetime_hint_seconds = *ticket_lifetime_hint_seconds,
        .ticket_length = *ticket_length,
    };
}

std::optional<TlsCertificateModel> parse_certificate_body(
    std::span<const std::uint8_t> handshake_body
) {
    const auto certificate_list_length = read_be24(handshake_body, 0U);
    if (!certificate_list_length.has_value()) {
        return std::nullopt;
    }

    const auto certificates_end = checked_add(3U, static_cast<std::size_t>(*certificate_list_length));
    if (!certificates_end.has_value() || *certificates_end != handshake_body.size()) {
        return std::nullopt;
    }

    TlsCertificateModel certificate {
        .declared_certificate_list_length = *certificate_list_length,
        .complete_certificate_list = true,
    };

    std::size_t offset = 3U;
    while (offset < *certificates_end) {
        if (certificate.certificate_entries.size() >= kTlsCertificateEntryLimit) {
            return std::nullopt;
        }

        const auto certificate_length = read_be24(handshake_body, offset);
        if (!certificate_length.has_value()) {
            return std::nullopt;
        }

        offset += 3U;
        const auto certificate_end = checked_add(offset, static_cast<std::size_t>(*certificate_length));
        if (!certificate_end.has_value() || *certificate_end > *certificates_end) {
            return std::nullopt;
        }

        certificate.certificate_entries.push_back(TlsCertificateEntryModel {
            .declared_der_length = *certificate_length,
            .available_der_length = *certificate_length,
            .complete = true,
        });
        offset = *certificate_end;
    }

    if (offset != *certificates_end) {
        return std::nullopt;
    }

    return certificate;
}

std::optional<TlsCertificateRequestModel> parse_tls12_certificate_request_body(
    std::span<const std::uint8_t> handshake_body
) {
    if (handshake_body.empty()) {
        return std::nullopt;
    }

    const auto certificate_types_length = static_cast<std::size_t>(handshake_body[0]);
    if (certificate_types_length == 0U || certificate_types_length > kTlsCertificateTypeLimit) {
        return std::nullopt;
    }

    const auto certificate_types_end = checked_add(1U, certificate_types_length);
    if (!certificate_types_end.has_value() || *certificate_types_end + 4U > handshake_body.size()) {
        return std::nullopt;
    }

    TlsCertificateRequestModel request {};
    request.certificate_type_ids.assign(
        handshake_body.begin() + 1,
        handshake_body.begin() + static_cast<std::ptrdiff_t>(*certificate_types_end)
    );

    std::size_t offset = *certificate_types_end;
    const auto signature_scheme_bytes_length = read_be16(handshake_body, offset);
    if (!signature_scheme_bytes_length.has_value() ||
        *signature_scheme_bytes_length < 2U ||
        (*signature_scheme_bytes_length % 2U) != 0U) {
        return std::nullopt;
    }

    request.signature_scheme_bytes_length = *signature_scheme_bytes_length;
    offset += 2U;
    const auto signature_schemes_end = checked_add(offset, static_cast<std::size_t>(*signature_scheme_bytes_length));
    if (!signature_schemes_end.has_value() || *signature_schemes_end + 2U > handshake_body.size()) {
        return std::nullopt;
    }

    const auto signature_scheme_count = static_cast<std::size_t>(*signature_scheme_bytes_length / 2U);
    if (signature_scheme_count > kTlsSignatureSchemeLimit) {
        return std::nullopt;
    }

    request.signature_scheme_ids.reserve(signature_scheme_count);
    while (offset < *signature_schemes_end) {
        const auto signature_scheme = read_be16(handshake_body, offset);
        if (!signature_scheme.has_value()) {
            return std::nullopt;
        }

        request.signature_scheme_ids.push_back(*signature_scheme);
        offset += 2U;
    }

    const auto certificate_authorities_bytes_length = read_be16(handshake_body, offset);
    if (!certificate_authorities_bytes_length.has_value()) {
        return std::nullopt;
    }

    request.certificate_authorities_bytes_length = *certificate_authorities_bytes_length;
    offset += 2U;
    const auto authorities_end = checked_add(offset, static_cast<std::size_t>(*certificate_authorities_bytes_length));
    if (!authorities_end.has_value() || *authorities_end != handshake_body.size()) {
        return std::nullopt;
    }

    while (offset < *authorities_end) {
        if (request.certificate_authority_entries.size() >= kTlsCertificateAuthorityEntryLimit) {
            return std::nullopt;
        }

        const auto authority_length = read_be16(handshake_body, offset);
        if (!authority_length.has_value()) {
            return std::nullopt;
        }

        offset += 2U;
        const auto authority_end = checked_add(offset, static_cast<std::size_t>(*authority_length));
        if (!authority_end.has_value() || *authority_end > *authorities_end) {
            return std::nullopt;
        }

        request.certificate_authority_entries.push_back(TlsCertificateAuthorityEntryModel {
            .declared_length = *authority_length,
            .available_length = *authority_length,
            .complete = true,
        });
        offset = *authority_end;
    }

    if (offset != *authorities_end) {
        return std::nullopt;
    }

    request.complete_certificate_authorities_vector = true;
    return request;
}

std::optional<TlsClientHelloModel> parse_client_hello_body(
    std::span<const std::uint8_t> handshake_body,
    const std::size_t handshake_source_offset
) {
    if (handshake_body.size() < 34U) {
        return std::nullopt;
    }

    TlsClientHelloModel hello {};
    const auto legacy_version = read_be16(handshake_body, 0U);
    if (!legacy_version.has_value()) {
        return std::nullopt;
    }
    hello.legacy_version = *legacy_version;
    std::copy_n(handshake_body.begin() + static_cast<std::ptrdiff_t>(2U), 32, hello.random.begin());

    std::size_t offset = 34U;
    const auto session_id_length = static_cast<std::size_t>(handshake_body[offset]);
    ++offset;
    if (offset + session_id_length + 2U > handshake_body.size()) {
        return std::nullopt;
    }
    hello.session_id.assign(
        handshake_body.begin() + static_cast<std::ptrdiff_t>(offset),
        handshake_body.begin() + static_cast<std::ptrdiff_t>(offset + session_id_length)
    );
    offset += session_id_length;

    const auto cipher_suites_length = read_be16(handshake_body, offset);
    if (!cipher_suites_length.has_value()) {
        return std::nullopt;
    }
    offset += 2U;
    if ((*cipher_suites_length % 2U) != 0U || offset + *cipher_suites_length + 1U > handshake_body.size()) {
        return std::nullopt;
    }
    for (std::size_t cursor = offset; cursor < offset + *cipher_suites_length; cursor += 2U) {
        const auto cipher_suite = read_be16(handshake_body, cursor);
        if (!cipher_suite.has_value()) {
            return std::nullopt;
        }
        hello.cipher_suites.push_back(*cipher_suite);
    }
    offset += *cipher_suites_length;

    const auto compression_methods_length = static_cast<std::size_t>(handshake_body[offset]);
    ++offset;
    if (offset + compression_methods_length > handshake_body.size()) {
        return std::nullopt;
    }
    hello.compression_methods.assign(
        handshake_body.begin() + static_cast<std::ptrdiff_t>(offset),
        handshake_body.begin() + static_cast<std::ptrdiff_t>(offset + compression_methods_length)
    );
    offset += compression_methods_length;

    if (offset == handshake_body.size()) {
        return hello;
    }
    if (offset + 2U > handshake_body.size()) {
        return std::nullopt;
    }

    const auto extensions_length = read_be16(handshake_body, offset);
    if (!extensions_length.has_value()) {
        return std::nullopt;
    }
    offset += 2U;
    const auto extensions_end = checked_add(offset, static_cast<std::size_t>(*extensions_length));
    if (!extensions_end.has_value() || *extensions_end != handshake_body.size()) {
        return std::nullopt;
    }

    std::size_t order_index = 0U;
    while (offset < *extensions_end) {
        const auto extension_offset = offset;
        const auto extension_header_end = checked_add(offset, 4U);
        if (!extension_header_end.has_value() || *extension_header_end > *extensions_end) {
            return std::nullopt;
        }

        const auto extension_type = read_be16(handshake_body, offset);
        const auto extension_length = read_be16(handshake_body, offset + 2U);
        if (!extension_type.has_value() || !extension_length.has_value()) {
            return std::nullopt;
        }

        offset += 4U;
        const auto extension_end = checked_add(offset, static_cast<std::size_t>(*extension_length));
        if (!extension_end.has_value() || *extension_end > *extensions_end) {
            return std::nullopt;
        }

        const auto extension_relative_offset = checked_add(kTlsHandshakeHeaderSize, extension_offset);
        if (!extension_relative_offset.has_value()) {
            return std::nullopt;
        }
        const auto extension_source_offset = make_input_relative_offset(
            handshake_source_offset,
            *extension_relative_offset
        );
        if (!extension_source_offset.has_value()) {
            return std::nullopt;
        }

        TlsExtensionModel extension {
            .source_offset = *extension_source_offset,
            .order_index = order_index,
            .type = *extension_type,
            .known_name = known_extension_name(*extension_type),
            .declared_length = *extension_length,
        };

        const auto extension_bytes = handshake_body.subspan(offset, *extension_length);
        switch (*extension_type) {
        case 0x0000U: {
            std::vector<std::string> server_names {};
            if (parse_server_name_extension(extension_bytes, server_names)) {
                extension.server_names = server_names;
                hello.sni_names.insert(hello.sni_names.end(), server_names.begin(), server_names.end());
                extension.structured_parse_status = TlsStructuredParseStatus::parsed;
            } else {
                extension.structured_parse_status = TlsStructuredParseStatus::malformed;
            }
            break;
        }
        case 0x0010U: {
            std::vector<std::string> alpn_protocols {};
            if (parse_alpn_extension(extension_bytes, alpn_protocols)) {
                extension.alpn_protocols = alpn_protocols;
                hello.alpn_protocols.insert(hello.alpn_protocols.end(), alpn_protocols.begin(), alpn_protocols.end());
                extension.structured_parse_status = TlsStructuredParseStatus::parsed;
            } else {
                extension.structured_parse_status = TlsStructuredParseStatus::malformed;
            }
            break;
        }
        case 0x002BU: {
            std::vector<std::uint16_t> supported_versions {};
            if (parse_supported_versions_client_extension(extension_bytes, supported_versions)) {
                extension.supported_versions = supported_versions;
                hello.supported_versions.insert(
                    hello.supported_versions.end(),
                    supported_versions.begin(),
                    supported_versions.end()
                );
                extension.structured_parse_status = TlsStructuredParseStatus::parsed;
            } else {
                extension.structured_parse_status = TlsStructuredParseStatus::malformed;
            }
            break;
        }
        case 0x000AU: {
            std::vector<std::uint16_t> supported_group_ids {};
            if (parse_supported_groups_extension(extension_bytes, supported_group_ids)) {
                extension.supported_group_ids = std::move(supported_group_ids);
                extension.structured_parse_status = TlsStructuredParseStatus::parsed;
            } else {
                extension.structured_parse_status = TlsStructuredParseStatus::malformed;
            }
            break;
        }
        case 0x000DU: {
            std::vector<std::uint16_t> signature_scheme_ids {};
            if (parse_signature_algorithms_extension(extension_bytes, signature_scheme_ids)) {
                extension.signature_scheme_ids = std::move(signature_scheme_ids);
                extension.structured_parse_status = TlsStructuredParseStatus::parsed;
            } else {
                extension.structured_parse_status = TlsStructuredParseStatus::malformed;
            }
            break;
        }
        case 0x0033U: {
            std::vector<TlsKeyShareEntryModel> key_share_entries {};
            if (parse_client_key_share_extension(extension_bytes, key_share_entries)) {
                extension.key_share_entries = std::move(key_share_entries);
                extension.structured_parse_status = TlsStructuredParseStatus::parsed;
            } else {
                extension.structured_parse_status = TlsStructuredParseStatus::malformed;
            }
            break;
        }
        case 0x002DU: {
            std::vector<std::uint8_t> psk_key_exchange_mode_ids {};
            if (parse_psk_key_exchange_modes_extension(extension_bytes, psk_key_exchange_mode_ids)) {
                extension.psk_key_exchange_mode_ids = std::move(psk_key_exchange_mode_ids);
                extension.structured_parse_status = TlsStructuredParseStatus::parsed;
            } else {
                extension.structured_parse_status = TlsStructuredParseStatus::malformed;
            }
            break;
        }
        case 0x0005U: {
            TlsStatusRequestModel status_request {};
            if (parse_status_request_extension(extension_bytes, status_request)) {
                extension.status_request = status_request;
                extension.structured_parse_status = TlsStructuredParseStatus::parsed;
            } else {
                extension.structured_parse_status = TlsStructuredParseStatus::malformed;
            }
            break;
        }
        case 0x001BU: {
            std::vector<std::uint16_t> certificate_compression_algorithm_ids {};
            if (parse_compress_certificate_extension(extension_bytes, certificate_compression_algorithm_ids)) {
                extension.certificate_compression_algorithm_ids = std::move(certificate_compression_algorithm_ids);
                extension.structured_parse_status = TlsStructuredParseStatus::parsed;
            } else {
                extension.structured_parse_status = TlsStructuredParseStatus::malformed;
            }
            break;
        }
        case 0x0015U:
            extension.padding_length = parse_padding_extension(extension_bytes);
            extension.structured_parse_status = TlsStructuredParseStatus::parsed;
            break;
        default:
            break;
        }

        hello.extensions.push_back(std::move(extension));
        offset = *extension_end;
        ++order_index;
    }

    if (offset != *extensions_end) {
        return std::nullopt;
    }

    return hello;
}

std::optional<TlsServerHelloModel> parse_server_hello_body(
    std::span<const std::uint8_t> handshake_body,
    const std::size_t handshake_source_offset
) {
    if (handshake_body.size() < 38U) {
        return std::nullopt;
    }

    TlsServerHelloModel hello {};
    const auto legacy_version = read_be16(handshake_body, 0U);
    if (!legacy_version.has_value()) {
        return std::nullopt;
    }
    hello.legacy_version = *legacy_version;
    hello.selected_tls_version = *legacy_version;
    std::copy_n(handshake_body.begin() + static_cast<std::ptrdiff_t>(2U), 32, hello.random.begin());

    std::size_t offset = 34U;
    const auto session_id_length = static_cast<std::size_t>(handshake_body[offset]);
    ++offset;
    if (offset + session_id_length + 3U > handshake_body.size()) {
        return std::nullopt;
    }

    hello.session_id.assign(
        handshake_body.begin() + static_cast<std::ptrdiff_t>(offset),
        handshake_body.begin() + static_cast<std::ptrdiff_t>(offset + session_id_length)
    );
    offset += session_id_length;

    const auto selected_cipher_suite = read_be16(handshake_body, offset);
    if (!selected_cipher_suite.has_value()) {
        return std::nullopt;
    }
    hello.selected_cipher_suite = *selected_cipher_suite;
    offset += 2U;

    hello.compression_method = handshake_body[offset];
    ++offset;

    if (offset == handshake_body.size()) {
        return hello;
    }
    if (offset + 2U > handshake_body.size()) {
        return std::nullopt;
    }

    const auto extensions_length = read_be16(handshake_body, offset);
    if (!extensions_length.has_value()) {
        return std::nullopt;
    }
    offset += 2U;
    const auto extensions_end = checked_add(offset, static_cast<std::size_t>(*extensions_length));
    if (!extensions_end.has_value() || *extensions_end != handshake_body.size()) {
        return std::nullopt;
    }

    std::size_t order_index = 0U;
    while (offset < *extensions_end) {
        const auto extension_offset = offset;
        const auto extension_header_end = checked_add(offset, 4U);
        if (!extension_header_end.has_value() || *extension_header_end > *extensions_end) {
            return std::nullopt;
        }

        const auto extension_type = read_be16(handshake_body, offset);
        const auto extension_length = read_be16(handshake_body, offset + 2U);
        if (!extension_type.has_value() || !extension_length.has_value()) {
            return std::nullopt;
        }

        offset += 4U;
        const auto extension_end = checked_add(offset, static_cast<std::size_t>(*extension_length));
        if (!extension_end.has_value() || *extension_end > *extensions_end) {
            return std::nullopt;
        }

        const auto extension_relative_offset = checked_add(kTlsHandshakeHeaderSize, extension_offset);
        if (!extension_relative_offset.has_value()) {
            return std::nullopt;
        }
        const auto extension_source_offset = make_input_relative_offset(
            handshake_source_offset,
            *extension_relative_offset
        );
        if (!extension_source_offset.has_value()) {
            return std::nullopt;
        }

        TlsExtensionModel extension {
            .source_offset = *extension_source_offset,
            .order_index = order_index,
            .type = *extension_type,
            .known_name = known_extension_name(*extension_type),
            .declared_length = *extension_length,
        };

        const auto extension_bytes = handshake_body.subspan(offset, *extension_length);
        if (*extension_type == 0x002BU) {
            auto selected_tls_version = hello.selected_tls_version;
            std::vector<std::uint16_t> supported_versions {};
            if (parse_supported_versions_server_extension(extension_bytes, supported_versions, selected_tls_version)) {
                extension.supported_versions = std::move(supported_versions);
                hello.selected_tls_version = selected_tls_version;
                extension.structured_parse_status = TlsStructuredParseStatus::parsed;
            } else {
                extension.structured_parse_status = TlsStructuredParseStatus::malformed;
            }
        } else if (*extension_type == 0x0033U) {
            if (extension_bytes.size() == 2U) {
                extension.structured_parse_status = TlsStructuredParseStatus::not_attempted;
            } else {
                std::vector<TlsKeyShareEntryModel> key_share_entries {};
                if (parse_server_key_share_extension(extension_bytes, key_share_entries)) {
                    extension.key_share_entries = std::move(key_share_entries);
                    extension.structured_parse_status = TlsStructuredParseStatus::parsed;
                } else {
                    extension.structured_parse_status = TlsStructuredParseStatus::malformed;
                }
            }
        }

        hello.extensions.push_back(std::move(extension));
        offset = *extension_end;
        ++order_index;
    }

    if (offset != *extensions_end) {
        return std::nullopt;
    }

    return hello;
}

std::vector<TlsHandshakeModel> parse_handshake_messages(
    std::span<const std::uint8_t> record_body,
    const std::size_t record_source_offset,
    const std::optional<std::uint16_t> record_legacy_version
) {
    std::vector<TlsHandshakeModel> handshakes {};
    std::size_t offset = 0U;
    const auto record_body_source_offset = checked_add(record_source_offset, kTlsRecordHeaderSize);
    if (!record_body_source_offset.has_value()) {
        return handshakes;
    }

    while (offset < record_body.size()) {
        const auto handshake_source_offset = checked_add(*record_body_source_offset, offset);
        if (!handshake_source_offset.has_value()) {
            break;
        }

        TlsHandshakeModel handshake {
            .source_offset = *handshake_source_offset,
            .available_bytes = record_body.size() - offset,
        };

        if (handshake.available_bytes >= 1U) {
            handshake.type = record_body[offset];
            handshake.kind = classify_handshake_type(*handshake.type);
        }

        if (handshake.available_bytes < kTlsHandshakeHeaderSize) {
            handshake.status = TlsHandshakeStatus::partial_header;
            handshakes.push_back(std::move(handshake));
            break;
        }

        const auto handshake_length = read_be24(record_body, offset + 1U);
        if (!handshake_length.has_value()) {
            handshake.status = TlsHandshakeStatus::partial_header;
            handshakes.push_back(std::move(handshake));
            break;
        }

        handshake.declared_body_length = *handshake_length;
        handshake.total_size = checked_add(kTlsHandshakeHeaderSize, static_cast<std::size_t>(*handshake_length));
        if (!handshake.total_size.has_value() || handshake.total_size.value() > handshake.available_bytes) {
            handshake.status = TlsHandshakeStatus::partial_body;
            handshakes.push_back(std::move(handshake));
            break;
        }

        handshake.status = TlsHandshakeStatus::complete;
        handshake.available_bytes = *handshake.total_size;
        const auto handshake_body = record_body.subspan(offset + kTlsHandshakeHeaderSize, *handshake_length);
        switch (handshake.kind) {
        case TlsHandshakeKind::client_hello: {
            const auto client_hello = parse_client_hello_body(handshake_body, handshake.source_offset);
            if (client_hello.has_value()) {
                handshake.client_hello = std::move(*client_hello);
                handshake.structured_parse_status = TlsStructuredParseStatus::parsed;
            } else {
                handshake.structured_parse_status = TlsStructuredParseStatus::malformed;
            }
            break;
        }
        case TlsHandshakeKind::server_hello: {
            const auto server_hello = parse_server_hello_body(handshake_body, handshake.source_offset);
            if (server_hello.has_value()) {
                handshake.server_hello = std::move(*server_hello);
                handshake.structured_parse_status = TlsStructuredParseStatus::parsed;
            } else {
                handshake.structured_parse_status = TlsStructuredParseStatus::malformed;
            }
            break;
        }
        case TlsHandshakeKind::new_session_ticket: {
            const auto new_session_ticket = parse_new_session_ticket_body(handshake_body);
            if (new_session_ticket.has_value()) {
                handshake.new_session_ticket = std::move(*new_session_ticket);
                handshake.structured_parse_status = TlsStructuredParseStatus::parsed;
            } else {
                handshake.structured_parse_status = TlsStructuredParseStatus::malformed;
            }
            break;
        }
        case TlsHandshakeKind::certificate: {
            const auto certificate = parse_certificate_body(handshake_body);
            if (certificate.has_value()) {
                handshake.certificate = std::move(*certificate);
                handshake.structured_parse_status = TlsStructuredParseStatus::parsed;
            } else {
                handshake.structured_parse_status = TlsStructuredParseStatus::malformed;
            }
            break;
        }
        case TlsHandshakeKind::certificate_request: {
            if (record_legacy_version != std::optional<std::uint16_t> {0x0303U}) {
                handshake.structured_parse_status = TlsStructuredParseStatus::not_attempted;
                break;
            }

            const auto certificate_request = parse_tls12_certificate_request_body(handshake_body);
            if (certificate_request.has_value()) {
                handshake.certificate_request = std::move(*certificate_request);
                handshake.structured_parse_status = TlsStructuredParseStatus::parsed;
            } else {
                handshake.structured_parse_status = TlsStructuredParseStatus::malformed;
            }
            break;
        }
        default:
            handshake.structured_parse_status = TlsStructuredParseStatus::not_attempted;
            break;
        }

        handshakes.push_back(std::move(handshake));
        offset += handshake.total_size.value();
    }

    return handshakes;
}

}  // namespace

TlsInspectionResult TlsInspectionParser::inspect(std::span<const std::uint8_t> tls_bytes) const {
    TlsInspectionResult result {
        .total_input_bytes = tls_bytes.size(),
    };

    std::size_t offset = 0U;
    bool post_change_cipher_spec = false;
    while (offset < tls_bytes.size()) {
        TlsRecordModel record {
            .source_offset = offset,
            .available_bytes = tls_bytes.size() - offset,
        };

        if (record.available_bytes >= 1U) {
            record.content_type = tls_bytes[offset];
            record.content_type_kind = classify_record_content_type(*record.content_type);
        }
        if (record.available_bytes >= 3U) {
            record.legacy_version = read_be16(tls_bytes, offset + 1U);
        }

        if (record.available_bytes < kTlsRecordHeaderSize) {
            record.status = TlsRecordStatus::partial_header;
            result.records.push_back(std::move(record));
            result.consumed_bytes = tls_bytes.size();
            result.stopped_after_partial_record = true;
            return result;
        }

        const auto declared_payload_length = read_be16(tls_bytes, offset + 3U);
        if (!declared_payload_length.has_value()) {
            record.status = TlsRecordStatus::partial_header;
            result.records.push_back(std::move(record));
            result.consumed_bytes = tls_bytes.size();
            result.stopped_after_partial_record = true;
            return result;
        }

        record.declared_payload_length = *declared_payload_length;
        record.total_size = checked_add(kTlsRecordHeaderSize, *declared_payload_length);
        if (!record.total_size.has_value()) {
            record.status = TlsRecordStatus::partial_body;
            result.records.push_back(std::move(record));
            result.consumed_bytes = tls_bytes.size();
            result.stopped_after_partial_record = true;
            return result;
        }

        const auto record_end = checked_add(offset, *record.total_size);
        if (!record_end.has_value() || *record_end > tls_bytes.size()) {
            record.status = TlsRecordStatus::partial_body;
            if (record.content_type_kind == TlsRecordContentTypeKind::handshake) {
                if (post_change_cipher_spec) {
                    record.handshake_payload_kind = TlsHandshakePayloadKind::encrypted_opaque;
                } else {
                    record.handshake_payload_kind = TlsHandshakePayloadKind::plaintext;
                    const auto available_record_body_bytes = tls_bytes.size() - (offset + kTlsRecordHeaderSize);
                    record.handshake_messages = parse_handshake_messages(
                        tls_bytes.subspan(offset + kTlsRecordHeaderSize, available_record_body_bytes),
                        offset,
                        record.legacy_version
                    );
                }
            }
            result.records.push_back(std::move(record));
            result.consumed_bytes = tls_bytes.size();
            result.stopped_after_partial_record = true;
            return result;
        }

        record.status = TlsRecordStatus::complete;
        record.available_bytes = *record.total_size;
        if (record.content_type_kind == TlsRecordContentTypeKind::handshake) {
            if (post_change_cipher_spec) {
                record.handshake_payload_kind = TlsHandshakePayloadKind::encrypted_opaque;
            } else {
                record.handshake_payload_kind = TlsHandshakePayloadKind::plaintext;
                record.handshake_messages = parse_handshake_messages(
                    tls_bytes.subspan(offset + kTlsRecordHeaderSize, *record.declared_payload_length),
                    offset,
                    record.legacy_version
                );
            }
        }

        result.records.push_back(std::move(record));
        if (result.records.back().content_type_kind == TlsRecordContentTypeKind::change_cipher_spec) {
            post_change_cipher_spec = true;
        }
        offset += *result.records.back().total_size;
    }

    result.consumed_bytes = offset;
    result.unparsed_trailing_bytes = tls_bytes.size() - offset;
    return result;
}

}  // namespace pfl
