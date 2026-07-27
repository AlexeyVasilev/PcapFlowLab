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

bool add_overflows(const std::size_t left, const std::size_t right) {
    return right > (static_cast<std::size_t>(-1) - left);
}

std::optional<std::size_t> checked_add(const std::size_t left, const std::size_t right) {
    if (add_overflows(left, right)) {
        return std::nullopt;
    }
    return left + right;
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
    TlsExtensionModel& extension,
    std::vector<std::string>& out_server_names
) {
    const auto server_name_list_length = read_be16(extension_bytes, 0U);
    if (!server_name_list_length.has_value()) {
        return false;
    }
    if (*server_name_list_length + 2U > extension_bytes.size()) {
        return false;
    }

    std::size_t offset = 2U;
    const auto names_end = 2U + static_cast<std::size_t>(*server_name_list_length);
    while (offset < names_end) {
        if (offset + 3U > names_end) {
            return false;
        }

        const auto name_type = extension_bytes[offset];
        const auto name_length = read_be16(extension_bytes, offset + 1U);
        if (!name_length.has_value()) {
            return false;
        }

        offset += 3U;
        if (offset + *name_length > names_end) {
            return false;
        }

        if (name_type == 0U) {
            auto name = bytes_to_text(extension_bytes.subspan(offset, *name_length));
            extension.server_names.push_back(name);
            out_server_names.push_back(std::move(name));
        }
        offset += *name_length;
    }

    return offset == names_end;
}

bool parse_alpn_extension(
    std::span<const std::uint8_t> extension_bytes,
    TlsExtensionModel& extension,
    std::vector<std::string>& out_alpn_protocols
) {
    const auto alpn_length = read_be16(extension_bytes, 0U);
    if (!alpn_length.has_value()) {
        return false;
    }
    if (*alpn_length + 2U > extension_bytes.size()) {
        return false;
    }

    std::size_t offset = 2U;
    const auto protocols_end = 2U + static_cast<std::size_t>(*alpn_length);
    while (offset < protocols_end) {
        if (offset + 1U > protocols_end) {
            return false;
        }

        const auto protocol_length = static_cast<std::size_t>(extension_bytes[offset]);
        ++offset;
        if (offset + protocol_length > protocols_end) {
            return false;
        }

        auto protocol = bytes_to_text(extension_bytes.subspan(offset, protocol_length));
        extension.alpn_protocols.push_back(protocol);
        out_alpn_protocols.push_back(std::move(protocol));
        offset += protocol_length;
    }

    return offset == protocols_end;
}

bool parse_supported_versions_client_extension(
    std::span<const std::uint8_t> extension_bytes,
    TlsExtensionModel& extension,
    std::vector<std::uint16_t>& out_supported_versions
) {
    if (extension_bytes.empty()) {
        return false;
    }

    const auto versions_length = static_cast<std::size_t>(extension_bytes[0]);
    if (1U + versions_length > extension_bytes.size() || (versions_length % 2U) != 0U) {
        return false;
    }

    for (std::size_t offset = 1U; offset < 1U + versions_length; offset += 2U) {
        const auto version = read_be16(extension_bytes, offset);
        if (!version.has_value()) {
            return false;
        }
        extension.supported_versions.push_back(*version);
        out_supported_versions.push_back(*version);
    }

    return true;
}

bool parse_supported_versions_server_extension(
    std::span<const std::uint8_t> extension_bytes,
    TlsExtensionModel& extension,
    std::uint16_t& out_selected_tls_version
) {
    const auto version = read_be16(extension_bytes, 0U);
    if (!version.has_value() || extension_bytes.size() != 2U) {
        return false;
    }

    extension.supported_versions.push_back(*version);
    out_selected_tls_version = *version;
    return true;
}

std::optional<TlsClientHelloModel> parse_client_hello_body(std::span<const std::uint8_t> handshake_body) {
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
    if (offset + *extensions_length > handshake_body.size()) {
        return std::nullopt;
    }

    const auto extensions_end = offset + *extensions_length;
    std::size_t order_index = 0U;
    while (offset < extensions_end) {
        if (offset + 4U > extensions_end) {
            return std::nullopt;
        }

        const auto extension_type = read_be16(handshake_body, offset);
        const auto extension_length = read_be16(handshake_body, offset + 2U);
        if (!extension_type.has_value() || !extension_length.has_value()) {
            return std::nullopt;
        }

        offset += 4U;
        if (offset + *extension_length > extensions_end) {
            return std::nullopt;
        }

        TlsExtensionModel extension {
            .source_offset = offset - 4U,
            .order_index = order_index,
            .type = *extension_type,
            .known_name = known_extension_name(*extension_type),
            .declared_length = *extension_length,
        };

        const auto extension_bytes = handshake_body.subspan(offset, *extension_length);
        switch (*extension_type) {
        case 0x0000U:
            if (!parse_server_name_extension(extension_bytes, extension, hello.sni_names)) {
                return std::nullopt;
            }
            break;
        case 0x0010U:
            if (!parse_alpn_extension(extension_bytes, extension, hello.alpn_protocols)) {
                return std::nullopt;
            }
            break;
        case 0x002BU:
            if (!parse_supported_versions_client_extension(extension_bytes, extension, hello.supported_versions)) {
                return std::nullopt;
            }
            break;
        default:
            break;
        }

        hello.extensions.push_back(std::move(extension));
        offset += *extension_length;
        ++order_index;
    }

    if (offset != extensions_end) {
        return std::nullopt;
    }

    return hello;
}

std::optional<TlsServerHelloModel> parse_server_hello_body(std::span<const std::uint8_t> handshake_body) {
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
    if (offset + *extensions_length > handshake_body.size()) {
        return std::nullopt;
    }

    const auto extensions_end = offset + *extensions_length;
    std::size_t order_index = 0U;
    while (offset < extensions_end) {
        if (offset + 4U > extensions_end) {
            return std::nullopt;
        }

        const auto extension_type = read_be16(handshake_body, offset);
        const auto extension_length = read_be16(handshake_body, offset + 2U);
        if (!extension_type.has_value() || !extension_length.has_value()) {
            return std::nullopt;
        }

        offset += 4U;
        if (offset + *extension_length > extensions_end) {
            return std::nullopt;
        }

        TlsExtensionModel extension {
            .source_offset = offset - 4U,
            .order_index = order_index,
            .type = *extension_type,
            .known_name = known_extension_name(*extension_type),
            .declared_length = *extension_length,
        };

        const auto extension_bytes = handshake_body.subspan(offset, *extension_length);
        if (*extension_type == 0x002BU) {
            if (!parse_supported_versions_server_extension(extension_bytes, extension, hello.selected_tls_version)) {
                return std::nullopt;
            }
        }

        hello.extensions.push_back(std::move(extension));
        offset += *extension_length;
        ++order_index;
    }

    if (offset != extensions_end) {
        return std::nullopt;
    }

    return hello;
}

std::vector<TlsHandshakeModel> parse_handshake_messages(
    std::span<const std::uint8_t> record_body,
    const std::size_t record_source_offset
) {
    std::vector<TlsHandshakeModel> handshakes {};
    std::size_t offset = 0U;

    while (offset < record_body.size()) {
        TlsHandshakeModel handshake {
            .source_offset = record_source_offset + kTlsRecordHeaderSize + offset,
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
        const auto handshake_body = record_body.subspan(offset + kTlsHandshakeHeaderSize, *handshake_length);
        switch (handshake.kind) {
        case TlsHandshakeKind::client_hello: {
            const auto client_hello = parse_client_hello_body(handshake_body);
            if (client_hello.has_value()) {
                handshake.client_hello = std::move(*client_hello);
                handshake.structured_parse_status = TlsStructuredParseStatus::parsed;
            } else {
                handshake.structured_parse_status = TlsStructuredParseStatus::malformed;
            }
            break;
        }
        case TlsHandshakeKind::server_hello: {
            const auto server_hello = parse_server_hello_body(handshake_body);
            if (server_hello.has_value()) {
                handshake.server_hello = std::move(*server_hello);
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
            result.records.push_back(std::move(record));
            result.consumed_bytes = tls_bytes.size();
            result.stopped_after_partial_record = true;
            return result;
        }

        record.status = TlsRecordStatus::complete;
        if (record.content_type_kind == TlsRecordContentTypeKind::handshake) {
            record.handshake_messages = parse_handshake_messages(
                tls_bytes.subspan(offset + kTlsRecordHeaderSize, *record.declared_payload_length),
                offset
            );
        }

        result.records.push_back(std::move(record));
        offset += *result.records.back().total_size;
    }

    result.consumed_bytes = offset;
    result.unparsed_trailing_bytes = tls_bytes.size() - offset;
    return result;
}

}  // namespace pfl
