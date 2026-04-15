#include "app/session/SessionTlsPresentation.h"

#include <algorithm>
#include <array>
#include <iomanip>
#include <initializer_list>
#include <optional>
#include <sstream>
#include <utility>

#include "app/session/CaptureSession.h"
#include "core/reassembly/ReassemblyTypes.h"
#include "core/services/HexDumpService.h"

namespace pfl::session_detail {

namespace {

constexpr std::size_t kTlsRecordHeaderSize = 5U;

bool contains_text(const std::string_view text, const std::string_view needle) noexcept {
    return text.find(needle) != std::string_view::npos;
}

std::uint16_t read_be16(std::span<const std::uint8_t> bytes, const std::size_t offset) noexcept {
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(bytes[offset]) << 8U) |
                                      static_cast<std::uint16_t>(bytes[offset + 1U]));
}

std::uint32_t read_be24(std::span<const std::uint8_t> bytes, const std::size_t offset) noexcept {
    return (static_cast<std::uint32_t>(bytes[offset]) << 16U) |
           (static_cast<std::uint32_t>(bytes[offset + 1U]) << 8U) |
           static_cast<std::uint32_t>(bytes[offset + 2U]);
}

bool looks_like_tls_record_prefix(std::span<const std::uint8_t> payload, const std::size_t offset = 0U) noexcept {
    if (offset > payload.size() || payload.size() - offset < kTlsRecordHeaderSize) {
        return false;
    }

    const auto content_type = payload[offset];
    if (content_type < 20U || content_type > 23U) {
        return false;
    }

    return payload[offset + 1U] == 0x03U && payload[offset + 2U] <= 0x04U;
}

std::optional<std::size_t> tls_record_size(std::span<const std::uint8_t> payload, const std::size_t offset = 0U) noexcept {
    if (!looks_like_tls_record_prefix(payload, offset)) {
        return std::nullopt;
    }

    const auto record_body_length = static_cast<std::size_t>(read_be16(payload, offset + 3U));
    const auto record_size = kTlsRecordHeaderSize + record_body_length;
    if (payload.size() - offset < record_size) {
        return std::nullopt;
    }

    return record_size;
}

std::string tls_record_version_text(const std::uint16_t version) {
    switch (version) {
    case 0x0301U:
        return "TLS 1.0 (0x0301)";
    case 0x0302U:
        return "TLS 1.1 (0x0302)";
    case 0x0303U:
        return "TLS 1.2 (0x0303)";
    case 0x0304U:
        return "TLS 1.3 (0x0304)";
    default: {
        std::ostringstream builder {};
        builder << "0x" << std::hex << version;
        return builder.str();
    }
    }
}

std::string bytes_to_text(std::span<const std::uint8_t> bytes) {
    return std::string(reinterpret_cast<const char*>(bytes.data()), bytes.size());
}

std::string bytes_to_hex_compact(std::span<const std::uint8_t> bytes) {
    if (bytes.empty()) {
        return "<empty>";
    }

    std::ostringstream text {};
    text << std::hex << std::setfill('0');
    for (std::size_t index = 0U; index < bytes.size(); ++index) {
        if (index > 0U) {
            text << ' ';
        }
        text << std::setw(2) << static_cast<unsigned int>(bytes[index]);
    }
    return text.str();
}

std::string tls_cipher_suite_text(const std::uint16_t cipher_suite) {
    switch (cipher_suite) {
    case 0x002FU:
        return "TLS_RSA_WITH_AES_128_CBC_SHA (0x002f)";
    case 0x0035U:
        return "TLS_RSA_WITH_AES_256_CBC_SHA (0x0035)";
    case 0x009CU:
        return "TLS_RSA_WITH_AES_128_GCM_SHA256 (0x009c)";
    case 0x009DU:
        return "TLS_RSA_WITH_AES_256_GCM_SHA384 (0x009d)";
    case 0x1301U:
        return "TLS_AES_128_GCM_SHA256 (0x1301)";
    case 0x1302U:
        return "TLS_AES_256_GCM_SHA384 (0x1302)";
    case 0x1303U:
        return "TLS_CHACHA20_POLY1305_SHA256 (0x1303)";
    case 0xC02BU:
        return "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (0xc02b)";
    case 0xC02CU:
        return "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 (0xc02c)";
    case 0xC02FU:
        return "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xc02f)";
    case 0xC030U:
        return "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (0xc030)";
    case 0xC013U:
        return "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (0xc013)";
    case 0xC014U:
        return "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA (0xc014)";
    case 0xCCA8U:
        return "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (0xcca8)";
    case 0xCCA9U:
        return "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 (0xcca9)";
    default: {
        std::ostringstream builder {};
        builder << "0x" << std::hex << std::setfill('0') << std::setw(4) << cipher_suite;
        return builder.str();
    }
    }
}

std::string tls_extension_type_text(const std::uint16_t extension_type) {
    switch (extension_type) {
    case 0x0000U:
        return "server_name";
    case 0x0005U:
        return "status_request";
    case 0x000AU:
        return "supported_groups";
    case 0x000BU:
        return "ec_point_formats";
    case 0x000DU:
        return "signature_algorithms";
    case 0x0010U:
        return "application_layer_protocol_negotiation";
    case 0x0012U:
        return "signed_certificate_timestamp";
    case 0x0015U:
        return "padding";
    case 0x0017U:
        return "extended_master_secret";
    case 0x0023U:
        return "session_ticket";
    case 0x002BU:
        return "supported_versions";
    case 0x002DU:
        return "psk_key_exchange_modes";
    case 0x0033U:
        return "key_share";
    case 0xFF01U:
        return "renegotiation_info";
    default: {
        std::ostringstream builder {};
        builder << "0x" << std::hex << std::setfill('0') << std::setw(4) << extension_type;
        return builder.str();
    }
    }
}

std::string join_limited_texts(const std::vector<std::string>& values, const std::size_t limit = 8U) {
    if (values.empty()) {
        return "<none>";
    }

    std::ostringstream text {};
    const auto emit_count = std::min(values.size(), limit);
    for (std::size_t index = 0U; index < emit_count; ++index) {
        if (index > 0U) {
            text << ", ";
        }
        text << values[index];
    }
    if (values.size() > emit_count) {
        text << " (" << values.size() << " total)";
    }
    return text.str();
}

struct Asn1Element {
    std::uint8_t tag {0U};
    std::size_t value_offset {0U};
    std::size_t length {0U};
};

std::optional<Asn1Element> parse_asn1_element(std::span<const std::uint8_t> bytes, const std::size_t offset) {
    if (offset >= bytes.size()) {
        return std::nullopt;
    }

    const auto tag = bytes[offset];
    if (offset + 1U >= bytes.size()) {
        return std::nullopt;
    }

    const auto length_byte = bytes[offset + 1U];
    std::size_t header_size = 2U;
    std::size_t length = 0U;
    if ((length_byte & 0x80U) == 0U) {
        length = length_byte;
    } else {
        const auto length_octets = static_cast<std::size_t>(length_byte & 0x7FU);
        if (length_octets == 0U || length_octets > sizeof(std::size_t) || offset + 2U + length_octets > bytes.size()) {
            return std::nullopt;
        }

        header_size += length_octets;
        for (std::size_t index = 0U; index < length_octets; ++index) {
            length = (length << 8U) | bytes[offset + 2U + index];
        }
    }

    if (offset + header_size + length > bytes.size()) {
        return std::nullopt;
    }

    return Asn1Element {
        .tag = tag,
        .value_offset = offset + header_size,
        .length = length,
    };
}

std::optional<std::span<const std::uint8_t>> asn1_element_value(std::span<const std::uint8_t> bytes, const Asn1Element& element) {
    if (element.value_offset + element.length > bytes.size()) {
        return std::nullopt;
    }
    return bytes.subspan(element.value_offset, element.length);
}

bool asn1_oid_equals(std::span<const std::uint8_t> value, std::initializer_list<std::uint8_t> expected) {
    if (value.size() != expected.size()) {
        return false;
    }
    return std::equal(value.begin(), value.end(), expected.begin(), expected.end());
}

std::string asn1_string_value(std::span<const std::uint8_t> value) {
    return bytes_to_text(value);
}

std::optional<std::string> extract_name_common_name(std::span<const std::uint8_t> name_bytes) {
    const auto sequence = parse_asn1_element(name_bytes, 0U);
    if (!sequence.has_value() || sequence->tag != 0x30U) {
        return std::nullopt;
    }

    auto content = asn1_element_value(name_bytes, *sequence);
    if (!content.has_value()) {
        return std::nullopt;
    }

    std::size_t offset = 0U;
    while (offset < content->size()) {
        const auto set = parse_asn1_element(*content, offset);
        if (!set.has_value() || set->tag != 0x31U) {
            return std::nullopt;
        }
        auto set_value = asn1_element_value(*content, *set);
        if (!set_value.has_value()) {
            return std::nullopt;
        }

        const auto attribute = parse_asn1_element(*set_value, 0U);
        if (!attribute.has_value() || attribute->tag != 0x30U) {
            return std::nullopt;
        }
        auto attribute_value = asn1_element_value(*set_value, *attribute);
        if (!attribute_value.has_value()) {
            return std::nullopt;
        }

        const auto oid = parse_asn1_element(*attribute_value, 0U);
        if (!oid.has_value() || oid->tag != 0x06U) {
            return std::nullopt;
        }
        auto oid_value = asn1_element_value(*attribute_value, *oid);
        if (!oid_value.has_value()) {
            return std::nullopt;
        }

        const auto string_offset = oid->value_offset + oid->length;
        const auto string_element = parse_asn1_element(*attribute_value, string_offset);
        if (!string_element.has_value()) {
            return std::nullopt;
        }
        auto string_value = asn1_element_value(*attribute_value, *string_element);
        if (!string_value.has_value()) {
            return std::nullopt;
        }

        if (asn1_oid_equals(*oid_value, {0x55U, 0x04U, 0x03U})) {
            return asn1_string_value(*string_value);
        }

        offset = set->value_offset + set->length;
    }

    return std::nullopt;
}

std::optional<std::pair<std::string, std::string>> extract_certificate_validity(std::span<const std::uint8_t> validity_bytes) {
    const auto sequence = parse_asn1_element(validity_bytes, 0U);
    if (!sequence.has_value() || sequence->tag != 0x30U) {
        return std::nullopt;
    }

    auto content = asn1_element_value(validity_bytes, *sequence);
    if (!content.has_value()) {
        return std::nullopt;
    }

    const auto not_before = parse_asn1_element(*content, 0U);
    if (!not_before.has_value()) {
        return std::nullopt;
    }
    auto not_before_value = asn1_element_value(*content, *not_before);
    if (!not_before_value.has_value()) {
        return std::nullopt;
    }

    const auto not_after = parse_asn1_element(*content, not_before->value_offset + not_before->length);
    if (!not_after.has_value()) {
        return std::nullopt;
    }
    auto not_after_value = asn1_element_value(*content, *not_after);
    if (!not_after_value.has_value()) {
        return std::nullopt;
    }

    return std::pair<std::string, std::string> {
        asn1_string_value(*not_before_value),
        asn1_string_value(*not_after_value),
    };
}

struct ParsedCertificateSummary {
    std::string subject_common_name {};
    std::string issuer_common_name {};
    std::string valid_from {};
    std::string valid_to {};
    std::vector<std::string> dns_names {};
};

std::optional<ParsedCertificateSummary> parse_certificate_summary(std::span<const std::uint8_t> certificate_bytes) {
    const auto certificate = parse_asn1_element(certificate_bytes, 0U);
    if (!certificate.has_value() || certificate->tag != 0x30U) {
        return std::nullopt;
    }
    auto certificate_value = asn1_element_value(certificate_bytes, *certificate);
    if (!certificate_value.has_value()) {
        return std::nullopt;
    }

    const auto tbs = parse_asn1_element(*certificate_value, 0U);
    if (!tbs.has_value() || tbs->tag != 0x30U) {
        return std::nullopt;
    }
    auto tbs_value = asn1_element_value(*certificate_value, *tbs);
    if (!tbs_value.has_value()) {
        return std::nullopt;
    }

    std::size_t offset = 0U;
    const auto first = parse_asn1_element(*tbs_value, offset);
    if (!first.has_value()) {
        return std::nullopt;
    }
    if (first->tag == 0xA0U) {
        offset = first->value_offset + first->length;
    }

    const auto serial = parse_asn1_element(*tbs_value, offset);
    if (!serial.has_value()) {
        return std::nullopt;
    }
    offset = serial->value_offset + serial->length;

    const auto signature = parse_asn1_element(*tbs_value, offset);
    if (!signature.has_value()) {
        return std::nullopt;
    }
    offset = signature->value_offset + signature->length;

    const auto issuer = parse_asn1_element(*tbs_value, offset);
    if (!issuer.has_value()) {
        return std::nullopt;
    }
    auto issuer_value = asn1_element_value(*tbs_value, *issuer);
    if (!issuer_value.has_value()) {
        return std::nullopt;
    }
    offset = issuer->value_offset + issuer->length;

    const auto validity = parse_asn1_element(*tbs_value, offset);
    if (!validity.has_value()) {
        return std::nullopt;
    }
    auto validity_value = asn1_element_value(*tbs_value, *validity);
    if (!validity_value.has_value()) {
        return std::nullopt;
    }
    offset = validity->value_offset + validity->length;

    const auto subject = parse_asn1_element(*tbs_value, offset);
    if (!subject.has_value()) {
        return std::nullopt;
    }
    auto subject_value = asn1_element_value(*tbs_value, *subject);
    if (!subject_value.has_value()) {
        return std::nullopt;
    }
    offset = subject->value_offset + subject->length;

    ParsedCertificateSummary summary {};
    if (const auto issuer_cn = extract_name_common_name(*issuer_value); issuer_cn.has_value()) {
        summary.issuer_common_name = *issuer_cn;
    }
    if (const auto subject_cn = extract_name_common_name(*subject_value); subject_cn.has_value()) {
        summary.subject_common_name = *subject_cn;
    }
    if (const auto validity_pair = extract_certificate_validity(*validity_value); validity_pair.has_value()) {
        summary.valid_from = validity_pair->first;
        summary.valid_to = validity_pair->second;
    }

    while (offset < tbs_value->size()) {
        const auto element = parse_asn1_element(*tbs_value, offset);
        if (!element.has_value()) {
            break;
        }

        if (element->tag == 0xA3U) {
            auto extensions_explicit = asn1_element_value(*tbs_value, *element);
            if (!extensions_explicit.has_value()) {
                break;
            }

            const auto extensions_seq = parse_asn1_element(*extensions_explicit, 0U);
            if (!extensions_seq.has_value() || extensions_seq->tag != 0x30U) {
                break;
            }
            auto extensions_value = asn1_element_value(*extensions_explicit, *extensions_seq);
            if (!extensions_value.has_value()) {
                break;
            }

            std::size_t ext_offset = 0U;
            while (ext_offset < extensions_value->size()) {
                const auto extension = parse_asn1_element(*extensions_value, ext_offset);
                if (!extension.has_value() || extension->tag != 0x30U) {
                    break;
                }
                auto extension_value = asn1_element_value(*extensions_value, *extension);
                if (!extension_value.has_value()) {
                    break;
                }

                const auto oid = parse_asn1_element(*extension_value, 0U);
                if (!oid.has_value() || oid->tag != 0x06U) {
                    break;
                }
                auto oid_value = asn1_element_value(*extension_value, *oid);
                if (!oid_value.has_value()) {
                    break;
                }

                std::size_t value_offset = oid->value_offset + oid->length;
                const auto maybe_critical = parse_asn1_element(*extension_value, value_offset);
                if (!maybe_critical.has_value()) {
                    break;
                }
                if (maybe_critical->tag == 0x01U) {
                    value_offset = maybe_critical->value_offset + maybe_critical->length;
                }

                const auto octet_string = parse_asn1_element(*extension_value, value_offset);
                if (!octet_string.has_value() || octet_string->tag != 0x04U) {
                    break;
                }
                auto octet_value = asn1_element_value(*extension_value, *octet_string);
                if (!octet_value.has_value()) {
                    break;
                }

                if (asn1_oid_equals(*oid_value, {0x55U, 0x1DU, 0x11U})) {
                    const auto san_seq = parse_asn1_element(*octet_value, 0U);
                    if (san_seq.has_value() && san_seq->tag == 0x30U) {
                        auto san_value = asn1_element_value(*octet_value, *san_seq);
                        if (san_value.has_value()) {
                            std::size_t san_offset = 0U;
                            while (san_offset < san_value->size()) {
                                const auto general_name = parse_asn1_element(*san_value, san_offset);
                                if (!general_name.has_value()) {
                                    break;
                                }
                                auto general_name_value = asn1_element_value(*san_value, *general_name);
                                if (!general_name_value.has_value()) {
                                    break;
                                }
                                if (general_name->tag == 0x82U) {
                                    summary.dns_names.push_back(bytes_to_text(*general_name_value));
                                }
                                san_offset = general_name->value_offset + general_name->length;
                            }
                        }
                    }
                }

                ext_offset = extension->value_offset + extension->length;
            }

            break;
        }

        offset = element->value_offset + element->length;
    }

    return summary;
}

struct ParsedTlsClientHello {
    std::string handshake_version {};
    std::string session_id {};
    std::vector<std::string> cipher_suites {};
    std::vector<std::string> extensions {};
    std::optional<std::string> sni {};
    std::vector<std::string> alpn_protocols {};
    std::vector<std::string> supported_versions {};
};

std::optional<ParsedTlsClientHello> parse_tls_client_hello(std::span<const std::uint8_t> handshake_body) {
    if (handshake_body.size() < 34U) {
        return std::nullopt;
    }

    ParsedTlsClientHello details {};
    details.handshake_version = tls_record_version_text(read_be16(handshake_body, 0U));

    std::size_t offset = 2U + 32U;
    const auto session_id_length = static_cast<std::size_t>(handshake_body[offset]);
    ++offset;
    if (offset + session_id_length + 2U > handshake_body.size()) {
        return std::nullopt;
    }
    details.session_id = bytes_to_hex_compact(handshake_body.subspan(offset, session_id_length));
    offset += session_id_length;

    const auto cipher_suites_length = static_cast<std::size_t>(read_be16(handshake_body, offset));
    offset += 2U;
    if ((cipher_suites_length % 2U) != 0U || offset + cipher_suites_length + 1U > handshake_body.size()) {
        return std::nullopt;
    }
    for (std::size_t cursor = offset; cursor < offset + cipher_suites_length; cursor += 2U) {
        details.cipher_suites.push_back(tls_cipher_suite_text(read_be16(handshake_body, cursor)));
    }
    offset += cipher_suites_length;

    const auto compression_methods_length = static_cast<std::size_t>(handshake_body[offset]);
    ++offset;
    if (offset + compression_methods_length > handshake_body.size()) {
        return std::nullopt;
    }
    offset += compression_methods_length;

    if (offset == handshake_body.size()) {
        return details;
    }
    if (offset + 2U > handshake_body.size()) {
        return std::nullopt;
    }

    const auto extensions_length = static_cast<std::size_t>(read_be16(handshake_body, offset));
    offset += 2U;
    if (offset + extensions_length > handshake_body.size()) {
        return std::nullopt;
    }

    const auto extensions_end = offset + extensions_length;
    while (offset + 4U <= extensions_end) {
        const auto extension_type = read_be16(handshake_body, offset);
        const auto extension_length = static_cast<std::size_t>(read_be16(handshake_body, offset + 2U));
        offset += 4U;
        if (offset + extension_length > extensions_end) {
            return std::nullopt;
        }

        details.extensions.push_back(tls_extension_type_text(extension_type));
        const auto extension_bytes = handshake_body.subspan(offset, extension_length);
        if (extension_type == 0x0000U && extension_bytes.size() >= 2U) {
            const auto server_name_list_length = static_cast<std::size_t>(read_be16(extension_bytes, 0U));
            if (extension_bytes.size() >= 2U + server_name_list_length) {
                std::size_t name_offset = 2U;
                while (name_offset + 3U <= 2U + server_name_list_length) {
                    const auto name_type = extension_bytes[name_offset];
                    const auto name_length = static_cast<std::size_t>(read_be16(extension_bytes, name_offset + 1U));
                    name_offset += 3U;
                    if (name_offset + name_length > 2U + server_name_list_length) {
                        break;
                    }
                    if (name_type == 0U) {
                        details.sni = bytes_to_text(extension_bytes.subspan(name_offset, name_length));
                        break;
                    }
                    name_offset += name_length;
                }
            }
        } else if (extension_type == 0x0010U && extension_bytes.size() >= 2U) {
            const auto alpn_length = static_cast<std::size_t>(read_be16(extension_bytes, 0U));
            if (extension_bytes.size() >= 2U + alpn_length) {
                std::size_t protocol_offset = 2U;
                while (protocol_offset < 2U + alpn_length) {
                    const auto protocol_length = static_cast<std::size_t>(extension_bytes[protocol_offset]);
                    ++protocol_offset;
                    if (protocol_offset + protocol_length > 2U + alpn_length) {
                        break;
                    }
                    details.alpn_protocols.push_back(bytes_to_text(extension_bytes.subspan(protocol_offset, protocol_length)));
                    protocol_offset += protocol_length;
                }
            }
        } else if (extension_type == 0x002BU && !extension_bytes.empty()) {
            const auto versions_length = static_cast<std::size_t>(extension_bytes[0]);
            if (extension_bytes.size() >= 1U + versions_length) {
                for (std::size_t cursor = 1U; cursor + 1U < 1U + versions_length; cursor += 2U) {
                    details.supported_versions.push_back(tls_record_version_text(read_be16(extension_bytes, cursor)));
                }
            }
        }

        offset += extension_length;
    }

    return details;
}

struct ParsedTlsServerHello {
    std::string selected_tls_version {};
    std::string selected_cipher_suite {};
    std::string session_id {};
    std::vector<std::string> extensions {};
};

std::optional<ParsedTlsServerHello> parse_tls_server_hello(std::span<const std::uint8_t> handshake_body) {
    if (handshake_body.size() < 38U) {
        return std::nullopt;
    }

    ParsedTlsServerHello details {};
    details.selected_tls_version = tls_record_version_text(read_be16(handshake_body, 0U));

    std::size_t offset = 2U + 32U;
    const auto session_id_length = static_cast<std::size_t>(handshake_body[offset]);
    ++offset;
    if (offset + session_id_length + 3U > handshake_body.size()) {
        return std::nullopt;
    }
    details.session_id = bytes_to_hex_compact(handshake_body.subspan(offset, session_id_length));
    offset += session_id_length;

    details.selected_cipher_suite = tls_cipher_suite_text(read_be16(handshake_body, offset));
    offset += 2U;

    ++offset;
    if (offset > handshake_body.size()) {
        return std::nullopt;
    }

    if (offset + 2U <= handshake_body.size()) {
        const auto extensions_length = static_cast<std::size_t>(read_be16(handshake_body, offset));
        offset += 2U;
        if (offset + extensions_length > handshake_body.size()) {
            return std::nullopt;
        }

        const auto extensions_end = offset + extensions_length;
        while (offset + 4U <= extensions_end) {
            const auto extension_type = read_be16(handshake_body, offset);
            const auto extension_length = static_cast<std::size_t>(read_be16(handshake_body, offset + 2U));
            offset += 4U;
            if (offset + extension_length > extensions_end) {
                return std::nullopt;
            }

            details.extensions.push_back(tls_extension_type_text(extension_type));
            const auto extension_bytes = handshake_body.subspan(offset, extension_length);
            if (extension_type == 0x002BU && extension_bytes.size() >= 2U) {
                details.selected_tls_version = tls_record_version_text(read_be16(extension_bytes, 0U));
            }

            offset += extension_length;
        }
    }

    return details;
}

std::string build_tls_certificate_details(std::span<const std::uint8_t> handshake_body) {
    if (handshake_body.empty()) {
        return {};
    }

    struct CertificateListBounds {
        std::size_t certificates_offset {0U};
        std::size_t certificates_end {0U};
        bool per_certificate_extensions {false};
    };

    auto find_certificate_list_offset = [&]() -> std::optional<CertificateListBounds> {
        if (handshake_body.size() >= 3U) {
            const auto tls12_list_length = static_cast<std::size_t>(read_be24(handshake_body, 0U));
            if (3U + tls12_list_length <= handshake_body.size()) {
                return CertificateListBounds {
                    .certificates_offset = 3U,
                    .certificates_end = 3U + tls12_list_length,
                    .per_certificate_extensions = false,
                };
            }
        }

        const auto context_length = static_cast<std::size_t>(handshake_body[0]);
        if (handshake_body.size() >= 1U + context_length + 3U) {
            const auto offset = 1U + context_length;
            const auto tls13_list_length = static_cast<std::size_t>(read_be24(handshake_body, offset));
            if (offset + 3U + tls13_list_length <= handshake_body.size()) {
                return CertificateListBounds {
                    .certificates_offset = offset + 3U,
                    .certificates_end = offset + 3U + tls13_list_length,
                    .per_certificate_extensions = true,
                };
            }
        }

        return std::nullopt;
    };

    const auto list_bounds = find_certificate_list_offset();
    if (!list_bounds.has_value()) {
        return {};
    }

    std::size_t offset = list_bounds->certificates_offset;
    const auto certificates_end = list_bounds->certificates_end;
    std::size_t certificate_entries = 0U;
    std::optional<ParsedCertificateSummary> first_certificate_summary {};
    std::size_t first_certificate_size = 0U;
    while (offset + 3U <= certificates_end) {
        const auto certificate_length = static_cast<std::size_t>(read_be24(handshake_body, offset));
        offset += 3U;
        if (offset + certificate_length > certificates_end) {
            return {};
        }

        const auto certificate_bytes = handshake_body.subspan(offset, certificate_length);
        if (certificate_entries == 0U) {
            first_certificate_size = certificate_length;
            first_certificate_summary = parse_certificate_summary(certificate_bytes);
        }
        ++certificate_entries;
        offset += certificate_length;

        if (list_bounds->per_certificate_extensions && offset + 2U <= certificates_end) {
            const auto extensions_length = static_cast<std::size_t>(read_be16(handshake_body, offset));
            offset += 2U;
            if (offset + extensions_length > certificates_end) {
                return {};
            }
            offset += extensions_length;
        }
    }

    std::ostringstream text {};
    text << "  Certificate Entries: " << certificate_entries << "\n"
         << "  Leaf Certificate Size: " << first_certificate_size << " bytes";

    if (first_certificate_summary.has_value()) {
        bool emitted_rich_field = false;
        if (!first_certificate_summary->subject_common_name.empty()) {
            text << "\n  Subject: " << first_certificate_summary->subject_common_name;
            emitted_rich_field = true;
        }
        if (!first_certificate_summary->issuer_common_name.empty()) {
            text << "\n  Issuer: " << first_certificate_summary->issuer_common_name;
            emitted_rich_field = true;
        }
        if (!first_certificate_summary->valid_from.empty() || !first_certificate_summary->valid_to.empty()) {
            text << "\n  Validity: " << first_certificate_summary->valid_from << " to " << first_certificate_summary->valid_to;
            emitted_rich_field = true;
        }
        if (!first_certificate_summary->dns_names.empty()) {
            text << "\n  SANs: " << join_limited_texts(first_certificate_summary->dns_names, 3U);
            emitted_rich_field = true;
        }
        if (!emitted_rich_field) {
            text << "\n  Certificate summary: parsed certificate metadata is limited for this stream item.";
        }
    } else {
        text << "\n  Certificate summary: available bytes do not support a richer parsed summary.";
    }

    return text.str();
}

std::string tls_handshake_details_text(const std::uint8_t handshake_type, std::span<const std::uint8_t> handshake_body) {
    std::ostringstream text {};
    switch (handshake_type) {
    case 1U: {
        const auto details = parse_tls_client_hello(handshake_body);
        if (!details.has_value()) {
            return {};
        }
        text << "  Handshake Version: " << details->handshake_version << "\n"
             << "  Session ID: " << details->session_id << "\n"
             << "  Cipher Suites: " << join_limited_texts(details->cipher_suites) << "\n"
             << "  Extensions: " << join_limited_texts(details->extensions);
        if (details->sni.has_value()) {
            text << "\n  SNI: " << *details->sni;
        }
        if (!details->alpn_protocols.empty()) {
            text << "\n  ALPN: " << join_limited_texts(details->alpn_protocols, 4U);
        }
        if (!details->supported_versions.empty()) {
            text << "\n  Supported Versions: " << join_limited_texts(details->supported_versions, 6U);
        }
        return text.str();
    }
    case 2U: {
        const auto details = parse_tls_server_hello(handshake_body);
        if (!details.has_value()) {
            return {};
        }
        text << "  Selected TLS Version: " << details->selected_tls_version << "\n"
             << "  Selected Cipher Suite: " << details->selected_cipher_suite << "\n"
             << "  Session ID: " << details->session_id;
        if (!details->extensions.empty()) {
            text << "\n  Extensions: " << join_limited_texts(details->extensions);
        }
        return text.str();
    }
    case 11U:
        return build_tls_certificate_details(handshake_body);
    default:
        return {};
    }
}

const char* tls_record_type_text(const std::uint8_t content_type) noexcept {
    switch (content_type) {
    case 20U:
        return "ChangeCipherSpec";
    case 21U:
        return "Alert";
    case 22U:
        return "Handshake";
    case 23U:
        return "ApplicationData";
    default:
        return "Unknown";
    }
}

const char* tls_alert_level_text(const std::uint8_t level) noexcept {
    switch (level) {
    case 1U:
        return "Warning";
    case 2U:
        return "Fatal";
    default:
        return nullptr;
    }
}

const char* tls_alert_description_text(const std::uint8_t description) noexcept {
    switch (description) {
    case 0U:
        return "Close Notify";
    case 10U:
        return "Unexpected Message";
    case 20U:
        return "Bad Record MAC";
    case 21U:
        return "Decryption Failed";
    case 22U:
        return "Record Overflow";
    case 40U:
        return "Handshake Failure";
    case 42U:
        return "Bad Certificate";
    case 43U:
        return "Unsupported Certificate";
    case 44U:
        return "Certificate Revoked";
    case 45U:
        return "Certificate Expired";
    case 46U:
        return "Certificate Unknown";
    case 47U:
        return "Illegal Parameter";
    case 48U:
        return "Unknown CA";
    case 49U:
        return "Access Denied";
    case 50U:
        return "Decode Error";
    case 51U:
        return "Decrypt Error";
    case 70U:
        return "Protocol Version";
    case 71U:
        return "Insufficient Security";
    case 80U:
        return "Internal Error";
    case 86U:
        return "Inappropriate Fallback";
    case 90U:
        return "User Canceled";
    case 109U:
        return "Missing Extension";
    case 110U:
        return "Unsupported Extension";
    case 112U:
        return "Unrecognized Name";
    case 116U:
        return "Certificate Required";
    case 120U:
        return "No Application Protocol";
    default:
        return nullptr;
    }
}

const char* tls_handshake_type_text(const std::uint8_t handshake_type) noexcept {
    switch (handshake_type) {
    case 0U:
        return "HelloRequest";
    case 1U:
        return "ClientHello";
    case 2U:
        return "ServerHello";
    case 4U:
        return "NewSessionTicket";
    case 5U:
        return "EndOfEarlyData";
    case 8U:
        return "EncryptedExtensions";
    case 11U:
        return "Certificate";
    case 12U:
        return "ServerKeyExchange";
    case 13U:
        return "CertificateRequest";
    case 14U:
        return "ServerHelloDone";
    case 15U:
        return "CertificateVerify";
    case 16U:
        return "ClientKeyExchange";
    case 20U:
        return "Finished";
    case 21U:
        return "CertificateURL";
    case 22U:
        return "CertificateStatus";
    case 23U:
        return "SupplementalData";
    case 24U:
        return "KeyUpdate";
    case 25U:
        return "CompressedCertificate";
    case 254U:
        return "MessageHash";
    default:
        return "Unknown";
    }
}

std::string tls_handshake_stream_label(const std::uint8_t handshake_type) {
    switch (handshake_type) {
    case 0U:
        return "TLS HelloRequest";
    case 1U:
        return "TLS ClientHello";
    case 2U:
        return "TLS ServerHello";
    case 4U:
        return "TLS NewSessionTicket";
    case 5U:
        return "TLS EndOfEarlyData";
    case 8U:
        return "TLS EncryptedExtensions";
    case 11U:
        return "TLS Certificate";
    case 12U:
        return "TLS ServerKeyExchange";
    case 13U:
        return "TLS CertificateRequest";
    case 14U:
        return "TLS ServerHelloDone";
    case 15U:
        return "TLS CertificateVerify";
    case 16U:
        return "TLS ClientKeyExchange";
    case 20U:
        return "TLS Finished";
    case 21U:
        return "TLS CertificateURL";
    case 22U:
        return "TLS CertificateStatus";
    case 23U:
        return "TLS SupplementalData";
    case 24U:
        return "TLS KeyUpdate";
    case 25U:
        return "TLS CompressedCertificate";
    case 254U:
        return "TLS MessageHash";
    default:
        return "TLS Handshake";
    }
}

std::string tls_stream_label(std::span<const std::uint8_t> record_bytes) {
    if (record_bytes.size() < kTlsRecordHeaderSize) {
        return "TLS Payload";
    }

    const auto content_type = record_bytes[0];
    switch (content_type) {
    case 20U:
        return "TLS ChangeCipherSpec";
    case 21U:
        return "TLS Alert";
    case 22U:
        if (record_bytes.size() >= kTlsRecordHeaderSize + 4U) {
            return tls_handshake_stream_label(record_bytes[kTlsRecordHeaderSize]);
        }
        return "TLS Handshake";
    case 23U:
        return "TLS AppData";
    default:
        return "TLS Record";
    }
}

std::string tls_record_protocol_text(std::span<const std::uint8_t> record_bytes) {
    if (record_bytes.size() < kTlsRecordHeaderSize) {
        return "TLS\n  Record details unavailable for this stream item.";
    }

    const auto content_type = record_bytes[0];
    const auto version = read_be16(record_bytes, 1U);
    const auto record_length = static_cast<std::size_t>(read_be16(record_bytes, 3U));

    std::ostringstream text {};
    text << "TLS\n"
         << "  Record Type: " << tls_record_type_text(content_type) << "\n"
         << "  Record Version: " << tls_record_version_text(version) << "\n"
         << "  Record Length: " << record_length;

    if (content_type == 22U && record_bytes.size() >= kTlsRecordHeaderSize + 4U) {
        const auto handshake_type = record_bytes[kTlsRecordHeaderSize];
        const auto handshake_length = static_cast<std::size_t>(read_be24(record_bytes, kTlsRecordHeaderSize + 1U));
        text << "\n"
             << "  Handshake Type: " << tls_handshake_type_text(handshake_type) << "\n"
             << "  Handshake Length: " << handshake_length;

        if (record_bytes.size() >= kTlsRecordHeaderSize + 4U + handshake_length) {
            const auto handshake_body = record_bytes.subspan(kTlsRecordHeaderSize + 4U, handshake_length);
            const auto details_text = tls_handshake_details_text(handshake_type, handshake_body);
            if (!details_text.empty()) {
                text << "\n" << details_text;
            }
        }
    }

    if (content_type == 21U && record_length >= 2U && record_bytes.size() >= kTlsRecordHeaderSize + 2U) {
        const auto alert_level = record_bytes[kTlsRecordHeaderSize];
        const auto alert_description = record_bytes[kTlsRecordHeaderSize + 1U];
        if (const auto* level_text = tls_alert_level_text(alert_level); level_text != nullptr) {
            text << "\n"
                 << "  Alert Level: " << level_text;
        } else {
            text << "\n"
                 << "  Alert Level: " << static_cast<unsigned int>(alert_level);
        }

        if (const auto* description_text = tls_alert_description_text(alert_description); description_text != nullptr) {
            text << "\n"
                 << "  Alert Description: " << description_text;
        } else {
            text << "\n"
                 << "  Alert Description: " << static_cast<unsigned int>(alert_description);
        }
    }

    return text.str();
}

struct ReassembledPayloadChunk {
    std::uint64_t packet_index {0};
    std::size_t byte_count {0};
};

std::optional<std::vector<ReassembledPayloadChunk>> build_reassembled_payload_chunks(
    const CaptureSession& session,
    const std::size_t flow_index,
    const ReassemblyResult& result
) {
    std::vector<ReassembledPayloadChunk> chunks {};
    chunks.reserve(result.packet_indices.size());
    std::size_t consumed_bytes = 0U;

    for (const auto packet_index : result.packet_indices) {
        if (consumed_bytes >= result.bytes.size()) {
            break;
        }

        const auto packet = session.find_packet(packet_index);
        if (!packet.has_value()) {
            return std::nullopt;
        }

        const auto payload_bytes = session.read_selected_flow_transport_payload(flow_index, *packet);
        if (payload_bytes.empty()) {
            return std::nullopt;
        }

        const auto trim_prefix_bytes = session.selected_flow_tcp_payload_trim_prefix_bytes(flow_index, packet_index);
        if (trim_prefix_bytes >= payload_bytes.size()) {
            continue;
        }

        const auto remaining_bytes = result.bytes.size() - consumed_bytes;
        const auto contributed_bytes = payload_bytes.size() - trim_prefix_bytes;
        const auto chunk_size = std::min<std::size_t>(contributed_bytes, remaining_bytes);
        if (chunk_size == 0U) {
            continue;
        }

        chunks.push_back(ReassembledPayloadChunk {
            .packet_index = packet_index,
            .byte_count = chunk_size,
        });
        consumed_bytes += chunk_size;
    }

    if (consumed_bytes != result.bytes.size()) {
        return std::nullopt;
    }

    return chunks;
}

std::vector<std::uint64_t> consume_reassembled_packet_indices(
    const std::vector<ReassembledPayloadChunk>& chunks,
    const std::size_t byte_count,
    std::size_t& chunk_index,
    std::size_t& chunk_offset
) {
    std::vector<std::uint64_t> packet_indices {};
    std::size_t remaining_bytes = byte_count;

    while (remaining_bytes > 0U && chunk_index < chunks.size()) {
        const auto& chunk = chunks[chunk_index];
        if (packet_indices.empty() || packet_indices.back() != chunk.packet_index) {
            packet_indices.push_back(chunk.packet_index);
        }

        const auto chunk_remaining = chunk.byte_count - chunk_offset;
        const auto consumed_here = std::min(remaining_bytes, chunk_remaining);
        remaining_bytes -= consumed_here;
        chunk_offset += consumed_here;

        if (chunk_offset >= chunk.byte_count) {
            ++chunk_index;
            chunk_offset = 0U;
        }
    }

    return packet_indices;
}

std::string limited_quality_tls_protocol_text(const bool record_fragment) {
    if (record_fragment) {
        return "TLS\n  Reassembled bytes do not contain a complete TLS record in this direction.";
    }

    return "TLS\n  Reassembled bytes suggest a TLS record, but stream reconstruction quality is limited for this direction.";
}

std::string tcp_gap_protocol_text(const std::string_view protocol_name) {
    return std::string(protocol_name) + "\n  Semantic parsing stopped for this direction because earlier TCP bytes are missing.\n  Later bytes are shown conservatively.";
}

}  // namespace

std::string tls_stream_label_from_protocol_text(const std::string_view protocol_text) {
    constexpr std::array<std::pair<std::string_view, std::string_view>, 17> handshake_labels {{
        {"Handshake Type: HelloRequest", "TLS HelloRequest"},
        {"Handshake Type: ClientHello", "TLS ClientHello"},
        {"Handshake Type: ServerHello", "TLS ServerHello"},
        {"Handshake Type: NewSessionTicket", "TLS NewSessionTicket"},
        {"Handshake Type: EndOfEarlyData", "TLS EndOfEarlyData"},
        {"Handshake Type: EncryptedExtensions", "TLS EncryptedExtensions"},
        {"Handshake Type: Certificate", "TLS Certificate"},
        {"Handshake Type: ServerKeyExchange", "TLS ServerKeyExchange"},
        {"Handshake Type: CertificateRequest", "TLS CertificateRequest"},
        {"Handshake Type: ServerHelloDone", "TLS ServerHelloDone"},
        {"Handshake Type: CertificateVerify", "TLS CertificateVerify"},
        {"Handshake Type: ClientKeyExchange", "TLS ClientKeyExchange"},
        {"Handshake Type: Finished", "TLS Finished"},
        {"Handshake Type: CertificateURL", "TLS CertificateURL"},
        {"Handshake Type: CertificateStatus", "TLS CertificateStatus"},
        {"Handshake Type: KeyUpdate", "TLS KeyUpdate"},
        {"Handshake Type: CompressedCertificate", "TLS CompressedCertificate"},
    }};

    for (const auto& [marker, label] : handshake_labels) {
        if (contains_text(protocol_text, marker)) {
            return std::string {label};
        }
    }

    if (contains_text(protocol_text, "Handshake Type: SupplementalData")) {
        return "TLS SupplementalData";
    }
    if (contains_text(protocol_text, "Handshake Type: MessageHash")) {
        return "TLS MessageHash";
    }
    if (contains_text(protocol_text, "Record Type: ChangeCipherSpec")) {
        return "TLS ChangeCipherSpec";
    }
    if (contains_text(protocol_text, "Record Type: Alert")) {
        return "TLS Alert";
    }
    if (contains_text(protocol_text, "Record Type: ApplicationData")) {
        return "TLS AppData";
    }
    if (contains_text(protocol_text, "Record Type: Handshake")) {
        return "TLS Handshake";
    }
    return "TLS Payload";
}

TlsPacketStreamPresentation build_tls_stream_items_for_packet(
    const std::uint64_t packet_index,
    std::span<const std::uint8_t> payload_bytes
) {
    TlsPacketStreamPresentation presentation {};
    if (!looks_like_tls_record_prefix(payload_bytes)) {
        return presentation;
    }

    presentation.handled = true;
    HexDumpService hex_dump_service {};
    std::size_t offset = 0U;

    while (offset < payload_bytes.size()) {
        if (!looks_like_tls_record_prefix(payload_bytes, offset)) {
            const auto trailing = payload_bytes.subspan(offset);
            if (!trailing.empty()) {
                presentation.items.push_back(TlsStreamPresentationItem {
                    .label = "TLS Payload (partial)",
                    .byte_count = trailing.size(),
                    .packet_indices = {packet_index},
                    .payload_hex_text = hex_dump_service.format(trailing),
                    .protocol_text = "TLS\n  Remaining bytes do not form a complete TLS record in this packet.",
                });
            }
            return presentation;
        }

        const auto record_size = tls_record_size(payload_bytes, offset);
        if (!record_size.has_value()) {
            const auto trailing = payload_bytes.subspan(offset);
            presentation.items.push_back(TlsStreamPresentationItem {
                .label = "TLS Record Fragment (partial)",
                .byte_count = trailing.size(),
                .packet_indices = {packet_index},
                .payload_hex_text = hex_dump_service.format(trailing),
                .protocol_text = "TLS\n  Record header is present but the full TLS record body is not available in this packet.",
            });
            return presentation;
        }

        const auto record_bytes = payload_bytes.subspan(offset, *record_size);
        presentation.items.push_back(TlsStreamPresentationItem {
            .label = tls_stream_label(record_bytes),
            .byte_count = record_bytes.size(),
            .packet_indices = {packet_index},
            .payload_hex_text = hex_dump_service.format(record_bytes),
            .protocol_text = tls_record_protocol_text(record_bytes),
        });
        offset += *record_size;
    }

    return presentation;
}

TlsDirectionalStreamPresentation build_tls_stream_items_from_reassembly(
    const CaptureSession& session,
    const std::size_t flow_index,
    const Direction direction,
    const std::size_t max_packets_to_scan
) {
    TlsDirectionalStreamPresentation presentation {};
    const auto result = session.reassemble_flow_direction(ReassemblyRequest {
        .flow_index = flow_index,
        .direction = direction,
        .max_packets = max_packets_to_scan,
        .max_bytes = 256U * 1024U,
    });
    if (!result.has_value() || result->bytes.empty()) {
        return presentation;
    }

    const auto payload_bytes = std::span<const std::uint8_t>(result->bytes.data(), result->bytes.size());
    if (!looks_like_tls_record_prefix(payload_bytes)) {
        return presentation;
    }

    const auto chunks = build_reassembled_payload_chunks(session, flow_index, *result);
    if (!chunks.has_value() || chunks->empty()) {
        return presentation;
    }

    HexDumpService hex_dump_service {};
    std::size_t offset = 0U;
    std::size_t chunk_index = 0U;
    std::size_t chunk_offset = 0U;
    bool emitted_any = false;

    while (offset < payload_bytes.size()) {
        if (!looks_like_tls_record_prefix(payload_bytes, offset)) {
            const auto trailing = payload_bytes.subspan(offset);
            if (!trailing.empty()) {
                const auto packet_indices = consume_reassembled_packet_indices(*chunks, trailing.size(), chunk_index, chunk_offset);
                presentation.items.push_back(TlsStreamPresentationItem {
                    .label = "TLS Payload (partial)",
                    .byte_count = trailing.size(),
                    .packet_indices = packet_indices,
                    .payload_hex_text = hex_dump_service.format(trailing),
                    .protocol_text = limited_quality_tls_protocol_text(false),
                });
            }
            presentation.used_reassembly = true;
            break;
        }

        const auto record_size = tls_record_size(payload_bytes, offset);
        if (!record_size.has_value()) {
            const auto trailing = payload_bytes.subspan(offset);
            const auto packet_indices = consume_reassembled_packet_indices(*chunks, trailing.size(), chunk_index, chunk_offset);
            presentation.items.push_back(TlsStreamPresentationItem {
                .label = "TLS Record Fragment (partial)",
                .byte_count = trailing.size(),
                .packet_indices = packet_indices,
                .payload_hex_text = hex_dump_service.format(trailing),
                .protocol_text = limited_quality_tls_protocol_text(true),
            });
            presentation.used_reassembly = true;
            break;
        }

        const auto record_bytes = payload_bytes.subspan(offset, *record_size);
        const auto packet_indices = consume_reassembled_packet_indices(*chunks, record_bytes.size(), chunk_index, chunk_offset);
        presentation.items.push_back(TlsStreamPresentationItem {
            .label = tls_stream_label(record_bytes),
            .byte_count = record_bytes.size(),
            .packet_indices = packet_indices,
            .payload_hex_text = hex_dump_service.format(record_bytes),
            .protocol_text = tls_record_protocol_text(record_bytes),
        });
        emitted_any = true;
        offset += *record_size;
    }

    presentation.used_reassembly = presentation.used_reassembly || emitted_any;
    if (presentation.used_reassembly) {
        presentation.covered_packet_indices.insert(result->packet_indices.begin(), result->packet_indices.end());
    }
    if (result->stopped_at_gap && result->first_gap_packet_index != 0U) {
        presentation.items.push_back(TlsStreamPresentationItem {
            .label = "TLS Gap",
            .byte_count = 0U,
            .packet_indices = {result->first_gap_packet_index},
            .payload_hex_text = {},
            .protocol_text = tcp_gap_protocol_text("TLS"),
        });
        presentation.used_reassembly = true;
        presentation.explicit_gap_item_emitted = true;
        presentation.first_gap_packet_index = result->first_gap_packet_index;
        presentation.fallback_label = "TLS Payload";
        presentation.fallback_protocol_text = tcp_gap_protocol_text("TLS");
    }

    return presentation;
}

}  // namespace pfl::session_detail