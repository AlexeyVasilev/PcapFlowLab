#include "core/services/TlsHandshakeDetails.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstddef>
#include <iomanip>
#include <initializer_list>
#include <optional>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace pfl {

namespace {

std::uint16_t read_be16(std::span<const std::uint8_t> bytes, const std::size_t offset) {
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(bytes[offset]) << 8U) |
                                      static_cast<std::uint16_t>(bytes[offset + 1U]));
}

std::uint32_t read_be24(std::span<const std::uint8_t> bytes, const std::size_t offset) {
    return (static_cast<std::uint32_t>(bytes[offset]) << 16U) |
           (static_cast<std::uint32_t>(bytes[offset + 1U]) << 8U) |
           static_cast<std::uint32_t>(bytes[offset + 2U]);
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

std::string tls_version_text(const std::uint16_t version) {
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
    if (offset >= bytes.size() || offset + 1U >= bytes.size()) {
        return std::nullopt;
    }

    const auto tag = bytes[offset];
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
    return value.size() == expected.size() && std::equal(value.begin(), value.end(), expected.begin(), expected.end());
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
            return bytes_to_text(*string_value);
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

    return std::pair<std::string, std::string> {bytes_to_text(*not_before_value), bytes_to_text(*not_after_value)};
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
    details.handshake_version = tls_version_text(read_be16(handshake_body, 0U));

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
                    details.supported_versions.push_back(tls_version_text(read_be16(extension_bytes, cursor)));
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
    details.selected_tls_version = tls_version_text(read_be16(handshake_body, 0U));

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
                details.selected_tls_version = tls_version_text(read_be16(extension_bytes, 0U));
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

    auto find_certificate_list_bounds = [&]() -> std::optional<CertificateListBounds> {
        if (handshake_body.size() >= 3U) {
            const auto tls12_length = static_cast<std::size_t>(read_be24(handshake_body, 0U));
            if (3U + tls12_length <= handshake_body.size()) {
                return CertificateListBounds {.certificates_offset = 3U, .certificates_end = 3U + tls12_length, .per_certificate_extensions = false};
            }
        }
        const auto context_length = static_cast<std::size_t>(handshake_body[0]);
        if (handshake_body.size() >= 1U + context_length + 3U) {
            const auto offset = 1U + context_length;
            const auto tls13_length = static_cast<std::size_t>(read_be24(handshake_body, offset));
            if (offset + 3U + tls13_length <= handshake_body.size()) {
                return CertificateListBounds {.certificates_offset = offset + 3U, .certificates_end = offset + 3U + tls13_length, .per_certificate_extensions = true};
            }
        }
        return std::nullopt;
    };

    const auto bounds = find_certificate_list_bounds();
    if (!bounds.has_value()) {
        return {};
    }

    std::size_t offset = bounds->certificates_offset;
    std::size_t certificate_entries = 0U;
    std::size_t first_certificate_size = 0U;
    std::optional<ParsedCertificateSummary> first_summary {};
    while (offset + 3U <= bounds->certificates_end) {
        const auto certificate_length = static_cast<std::size_t>(read_be24(handshake_body, offset));
        offset += 3U;
        if (offset + certificate_length > bounds->certificates_end) {
            return {};
        }
        const auto certificate_bytes = handshake_body.subspan(offset, certificate_length);
        if (certificate_entries == 0U) {
            first_certificate_size = certificate_length;
            first_summary = parse_certificate_summary(certificate_bytes);
        }
        ++certificate_entries;
        offset += certificate_length;

        if (bounds->per_certificate_extensions && offset + 2U <= bounds->certificates_end) {
            const auto extensions_length = static_cast<std::size_t>(read_be16(handshake_body, offset));
            offset += 2U;
            if (offset + extensions_length > bounds->certificates_end) {
                return {};
            }
            offset += extensions_length;
        }
    }

    std::ostringstream text {};
    text << "  Certificate Entries: " << certificate_entries << "\n"
         << "  Leaf Certificate Size: " << first_certificate_size << " bytes";

    if (first_summary.has_value()) {
        bool emitted_rich_field = false;
        if (!first_summary->subject_common_name.empty()) {
            text << "\n  Subject: " << first_summary->subject_common_name;
            emitted_rich_field = true;
        }
        if (!first_summary->issuer_common_name.empty()) {
            text << "\n  Issuer: " << first_summary->issuer_common_name;
            emitted_rich_field = true;
        }
        if (!first_summary->valid_from.empty() || !first_summary->valid_to.empty()) {
            text << "\n  Validity: " << first_summary->valid_from << " to " << first_summary->valid_to;
            emitted_rich_field = true;
        }
        if (!first_summary->dns_names.empty()) {
            text << "\n  SANs: " << join_limited_texts(first_summary->dns_names, 3U);
            emitted_rich_field = true;
        }
        if (!emitted_rich_field) {
            text << "\n  Certificate summary: parsed certificate metadata is limited for this packet.";
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

const char* tls_handshake_type_text(const std::uint8_t handshake_type) noexcept {
    switch (handshake_type) {
    case 1U:
        return "ClientHello";
    case 2U:
        return "ServerHello";
    case 4U:
        return "NewSessionTicket";
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
    default:
        return "Unknown";
    }
}

}  // namespace

std::optional<TlsHandshakeDetails> parse_tls_handshake_details(std::span<const std::uint8_t> handshake_bytes) {
    if (handshake_bytes.size() < 4U) {
        return std::nullopt;
    }

    const auto handshake_type = handshake_bytes[0];
    const auto handshake_length = static_cast<std::size_t>(read_be24(handshake_bytes, 1U));
    if (handshake_bytes.size() < 4U + handshake_length) {
        return std::nullopt;
    }

    const auto handshake_body = handshake_bytes.subspan(4U, handshake_length);
    return TlsHandshakeDetails {
        .handshake_type = handshake_type,
        .handshake_length = handshake_length,
        .handshake_type_text = tls_handshake_type_text(handshake_type),
        .details_text = tls_handshake_details_text(handshake_type, handshake_body),
    };
}

}  // namespace pfl