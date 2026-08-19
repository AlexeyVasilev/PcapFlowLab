#include "app/session/SessionTlsPresentation.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <iomanip>
#include <initializer_list>
#include <limits>
#include <optional>
#include <utility>

#include "app/session/CaptureSession.h"
#include "app/session/SelectedFlowPacketSemantics.h"
#include "core/decode/PacketDecodeSupport.h"
#include "core/reassembly/ReassemblyTypes.h"
#include "core/services/TlsInspectionParser.h"

namespace pfl::session_detail {

namespace {

constexpr std::size_t kTlsRecordHeaderSize = 5U;

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

std::string tls_stream_label(
    std::span<const std::uint8_t> record_bytes,
    const TlsStreamItemSemanticKind semantic_kind = TlsStreamItemSemanticKind::none
) {
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
        if (semantic_kind == TlsStreamItemSemanticKind::encrypted_handshake) {
            return "TLS Encrypted Handshake Message";
        }
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

std::string tls_record_protocol_text(
    std::span<const std::uint8_t> record_bytes,
    const TlsStreamItemSemanticKind semantic_kind = TlsStreamItemSemanticKind::none
) {
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

    if (content_type == 22U && semantic_kind == TlsStreamItemSemanticKind::encrypted_handshake) {
        text << "\n"
             << "  Payload Interpretation: Encrypted/opaque handshake payload";
    } else if (content_type == 21U && semantic_kind == TlsStreamItemSemanticKind::encrypted_alert) {
        text << "\n"
             << "  Payload Interpretation: Encrypted/opaque alert payload";
    } else if (content_type == 22U && record_bytes.size() >= kTlsRecordHeaderSize + 4U) {
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

    if (content_type == 21U &&
        semantic_kind != TlsStreamItemSemanticKind::encrypted_alert &&
        record_length >= 2U &&
        record_bytes.size() >= kTlsRecordHeaderSize + 2U) {
        const auto alert_level = record_bytes[kTlsRecordHeaderSize];
        const auto alert_description = record_bytes[kTlsRecordHeaderSize + 1U];
        if (const auto level_text = tls_alert_level_name(alert_level); level_text.has_value()) {
            text << "\n"
                 << "  Alert Level: " << *level_text;
        } else {
            text << "\n"
                 << "  Alert Level: " << static_cast<unsigned int>(alert_level);
        }

        if (const auto description_text = tls_alert_description_name(alert_description);
            description_text.has_value()) {
            text << "\n"
                 << "  Alert Description: " << *description_text;
        } else {
            text << "\n"
                 << "  Alert Description: " << static_cast<unsigned int>(alert_description);
        }
    }

    return text.str();
}

TlsStreamItemSemanticKind tls_stream_semantic_kind(
    std::span<const std::uint8_t> record_bytes,
    const bool post_change_cipher_spec
) {
    if (record_bytes.size() < kTlsRecordHeaderSize) {
        return TlsStreamItemSemanticKind::partial_payload;
    }

    switch (record_bytes[0]) {
    case 20U:
        return TlsStreamItemSemanticKind::change_cipher_spec;
    case 21U:
        return post_change_cipher_spec
            ? TlsStreamItemSemanticKind::encrypted_alert
            : TlsStreamItemSemanticKind::alert;
    case 22U:
        return post_change_cipher_spec
            ? TlsStreamItemSemanticKind::encrypted_handshake
            : TlsStreamItemSemanticKind::plaintext_handshake;
    case 23U:
        return TlsStreamItemSemanticKind::application_data;
    default:
        return TlsStreamItemSemanticKind::generic_record;
    }
}

std::optional<std::size_t> derive_original_tcp_payload_length_from_headers(
    std::span<const std::uint8_t> packet_bytes,
    const PacketRef& packet
) {
    const auto network = detail::parse_network_payload(packet_bytes, packet.data_link_type);
    if (!network.has_value()) {
        return std::nullopt;
    }

    if (network->protocol_type == detail::kEtherTypeIpv4) {
        const auto ipv4_offset = network->payload_offset;
        const auto ipv4_bounds = detail::parse_ipv4_packet_bounds(packet_bytes, ipv4_offset);
        if (!ipv4_bounds.has_value()) {
            return std::nullopt;
        }

        const auto flags_fragment = detail::read_be16(packet_bytes, ipv4_offset + 6U);
        if ((flags_fragment & 0x3FFFU) != 0U) {
            return std::nullopt;
        }

        if (packet_bytes[ipv4_offset + 9U] != detail::kIpProtocolTcp) {
            return std::nullopt;
        }

        const auto transport_offset = ipv4_offset + ipv4_bounds->header_length;
        if (transport_offset + detail::kTcpMinimumHeaderSize > packet_bytes.size()) {
            return std::nullopt;
        }

        const auto tcp_header_length = static_cast<std::size_t>((packet_bytes[transport_offset + 12U] >> 4U) * 4U);
        if (tcp_header_length < detail::kTcpMinimumHeaderSize ||
            transport_offset + tcp_header_length > packet_bytes.size()) {
            return std::nullopt;
        }

        if (!ipv4_bounds->bounds_from_captured_bytes) {
            if (ipv4_bounds->total_length < ipv4_bounds->header_length + tcp_header_length) {
                return std::nullopt;
            }

            return static_cast<std::size_t>(
                static_cast<std::size_t>(ipv4_bounds->total_length) - ipv4_bounds->header_length - tcp_header_length
            );
        }

        const auto transport_payload_offset = transport_offset + tcp_header_length;
        if (packet.original_length < transport_payload_offset) {
            return std::nullopt;
        }

        return static_cast<std::size_t>(packet.original_length - transport_payload_offset);
    }

    if (network->protocol_type == detail::kEtherTypeIpv6) {
        const auto ipv6_offset = network->payload_offset;
        if (packet_bytes.size() < ipv6_offset + detail::kIpv6HeaderSize) {
            return std::nullopt;
        }

        const auto version = static_cast<std::uint8_t>(packet_bytes[ipv6_offset] >> 4U);
        if (version != 6U) {
            return std::nullopt;
        }

        const auto ipv6_payload_length = static_cast<std::size_t>(detail::read_be16(packet_bytes, ipv6_offset + 4U));
        const auto nominal_packet_end = ipv6_offset + detail::kIpv6HeaderSize + ipv6_payload_length;
        const auto payload = detail::parse_ipv6_payload(packet_bytes, ipv6_offset);
        if (!payload.has_value() || payload->has_fragment_header || payload->next_header != detail::kIpProtocolTcp) {
            return std::nullopt;
        }

        if (payload->payload_offset + detail::kTcpMinimumHeaderSize > packet_bytes.size()) {
            return std::nullopt;
        }

        const auto tcp_header_length = static_cast<std::size_t>((packet_bytes[payload->payload_offset + 12U] >> 4U) * 4U);
        if (tcp_header_length < detail::kTcpMinimumHeaderSize ||
            payload->payload_offset + tcp_header_length > packet_bytes.size() ||
            payload->payload_offset + tcp_header_length > nominal_packet_end) {
            return std::nullopt;
        }

        return nominal_packet_end - (payload->payload_offset + tcp_header_length);
    }

    return std::nullopt;
}

std::optional<std::size_t> derive_original_tcp_payload_length_from_headers(
    const CaptureSession& session,
    const PacketRef& packet
) {
    const auto packet_bytes = session.read_packet_data(packet);
    if (packet_bytes.empty()) {
        return std::nullopt;
    }

    return derive_original_tcp_payload_length_from_headers(
        std::span<const std::uint8_t>(packet_bytes.data(), packet_bytes.size()),
        packet
    );
}

bool direction_contains_truncated_packet(std::span<const PacketRef> packets) noexcept {
    return std::any_of(packets.begin(), packets.end(), [](const PacketRef& packet) {
        return packet.captured_length < packet.original_length;
    });
}

struct PendingSelectedTlsRecord {
    std::string label {};
    std::size_t total_byte_count {0U};
    std::size_t remaining_original_bytes {0U};
    std::vector<std::uint64_t> packet_indices {};
    std::vector<std::uint8_t> captured_bytes {};
    TlsStreamItemSemanticKind semantic_kind {TlsStreamItemSemanticKind::none};
    bool has_constricted_contribution {false};
    std::vector<std::string> constricted_contribution_notes {};
    std::string protocol_text {};
    std::vector<std::string> constricted_notes {};
    std::vector<TlsSelectedPacketContribution> contributions {};
    bool selected_packet_participated {false};
    TlsInspectionParserContext initial_parser_context {};
};

void append_constricted_packet_note(PendingSelectedTlsRecord& record, const PacketRef& packet) {
    if (packet.captured_length >= packet.original_length) {
        return;
    }

    std::ostringstream note {};
    note << "  Constricted packet #" << (packet.packet_index + 1U)
         << ": captured " << packet.captured_length
         << " / original " << packet.original_length << " bytes.";
    record.constricted_notes.push_back(note.str());
}

void append_constricted_contribution_note(
    PendingSelectedTlsRecord& record,
    const PacketRef& packet,
    const std::size_t captured_contribution,
    const std::size_t original_contribution
) {
    if (packet.captured_length >= packet.original_length || captured_contribution >= original_contribution) {
        return;
    }

    std::ostringstream note {};
    note << "#" << (packet.packet_index + 1U)
         << " contributed " << captured_contribution
         << " / " << original_contribution << " bytes";
    record.has_constricted_contribution = true;
    record.constricted_contribution_notes.push_back(note.str());
}

void append_unique_packet_index(std::vector<std::uint64_t>& packet_indices, const std::uint64_t packet_index) {
    if (packet_indices.empty() || packet_indices.back() != packet_index) {
        packet_indices.push_back(packet_index);
    }
}

struct ReassembledPayloadChunk {
    std::uint64_t packet_index {0};
    std::size_t byte_count {0};
};

std::optional<std::vector<ReassembledPayloadChunk>> build_reassembled_payload_chunks(
    const ReassemblyResult& result
) {
    if (result.packet_indices.size() != result.packet_byte_counts.size()) {
        return std::nullopt;
    }

    std::vector<ReassembledPayloadChunk> chunks {};
    chunks.reserve(result.packet_indices.size());
    std::size_t consumed_bytes = 0U;

    for (std::size_t index = 0U; index < result.packet_indices.size(); ++index) {
        if (consumed_bytes >= result.bytes.size()) {
            break;
        }

        const auto remaining_bytes = result.bytes.size() - consumed_bytes;
        const auto chunk_size = std::min<std::size_t>(result.packet_byte_counts[index], remaining_bytes);
        if (chunk_size == 0U) {
            continue;
        }

        chunks.push_back(ReassembledPayloadChunk {
            .packet_index = result.packet_indices[index],
            .byte_count = chunk_size,
        });
        consumed_bytes += chunk_size;
    }

    if (consumed_bytes != result.bytes.size()) {
        return std::nullopt;
    }

    return chunks;
}

bool is_plausible_service_name_char(const char value) noexcept {
    return std::isalnum(static_cast<unsigned char>(value)) != 0 || value == '.' || value == '-' || value == '_';
}

bool is_plausible_service_name(const std::string_view value) noexcept {
    if (value.empty()) {
        return false;
    }

    for (const auto character : value) {
        if (!is_plausible_service_name_char(character)) {
            return false;
        }
    }

    return value.find('.') != std::string_view::npos;
}

Direction direction_from_packet_row(const PacketRow& row) noexcept {
    return !row.direction_text.empty() && row.direction_text.front() == 'B'
        ? Direction::b_to_a
        : Direction::a_to_b;
}

TlsSelectedPacketStatus finalized_selected_record_status(const PendingSelectedTlsRecord& record) noexcept {
    if (record.remaining_original_bytes != 0U) {
        return record.has_constricted_contribution
            ? TlsSelectedPacketStatus::capture_constricted
            : TlsSelectedPacketStatus::incomplete_window;
    }

    if (record.has_constricted_contribution || record.captured_bytes.size() != record.total_byte_count) {
        return TlsSelectedPacketStatus::capture_constricted;
    }

    return TlsSelectedPacketStatus::complete;
}

std::optional<TlsSelectedPacketRecordContext> finalize_selected_packet_record_context(
    PendingSelectedTlsRecord&& record,
    const TlsSelectedPacketStatus status,
    const std::uint64_t selected_flow_packet_index
) {
    const bool definite_multi_packet_context =
        record.contributions.size() > 1U ||
        status != TlsSelectedPacketStatus::complete ||
        record.captured_bytes.size() != record.total_byte_count;
    if (!record.selected_packet_participated || !definite_multi_packet_context) {
        return std::nullopt;
    }

    const auto selected_contribution = std::find_if(
        record.contributions.begin(),
        record.contributions.end(),
        [&](const TlsSelectedPacketContribution& contribution) {
            return contribution.flow_packet_index == selected_flow_packet_index;
        }
    );

    std::optional<std::uint64_t> selected_contribution_flow_packet_index {};
    if (selected_contribution != record.contributions.end()) {
        selected_contribution_flow_packet_index = selected_contribution->flow_packet_index;
    }

    std::optional<std::uint64_t> completion_flow_packet_index {};
    if (!record.contributions.empty()) {
        completion_flow_packet_index = record.contributions.back().flow_packet_index;
    }

    return TlsSelectedPacketRecordContext {
        .label = std::move(record.label),
        .protocol_text = std::move(record.protocol_text),
        .captured_bytes = std::move(record.captured_bytes),
        .total_record_size = record.total_byte_count,
        .semantic_kind = record.semantic_kind,
        .initial_parser_context = record.initial_parser_context,
        .status = status,
        .contributions = std::move(record.contributions),
        .selected_contribution_flow_packet_index = selected_contribution_flow_packet_index,
        .completion_flow_packet_index = completion_flow_packet_index,
        .has_constricted_contribution = record.has_constricted_contribution,
        .constricted_contribution_notes = std::move(record.constricted_contribution_notes),
        .constricted_packet_notes = std::move(record.constricted_notes),
    };
}

struct PendingTlsHintRecord {
    std::size_t total_byte_count {0U};
    std::size_t remaining_original_bytes {0U};
    std::vector<std::uint8_t> captured_bytes {};
};

struct PendingTlsSemanticRecord {
    std::size_t remaining_original_bytes {0U};
    TlsInspectionParserContext initial_parser_context {};
    std::vector<std::uint8_t> captured_bytes {};
};

TlsInspectionParserContext advance_tls_parser_context_with_exact_record(
    const TlsInspectionParserContext& initial_context,
    std::span<const std::uint8_t> record_bytes
) {
    if (!looks_like_tls_record_prefix(record_bytes)) {
        return initial_context;
    }

    const auto record_size = tls_record_size(record_bytes);
    if (!record_size.has_value() || *record_size != record_bytes.size()) {
        return initial_context;
    }

    TlsInspectionParser parser {};
    return parser.inspect(record_bytes, initial_context).final_context;
}

std::optional<TlsInspectionResult> inspect_tls_record_with_exact_context(
    const TlsInspectionParserContext& initial_context,
    std::span<const std::uint8_t> record_bytes
) {
    if (!looks_like_tls_record_prefix(record_bytes)) {
        return std::nullopt;
    }

    const auto record_size = tls_record_size(record_bytes);
    if (!record_size.has_value() || *record_size != record_bytes.size()) {
        return std::nullopt;
    }

    TlsInspectionParser parser {};
    return parser.inspect(record_bytes, initial_context);
}

void sync_tls_parser_context_flags(
    const TlsInspectionParserContext& context,
    bool& post_change_cipher_spec,
    bool& saw_tls_context
) noexcept {
    post_change_cipher_spec = context.semantic_state == TlsInspectionSemanticState::post_change_cipher_spec;
    saw_tls_context = saw_tls_context || context.semantic_state != TlsInspectionSemanticState::unknown;
}

std::optional<std::string> extract_service_hint_from_complete_tls_record(
    std::span<const std::uint8_t> record_bytes
) {
    if (record_bytes.empty()) {
        return std::nullopt;
    }

    TlsInspectionParser parser {};
    const auto inspection = parser.inspect(record_bytes);
    for (const auto& record : inspection.records) {
        if (record.status != TlsRecordStatus::complete) {
            continue;
        }

        for (const auto& handshake : record.handshake_messages) {
            if (handshake.kind != TlsHandshakeKind::client_hello ||
                handshake.status != TlsHandshakeStatus::complete ||
                handshake.structured_parse_status != TlsStructuredParseStatus::parsed ||
                !handshake.client_hello.has_value()) {
                continue;
            }

            for (const auto& server_name : handshake.client_hello->sni_names) {
                if (is_plausible_service_name(server_name)) {
                    return server_name;
                }
            }
        }
    }

    return std::nullopt;
}

struct TlsScannerConsumedPrefix {
    std::vector<std::uint64_t> packet_indices {};
    std::vector<std::uint8_t> captured_bytes {};
    std::uint64_t first_packet_index {0};
    std::uint64_t first_flow_packet_index {0};
    bool has_constricted_contribution {false};
    std::vector<std::string> constricted_contribution_notes {};
    std::vector<std::string> constricted_packet_notes {};
};

std::uint32_t allocate_tls_scanner_intra_packet_ordinal(
    TlsStreamScannerState& state,
    const std::uint64_t packet_index
) noexcept {
    if (state.ordinal_packet_index != packet_index) {
        state.ordinal_packet_index = packet_index;
        state.next_intra_packet_ordinal = 0U;
    }

    return state.next_intra_packet_ordinal++;
}

void append_tls_stream_scanner_contributions(
    TlsStreamScannerState& state,
    std::span<const TlsStreamScannerContribution> contributions
) {
    for (const auto& contribution : contributions) {
        if (contribution.original_byte_count == 0U) {
            continue;
        }

        state.buffered_contributions.push_back(TlsStreamScannerBufferedContribution {
            .packet_index = contribution.packet_index,
            .flow_packet_index = contribution.flow_packet_index,
            .captured_bytes = contribution.captured_bytes,
            .original_byte_count = contribution.original_byte_count,
            .packet_captured_length = contribution.packet_captured_length,
            .packet_original_length = contribution.packet_original_length,
        });
    }
}

std::size_t tls_stream_scanner_total_original_bytes(const TlsStreamScannerState& state) noexcept {
    std::size_t total = 0U;
    for (const auto& contribution : state.buffered_contributions) {
        total += contribution.original_byte_count;
    }
    return total;
}

std::vector<std::uint8_t> flatten_tls_stream_scanner_captured_bytes(
    const TlsStreamScannerState& state,
    const std::size_t max_bytes = std::numeric_limits<std::size_t>::max()
) {
    std::vector<std::uint8_t> bytes {};
    std::size_t remaining = max_bytes;
    for (const auto& contribution : state.buffered_contributions) {
        if (remaining == 0U) {
            break;
        }

        const auto copy_count = std::min(remaining, contribution.captured_bytes.size());
        bytes.insert(
            bytes.end(),
            contribution.captured_bytes.begin(),
            contribution.captured_bytes.begin() + static_cast<std::ptrdiff_t>(copy_count)
        );
        remaining -= copy_count;
    }
    return bytes;
}

void maybe_initialize_tls_scanner_pending_record(TlsStreamScannerState& state) {
    if (state.pending_record.has_value() || state.buffered_contributions.empty()) {
        return;
    }

    const auto captured_bytes = flatten_tls_stream_scanner_captured_bytes(state);
    if (captured_bytes.size() < kTlsRecordHeaderSize) {
        return;
    }
    const auto captured_span = std::span<const std::uint8_t>(captured_bytes.data(), captured_bytes.size());
    if (!looks_like_tls_record_prefix(captured_span)) {
        return;
    }

    const auto total_byte_count = kTlsRecordHeaderSize + static_cast<std::size_t>(read_be16(captured_span, 3U));
    const auto semantic_kind = tls_stream_semantic_kind(captured_span.first(std::min(captured_span.size(), total_byte_count)), state.post_change_cipher_spec);
    const auto& first_contribution = state.buffered_contributions.front();
    state.pending_record = TlsStreamScannerPendingRecordState {
        .label = tls_stream_label(captured_span.first(std::min(captured_span.size(), total_byte_count)), semantic_kind),
        .total_byte_count = total_byte_count,
        .semantic_kind = semantic_kind,
        .initial_parser_context = state.parser_context,
        .first_packet_index = first_contribution.packet_index,
        .first_flow_packet_index = first_contribution.flow_packet_index,
        .intra_packet_ordinal = allocate_tls_scanner_intra_packet_ordinal(state, first_contribution.packet_index),
    };
    state.saw_tls_context = true;
}

TlsScannerConsumedPrefix consume_tls_scanner_original_prefix(
    TlsStreamScannerState& state,
    const std::size_t original_byte_count
) {
    TlsScannerConsumedPrefix consumed {};
    std::size_t remaining_original_bytes = original_byte_count;
    bool first = true;

    while (remaining_original_bytes > 0U && !state.buffered_contributions.empty()) {
        auto& contribution = state.buffered_contributions.front();
        if (first) {
            consumed.first_packet_index = contribution.packet_index;
            consumed.first_flow_packet_index = contribution.flow_packet_index;
            first = false;
        }

        append_unique_packet_index(consumed.packet_indices, contribution.packet_index);

        const auto original_contribution = std::min(remaining_original_bytes, contribution.original_byte_count);
        const auto captured_contribution = std::min(original_contribution, contribution.captured_bytes.size());
        consumed.captured_bytes.insert(
            consumed.captured_bytes.end(),
            contribution.captured_bytes.begin(),
            contribution.captured_bytes.begin() + static_cast<std::ptrdiff_t>(captured_contribution)
        );

        if (contribution.packet_captured_length < contribution.packet_original_length &&
            captured_contribution < original_contribution) {
            std::ostringstream contribution_note {};
            contribution_note << "#" << (contribution.packet_index + 1U)
                              << " contributed " << captured_contribution
                              << " / " << original_contribution << " bytes";
            consumed.has_constricted_contribution = true;
            consumed.constricted_contribution_notes.push_back(contribution_note.str());

            std::ostringstream packet_note {};
            packet_note << "  Constricted packet #" << (contribution.packet_index + 1U)
                        << ": captured " << contribution.packet_captured_length
                        << " / original " << contribution.packet_original_length << " bytes.";
            consumed.constricted_packet_notes.push_back(packet_note.str());
        }

        remaining_original_bytes -= original_contribution;
        contribution.original_byte_count -= original_contribution;
        contribution.captured_bytes.erase(
            contribution.captured_bytes.begin(),
            contribution.captured_bytes.begin() + static_cast<std::ptrdiff_t>(captured_contribution)
        );

        if (contribution.original_byte_count == 0U) {
            state.buffered_contributions.erase(state.buffered_contributions.begin());
        }
    }

    return consumed;
}

TlsScannedStreamRow make_tls_scanned_stream_row(
    const TlsStreamPresentationItem& item,
    const std::uint64_t first_packet_index,
    const std::uint64_t first_flow_packet_index,
    const std::uint32_t intra_packet_ordinal
) {
    return TlsScannedStreamRow {
        .item = item,
        .first_packet_index = first_packet_index,
        .first_flow_packet_index = first_flow_packet_index,
        .intra_packet_ordinal = intra_packet_ordinal,
    };
}

std::optional<TlsScannedStreamRow> make_tls_stream_scanner_partial_row(
    const TlsStreamScannerState& state,
    const StreamMaterializationStability stability
) {
    if (state.buffered_contributions.empty()) {
        return std::nullopt;
    }

    const auto captured_bytes = flatten_tls_stream_scanner_captured_bytes(state);
    if (captured_bytes.empty()) {
        return std::nullopt;
    }

    std::vector<std::uint64_t> packet_indices {};
    bool has_constricted_contribution = false;
    std::vector<std::string> constricted_contribution_notes {};
    std::vector<std::string> constricted_packet_notes {};
    for (const auto& contribution : state.buffered_contributions) {
        append_unique_packet_index(packet_indices, contribution.packet_index);
        const auto captured_contribution = std::min(contribution.captured_bytes.size(), contribution.original_byte_count);
        if (contribution.packet_captured_length < contribution.packet_original_length &&
            captured_contribution < contribution.original_byte_count) {
            std::ostringstream contribution_note {};
            contribution_note << "#" << (contribution.packet_index + 1U)
                              << " contributed " << captured_contribution
                              << " / " << contribution.original_byte_count << " bytes";
            constricted_contribution_notes.push_back(contribution_note.str());
            std::ostringstream packet_note {};
            packet_note << "  Constricted packet #" << (contribution.packet_index + 1U)
                        << ": captured " << contribution.packet_captured_length
                        << " / original " << contribution.packet_original_length << " bytes.";
            constricted_packet_notes.push_back(packet_note.str());
            has_constricted_contribution = true;
        }
    }

    const bool has_record_prefix = captured_bytes.size() >= kTlsRecordHeaderSize &&
        looks_like_tls_record_prefix(std::span<const std::uint8_t>(captured_bytes.data(), captured_bytes.size()));
    const bool record_fragment = has_record_prefix || !state.prefer_payload_partial_for_unrecognized_trailing_bytes
        ? captured_bytes.size() >= kTlsRecordHeaderSize
        : false;

    const auto& first_contribution = state.buffered_contributions.front();
    const auto intra_packet_ordinal = state.pending_record.has_value()
        ? state.pending_record->intra_packet_ordinal
        : 0U;

    return make_tls_scanned_stream_row(
        TlsStreamPresentationItem {
            .label = record_fragment ? "TLS Record Fragment (partial)" : "TLS Payload (partial)",
            .byte_count = captured_bytes.size(),
            .packet_indices = std::move(packet_indices),
            .stability = stability,
            .has_constricted_contribution = has_constricted_contribution,
            .constricted_contribution_notes = std::move(constricted_contribution_notes),
            .constricted_packet_notes = std::move(constricted_packet_notes),
            .summary_payload_bytes = captured_bytes,
            .summary_records = {},
            .semantic_kind = record_fragment
                ? TlsStreamItemSemanticKind::partial_record
                : TlsStreamItemSemanticKind::partial_payload,
            .initial_parser_context = state.pending_record.has_value()
                ? state.pending_record->initial_parser_context
                : state.parser_context,
            .final_parser_context = state.pending_record.has_value()
                ? state.pending_record->initial_parser_context
                : state.parser_context,
        },
        first_contribution.packet_index,
        first_contribution.flow_packet_index,
        intra_packet_ordinal
    );
}

}  // namespace

TlsStreamScannerState make_tls_stream_scanner_state(
    const Direction direction,
    const bool prefer_payload_partial_for_unrecognized_trailing_bytes
) {
    return TlsStreamScannerState {
        .direction = direction,
        .buffered_contributions = {},
        .pending_record = std::nullopt,
        .post_change_cipher_spec = false,
        .saw_tls_context = false,
        .parser_context = TlsInspectionParserContext {
            .semantic_state = TlsInspectionSemanticState::plaintext,
        },
        .prefer_payload_partial_for_unrecognized_trailing_bytes =
            prefer_payload_partial_for_unrecognized_trailing_bytes,
        .ordinal_packet_index = 0U,
        .next_intra_packet_ordinal = 0U,
    };
}

TlsStreamScannerOutput consume_tls_stream_scanner(
    TlsStreamScannerState& state,
    const std::span<const TlsStreamScannerContribution> contributions,
    const std::size_t max_finalized_items,
    const TlsStreamScannerFinishMode finish_mode
) {
    TlsStreamScannerOutput output {};
    append_tls_stream_scanner_contributions(state, contributions);

    if (max_finalized_items == 0U) {
        output.budget_exhausted = !state.buffered_contributions.empty();
        return output;
    }

    while (output.stable_rows.size() < max_finalized_items) {
        if (state.buffered_contributions.empty()) {
            state.pending_record.reset();
            break;
        }

        maybe_initialize_tls_scanner_pending_record(state);
        if (!state.pending_record.has_value()) {
            break;
        }

        if (tls_stream_scanner_total_original_bytes(state) < state.pending_record->total_byte_count) {
            break;
        }

        auto consumed = consume_tls_scanner_original_prefix(state, state.pending_record->total_byte_count);
        const auto finalized_record_span = std::span<const std::uint8_t>(
            consumed.captured_bytes.data(),
            consumed.captured_bytes.size());
        const auto finalized_semantic_kind = tls_stream_semantic_kind(
            finalized_record_span,
            state.post_change_cipher_spec
        );
        const auto inspection = inspect_tls_record_with_exact_context(
            state.pending_record->initial_parser_context,
            finalized_record_span
        );
        const auto final_parser_context = inspection.has_value()
            ? inspection->final_context
            : advance_tls_parser_context_with_exact_record(
                state.pending_record->initial_parser_context,
                finalized_record_span
            );
        auto item = TlsStreamPresentationItem {
            .label = tls_stream_label(finalized_record_span, finalized_semantic_kind),
            .byte_count = state.pending_record->total_byte_count,
            .packet_indices = std::move(consumed.packet_indices),
            .stability = StreamMaterializationStability::stable,
            .has_constricted_contribution = consumed.has_constricted_contribution,
            .constricted_contribution_notes = std::move(consumed.constricted_contribution_notes),
            .constricted_packet_notes = std::move(consumed.constricted_packet_notes),
            .summary_payload_bytes = consumed.captured_bytes,
            .summary_records = inspection.has_value() ? std::move(inspection->records) : std::vector<TlsRecordModel> {},
            .semantic_kind = finalized_semantic_kind,
            .initial_parser_context = state.pending_record->initial_parser_context,
            .final_parser_context = final_parser_context,
        };
        output.stable_rows.push_back(make_tls_scanned_stream_row(
            item,
            state.pending_record->first_packet_index,
            state.pending_record->first_flow_packet_index,
            state.pending_record->intra_packet_ordinal
        ));
        state.parser_context = final_parser_context;
        sync_tls_parser_context_flags(state.parser_context, state.post_change_cipher_spec, state.saw_tls_context);
        state.pending_record.reset();
    }

    if (output.stable_rows.size() >= max_finalized_items && !state.buffered_contributions.empty()) {
        output.budget_exhausted = true;
        return output;
    }

    if (state.buffered_contributions.empty()) {
        state.pending_record.reset();
        return output;
    }

    maybe_initialize_tls_scanner_pending_record(state);

    if (finish_mode == TlsStreamScannerFinishMode::flow_end) {
        const auto partial_row = make_tls_stream_scanner_partial_row(
            state,
            StreamMaterializationStability::stable
        );
        if (partial_row.has_value() && output.stable_rows.size() < max_finalized_items) {
            output.stable_rows.push_back(*partial_row);
            state.buffered_contributions.clear();
            state.pending_record.reset();
        } else if (partial_row.has_value()) {
            output.budget_exhausted = true;
        }
        return output;
    }

    if (finish_mode == TlsStreamScannerFinishMode::window_end ||
        finish_mode == TlsStreamScannerFinishMode::tcp_gap) {
        const bool stable_constricted = std::any_of(
            state.buffered_contributions.begin(),
            state.buffered_contributions.end(),
            [](const TlsStreamScannerBufferedContribution& contribution) {
                return contribution.packet_captured_length < contribution.packet_original_length;
            }
        );
        const auto partial_row = make_tls_stream_scanner_partial_row(
            state,
            stable_constricted ? StreamMaterializationStability::stable : StreamMaterializationStability::window_incomplete
        );
        if (partial_row.has_value()) {
            if (stable_constricted) {
                if (output.stable_rows.size() < max_finalized_items) {
                    output.stable_rows.push_back(*partial_row);
                    state.buffered_contributions.clear();
                    state.pending_record.reset();
                } else {
                    output.budget_exhausted = true;
                }
            } else {
                output.provisional_row = partial_row;
                output.provisional_depends_on_more_input = true;
            }
        }
    }

    return output;
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
    std::size_t offset = 0U;
    bool post_change_cipher_spec = false;
    TlsInspectionParserContext parser_context {
        .semantic_state = TlsInspectionSemanticState::plaintext,
    };

    while (offset < payload_bytes.size()) {
        if (!looks_like_tls_record_prefix(payload_bytes, offset)) {
            const auto trailing = payload_bytes.subspan(offset);
            if (!trailing.empty()) {
                presentation.items.push_back(TlsStreamPresentationItem {
                    .label = "TLS Payload (partial)",
                    .byte_count = trailing.size(),
                    .packet_indices = {packet_index},
                    .summary_payload_bytes = std::vector<std::uint8_t>(trailing.begin(), trailing.end()),
                    .summary_records = {},
                    .semantic_kind = TlsStreamItemSemanticKind::partial_payload,
                    .initial_parser_context = parser_context,
                    .final_parser_context = parser_context,
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
                .summary_payload_bytes = std::vector<std::uint8_t>(trailing.begin(), trailing.end()),
                .summary_records = {},
                .semantic_kind = TlsStreamItemSemanticKind::partial_record,
                .initial_parser_context = parser_context,
                .final_parser_context = parser_context,
            });
            return presentation;
        }

        const auto record_bytes = payload_bytes.subspan(offset, *record_size);
        const auto semantic_kind = tls_stream_semantic_kind(record_bytes, post_change_cipher_spec);
        const auto inspection = inspect_tls_record_with_exact_context(parser_context, record_bytes);
        const auto final_parser_context = inspection.has_value()
            ? inspection->final_context
            : advance_tls_parser_context_with_exact_record(parser_context, record_bytes);
        presentation.items.push_back(TlsStreamPresentationItem {
            .label = tls_stream_label(record_bytes, semantic_kind),
            .byte_count = record_bytes.size(),
            .packet_indices = {packet_index},
            .summary_payload_bytes = std::vector<std::uint8_t>(record_bytes.begin(), record_bytes.end()),
            .summary_records = inspection.has_value() ? std::move(inspection->records) : std::vector<TlsRecordModel> {},
            .semantic_kind = semantic_kind,
            .initial_parser_context = parser_context,
            .final_parser_context = final_parser_context,
        });
        parser_context = final_parser_context;
        sync_tls_parser_context_flags(parser_context, post_change_cipher_spec, presentation.handled);
        offset += *record_size;
    }

    return presentation;
}

bool append_bounded_tls_item(
    TlsDirectionalStreamPresentation& presentation,
    TlsStreamPresentationItem item,
    std::size_t& logical_item_count,
    const std::size_t skip_item_count,
    const std::size_t max_item_count
) {
    if (logical_item_count >= skip_item_count && presentation.items.size() < max_item_count) {
        presentation.items.push_back(std::move(item));
    }
    ++logical_item_count;
    return presentation.items.size() < max_item_count;
}

TlsDirectionalStreamPresentation build_tls_stream_items_from_contiguous_reassembly(
    const CaptureSession& session,
    const std::size_t flow_index,
    const Direction direction,
    const std::span<const PacketRef> direction_packets,
    const std::size_t skip_item_count,
    const std::size_t max_item_count,
    const bool actual_end_of_flow_known
) {
    TlsDirectionalStreamPresentation presentation {};
    if (max_item_count == 0U) {
        return presentation;
    }

    const auto result = session.reassemble_flow_direction(
        ReassemblyRequest {
            .flow_index = flow_index,
            .direction = direction,
            .max_packets = direction_packets.size(),
            .max_bytes = 256U * 1024U,
        },
        direction_packets
    );
    if (!result.has_value() || result->bytes.empty()) {
        return presentation;
    }

    const auto payload_bytes = std::span<const std::uint8_t>(result->bytes.data(), result->bytes.size());
    const bool has_tls_prefix = looks_like_tls_record_prefix(payload_bytes);
    if (!has_tls_prefix) {
        return presentation;
    }

    const auto chunks = build_reassembled_payload_chunks(*result);
    if (!chunks.has_value() || chunks->empty()) {
        return presentation;
    }

    std::map<std::uint64_t, std::uint64_t> flow_packet_index_by_packet_index {};
    for (std::size_t index = 0U; index < direction_packets.size(); ++index) {
        flow_packet_index_by_packet_index.emplace(direction_packets[index].packet_index, static_cast<std::uint64_t>(index + 1U));
    }

    std::vector<TlsStreamScannerContribution> contributions {};
    contributions.reserve(chunks->size());
    std::size_t payload_offset = 0U;
    for (const auto& chunk : *chunks) {
        const auto flow_packet_index_it = flow_packet_index_by_packet_index.find(chunk.packet_index);
        contributions.push_back(TlsStreamScannerContribution {
            .packet_index = chunk.packet_index,
            .flow_packet_index = flow_packet_index_it != flow_packet_index_by_packet_index.end()
                ? flow_packet_index_it->second
                : 0U,
            .captured_bytes = std::vector<std::uint8_t>(
                payload_bytes.begin() + static_cast<std::ptrdiff_t>(payload_offset),
                payload_bytes.begin() + static_cast<std::ptrdiff_t>(payload_offset + chunk.byte_count)
            ),
            .original_byte_count = chunk.byte_count,
            .packet_captured_length = static_cast<std::uint32_t>(chunk.byte_count),
            .packet_original_length = static_cast<std::uint32_t>(chunk.byte_count),
        });
        payload_offset += chunk.byte_count;
    }

    std::size_t logical_item_count = 0U;
    auto scanner_state = make_tls_stream_scanner_state(direction, true);
    const auto scanner_output = consume_tls_stream_scanner(
        scanner_state,
        contributions,
        skip_item_count + max_item_count,
        actual_end_of_flow_known
            ? TlsStreamScannerFinishMode::flow_end
            : TlsStreamScannerFinishMode::window_end
    );

    for (const auto& row : scanner_output.stable_rows) {
        append_bounded_tls_item(
            presentation,
            row.item,
            logical_item_count,
            skip_item_count,
            max_item_count
        );
    }
    if (scanner_output.provisional_row.has_value()) {
        append_bounded_tls_item(
            presentation,
            scanner_output.provisional_row->item,
            logical_item_count,
            skip_item_count,
            max_item_count
        );
    }

    presentation.used_reassembly =
        scanner_state.saw_tls_context
        || !scanner_output.stable_rows.empty()
        || scanner_output.provisional_row.has_value();
    if (presentation.used_reassembly) {
        presentation.covered_packet_indices.insert(result->packet_indices.begin(), result->packet_indices.end());
    }
    if (result->stopped_at_gap && result->first_gap_packet_index != 0U) {
        append_bounded_tls_item(
            presentation,
            TlsStreamPresentationItem {
            .label = "TLS Gap",
            .byte_count = 0U,
            .packet_indices = {result->first_gap_packet_index},
            .summary_records = {},
            .semantic_kind = TlsStreamItemSemanticKind::gap,
            },
            logical_item_count,
            skip_item_count,
            max_item_count
        );
        presentation.used_reassembly = true;
        presentation.explicit_gap_item_emitted = true;
        presentation.first_gap_packet_index = result->first_gap_packet_index;
        presentation.fallback_label = "TLS Payload";
    }

    return presentation;
}

TlsDirectionalStreamPresentation build_tls_stream_items_from_constricted_packets(
    const CaptureSession& session,
    const std::size_t flow_index,
    const Direction direction,
    std::span<const PacketRef> direction_packets,
    const std::size_t skip_item_count,
    const std::size_t max_item_count,
    const bool actual_end_of_flow_known
) {
    TlsDirectionalStreamPresentation presentation {};
    if (direction_packets.empty() || max_item_count == 0U) {
        return presentation;
    }

    const auto gap_packet_index = session.selected_flow_tcp_direction_first_gap_packet_index(flow_index, direction);
    const auto gap_included_in_window = gap_packet_index.has_value()
        && std::any_of(direction_packets.begin(), direction_packets.end(), [&](const PacketRef& packet) {
            return packet.packet_index >= *gap_packet_index;
        });
    std::size_t logical_item_count = 0U;

    auto emit_gap_item = [&]() {
        if (presentation.explicit_gap_item_emitted || !gap_packet_index.has_value()) {
            return;
        }

        append_bounded_tls_item(
            presentation,
            TlsStreamPresentationItem {
            .label = "TLS Gap",
            .byte_count = 0U,
            .packet_indices = {*gap_packet_index},
            .summary_records = {},
            .semantic_kind = TlsStreamItemSemanticKind::gap,
            },
            logical_item_count,
            skip_item_count,
            max_item_count
        );
        presentation.used_reassembly = true;
        presentation.explicit_gap_item_emitted = true;
        presentation.first_gap_packet_index = *gap_packet_index;
        presentation.fallback_label = "TLS Payload";
    };

    std::vector<TlsStreamScannerContribution> contributions {};
    contributions.reserve(direction_packets.size());
    for (const auto& packet : direction_packets) {
        if (gap_packet_index.has_value() && packet.packet_index >= *gap_packet_index) {
            break;
        }

        if (session.should_suppress_selected_flow_tcp_payload(flow_index, packet.packet_index)) {
            continue;
        }

        auto payload_bytes = session.read_selected_flow_transport_payload(flow_index, packet);
        if (payload_bytes.empty()) {
            continue;
        }

        const auto trim_prefix_bytes = session.selected_flow_tcp_payload_trim_prefix_bytes(flow_index, packet.packet_index);
        if (trim_prefix_bytes >= payload_bytes.size()) {
            continue;
        }

        const auto original_payload_length = derive_original_tcp_payload_length_from_headers(session, packet);
        if (!original_payload_length.has_value()) {
            continue;
        }

        auto payload_vector = std::vector<std::uint8_t>(
            payload_bytes.data() + static_cast<std::ptrdiff_t>(trim_prefix_bytes),
            payload_bytes.data() + static_cast<std::ptrdiff_t>(payload_bytes.size())
        );
        const auto original_byte_count = *original_payload_length > trim_prefix_bytes
            ? *original_payload_length - trim_prefix_bytes
            : 0U;
        if (original_byte_count == 0U) {
            continue;
        }
        contributions.push_back(TlsStreamScannerContribution {
            .packet_index = packet.packet_index,
            .flow_packet_index = packet.packet_index + 1U,
            .captured_bytes = std::move(payload_vector),
            .original_byte_count = original_byte_count,
            .packet_captured_length = packet.captured_length,
            .packet_original_length = packet.original_length,
        });
    }

    auto scanner_state = make_tls_stream_scanner_state(direction, false);
    const auto scanner_output = consume_tls_stream_scanner(
        scanner_state,
        contributions,
        skip_item_count + max_item_count,
        actual_end_of_flow_known
            ? TlsStreamScannerFinishMode::flow_end
            : TlsStreamScannerFinishMode::window_end
    );

    for (const auto& row : scanner_output.stable_rows) {
        append_bounded_tls_item(
            presentation,
            row.item,
            logical_item_count,
            skip_item_count,
            max_item_count
        );
        presentation.covered_packet_indices.insert(
            row.item.packet_indices.begin(),
            row.item.packet_indices.end()
        );
    }
    if (!gap_included_in_window && scanner_output.provisional_row.has_value()) {
        append_bounded_tls_item(
            presentation,
            scanner_output.provisional_row->item,
            logical_item_count,
            skip_item_count,
            max_item_count
        );
        presentation.covered_packet_indices.insert(
            scanner_output.provisional_row->item.packet_indices.begin(),
            scanner_output.provisional_row->item.packet_indices.end()
        );
    }

    const bool have_tls_context =
        scanner_state.saw_tls_context
        || !scanner_output.stable_rows.empty()
        || scanner_output.provisional_row.has_value();
    if (!have_tls_context) {
        return {};
    }
    presentation.used_reassembly = true;
    if (gap_included_in_window) {
        emit_gap_item();
    }
    return presentation;
}

TlsDirectionalStreamPresentation build_tls_stream_items_from_reassembly(
    const CaptureSession& session,
    const std::size_t flow_index,
    const Direction direction,
    const std::span<const PacketRef> direction_packets
) {
    if (direction_contains_truncated_packet(direction_packets)) {
        return build_tls_stream_items_from_constricted_packets(
            session,
            flow_index,
            direction,
            direction_packets,
            0U,
            std::numeric_limits<std::size_t>::max(),
            true
        );
    }

    return build_tls_stream_items_from_contiguous_reassembly(
        session,
        flow_index,
        direction,
        direction_packets,
        0U,
        std::numeric_limits<std::size_t>::max(),
        true
    );
}

TlsDirectionalStreamPresentation build_tls_stream_items_from_reassembly_bounded(
    const CaptureSession& session,
    const std::size_t flow_index,
    const Direction direction,
    const std::span<const PacketRef> direction_packets,
    const std::size_t skip_item_count,
    const std::size_t max_item_count
) {
    if (direction_contains_truncated_packet(direction_packets)) {
        return build_tls_stream_items_from_constricted_packets(
            session,
            flow_index,
            direction,
            direction_packets,
            skip_item_count,
            max_item_count,
            false
        );
    }

    return build_tls_stream_items_from_contiguous_reassembly(
        session,
        flow_index,
        direction,
        direction_packets,
        skip_item_count,
        max_item_count,
        false
    );
}

TlsSelectedPacketAnalysis analyze_selected_packet_tls_contexts(
    CaptureSession& session,
    const std::size_t flow_index,
    const std::uint64_t selected_flow_packet_index,
    const std::size_t loaded_packet_window_count
) {
    TlsSelectedPacketAnalysis analysis {};
    if (loaded_packet_window_count == 0U) {
        return analysis;
    }

    const auto bounded_window_count = std::min(loaded_packet_window_count, session.flow_packet_count(flow_index));
    if (selected_flow_packet_index >= bounded_window_count) {
        return analysis;
    }

    session.prepare_selected_flow_packet_cache(flow_index, bounded_window_count);
    const auto retransmission_packets = session.suspected_tcp_retransmission_packet_indices(flow_index, bounded_window_count);
    session.set_selected_flow_tcp_payload_suppression(flow_index, retransmission_packets, bounded_window_count);

    const auto prefix_rows = session.list_flow_packets(flow_index, 0U, bounded_window_count);
    if (prefix_rows.empty() || selected_flow_packet_index >= prefix_rows.size()) {
        return analysis;
    }

    const auto& selected_row = prefix_rows[static_cast<std::size_t>(selected_flow_packet_index)];
    const auto selected_direction = direction_from_packet_row(selected_row);
    const auto gap_packet_index = session.selected_flow_tcp_direction_first_gap_packet_index(flow_index, selected_direction);
    bool selected_initial_context_recorded = false;

    std::optional<PendingSelectedTlsRecord> pending_record {};
    auto current_context = TlsInspectionParserContext {
        .semantic_state = TlsInspectionSemanticState::plaintext,
    };
    std::optional<std::uint16_t> negotiated_cipher_suite {};
    std::optional<std::uint16_t> negotiated_version {};
    TlsInspectionParser parser {};

    for (const auto& row : prefix_rows) {
        if (row.row_number == selected_row.row_number && !selected_initial_context_recorded) {
            const auto selected_packet = session.selected_flow_packet_at(flow_index, row.row_number);
            if (!selected_packet.has_value() ||
                (gap_packet_index.has_value() && selected_packet->packet_index >= *gap_packet_index)) {
                analysis.initial_parser_context = TlsInspectionParserContext {
                    .semantic_state = TlsInspectionSemanticState::unknown,
                };
            } else {
                current_context.negotiated_cipher_suite = negotiated_cipher_suite;
                current_context.negotiated_version = negotiated_version;
                analysis.initial_parser_context = current_context;
            }
            selected_initial_context_recorded = true;
        }

        const auto packet = session.selected_flow_packet_at(flow_index, row.row_number);
        if (!packet.has_value()) {
            continue;
        }

        if (gap_packet_index.has_value() &&
            packet->packet_index >= *gap_packet_index &&
            pending_record.has_value()) {
                if (const auto context = finalize_selected_packet_record_context(
                    std::move(*pending_record),
                    TlsSelectedPacketStatus::tcp_gap,
                    selected_flow_packet_index
                );
                context.has_value()) {
                analysis.reconstructed_records.push_back(std::move(*context));
            }
            break;
        }

        const auto metadata = derive_transient_packet_metadata(session, *packet);
        if (metadata.captured_transport_payload_length.value_or(0U) == 0U ||
            session.should_suppress_selected_flow_tcp_payload(flow_index, packet->packet_index)) {
            continue;
        }

        auto payload_bytes = session.read_selected_flow_transport_payload(flow_index, *packet);
        if (payload_bytes.empty()) {
            continue;
        }

        const auto trim_prefix_bytes = session.selected_flow_tcp_payload_trim_prefix_bytes(flow_index, packet->packet_index);
        if (trim_prefix_bytes >= payload_bytes.size()) {
            continue;
        }

        const auto original_payload_length = derive_original_tcp_payload_length_from_headers(session, *packet);
        if (!original_payload_length.has_value()) {
            if (pending_record.has_value()) {
                if (const auto context = finalize_selected_packet_record_context(
                        std::move(*pending_record),
                        TlsSelectedPacketStatus::malformed,
                        selected_flow_packet_index
                    );
                    context.has_value()) {
                    analysis.reconstructed_records.push_back(std::move(*context));
                }
                pending_record.reset();
            }
            break;
        }

        const auto payload_span = std::span<const std::uint8_t>(
            payload_bytes.data() + static_cast<std::ptrdiff_t>(trim_prefix_bytes),
            payload_bytes.size() - trim_prefix_bytes
        );
        const auto row_direction = direction_from_packet_row(row);
        if (row_direction != selected_direction) {
            const auto inspected = parser.inspect(payload_span, TlsInspectionParserContext {
                .semantic_state = TlsInspectionSemanticState::plaintext,
                .negotiated_cipher_suite = negotiated_cipher_suite,
                .negotiated_version = negotiated_version,
            });
            negotiated_cipher_suite = inspected.final_context.negotiated_cipher_suite;
            negotiated_version = inspected.final_context.negotiated_version;
            continue;
        }

        current_context.negotiated_cipher_suite = negotiated_cipher_suite;
        current_context.negotiated_version = negotiated_version;

        std::size_t captured_offset = 0U;
        std::size_t record_budget_remaining = *original_payload_length;
        std::size_t unique_original_remaining = *original_payload_length > trim_prefix_bytes
            ? *original_payload_length - trim_prefix_bytes
            : 0U;

        while (record_budget_remaining > 0U) {
            if (pending_record.has_value()) {
                const auto contributed_original_bytes = std::min(
                    unique_original_remaining,
                    pending_record->remaining_original_bytes
                );
                if (contributed_original_bytes == 0U) {
                    break;
                }

                const auto captured_remaining = payload_span.size() - std::min(payload_span.size(), captured_offset);
                const auto captured_contribution = std::min(captured_remaining, contributed_original_bytes);
                append_unique_packet_index(pending_record->packet_indices, packet->packet_index);

                if (captured_contribution > 0U) {
                    pending_record->contributions.push_back(TlsSelectedPacketContribution {
                        .packet_index = packet->packet_index,
                        .flow_packet_index = row.row_number - 1U,
                        .record_offset = pending_record->captured_bytes.size(),
                        .captured_byte_count = captured_contribution,
                    });
                    pending_record->captured_bytes.insert(
                        pending_record->captured_bytes.end(),
                        payload_span.begin() + static_cast<std::ptrdiff_t>(captured_offset),
                        payload_span.begin() + static_cast<std::ptrdiff_t>(captured_offset + captured_contribution)
                    );
                }

                if ((row.row_number - 1U) == selected_flow_packet_index) {
                    pending_record->selected_packet_participated = true;
                }

                if (packet->captured_length < packet->original_length && captured_contribution < contributed_original_bytes) {
                    append_constricted_packet_note(*pending_record, *packet);
                    append_constricted_contribution_note(
                        *pending_record,
                        *packet,
                        captured_contribution,
                        contributed_original_bytes
                    );
                }

                pending_record->remaining_original_bytes -= contributed_original_bytes;
                unique_original_remaining -= contributed_original_bytes;
                record_budget_remaining = contributed_original_bytes > record_budget_remaining
                    ? 0U
                    : record_budget_remaining - contributed_original_bytes;
                captured_offset += captured_contribution;

                if (pending_record->remaining_original_bytes == 0U) {
                    const auto status = finalized_selected_record_status(*pending_record);
                    if (status == TlsSelectedPacketStatus::complete &&
                        pending_record->captured_bytes.size() == pending_record->total_byte_count) {
                        current_context = advance_tls_parser_context_with_exact_record(
                            pending_record->initial_parser_context,
                            std::span<const std::uint8_t>(
                                pending_record->captured_bytes.data(),
                                pending_record->captured_bytes.size()
                            )
                        );
                        negotiated_cipher_suite = current_context.negotiated_cipher_suite;
                        negotiated_version = current_context.negotiated_version;
                    }
                    if (const auto context = finalize_selected_packet_record_context(
                            std::move(*pending_record),
                            status,
                            selected_flow_packet_index
                        );
                        context.has_value()) {
                        analysis.reconstructed_records.push_back(std::move(*context));
                    }
                    pending_record.reset();
                    continue;
                }

                break;
            }

            if (captured_offset >= payload_span.size()) {
                break;
            }

            const auto captured_remaining = payload_span.size() - captured_offset;
            const bool has_record_prefix = captured_remaining >= kTlsRecordHeaderSize &&
                looks_like_tls_record_prefix(payload_span, captured_offset);
            if (captured_remaining < kTlsRecordHeaderSize || !has_record_prefix) {
                break;
            }

            const auto record_body_length = static_cast<std::size_t>(read_be16(payload_span, captured_offset + 3U));
            const auto record_size = kTlsRecordHeaderSize + record_body_length;
            const auto contributed_original_bytes = std::min(record_budget_remaining, record_size);
            const auto contributed_unique_bytes = std::min(unique_original_remaining, contributed_original_bytes);
            const auto captured_contribution = std::min(captured_remaining, contributed_original_bytes);
            const auto captured_record_bytes = payload_span.subspan(captured_offset, captured_contribution);
            const auto semantic_kind = tls_stream_semantic_kind(
                captured_record_bytes,
                current_context.semantic_state == TlsInspectionSemanticState::post_change_cipher_spec
            );
            PendingSelectedTlsRecord record {
                .label = tls_stream_label(captured_record_bytes, semantic_kind),
                .total_byte_count = record_size,
                .remaining_original_bytes = record_size - contributed_original_bytes,
                .packet_indices = {packet->packet_index},
                .captured_bytes = std::vector<std::uint8_t>(captured_record_bytes.begin(), captured_record_bytes.end()),
                .semantic_kind = semantic_kind,
                .protocol_text = tls_record_protocol_text(captured_record_bytes, semantic_kind),
                .initial_parser_context = current_context,
            };

            if (captured_contribution > 0U) {
                record.contributions.push_back(TlsSelectedPacketContribution {
                    .packet_index = packet->packet_index,
                    .flow_packet_index = row.row_number - 1U,
                    .record_offset = 0U,
                    .captured_byte_count = captured_contribution,
                });
            }

            if ((row.row_number - 1U) == selected_flow_packet_index) {
                record.selected_packet_participated = true;
            }

            if (packet->captured_length < packet->original_length && captured_contribution < record_size) {
                append_constricted_packet_note(record, *packet);
            }
            append_constricted_contribution_note(
                record,
                *packet,
                captured_contribution,
                contributed_original_bytes
            );

            record_budget_remaining -= contributed_original_bytes;
            unique_original_remaining -= contributed_unique_bytes;
            captured_offset += captured_contribution;

            if (record.remaining_original_bytes == 0U) {
                const auto status = finalized_selected_record_status(record);
                if (status == TlsSelectedPacketStatus::complete &&
                    record.captured_bytes.size() == record.total_byte_count) {
                    current_context = advance_tls_parser_context_with_exact_record(
                        record.initial_parser_context,
                        std::span<const std::uint8_t>(
                            record.captured_bytes.data(),
                            record.captured_bytes.size()
                        )
                    );
                    negotiated_cipher_suite = current_context.negotiated_cipher_suite;
                    negotiated_version = current_context.negotiated_version;
                }
                if (const auto context = finalize_selected_packet_record_context(
                        std::move(record),
                        status,
                        selected_flow_packet_index
                    );
                    context.has_value()) {
                    analysis.reconstructed_records.push_back(std::move(*context));
                }
                continue;
            }

            pending_record = std::move(record);
            break;
        }
    }

    if (pending_record.has_value()) {
        const auto status = pending_record->has_constricted_contribution
            ? TlsSelectedPacketStatus::capture_constricted
            : TlsSelectedPacketStatus::incomplete_window;
        if (const auto context = finalize_selected_packet_record_context(
                std::move(*pending_record),
                status,
                selected_flow_packet_index
            );
            context.has_value()) {
            analysis.reconstructed_records.push_back(std::move(*context));
        }
    }

    return analysis;
}

std::vector<TlsSelectedPacketRecordContext> build_selected_packet_tls_contexts(
    CaptureSession& session,
    const std::size_t flow_index,
    const std::uint64_t selected_flow_packet_index,
    const std::size_t loaded_packet_window_count
) {
    return analyze_selected_packet_tls_contexts(
        session,
        flow_index,
        selected_flow_packet_index,
        loaded_packet_window_count
    ).reconstructed_records;
}

std::optional<std::string> derive_tls_service_hint_for_loaded_flow_prefix(
    CaptureSession& session,
    const std::size_t flow_index,
    const std::size_t loaded_packet_window_count
) {
    if (loaded_packet_window_count == 0U) {
        return std::nullopt;
    }

    const auto bounded_window_count = std::min(loaded_packet_window_count, session.flow_packet_count(flow_index));
    if (bounded_window_count == 0U) {
        return std::nullopt;
    }

    session.prepare_selected_flow_packet_cache(flow_index, bounded_window_count);
    const auto retransmission_packets = session.suspected_tcp_retransmission_packet_indices(flow_index, bounded_window_count);
    session.set_selected_flow_tcp_payload_suppression(flow_index, retransmission_packets, bounded_window_count);

    const auto prefix_rows = session.list_flow_packets(flow_index, 0U, bounded_window_count);
    if (prefix_rows.empty()) {
        return std::nullopt;
    }

    struct DirectionState {
        std::optional<PendingTlsHintRecord> pending_record {};
        std::optional<std::uint64_t> first_gap_packet_index {};
    };

    DirectionState a_to_b_state {
        .first_gap_packet_index = session.selected_flow_tcp_direction_first_gap_packet_index(flow_index, Direction::a_to_b),
    };
    DirectionState b_to_a_state {
        .first_gap_packet_index = session.selected_flow_tcp_direction_first_gap_packet_index(flow_index, Direction::b_to_a),
    };

    for (const auto& row : prefix_rows) {
        const auto direction = direction_from_packet_row(row);
        auto& state = direction == Direction::a_to_b ? a_to_b_state : b_to_a_state;

        const auto packet = session.selected_flow_packet_at(flow_index, row.row_number);
        if (!packet.has_value()) {
            continue;
        }

        if (state.first_gap_packet_index.has_value() &&
            packet->packet_index >= *state.first_gap_packet_index &&
            state.pending_record.has_value()) {
            state.pending_record.reset();
            continue;
        }

        const auto metadata = derive_transient_packet_metadata(session, *packet);
        if (metadata.captured_transport_payload_length.value_or(0U) == 0U ||
            session.should_suppress_selected_flow_tcp_payload(flow_index, packet->packet_index)) {
            continue;
        }

        auto payload_bytes = session.read_selected_flow_transport_payload(flow_index, *packet);
        if (payload_bytes.empty()) {
            continue;
        }

        const auto trim_prefix_bytes = session.selected_flow_tcp_payload_trim_prefix_bytes(flow_index, packet->packet_index);
        if (trim_prefix_bytes >= payload_bytes.size()) {
            continue;
        }

        const auto original_payload_length = derive_original_tcp_payload_length_from_headers(session, *packet);
        if (!original_payload_length.has_value()) {
            state.pending_record.reset();
            continue;
        }

        const auto payload_span = std::span<const std::uint8_t>(
            payload_bytes.data() + static_cast<std::ptrdiff_t>(trim_prefix_bytes),
            payload_bytes.size() - trim_prefix_bytes
        );

        std::size_t captured_offset = 0U;
        std::size_t record_budget_remaining = *original_payload_length;
        std::size_t unique_original_remaining = *original_payload_length > trim_prefix_bytes
            ? *original_payload_length - trim_prefix_bytes
            : 0U;

        while (record_budget_remaining > 0U) {
            if (state.pending_record.has_value()) {
                const auto contributed_original_bytes = std::min(
                    unique_original_remaining,
                    state.pending_record->remaining_original_bytes
                );
                if (contributed_original_bytes == 0U) {
                    break;
                }

                const auto captured_remaining = payload_span.size() - std::min(payload_span.size(), captured_offset);
                const auto captured_contribution = std::min(captured_remaining, contributed_original_bytes);
                if (captured_contribution > 0U) {
                    state.pending_record->captured_bytes.insert(
                        state.pending_record->captured_bytes.end(),
                        payload_span.begin() + static_cast<std::ptrdiff_t>(captured_offset),
                        payload_span.begin() + static_cast<std::ptrdiff_t>(captured_offset + captured_contribution)
                    );
                }

                state.pending_record->remaining_original_bytes -= contributed_original_bytes;
                unique_original_remaining -= contributed_original_bytes;
                record_budget_remaining = contributed_original_bytes > record_budget_remaining
                    ? 0U
                    : record_budget_remaining - contributed_original_bytes;
                captured_offset += captured_contribution;

                if (state.pending_record->remaining_original_bytes == 0U) {
                    if (state.pending_record->captured_bytes.size() == state.pending_record->total_byte_count) {
                        if (const auto service_hint = extract_service_hint_from_complete_tls_record(
                                std::span<const std::uint8_t>(
                                    state.pending_record->captured_bytes.data(),
                                    state.pending_record->captured_bytes.size()
                                )
                            );
                            service_hint.has_value()) {
                            return service_hint;
                        }
                    }
                    state.pending_record.reset();
                    continue;
                }

                break;
            }

            if (captured_offset >= payload_span.size()) {
                break;
            }

            const auto captured_remaining = payload_span.size() - captured_offset;
            const bool has_record_prefix = captured_remaining >= kTlsRecordHeaderSize &&
                looks_like_tls_record_prefix(payload_span, captured_offset);
            if (captured_remaining < kTlsRecordHeaderSize || !has_record_prefix) {
                break;
            }

            const auto record_body_length = static_cast<std::size_t>(read_be16(payload_span, captured_offset + 3U));
            const auto record_size = kTlsRecordHeaderSize + record_body_length;
            const auto contributed_original_bytes = std::min(record_budget_remaining, record_size);
            const auto contributed_unique_bytes = std::min(unique_original_remaining, contributed_original_bytes);
            const auto captured_contribution = std::min(captured_remaining, contributed_original_bytes);
            const auto captured_record_bytes = payload_span.subspan(captured_offset, captured_contribution);

            PendingTlsHintRecord record {
                .total_byte_count = record_size,
                .remaining_original_bytes = record_size - contributed_original_bytes,
                .captured_bytes = std::vector<std::uint8_t>(captured_record_bytes.begin(), captured_record_bytes.end()),
            };

            record_budget_remaining -= contributed_original_bytes;
            unique_original_remaining -= contributed_unique_bytes;
            captured_offset += captured_contribution;

            if (record.remaining_original_bytes == 0U) {
                if (record.captured_bytes.size() == record.total_byte_count) {
                    if (const auto service_hint = extract_service_hint_from_complete_tls_record(
                            std::span<const std::uint8_t>(
                                record.captured_bytes.data(),
                                record.captured_bytes.size()
                            )
                        );
                        service_hint.has_value()) {
                        return service_hint;
                    }
                }
                continue;
            }

            state.pending_record = std::move(record);
            break;
        }
    }

    return std::nullopt;
}

}  // namespace pfl::session_detail
