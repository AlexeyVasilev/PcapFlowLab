#include "app/session/AdvancedFlowFilterFormat.h"

#include <algorithm>
#include <array>
#include <charconv>
#include <cctype>
#include <cstdint>
#include <limits>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

#include "app/session/SessionFormatting.h"
#include "core/domain/FlowHints.h"
#include "core/domain/ProtocolId.h"
#include "core/domain/ProtocolPath.h"

namespace pfl::session_detail {

namespace {

constexpr std::string_view kFormatVersionKey {"format_version"};
constexpr std::string_view kFormatVersionValue {"2"};

char ascii_lower(const char value) noexcept {
    if (value >= 'A' && value <= 'Z') {
        return static_cast<char>(value - 'A' + 'a');
    }
    return value;
}

bool equals_ascii_case_insensitive(const std::string_view left, const std::string_view right) noexcept {
    if (left.size() != right.size()) {
        return false;
    }

    for (std::size_t index = 0; index < left.size(); ++index) {
        if (ascii_lower(left[index]) != ascii_lower(right[index])) {
            return false;
        }
    }
    return true;
}

std::optional<bool> parse_bool_token(const std::string_view token) noexcept {
    if (equals_ascii_case_insensitive(token, "true")) {
        return true;
    }
    if (equals_ascii_case_insensitive(token, "false")) {
        return false;
    }
    return std::nullopt;
}

bool is_ascii_whitespace(const char ch) noexcept {
    return ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n' || ch == '\f' || ch == '\v';
}

std::string_view trim_ascii(const std::string_view value) noexcept {
    std::size_t first = 0U;
    while (first < value.size() && is_ascii_whitespace(value[first])) {
        ++first;
    }

    std::size_t last = value.size();
    while (last > first && is_ascii_whitespace(value[last - 1U])) {
        --last;
    }

    return value.substr(first, last - first);
}

struct ParsedAssignmentLine {
    std::string_view content {};
    std::size_t comment_column {0U};
};

struct ParsedQuotedString {
    bool ok {false};
    bool unterminated {false};
    bool invalid_escape {false};
    std::size_t error_column {0U};
    std::string value {};
};

struct ParsedUint64 {
    bool ok {false};
    bool overflow {false};
    std::uint64_t value {0U};
};

struct ParsedUint32 {
    bool ok {false};
    bool overflow {false};
    std::uint32_t value {0U};
};

struct ParsedUint16 {
    bool ok {false};
    bool overflow {false};
    std::uint16_t value {0U};
};

struct ParsedUint8 {
    bool ok {false};
    bool overflow {false};
    std::uint8_t value {0U};
};

struct ParsedPortRange {
    bool ok {false};
    bool overflow {false};
    bool reversed {false};
    AdvancedFlowFilterPortRange range {};
};

struct ParsedLayerToken {
    bool ok {false};
    bool invalid_syntax {false};
    AdvancedFlowFilterProtocolLayerPredicate predicate {};
};

struct KeySegments {
    std::vector<std::string_view> values {};
};

AdvancedFlowFilterTextParseResult make_parse_error(
    const AdvancedFlowFilterTextParseStatus status,
    const std::size_t line,
    const std::optional<std::size_t> column,
    std::string key,
    std::string token,
    std::string message
) {
    AdvancedFlowFilterTextParseResult result {};
    result.status = status;
    result.issue = AdvancedFlowFilterTextParseIssue {
        .status = status,
        .line = line,
        .column = column,
        .key = std::move(key),
        .token = std::move(token),
        .message = std::move(message),
    };
    return result;
}

AdvancedFlowFilterTextFormatResult make_format_error(std::string category, std::string message) {
    AdvancedFlowFilterTextFormatResult result {};
    result.status = AdvancedFlowFilterTextFormatStatus::unrepresentable_spec;
    result.issue = AdvancedFlowFilterTextFormatIssue {
        .status = AdvancedFlowFilterTextFormatStatus::unrepresentable_spec,
        .category = std::move(category),
        .message = std::move(message),
    };
    return result;
}

ParsedAssignmentLine strip_trailing_comment(const std::string_view raw_line) {
    bool in_quotes = false;
    bool escaped = false;

    for (std::size_t index = 0; index < raw_line.size(); ++index) {
        const auto ch = raw_line[index];
        if (in_quotes) {
            if (escaped) {
                escaped = false;
                continue;
            }
            if (ch == '\\') {
                escaped = true;
                continue;
            }
            if (ch == '"') {
                in_quotes = false;
            }
            continue;
        }

        if (ch == '"') {
            in_quotes = true;
            continue;
        }
        if (ch == '#') {
            return ParsedAssignmentLine {
                .content = trim_ascii(raw_line.substr(0U, index)),
                .comment_column = index + 1U,
            };
        }
    }

    return ParsedAssignmentLine {
        .content = trim_ascii(raw_line),
        .comment_column = raw_line.size() + 1U,
    };
}

std::optional<std::size_t> find_assignment_equals(const std::string_view line) {
    bool in_quotes = false;
    bool escaped = false;

    for (std::size_t index = 0; index < line.size(); ++index) {
        const auto ch = line[index];
        if (in_quotes) {
            if (escaped) {
                escaped = false;
                continue;
            }
            if (ch == '\\') {
                escaped = true;
                continue;
            }
            if (ch == '"') {
                in_quotes = false;
            }
            continue;
        }

        if (ch == '"') {
            in_quotes = true;
            continue;
        }
        if (ch == '=') {
            return index;
        }
    }

    return std::nullopt;
}

KeySegments split_key_segments(const std::string_view key) {
    KeySegments segments {};
    std::size_t start = 0U;
    while (start <= key.size()) {
        const auto dot_pos = key.find('.', start);
        if (dot_pos == std::string_view::npos) {
            segments.values.push_back(key.substr(start));
            break;
        }
        segments.values.push_back(key.substr(start, dot_pos - start));
        start = dot_pos + 1U;
    }
    return segments;
}

ParsedQuotedString parse_quoted_string(const std::string_view value, const std::size_t value_column_base) {
    ParsedQuotedString parsed {};
    if (value.empty() || value.front() != '"') {
        parsed.error_column = value_column_base;
        return parsed;
    }

    std::size_t index = 1U;
    while (index < value.size()) {
        const auto ch = value[index];
        if (ch == '"') {
            if (trim_ascii(value.substr(index + 1U)).empty()) {
                parsed.ok = true;
                return parsed;
            }
            parsed.error_column = value_column_base + index + 1U;
            return parsed;
        }
        if (ch == '\\') {
            if (index + 1U >= value.size()) {
                parsed.invalid_escape = true;
                parsed.error_column = value_column_base + index + 1U;
                return parsed;
            }
            const auto escaped = value[index + 1U];
            switch (escaped) {
            case '\\':
                parsed.value.push_back('\\');
                break;
            case '"':
                parsed.value.push_back('"');
                break;
            case 'n':
                parsed.value.push_back('\n');
                break;
            case 'r':
                parsed.value.push_back('\r');
                break;
            case 't':
                parsed.value.push_back('\t');
                break;
            default:
                parsed.invalid_escape = true;
                parsed.error_column = value_column_base + index + 1U;
                return parsed;
            }
            index += 2U;
            continue;
        }

        if (static_cast<unsigned char>(ch) < 0x20U) {
            parsed.error_column = value_column_base + index + 1U;
            return parsed;
        }

        parsed.value.push_back(ch);
        ++index;
    }

    parsed.unterminated = true;
    parsed.error_column = value_column_base;
    return parsed;
}

ParsedUint64 parse_uint64_decimal(const std::string_view text) {
    ParsedUint64 parsed {};
    if (text.empty()) {
        return parsed;
    }

    std::uint64_t value = 0U;
    const auto* begin = text.data();
    const auto* end = text.data() + text.size();
    const auto result = std::from_chars(begin, end, value, 10);
    if (result.ec == std::errc::result_out_of_range) {
        parsed.overflow = true;
        return parsed;
    }
    if (result.ec != std::errc {} || result.ptr != end) {
        return parsed;
    }

    parsed.ok = true;
    parsed.value = value;
    return parsed;
}

ParsedUint64 parse_uint64_decimal_or_hex(const std::string_view text) {
    if (text.size() > 2U && text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) {
        ParsedUint64 parsed {};
        std::uint64_t value = 0U;
        const auto* begin = text.data() + 2U;
        const auto* end = text.data() + text.size();
        const auto result = std::from_chars(begin, end, value, 16);
        if (result.ec == std::errc::result_out_of_range) {
            parsed.overflow = true;
            return parsed;
        }
        if (result.ec != std::errc {} || result.ptr != end) {
            return parsed;
        }
        parsed.ok = true;
        parsed.value = value;
        return parsed;
    }

    return parse_uint64_decimal(text);
}

ParsedUint32 narrow_uint32(const ParsedUint64& parsed) {
    ParsedUint32 narrowed {};
    if (!parsed.ok) {
        narrowed.overflow = parsed.overflow;
        return narrowed;
    }
    if (parsed.value > std::numeric_limits<std::uint32_t>::max()) {
        narrowed.overflow = true;
        return narrowed;
    }
    narrowed.ok = true;
    narrowed.value = static_cast<std::uint32_t>(parsed.value);
    return narrowed;
}

ParsedUint16 narrow_uint16(const ParsedUint64& parsed) {
    ParsedUint16 narrowed {};
    if (!parsed.ok) {
        narrowed.overflow = parsed.overflow;
        return narrowed;
    }
    if (parsed.value > std::numeric_limits<std::uint16_t>::max()) {
        narrowed.overflow = true;
        return narrowed;
    }
    narrowed.ok = true;
    narrowed.value = static_cast<std::uint16_t>(parsed.value);
    return narrowed;
}

ParsedUint8 narrow_uint8(const ParsedUint64& parsed) {
    ParsedUint8 narrowed {};
    if (!parsed.ok) {
        narrowed.overflow = parsed.overflow;
        return narrowed;
    }
    if (parsed.value > std::numeric_limits<std::uint8_t>::max()) {
        narrowed.overflow = true;
        return narrowed;
    }
    narrowed.ok = true;
    narrowed.value = static_cast<std::uint8_t>(parsed.value);
    return narrowed;
}

std::optional<std::uint32_t> parse_ipv4_address(const std::string_view text) {
    std::array<std::uint8_t, 4> octets {};
    std::size_t start = 0U;

    for (std::size_t index = 0; index < octets.size(); ++index) {
        const auto dot = text.find('.', start);
        const auto token = dot == std::string_view::npos
            ? text.substr(start)
            : text.substr(start, dot - start);
        const auto parsed = narrow_uint8(parse_uint64_decimal(token));
        if (!parsed.ok) {
            return std::nullopt;
        }
        octets[index] = parsed.value;

        if (index + 1U == octets.size()) {
            if (dot != std::string_view::npos) {
                return std::nullopt;
            }
        } else {
            if (dot == std::string_view::npos) {
                return std::nullopt;
            }
            start = dot + 1U;
        }
    }

    return (static_cast<std::uint32_t>(octets[0]) << 24U) |
        (static_cast<std::uint32_t>(octets[1]) << 16U) |
        (static_cast<std::uint32_t>(octets[2]) << 8U) |
        static_cast<std::uint32_t>(octets[3]);
}

std::optional<std::uint16_t> parse_ipv6_hextet(const std::string_view token) {
    if (token.empty() || token.size() > 4U) {
        return std::nullopt;
    }
    std::uint16_t value = 0U;
    const auto* begin = token.data();
    const auto* end = token.data() + token.size();
    const auto result = std::from_chars(begin, end, value, 16);
    if (result.ec != std::errc {} || result.ptr != end) {
        return std::nullopt;
    }
    return value;
}

bool append_ipv6_segment_words(std::vector<std::uint16_t>& out, const std::string_view segment) {
    if (segment.empty()) {
        return true;
    }

    std::size_t start = 0U;
    while (start <= segment.size()) {
        const auto colon = segment.find(':', start);
        const auto token = colon == std::string_view::npos
            ? segment.substr(start)
            : segment.substr(start, colon - start);
        if (token.empty()) {
            return false;
        }
        const auto word = parse_ipv6_hextet(token);
        if (!word.has_value()) {
            return false;
        }
        out.push_back(*word);
        if (colon == std::string_view::npos) {
            break;
        }
        start = colon + 1U;
    }

    return true;
}

std::optional<std::array<std::uint8_t, 16>> parse_ipv6_address(const std::string_view text) {
    if (text.empty()) {
        return std::nullopt;
    }
    if (text.find('.') != std::string_view::npos) {
        return std::nullopt;
    }

    const auto double_colon = text.find("::");
    if (double_colon == std::string_view::npos) {
        std::vector<std::uint16_t> words {};
        words.reserve(8U);
        if (!append_ipv6_segment_words(words, text) || words.size() != 8U) {
            return std::nullopt;
        }

        std::array<std::uint8_t, 16> bytes {};
        for (std::size_t index = 0; index < words.size(); ++index) {
            bytes[index * 2U] = static_cast<std::uint8_t>(words[index] >> 8U);
            bytes[index * 2U + 1U] = static_cast<std::uint8_t>(words[index] & 0xFFU);
        }
        return bytes;
    }

    if (text.find("::", double_colon + 2U) != std::string_view::npos) {
        return std::nullopt;
    }

    std::vector<std::uint16_t> left_words {};
    std::vector<std::uint16_t> right_words {};
    left_words.reserve(8U);
    right_words.reserve(8U);

    const auto left = text.substr(0U, double_colon);
    const auto right = text.substr(double_colon + 2U);
    if (!append_ipv6_segment_words(left_words, left) || !append_ipv6_segment_words(right_words, right)) {
        return std::nullopt;
    }
    if (left_words.size() + right_words.size() >= 8U) {
        return std::nullopt;
    }

    std::array<std::uint8_t, 16> bytes {};
    std::size_t byte_index = 0U;
    for (const auto word : left_words) {
        bytes[byte_index++] = static_cast<std::uint8_t>(word >> 8U);
        bytes[byte_index++] = static_cast<std::uint8_t>(word & 0xFFU);
    }

    byte_index = (8U - right_words.size()) * 2U;
    for (const auto word : right_words) {
        bytes[byte_index++] = static_cast<std::uint8_t>(word >> 8U);
        bytes[byte_index++] = static_cast<std::uint8_t>(word & 0xFFU);
    }

    return bytes;
}

std::optional<ProtocolId> parse_protocol_id_token(const std::string_view token) {
    if (equals_ascii_case_insensitive(token, "unknown")) {
        return ProtocolId::unknown;
    }
    if (equals_ascii_case_insensitive(token, "icmp")) {
        return ProtocolId::icmp;
    }
    if (equals_ascii_case_insensitive(token, "igmp")) {
        return ProtocolId::igmp;
    }
    if (equals_ascii_case_insensitive(token, "tcp")) {
        return ProtocolId::tcp;
    }
    if (equals_ascii_case_insensitive(token, "udp")) {
        return ProtocolId::udp;
    }
    if (equals_ascii_case_insensitive(token, "esp")) {
        return ProtocolId::esp;
    }
    if (equals_ascii_case_insensitive(token, "icmpv6")) {
        return ProtocolId::icmpv6;
    }
    if (equals_ascii_case_insensitive(token, "sctp")) {
        return ProtocolId::sctp;
    }
    if (equals_ascii_case_insensitive(token, "arp")) {
        return ProtocolId::arp;
    }
    return std::nullopt;
}

std::optional<FlowProtocolHint> parse_flow_protocol_hint_token(const std::string_view token) {
    if (equals_ascii_case_insensitive(token, "unknown")) {
        return FlowProtocolHint::unknown;
    }
    if (equals_ascii_case_insensitive(token, "tls")) {
        return FlowProtocolHint::tls;
    }
    if (equals_ascii_case_insensitive(token, "http")) {
        return FlowProtocolHint::http;
    }
    if (equals_ascii_case_insensitive(token, "dns")) {
        return FlowProtocolHint::dns;
    }
    if (equals_ascii_case_insensitive(token, "quic")) {
        return FlowProtocolHint::quic;
    }
    if (equals_ascii_case_insensitive(token, "ssh")) {
        return FlowProtocolHint::ssh;
    }
    if (equals_ascii_case_insensitive(token, "stun")) {
        return FlowProtocolHint::stun;
    }
    if (equals_ascii_case_insensitive(token, "bittorrent")) {
        return FlowProtocolHint::bittorrent;
    }
    if (equals_ascii_case_insensitive(token, "dhcp")) {
        return FlowProtocolHint::dhcp;
    }
    if (equals_ascii_case_insensitive(token, "mdns")) {
        return FlowProtocolHint::mdns;
    }
    if (equals_ascii_case_insensitive(token, "smtp")) {
        return FlowProtocolHint::smtp;
    }
    if (equals_ascii_case_insensitive(token, "pop3")) {
        return FlowProtocolHint::pop3;
    }
    if (equals_ascii_case_insensitive(token, "imap")) {
        return FlowProtocolHint::imap;
    }
    if (equals_ascii_case_insensitive(token, "igmp")) {
        return FlowProtocolHint::igmp;
    }
    if (equals_ascii_case_insensitive(token, "igmpv1")) {
        return FlowProtocolHint::igmpv1;
    }
    if (equals_ascii_case_insensitive(token, "igmpv2")) {
        return FlowProtocolHint::igmpv2;
    }
    if (equals_ascii_case_insensitive(token, "igmpv3")) {
        return FlowProtocolHint::igmpv3;
    }
    return std::nullopt;
}

std::optional<TlsVersionHint> parse_tls_version_token(const std::string_view token) {
    if (equals_ascii_case_insensitive(token, "unknown")) {
        return TlsVersionHint::unknown;
    }
    if (equals_ascii_case_insensitive(token, "tls1_2")) {
        return TlsVersionHint::tls12;
    }
    if (equals_ascii_case_insensitive(token, "tls1_3")) {
        return TlsVersionHint::tls13;
    }
    return std::nullopt;
}

std::optional<QuicVersionHint> parse_quic_version_token(const std::string_view token) {
    if (equals_ascii_case_insensitive(token, "unknown")) {
        return QuicVersionHint::unknown;
    }
    if (equals_ascii_case_insensitive(token, "v1")) {
        return QuicVersionHint::v1;
    }
    if (equals_ascii_case_insensitive(token, "draft29")) {
        return QuicVersionHint::draft29;
    }
    if (equals_ascii_case_insensitive(token, "v2")) {
        return QuicVersionHint::v2;
    }
    return std::nullopt;
}

std::optional<AdvancedFlowFilterDirectionality> parse_directionality_token(const std::string_view token) {
    if (equals_ascii_case_insensitive(token, "unidirectional")) {
        return AdvancedFlowFilterDirectionality::unidirectional;
    }
    if (equals_ascii_case_insensitive(token, "bidirectional")) {
        return AdvancedFlowFilterDirectionality::bidirectional;
    }
    return std::nullopt;
}

std::optional<FlowAddressFamily> parse_address_family_token(const std::string_view token) {
    if (equals_ascii_case_insensitive(token, "ipv4")) {
        return FlowAddressFamily::ipv4;
    }
    if (equals_ascii_case_insensitive(token, "ipv6")) {
        return FlowAddressFamily::ipv6;
    }
    return std::nullopt;
}

std::optional<AdvancedFlowFilterPortScope> parse_port_scope_token(const std::string_view token) {
    if (token == "either") {
        return AdvancedFlowFilterPortScope::either_endpoint;
    }
    if (token == "a") {
        return AdvancedFlowFilterPortScope::endpoint_a;
    }
    if (token == "b") {
        return AdvancedFlowFilterPortScope::endpoint_b;
    }
    return std::nullopt;
}

std::optional<AdvancedFlowFilterEndpointScope> parse_endpoint_scope_token(const std::string_view token) {
    if (token == "either") {
        return AdvancedFlowFilterEndpointScope::either_endpoint;
    }
    if (token == "a") {
        return AdvancedFlowFilterEndpointScope::endpoint_a;
    }
    if (token == "b") {
        return AdvancedFlowFilterEndpointScope::endpoint_b;
    }
    return std::nullopt;
}

std::optional<AdvancedFlowFilterStringCaseSensitivity> parse_case_sensitivity_token(const std::string_view token) {
    if (token == "ci") {
        return AdvancedFlowFilterStringCaseSensitivity::ascii_case_insensitive;
    }
    if (token == "cs") {
        return AdvancedFlowFilterStringCaseSensitivity::case_sensitive;
    }
    return std::nullopt;
}

std::optional<AdvancedFlowFilterServicePredicateKind> parse_service_operator_token(const std::string_view token) {
    if (token == "equals") {
        return AdvancedFlowFilterServicePredicateKind::equals;
    }
    if (token == "starts_with") {
        return AdvancedFlowFilterServicePredicateKind::starts_with;
    }
    if (token == "contains") {
        return AdvancedFlowFilterServicePredicateKind::contains;
    }
    return std::nullopt;
}

std::optional<AdvancedFlowFilterProtocolPathMatchKind> parse_protocol_path_match_kind_token(const std::string_view token) {
    if (token == "exact") {
        return AdvancedFlowFilterProtocolPathMatchKind::exact_path;
    }
    if (token == "prefix") {
        return AdvancedFlowFilterProtocolPathMatchKind::path_prefix;
    }
    if (token == "contains") {
        return AdvancedFlowFilterProtocolPathMatchKind::contains_layer;
    }
    return std::nullopt;
}

std::optional<ProtocolLayerIdentifierKind> expected_identifier_kind(const ProtocolLayerKind kind) noexcept {
    switch (kind) {
    case ProtocolLayerKind::vlan:
        return ProtocolLayerIdentifierKind::vlan_vid;
    case ProtocolLayerKind::mpls:
        return ProtocolLayerIdentifierKind::mpls_label;
    case ProtocolLayerKind::pbb:
        return ProtocolLayerIdentifierKind::pbb_isid;
    case ProtocolLayerKind::vxlan:
        return ProtocolLayerIdentifierKind::vxlan_vni;
    case ProtocolLayerKind::geneve:
        return ProtocolLayerIdentifierKind::geneve_vni;
    case ProtocolLayerKind::gtpu:
        return ProtocolLayerIdentifierKind::gtpu_teid;
    case ProtocolLayerKind::gre:
        return ProtocolLayerIdentifierKind::gre_key;
    case ProtocolLayerKind::ah:
        return ProtocolLayerIdentifierKind::ah_spi;
    case ProtocolLayerKind::esp:
        return ProtocolLayerIdentifierKind::esp_spi;
    default:
        return std::nullopt;
    }
}

std::optional<ProtocolLayerKind> parse_protocol_layer_kind_token(const std::string_view token) {
    if (equals_ascii_case_insensitive(token, "EthernetII")) {
        return ProtocolLayerKind::ethernet_ii;
    }
    if (equals_ascii_case_insensitive(token, "IEEE 802.3")) {
        return ProtocolLayerKind::ieee8023;
    }
    if (equals_ascii_case_insensitive(token, "LLC/SNAP")) {
        return ProtocolLayerKind::llc_snap;
    }
    if (equals_ascii_case_insensitive(token, "LinuxSll")) {
        return ProtocolLayerKind::linux_sll;
    }
    if (equals_ascii_case_insensitive(token, "LinuxSll2")) {
        return ProtocolLayerKind::linux_sll2;
    }
    if (equals_ascii_case_insensitive(token, "VLAN")) {
        return ProtocolLayerKind::vlan;
    }
    if (equals_ascii_case_insensitive(token, "MPLS")) {
        return ProtocolLayerKind::mpls;
    }
    if (equals_ascii_case_insensitive(token, "MPLS PW")) {
        return ProtocolLayerKind::mpls_pw;
    }
    if (equals_ascii_case_insensitive(token, "PBB")) {
        return ProtocolLayerKind::pbb;
    }
    if (equals_ascii_case_insensitive(token, "PPPoE")) {
        return ProtocolLayerKind::pppoe;
    }
    if (equals_ascii_case_insensitive(token, "PPP")) {
        return ProtocolLayerKind::ppp;
    }
    if (equals_ascii_case_insensitive(token, "MACsec")) {
        return ProtocolLayerKind::macsec;
    }
    if (equals_ascii_case_insensitive(token, "IPv4")) {
        return ProtocolLayerKind::ipv4;
    }
    if (equals_ascii_case_insensitive(token, "IPv6")) {
        return ProtocolLayerKind::ipv6;
    }
    if (equals_ascii_case_insensitive(token, "TCP")) {
        return ProtocolLayerKind::tcp;
    }
    if (equals_ascii_case_insensitive(token, "UDP")) {
        return ProtocolLayerKind::udp;
    }
    if (equals_ascii_case_insensitive(token, "SCTP")) {
        return ProtocolLayerKind::sctp;
    }
    if (equals_ascii_case_insensitive(token, "ICMP")) {
        return ProtocolLayerKind::icmp;
    }
    if (equals_ascii_case_insensitive(token, "ICMPv6")) {
        return ProtocolLayerKind::icmpv6;
    }
    if (equals_ascii_case_insensitive(token, "ARP")) {
        return ProtocolLayerKind::arp;
    }
    if (equals_ascii_case_insensitive(token, "VXLAN")) {
        return ProtocolLayerKind::vxlan;
    }
    if (equals_ascii_case_insensitive(token, "Geneve")) {
        return ProtocolLayerKind::geneve;
    }
    if (equals_ascii_case_insensitive(token, "GTP-U")) {
        return ProtocolLayerKind::gtpu;
    }
    if (equals_ascii_case_insensitive(token, "GRE")) {
        return ProtocolLayerKind::gre;
    }
    if (equals_ascii_case_insensitive(token, "AH")) {
        return ProtocolLayerKind::ah;
    }
    if (equals_ascii_case_insensitive(token, "ESP")) {
        return ProtocolLayerKind::esp;
    }
    return std::nullopt;
}

ParsedPortRange parse_port_range_value(const std::string_view value) {
    ParsedPortRange parsed {};

    const auto dash_pos = value.find('-');
    if (dash_pos == std::string_view::npos) {
        const auto port = narrow_uint16(parse_uint64_decimal(value));
        if (!port.ok) {
            parsed.overflow = port.overflow;
            return parsed;
        }
        parsed.ok = true;
        parsed.range = AdvancedFlowFilterPortRange {.first = port.value, .last = port.value};
        return parsed;
    }

    if (value.find('-', dash_pos + 1U) != std::string_view::npos) {
        return parsed;
    }

    const auto first = trim_ascii(value.substr(0U, dash_pos));
    const auto last = trim_ascii(value.substr(dash_pos + 1U));
    if (first.empty() || last.empty()) {
        return parsed;
    }

    const auto first_port = narrow_uint16(parse_uint64_decimal(first));
    const auto last_port = narrow_uint16(parse_uint64_decimal(last));
    if (!first_port.ok || !last_port.ok) {
        parsed.overflow = first_port.overflow || last_port.overflow;
        return parsed;
    }

    parsed.ok = true;
    parsed.range = AdvancedFlowFilterPortRange {.first = first_port.value, .last = last_port.value};
    parsed.reversed = first_port.value > last_port.value;
    return parsed;
}

std::optional<std::uint64_t> checked_multiply(const std::uint64_t left, const std::uint64_t right) {
    if (left == 0U || right == 0U) {
        return 0U;
    }
    if (left > std::numeric_limits<std::uint64_t>::max() / right) {
        return std::nullopt;
    }
    return left * right;
}

ParsedUint64 parse_byte_quantity_value(const std::string_view value, const bool allow_bare_bytes) {
    ParsedUint64 parsed {};
    if (value.empty()) {
        return parsed;
    }

    std::size_t suffix_pos = 0U;
    while (suffix_pos < value.size() && std::isdigit(static_cast<unsigned char>(value[suffix_pos])) != 0) {
        ++suffix_pos;
    }

    const auto quantity_text = value.substr(0U, suffix_pos);
    const auto suffix = value.substr(suffix_pos);
    const auto quantity = parse_uint64_decimal(quantity_text);
    if (!quantity.ok) {
        parsed.overflow = quantity.overflow;
        return parsed;
    }

    std::uint64_t multiplier = 0U;
    if (suffix.empty() && allow_bare_bytes) {
        multiplier = 1U;
    } else if (suffix == "B") {
        multiplier = 1U;
    } else if (suffix == "KiB") {
        multiplier = 1024ULL;
    } else if (suffix == "MiB") {
        multiplier = 1024ULL * 1024ULL;
    } else if (suffix == "GiB") {
        multiplier = 1024ULL * 1024ULL * 1024ULL;
    } else if (suffix == "TiB") {
        multiplier = 1024ULL * 1024ULL * 1024ULL * 1024ULL;
    } else {
        return parsed;
    }

    const auto product = checked_multiply(quantity.value, multiplier);
    if (!product.has_value()) {
        parsed.overflow = true;
        return parsed;
    }

    parsed.ok = true;
    parsed.value = *product;
    return parsed;
}

ParsedUint64 parse_duration_quantity_value(const std::string_view value) {
    ParsedUint64 parsed {};
    if (value.empty()) {
        return parsed;
    }

    std::size_t suffix_pos = 0U;
    while (suffix_pos < value.size() && std::isdigit(static_cast<unsigned char>(value[suffix_pos])) != 0) {
        ++suffix_pos;
    }
    if (suffix_pos == value.size()) {
        return parsed;
    }

    const auto quantity_text = value.substr(0U, suffix_pos);
    const auto suffix = value.substr(suffix_pos);
    const auto quantity = parse_uint64_decimal(quantity_text);
    if (!quantity.ok) {
        parsed.overflow = quantity.overflow;
        return parsed;
    }

    std::uint64_t multiplier = 0U;
    if (suffix == "us") {
        multiplier = 1U;
    } else if (suffix == "ms") {
        multiplier = 1000U;
    } else if (suffix == "s") {
        multiplier = 1000ULL * 1000ULL;
    } else if (suffix == "m") {
        multiplier = 60ULL * 1000ULL * 1000ULL;
    } else if (suffix == "h") {
        multiplier = 60ULL * 60ULL * 1000ULL * 1000ULL;
    } else {
        return parsed;
    }

    const auto product = checked_multiply(quantity.value, multiplier);
    if (!product.has_value()) {
        parsed.overflow = true;
        return parsed;
    }

    parsed.ok = true;
    parsed.value = *product;
    return parsed;
}

ParsedLayerToken parse_protocol_layer_token(const std::string_view token_text) {
    ParsedLayerToken parsed {};
    const auto token = trim_ascii(token_text);
    if (token.empty()) {
        parsed.invalid_syntax = true;
        return parsed;
    }

    const auto open_paren = token.find('(');
    const auto close_paren = token.rfind(')');
    if ((open_paren == std::string_view::npos) != (close_paren == std::string_view::npos)) {
        parsed.invalid_syntax = true;
        return parsed;
    }

    std::string_view layer_name = token;
    std::optional<ProtocolLayerIdentifier> identifier {};
    if (open_paren != std::string_view::npos) {
        if (close_paren != token.size() - 1U || open_paren == 0U || close_paren <= open_paren + 1U) {
            parsed.invalid_syntax = true;
            return parsed;
        }

        layer_name = trim_ascii(token.substr(0U, open_paren));
        const auto payload = trim_ascii(token.substr(open_paren + 1U, close_paren - open_paren - 1U));
        const auto equals = payload.find('=');
        if (equals == std::string_view::npos || payload.find('=', equals + 1U) != std::string_view::npos) {
            parsed.invalid_syntax = true;
            return parsed;
        }
        const auto identifier_name = trim_ascii(payload.substr(0U, equals));
        const auto identifier_value_text = trim_ascii(payload.substr(equals + 1U));
        if (identifier_name.empty() || identifier_value_text.empty()) {
            parsed.invalid_syntax = true;
            return parsed;
        }

        const auto kind = parse_protocol_layer_kind_token(layer_name);
        if (!kind.has_value()) {
            parsed.invalid_syntax = true;
            return parsed;
        }

        const auto expected_kind = expected_identifier_kind(*kind);
        if (!expected_kind.has_value()) {
            parsed.invalid_syntax = true;
            return parsed;
        }

        const auto parsed_value = parse_uint64_decimal_or_hex(identifier_value_text);
        if (!parsed_value.ok) {
            parsed.invalid_syntax = true;
            return parsed;
        }

        ProtocolLayerIdentifierKind identifier_kind {ProtocolLayerIdentifierKind::none};
        switch (*expected_kind) {
        case ProtocolLayerIdentifierKind::vlan_vid:
            if (identifier_name != "vid") {
                parsed.invalid_syntax = true;
                return parsed;
            }
            identifier_kind = ProtocolLayerIdentifierKind::vlan_vid;
            break;
        case ProtocolLayerIdentifierKind::mpls_label:
            if (identifier_name != "label") {
                parsed.invalid_syntax = true;
                return parsed;
            }
            identifier_kind = ProtocolLayerIdentifierKind::mpls_label;
            break;
        case ProtocolLayerIdentifierKind::pbb_isid:
            if (identifier_name != "isid") {
                parsed.invalid_syntax = true;
                return parsed;
            }
            identifier_kind = ProtocolLayerIdentifierKind::pbb_isid;
            break;
        case ProtocolLayerIdentifierKind::vxlan_vni:
            if (identifier_name != "vni") {
                parsed.invalid_syntax = true;
                return parsed;
            }
            identifier_kind = ProtocolLayerIdentifierKind::vxlan_vni;
            break;
        case ProtocolLayerIdentifierKind::geneve_vni:
            if (identifier_name != "vni") {
                parsed.invalid_syntax = true;
                return parsed;
            }
            identifier_kind = ProtocolLayerIdentifierKind::geneve_vni;
            break;
        case ProtocolLayerIdentifierKind::gtpu_teid:
            if (identifier_name != "teid") {
                parsed.invalid_syntax = true;
                return parsed;
            }
            identifier_kind = ProtocolLayerIdentifierKind::gtpu_teid;
            break;
        case ProtocolLayerIdentifierKind::gre_key:
            if (identifier_name != "key") {
                parsed.invalid_syntax = true;
                return parsed;
            }
            identifier_kind = ProtocolLayerIdentifierKind::gre_key;
            break;
        case ProtocolLayerIdentifierKind::ah_spi:
            if (identifier_name != "spi") {
                parsed.invalid_syntax = true;
                return parsed;
            }
            identifier_kind = ProtocolLayerIdentifierKind::ah_spi;
            break;
        case ProtocolLayerIdentifierKind::esp_spi:
            if (identifier_name != "spi") {
                parsed.invalid_syntax = true;
                return parsed;
            }
            identifier_kind = ProtocolLayerIdentifierKind::esp_spi;
            break;
        default:
            parsed.invalid_syntax = true;
            return parsed;
        }

        identifier = ProtocolLayerIdentifier {
            .kind = identifier_kind,
            .value = parsed_value.value,
        };
    }

    const auto kind = parse_protocol_layer_kind_token(layer_name);
    if (!kind.has_value()) {
        parsed.invalid_syntax = true;
        return parsed;
    }

    parsed.ok = true;
    parsed.predicate = AdvancedFlowFilterProtocolLayerPredicate {
        .kind = *kind,
        .identifier = identifier,
    };
    return parsed;
}

std::optional<std::vector<AdvancedFlowFilterProtocolLayerPredicate>> parse_protocol_path_layers(
    const std::string_view value,
    const bool contains_requires_single_layer
) {
    std::vector<AdvancedFlowFilterProtocolLayerPredicate> layers {};
    std::size_t start = 0U;
    int paren_depth = 0;

    for (std::size_t index = 0; index <= value.size(); ++index) {
        const bool at_end = index == value.size();
        const auto ch = at_end ? '\0' : value[index];
        if (!at_end) {
            if (ch == '(') {
                ++paren_depth;
            } else if (ch == ')') {
                --paren_depth;
                if (paren_depth < 0) {
                    return std::nullopt;
                }
            }
        }

        if (at_end || (ch == '>' && paren_depth == 0)) {
            const auto token = trim_ascii(value.substr(start, index - start));
            const auto parsed_layer = parse_protocol_layer_token(token);
            if (!parsed_layer.ok) {
                return std::nullopt;
            }
            layers.push_back(parsed_layer.predicate);
            start = index + 1U;
        }
    }

    if (paren_depth != 0 || layers.empty()) {
        return std::nullopt;
    }
    if (contains_requires_single_layer && layers.size() != 1U) {
        return std::nullopt;
    }
    return layers;
}

std::string format_protocol_id_token(const ProtocolId protocol) {
    switch (protocol) {
    case ProtocolId::unknown:
        return "unknown";
    case ProtocolId::icmp:
        return "icmp";
    case ProtocolId::igmp:
        return "igmp";
    case ProtocolId::tcp:
        return "tcp";
    case ProtocolId::udp:
        return "udp";
    case ProtocolId::esp:
        return "esp";
    case ProtocolId::icmpv6:
        return "icmpv6";
    case ProtocolId::sctp:
        return "sctp";
    case ProtocolId::arp:
        return "arp";
    }
    return {};
}

std::string format_flow_protocol_hint_token(const FlowProtocolHint hint) {
    switch (hint) {
    case FlowProtocolHint::unknown:
        return "unknown";
    case FlowProtocolHint::tls:
        return "tls";
    case FlowProtocolHint::http:
        return "http";
    case FlowProtocolHint::dns:
        return "dns";
    case FlowProtocolHint::quic:
        return "quic";
    case FlowProtocolHint::ssh:
        return "ssh";
    case FlowProtocolHint::stun:
        return "stun";
    case FlowProtocolHint::bittorrent:
        return "bittorrent";
    case FlowProtocolHint::dhcp:
        return "dhcp";
    case FlowProtocolHint::mdns:
        return "mdns";
    case FlowProtocolHint::smtp:
        return "smtp";
    case FlowProtocolHint::pop3:
        return "pop3";
    case FlowProtocolHint::imap:
        return "imap";
    case FlowProtocolHint::possible_tls:
        return {};
    case FlowProtocolHint::possible_quic:
        return {};
    case FlowProtocolHint::igmp:
        return "igmp";
    case FlowProtocolHint::igmpv1:
        return "igmpv1";
    case FlowProtocolHint::igmpv2:
        return "igmpv2";
    case FlowProtocolHint::igmpv3:
        return "igmpv3";
    }
    return {};
}

std::string format_tls_version_token(const TlsVersionHint version) {
    switch (version) {
    case TlsVersionHint::unknown:
        return "unknown";
    case TlsVersionHint::tls12:
        return "tls1_2";
    case TlsVersionHint::tls13:
        return "tls1_3";
    }
    return {};
}

std::string format_quic_version_token(const QuicVersionHint version) {
    switch (version) {
    case QuicVersionHint::unknown:
        return "unknown";
    case QuicVersionHint::v1:
        return "v1";
    case QuicVersionHint::draft29:
        return "draft29";
    case QuicVersionHint::v2:
        return "v2";
    }
    return {};
}

std::string format_directionality_token(const AdvancedFlowFilterDirectionality value) {
    switch (value) {
    case AdvancedFlowFilterDirectionality::unidirectional:
        return "unidirectional";
    case AdvancedFlowFilterDirectionality::bidirectional:
        return "bidirectional";
    }
    return {};
}

std::string format_address_family_token(const FlowAddressFamily family) {
    switch (family) {
    case FlowAddressFamily::ipv4:
        return "ipv4";
    case FlowAddressFamily::ipv6:
        return "ipv6";
    default:
        return {};
    }
}

std::string format_port_scope_token(const AdvancedFlowFilterPortScope scope) {
    switch (scope) {
    case AdvancedFlowFilterPortScope::either_endpoint:
        return "either";
    case AdvancedFlowFilterPortScope::endpoint_a:
        return "a";
    case AdvancedFlowFilterPortScope::endpoint_b:
        return "b";
    }
    return {};
}

std::string format_endpoint_scope_token(const AdvancedFlowFilterEndpointScope scope) {
    switch (scope) {
    case AdvancedFlowFilterEndpointScope::either_endpoint:
        return "either";
    case AdvancedFlowFilterEndpointScope::endpoint_a:
        return "a";
    case AdvancedFlowFilterEndpointScope::endpoint_b:
        return "b";
    }
    return {};
}

std::string format_service_case_token(const AdvancedFlowFilterStringCaseSensitivity sensitivity) {
    switch (sensitivity) {
    case AdvancedFlowFilterStringCaseSensitivity::ascii_case_insensitive:
        return "ci";
    case AdvancedFlowFilterStringCaseSensitivity::case_sensitive:
        return "cs";
    }
    return {};
}

std::string format_service_operator_token(const AdvancedFlowFilterServicePredicateKind kind) {
    switch (kind) {
    case AdvancedFlowFilterServicePredicateKind::equals:
        return "equals";
    case AdvancedFlowFilterServicePredicateKind::starts_with:
        return "starts_with";
    case AdvancedFlowFilterServicePredicateKind::contains:
        return "contains";
    default:
        return {};
    }
}

std::string format_protocol_path_match_kind_token(const AdvancedFlowFilterProtocolPathMatchKind kind) {
    switch (kind) {
    case AdvancedFlowFilterProtocolPathMatchKind::exact_path:
        return "exact";
    case AdvancedFlowFilterProtocolPathMatchKind::path_prefix:
        return "prefix";
    case AdvancedFlowFilterProtocolPathMatchKind::contains_layer:
        return "contains";
    }
    return {};
}

std::string format_bool_token(const bool value) {
    return value ? "true" : "false";
}

std::string escape_quoted_string(const std::string_view value) {
    std::string escaped {};
    escaped.reserve(value.size() + 2U);
    escaped.push_back('"');
    for (const char ch : value) {
        switch (ch) {
        case '\\':
            escaped += "\\\\";
            break;
        case '"':
            escaped += "\\\"";
            break;
        case '\n':
            escaped += "\\n";
            break;
        case '\r':
            escaped += "\\r";
            break;
        case '\t':
            escaped += "\\t";
            break;
        default:
            escaped.push_back(ch);
            break;
        }
    }
    escaped.push_back('"');
    return escaped;
}

std::string format_port_range_value(const AdvancedFlowFilterPortRange& range) {
    if (range.first == range.last) {
        return std::to_string(range.first);
    }
    return std::to_string(range.first) + "-" + std::to_string(range.last);
}

std::string format_byte_quantity_value(const std::uint64_t value) {
    struct Unit {
        const char* suffix;
        std::uint64_t multiplier;
    };

    static constexpr std::array<Unit, 5> units {{
        {"TiB", 1024ULL * 1024ULL * 1024ULL * 1024ULL},
        {"GiB", 1024ULL * 1024ULL * 1024ULL},
        {"MiB", 1024ULL * 1024ULL},
        {"KiB", 1024ULL},
        {"B", 1ULL},
    }};

    for (const auto& unit : units) {
        if (value >= unit.multiplier && value % unit.multiplier == 0U) {
            return std::to_string(value / unit.multiplier) + unit.suffix;
        }
    }

    return std::to_string(value) + "B";
}

std::string format_duration_value(const std::uint64_t value_us) {
    struct Unit {
        const char* suffix;
        std::uint64_t multiplier;
    };

    static constexpr std::array<Unit, 5> units {{
        {"h", 60ULL * 60ULL * 1000ULL * 1000ULL},
        {"m", 60ULL * 1000ULL * 1000ULL},
        {"s", 1000ULL * 1000ULL},
        {"ms", 1000ULL},
        {"us", 1ULL},
    }};

    for (const auto& unit : units) {
        if (value_us >= unit.multiplier && value_us % unit.multiplier == 0U) {
            return std::to_string(value_us / unit.multiplier) + unit.suffix;
        }
    }

    return std::to_string(value_us) + "us";
}

std::string format_protocol_path_value(
    const std::vector<AdvancedFlowFilterProtocolLayerPredicate>& layers,
    bool* ok
) {
    if (layers.empty()) {
        *ok = false;
        return {};
    }

    std::ostringstream builder {};
    for (std::size_t index = 0; index < layers.size(); ++index) {
        const auto kind = layers[index].kind;
        if (kind == ProtocolLayerKind::unknown) {
            *ok = false;
            return {};
        }

        if (layers[index].identifier.has_value()) {
            const auto expected_kind = expected_identifier_kind(kind);
            if (!expected_kind.has_value() || *expected_kind != layers[index].identifier->kind) {
                *ok = false;
                return {};
            }
        }

        const auto identifier = layers[index].identifier.value_or(ProtocolLayerIdentifier {});
        const auto key = LayerKey {
            .kind = kind,
            .identifier = identifier,
        };
        const auto formatted = format_protocol_layer_key(key);
        if (formatted == "Unknown") {
            *ok = false;
            return {};
        }
        if (index != 0U) {
            builder << " > ";
        }
        builder << formatted;
    }

    *ok = true;
    return builder.str();
}

bool is_scalar_key(const std::string_view key) {
    return key == "section.address_family.enabled" ||
        key == "section.flow_protocol.enabled" ||
        key == "section.detected_protocol.enabled" ||
        key == "section.tls_version.enabled" ||
        key == "section.quic_version.enabled" ||
        key == "section.directionality.enabled" ||
        key == "section.ports.enabled" ||
        key == "section.ip_addresses.enabled" ||
        key == "section.traffic.enabled" ||
        key == "section.service.enabled" ||
        key == "section.protocol_path.enabled" ||
        key == "section.contains_layer.enabled" ||
        key == "packet_count.min" ||
        key == "packet_count.max" ||
        key == "original_bytes.min" ||
        key == "original_bytes.max" ||
        key == "captured_bytes.min" ||
        key == "captured_bytes.max" ||
        key == "duration.min" ||
        key == "duration.max" ||
        key == "fragmented_packet_count.min" ||
        key == "fragmented_packet_count.max" ||
        key == "truncated_packet_count.min" ||
        key == "truncated_packet_count.max" ||
        key == "tcp_syn_count.min" ||
        key == "tcp_syn_count.max" ||
        key == "tcp_fin_count.min" ||
        key == "tcp_fin_count.max" ||
        key == "tcp_rst_count.min" ||
        key == "tcp_rst_count.max" ||
        key == "max_original_packet_length.min" ||
        key == "max_original_packet_length.max" ||
        key == "max_captured_packet_length.min" ||
        key == "max_captured_packet_length.max";
}

template <typename T>
void assign_range_bound(
    std::optional<AdvancedFlowFilterInclusiveRange<T>>& range,
    const std::string_view bound,
    const T value
) {
    if (!range.has_value()) {
        range = AdvancedFlowFilterInclusiveRange<T> {};
    }
    if (bound == "min") {
        range->min = value;
    } else {
        range->max = value;
    }
}

bool assign_section_enabled_state(
    AdvancedFlowFilterDocumentSectionStates& states,
    const std::string_view section_key,
    const bool enabled
) noexcept {
    if (section_key == "address_family") {
        states.address_family = enabled;
    } else if (section_key == "flow_protocol") {
        states.flow_protocol = enabled;
    } else if (section_key == "detected_protocol") {
        states.detected_protocol = enabled;
    } else if (section_key == "tls_version") {
        states.tls_version = enabled;
    } else if (section_key == "quic_version") {
        states.quic_version = enabled;
    } else if (section_key == "directionality") {
        states.directionality = enabled;
    } else if (section_key == "ports") {
        states.ports = enabled;
    } else if (section_key == "ip_addresses") {
        states.ip_addresses = enabled;
    } else if (section_key == "traffic") {
        states.traffic = enabled;
    } else if (section_key == "service") {
        states.service = enabled;
    } else if (section_key == "protocol_path") {
        states.protocol_path = enabled;
    } else if (section_key == "contains_layer") {
        states.contains_layer = enabled;
    } else {
        return false;
    }

    return true;
}

void append_non_default_section_state_lines(
    std::vector<std::string>& lines,
    const AdvancedFlowFilterDocumentSectionStates& section_states
) {
    auto append_if_disabled = [&](const std::string_view key, const bool enabled) {
        if (!enabled) {
            lines.push_back(std::string("section.") + std::string(key) + ".enabled = " + format_bool_token(false));
        }
    };

    append_if_disabled("address_family", section_states.address_family);
    append_if_disabled("flow_protocol", section_states.flow_protocol);
    append_if_disabled("detected_protocol", section_states.detected_protocol);
    append_if_disabled("tls_version", section_states.tls_version);
    append_if_disabled("quic_version", section_states.quic_version);
    append_if_disabled("directionality", section_states.directionality);
    append_if_disabled("ports", section_states.ports);
    append_if_disabled("ip_addresses", section_states.ip_addresses);
    append_if_disabled("traffic", section_states.traffic);
    append_if_disabled("service", section_states.service);
    append_if_disabled("protocol_path", section_states.protocol_path);
    append_if_disabled("contains_layer", section_states.contains_layer);
}

}  // namespace

AdvancedFlowFilterParsedUnsignedIntegerText parse_advanced_flow_filter_unsigned_integer_text(
    const std::string_view text
) {
    const auto parsed = parse_uint64_decimal_or_hex(text);
    return AdvancedFlowFilterParsedUnsignedIntegerText {
        .ok = parsed.ok,
        .overflow = parsed.overflow,
        .value = parsed.value,
    };
}

AdvancedFlowFilterTextParseResult parse_advanced_flow_filter_text(const std::string_view input_text) {
    std::string_view text = input_text;
    if (text.size() >= 3U &&
        static_cast<unsigned char>(text[0]) == 0xEFU &&
        static_cast<unsigned char>(text[1]) == 0xBBU &&
        static_cast<unsigned char>(text[2]) == 0xBFU) {
        text.remove_prefix(3U);
    }

    AdvancedFlowFilterTextParseResult result {};
    auto& configured_spec = result.document.configured_spec;
    auto& section_states = result.document.section_states;
    bool seen_version = false;
    bool saw_meaningful_line = false;
    std::unordered_set<std::string> seen_scalar_keys {};

    std::size_t line_number = 1U;
    std::size_t line_start = 0U;
    while (line_start <= text.size()) {
        const auto newline = text.find('\n', line_start);
        auto raw_line = newline == std::string_view::npos
            ? text.substr(line_start)
            : text.substr(line_start, newline - line_start);
        if (!raw_line.empty() && raw_line.back() == '\r') {
            raw_line.remove_suffix(1U);
        }

        const auto stripped = strip_trailing_comment(raw_line);
        if (!stripped.content.empty()) {
            const auto equals = find_assignment_equals(stripped.content);
            if (!equals.has_value()) {
                return make_parse_error(
                    AdvancedFlowFilterTextParseStatus::malformed_assignment,
                    line_number,
                    std::nullopt,
                    {},
                    std::string(stripped.content),
                    "Expected assignment separator '='."
                );
            }

            const auto key = trim_ascii(stripped.content.substr(0U, *equals));
            const auto value = trim_ascii(stripped.content.substr(*equals + 1U));
            if (key.empty() || value.empty()) {
                return make_parse_error(
                    AdvancedFlowFilterTextParseStatus::malformed_assignment,
                    line_number,
                    std::nullopt,
                    std::string(key),
                    std::string(value),
                    "Key and value must both be present."
                );
            }

            if (!saw_meaningful_line && key != kFormatVersionKey) {
                return make_parse_error(
                    AdvancedFlowFilterTextParseStatus::missing_format_version,
                    line_number,
                    1U,
                    std::string(key),
                    {},
                    "The first meaningful line must be 'format_version = 2'."
                );
            }
            saw_meaningful_line = true;

            if (key == kFormatVersionKey) {
                if (seen_version) {
                    return make_parse_error(
                        AdvancedFlowFilterTextParseStatus::duplicate_format_version,
                        line_number,
                        1U,
                        std::string(key),
                        std::string(value),
                        "Duplicate format_version declaration."
                    );
                }

                const auto parsed_version = parse_uint64_decimal(value);
                if (!parsed_version.ok) {
                    return make_parse_error(
                        parsed_version.overflow
                            ? AdvancedFlowFilterTextParseStatus::numeric_overflow
                            : AdvancedFlowFilterTextParseStatus::invalid_value,
                        line_number,
                        *equals + 2U,
                        std::string(key),
                        std::string(value),
                        "format_version must be a decimal integer."
                    );
                }
                if (parsed_version.value != 2U) {
                    return make_parse_error(
                        AdvancedFlowFilterTextParseStatus::unsupported_format_version,
                        line_number,
                        *equals + 2U,
                        std::string(key),
                        std::string(value),
                        "Only format_version = 2 is currently supported."
                    );
                }

                seen_version = true;
            } else {
                if (!seen_version) {
                    return make_parse_error(
                        AdvancedFlowFilterTextParseStatus::missing_format_version,
                        line_number,
                        1U,
                        std::string(key),
                        {},
                        "format_version must appear before any filter predicate."
                    );
                }

                if (is_scalar_key(key)) {
                    const auto inserted = seen_scalar_keys.insert(std::string(key));
                    if (!inserted.second) {
                        return make_parse_error(
                            AdvancedFlowFilterTextParseStatus::duplicate_scalar_key,
                            line_number,
                            1U,
                            std::string(key),
                            {},
                            "This scalar key may appear at most once."
                        );
                    }
                }

                const auto key_segments = split_key_segments(key);
                if (key_segments.values.empty()) {
                    return make_parse_error(
                        AdvancedFlowFilterTextParseStatus::unknown_key,
                        line_number,
                        1U,
                        std::string(key),
                        {},
                        "Unknown key."
                    );
                }

                const auto value_column = *equals + 2U;
                const auto root = key_segments.values[0];

                if (root == "section" && key_segments.values.size() == 3U) {
                    if (key_segments.values[2] != "enabled") {
                        return make_parse_error(
                            AdvancedFlowFilterTextParseStatus::unknown_key,
                            line_number,
                            1U,
                            std::string(key),
                            {},
                            "Unknown section key."
                        );
                    }

                    const auto enabled = parse_bool_token(value);
                    if (!enabled.has_value()) {
                        return make_parse_error(
                            AdvancedFlowFilterTextParseStatus::invalid_value,
                            line_number,
                            value_column,
                            std::string(key),
                            std::string(value),
                            "Section enabled state must be true or false."
                        );
                    }

                    if (!assign_section_enabled_state(section_states, key_segments.values[1], *enabled)) {
                        return make_parse_error(
                            AdvancedFlowFilterTextParseStatus::unknown_key,
                            line_number,
                            1U,
                            std::string(key),
                            {},
                            "Unknown section key."
                        );
                    }
                } else if (root == "address_family" && key_segments.values.size() == 2U) {
                    auto family = parse_address_family_token(value);
                    if (!family.has_value()) {
                        return make_parse_error(
                            AdvancedFlowFilterTextParseStatus::invalid_enum_token,
                            line_number,
                            value_column,
                            std::string(key),
                            std::string(value),
                            "Unknown address family token."
                        );
                    }

                    if (key_segments.values[1] == "include") {
                        configured_spec.address_family.include.push_back(*family);
                    } else if (key_segments.values[1] == "exclude") {
                        configured_spec.address_family.exclude.push_back(*family);
                    } else {
                        return make_parse_error(
                            AdvancedFlowFilterTextParseStatus::unknown_key,
                            line_number,
                            1U,
                            std::string(key),
                            {},
                            "Unknown address_family key."
                        );
                    }
                } else if (root == "flow_protocol" && key_segments.values.size() == 2U) {
                    auto protocol = parse_protocol_id_token(value);
                    if (!protocol.has_value()) {
                        return make_parse_error(
                            AdvancedFlowFilterTextParseStatus::invalid_enum_token,
                            line_number,
                            value_column,
                            std::string(key),
                            std::string(value),
                            "Unknown flow protocol token."
                        );
                    }

                    if (key_segments.values[1] == "include") {
                        configured_spec.flow_protocol.include.push_back(*protocol);
                    } else if (key_segments.values[1] == "exclude") {
                        configured_spec.flow_protocol.exclude.push_back(*protocol);
                    } else {
                        return make_parse_error(
                            AdvancedFlowFilterTextParseStatus::unknown_key,
                            line_number,
                            1U,
                            std::string(key),
                            {},
                            "Unknown flow_protocol key."
                        );
                    }
                } else if (root == "detected_protocol" && key_segments.values.size() == 2U) {
                    auto hint = parse_flow_protocol_hint_token(value);
                    if (!hint.has_value()) {
                        return make_parse_error(
                            AdvancedFlowFilterTextParseStatus::invalid_enum_token,
                            line_number,
                            value_column,
                            std::string(key),
                            std::string(value),
                            "Unknown detected protocol token."
                        );
                    }

                    if (key_segments.values[1] == "include") {
                        configured_spec.detected_protocol.include.push_back(*hint);
                    } else if (key_segments.values[1] == "exclude") {
                        configured_spec.detected_protocol.exclude.push_back(*hint);
                    } else {
                        return make_parse_error(
                            AdvancedFlowFilterTextParseStatus::unknown_key,
                            line_number,
                            1U,
                            std::string(key),
                            {},
                            "Unknown detected_protocol key."
                        );
                    }
                } else if (root == "tls_version" && key_segments.values.size() == 2U) {
                    auto version = parse_tls_version_token(value);
                    if (!version.has_value()) {
                        return make_parse_error(
                            AdvancedFlowFilterTextParseStatus::invalid_enum_token,
                            line_number,
                            value_column,
                            std::string(key),
                            std::string(value),
                            "Unknown TLS version token."
                        );
                    }

                    if (key_segments.values[1] == "include") {
                        configured_spec.tls_version.include.push_back(*version);
                    } else if (key_segments.values[1] == "exclude") {
                        configured_spec.tls_version.exclude.push_back(*version);
                    } else {
                        return make_parse_error(
                            AdvancedFlowFilterTextParseStatus::unknown_key,
                            line_number,
                            1U,
                            std::string(key),
                            {},
                            "Unknown tls_version key."
                        );
                    }
                } else if (root == "quic_version" && key_segments.values.size() == 2U) {
                    auto version = parse_quic_version_token(value);
                    if (!version.has_value()) {
                        return make_parse_error(
                            AdvancedFlowFilterTextParseStatus::invalid_enum_token,
                            line_number,
                            value_column,
                            std::string(key),
                            std::string(value),
                            "Unknown QUIC version token."
                        );
                    }

                    if (key_segments.values[1] == "include") {
                        configured_spec.quic_version.include.push_back(*version);
                    } else if (key_segments.values[1] == "exclude") {
                        configured_spec.quic_version.exclude.push_back(*version);
                    } else {
                        return make_parse_error(
                            AdvancedFlowFilterTextParseStatus::unknown_key,
                            line_number,
                            1U,
                            std::string(key),
                            {},
                            "Unknown quic_version key."
                        );
                    }
                } else if (root == "directionality" && key_segments.values.size() == 2U) {
                    auto directionality = parse_directionality_token(value);
                    if (!directionality.has_value()) {
                        return make_parse_error(
                            AdvancedFlowFilterTextParseStatus::invalid_enum_token,
                            line_number,
                            value_column,
                            std::string(key),
                            std::string(value),
                            "Unknown directionality token."
                        );
                    }

                    if (key_segments.values[1] == "include") {
                        configured_spec.directionality.include.push_back(*directionality);
                    } else if (key_segments.values[1] == "exclude") {
                        configured_spec.directionality.exclude.push_back(*directionality);
                    } else {
                        return make_parse_error(
                            AdvancedFlowFilterTextParseStatus::unknown_key,
                            line_number,
                            1U,
                            std::string(key),
                            {},
                            "Unknown directionality key."
                        );
                    }
                } else if (root == "port" && key_segments.values.size() == 3U) {
                    const auto scope = parse_port_scope_token(key_segments.values[1]);
                    if (!scope.has_value()) {
                        return make_parse_error(
                            AdvancedFlowFilterTextParseStatus::unknown_key,
                            line_number,
                            1U,
                            std::string(key),
                            {},
                            "Unknown port scope."
                        );
                    }

                    const auto range = parse_port_range_value(value);
                    if (!range.ok) {
                        return make_parse_error(
                            range.overflow
                                ? AdvancedFlowFilterTextParseStatus::numeric_overflow
                                : AdvancedFlowFilterTextParseStatus::invalid_value,
                            line_number,
                            value_column,
                            std::string(key),
                            std::string(value),
                            "Invalid port or port range value."
                        );
                    }
                    if (range.reversed) {
                        return make_parse_error(
                            AdvancedFlowFilterTextParseStatus::invalid_value,
                            line_number,
                            value_column,
                            std::string(key),
                            std::string(value),
                            "Port ranges must use ascending bounds."
                        );
                    }

                    AdvancedFlowFilterPortPredicate predicate {
                        .scope = *scope,
                        .range = range.range,
                    };
                    if (key_segments.values[2] == "include") {
                        configured_spec.ports.include.push_back(predicate);
                    } else if (key_segments.values[2] == "exclude") {
                        configured_spec.ports.exclude.push_back(predicate);
                    } else {
                        return make_parse_error(
                            AdvancedFlowFilterTextParseStatus::unknown_key,
                            line_number,
                            1U,
                            std::string(key),
                            {},
                            "Unknown port action."
                        );
                    }
                } else if (root == "ip" && key_segments.values.size() == 3U) {
                    const auto scope = parse_endpoint_scope_token(key_segments.values[1]);
                    if (!scope.has_value()) {
                        return make_parse_error(
                            AdvancedFlowFilterTextParseStatus::unknown_key,
                            line_number,
                            1U,
                            std::string(key),
                            {},
                            "Unknown IP endpoint scope."
                        );
                    }

                    const auto slash = value.find('/');
                    const auto address_text = slash == std::string_view::npos ? value : value.substr(0U, slash);
                    const auto prefix_text = slash == std::string_view::npos ? std::string_view {} : value.substr(slash + 1U);
                    if (value.find('/', slash == std::string_view::npos ? 0U : slash + 1U) != std::string_view::npos) {
                        return make_parse_error(
                            AdvancedFlowFilterTextParseStatus::invalid_ip_address,
                            line_number,
                            value_column,
                            std::string(key),
                            std::string(value),
                            "Invalid IP/CIDR syntax."
                        );
                    }

                    if (address_text.find(':') != std::string_view::npos) {
                        const auto address = parse_ipv6_address(address_text);
                        if (!address.has_value()) {
                            return make_parse_error(
                                AdvancedFlowFilterTextParseStatus::invalid_ip_address,
                                line_number,
                                value_column,
                                std::string(key),
                                std::string(value),
                                "Invalid IPv6 address."
                            );
                        }

                        AdvancedFlowFilterIpv6AddressPredicate predicate {
                            .match_kind = slash == std::string_view::npos
                                ? AdvancedFlowFilterAddressMatchKind::exact
                                : AdvancedFlowFilterAddressMatchKind::cidr,
                            .scope = *scope,
                            .value = *address,
                            .prefix_length = slash == std::string_view::npos
                                ? static_cast<std::uint8_t>(128U)
                                : static_cast<std::uint8_t>(0U),
                        };
                        if (slash != std::string_view::npos) {
                            const auto prefix = narrow_uint8(parse_uint64_decimal(prefix_text));
                            if (!prefix.ok) {
                                return make_parse_error(
                                    prefix.overflow
                                        ? AdvancedFlowFilterTextParseStatus::numeric_overflow
                                        : AdvancedFlowFilterTextParseStatus::invalid_value,
                                    line_number,
                                    value_column + slash + 1U,
                                    std::string(key),
                                    std::string(value),
                                    "Invalid IPv6 prefix length."
                                );
                            }
                            predicate.prefix_length = prefix.value;
                        }

                        if (key_segments.values[2] == "include") {
                            configured_spec.addresses.ipv6_include.push_back(predicate);
                        } else if (key_segments.values[2] == "exclude") {
                            configured_spec.addresses.ipv6_exclude.push_back(predicate);
                        } else {
                            return make_parse_error(
                                AdvancedFlowFilterTextParseStatus::unknown_key,
                                line_number,
                                1U,
                                std::string(key),
                                {},
                                "Unknown IP action."
                            );
                        }
                    } else {
                        const auto address = parse_ipv4_address(address_text);
                        if (!address.has_value()) {
                            return make_parse_error(
                                AdvancedFlowFilterTextParseStatus::invalid_ip_address,
                                line_number,
                                value_column,
                                std::string(key),
                                std::string(value),
                                "Invalid IPv4 address."
                            );
                        }

                        AdvancedFlowFilterIpv4AddressPredicate predicate {
                            .match_kind = slash == std::string_view::npos
                                ? AdvancedFlowFilterAddressMatchKind::exact
                                : AdvancedFlowFilterAddressMatchKind::cidr,
                            .scope = *scope,
                            .value = *address,
                            .prefix_length = slash == std::string_view::npos
                                ? static_cast<std::uint8_t>(32U)
                                : static_cast<std::uint8_t>(0U),
                        };
                        if (slash != std::string_view::npos) {
                            const auto prefix = narrow_uint8(parse_uint64_decimal(prefix_text));
                            if (!prefix.ok) {
                                return make_parse_error(
                                    prefix.overflow
                                        ? AdvancedFlowFilterTextParseStatus::numeric_overflow
                                        : AdvancedFlowFilterTextParseStatus::invalid_value,
                                    line_number,
                                    value_column + slash + 1U,
                                    std::string(key),
                                    std::string(value),
                                    "Invalid IPv4 prefix length."
                                );
                            }
                            predicate.prefix_length = prefix.value;
                        }

                        if (key_segments.values[2] == "include") {
                            configured_spec.addresses.ipv4_include.push_back(predicate);
                        } else if (key_segments.values[2] == "exclude") {
                            configured_spec.addresses.ipv4_exclude.push_back(predicate);
                        } else {
                            return make_parse_error(
                                AdvancedFlowFilterTextParseStatus::unknown_key,
                                line_number,
                                1U,
                                std::string(key),
                                {},
                                "Unknown IP action."
                            );
                        }
                    }
                } else if (root == "service" && key_segments.values.size() == 3U &&
                           key_segments.values[1] == "state") {
                    AdvancedFlowFilterServicePredicate predicate {};
                    if (equals_ascii_case_insensitive(value, "known")) {
                        predicate.kind = AdvancedFlowFilterServicePredicateKind::known;
                    } else if (equals_ascii_case_insensitive(value, "unknown")) {
                        predicate.kind = AdvancedFlowFilterServicePredicateKind::unknown;
                    } else {
                        return make_parse_error(
                            AdvancedFlowFilterTextParseStatus::invalid_enum_token,
                            line_number,
                            value_column,
                            std::string(key),
                            std::string(value),
                            "service.state requires 'known' or 'unknown'."
                        );
                    }

                    if (key_segments.values[2] == "include") {
                        configured_spec.service.include.push_back(predicate);
                    } else if (key_segments.values[2] == "exclude") {
                        configured_spec.service.exclude.push_back(predicate);
                    } else {
                        return make_parse_error(
                            AdvancedFlowFilterTextParseStatus::unknown_key,
                            line_number,
                            1U,
                            std::string(key),
                            {},
                            "Unknown service.state action."
                        );
                    }
                } else if (root == "service" && key_segments.values.size() == 4U) {
                    const auto operator_kind = parse_service_operator_token(key_segments.values[1]);
                    const auto case_sensitivity = parse_case_sensitivity_token(key_segments.values[2]);
                    if (!operator_kind.has_value() || !case_sensitivity.has_value()) {
                        return make_parse_error(
                            AdvancedFlowFilterTextParseStatus::unknown_key,
                            line_number,
                            1U,
                            std::string(key),
                            {},
                            "Unknown service predicate key."
                        );
                    }

                    const auto parsed_string = parse_quoted_string(value, value_column);
                    if (!parsed_string.ok) {
                        if (parsed_string.invalid_escape) {
                            return make_parse_error(
                                AdvancedFlowFilterTextParseStatus::invalid_escape,
                                line_number,
                                parsed_string.error_column,
                                std::string(key),
                                std::string(value),
                                "Invalid escape sequence in quoted string."
                            );
                        }
                        if (parsed_string.unterminated) {
                            return make_parse_error(
                                AdvancedFlowFilterTextParseStatus::unterminated_string,
                                line_number,
                                parsed_string.error_column,
                                std::string(key),
                                std::string(value),
                                "Unterminated quoted string."
                            );
                        }
                        return make_parse_error(
                            AdvancedFlowFilterTextParseStatus::invalid_value,
                            line_number,
                            parsed_string.error_column == 0U ? std::optional<std::size_t> {} : parsed_string.error_column,
                            std::string(key),
                            std::string(value),
                            "Expected a quoted service string."
                        );
                    }

                    AdvancedFlowFilterServicePredicate predicate {
                        .kind = *operator_kind,
                        .value = parsed_string.value,
                        .case_sensitivity = *case_sensitivity,
                    };
                    if (key_segments.values[3] == "include") {
                        configured_spec.service.include.push_back(std::move(predicate));
                    } else if (key_segments.values[3] == "exclude") {
                        configured_spec.service.exclude.push_back(std::move(predicate));
                    } else {
                        return make_parse_error(
                            AdvancedFlowFilterTextParseStatus::unknown_key,
                            line_number,
                            1U,
                            std::string(key),
                            {},
                            "Unknown service text-predicate action."
                        );
                    }
                } else if (root == "protocol_path" && key_segments.values.size() == 3U) {
                    const auto match_kind = parse_protocol_path_match_kind_token(key_segments.values[1]);
                    if (!match_kind.has_value()) {
                        return make_parse_error(
                            AdvancedFlowFilterTextParseStatus::unknown_key,
                            line_number,
                            1U,
                            std::string(key),
                            {},
                            "Unknown protocol_path predicate key."
                        );
                    }

                    const auto layers = parse_protocol_path_layers(
                        value,
                        *match_kind == AdvancedFlowFilterProtocolPathMatchKind::contains_layer
                    );
                    if (!layers.has_value()) {
                        return make_parse_error(
                            AdvancedFlowFilterTextParseStatus::invalid_protocol_path_syntax,
                            line_number,
                            value_column,
                            std::string(key),
                            std::string(value),
                            "Invalid Protocol Path predicate syntax."
                        );
                    }

                    AdvancedFlowFilterProtocolPathPredicate predicate {
                        .match_kind = *match_kind,
                        .layers = *layers,
                    };
                    if (key_segments.values[2] == "include") {
                        configured_spec.protocol_path.include.push_back(std::move(predicate));
                    } else if (key_segments.values[2] == "exclude") {
                        configured_spec.protocol_path.exclude.push_back(std::move(predicate));
                    } else {
                        return make_parse_error(
                            AdvancedFlowFilterTextParseStatus::unknown_key,
                            line_number,
                            1U,
                            std::string(key),
                            {},
                            "Unknown protocol_path action."
                        );
                    }
                } else if ((root == "packet_count" ||
                            root == "fragmented_packet_count" ||
                            root == "truncated_packet_count" ||
                            root == "tcp_syn_count" ||
                            root == "tcp_fin_count" ||
                            root == "tcp_rst_count") &&
                           key_segments.values.size() == 2U &&
                           (key_segments.values[1] == "min" || key_segments.values[1] == "max")) {
                    const auto parsed_value = parse_uint64_decimal(value);
                    if (!parsed_value.ok) {
                        return make_parse_error(
                            parsed_value.overflow
                                ? AdvancedFlowFilterTextParseStatus::numeric_overflow
                                : AdvancedFlowFilterTextParseStatus::invalid_value,
                            line_number,
                            value_column,
                            std::string(key),
                            std::string(value),
                            "Expected an unsigned integer value."
                        );
                    }

                    if (root == "packet_count") {
                        assign_range_bound(configured_spec.aggregate.packet_count, key_segments.values[1], parsed_value.value);
                    } else if (root == "fragmented_packet_count") {
                        assign_range_bound(configured_spec.aggregate.fragmented_packet_count, key_segments.values[1], parsed_value.value);
                    } else if (root == "truncated_packet_count") {
                        assign_range_bound(configured_spec.aggregate.truncated_packet_count, key_segments.values[1], parsed_value.value);
                    } else if (root == "tcp_syn_count") {
                        assign_range_bound(configured_spec.aggregate.tcp_syn_count, key_segments.values[1], parsed_value.value);
                    } else if (root == "tcp_fin_count") {
                        assign_range_bound(configured_spec.aggregate.tcp_fin_count, key_segments.values[1], parsed_value.value);
                    } else {
                        assign_range_bound(configured_spec.aggregate.tcp_rst_count, key_segments.values[1], parsed_value.value);
                    }
                } else if ((root == "original_bytes" ||
                            root == "captured_bytes" ||
                            root == "duration") &&
                           key_segments.values.size() == 2U &&
                           (key_segments.values[1] == "min" || key_segments.values[1] == "max")) {
                    const auto parsed_value = root == "duration"
                        ? parse_duration_quantity_value(value)
                        : parse_byte_quantity_value(value, true);
                    if (!parsed_value.ok) {
                        return make_parse_error(
                            parsed_value.overflow
                                ? AdvancedFlowFilterTextParseStatus::numeric_overflow
                                : AdvancedFlowFilterTextParseStatus::invalid_value,
                            line_number,
                            value_column,
                            std::string(key),
                            std::string(value),
                            root == "duration"
                                ? "Invalid duration value."
                                : "Invalid byte quantity."
                        );
                    }

                    if (root == "original_bytes") {
                        assign_range_bound(configured_spec.aggregate.original_bytes, key_segments.values[1], parsed_value.value);
                    } else if (root == "captured_bytes") {
                        assign_range_bound(configured_spec.aggregate.captured_bytes, key_segments.values[1], parsed_value.value);
                    } else {
                        assign_range_bound(configured_spec.aggregate.duration_us, key_segments.values[1], parsed_value.value);
                    }
                } else if ((root == "max_original_packet_length" ||
                            root == "max_captured_packet_length") &&
                           key_segments.values.size() == 2U &&
                           (key_segments.values[1] == "min" || key_segments.values[1] == "max")) {
                    const auto parsed_value = narrow_uint32(parse_byte_quantity_value(value, true));
                    if (!parsed_value.ok) {
                        return make_parse_error(
                            parsed_value.overflow
                                ? AdvancedFlowFilterTextParseStatus::numeric_overflow
                                : AdvancedFlowFilterTextParseStatus::invalid_value,
                            line_number,
                            value_column,
                            std::string(key),
                            std::string(value),
                            "Invalid max packet-length quantity."
                        );
                    }

                    if (root == "max_original_packet_length") {
                        assign_range_bound(configured_spec.aggregate.max_original_packet_length, key_segments.values[1], parsed_value.value);
                    } else {
                        assign_range_bound(configured_spec.aggregate.max_captured_packet_length, key_segments.values[1], parsed_value.value);
                    }
                } else {
                    return make_parse_error(
                        AdvancedFlowFilterTextParseStatus::unknown_key,
                        line_number,
                        1U,
                        std::string(key),
                        {},
                        "Unknown key."
                    );
                }
            }
        }

        if (newline == std::string_view::npos) {
            break;
        }
        line_start = newline + 1U;
        ++line_number;
    }

    if (!seen_version) {
        return make_parse_error(
            AdvancedFlowFilterTextParseStatus::missing_format_version,
            saw_meaningful_line ? 1U : 0U,
            std::nullopt,
            {},
            {},
            "Missing required format_version = 2 declaration."
        );
    }

    return result;
}

AdvancedFlowFilterTextFormatResult format_advanced_flow_filter_text(const AdvancedFlowFilterDocument& document) {
    AdvancedFlowFilterTextFormatResult result {};
    std::vector<std::string> lines {};
    lines.push_back(std::string("format_version = ") + std::string(kFormatVersionValue));
    append_non_default_section_state_lines(lines, document.section_states);
    const auto& spec = document.configured_spec;

    auto append_line = [&](std::string key, std::string value) {
        lines.push_back(std::move(key) + " = " + std::move(value));
    };

    for (const auto& predicate : spec.protocol_path.include) {
        const auto match_kind = format_protocol_path_match_kind_token(predicate.match_kind);
        bool ok = false;
        const auto value = format_protocol_path_value(predicate.layers, &ok);
        if (match_kind.empty() || !ok) {
            return make_format_error("protocol_path", "Spec contains an unrepresentable Protocol Path include predicate.");
        }
        append_line("protocol_path." + match_kind + ".include", value);
    }
    for (const auto& predicate : spec.protocol_path.exclude) {
        const auto match_kind = format_protocol_path_match_kind_token(predicate.match_kind);
        bool ok = false;
        const auto value = format_protocol_path_value(predicate.layers, &ok);
        if (match_kind.empty() || !ok) {
            return make_format_error("protocol_path", "Spec contains an unrepresentable Protocol Path exclude predicate.");
        }
        append_line("protocol_path." + match_kind + ".exclude", value);
    }

    for (const auto family : spec.address_family.include) {
        const auto token = format_address_family_token(family);
        if (token.empty()) {
            return make_format_error("address_family", "Spec contains an unrepresentable address family token.");
        }
        append_line("address_family.include", token);
    }
    for (const auto family : spec.address_family.exclude) {
        const auto token = format_address_family_token(family);
        if (token.empty()) {
            return make_format_error("address_family", "Spec contains an unrepresentable address family token.");
        }
        append_line("address_family.exclude", token);
    }

    for (const auto protocol : spec.flow_protocol.include) {
        const auto token = format_protocol_id_token(protocol);
        if (token.empty()) {
            return make_format_error("flow_protocol", "Spec contains an unrepresentable flow protocol token.");
        }
        append_line("flow_protocol.include", token);
    }
    for (const auto protocol : spec.flow_protocol.exclude) {
        const auto token = format_protocol_id_token(protocol);
        if (token.empty()) {
            return make_format_error("flow_protocol", "Spec contains an unrepresentable flow protocol token.");
        }
        append_line("flow_protocol.exclude", token);
    }

    for (const auto hint : spec.detected_protocol.include) {
        const auto token = format_flow_protocol_hint_token(hint);
        if (token.empty()) {
            return make_format_error("detected_protocol", "Spec contains an unrepresentable detected protocol token.");
        }
        append_line("detected_protocol.include", token);
    }
    for (const auto hint : spec.detected_protocol.exclude) {
        const auto token = format_flow_protocol_hint_token(hint);
        if (token.empty()) {
            return make_format_error("detected_protocol", "Spec contains an unrepresentable detected protocol token.");
        }
        append_line("detected_protocol.exclude", token);
    }

    for (const auto version : spec.tls_version.include) {
        const auto token = format_tls_version_token(version);
        if (token.empty()) {
            return make_format_error("tls_version", "Spec contains an unrepresentable TLS version token.");
        }
        append_line("tls_version.include", token);
    }
    for (const auto version : spec.tls_version.exclude) {
        const auto token = format_tls_version_token(version);
        if (token.empty()) {
            return make_format_error("tls_version", "Spec contains an unrepresentable TLS version token.");
        }
        append_line("tls_version.exclude", token);
    }

    for (const auto version : spec.quic_version.include) {
        const auto token = format_quic_version_token(version);
        if (token.empty()) {
            return make_format_error("quic_version", "Spec contains an unrepresentable QUIC version token.");
        }
        append_line("quic_version.include", token);
    }
    for (const auto version : spec.quic_version.exclude) {
        const auto token = format_quic_version_token(version);
        if (token.empty()) {
            return make_format_error("quic_version", "Spec contains an unrepresentable QUIC version token.");
        }
        append_line("quic_version.exclude", token);
    }

    for (const auto& predicate : spec.ports.include) {
        const auto scope = format_port_scope_token(predicate.scope);
        if (scope.empty()) {
            return make_format_error("ports", "Spec contains an unrepresentable port-scope predicate.");
        }
        append_line("port." + scope + ".include", format_port_range_value(predicate.range));
    }
    for (const auto& predicate : spec.ports.exclude) {
        const auto scope = format_port_scope_token(predicate.scope);
        if (scope.empty()) {
            return make_format_error("ports", "Spec contains an unrepresentable port-scope predicate.");
        }
        append_line("port." + scope + ".exclude", format_port_range_value(predicate.range));
    }

    if (spec.aggregate.packet_count.has_value()) {
        if (spec.aggregate.packet_count->min.has_value()) {
            append_line("packet_count.min", std::to_string(*spec.aggregate.packet_count->min));
        }
        if (spec.aggregate.packet_count->max.has_value()) {
            append_line("packet_count.max", std::to_string(*spec.aggregate.packet_count->max));
        }
    }
    if (spec.aggregate.original_bytes.has_value()) {
        if (spec.aggregate.original_bytes->min.has_value()) {
            append_line("original_bytes.min", format_byte_quantity_value(*spec.aggregate.original_bytes->min));
        }
        if (spec.aggregate.original_bytes->max.has_value()) {
            append_line("original_bytes.max", format_byte_quantity_value(*spec.aggregate.original_bytes->max));
        }
    }
    if (spec.aggregate.captured_bytes.has_value()) {
        if (spec.aggregate.captured_bytes->min.has_value()) {
            append_line("captured_bytes.min", format_byte_quantity_value(*spec.aggregate.captured_bytes->min));
        }
        if (spec.aggregate.captured_bytes->max.has_value()) {
            append_line("captured_bytes.max", format_byte_quantity_value(*spec.aggregate.captured_bytes->max));
        }
    }
    if (spec.aggregate.duration_us.has_value()) {
        if (spec.aggregate.duration_us->min.has_value()) {
            append_line("duration.min", format_duration_value(*spec.aggregate.duration_us->min));
        }
        if (spec.aggregate.duration_us->max.has_value()) {
            append_line("duration.max", format_duration_value(*spec.aggregate.duration_us->max));
        }
    }
    if (spec.aggregate.fragmented_packet_count.has_value()) {
        if (spec.aggregate.fragmented_packet_count->min.has_value()) {
            append_line("fragmented_packet_count.min", std::to_string(*spec.aggregate.fragmented_packet_count->min));
        }
        if (spec.aggregate.fragmented_packet_count->max.has_value()) {
            append_line("fragmented_packet_count.max", std::to_string(*spec.aggregate.fragmented_packet_count->max));
        }
    }
    if (spec.aggregate.truncated_packet_count.has_value()) {
        if (spec.aggregate.truncated_packet_count->min.has_value()) {
            append_line("truncated_packet_count.min", std::to_string(*spec.aggregate.truncated_packet_count->min));
        }
        if (spec.aggregate.truncated_packet_count->max.has_value()) {
            append_line("truncated_packet_count.max", std::to_string(*spec.aggregate.truncated_packet_count->max));
        }
    }
    if (spec.aggregate.tcp_syn_count.has_value()) {
        if (spec.aggregate.tcp_syn_count->min.has_value()) {
            append_line("tcp_syn_count.min", std::to_string(*spec.aggregate.tcp_syn_count->min));
        }
        if (spec.aggregate.tcp_syn_count->max.has_value()) {
            append_line("tcp_syn_count.max", std::to_string(*spec.aggregate.tcp_syn_count->max));
        }
    }
    if (spec.aggregate.tcp_fin_count.has_value()) {
        if (spec.aggregate.tcp_fin_count->min.has_value()) {
            append_line("tcp_fin_count.min", std::to_string(*spec.aggregate.tcp_fin_count->min));
        }
        if (spec.aggregate.tcp_fin_count->max.has_value()) {
            append_line("tcp_fin_count.max", std::to_string(*spec.aggregate.tcp_fin_count->max));
        }
    }
    if (spec.aggregate.tcp_rst_count.has_value()) {
        if (spec.aggregate.tcp_rst_count->min.has_value()) {
            append_line("tcp_rst_count.min", std::to_string(*spec.aggregate.tcp_rst_count->min));
        }
        if (spec.aggregate.tcp_rst_count->max.has_value()) {
            append_line("tcp_rst_count.max", std::to_string(*spec.aggregate.tcp_rst_count->max));
        }
    }
    if (spec.aggregate.max_original_packet_length.has_value()) {
        if (spec.aggregate.max_original_packet_length->min.has_value()) {
            append_line(
                "max_original_packet_length.min",
                format_byte_quantity_value(*spec.aggregate.max_original_packet_length->min)
            );
        }
        if (spec.aggregate.max_original_packet_length->max.has_value()) {
            append_line(
                "max_original_packet_length.max",
                format_byte_quantity_value(*spec.aggregate.max_original_packet_length->max)
            );
        }
    }
    if (spec.aggregate.max_captured_packet_length.has_value()) {
        if (spec.aggregate.max_captured_packet_length->min.has_value()) {
            append_line(
                "max_captured_packet_length.min",
                format_byte_quantity_value(*spec.aggregate.max_captured_packet_length->min)
            );
        }
        if (spec.aggregate.max_captured_packet_length->max.has_value()) {
            append_line(
                "max_captured_packet_length.max",
                format_byte_quantity_value(*spec.aggregate.max_captured_packet_length->max)
            );
        }
    }

    for (const auto value : spec.directionality.include) {
        const auto token = format_directionality_token(value);
        if (token.empty()) {
            return make_format_error("directionality", "Spec contains an unrepresentable directionality token.");
        }
        append_line("directionality.include", token);
    }
    for (const auto value : spec.directionality.exclude) {
        const auto token = format_directionality_token(value);
        if (token.empty()) {
            return make_format_error("directionality", "Spec contains an unrepresentable directionality token.");
        }
        append_line("directionality.exclude", token);
    }

    for (const auto& predicate : spec.addresses.ipv4_include) {
        const auto scope = format_endpoint_scope_token(predicate.scope);
        if (scope.empty()) {
            return make_format_error("addresses", "Spec contains an unrepresentable IPv4 endpoint scope.");
        }
        const auto address = format_ipv4_address(predicate.value);
        append_line(
            "ip." + scope + ".include",
            predicate.match_kind == AdvancedFlowFilterAddressMatchKind::exact
                ? address
                : address + "/" + std::to_string(predicate.prefix_length)
        );
    }
    for (const auto& predicate : spec.addresses.ipv6_include) {
        const auto scope = format_endpoint_scope_token(predicate.scope);
        if (scope.empty()) {
            return make_format_error("addresses", "Spec contains an unrepresentable IPv6 endpoint scope.");
        }
        const auto address = format_ipv6_address(predicate.value);
        append_line(
            "ip." + scope + ".include",
            predicate.match_kind == AdvancedFlowFilterAddressMatchKind::exact
                ? address
                : address + "/" + std::to_string(predicate.prefix_length)
        );
    }
    for (const auto& predicate : spec.addresses.ipv4_exclude) {
        const auto scope = format_endpoint_scope_token(predicate.scope);
        if (scope.empty()) {
            return make_format_error("addresses", "Spec contains an unrepresentable IPv4 endpoint scope.");
        }
        const auto address = format_ipv4_address(predicate.value);
        append_line(
            "ip." + scope + ".exclude",
            predicate.match_kind == AdvancedFlowFilterAddressMatchKind::exact
                ? address
                : address + "/" + std::to_string(predicate.prefix_length)
        );
    }
    for (const auto& predicate : spec.addresses.ipv6_exclude) {
        const auto scope = format_endpoint_scope_token(predicate.scope);
        if (scope.empty()) {
            return make_format_error("addresses", "Spec contains an unrepresentable IPv6 endpoint scope.");
        }
        const auto address = format_ipv6_address(predicate.value);
        append_line(
            "ip." + scope + ".exclude",
            predicate.match_kind == AdvancedFlowFilterAddressMatchKind::exact
                ? address
                : address + "/" + std::to_string(predicate.prefix_length)
        );
    }

    for (const auto& predicate : spec.service.include) {
        switch (predicate.kind) {
        case AdvancedFlowFilterServicePredicateKind::known:
            append_line("service.state.include", "known");
            break;
        case AdvancedFlowFilterServicePredicateKind::unknown:
            append_line("service.state.include", "unknown");
            break;
        case AdvancedFlowFilterServicePredicateKind::equals:
        case AdvancedFlowFilterServicePredicateKind::starts_with:
        case AdvancedFlowFilterServicePredicateKind::contains: {
            const auto op = format_service_operator_token(predicate.kind);
            const auto cs = format_service_case_token(predicate.case_sensitivity);
            if (op.empty() || cs.empty()) {
                return make_format_error("service", "Spec contains an unrepresentable service predicate.");
            }
            append_line("service." + op + "." + cs + ".include", escape_quoted_string(predicate.value));
            break;
        }
        }
    }
    for (const auto& predicate : spec.service.exclude) {
        switch (predicate.kind) {
        case AdvancedFlowFilterServicePredicateKind::known:
            append_line("service.state.exclude", "known");
            break;
        case AdvancedFlowFilterServicePredicateKind::unknown:
            append_line("service.state.exclude", "unknown");
            break;
        case AdvancedFlowFilterServicePredicateKind::equals:
        case AdvancedFlowFilterServicePredicateKind::starts_with:
        case AdvancedFlowFilterServicePredicateKind::contains: {
            const auto op = format_service_operator_token(predicate.kind);
            const auto cs = format_service_case_token(predicate.case_sensitivity);
            if (op.empty() || cs.empty()) {
                return make_format_error("service", "Spec contains an unrepresentable service predicate.");
            }
            append_line("service." + op + "." + cs + ".exclude", escape_quoted_string(predicate.value));
            break;
        }
        }
    }

    std::ostringstream text {};
    for (const auto& line : lines) {
        text << line << '\n';
    }
    result.text = text.str();
    return result;
}

}  // namespace pfl::session_detail
