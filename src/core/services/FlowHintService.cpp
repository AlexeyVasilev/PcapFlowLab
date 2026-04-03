#include "core/services/FlowHintService.h"

#include <array>
#include <cctype>
#include <optional>
#include <span>
#include <string>
#include <string_view>

#include "core/domain/ProtocolId.h"
#include "core/io/LinkType.h"
#include "core/services/PacketPayloadService.h"
#include "core/services/QuicInitialParser.h"

namespace pfl {

namespace {

constexpr std::uint16_t kDnsPort = 53;
constexpr std::uint16_t kDhcpServerPort = 67;
constexpr std::uint16_t kDhcpClientPort = 68;
constexpr std::uint16_t kMdnsPort = 5353;
constexpr std::uint16_t kHttpsPort = 443;
constexpr std::uint16_t kSmtpPort = 25;
constexpr std::uint16_t kSubmissionPort = 587;
constexpr std::uint16_t kPop3Port = 110;
constexpr std::uint16_t kImapPort = 143;
constexpr std::uint16_t kTlsRecordHeaderSize = 5;
constexpr std::uint16_t kDnsHeaderSize = 12;
constexpr std::uint32_t kMdnsIpv4Multicast = 0xE00000FBU;
constexpr std::array<std::uint8_t, 16> kMdnsIpv6Multicast {0xFF, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFB};
constexpr std::uint32_t kStunMagicCookie = 0x2112A442U;
constexpr std::size_t kStunHeaderSize = 20U;
constexpr std::size_t kBootpFixedHeaderSize = 236U;
constexpr std::size_t kDhcpMagicCookieOffset = kBootpFixedHeaderSize;
constexpr std::size_t kDhcpMinPayloadSize = kDhcpMagicCookieOffset + 4U;
constexpr std::uint32_t kDhcpMagicCookie = 0x63825363U;
constexpr std::string_view kBitTorrentHandshakeProtocol = "BitTorrent protocol";
constexpr std::size_t kBitTorrentHandshakeSize = 68U;

struct FlowHintDetectionSettings {
    AnalysisSettings analysis_settings {};
    bool enable_quic_initial_sni {false};
};

std::uint16_t read_be16(std::span<const std::uint8_t> bytes, const std::size_t offset) {
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(bytes[offset]) << 8U) |
                                      static_cast<std::uint16_t>(bytes[offset + 1U]));
}

std::uint32_t read_be24(std::span<const std::uint8_t> bytes, const std::size_t offset) {
    return (static_cast<std::uint32_t>(bytes[offset]) << 16U) |
           (static_cast<std::uint32_t>(bytes[offset + 1U]) << 8U) |
           static_cast<std::uint32_t>(bytes[offset + 2U]);
}

std::uint32_t read_be32(std::span<const std::uint8_t> bytes, const std::size_t offset) {
    return (static_cast<std::uint32_t>(bytes[offset]) << 24U) |
           (static_cast<std::uint32_t>(bytes[offset + 1U]) << 16U) |
           (static_cast<std::uint32_t>(bytes[offset + 2U]) << 8U) |
           static_cast<std::uint32_t>(bytes[offset + 3U]);
}

bool has_port(const std::uint16_t left, const std::uint16_t right, const std::uint16_t port) noexcept {
    return left == port || right == port;
}

bool has_port_pair(const std::uint16_t left, const std::uint16_t right, const std::uint16_t port_a, const std::uint16_t port_b) noexcept {
    return (left == port_a && right == port_b) || (left == port_b && right == port_a);
}

bool is_mdns_multicast_destination(const std::uint32_t destination) noexcept {
    return destination == kMdnsIpv4Multicast;
}

bool is_mdns_multicast_destination(const std::array<std::uint8_t, 16>& destination) noexcept {
    return destination == kMdnsIpv6Multicast;
}

std::string_view payload_as_text(std::span<const std::uint8_t> payload) {
    return std::string_view(reinterpret_cast<const char*>(payload.data()), payload.size());
}

bool ascii_iequals(const char left, const char right) noexcept {
    return std::tolower(static_cast<unsigned char>(left)) == std::tolower(static_cast<unsigned char>(right));
}

bool starts_with_ascii_case_insensitive(const std::string_view value, const std::string_view prefix) noexcept {
    if (value.size() < prefix.size()) {
        return false;
    }

    for (std::size_t index = 0; index < prefix.size(); ++index) {
        if (!ascii_iequals(value[index], prefix[index])) {
            return false;
        }
    }

    return true;
}

std::string trim_ascii(std::string_view value) {
    while (!value.empty() && (value.front() == ' ' || value.front() == '\t' || value.front() == '\r' || value.front() == '\n')) {
        value.remove_prefix(1);
    }

    while (!value.empty() && (value.back() == ' ' || value.back() == '\t' || value.back() == '\r' || value.back() == '\n')) {
        value.remove_suffix(1);
    }

    return std::string(value);
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

    return true;
}

bool looks_like_http_request(const std::string_view payload_text) noexcept {
    constexpr std::array<std::string_view, 9> methods {
        "GET ", "POST ", "PUT ", "HEAD ", "OPTIONS ", "DELETE ", "PATCH ", "CONNECT ", "TRACE ",
    };

    for (const auto method : methods) {
        if (payload_text.starts_with(method)) {
            return true;
        }
    }

    return false;
}

bool looks_like_http_response(const std::string_view payload_text) noexcept {
    return payload_text.starts_with("HTTP/1.");
}

bool looks_like_ssh_banner(std::span<const std::uint8_t> payload) noexcept {
    return payload.size() >= 4U && payload_as_text(payload).starts_with("SSH-");
}

bool looks_like_stun_message(std::span<const std::uint8_t> payload) {
    if (payload.size() < kStunHeaderSize) {
        return false;
    }

    if ((payload[0] & 0xC0U) != 0U) {
        return false;
    }

    const auto message_length = static_cast<std::size_t>(read_be16(payload, 2U));
    if ((message_length % 4U) != 0U) {
        return false;
    }

    if (payload.size() != (kStunHeaderSize + message_length)) {
        return false;
    }

    return read_be32(payload, 4U) == kStunMagicCookie;
}

bool looks_like_bittorrent_handshake(std::span<const std::uint8_t> payload) {
    if (payload.size() < kBitTorrentHandshakeSize) {
        return false;
    }

    if (payload[0] != static_cast<std::uint8_t>(kBitTorrentHandshakeProtocol.size())) {
        return false;
    }

    const auto protocol_name = payload_as_text(payload.subspan(1U, kBitTorrentHandshakeProtocol.size()));
    return protocol_name == kBitTorrentHandshakeProtocol;
}

bool looks_like_smtp_payload(std::span<const std::uint8_t> payload) noexcept {
    const auto payload_text = payload_as_text(payload);
    return payload_text.starts_with("220 ") || payload_text.starts_with("HELO ") ||
           payload_text.starts_with("EHLO ") || payload_text.starts_with("MAIL FROM:");
}

bool looks_like_pop3_payload(std::span<const std::uint8_t> payload) noexcept {
    const auto payload_text = payload_as_text(payload);
    return payload_text.starts_with("+OK") || payload_text.starts_with("USER") ||
           payload_text.starts_with("PASS");
}

bool looks_like_imap_payload(std::span<const std::uint8_t> payload) noexcept {
    const auto payload_text = payload_as_text(payload);
    if (payload_text.starts_with("* OK")) {
        return true;
    }

    if (payload_text.size() < 5U || payload_text[0] != 'A') {
        return false;
    }

    std::size_t index = 1U;
    while (index < payload_text.size() && payload_text[index] >= '0' && payload_text[index] <= '9') {
        ++index;
    }

    if (index == 1U || index >= payload_text.size() || payload_text[index] != ' ') {
        return false;
    }

    ++index;
    const auto command = payload_text.substr(index);
    return command.starts_with("LOGIN ") || command.starts_with("CAPABILITY") || command == "LOGIN";
}

bool looks_like_dhcp_message(std::span<const std::uint8_t> payload) {
    if (payload.size() < kDhcpMinPayloadSize) {
        return false;
    }

    return read_be32(payload, kDhcpMagicCookieOffset) == kDhcpMagicCookie;
}

std::optional<std::string> extract_http_host(std::span<const std::uint8_t> payload) {
    const auto payload_text = payload_as_text(payload);
    if (!looks_like_http_request(payload_text)) {
        return std::nullopt;
    }

    std::size_t line_start = 0;
    while (line_start < payload_text.size()) {
        auto line_end = payload_text.find("\r\n", line_start);
        std::size_t line_step = 2;
        if (line_end == std::string_view::npos) {
            line_end = payload_text.find('\n', line_start);
            line_step = 1;
        }
        if (line_end == std::string_view::npos) {
            line_end = payload_text.size();
            line_step = 0;
        }

        const auto line = payload_text.substr(line_start, line_end - line_start);
        if (line.empty()) {
            break;
        }

        if (starts_with_ascii_case_insensitive(line, "Host:")) {
            const auto host = trim_ascii(line.substr(5));
            if (is_plausible_service_name(host)) {
                return host;
            }
            return std::nullopt;
        }

        if (line_step == 0) {
            break;
        }

        line_start = line_end + line_step;
    }

    return std::nullopt;
}

std::optional<std::string> extract_http_request_path(std::span<const std::uint8_t> payload) {
    const auto payload_text = payload_as_text(payload);
    if (!looks_like_http_request(payload_text)) {
        return std::nullopt;
    }

    auto line_end = payload_text.find("\r\n");
    if (line_end == std::string_view::npos) {
        line_end = payload_text.find('\n');
    }
    if (line_end == std::string_view::npos) {
        return std::nullopt;
    }

    const auto request_line = payload_text.substr(0, line_end);
    const auto first_space = request_line.find(' ');
    if (first_space == std::string_view::npos) {
        return std::nullopt;
    }

    const auto second_space = request_line.find(' ', first_space + 1U);
    if (second_space == std::string_view::npos || second_space <= first_space + 1U) {
        return std::nullopt;
    }

    const auto path = request_line.substr(first_space + 1U, second_space - first_space - 1U);
    const auto version = request_line.substr(second_space + 1U);
    if (!version.starts_with("HTTP/1.") || path.empty() || path.front() != '/') {
        return std::nullopt;
    }

    return std::string(path);
}

bool looks_like_tls_record(std::span<const std::uint8_t> payload) {
    if (payload.size() < kTlsRecordHeaderSize) {
        return false;
    }

    const auto content_type = payload[0];
    if (content_type < 20U || content_type > 23U) {
        return false;
    }

    if (payload[1] != 0x03U || payload[2] > 0x04U) {
        return false;
    }

    const auto record_length = static_cast<std::size_t>(read_be16(payload, 3U));
    return record_length > 0U && record_length <= (payload.size() - kTlsRecordHeaderSize);
}

std::optional<std::string> extract_tls_sni(std::span<const std::uint8_t> payload) {
    if (!looks_like_tls_record(payload) || payload[0] != 0x16U) {
        return std::nullopt;
    }

    const auto record_length = static_cast<std::size_t>(read_be16(payload, 3U));
    const auto record = payload.subspan(kTlsRecordHeaderSize, record_length);
    if (record.size() < 4U || record[0] != 0x01U) {
        return std::nullopt;
    }

    const auto handshake_length = static_cast<std::size_t>(read_be24(record, 1U));
    if (record.size() < 4U + handshake_length) {
        return std::nullopt;
    }

    auto body = record.subspan(4U, handshake_length);
    std::size_t offset = 0U;
    if (body.size() < 34U) {
        return std::nullopt;
    }

    offset += 2U;
    offset += 32U;

    const auto session_id_length = static_cast<std::size_t>(body[offset]);
    ++offset;
    if (body.size() < offset + session_id_length + 2U) {
        return std::nullopt;
    }
    offset += session_id_length;

    const auto cipher_suites_length = static_cast<std::size_t>(read_be16(body, offset));
    offset += 2U;
    if (cipher_suites_length == 0U || body.size() < offset + cipher_suites_length + 1U) {
        return std::nullopt;
    }
    offset += cipher_suites_length;

    const auto compression_methods_length = static_cast<std::size_t>(body[offset]);
    ++offset;
    if (body.size() < offset + compression_methods_length + 2U) {
        return std::nullopt;
    }
    offset += compression_methods_length;

    const auto extensions_length = static_cast<std::size_t>(read_be16(body, offset));
    offset += 2U;
    if (body.size() < offset + extensions_length) {
        return std::nullopt;
    }

    const auto extensions_end = offset + extensions_length;
    while (offset + 4U <= extensions_end) {
        const auto extension_type = read_be16(body, offset);
        const auto extension_length = static_cast<std::size_t>(read_be16(body, offset + 2U));
        offset += 4U;
        if (offset + extension_length > extensions_end) {
            return std::nullopt;
        }

        if (extension_type == 0x0000U) {
            auto server_name_extension = body.subspan(offset, extension_length);
            if (server_name_extension.size() < 2U) {
                return std::nullopt;
            }

            const auto server_name_list_length = static_cast<std::size_t>(read_be16(server_name_extension, 0U));
            if (server_name_extension.size() < 2U + server_name_list_length) {
                return std::nullopt;
            }

            std::size_t name_offset = 2U;
            while (name_offset + 3U <= 2U + server_name_list_length) {
                const auto name_type = server_name_extension[name_offset];
                const auto name_length = static_cast<std::size_t>(read_be16(server_name_extension, name_offset + 1U));
                name_offset += 3U;
                if (name_offset + name_length > 2U + server_name_list_length) {
                    return std::nullopt;
                }

                if (name_type == 0U) {
                    const auto server_name = payload_as_text(server_name_extension.subspan(name_offset, name_length));
                    if (is_plausible_service_name(server_name)) {
                        return std::string(server_name);
                    }
                    return std::nullopt;
                }

                name_offset += name_length;
            }
        }

        offset += extension_length;
    }

    return std::nullopt;
}

std::optional<std::string> parse_dns_name(std::span<const std::uint8_t> message, std::size_t& offset) {
    std::string name {};
    bool first_label = true;

    for (std::size_t label_count = 0; label_count < 32U; ++label_count) {
        if (offset >= message.size()) {
            return std::nullopt;
        }

        const auto label_length = static_cast<std::size_t>(message[offset]);
        ++offset;

        if (label_length == 0U) {
            return name.empty() ? std::optional<std::string> {std::string(".")} : std::optional<std::string> {name};
        }

        if ((label_length & 0xC0U) != 0U || offset + label_length > message.size()) {
            return std::nullopt;
        }

        if (!first_label) {
            name.push_back('.');
        }
        first_label = false;

        for (std::size_t index = 0U; index < label_length; ++index) {
            const auto character = static_cast<char>(message[offset + index]);
            if (!is_plausible_service_name_char(character)) {
                return std::nullopt;
            }
            name.push_back(character);
        }

        offset += label_length;
    }

    return std::nullopt;
}

std::optional<std::span<const std::uint8_t>> dns_message(std::span<const std::uint8_t> payload, const bool tcp) {
    if (tcp) {
        if (payload.size() < 2U) {
            return std::nullopt;
        }

        const auto message_length = static_cast<std::size_t>(read_be16(payload, 0U));
        if (message_length < kDnsHeaderSize || payload.size() < 2U + message_length) {
            return std::nullopt;
        }

        return payload.subspan(2U, message_length);
    }

    if (payload.size() < kDnsHeaderSize) {
        return std::nullopt;
    }

    return payload;
}

FlowHintUpdate detect_dns_hint(std::span<const std::uint8_t> payload, const bool tcp) {
    const auto message = dns_message(payload, tcp);
    if (!message.has_value()) {
        return {};
    }

    const auto qdcount = read_be16(*message, 4U);
    if (qdcount == 0U) {
        return {};
    }

    FlowHintUpdate hint {
        .protocol_hint = FlowProtocolHint::dns,
    };

    std::size_t offset = kDnsHeaderSize;
    const auto qname = parse_dns_name(*message, offset);
    if (qname.has_value() && *qname != ".") {
        hint.service_hint = *qname;
    }

    return hint;
}
template <typename FlowKey>
FlowHintUpdate detect_mdns_hint(std::span<const std::uint8_t> payload, const FlowKey& flow_key) {
    if (!has_port(flow_key.src_port, flow_key.dst_port, kMdnsPort)) {
        return {};
    }

    if (!is_mdns_multicast_destination(flow_key.dst_addr)) {
        return {};
    }

    if (payload.size() < kDnsHeaderSize) {
        return {};
    }

    const auto question_count = read_be16(payload, 4U);
    const auto answer_count = read_be16(payload, 6U);
    const auto authority_count = read_be16(payload, 8U);
    const auto additional_count = read_be16(payload, 10U);
    if (question_count == 0U && answer_count == 0U && authority_count == 0U && additional_count == 0U) {
        return {};
    }

    return FlowHintUpdate {
        .protocol_hint = FlowProtocolHint::mdns,
    };
}

FlowHintUpdate detect_http_hint(std::span<const std::uint8_t> payload, const AnalysisSettings& settings) {
    const auto payload_text = payload_as_text(payload);
    if (!looks_like_http_request(payload_text) && !looks_like_http_response(payload_text)) {
        return {};
    }

    FlowHintUpdate hint {
        .protocol_hint = FlowProtocolHint::http,
    };

    const auto host = extract_http_host(payload);
    if (host.has_value()) {
        hint.service_hint = *host;
        return hint;
    }

    if (settings.http_use_path_as_service_hint) {
        const auto path = extract_http_request_path(payload);
        if (path.has_value()) {
            hint.service_hint = *path;
        }
    }

    return hint;
}

FlowHintUpdate detect_ssh_hint(std::span<const std::uint8_t> payload) {
    if (!looks_like_ssh_banner(payload)) {
        return {};
    }

    return FlowHintUpdate {
        .protocol_hint = FlowProtocolHint::ssh,
    };
}

FlowHintUpdate detect_stun_hint(std::span<const std::uint8_t> payload) {
    if (!looks_like_stun_message(payload)) {
        return {};
    }

    return FlowHintUpdate {
        .protocol_hint = FlowProtocolHint::stun,
    };
}
FlowHintUpdate detect_dhcp_hint(std::span<const std::uint8_t> payload,
                                const std::uint16_t src_port,
                                const std::uint16_t dst_port) {
    if (!has_port_pair(src_port, dst_port, kDhcpClientPort, kDhcpServerPort)) {
        return {};
    }

    if (!looks_like_dhcp_message(payload)) {
        return {};
    }

    return FlowHintUpdate {
        .protocol_hint = FlowProtocolHint::dhcp,
    };
}

FlowHintUpdate detect_bittorrent_hint(std::span<const std::uint8_t> payload) {
    if (!looks_like_bittorrent_handshake(payload)) {
        return {};
    }

    return FlowHintUpdate {
        .protocol_hint = FlowProtocolHint::bittorrent,
    };
}

FlowHintUpdate detect_smtp_hint(std::span<const std::uint8_t> payload,
                                const std::uint16_t src_port,
                                const std::uint16_t dst_port) {
    if (!has_port(src_port, dst_port, kSmtpPort) && !has_port(src_port, dst_port, kSubmissionPort)) {
        return {};
    }

    if (!looks_like_smtp_payload(payload)) {
        return {};
    }

    return FlowHintUpdate {
        .protocol_hint = FlowProtocolHint::smtp,
    };
}

FlowHintUpdate detect_pop3_hint(std::span<const std::uint8_t> payload,
                                const std::uint16_t src_port,
                                const std::uint16_t dst_port) {
    if (!has_port(src_port, dst_port, kPop3Port)) {
        return {};
    }

    if (!looks_like_pop3_payload(payload)) {
        return {};
    }

    return FlowHintUpdate {
        .protocol_hint = FlowProtocolHint::pop3,
    };
}

FlowHintUpdate detect_imap_hint(std::span<const std::uint8_t> payload,
                                const std::uint16_t src_port,
                                const std::uint16_t dst_port) {
    if (!has_port(src_port, dst_port, kImapPort)) {
        return {};
    }

    if (!looks_like_imap_payload(payload)) {
        return {};
    }

    return FlowHintUpdate {
        .protocol_hint = FlowProtocolHint::imap,
    };
}

FlowHintUpdate detect_tls_hint(std::span<const std::uint8_t> payload) {
    if (!looks_like_tls_record(payload)) {
        return {};
    }

    FlowHintUpdate hint {
        .protocol_hint = FlowProtocolHint::tls,
        .tls_version = classify_tls_version(read_be16(payload, 1U)),
    };

    const auto sni = extract_tls_sni(payload);
    if (sni.has_value()) {
        hint.service_hint = *sni;
    }

    return hint;
}

template <typename FlowKey, typename QuicStateMap>
FlowHintUpdate detect_quic_hint(std::span<const std::uint8_t> payload,
                                const FlowKey& flow_key,
                                QuicStateMap& quic_state,
                                const std::uint16_t src_port,
                                const std::uint16_t dst_port,
                                const bool enable_quic_initial_sni) {
    if (payload.size() < 7U) {
        return {};
    }

    const auto first_byte = payload[0];
    if ((first_byte & 0x80U) == 0U || (first_byte & 0x40U) == 0U) {
        return {};
    }

    const auto quic_version = read_be32(payload, 1U);
    if (quic_version == 0U) {
        return {};
    }

    const auto destination_connection_id_length = static_cast<std::size_t>(payload[5U]);
    if (payload.size() < 6U + destination_connection_id_length + 1U) {
        return {};
    }

    const auto source_connection_id_length_offset = 6U + destination_connection_id_length;
    const auto source_connection_id_length = static_cast<std::size_t>(payload[source_connection_id_length_offset]);
    if (payload.size() < source_connection_id_length_offset + 1U + source_connection_id_length) {
        return {};
    }

    FlowHintUpdate hint {
        .protocol_hint = FlowProtocolHint::quic,
        .quic_version = classify_quic_version(quic_version),
    };

    if (!enable_quic_initial_sni || src_port == kHttpsPort || dst_port != kHttpsPort) {
        return hint;
    }

    auto& state = quic_state[flow_key];
    if (state.exhausted) {
        return hint;
    }

    QuicInitialParser parser {};
    if (!parser.is_client_initial_packet(payload)) {
        return hint;
    }

    if (state.initial_payloads.size() >= QuicInitialParser::kMaxInitialPackets) {
        state.exhausted = true;
        state.initial_payloads.clear();
        return hint;
    }

    state.initial_payloads.emplace_back(payload.begin(), payload.end());
    const auto sni = parser.extract_client_initial_sni(
        std::span<const std::vector<std::uint8_t>>(state.initial_payloads.data(), state.initial_payloads.size())
    );
    if (sni.has_value()) {
        hint.service_hint = *sni;
        state.exhausted = true;
        state.initial_payloads.clear();
        return hint;
    }

    if (state.initial_payloads.size() >= QuicInitialParser::kMaxInitialPackets) {
        state.exhausted = true;
        state.initial_payloads.clear();
    }

    return hint;
}

template <typename FlowKey, typename QuicStateMap>
FlowHintUpdate detect_transport_hints(std::span<const std::uint8_t> packet_bytes,
                                      const std::uint32_t data_link_type,
                                      const FlowKey& flow_key,
                                      const FlowHintDetectionSettings& settings,
                                      QuicStateMap& quic_state) {
    PacketPayloadService payload_service {};
    const auto payload = payload_service.extract_transport_payload(packet_bytes, data_link_type);
    if (payload.empty()) {
        return {};
    }

    const auto payload_view = std::span<const std::uint8_t>(payload.data(), payload.size());

    switch (flow_key.protocol) {
    case ProtocolId::tcp:
        if (has_port(flow_key.src_port, flow_key.dst_port, kDnsPort)) {
            const auto dns_hint = detect_dns_hint(payload_view, true);
            if (dns_hint.protocol_hint != FlowProtocolHint::unknown) {
                return dns_hint;
            }
        }

        {
            const auto tls_hint = detect_tls_hint(payload_view);
            if (tls_hint.protocol_hint != FlowProtocolHint::unknown) {
                return tls_hint;
            }
        }

        {
            const auto http_hint = detect_http_hint(payload_view, settings.analysis_settings);
            if (http_hint.protocol_hint != FlowProtocolHint::unknown) {
                return http_hint;
            }
        }

        {
            const auto ssh_hint = detect_ssh_hint(payload_view);
            if (ssh_hint.protocol_hint != FlowProtocolHint::unknown) {
                return ssh_hint;
            }
        }

        {
            const auto smtp_hint = detect_smtp_hint(payload_view, flow_key.src_port, flow_key.dst_port);
            if (smtp_hint.protocol_hint != FlowProtocolHint::unknown) {
                return smtp_hint;
            }
        }

        {
            const auto pop3_hint = detect_pop3_hint(payload_view, flow_key.src_port, flow_key.dst_port);
            if (pop3_hint.protocol_hint != FlowProtocolHint::unknown) {
                return pop3_hint;
            }
        }

        {
            const auto imap_hint = detect_imap_hint(payload_view, flow_key.src_port, flow_key.dst_port);
            if (imap_hint.protocol_hint != FlowProtocolHint::unknown) {
                return imap_hint;
            }
        }

        return detect_bittorrent_hint(payload_view);
    case ProtocolId::udp:
        {
            const auto mdns_hint = detect_mdns_hint(payload_view, flow_key);
            if (mdns_hint.protocol_hint != FlowProtocolHint::unknown) {
                return mdns_hint;
            }
        }

        if (has_port(flow_key.src_port, flow_key.dst_port, kDnsPort)) {
            const auto dns_hint = detect_dns_hint(payload_view, false);
            if (dns_hint.protocol_hint != FlowProtocolHint::unknown) {
                return dns_hint;
            }
        }

        if (has_port(flow_key.src_port, flow_key.dst_port, kHttpsPort)) {
            const auto quic_hint = detect_quic_hint(
                payload_view,
                flow_key,
                quic_state,
                flow_key.src_port,
                flow_key.dst_port,
                settings.enable_quic_initial_sni
            );
            if (quic_hint.protocol_hint != FlowProtocolHint::unknown) {
                return quic_hint;
            }
        }

        {
            const auto dhcp_hint = detect_dhcp_hint(payload_view, flow_key.src_port, flow_key.dst_port);
            if (dhcp_hint.protocol_hint != FlowProtocolHint::unknown) {
                return dhcp_hint;
            }
        }

        return detect_stun_hint(payload_view);
    default:
        return {};
    }
}
}  // namespace

FlowHintService::FlowHintService(const AnalysisSettings settings, const bool enable_quic_initial_sni)
    : settings_(settings)
    , enable_quic_initial_sni_(enable_quic_initial_sni) {
}

FlowHintUpdate FlowHintService::detect(std::span<const std::uint8_t> packet_bytes, const FlowKeyV4& flow_key) const {
    return detect(packet_bytes, kLinkTypeEthernet, flow_key);
}

FlowHintUpdate FlowHintService::detect(std::span<const std::uint8_t> packet_bytes,
                                       const std::uint32_t data_link_type,
                                       const FlowKeyV4& flow_key) const {
    return detect_transport_hints(packet_bytes, data_link_type, flow_key, FlowHintDetectionSettings {
        .analysis_settings = settings_,
        .enable_quic_initial_sni = enable_quic_initial_sni_,
    }, quic_initial_ipv4_states_);
}

FlowHintUpdate FlowHintService::detect(std::span<const std::uint8_t> packet_bytes, const FlowKeyV6& flow_key) const {
    return detect(packet_bytes, kLinkTypeEthernet, flow_key);
}

FlowHintUpdate FlowHintService::detect(std::span<const std::uint8_t> packet_bytes,
                                       const std::uint32_t data_link_type,
                                       const FlowKeyV6& flow_key) const {
    return detect_transport_hints(packet_bytes, data_link_type, flow_key, FlowHintDetectionSettings {
        .analysis_settings = settings_,
        .enable_quic_initial_sni = enable_quic_initial_sni_,
    }, quic_initial_ipv6_states_);
}

}  // namespace pfl


