#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "TestSupport.h"
#include "PcapTestUtils.h"
#include "app/session/CaptureSession.h"
#include "app/session/SelectedFlowPacketSemantics.h"
#include "app/session/SessionFormatting.h"
#include "core/services/PacketDetailsService.h"
#include "core/services/PacketPayloadService.h"
#include "core/services/QuicPacketProtocolAnalyzer.h"

namespace pfl::tests {

namespace {

void append_be16(std::vector<std::uint8_t>& bytes, const std::uint16_t value) {
    bytes.push_back(static_cast<std::uint8_t>((value >> 8U) & 0xFFU));
    bytes.push_back(static_cast<std::uint8_t>(value & 0xFFU));
}

void append_be24(std::vector<std::uint8_t>& bytes, const std::uint32_t value) {
    bytes.push_back(static_cast<std::uint8_t>((value >> 16U) & 0xFFU));
    bytes.push_back(static_cast<std::uint8_t>((value >> 8U) & 0xFFU));
    bytes.push_back(static_cast<std::uint8_t>(value & 0xFFU));
}

constexpr std::string_view kNoProtocolDetailsMessage = "No protocol-specific details available for this packet.";
constexpr std::string_view kUnavailableProtocolDetailsMessage = "Protocol details unavailable for this packet.";

std::filesystem::path fixture_path(const std::filesystem::path& relative_path) {
    return std::filesystem::path(__FILE__).parent_path().parent_path() / "data" / relative_path;
}

PacketRef require_packet(CaptureSession& session, const std::uint64_t packet_index) {
    const auto packet = session.find_packet(packet_index);
    PFL_EXPECT(packet.has_value());
    return *packet;
}

std::uint32_t require_captured_transport_payload_length(CaptureSession& session, const PacketRef& packet) {
    const auto payload_length = session_detail::derive_captured_transport_payload_length_from_headers(session, packet);
    PFL_REQUIRE(payload_length.has_value());
    return *payload_length;
}

std::string_view trim_ascii(std::string_view text) {
    while (!text.empty() && (text.front() == ' ' || text.front() == '\t' || text.front() == '\r')) {
        text.remove_prefix(1U);
    }
    while (!text.empty() && (text.back() == ' ' || text.back() == '\t' || text.back() == '\r')) {
        text.remove_suffix(1U);
    }
    return text;
}

std::optional<std::string_view> find_protocol_detail_value(
    const std::string_view protocol_text,
    const std::string_view label_with_colon
) {
    std::size_t line_start = 0U;
    while (line_start <= protocol_text.size()) {
        const auto line_end = protocol_text.find('\n', line_start);
        const auto raw_line = protocol_text.substr(
            line_start,
            line_end == std::string_view::npos ? protocol_text.size() - line_start : line_end - line_start
        );
        const auto line = trim_ascii(raw_line);
        if (line.starts_with(label_with_colon)) {
            return trim_ascii(line.substr(label_with_colon.size()));
        }
        if (line_end == std::string_view::npos) {
            break;
        }
        line_start = line_end + 1U;
    }
    return std::nullopt;
}

std::size_t count_hex_byte_tokens(const std::string_view value) {
    std::size_t count = 0U;
    std::size_t offset = 0U;
    while (offset < value.size()) {
        while (offset < value.size() && value[offset] == ' ') {
            ++offset;
        }
        if (offset >= value.size()) {
            break;
        }
        const auto next_space = value.find(' ', offset);
        ++count;
        if (next_space == std::string_view::npos) {
            break;
        }
        offset = next_space + 1U;
    }
    return count;
}

std::optional<std::size_t> parse_total_count_suffix(const std::string_view value) {
    const auto total_pos = value.rfind(" total)");
    if (total_pos == std::string_view::npos) {
        return std::nullopt;
    }
    const auto open_pos = value.rfind('(', total_pos);
    if (open_pos == std::string_view::npos || open_pos + 1U >= total_pos) {
        return std::nullopt;
    }

    std::size_t parsed = 0U;
    for (std::size_t index = open_pos + 1U; index < total_pos; ++index) {
        const auto character = value[index];
        if (character < '0' || character > '9') {
            return std::nullopt;
        }
        parsed = (parsed * 10U) + static_cast<std::size_t>(character - '0');
    }
    return parsed;
}

std::uint16_t read_be16_at(std::span<const std::uint8_t> bytes, const std::size_t offset) {
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(bytes[offset]) << 8U) |
                                      static_cast<std::uint16_t>(bytes[offset + 1U]));
}

std::uint32_t read_be24_at(std::span<const std::uint8_t> bytes, const std::size_t offset) {
    return (static_cast<std::uint32_t>(bytes[offset]) << 16U) |
           (static_cast<std::uint32_t>(bytes[offset + 1U]) << 8U) |
           static_cast<std::uint32_t>(bytes[offset + 2U]);
}

struct ParsedTlsRecord {
    std::uint8_t content_type {0U};
    std::uint16_t legacy_version {0U};
    std::size_t record_length {0U};
    std::size_t total_bytes {0U};
    std::span<const std::uint8_t> body {};
};

struct ParsedTlsPayload {
    std::vector<ParsedTlsRecord> records {};
    std::size_t trailing_bytes {0U};
};

ParsedTlsPayload parse_tls_payload(std::span<const std::uint8_t> payload) {
    ParsedTlsPayload parsed {};
    std::size_t offset = 0U;
    while (offset + 5U <= payload.size()) {
        const auto record_length = static_cast<std::size_t>(read_be16_at(payload, offset + 3U));
        const auto total_bytes = 5U + record_length;
        if (offset + total_bytes > payload.size()) {
            break;
        }

        parsed.records.push_back(ParsedTlsRecord {
            .content_type = payload[offset],
            .legacy_version = read_be16_at(payload, offset + 1U),
            .record_length = record_length,
            .total_bytes = total_bytes,
            .body = payload.subspan(offset + 5U, record_length),
        });
        offset += total_bytes;
    }
    parsed.trailing_bytes = payload.size() - offset;
    return parsed;
}

struct ParsedTlsClientHelloFacts {
    std::uint8_t handshake_type {0U};
    std::size_t handshake_length {0U};
    std::uint16_t handshake_legacy_version {0U};
    std::size_t session_id_length {0U};
    std::size_t cipher_suite_count {0U};
    std::size_t compression_method_count {0U};
    std::size_t extension_count {0U};
    std::optional<std::string> sni {};
    std::vector<std::string> alpn_protocols {};
    std::vector<std::uint16_t> supported_versions {};
};

std::optional<ParsedTlsClientHelloFacts> parse_tls_client_hello_facts(std::span<const std::uint8_t> record_body) {
    if (record_body.size() < 4U + 34U) {
        return std::nullopt;
    }

    ParsedTlsClientHelloFacts facts {};
    facts.handshake_type = record_body[0];
    facts.handshake_length = read_be24_at(record_body, 1U);
    if (record_body.size() < 4U + facts.handshake_length) {
        return std::nullopt;
    }

    const auto handshake_body = record_body.subspan(4U, facts.handshake_length);
    facts.handshake_legacy_version = read_be16_at(handshake_body, 0U);

    std::size_t offset = 2U + 32U;
    facts.session_id_length = static_cast<std::size_t>(handshake_body[offset]);
    ++offset;
    if (offset + facts.session_id_length + 2U > handshake_body.size()) {
        return std::nullopt;
    }
    offset += facts.session_id_length;

    const auto cipher_suites_length = static_cast<std::size_t>(read_be16_at(handshake_body, offset));
    offset += 2U;
    if ((cipher_suites_length % 2U) != 0U || offset + cipher_suites_length + 1U > handshake_body.size()) {
        return std::nullopt;
    }
    facts.cipher_suite_count = cipher_suites_length / 2U;
    offset += cipher_suites_length;

    facts.compression_method_count = static_cast<std::size_t>(handshake_body[offset]);
    ++offset;
    if (offset + facts.compression_method_count > handshake_body.size()) {
        return std::nullopt;
    }
    offset += facts.compression_method_count;

    if (offset == handshake_body.size()) {
        return facts;
    }
    if (offset + 2U > handshake_body.size()) {
        return std::nullopt;
    }

    const auto extensions_length = static_cast<std::size_t>(read_be16_at(handshake_body, offset));
    offset += 2U;
    if (offset + extensions_length > handshake_body.size()) {
        return std::nullopt;
    }

    const auto extensions_end = offset + extensions_length;
    while (offset + 4U <= extensions_end) {
        const auto extension_type = read_be16_at(handshake_body, offset);
        const auto extension_length = static_cast<std::size_t>(read_be16_at(handshake_body, offset + 2U));
        offset += 4U;
        if (offset + extension_length > extensions_end) {
            return std::nullopt;
        }

        ++facts.extension_count;
        const auto extension_bytes = handshake_body.subspan(offset, extension_length);

        if (extension_type == 0x0000U && extension_bytes.size() >= 2U) {
            const auto server_name_list_length = static_cast<std::size_t>(read_be16_at(extension_bytes, 0U));
            if (extension_bytes.size() >= 2U + server_name_list_length) {
                std::size_t name_offset = 2U;
                while (name_offset + 3U <= 2U + server_name_list_length) {
                    const auto name_type = extension_bytes[name_offset];
                    const auto name_length = static_cast<std::size_t>(read_be16_at(extension_bytes, name_offset + 1U));
                    name_offset += 3U;
                    if (name_offset + name_length > 2U + server_name_list_length) {
                        break;
                    }
                    if (name_type == 0U) {
                        facts.sni = std::string(
                            reinterpret_cast<const char*>(extension_bytes.data() + static_cast<std::ptrdiff_t>(name_offset)),
                            name_length
                        );
                        break;
                    }
                    name_offset += name_length;
                }
            }
        } else if (extension_type == 0x0010U && extension_bytes.size() >= 2U) {
            const auto alpn_length = static_cast<std::size_t>(read_be16_at(extension_bytes, 0U));
            if (extension_bytes.size() >= 2U + alpn_length) {
                std::size_t protocol_offset = 2U;
                while (protocol_offset < 2U + alpn_length) {
                    const auto protocol_length = static_cast<std::size_t>(extension_bytes[protocol_offset]);
                    ++protocol_offset;
                    if (protocol_offset + protocol_length > 2U + alpn_length) {
                        break;
                    }
                    facts.alpn_protocols.emplace_back(
                        reinterpret_cast<const char*>(extension_bytes.data() + static_cast<std::ptrdiff_t>(protocol_offset)),
                        protocol_length
                    );
                    protocol_offset += protocol_length;
                }
            }
        } else if (extension_type == 0x002BU && !extension_bytes.empty()) {
            const auto versions_length = static_cast<std::size_t>(extension_bytes[0]);
            if (extension_bytes.size() >= 1U + versions_length) {
                for (std::size_t cursor = 1U; cursor + 1U < 1U + versions_length; cursor += 2U) {
                    facts.supported_versions.push_back(read_be16_at(extension_bytes, cursor));
                }
            }
        }

        offset += extension_length;
    }

    return facts;
}

struct ParsedTlsServerHelloFacts {
    std::uint8_t handshake_type {0U};
    std::size_t handshake_length {0U};
    std::uint16_t handshake_legacy_version {0U};
    std::size_t session_id_length {0U};
    std::uint16_t cipher_suite {0U};
    std::uint8_t compression_method {0U};
    std::size_t extension_count {0U};
    std::vector<std::uint16_t> extension_types {};
    std::uint16_t selected_tls_version {0U};
};

std::optional<ParsedTlsServerHelloFacts> parse_tls_server_hello_facts(std::span<const std::uint8_t> record_body) {
    if (record_body.size() < 4U + 38U) {
        return std::nullopt;
    }

    ParsedTlsServerHelloFacts facts {};
    facts.handshake_type = record_body[0];
    facts.handshake_length = read_be24_at(record_body, 1U);
    if (record_body.size() < 4U + facts.handshake_length) {
        return std::nullopt;
    }

    const auto handshake_body = record_body.subspan(4U, facts.handshake_length);
    facts.handshake_legacy_version = read_be16_at(handshake_body, 0U);
    facts.selected_tls_version = facts.handshake_legacy_version;

    std::size_t offset = 2U + 32U;
    facts.session_id_length = static_cast<std::size_t>(handshake_body[offset]);
    ++offset;
    if (offset + facts.session_id_length + 3U > handshake_body.size()) {
        return std::nullopt;
    }
    offset += facts.session_id_length;

    facts.cipher_suite = read_be16_at(handshake_body, offset);
    offset += 2U;
    facts.compression_method = handshake_body[offset];
    ++offset;

    if (offset + 2U > handshake_body.size()) {
        return facts;
    }

    const auto extensions_length = static_cast<std::size_t>(read_be16_at(handshake_body, offset));
    offset += 2U;
    if (offset + extensions_length > handshake_body.size()) {
        return std::nullopt;
    }

    const auto extensions_end = offset + extensions_length;
    while (offset + 4U <= extensions_end) {
        const auto extension_type = read_be16_at(handshake_body, offset);
        const auto extension_length = static_cast<std::size_t>(read_be16_at(handshake_body, offset + 2U));
        offset += 4U;
        if (offset + extension_length > extensions_end) {
            return std::nullopt;
        }
        ++facts.extension_count;
        facts.extension_types.push_back(extension_type);
        if (extension_type == 0x002BU && extension_length >= 2U) {
            facts.selected_tls_version = read_be16_at(handshake_body, offset);
        }
        offset += extension_length;
    }

    return facts;
}

std::vector<std::uint8_t> make_tls_client_hello_payload() {
    const std::vector<std::uint8_t> server_name {'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'o', 'r', 'g'};

    std::vector<std::uint8_t> extension_data {};
    append_be16(extension_data, static_cast<std::uint16_t>(server_name.size() + 3U));
    extension_data.push_back(0x00U);
    append_be16(extension_data, static_cast<std::uint16_t>(server_name.size()));
    extension_data.insert(extension_data.end(), server_name.begin(), server_name.end());

    std::vector<std::uint8_t> extensions {};
    append_be16(extensions, 0x0000U);
    append_be16(extensions, static_cast<std::uint16_t>(extension_data.size()));
    extensions.insert(extensions.end(), extension_data.begin(), extension_data.end());

    std::vector<std::uint8_t> body {};
    body.push_back(0x03U);
    body.push_back(0x03U);
    for (std::uint8_t index = 0U; index < 32U; ++index) {
        body.push_back(index);
    }
    body.push_back(0x00U);
    append_be16(body, 0x0002U);
    append_be16(body, 0x1301U);
    body.push_back(0x01U);
    body.push_back(0x00U);
    append_be16(body, static_cast<std::uint16_t>(extensions.size()));
    body.insert(body.end(), extensions.begin(), extensions.end());

    std::vector<std::uint8_t> payload {};
    payload.push_back(0x16U);
    payload.push_back(0x03U);
    payload.push_back(0x03U);
    append_be16(payload, static_cast<std::uint16_t>(body.size() + 4U));
    payload.push_back(0x01U);
    payload.push_back(static_cast<std::uint8_t>((body.size() >> 16U) & 0xFFU));
    payload.push_back(static_cast<std::uint8_t>((body.size() >> 8U) & 0xFFU));
    payload.push_back(static_cast<std::uint8_t>(body.size() & 0xFFU));
    payload.insert(payload.end(), body.begin(), body.end());
    return payload;
}

std::vector<std::uint8_t> make_tls_alert_payload(
    const std::uint8_t level = 0x01U,
    const std::uint8_t description = 0x00U,
    const std::uint16_t version = 0x0303U
) {
    std::vector<std::uint8_t> payload {};
    payload.push_back(0x15U);
    append_be16(payload, version);
    append_be16(payload, 2U);
    payload.push_back(level);
    payload.push_back(description);
    return payload;
}

std::vector<std::uint8_t> make_tls_client_hello_handshake_bytes() {
    const std::vector<std::uint8_t> server_name {'s', 't', 'a', 'g', 'e', '1', '.', 'e', 'x', 'a', 'm', 'p', 'l', 'e'};

    std::vector<std::uint8_t> sni_extension_data {};
    append_be16(sni_extension_data, static_cast<std::uint16_t>(server_name.size() + 3U));
    sni_extension_data.push_back(0x00U);
    append_be16(sni_extension_data, static_cast<std::uint16_t>(server_name.size()));
    sni_extension_data.insert(sni_extension_data.end(), server_name.begin(), server_name.end());

    std::vector<std::uint8_t> supported_versions_extension_data {0x02U, 0x03U, 0x04U};

    std::vector<std::uint8_t> extensions {};
    append_be16(extensions, 0x0000U);
    append_be16(extensions, static_cast<std::uint16_t>(sni_extension_data.size()));
    extensions.insert(extensions.end(), sni_extension_data.begin(), sni_extension_data.end());
    append_be16(extensions, 0x002BU);
    append_be16(extensions, static_cast<std::uint16_t>(supported_versions_extension_data.size()));
    extensions.insert(extensions.end(), supported_versions_extension_data.begin(), supported_versions_extension_data.end());

    std::vector<std::uint8_t> body {};
    body.push_back(0x03U);
    body.push_back(0x03U);
    for (std::uint8_t index = 0U; index < 32U; ++index) {
        body.push_back(static_cast<std::uint8_t>(0x10U + index));
    }
    body.push_back(0x00U);
    append_be16(body, 0x0002U);
    append_be16(body, 0x1301U);
    body.push_back(0x01U);
    body.push_back(0x00U);
    append_be16(body, static_cast<std::uint16_t>(extensions.size()));
    body.insert(body.end(), extensions.begin(), extensions.end());

    std::vector<std::uint8_t> handshake {0x01U};
    append_be24(handshake, static_cast<std::uint32_t>(body.size()));
    handshake.insert(handshake.end(), body.begin(), body.end());
    return handshake;
}

void append_quic_varint(std::vector<std::uint8_t>& bytes, const std::uint64_t value) {
    if (value < 64U) {
        bytes.push_back(static_cast<std::uint8_t>(value));
        return;
    }

    PFL_EXPECT(value < 16384U);
    bytes.push_back(static_cast<std::uint8_t>(0x40U | ((value >> 8U) & 0x3FU)));
    bytes.push_back(static_cast<std::uint8_t>(value & 0xFFU));
}

std::vector<std::uint8_t> make_plaintext_quic_initial_payload(const std::vector<std::uint8_t>& frame_bytes) {
    std::vector<std::uint8_t> payload {
        0xC0U,
        0x00U, 0x00U, 0x00U, 0x01U,
        0x08U,
        0x11U, 0x22U, 0x33U, 0x44U, 0x55U, 0x66U, 0x77U, 0x88U,
        0x08U,
        0x99U, 0xAAU, 0xBBU, 0xCCU, 0xDDU, 0xEEU, 0xFFU, 0x00U,
        0x00U,
    };

    append_quic_varint(payload, frame_bytes.size() + 1U);
    payload.push_back(0x00U);
    payload.insert(payload.end(), frame_bytes.begin(), frame_bytes.end());
    return payload;
}

std::vector<std::uint8_t> make_plaintext_quic_long_header_payload(
    const std::uint8_t first_byte,
    const std::vector<std::uint8_t>& frame_bytes
) {
    std::vector<std::uint8_t> payload {
        first_byte,
        0x00U, 0x00U, 0x00U, 0x01U,
        0x08U,
        0x11U, 0x22U, 0x33U, 0x44U, 0x55U, 0x66U, 0x77U, 0x88U,
        0x08U,
        0x99U, 0xAAU, 0xBBU, 0xCCU, 0xDDU, 0xEEU, 0xFFU, 0x00U,
    };

    if (((first_byte >> 4U) & 0x03U) == 0U) {
        payload.push_back(0x00U);
    }
    append_quic_varint(payload, frame_bytes.size() + 1U);
    payload.push_back(0x00U);
    payload.insert(payload.end(), frame_bytes.begin(), frame_bytes.end());
    return payload;
}

std::vector<std::uint8_t> make_plaintext_quic_zero_rtt_payload(const std::vector<std::uint8_t>& frame_bytes) {
    return make_plaintext_quic_long_header_payload(0xD0U, frame_bytes);
}

std::vector<std::uint8_t> concat_bytes(
    const std::vector<std::uint8_t>& first,
    const std::vector<std::uint8_t>& second
) {
    std::vector<std::uint8_t> combined {};
    combined.reserve(first.size() + second.size());
    combined.insert(combined.end(), first.begin(), first.end());
    combined.insert(combined.end(), second.begin(), second.end());
    return combined;
}

std::vector<std::uint8_t> make_quic_crypto_frame_bytes(
    const std::uint64_t crypto_offset,
    const std::vector<std::uint8_t>& crypto_bytes
) {
    std::vector<std::uint8_t> frame {0x06U};
    append_quic_varint(frame, crypto_offset);
    append_quic_varint(frame, crypto_bytes.size());
    frame.insert(frame.end(), crypto_bytes.begin(), crypto_bytes.end());
    return frame;
}

std::vector<std::uint8_t> make_quic_crypto_frame_bytes(const std::vector<std::uint8_t>& crypto_bytes) {
    return make_quic_crypto_frame_bytes(0U, crypto_bytes);
}

std::vector<std::uint8_t> make_quic_ack_frame_bytes() {
    return {0x02U, 0x00U, 0x00U, 0x00U, 0x00U};
}

std::vector<std::uint8_t> make_tls_server_hello_handshake_bytes() {
    std::vector<std::uint8_t> body {};
    append_be16(body, 0x0303U);
    for (std::uint8_t index = 0U; index < 32U; ++index) {
        body.push_back(static_cast<std::uint8_t>(0xA0U + index));
    }
    body.push_back(0x00U);
    append_be16(body, 0x1301U);
    body.push_back(0x00U);

    std::vector<std::uint8_t> extensions {};
    append_be16(extensions, 0x002BU);
    append_be16(extensions, 0x0002U);
    extensions.push_back(0x03U);
    extensions.push_back(0x04U);

    append_be16(body, static_cast<std::uint16_t>(extensions.size()));
    body.insert(body.end(), extensions.begin(), extensions.end());

    std::vector<std::uint8_t> handshake {0x02U};
    append_be24(handshake, static_cast<std::uint32_t>(body.size()));
    handshake.insert(handshake.end(), body.begin(), body.end());
    return handshake;
}

std::vector<std::uint8_t> make_quic_truncated_payload() {
    return {
        0xC0U,
        0x00U, 0x00U, 0x00U, 0x01U,
        0x08U,
        0x11U, 0x22U, 0x33U, 0x44U,
    };
}

}  // namespace

void run_packet_protocol_details_tests() {
    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/tls/tls_client_hello_1.pcap"), CaptureImportOptions {}));
        const auto packet = require_packet(session, 0);
        PFL_EXPECT(require_captured_transport_payload_length(session, packet) == 517U);
        const auto packet_bytes = session.read_packet_data(packet);
        PacketPayloadService payload_service {};
        const auto payload = payload_service.extract_transport_payload(packet_bytes, packet.data_link_type);
        PFL_EXPECT(payload.size() == 517U);
        const auto parsed_payload = parse_tls_payload(payload);
        PFL_EXPECT(parsed_payload.records.size() == 1U);
        PFL_EXPECT(parsed_payload.trailing_bytes == 0U);
        PFL_EXPECT(parsed_payload.records[0].content_type == 22U);
        PFL_EXPECT(parsed_payload.records[0].legacy_version == 0x0301U);
        PFL_EXPECT(parsed_payload.records[0].record_length == 512U);
        PFL_EXPECT(parsed_payload.records[0].total_bytes == 517U);
        const auto parsed_client_hello = parse_tls_client_hello_facts(parsed_payload.records[0].body);
        PFL_REQUIRE(parsed_client_hello.has_value());
        PFL_EXPECT(parsed_client_hello->handshake_type == 1U);
        PFL_EXPECT(parsed_client_hello->handshake_length == 508U);
        PFL_EXPECT(parsed_client_hello->handshake_legacy_version == 0x0303U);
        PFL_EXPECT(parsed_client_hello->session_id_length == 32U);
        PFL_EXPECT(parsed_client_hello->cipher_suite_count == 16U);
        PFL_EXPECT(parsed_client_hello->compression_method_count == 1U);
        PFL_EXPECT(parsed_client_hello->extension_count == 18U);
        PFL_REQUIRE(parsed_client_hello->sni.has_value());
        PFL_EXPECT(*parsed_client_hello->sni == "auth.split.io");
        PFL_EXPECT(std::find(parsed_client_hello->alpn_protocols.begin(), parsed_client_hello->alpn_protocols.end(), "h2") != parsed_client_hello->alpn_protocols.end());
        PFL_EXPECT(std::find(parsed_client_hello->alpn_protocols.begin(), parsed_client_hello->alpn_protocols.end(), "http/1.1") != parsed_client_hello->alpn_protocols.end());
        PFL_EXPECT(std::find(parsed_client_hello->supported_versions.begin(), parsed_client_hello->supported_versions.end(), 0x0304U) != parsed_client_hello->supported_versions.end());
        PFL_EXPECT(std::find(parsed_client_hello->supported_versions.begin(), parsed_client_hello->supported_versions.end(), 0x0303U) != parsed_client_hello->supported_versions.end());
        const auto text = session.read_packet_protocol_details_text(packet);
        PFL_EXPECT(text.find("TLS") != std::string::npos);
        const auto record_type = find_protocol_detail_value(text, "Record Type:");
        const auto record_version = find_protocol_detail_value(text, "Record Version:");
        const auto record_length = find_protocol_detail_value(text, "Record Length:");
        const auto handshake_type = find_protocol_detail_value(text, "Handshake Type:");
        const auto handshake_length = find_protocol_detail_value(text, "Handshake Length:");
        const auto handshake_version = find_protocol_detail_value(text, "Handshake Version:");
        const auto session_id = find_protocol_detail_value(text, "Session ID:");
        const auto cipher_suites = find_protocol_detail_value(text, "Cipher Suites:");
        const auto extensions = find_protocol_detail_value(text, "Extensions:");
        const auto sni = find_protocol_detail_value(text, "SNI:");
        const auto alpn = find_protocol_detail_value(text, "ALPN:");
        const auto supported_versions = find_protocol_detail_value(text, "Supported Versions:");
        PFL_REQUIRE(record_type.has_value());
        PFL_REQUIRE(record_version.has_value());
        PFL_REQUIRE(record_length.has_value());
        PFL_REQUIRE(handshake_type.has_value());
        PFL_REQUIRE(handshake_length.has_value());
        PFL_REQUIRE(handshake_version.has_value());
        PFL_REQUIRE(session_id.has_value());
        PFL_REQUIRE(cipher_suites.has_value());
        PFL_REQUIRE(extensions.has_value());
        PFL_REQUIRE(sni.has_value());
        PFL_REQUIRE(alpn.has_value());
        PFL_REQUIRE(supported_versions.has_value());
        PFL_EXPECT(*record_type == "Handshake");
        PFL_EXPECT(*record_version == "TLS 1.0 (0x0301)");
        PFL_EXPECT(*record_length == "512");
        PFL_EXPECT(*handshake_type == "ClientHello");
        PFL_EXPECT(*handshake_length == "508");
        PFL_EXPECT(*handshake_version == "TLS 1.2 (0x0303)");
        PFL_EXPECT(count_hex_byte_tokens(*session_id) == 32U);
        const auto cipher_suite_total = parse_total_count_suffix(*cipher_suites);
        const auto extension_total = parse_total_count_suffix(*extensions);
        PFL_REQUIRE(cipher_suite_total.has_value());
        PFL_REQUIRE(extension_total.has_value());
        PFL_EXPECT(*cipher_suite_total == 16U);
        PFL_EXPECT(*extension_total == 18U);
        PFL_EXPECT(*sni == "auth.split.io");
        PFL_EXPECT(alpn->find("h2") != std::string_view::npos);
        PFL_EXPECT(alpn->find("http/1.1") != std::string_view::npos);
        PFL_EXPECT(supported_versions->find("TLS 1.3 (0x0304)") != std::string_view::npos);
        PFL_EXPECT(supported_versions->find("TLS 1.2 (0x0303)") != std::string_view::npos);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/tls/tls_1_3_client_hello_5.pcap"), CaptureImportOptions {}));
        const auto packet = require_packet(session, 0);
        PFL_EXPECT(require_captured_transport_payload_length(session, packet) == 517U);
        const auto packet_bytes = session.read_packet_data(packet);
        PacketPayloadService payload_service {};
        const auto payload = payload_service.extract_transport_payload(packet_bytes, packet.data_link_type);
        PFL_EXPECT(payload.size() == 517U);
        const auto parsed_payload = parse_tls_payload(payload);
        PFL_EXPECT(parsed_payload.records.size() == 1U);
        PFL_EXPECT(parsed_payload.trailing_bytes == 0U);
        PFL_EXPECT(parsed_payload.records[0].content_type == 22U);
        PFL_EXPECT(parsed_payload.records[0].legacy_version == 0x0301U);
        PFL_EXPECT(parsed_payload.records[0].record_length == 512U);
        PFL_EXPECT(parsed_payload.records[0].total_bytes == 517U);
        const auto parsed_client_hello = parse_tls_client_hello_facts(parsed_payload.records[0].body);
        PFL_REQUIRE(parsed_client_hello.has_value());
        PFL_EXPECT(parsed_client_hello->handshake_type == 1U);
        PFL_EXPECT(parsed_client_hello->handshake_length == 508U);
        PFL_EXPECT(parsed_client_hello->handshake_legacy_version == 0x0303U);
        PFL_EXPECT(parsed_client_hello->session_id_length == 32U);
        PFL_EXPECT(parsed_client_hello->cipher_suite_count == 21U);
        PFL_EXPECT(parsed_client_hello->compression_method_count == 1U);
        PFL_EXPECT(parsed_client_hello->extension_count == 16U);
        PFL_REQUIRE(parsed_client_hello->sni.has_value());
        PFL_EXPECT(*parsed_client_hello->sni == "p101-fmf.icloud.com");
        PFL_EXPECT(std::find(parsed_client_hello->alpn_protocols.begin(), parsed_client_hello->alpn_protocols.end(), "h2") != parsed_client_hello->alpn_protocols.end());
        PFL_EXPECT(std::find(parsed_client_hello->alpn_protocols.begin(), parsed_client_hello->alpn_protocols.end(), "http/1.1") != parsed_client_hello->alpn_protocols.end());
        PFL_EXPECT(std::find(parsed_client_hello->supported_versions.begin(), parsed_client_hello->supported_versions.end(), 0x0304U) != parsed_client_hello->supported_versions.end());
        PFL_EXPECT(std::find(parsed_client_hello->supported_versions.begin(), parsed_client_hello->supported_versions.end(), 0x0303U) != parsed_client_hello->supported_versions.end());
        PFL_EXPECT(std::find(parsed_client_hello->supported_versions.begin(), parsed_client_hello->supported_versions.end(), 0x0302U) != parsed_client_hello->supported_versions.end());
        PFL_EXPECT(std::find(parsed_client_hello->supported_versions.begin(), parsed_client_hello->supported_versions.end(), 0x0301U) != parsed_client_hello->supported_versions.end());
        const auto text = session.read_packet_protocol_details_text(packet);
        const auto record_type = find_protocol_detail_value(text, "Record Type:");
        const auto record_version = find_protocol_detail_value(text, "Record Version:");
        const auto record_length = find_protocol_detail_value(text, "Record Length:");
        const auto handshake_type = find_protocol_detail_value(text, "Handshake Type:");
        const auto handshake_length = find_protocol_detail_value(text, "Handshake Length:");
        const auto handshake_version = find_protocol_detail_value(text, "Handshake Version:");
        const auto session_id = find_protocol_detail_value(text, "Session ID:");
        const auto cipher_suites = find_protocol_detail_value(text, "Cipher Suites:");
        const auto extensions = find_protocol_detail_value(text, "Extensions:");
        const auto sni = find_protocol_detail_value(text, "SNI:");
        const auto alpn = find_protocol_detail_value(text, "ALPN:");
        const auto supported_versions = find_protocol_detail_value(text, "Supported Versions:");
        PFL_REQUIRE(record_type.has_value());
        PFL_REQUIRE(record_version.has_value());
        PFL_REQUIRE(record_length.has_value());
        PFL_REQUIRE(handshake_type.has_value());
        PFL_REQUIRE(handshake_length.has_value());
        PFL_REQUIRE(handshake_version.has_value());
        PFL_REQUIRE(session_id.has_value());
        PFL_REQUIRE(cipher_suites.has_value());
        PFL_REQUIRE(extensions.has_value());
        PFL_REQUIRE(sni.has_value());
        PFL_REQUIRE(alpn.has_value());
        PFL_REQUIRE(supported_versions.has_value());
        PFL_EXPECT(*record_type == "Handshake");
        PFL_EXPECT(*record_version == "TLS 1.0 (0x0301)");
        PFL_EXPECT(*record_length == "512");
        PFL_EXPECT(*handshake_type == "ClientHello");
        PFL_EXPECT(*handshake_length == "508");
        PFL_EXPECT(*handshake_version == "TLS 1.2 (0x0303)");
        PFL_EXPECT(count_hex_byte_tokens(*session_id) == 32U);
        const auto cipher_suite_total = parse_total_count_suffix(*cipher_suites);
        const auto extension_total = parse_total_count_suffix(*extensions);
        PFL_REQUIRE(cipher_suite_total.has_value());
        PFL_REQUIRE(extension_total.has_value());
        PFL_EXPECT(*cipher_suite_total == 21U);
        PFL_EXPECT(*extension_total == 16U);
        PFL_EXPECT(*sni == "p101-fmf.icloud.com");
        PFL_EXPECT(alpn->find("h2") != std::string_view::npos);
        PFL_EXPECT(alpn->find("http/1.1") != std::string_view::npos);
        PFL_EXPECT(supported_versions->find("TLS 1.3 (0x0304)") != std::string_view::npos);
        PFL_EXPECT(supported_versions->find("TLS 1.2 (0x0303)") != std::string_view::npos);
        PFL_EXPECT(supported_versions->find("TLS 1.1 (0x0302)") != std::string_view::npos);
        PFL_EXPECT(supported_versions->find("TLS 1.0 (0x0301)") != std::string_view::npos);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/tls/tls_1_2_server_hello_4.pcap"), CaptureImportOptions {}));
        const auto packet = require_packet(session, 0);
        PFL_EXPECT(require_captured_transport_payload_length(session, packet) == 96U);
        const auto packet_bytes = session.read_packet_data(packet);
        PacketPayloadService payload_service {};
        const auto payload = payload_service.extract_transport_payload(packet_bytes, packet.data_link_type);
        PFL_EXPECT(payload.size() == 96U);
        const auto parsed_payload = parse_tls_payload(payload);
        PFL_EXPECT(parsed_payload.records.size() == 1U);
        PFL_EXPECT(parsed_payload.trailing_bytes == 0U);
        PFL_EXPECT(parsed_payload.records[0].content_type == 22U);
        PFL_EXPECT(parsed_payload.records[0].legacy_version == 0x0303U);
        PFL_EXPECT(parsed_payload.records[0].record_length == 91U);
        PFL_EXPECT(parsed_payload.records[0].total_bytes == 96U);
        const auto parsed_server_hello = parse_tls_server_hello_facts(parsed_payload.records[0].body);
        PFL_REQUIRE(parsed_server_hello.has_value());
        PFL_EXPECT(parsed_server_hello->handshake_type == 2U);
        PFL_EXPECT(parsed_server_hello->handshake_length == 87U);
        PFL_EXPECT(parsed_server_hello->handshake_legacy_version == 0x0303U);
        PFL_EXPECT(parsed_server_hello->selected_tls_version == 0x0303U);
        PFL_EXPECT(parsed_server_hello->session_id_length == 32U);
        PFL_EXPECT(parsed_server_hello->cipher_suite == 0xC02FU);
        PFL_EXPECT(parsed_server_hello->compression_method == 0U);
        PFL_EXPECT(parsed_server_hello->extension_count == 3U);
        PFL_EXPECT(std::find(parsed_server_hello->extension_types.begin(), parsed_server_hello->extension_types.end(), 0x000BU) != parsed_server_hello->extension_types.end());
        PFL_EXPECT(std::find(parsed_server_hello->extension_types.begin(), parsed_server_hello->extension_types.end(), 0xFF01U) != parsed_server_hello->extension_types.end());
        PFL_EXPECT(std::find(parsed_server_hello->extension_types.begin(), parsed_server_hello->extension_types.end(), 0x0017U) != parsed_server_hello->extension_types.end());
        const auto text = session.read_packet_protocol_details_text(packet);
        const auto record_type = find_protocol_detail_value(text, "Record Type:");
        const auto record_version = find_protocol_detail_value(text, "Record Version:");
        const auto record_length = find_protocol_detail_value(text, "Record Length:");
        const auto handshake_type = find_protocol_detail_value(text, "Handshake Type:");
        const auto handshake_length = find_protocol_detail_value(text, "Handshake Length:");
        const auto selected_tls_version = find_protocol_detail_value(text, "Selected TLS Version:");
        const auto selected_cipher_suite = find_protocol_detail_value(text, "Selected Cipher Suite:");
        const auto session_id = find_protocol_detail_value(text, "Session ID:");
        const auto extensions = find_protocol_detail_value(text, "Extensions:");
        PFL_REQUIRE(record_type.has_value());
        PFL_REQUIRE(record_version.has_value());
        PFL_REQUIRE(record_length.has_value());
        PFL_REQUIRE(handshake_type.has_value());
        PFL_REQUIRE(handshake_length.has_value());
        PFL_REQUIRE(selected_tls_version.has_value());
        PFL_REQUIRE(selected_cipher_suite.has_value());
        PFL_REQUIRE(session_id.has_value());
        PFL_REQUIRE(extensions.has_value());
        PFL_EXPECT(*record_type == "Handshake");
        PFL_EXPECT(*record_version == "TLS 1.2 (0x0303)");
        PFL_EXPECT(*record_length == "91");
        PFL_EXPECT(*handshake_type == "ServerHello");
        PFL_EXPECT(*handshake_length == "87");
        PFL_EXPECT(*selected_tls_version == "TLS 1.2 (0x0303)");
        PFL_EXPECT(*selected_cipher_suite == "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xc02f)");
        PFL_EXPECT(count_hex_byte_tokens(*session_id) == 32U);
        PFL_EXPECT(extensions->find("ec_point_formats") != std::string_view::npos);
        PFL_EXPECT(extensions->find("renegotiation_info") != std::string_view::npos);
        PFL_EXPECT(extensions->find("extended_master_secret") != std::string_view::npos);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/tls/tls_1_3_server_hello_6.pcap"), CaptureImportOptions {}));
        const auto packet = require_packet(session, 0);
        PFL_EXPECT(require_captured_transport_payload_length(session, packet) == 1400U);
        const auto packet_bytes = session.read_packet_data(packet);
        PacketPayloadService payload_service {};
        const auto payload = payload_service.extract_transport_payload(packet_bytes, packet.data_link_type);
        PFL_EXPECT(payload.size() == 1400U);
        const auto parsed_payload = parse_tls_payload(payload);
        PFL_EXPECT(parsed_payload.records.size() == 2U);
        PFL_EXPECT(parsed_payload.trailing_bytes == 179U);
        PFL_EXPECT(parsed_payload.records[0].content_type == 22U);
        PFL_EXPECT(parsed_payload.records[0].legacy_version == 0x0303U);
        PFL_EXPECT(parsed_payload.records[0].record_length == 1210U);
        PFL_EXPECT(parsed_payload.records[0].total_bytes == 1215U);
        PFL_EXPECT(parsed_payload.records[1].content_type == 20U);
        PFL_EXPECT(parsed_payload.records[1].legacy_version == 0x0303U);
        PFL_EXPECT(parsed_payload.records[1].record_length == 1U);
        PFL_EXPECT(parsed_payload.records[1].total_bytes == 6U);
        const auto parsed_server_hello = parse_tls_server_hello_facts(parsed_payload.records[0].body);
        PFL_REQUIRE(parsed_server_hello.has_value());
        PFL_EXPECT(parsed_server_hello->handshake_type == 2U);
        PFL_EXPECT(parsed_server_hello->handshake_length == 1206U);
        PFL_EXPECT(parsed_server_hello->handshake_legacy_version == 0x0303U);
        PFL_EXPECT(parsed_server_hello->selected_tls_version == 0x0304U);
        PFL_EXPECT(parsed_server_hello->session_id_length == 32U);
        PFL_EXPECT(parsed_server_hello->cipher_suite == 0x1301U);
        PFL_EXPECT(parsed_server_hello->compression_method == 0U);
        PFL_EXPECT(parsed_server_hello->extension_count == 2U);
        PFL_EXPECT(std::find(parsed_server_hello->extension_types.begin(), parsed_server_hello->extension_types.end(), 0x0033U) != parsed_server_hello->extension_types.end());
        PFL_EXPECT(std::find(parsed_server_hello->extension_types.begin(), parsed_server_hello->extension_types.end(), 0x002BU) != parsed_server_hello->extension_types.end());
        const auto text = session.read_packet_protocol_details_text(packet);
        PFL_EXPECT(text.find("TLS") != std::string::npos);
        const auto record_type = find_protocol_detail_value(text, "Record Type:");
        const auto record_version = find_protocol_detail_value(text, "Record Version:");
        const auto record_length = find_protocol_detail_value(text, "Record Length:");
        const auto handshake_type = find_protocol_detail_value(text, "Handshake Type:");
        const auto handshake_length = find_protocol_detail_value(text, "Handshake Length:");
        const auto selected_tls_version = find_protocol_detail_value(text, "Selected TLS Version:");
        const auto selected_cipher_suite = find_protocol_detail_value(text, "Selected Cipher Suite:");
        const auto session_id = find_protocol_detail_value(text, "Session ID:");
        const auto extensions = find_protocol_detail_value(text, "Extensions:");
        PFL_REQUIRE(record_type.has_value());
        PFL_REQUIRE(record_version.has_value());
        PFL_REQUIRE(record_length.has_value());
        PFL_REQUIRE(handshake_type.has_value());
        PFL_REQUIRE(handshake_length.has_value());
        PFL_REQUIRE(selected_tls_version.has_value());
        PFL_REQUIRE(selected_cipher_suite.has_value());
        PFL_REQUIRE(session_id.has_value());
        PFL_REQUIRE(extensions.has_value());
        PFL_EXPECT(*record_type == "Handshake");
        PFL_EXPECT(*record_version == "TLS 1.2 (0x0303)");
        PFL_EXPECT(*record_length == "1210");
        PFL_EXPECT(*handshake_type == "ServerHello");
        PFL_EXPECT(*handshake_length == "1206");
        PFL_EXPECT(*selected_tls_version == "TLS 1.3 (0x0304)");
        PFL_EXPECT(*selected_cipher_suite == "TLS_AES_128_GCM_SHA256 (0x1301)");
        PFL_EXPECT(count_hex_byte_tokens(*session_id) == 32U);
        PFL_EXPECT(extensions->find("key_share") != std::string_view::npos);
        PFL_EXPECT(extensions->find("supported_versions") != std::string_view::npos);
    }

    {
        const auto packet_bytes = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
            ipv4(10, 0, 0, 11), ipv4(10, 0, 0, 12), 54443, 443, make_tls_alert_payload(), 0x18);
        const auto capture_path = write_temp_pcap(
            "pfl_protocol_tls_alert.pcap",
            make_classic_pcap({{100, packet_bytes}})
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(capture_path, CaptureImportOptions {}));
        const auto packet = require_packet(session, 0);
        const auto text = session.read_packet_protocol_details_text(packet);
        PFL_EXPECT(text.find("TLS") != std::string::npos);
        PFL_EXPECT(text.find("Record Type: Alert") != std::string::npos);
        PFL_EXPECT(text.find("Alert Level: Warning") != std::string::npos);
        PFL_EXPECT(text.find("Alert Description: Close Notify") != std::string::npos);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/quic/quic_initial_ch_1.pcap"), CaptureImportOptions {}));
        const auto packet = require_packet(session, 0);
        const auto text = session.read_packet_protocol_details_text(packet);
        PFL_EXPECT(text.find("QUIC") != std::string::npos);
        PFL_EXPECT(text.find("Header Form: Long") != std::string::npos);
        PFL_EXPECT(text.find("Packet Type: Initial") != std::string::npos);
        PFL_EXPECT(text.find("Version:") != std::string::npos);
        PFL_EXPECT(text.find("Destination Connection ID Length:") != std::string::npos);
        PFL_EXPECT(text.find("Source Connection ID Length:") != std::string::npos);
        PFL_EXPECT(text.find("TLS Handshake Type: ClientHello") != std::string::npos);
        PFL_EXPECT(text.find("Cipher Suites:") != std::string::npos);
        PFL_EXPECT(text.find("Supported Versions:") != std::string::npos);
        PFL_EXPECT(text.find("SNI:") != std::string::npos);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/quic/quic_handshake_3.pcap"), CaptureImportOptions {}));
        const auto packet = require_packet(session, 0);
        const auto text = session.read_packet_protocol_details_text(packet);
        PFL_EXPECT(text.find("QUIC") != std::string::npos);
        PFL_EXPECT(text.find("Header Form: Long") != std::string::npos);
        PFL_EXPECT(text.find("Packet Type: Handshake") != std::string::npos);
        PFL_EXPECT(text.find("Destination Connection ID Length:") != std::string::npos);
    }

    {
        QuicPacketProtocolAnalyzer analyzer {};
        const auto zero_rtt_payload = make_plaintext_quic_zero_rtt_payload({0x01U});
        const auto zero_rtt_inspection = analyzer.inspect_udp_payload(
            std::span<const std::uint8_t>(zero_rtt_payload.data(), zero_rtt_payload.size())
        );
        PFL_REQUIRE(zero_rtt_inspection.has_value());
        PFL_REQUIRE(zero_rtt_inspection->packets.size() == 1U);
        PFL_EXPECT(zero_rtt_inspection->packets[0].packet_type == QuicPacketType::zero_rtt);

        const auto zero_rtt_text = analyzer.analyze_udp_payload(
            std::span<const std::uint8_t>(zero_rtt_payload.data(), zero_rtt_payload.size())
        );
        PFL_REQUIRE(zero_rtt_text.has_value());
        PFL_EXPECT(zero_rtt_text->find("Packet Type: 0-RTT") != std::string::npos);
    }

    {
        QuicPacketProtocolAnalyzer analyzer {};
        const auto initial_payload = make_plaintext_quic_initial_payload(
            make_quic_crypto_frame_bytes(make_tls_client_hello_handshake_bytes())
        );
        const auto zero_rtt_payload = make_plaintext_quic_zero_rtt_payload({0x01U});
        const auto coalesced_payload = concat_bytes(initial_payload, zero_rtt_payload);
        const auto coalesced_inspection = analyzer.inspect_udp_payload(
            std::span<const std::uint8_t>(coalesced_payload.data(), coalesced_payload.size())
        );
        PFL_REQUIRE(coalesced_inspection.has_value());
        PFL_REQUIRE(coalesced_inspection->packets.size() == 2U);
        PFL_EXPECT(coalesced_inspection->packets[0].packet_type == QuicPacketType::initial);
        PFL_EXPECT(coalesced_inspection->packets[1].packet_type == QuicPacketType::zero_rtt);
        PFL_EXPECT(!coalesced_inspection->packets[0].tls_crypto_prefix.empty());

        const auto coalesced_text = analyzer.analyze_udp_payload(
            std::span<const std::uint8_t>(coalesced_payload.data(), coalesced_payload.size())
        );
        PFL_REQUIRE(coalesced_text.has_value());
        PFL_EXPECT(coalesced_text->find("Packet Type: Initial") != std::string::npos);
        PFL_EXPECT(coalesced_text->find("Additional Packet Types: 0-RTT") != std::string::npos);
    }

    {
        const auto packet_bytes = make_ethernet_ipv4_udp_packet_with_bytes_payload(
            ipv4(10, 1, 0, 7), ipv4(8, 8, 8, 8), 54000, 443,
            make_plaintext_quic_initial_payload(make_quic_crypto_frame_bytes(make_tls_server_hello_handshake_bytes())));
        const auto capture_path = write_temp_pcap(
            "pfl_protocol_quic_server_hello_plaintext.pcap",
            make_classic_pcap({{100, packet_bytes}})
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(capture_path, CaptureImportOptions {}));
        const auto packet = require_packet(session, 0);
        const auto text = session.read_packet_protocol_details_text(packet);
        PFL_EXPECT(text.find("QUIC") != std::string::npos);
        PFL_EXPECT(text.find("Frame Presence: CRYPTO") != std::string::npos);
        PFL_EXPECT(text.find("TLS Handshake Type: ServerHello") != std::string::npos);
        PFL_EXPECT(text.find("Selected TLS Version:") != std::string::npos);
        PFL_EXPECT(text.find("Selected Cipher Suite:") != std::string::npos);
    }

    {
        const auto client_hello_packet = make_ethernet_ipv4_udp_packet_with_bytes_payload(
            ipv4(10, 1, 0, 10), ipv4(10, 1, 0, 20), 54010, 443,
            make_plaintext_quic_initial_payload(make_quic_crypto_frame_bytes(make_tls_client_hello_handshake_bytes())));
        const auto server_hello_packet = make_ethernet_ipv4_udp_packet_with_bytes_payload(
            ipv4(10, 1, 0, 20), ipv4(10, 1, 0, 10), 443, 54010,
            make_plaintext_quic_initial_payload(make_quic_crypto_frame_bytes(make_tls_server_hello_handshake_bytes())));
        const auto server_ack_packet = make_ethernet_ipv4_udp_packet_with_bytes_payload(
            ipv4(10, 1, 0, 20), ipv4(10, 1, 0, 10), 443, 54010,
            make_plaintext_quic_initial_payload(make_quic_ack_frame_bytes()));
        const auto capture_path = write_temp_pcap(
            "pfl_protocol_quic_direction_ownership_stage1.pcap",
            make_classic_pcap(std::vector<std::pair<std::uint32_t, std::vector<std::uint8_t>>> {
                {100U, client_hello_packet},
                {200U, server_hello_packet},
                {300U, server_ack_packet},
            })
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(capture_path, CaptureImportOptions {}));

        const auto client_context = session.derive_quic_protocol_details_for_packet(0, 0);
        PFL_EXPECT(client_context.has_value());
        PFL_EXPECT(client_context->find("TLS Handshake Type: ClientHello") != std::string::npos);
        PFL_EXPECT(client_context->find("ServerHello") == std::string::npos);

        const auto server_context = session.derive_quic_protocol_details_for_packet(0, 1);
        PFL_EXPECT(server_context.has_value());
        PFL_EXPECT(server_context->find("TLS Handshake Type: ServerHello") != std::string::npos);
        PFL_EXPECT(server_context->find("ClientHello") == std::string::npos);
        PFL_EXPECT(server_context->find("SNI:") == std::string::npos);

        const auto server_ack_context = session.derive_quic_protocol_details_for_packet(0, 2);
        PFL_EXPECT(!server_ack_context.has_value());
    }

    {
        const auto server_hello_bytes = make_tls_server_hello_handshake_bytes();
        const auto split_offset = server_hello_bytes.size() / 2U;
        const std::vector<std::uint8_t> server_hello_prefix(server_hello_bytes.begin(), server_hello_bytes.begin() + static_cast<std::ptrdiff_t>(split_offset));
        const std::vector<std::uint8_t> server_hello_suffix(server_hello_bytes.begin() + static_cast<std::ptrdiff_t>(split_offset), server_hello_bytes.end());

        const auto client_hello_packet = make_ethernet_ipv4_udp_packet_with_bytes_payload(
            ipv4(10, 1, 0, 30), ipv4(10, 1, 0, 40), 54030, 443,
            make_plaintext_quic_initial_payload(make_quic_crypto_frame_bytes(make_tls_client_hello_handshake_bytes())));
        const auto server_hello_prefix_packet = make_ethernet_ipv4_udp_packet_with_bytes_payload(
            ipv4(10, 1, 0, 40), ipv4(10, 1, 0, 30), 443, 54030,
            make_plaintext_quic_initial_payload(make_quic_crypto_frame_bytes(server_hello_prefix)));
        const auto server_hello_suffix_packet = make_ethernet_ipv4_udp_packet_with_bytes_payload(
            ipv4(10, 1, 0, 40), ipv4(10, 1, 0, 30), 443, 54030,
            make_plaintext_quic_initial_payload(concat_bytes(
                make_quic_crypto_frame_bytes(static_cast<std::uint64_t>(split_offset), server_hello_suffix),
                make_quic_ack_frame_bytes()
            )));
        const auto capture_path = write_temp_pcap(
            "pfl_protocol_quic_server_hello_bounded_tail_attachment.pcap",
            make_classic_pcap(std::vector<std::pair<std::uint32_t, std::vector<std::uint8_t>>> {
                {100U, client_hello_packet},
                {200U, server_hello_prefix_packet},
                {300U, server_hello_suffix_packet},
            })
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(capture_path, CaptureImportOptions {}));

        const auto server_tail_context = session.derive_quic_protocol_details_for_packet(0, 2);
        PFL_EXPECT(server_tail_context.has_value());
        PFL_EXPECT(server_tail_context->find("TLS Handshake Type: ServerHello") != std::string::npos);
        PFL_EXPECT(server_tail_context->find("Selected TLS Version:") != std::string::npos);
        PFL_EXPECT(server_tail_context->find("Selected Cipher Suite:") != std::string::npos);
        PFL_EXPECT(server_tail_context->find("Extensions:") != std::string::npos);
        PFL_EXPECT(server_tail_context->find("ClientHello") == std::string::npos);
        PFL_EXPECT(server_tail_context->find("Cipher Suites:") == std::string::npos);
        PFL_EXPECT(server_tail_context->find("SNI:") == std::string::npos);
    }

    {
        const auto server_hello_bytes = make_tls_server_hello_handshake_bytes();
        const auto split_offset = server_hello_bytes.size() / 2U;
        const std::vector<std::uint8_t> server_hello_suffix(server_hello_bytes.begin() + static_cast<std::ptrdiff_t>(split_offset), server_hello_bytes.end());

        const auto client_hello_packet = make_ethernet_ipv4_udp_packet_with_bytes_payload(
            ipv4(10, 1, 0, 50), ipv4(10, 1, 0, 60), 54050, 443,
            make_plaintext_quic_initial_payload(make_quic_crypto_frame_bytes(make_tls_client_hello_handshake_bytes())));
        const auto server_hello_suffix_packet = make_ethernet_ipv4_udp_packet_with_bytes_payload(
            ipv4(10, 1, 0, 60), ipv4(10, 1, 0, 50), 443, 54050,
            make_plaintext_quic_initial_payload(make_quic_crypto_frame_bytes(static_cast<std::uint64_t>(split_offset), server_hello_suffix)));
        const auto capture_path = write_temp_pcap(
            "pfl_protocol_quic_server_hello_insufficient_tail_only.pcap",
            make_classic_pcap(std::vector<std::pair<std::uint32_t, std::vector<std::uint8_t>>> {
                {100U, client_hello_packet},
                {200U, server_hello_suffix_packet},
            })
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(capture_path, CaptureImportOptions {}));

        const auto server_tail_context = session.derive_quic_protocol_details_for_packet(0, 1);
        PFL_EXPECT(!server_tail_context.has_value());
        const auto server_tail_protocol_text = session.derive_quic_protocol_text_for_packet(0, 1);
        PFL_EXPECT(server_tail_protocol_text.has_value());
        PFL_EXPECT(server_tail_protocol_text->find("TLS Handshake Type: ServerHello") == std::string::npos);
        PFL_EXPECT(server_tail_protocol_text->find("ClientHello") == std::string::npos);
    }

    {
        const auto source_path = write_temp_pcap(
            "pfl_protocol_details_missing_source_tls.pcap",
            make_classic_pcap({
                {100, make_ethernet_ipv4_tcp_packet_with_bytes_payload(
                    ipv4(192, 168, 50, 10), ipv4(93, 184, 216, 34), 51515, 443, make_tls_client_hello_payload(), 0x18)},
            })
        );
        const auto index_path = std::filesystem::temp_directory_path() / "pfl_protocol_details_missing_source.idx";
        const auto moved_source_path = std::filesystem::temp_directory_path() / "pfl_protocol_details_missing_source.gone.pcap";
        std::filesystem::remove(index_path);
        std::filesystem::remove(moved_source_path);

        CaptureSession original_session {};
        PFL_EXPECT(original_session.open_capture(source_path, CaptureImportOptions {}));
        PFL_EXPECT(original_session.save_index(index_path));
        std::filesystem::rename(source_path, moved_source_path);

        CaptureSession loaded_session {};
        PFL_EXPECT(loaded_session.load_index(index_path));
        PFL_EXPECT(!loaded_session.has_source_capture());
        const auto packet = require_packet(loaded_session, 0);
        PFL_EXPECT(loaded_session.read_packet_protocol_details_text(packet) == kUnavailableProtocolDetailsMessage);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/dns/dns_request_1.pcap"), CaptureImportOptions {}));
        const auto packet = require_packet(session, 0);
        const auto text = session.read_packet_protocol_details_text(packet);
        PFL_EXPECT(text.find("DNS") != std::string::npos);
        PFL_EXPECT(text.find("Message Type: Query") != std::string::npos);
        PFL_EXPECT(text.find("QName: gsp85-ssl.ls.apple.com") != std::string::npos);
        PFL_EXPECT(text.find("QType: HTTPS (65)") != std::string::npos);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/http/http_get_1.pcap"), CaptureImportOptions {}));
        const auto packet = require_packet(session, 0);
        const auto text = session.read_packet_protocol_details_text(packet);
        PFL_EXPECT(text.find("HTTP") != std::string::npos);
        PFL_EXPECT(text.find("Message Type: Request") != std::string::npos);
        PFL_EXPECT(text.find("Method: GET") != std::string::npos);
        PFL_EXPECT(text.find("Path: /components/com_virtuemart/assets/css/vm-ltr-common.css?vmver=8dcacf73") != std::string::npos);
        PFL_EXPECT(text.find("Version: HTTP/1.1") != std::string::npos);
        PFL_EXPECT(text.find("Host: www.kresla-darom.ru") != std::string::npos);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/http/http_answer_2.pcap"), CaptureImportOptions {}));
        const auto packet = require_packet(session, 0);
        const auto text = session.read_packet_protocol_details_text(packet);
        PFL_EXPECT(text.find("HTTP") != std::string::npos);
        PFL_EXPECT(text.find("Message Type: Response") != std::string::npos);
        PFL_EXPECT(text.find("Version: HTTP/1.1") != std::string::npos);
        PFL_EXPECT(text.find("Status Code: 200") != std::string::npos);
    }

    {
        const auto arp_packet = make_ethernet_arp_packet(ipv4(192, 168, 1, 10), ipv4(192, 168, 1, 1), 1);
        const auto capture_path = write_temp_pcap(
            "pfl_protocol_arp_deep.pcap",
            make_classic_pcap({{100, arp_packet}})
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(capture_path, CaptureImportOptions {}));
        const auto packet = require_packet(session, 0);
        const auto text = session.read_packet_protocol_details_text(packet);
        PFL_EXPECT(text.find("Protocol: ARP (Address Resolution Protocol)") != std::string::npos);
        PFL_EXPECT(text.find("Hardware Type: Ethernet (1)") != std::string::npos);
        PFL_EXPECT(text.find("Protocol Type: IPv4 (0x0800)") != std::string::npos);
        PFL_EXPECT(text.find("Opcode: request (1)") != std::string::npos);
        PFL_EXPECT(text.find("Sender MAC Address: 00:11:22:33:44:55") != std::string::npos);
        PFL_EXPECT(text.find("Sender Protocol Address: 192.168.1.10") != std::string::npos);
        PFL_EXPECT(text.find("Target Protocol Address: 192.168.1.1") != std::string::npos);
    }

    {
        auto truncated_arp_packet = make_ethernet_arp_packet(ipv4(192, 168, 1, 10), ipv4(192, 168, 1, 1), 1U);
        truncated_arp_packet.resize(truncated_arp_packet.size() - 3U);
        PacketDetailsService details_service {};
        const PacketRef packet_ref {
            .packet_index = 0,
            .byte_offset = 0,
            .captured_length = static_cast<std::uint32_t>(truncated_arp_packet.size()),
            .original_length = static_cast<std::uint32_t>(truncated_arp_packet.size() + 3U),
        };

        const auto details = details_service.decode(truncated_arp_packet, packet_ref);
        PFL_EXPECT(details.has_value());
        const auto text = session_detail::build_basic_protocol_details_text(*details);
        PFL_EXPECT(text.has_value());
        const auto& protocol_text = *text;
        PFL_EXPECT(protocol_text.find("Protocol: ARP (Address Resolution Protocol)") != std::string::npos);
        PFL_EXPECT(protocol_text.find("Target Protocol Address: c0 (truncated)") != std::string::npos);
        PFL_EXPECT(protocol_text.find("(truncated)") != std::string::npos);
        PFL_EXPECT(protocol_text.find("Warning: ARP address section is truncated.") != std::string::npos);
    }

    {
        const auto unknown_arp_packet = make_ethernet_arp_packet_with_fields(
            {0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
            {0x0a, 0x0a, 0x0c, 0x02},
            {0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
            {0x0a, 0x0a, 0x0c, 0x01},
            7U,
            99U,
            0x88B5U
        );
        PacketDetailsService details_service {};
        const PacketRef packet_ref {
            .packet_index = 0,
            .byte_offset = 0,
            .captured_length = static_cast<std::uint32_t>(unknown_arp_packet.size()),
            .original_length = static_cast<std::uint32_t>(unknown_arp_packet.size()),
        };

        const auto details = details_service.decode(unknown_arp_packet, packet_ref);
        PFL_EXPECT(details.has_value());
        const auto text = session_detail::build_basic_protocol_details_text(*details);
        PFL_EXPECT(text.has_value());
        const auto& protocol_text = *text;
        PFL_EXPECT(protocol_text.find("Hardware Type: Unknown (99)") != std::string::npos);
        PFL_EXPECT(protocol_text.find("Protocol Type: 0x88b5") != std::string::npos);
        PFL_EXPECT(protocol_text.find("Opcode: opcode 7") != std::string::npos);
    }

    {
        const auto icmp_packet = make_ethernet_ipv4_icmp_packet(ipv4(10, 0, 0, 10), ipv4(10, 0, 0, 20), 8, 0);
        const auto capture_path = write_temp_pcap(
            "pfl_protocol_icmp_deep.pcap",
            make_classic_pcap({{100, icmp_packet}})
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(capture_path, CaptureImportOptions {}));
        const auto packet = require_packet(session, 0);
        const auto text = session.read_packet_protocol_details_text(packet);
        PFL_EXPECT(text.find("ICMP") != std::string::npos);
        PFL_EXPECT(text.find("Type: 8") != std::string::npos);
        PFL_EXPECT(text.find("Code: 0") != std::string::npos);
        PFL_EXPECT(text.find("Source: 10.0.0.10") != std::string::npos);
        PFL_EXPECT(text.find("Destination: 10.0.0.20") != std::string::npos);
    }

    {
        const auto ipv6_src = ipv6({0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01});
        const auto ipv6_dst = ipv6({0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02});
        const auto icmpv6_packet = make_ethernet_ipv6_icmpv6_with_hop_by_hop_packet(ipv6_src, ipv6_dst, 128, 0);
        const auto capture_path = write_temp_pcap(
            "pfl_protocol_icmpv6_deep.pcap",
            make_classic_pcap({{100, icmpv6_packet}})
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(capture_path, CaptureImportOptions {}));
        const auto packet = require_packet(session, 0);
        const auto text = session.read_packet_protocol_details_text(packet);
        PFL_EXPECT(text.find("ICMPv6") != std::string::npos);
        PFL_EXPECT(text.find("Type: 128") != std::string::npos);
        PFL_EXPECT(text.find("Code: 0") != std::string::npos);
        PFL_EXPECT(text.find("Source: 2001:0db8:0000:0000:0000:0000:0000:0001") != std::string::npos);
        PFL_EXPECT(text.find("Destination: 2001:0db8:0000:0000:0000:0000:0000:0002") != std::string::npos);
    }

    {
        const auto packet_bytes = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
            ipv4(10, 0, 0, 1), ipv4(10, 0, 0, 2), 1111, 80,
            std::vector<std::uint8_t> {'G', 'E', 'T', ' ', '/', ' '}, 0x18);
        const auto capture_path = write_temp_pcap(
            "pfl_protocol_http_only.pcap",
            make_classic_pcap({{100, packet_bytes}})
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(capture_path, CaptureImportOptions {}));
        const auto packet = require_packet(session, 0);
        PFL_EXPECT(session.read_packet_protocol_details_text(packet) == kNoProtocolDetailsMessage);
    }

    {
        const std::vector<std::uint8_t> truncated_dns {
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x03, 'w', 'w', 'w', 0x00,
        };
        const auto packet_bytes = make_ethernet_ipv4_udp_packet_with_bytes_payload(
            ipv4(10, 1, 0, 1), ipv4(8, 8, 8, 8), 53000, 53, truncated_dns);
        const auto capture_path = write_temp_pcap(
            "pfl_protocol_dns_truncated.pcap",
            make_classic_pcap({{100, packet_bytes}})
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(capture_path, CaptureImportOptions {}));
        const auto packet = require_packet(session, 0);
        PFL_EXPECT(session.read_packet_protocol_details_text(packet) == kNoProtocolDetailsMessage);
    }

    {
        const auto packet_bytes = make_ethernet_ipv4_udp_packet_with_bytes_payload(
            ipv4(10, 1, 0, 5), ipv4(8, 8, 8, 8), 54000, 443, make_quic_truncated_payload());
        const auto capture_path = write_temp_pcap(
            "pfl_protocol_quic_truncated.pcap",
            make_classic_pcap({{100, packet_bytes}})
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(capture_path, CaptureImportOptions {}));
        const auto packet = require_packet(session, 0);
        PFL_EXPECT(session.read_packet_protocol_details_text(packet) == kNoProtocolDetailsMessage);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(
            fixture_path("parsing/udp/udp_truncated_quic_like_payload_3.pcap"),
            CaptureImportOptions {}
        ));
        PFL_EXPECT(session.summary().packet_count == 1U);
        PFL_EXPECT(session.summary().flow_count == 1U);

        const auto packet = require_packet(session, 0);
        PFL_EXPECT(packet.captured_length < packet.original_length);
        PFL_EXPECT(require_captured_transport_payload_length(session, packet) == 32U);
        PFL_EXPECT(session.read_packet_protocol_details_text(packet) == kNoProtocolDetailsMessage);
    }

    {
        const std::vector<std::uint8_t> truncated_tls {0x16, 0x03, 0x03, 0x00, 0x10, 0x01, 0x00};
        const auto packet_bytes = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
            ipv4(10, 0, 0, 3), ipv4(10, 0, 0, 4), 12345, 443, truncated_tls, 0x18);
        const auto capture_path = write_temp_pcap(
            "pfl_protocol_tls_truncated.pcap",
            make_classic_pcap({{100, packet_bytes}})
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(capture_path, CaptureImportOptions {}));
        const auto packet = require_packet(session, 0);
        const auto text = session.read_packet_protocol_details_text(packet);
        PFL_EXPECT(text == kNoProtocolDetailsMessage);
        PFL_EXPECT(text.find("Cipher Suites:") == std::string::npos);
        PFL_EXPECT(text.find("Selected Cipher Suite:") == std::string::npos);
        PFL_EXPECT(text.find("Subject:") == std::string::npos);
    }
}

}  // namespace pfl::tests

