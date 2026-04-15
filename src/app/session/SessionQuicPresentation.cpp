#include "app/session/SessionQuicPresentation.h"

#include <algorithm>
#include <iomanip>
#include <limits>
#include <optional>
#include <sstream>

#include "app/session/CaptureSession.h"
#include "core/services/PacketPayloadService.h"
#include "core/services/QuicInitialParser.h"

namespace pfl::session_detail {

namespace {

constexpr std::uint16_t kHttpsPort = 443U;
constexpr std::size_t kMaxQuicConnectionIdLength = 20U;
constexpr std::size_t kMaxQuicFrameSummaryCount = 32U;
constexpr std::size_t kQuicPresentationPacketBudget = 4U;

struct QuicFramePresenceSummary {
    bool ack {false};
    bool crypto {false};
    bool zero_rtt {false};
    bool padding {false};
    bool ping {false};
};

struct ParsedQuicPresentationPacket {
    QuicPresentationShellType shell_type {QuicPresentationShellType::none};
    QuicPresentationShellMetadata shell {};
    std::optional<QuicFramePresenceSummary> frame_summary {};
    std::vector<std::uint8_t> plaintext_payload_candidate {};
    bool is_client_initial {false};
    std::optional<std::string> sni {};
    std::optional<TlsHandshakeDetails> tls_handshake {};
    std::size_t packet_bytes_consumed {0U};
};

struct QuicPresentationCandidate {
    PacketRef packet {};
    std::vector<std::uint8_t> udp_payload {};
    ParsedQuicPresentationPacket parsed {};
    std::vector<ParsedQuicPresentationPacket> datagram_packets {};
};

struct QuicSemanticItemInfo {
    QuicPresentationSemanticType semantic {};
    std::size_t byte_count {0U};
};

std::uint32_t read_be32(std::span<const std::uint8_t> bytes, const std::size_t offset) noexcept {
    return (static_cast<std::uint32_t>(bytes[offset]) << 24U) |
           (static_cast<std::uint32_t>(bytes[offset + 1U]) << 16U) |
           (static_cast<std::uint32_t>(bytes[offset + 2U]) << 8U) |
           static_cast<std::uint32_t>(bytes[offset + 3U]);
}

std::string quic_hex_text(std::span<const std::uint8_t> bytes, const std::size_t max_bytes = 8U) {
    if (bytes.empty()) {
        return "<empty>";
    }

    std::ostringstream text {};
    text << std::hex << std::setfill('0');
    const auto emit_count = std::min(bytes.size(), max_bytes);
    for (std::size_t index = 0U; index < emit_count; ++index) {
        if (index > 0U) {
            text << ' ';
        }
        text << std::setw(2) << static_cast<unsigned int>(bytes[index]);
    }
    if (bytes.size() > emit_count) {
        text << " ...";
    }
    return text.str();
}

std::string quic_version_text(const std::uint32_t version) {
    switch (version) {
    case 0x00000000U:
        return "Version Negotiation (0x00000000)";
    case 0x00000001U:
        return "QUIC v1 (0x00000001)";
    case 0x6B3343CFU:
        return "QUIC v2 (0x6b3343cf)";
    case 0xFF00001DU:
        return "QUIC draft-29 (0xff00001d)";
    default: {
        std::ostringstream builder {};
        builder << "0x" << std::hex << std::setfill('0') << std::setw(8) << version;
        return builder.str();
    }
    }
}

const char* quic_shell_type_text(const QuicPresentationShellType shell_type) noexcept {
    switch (shell_type) {
    case QuicPresentationShellType::initial:
        return "Initial";
    case QuicPresentationShellType::zero_rtt:
        return "0-RTT";
    case QuicPresentationShellType::handshake:
        return "Handshake";
    case QuicPresentationShellType::retry:
        return "Retry";
    case QuicPresentationShellType::version_negotiation:
        return "Version Negotiation";
    case QuicPresentationShellType::protected_payload:
        return "Protected Payload";
    default:
        return "Unknown";
    }
}

const char* quic_semantic_text(const QuicPresentationSemanticType semantic) noexcept {
    switch (semantic) {
    case QuicPresentationSemanticType::ack:
        return "ACK";
    case QuicPresentationSemanticType::crypto:
        return "CRYPTO";
    case QuicPresentationSemanticType::zero_rtt:
        return "0-RTT";
    case QuicPresentationSemanticType::padding:
        return "PADDING";
    case QuicPresentationSemanticType::ping:
        return "PING";
    default:
        return "UNKNOWN";
    }
}

bool quic_has_semantic(const QuicPresentationResult& result, const QuicPresentationSemanticType semantic) noexcept {
    return std::find(result.semantics.begin(), result.semantics.end(), semantic) != result.semantics.end();
}

bool quic_has_additional_shell_type(const QuicPresentationResult& result, const QuicPresentationShellType shell_type) noexcept {
    return std::find(result.additional_shell_types.begin(), result.additional_shell_types.end(), shell_type) != result.additional_shell_types.end();
}

std::string quic_semantics_text(const QuicPresentationResult& result) {
    if (result.semantics.empty()) {
        return {};
    }

    std::ostringstream text {};
    for (std::size_t index = 0U; index < result.semantics.size(); ++index) {
        if (index > 0U) {
            text << ", ";
        }
        text << quic_semantic_text(result.semantics[index]);
    }
    return text.str();
}

bool should_emit_quic_stream_item(const QuicPresentationResult& result) noexcept {
    if (result.shell_type == QuicPresentationShellType::version_negotiation ||
        result.shell_type == QuicPresentationShellType::retry ||
        result.shell_type == QuicPresentationShellType::zero_rtt ||
        result.shell_type == QuicPresentationShellType::handshake ||
        result.shell_type == QuicPresentationShellType::protected_payload) {
        return true;
    }

    if (result.semantics.empty()) {
        return result.shell_type == QuicPresentationShellType::initial;
    }

    const bool has_ack = quic_has_semantic(result, QuicPresentationSemanticType::ack);
    const bool has_crypto = quic_has_semantic(result, QuicPresentationSemanticType::crypto);
    const bool has_zero_rtt = quic_has_semantic(result, QuicPresentationSemanticType::zero_rtt);
    const bool has_padding = quic_has_semantic(result, QuicPresentationSemanticType::padding);
    const bool has_ping = quic_has_semantic(result, QuicPresentationSemanticType::ping);

    if (!has_ack && !has_crypto && !has_zero_rtt && (has_padding || has_ping)) {
        return false;
    }

    return true;
}

std::string quic_stream_label_from_result(const QuicPresentationResult& result) {
    if (result.shell_type == QuicPresentationShellType::version_negotiation) {
        return "QUIC Version Negotiation";
    }
    if (result.shell_type == QuicPresentationShellType::retry) {
        return "QUIC Retry";
    }

    const bool has_ack = quic_has_semantic(result, QuicPresentationSemanticType::ack);
    const bool has_crypto = quic_has_semantic(result, QuicPresentationSemanticType::crypto);
    const bool has_zero_rtt = quic_has_semantic(result, QuicPresentationSemanticType::zero_rtt);
    if (has_ack && !has_crypto && !has_zero_rtt) {
        return "QUIC Initial: ACK";
    }
    if (has_crypto && !has_ack && !has_zero_rtt) {
        return "QUIC Initial: CRYPTO";
    }
    if (has_zero_rtt && !has_ack && !has_crypto) {
        return "0-RTT";
    }

    switch (result.shell_type) {
    case QuicPresentationShellType::initial:
        return "QUIC Initial";
    case QuicPresentationShellType::zero_rtt:
        return "0-RTT";
    case QuicPresentationShellType::handshake:
        return "Handshake";
    case QuicPresentationShellType::protected_payload:
        return "Protected payload";
    default:
        return "UDP Payload";
    }
}

std::optional<std::uint64_t> quic_read_varint(std::span<const std::uint8_t> bytes, std::size_t& offset) {
    if (offset >= bytes.size()) {
        return std::nullopt;
    }

    const auto first = bytes[offset];
    const auto encoded_length = static_cast<std::size_t>(1U << ((first >> 6U) & 0x03U));
    if (offset + encoded_length > bytes.size()) {
        return std::nullopt;
    }

    std::uint64_t value = static_cast<std::uint64_t>(first & 0x3FU);
    for (std::size_t index = 1U; index < encoded_length; ++index) {
        value = (value << 8U) | static_cast<std::uint64_t>(bytes[offset + index]);
    }

    offset += encoded_length;
    return value;
}

std::optional<std::size_t> quic_read_varint_size(std::span<const std::uint8_t> bytes, std::size_t& offset) {
    const auto value = quic_read_varint(bytes, offset);
    if (!value.has_value() || *value > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
        return std::nullopt;
    }

    return static_cast<std::size_t>(*value);
}

bool quic_skip_bytes(std::span<const std::uint8_t> bytes, std::size_t& offset, const std::size_t count) {
    if (offset + count > bytes.size()) {
        return false;
    }

    offset += count;
    return true;
}

bool quic_skip_ack_frame(std::span<const std::uint8_t> bytes, std::size_t& offset, const bool has_ecn) {
    const auto largest_ack = quic_read_varint(bytes, offset);
    const auto ack_delay = quic_read_varint(bytes, offset);
    const auto ack_range_count = quic_read_varint_size(bytes, offset);
    const auto first_ack_range = quic_read_varint(bytes, offset);
    if (!largest_ack.has_value() || !ack_delay.has_value() || !ack_range_count.has_value() || !first_ack_range.has_value()) {
        return false;
    }

    for (std::size_t index = 0U; index < *ack_range_count; ++index) {
        const auto gap = quic_read_varint(bytes, offset);
        const auto ack_range_length = quic_read_varint(bytes, offset);
        if (!gap.has_value() || !ack_range_length.has_value()) {
            return false;
        }
    }

    if (!has_ecn) {
        return true;
    }

    return quic_read_varint(bytes, offset).has_value() &&
           quic_read_varint(bytes, offset).has_value() &&
           quic_read_varint(bytes, offset).has_value();
}

bool quic_skip_stream_frame(std::span<const std::uint8_t> bytes, std::size_t& offset, const std::uint8_t frame_type) {
    if (!quic_read_varint(bytes, offset).has_value()) {
        return false;
    }

    const bool has_offset = (frame_type & 0x04U) != 0U;
    const bool has_length = (frame_type & 0x02U) != 0U;
    if (has_offset && !quic_read_varint(bytes, offset).has_value()) {
        return false;
    }

    if (!has_length) {
        offset = bytes.size();
        return true;
    }

    const auto length = quic_read_varint_size(bytes, offset);
    return length.has_value() && quic_skip_bytes(bytes, offset, *length);
}

bool quic_skip_frame_payload(std::span<const std::uint8_t> bytes, std::size_t& offset, const std::uint8_t frame_type) {
    switch (frame_type) {
    case 0x02U:
        return quic_skip_ack_frame(bytes, offset, false);
    case 0x03U:
        return quic_skip_ack_frame(bytes, offset, true);
    case 0x04U:
        return quic_read_varint(bytes, offset).has_value() &&
               quic_read_varint(bytes, offset).has_value() &&
               quic_read_varint(bytes, offset).has_value();
    case 0x05U:
        return quic_read_varint(bytes, offset).has_value() && quic_read_varint(bytes, offset).has_value();
    case 0x07U: {
        const auto token_length = quic_read_varint_size(bytes, offset);
        return token_length.has_value() && quic_skip_bytes(bytes, offset, *token_length);
    }
    case 0x08U:
    case 0x09U:
    case 0x0AU:
    case 0x0BU:
    case 0x0CU:
    case 0x0DU:
    case 0x0EU:
    case 0x0FU:
        return quic_skip_stream_frame(bytes, offset, frame_type);
    case 0x10U:
    case 0x12U:
    case 0x13U:
    case 0x14U:
    case 0x16U:
    case 0x17U:
    case 0x19U:
        return quic_read_varint(bytes, offset).has_value();
    case 0x11U:
    case 0x15U:
        return quic_read_varint(bytes, offset).has_value() && quic_read_varint(bytes, offset).has_value();
    case 0x18U: {
        const auto sequence_number = quic_read_varint(bytes, offset);
        const auto retire_prior_to = quic_read_varint(bytes, offset);
        if (!sequence_number.has_value() || !retire_prior_to.has_value() || offset >= bytes.size()) {
            return false;
        }

        const auto connection_id_length = static_cast<std::size_t>(bytes[offset++]);
        return quic_skip_bytes(bytes, offset, connection_id_length) && quic_skip_bytes(bytes, offset, 16U);
    }
    case 0x1AU:
    case 0x1BU:
        return quic_skip_bytes(bytes, offset, 8U);
    case 0x1CU: {
        const auto error_code = quic_read_varint(bytes, offset);
        const auto triggering_frame_type = quic_read_varint(bytes, offset);
        const auto reason_length = quic_read_varint_size(bytes, offset);
        return error_code.has_value() && triggering_frame_type.has_value() &&
               reason_length.has_value() && quic_skip_bytes(bytes, offset, *reason_length);
    }
    case 0x1DU: {
        const auto error_code = quic_read_varint(bytes, offset);
        const auto reason_length = quic_read_varint_size(bytes, offset);
        return error_code.has_value() && reason_length.has_value() && quic_skip_bytes(bytes, offset, *reason_length);
    }
    case 0x1EU:
    case 0x01U:
        return true;
    default: {
        const auto extension_length = quic_read_varint_size(bytes, offset);
        if (extension_length.has_value()) {
            return quic_skip_bytes(bytes, offset, *extension_length);
        }
        return false;
    }
    }
}

std::optional<QuicFramePresenceSummary> summarize_quic_plaintext_frames(std::span<const std::uint8_t> bytes) {
    if (bytes.empty()) {
        return std::nullopt;
    }

    QuicFramePresenceSummary summary {};
    std::size_t offset = 0U;
    std::size_t frame_count = 0U;
    bool saw_non_padding = false;

    while (offset < bytes.size()) {
        const auto frame_type = bytes[offset++];
        if (frame_type == 0x00U) {
            if (++frame_count > kMaxQuicFrameSummaryCount) {
                return std::nullopt;
            }
            summary.padding = true;
            while (offset < bytes.size() && bytes[offset] == 0x00U) {
                ++offset;
            }
            continue;
        }

        if (++frame_count > kMaxQuicFrameSummaryCount) {
            return std::nullopt;
        }
        saw_non_padding = true;
        if (frame_type == 0x01U) {
            summary.ping = true;
            continue;
        }
        if (frame_type == 0x02U || frame_type == 0x03U) {
            summary.ack = true;
            if (!quic_skip_ack_frame(bytes, offset, frame_type == 0x03U)) {
                return std::nullopt;
            }
            continue;
        }
        if (frame_type == 0x06U) {
            summary.crypto = true;
            const auto crypto_offset = quic_read_varint(bytes, offset);
            const auto crypto_length = quic_read_varint_size(bytes, offset);
            if (!crypto_offset.has_value() || !crypto_length.has_value() || !quic_skip_bytes(bytes, offset, *crypto_length)) {
                return std::nullopt;
            }
            continue;
        }
        if (frame_type >= 0x08U && frame_type <= 0x0FU) {
            summary.zero_rtt = true;
            if (!quic_skip_stream_frame(bytes, offset, frame_type)) {
                return std::nullopt;
            }
            continue;
        }
        if (!quic_skip_frame_payload(bytes, offset, frame_type)) {
            return std::nullopt;
        }
    }

    if (!saw_non_padding && !summary.padding) {
        return std::nullopt;
    }

    return summary;
}

std::vector<QuicPresentationSemanticType> quic_semantics_from_summary(const QuicFramePresenceSummary& summary) {
    std::vector<QuicPresentationSemanticType> semantics {};
    if (summary.ack) {
        semantics.push_back(QuicPresentationSemanticType::ack);
    }
    if (summary.crypto) {
        semantics.push_back(QuicPresentationSemanticType::crypto);
    }
    if (summary.zero_rtt) {
        semantics.push_back(QuicPresentationSemanticType::zero_rtt);
    }
    if (summary.padding) {
        semantics.push_back(QuicPresentationSemanticType::padding);
    }
    if (summary.ping) {
        semantics.push_back(QuicPresentationSemanticType::ping);
    }
    return semantics;
}

std::vector<QuicSemanticItemInfo> quic_semantic_items_from_plaintext(std::span<const std::uint8_t> bytes) {
    std::vector<QuicSemanticItemInfo> items {};
    if (bytes.empty()) {
        return items;
    }

    std::size_t offset = 0U;
    std::size_t frame_count = 0U;
    while (offset < bytes.size()) {
        const auto frame_start = offset;
        const auto frame_type = bytes[offset++];
        if (frame_type == 0x00U) {
            if (++frame_count > kMaxQuicFrameSummaryCount) {
                return {};
            }
            while (offset < bytes.size() && bytes[offset] == 0x00U) {
                ++offset;
            }
            continue;
        }
        if (++frame_count > kMaxQuicFrameSummaryCount) {
            return {};
        }
        if (frame_type == 0x01U) {
            continue;
        }
        if (frame_type == 0x02U || frame_type == 0x03U) {
            if (!quic_skip_ack_frame(bytes, offset, frame_type == 0x03U)) {
                return {};
            }
            items.push_back(QuicSemanticItemInfo {
                .semantic = QuicPresentationSemanticType::ack,
                .byte_count = offset - frame_start,
            });
            continue;
        }
        if (frame_type == 0x06U) {
            const auto crypto_offset = quic_read_varint(bytes, offset);
            const auto crypto_length = quic_read_varint_size(bytes, offset);
            if (!crypto_offset.has_value() || !crypto_length.has_value() || !quic_skip_bytes(bytes, offset, *crypto_length)) {
                return {};
            }
            items.push_back(QuicSemanticItemInfo {
                .semantic = QuicPresentationSemanticType::crypto,
                .byte_count = offset - frame_start,
            });
            continue;
        }
        if (frame_type >= 0x08U && frame_type <= 0x0FU) {
            if (!quic_skip_stream_frame(bytes, offset, frame_type)) {
                return {};
            }
            items.push_back(QuicSemanticItemInfo {
                .semantic = QuicPresentationSemanticType::zero_rtt,
                .byte_count = offset - frame_start,
            });
            continue;
        }
        if (!quic_skip_frame_payload(bytes, offset, frame_type)) {
            return {};
        }
    }

    return items;
}

std::optional<TlsHandshakeDetails> parse_tls_handshake_from_quic_plaintext_payloads(
    std::span<const std::vector<std::uint8_t>> plaintext_payloads
) {
    QuicInitialParser initial_parser {};
    const auto crypto_prefix = initial_parser.extract_crypto_prefix_from_payloads(plaintext_payloads);
    if (!crypto_prefix.has_value()) {
        return std::nullopt;
    }

    return parse_tls_handshake_details(std::span<const std::uint8_t>(crypto_prefix->data(), crypto_prefix->size()));
}

std::optional<ParsedQuicPresentationPacket> parse_quic_presentation_packet(std::span<const std::uint8_t> udp_payload) {
    if (udp_payload.empty()) {
        return std::nullopt;
    }

    const auto first = udp_payload[0];
    const bool long_header = (first & 0x80U) != 0U;
    QuicInitialParser initial_parser {};

    if (!long_header) {
        if ((first & 0x40U) == 0U || udp_payload.size() < 4U) {
            return std::nullopt;
        }

        ParsedQuicPresentationPacket packet {};
        packet.shell_type = QuicPresentationShellType::protected_payload;
        packet.shell.header_form = "Short";
        packet.packet_bytes_consumed = udp_payload.size();
        return packet;
    }

    if (udp_payload.size() < 7U) {
        return std::nullopt;
    }

    ParsedQuicPresentationPacket packet {};
    packet.shell.header_form = "Long";
    packet.shell.version = read_be32(udp_payload, 1U);

    std::size_t offset = 5U;
    const auto dcid_length = static_cast<std::size_t>(udp_payload[offset++]);
    if (dcid_length > kMaxQuicConnectionIdLength || offset + dcid_length + 1U > udp_payload.size()) {
        return std::nullopt;
    }
    packet.shell.dcid.assign(
        udp_payload.begin() + static_cast<std::ptrdiff_t>(offset),
        udp_payload.begin() + static_cast<std::ptrdiff_t>(offset + dcid_length)
    );
    offset += dcid_length;

    const auto scid_length = static_cast<std::size_t>(udp_payload[offset++]);
    if (scid_length > kMaxQuicConnectionIdLength || offset + scid_length > udp_payload.size()) {
        return std::nullopt;
    }
    packet.shell.scid.assign(
        udp_payload.begin() + static_cast<std::ptrdiff_t>(offset),
        udp_payload.begin() + static_cast<std::ptrdiff_t>(offset + scid_length)
    );
    offset += scid_length;

    if (*packet.shell.version == 0U) {
        packet.shell_type = QuicPresentationShellType::version_negotiation;
        packet.packet_bytes_consumed = udp_payload.size();
        return packet;
    }

    if ((first & 0x40U) == 0U) {
        return std::nullopt;
    }

    const auto packet_type_bits = static_cast<std::uint8_t>((first >> 4U) & 0x03U);
    if (packet_type_bits == 0U) {
        packet.shell_type = QuicPresentationShellType::initial;
        const auto token_length = quic_read_varint_size(udp_payload, offset);
        if (!token_length.has_value() || !quic_skip_bytes(udp_payload, offset, *token_length)) {
            return std::nullopt;
        }
        packet.is_client_initial = initial_parser.is_client_initial_packet(udp_payload);
    } else if (packet_type_bits == 1U) {
        packet.shell_type = QuicPresentationShellType::zero_rtt;
    } else if (packet_type_bits == 2U) {
        packet.shell_type = QuicPresentationShellType::handshake;
    } else {
        packet.shell_type = QuicPresentationShellType::retry;
        if (udp_payload.size() < offset + 16U) {
            return std::nullopt;
        }
        packet.packet_bytes_consumed = udp_payload.size();
        return packet;
    }

    const auto length = quic_read_varint_size(udp_payload, offset);
    if (!length.has_value()) {
        return std::nullopt;
    }

    const auto packet_number_length = static_cast<std::size_t>((first & 0x03U) + 1U);
    if (offset + *length > udp_payload.size() || *length < packet_number_length) {
        return std::nullopt;
    }

    const auto frame_offset = offset + packet_number_length;
    const auto packet_end = offset + *length;
    if (frame_offset > packet_end) {
        return std::nullopt;
    }

    const auto plaintext_candidate = udp_payload.subspan(frame_offset, packet_end - frame_offset);
    packet.frame_summary = summarize_quic_plaintext_frames(plaintext_candidate);
    if (packet.frame_summary.has_value()) {
        packet.plaintext_payload_candidate.assign(plaintext_candidate.begin(), plaintext_candidate.end());
        if (packet.frame_summary->crypto) {
            const std::vector<std::vector<std::uint8_t>> plaintext_payloads {
                std::vector<std::uint8_t>(plaintext_candidate.begin(), plaintext_candidate.end())
            };
            packet.tls_handshake = parse_tls_handshake_from_quic_plaintext_payloads(
                std::span<const std::vector<std::uint8_t>>(plaintext_payloads.data(), plaintext_payloads.size())
            );
        }
    }

    if (packet.is_client_initial) {
        packet.sni = initial_parser.extract_client_initial_sni(udp_payload);
        if (!packet.tls_handshake.has_value()) {
            const auto crypto_prefix = initial_parser.extract_client_initial_crypto_prefix(udp_payload);
            if (crypto_prefix.has_value()) {
                packet.tls_handshake = parse_tls_handshake_details(
                    std::span<const std::uint8_t>(crypto_prefix->data(), crypto_prefix->size())
                );
            }
        }
    }

    packet.packet_bytes_consumed = packet_end;
    return packet;
}

std::vector<ParsedQuicPresentationPacket> parse_quic_presentation_datagram(std::span<const std::uint8_t> udp_payload) {
    std::vector<ParsedQuicPresentationPacket> packets {};
    std::size_t offset = 0U;

    while (offset < udp_payload.size()) {
        const auto parsed = parse_quic_presentation_packet(udp_payload.subspan(offset));
        if (!parsed.has_value() || parsed->packet_bytes_consumed == 0U) {
            if (packets.empty()) {
                return {};
            }
            break;
        }

        packets.push_back(*parsed);

        if (parsed->shell.header_form == "Short") {
            break;
        }

        offset += parsed->packet_bytes_consumed;
    }

    return packets;
}

std::optional<std::vector<std::uint8_t>> decrypt_quic_initial_plaintext_for_direction(
    QuicInitialParser& initial_parser,
    std::span<const std::uint8_t> udp_payload,
    const bool is_client_to_server,
    std::span<const std::uint8_t> initial_secret_connection_id = {}
) {
    return initial_parser.decrypt_initial_plaintext(
        udp_payload,
        !is_client_to_server,
        initial_secret_connection_id
    );
}

template <typename PacketList>
std::optional<std::vector<std::uint8_t>> find_quic_client_initial_connection_id_impl(
    const CaptureSession& session,
    const PacketList& packets,
    const std::optional<std::size_t> flow_index = std::nullopt
) {
    PacketPayloadService payload_service {};
    for (const auto& packet : packets) {
        if (packet.is_ip_fragmented) {
            continue;
        }

        const auto udp_payload = flow_index.has_value()
            ? session.read_selected_flow_transport_payload(*flow_index, packet)
            : [&]() {
                const auto packet_bytes = session.read_packet_data(packet);
                if (packet_bytes.empty()) {
                    return std::vector<std::uint8_t> {};
                }
                return payload_service.extract_transport_payload(packet_bytes, packet.data_link_type);
            }();
        if (udp_payload.empty()) {
            continue;
        }

        const auto datagram_packets = parse_quic_presentation_datagram(
            std::span<const std::uint8_t>(udp_payload.data(), udp_payload.size())
        );
        if (datagram_packets.empty()) {
            continue;
        }

        for (const auto& parsed_packet : datagram_packets) {
            if (parsed_packet.shell_type == QuicPresentationShellType::initial &&
                parsed_packet.is_client_initial &&
                !parsed_packet.shell.dcid.empty()) {
                return parsed_packet.shell.dcid;
            }
        }
    }

    return std::nullopt;
}

template <typename Connection>
std::optional<std::vector<std::uint8_t>> find_quic_client_initial_connection_id_for_connection_impl(
    const CaptureSession& session,
    const Connection& connection,
    const std::optional<std::size_t> flow_index = std::nullopt
) {
    std::vector<PacketRef> packets {};
    packets.reserve(connection.flow_a.packets.size() + connection.flow_b.packets.size());
    packets.insert(packets.end(), connection.flow_a.packets.begin(), connection.flow_a.packets.end());
    packets.insert(packets.end(), connection.flow_b.packets.begin(), connection.flow_b.packets.end());
    std::sort(packets.begin(), packets.end(), [](const PacketRef& lhs, const PacketRef& rhs) {
        return lhs.packet_index < rhs.packet_index;
    });
    return find_quic_client_initial_connection_id_impl(session, packets, flow_index);
}

template <typename PacketList>
std::optional<std::vector<std::size_t>> find_selected_packet_positions(
    const PacketList& packets,
    const std::vector<std::uint64_t>& selected_packet_indices
) {
    std::vector<std::size_t> positions {};
    positions.reserve(selected_packet_indices.size());
    for (const auto packet_index : selected_packet_indices) {
        const auto it = std::find_if(packets.begin(), packets.end(), [&](const PacketRef& packet) {
            return packet.packet_index == packet_index;
        });
        if (it == packets.end()) {
            return std::nullopt;
        }

        positions.push_back(static_cast<std::size_t>(std::distance(packets.begin(), it)));
    }

    return positions;
}

bool selected_packet_indices_are_covered(
    const std::vector<std::uint64_t>& selected_packet_indices,
    const std::vector<std::uint64_t>& owner_packet_indices
) noexcept {
    return std::all_of(selected_packet_indices.begin(), selected_packet_indices.end(), [&](const std::uint64_t packet_index) {
        return std::find(owner_packet_indices.begin(), owner_packet_indices.end(), packet_index) != owner_packet_indices.end();
    });
}

template <typename FlowKey>
bool is_quic_client_to_server(const FlowKey& flow_key) noexcept {
    return flow_key.src_port != kHttpsPort && flow_key.dst_port == kHttpsPort;
}

template <typename FlowKey>
std::optional<QuicPresentationResult> build_quic_presentation_for_selected_direction_impl(
    const CaptureSession& session,
    const FlowKey& flow_key,
    std::span<const PacketRef> packets,
    const std::vector<std::uint64_t>& selected_packet_indices,
    std::span<const std::uint8_t> initial_secret_connection_id = {},
    const std::optional<std::size_t> flow_index = std::nullopt
) {
    if (selected_packet_indices.empty()) {
        return std::nullopt;
    }

    const auto selected_positions = find_selected_packet_positions(packets, selected_packet_indices);
    if (!selected_positions.has_value() || selected_positions->empty()) {
        return std::nullopt;
    }
    const auto earliest_selected_position = *std::min_element(selected_positions->begin(), selected_positions->end());
    const auto scan_start_position = earliest_selected_position >= (kQuicPresentationPacketBudget - 1U)
        ? earliest_selected_position - (kQuicPresentationPacketBudget - 1U)
        : 0U;

    PacketPayloadService payload_service {};
    QuicInitialParser initial_parser {};
    std::vector<QuicPresentationCandidate> candidates {};
    candidates.reserve(kQuicPresentationPacketBudget);

    for (std::size_t position = scan_start_position;
         position < packets.size() && candidates.size() < kQuicPresentationPacketBudget;
         ++position) {
        const auto& packet = packets[position];
        if (packet.is_ip_fragmented) {
            continue;
        }

        const auto udp_payload = flow_index.has_value()
            ? session.read_selected_flow_transport_payload(*flow_index, packet)
            : [&]() {
                const auto packet_bytes = session.read_packet_data(packet);
                if (packet_bytes.empty()) {
                    return std::vector<std::uint8_t> {};
                }
                return payload_service.extract_transport_payload(packet_bytes, packet.data_link_type);
            }();
        if (udp_payload.empty()) {
            continue;
        }

        const auto datagram_packets = parse_quic_presentation_datagram(
            std::span<const std::uint8_t>(udp_payload.data(), udp_payload.size())
        );
        if (datagram_packets.empty()) {
            if (std::find(selected_packet_indices.begin(), selected_packet_indices.end(), packet.packet_index) != selected_packet_indices.end()) {
                return std::nullopt;
            }
            continue;
        }

        const auto parsed = datagram_packets.front();
        candidates.push_back(QuicPresentationCandidate {
            .packet = packet,
            .udp_payload = std::move(udp_payload),
            .parsed = parsed,
            .datagram_packets = datagram_packets,
        });
    }

    if (candidates.empty()) {
        return std::nullopt;
    }

    const auto anchor_it = std::find_if(candidates.begin(), candidates.end(), [&](const QuicPresentationCandidate& candidate) {
        return candidate.packet.packet_index == selected_packet_indices.front();
    });
    if (anchor_it == candidates.end()) {
        return std::nullopt;
    }
    const auto selected_packets_present = std::all_of(selected_packet_indices.begin(), selected_packet_indices.end(), [&](const std::uint64_t packet_index) {
        return std::find_if(candidates.begin(), candidates.end(), [&](const QuicPresentationCandidate& candidate) {
            return candidate.packet.packet_index == packet_index;
        }) != candidates.end();
    });
    if (!selected_packets_present) {
        return std::nullopt;
    }
    const auto anchor_position = static_cast<std::size_t>(std::distance(candidates.begin(), anchor_it));
    const bool client_to_server = is_quic_client_to_server(flow_key);

    QuicPresentationResult result {};
    result.shell_type = anchor_it->parsed.shell_type;
    result.shell = anchor_it->parsed.shell;
    result.selected_packet_indices = selected_packet_indices;
    for (std::size_t packet_index = 1U; packet_index < anchor_it->datagram_packets.size(); ++packet_index) {
        const auto shell_type = anchor_it->datagram_packets[packet_index].shell_type;
        if (shell_type == QuicPresentationShellType::none) {
            continue;
        }
        if (!quic_has_additional_shell_type(result, shell_type)) {
            result.additional_shell_types.push_back(shell_type);
        }
    }
    if (anchor_it->parsed.frame_summary.has_value()) {
        result.semantics = quic_semantics_from_summary(*anchor_it->parsed.frame_summary);
    }

    if (anchor_it->parsed.sni.has_value()) {
        result.sni = anchor_it->parsed.sni;
    }
    if (anchor_it->parsed.tls_handshake.has_value() && selected_packet_indices.size() == 1U) {
        result.tls_handshake = anchor_it->parsed.tls_handshake;
        result.crypto_packet_indices.push_back(anchor_it->packet.packet_index);
    }

    if (result.shell_type == QuicPresentationShellType::initial) {
        std::vector<std::vector<std::uint8_t>> crypto_plaintexts {};
        std::vector<std::uint64_t> crypto_packet_indices {};
        auto initial_start = anchor_position;
        while (initial_start > 0U && candidates[initial_start - 1U].parsed.shell_type == QuicPresentationShellType::initial) {
            --initial_start;
        }
        auto initial_end = anchor_position;
        while (initial_end + 1U < candidates.size() && candidates[initial_end + 1U].parsed.shell_type == QuicPresentationShellType::initial) {
            ++initial_end;
        }

        for (std::size_t position = initial_start; position <= initial_end; ++position) {
            const auto& candidate = candidates[position];
            const auto plaintext = decrypt_quic_initial_plaintext_for_direction(
                initial_parser,
                std::span<const std::uint8_t>(candidate.udp_payload.data(), candidate.udp_payload.size()),
                client_to_server,
                initial_secret_connection_id
            );
            if (!plaintext.has_value()) {
                continue;
            }

            const auto summary = summarize_quic_plaintext_frames(
                std::span<const std::uint8_t>(plaintext->data(), plaintext->size())
            );
            const bool is_anchor_packet = candidate.packet.packet_index == anchor_it->packet.packet_index;
            if (is_anchor_packet && summary.has_value()) {
                result.semantics = quic_semantics_from_summary(*summary);
            }

            if (!summary.has_value() || !summary->crypto) {
                continue;
            }

            if (is_anchor_packet && !result.tls_handshake.has_value()) {
                const std::vector<std::vector<std::uint8_t>> plaintext_payloads {*plaintext};
                if (const auto tls_handshake = parse_tls_handshake_from_quic_plaintext_payloads(
                        std::span<const std::vector<std::uint8_t>>(plaintext_payloads.data(), plaintext_payloads.size()));
                    tls_handshake.has_value()) {
                    result.tls_handshake = tls_handshake;
                    result.crypto_packet_indices = {candidate.packet.packet_index};
                }
            }

            crypto_plaintexts.push_back(*plaintext);
            crypto_packet_indices.push_back(candidate.packet.packet_index);
        }

        if (!crypto_plaintexts.empty()) {
            const auto payload_span = std::span<const std::vector<std::uint8_t>>(
                crypto_plaintexts.data(),
                crypto_plaintexts.size()
            );
            if (client_to_server &&
                !result.sni.has_value() &&
                selected_packet_indices_are_covered(selected_packet_indices, crypto_packet_indices)) {
                result.sni = initial_parser.extract_client_initial_sni_from_crypto_payloads(payload_span);
            }
            if (!result.tls_handshake.has_value()) {
                const auto crypto_prefix = initial_parser.extract_crypto_prefix_from_payloads(payload_span);
                if (crypto_prefix.has_value()) {
                    const auto tls_handshake = parse_tls_handshake_details(
                        std::span<const std::uint8_t>(crypto_prefix->data(), crypto_prefix->size())
                    );
                    if (tls_handshake.has_value() && selected_packet_indices_are_covered(selected_packet_indices, crypto_packet_indices)) {
                        result.tls_handshake = tls_handshake;
                        result.used_bounded_crypto_assembly = crypto_plaintexts.size() > 1U;
                        result.crypto_packet_indices = crypto_packet_indices;
                    }
                }
            }
        }
    }

    if (!result.tls_handshake.has_value()) {
        std::vector<std::vector<std::uint8_t>> plaintext_payloads {};
        std::vector<std::uint64_t> crypto_packet_indices {};
        for (const auto& candidate : candidates) {
            if (candidate.parsed.plaintext_payload_candidate.empty() ||
                !candidate.parsed.frame_summary.has_value() ||
                !candidate.parsed.frame_summary->crypto) {
                continue;
            }

            plaintext_payloads.push_back(candidate.parsed.plaintext_payload_candidate);
            crypto_packet_indices.push_back(candidate.packet.packet_index);
        }

        if (!plaintext_payloads.empty()) {
            const auto payload_span = std::span<const std::vector<std::uint8_t>>(
                plaintext_payloads.data(),
                plaintext_payloads.size()
            );
            const auto tls_handshake = parse_tls_handshake_from_quic_plaintext_payloads(payload_span);
            if (tls_handshake.has_value() && selected_packet_indices_are_covered(selected_packet_indices, crypto_packet_indices)) {
                result.tls_handshake = tls_handshake;
                result.used_bounded_crypto_assembly = plaintext_payloads.size() > 1U;
                result.crypto_packet_indices = crypto_packet_indices;
            }
        }
    }

    return result;
}

std::optional<std::string> merge_quic_protocol_text(
    const std::optional<std::string>& base_protocol_text,
    const std::optional<std::string>& enrichment_text
) {
    if ((!base_protocol_text.has_value() || base_protocol_text->empty()) &&
        (!enrichment_text.has_value() || enrichment_text->empty())) {
        return std::nullopt;
    }
    if (!enrichment_text.has_value() || enrichment_text->empty()) {
        return base_protocol_text;
    }
    if (!base_protocol_text.has_value() || base_protocol_text->empty()) {
        return enrichment_text;
    }
    if (base_protocol_text->find(*enrichment_text) != std::string::npos) {
        return base_protocol_text;
    }

    return *base_protocol_text + "\n" + *enrichment_text;
}

template <typename FlowKey>
QuicStreamPacketPresentation build_quic_stream_packet_presentation_impl(
    const CaptureSession& session,
    const std::size_t flow_index,
    const FlowKey& flow_key,
    std::span<const PacketRef> flow_packets,
    const PacketRef& packet,
    std::span<const std::uint8_t> payload_span,
    std::span<const std::uint8_t> initial_secret_connection_id
) {
    const auto context_result = build_quic_presentation_for_selected_direction_impl(
        session,
        flow_key,
        flow_packets,
        std::vector<std::uint64_t> {packet.packet_index},
        initial_secret_connection_id,
        flow_index
    );
    const auto datagram_packets = parse_quic_presentation_datagram(payload_span);

    if (datagram_packets.empty()) {
        return {};
    }

    QuicStreamPacketPresentation presentation {};
    presentation.handled = true;

    const auto context_enrichment = context_result.has_value()
        ? format_quic_presentation_enrichment(*context_result)
        : std::optional<std::string> {};
    const bool client_to_server = is_quic_client_to_server(flow_key);
    QuicInitialParser initial_parser {};

    std::size_t packet_offset = 0U;
    for (const auto& parsed_packet : datagram_packets) {
        const auto packet_slice_length = std::min(parsed_packet.packet_bytes_consumed, payload_span.size() - packet_offset);
        const auto packet_slice = payload_span.subspan(packet_offset, packet_slice_length);
        packet_offset += packet_slice_length;

        if (parsed_packet.shell_type == QuicPresentationShellType::initial) {
            QuicPresentationResult aggregate_result {};
            aggregate_result.shell_type = parsed_packet.shell_type;
            aggregate_result.shell = parsed_packet.shell;
            aggregate_result.selected_packet_indices = {packet.packet_index};
            aggregate_result.sni = context_result.has_value() ? context_result->sni : std::optional<std::string> {};
            aggregate_result.tls_handshake = context_result.has_value() ? context_result->tls_handshake : std::optional<TlsHandshakeDetails> {};
            aggregate_result.crypto_packet_indices = context_result.has_value() ? context_result->crypto_packet_indices : std::vector<std::uint64_t> {};
            aggregate_result.used_bounded_crypto_assembly = context_result.has_value() && context_result->used_bounded_crypto_assembly;

            std::optional<QuicFramePresenceSummary> aggregate_summary = parsed_packet.frame_summary;
            std::vector<QuicSemanticItemInfo> semantic_items = quic_semantic_items_from_plaintext(parsed_packet.plaintext_payload_candidate);
            if (!aggregate_summary.has_value() || semantic_items.empty()) {
                const auto plaintext = decrypt_quic_initial_plaintext_for_direction(
                    initial_parser,
                    packet_slice,
                    client_to_server,
                    initial_secret_connection_id
                );
                if (plaintext.has_value()) {
                    aggregate_summary = summarize_quic_plaintext_frames(
                        std::span<const std::uint8_t>(plaintext->data(), plaintext->size())
                    );
                    semantic_items = quic_semantic_items_from_plaintext(
                        std::span<const std::uint8_t>(plaintext->data(), plaintext->size())
                    );
                }
            }

            if (aggregate_summary.has_value()) {
                aggregate_result.semantics = quic_semantics_from_summary(*aggregate_summary);
            }

            const auto protocol_text = merge_quic_protocol_text(
                format_quic_presentation_protocol_text(aggregate_result),
                context_enrichment
            );

            if (!semantic_items.empty()) {
                for (const auto& semantic_item : semantic_items) {
                    QuicPresentationResult label_result {};
                    label_result.shell_type = parsed_packet.shell_type;
                    label_result.shell = parsed_packet.shell;
                    label_result.semantics = {semantic_item.semantic};
                    presentation.items.push_back(QuicStreamPacketItem {
                        .label = quic_stream_label_from_result(label_result),
                        .byte_count = semantic_item.byte_count > 0U ? semantic_item.byte_count : packet_slice_length,
                        .protocol_text = protocol_text.value_or(std::string {}),
                    });
                }
                continue;
            }

            if (should_emit_quic_stream_item(aggregate_result)) {
                presentation.items.push_back(QuicStreamPacketItem {
                    .label = quic_stream_label_from_result(aggregate_result),
                    .byte_count = packet_slice_length,
                    .protocol_text = protocol_text.value_or(std::string {}),
                });
            }
            continue;
        }

        QuicPresentationResult result {};
        result.shell_type = parsed_packet.shell_type;
        result.shell = parsed_packet.shell;
        if (parsed_packet.frame_summary.has_value()) {
            result.semantics = quic_semantics_from_summary(*parsed_packet.frame_summary);
        }
        result.selected_packet_indices = {packet.packet_index};
        result.sni = parsed_packet.sni;
        result.tls_handshake = parsed_packet.tls_handshake;

        if (!should_emit_quic_stream_item(result)) {
            continue;
        }

        const auto protocol_text = format_quic_presentation_protocol_text(result);
        presentation.items.push_back(QuicStreamPacketItem {
            .label = quic_stream_label_from_result(result),
            .byte_count = packet_slice_length,
            .protocol_text = protocol_text.value_or(std::string {}),
        });
    }

    return presentation;
}

}  // namespace

std::optional<std::vector<std::uint8_t>> find_quic_client_initial_connection_id_for_connection(
    const CaptureSession& session,
    const ConnectionV4& connection,
    const std::optional<std::size_t> flow_index
) {
    return find_quic_client_initial_connection_id_for_connection_impl(session, connection, flow_index);
}

std::optional<std::vector<std::uint8_t>> find_quic_client_initial_connection_id_for_connection(
    const CaptureSession& session,
    const ConnectionV6& connection,
    const std::optional<std::size_t> flow_index
) {
    return find_quic_client_initial_connection_id_for_connection_impl(session, connection, flow_index);
}

std::optional<QuicPresentationResult> build_quic_presentation_for_selected_direction(
    const CaptureSession& session,
    const FlowKeyV4& flow_key,
    std::span<const PacketRef> packets,
    const std::vector<std::uint64_t>& selected_packet_indices,
    std::span<const std::uint8_t> initial_secret_connection_id,
    const std::optional<std::size_t> flow_index
) {
    return build_quic_presentation_for_selected_direction_impl(
        session,
        flow_key,
        packets,
        selected_packet_indices,
        initial_secret_connection_id,
        flow_index
    );
}

std::optional<QuicPresentationResult> build_quic_presentation_for_selected_direction(
    const CaptureSession& session,
    const FlowKeyV6& flow_key,
    std::span<const PacketRef> packets,
    const std::vector<std::uint64_t>& selected_packet_indices,
    std::span<const std::uint8_t> initial_secret_connection_id,
    const std::optional<std::size_t> flow_index
) {
    return build_quic_presentation_for_selected_direction_impl(
        session,
        flow_key,
        packets,
        selected_packet_indices,
        initial_secret_connection_id,
        flow_index
    );
}

std::optional<std::string> format_quic_presentation_protocol_text(const QuicPresentationResult& result) {
    if (result.shell_type == QuicPresentationShellType::none) {
        return std::nullopt;
    }

    std::ostringstream text {};
    text << "QUIC\n"
         << "  Header Form: " << result.shell.header_form << "\n"
         << "  Packet Type: " << quic_shell_type_text(result.shell_type);

    if (result.shell.version.has_value()) {
        text << "\n"
             << "  Version: " << quic_version_text(*result.shell.version);
    }

    if (!result.shell.dcid.empty()) {
        text << "\n"
             << "  Destination Connection ID Length: " << result.shell.dcid.size() << "\n"
             << "  Destination Connection ID: " << quic_hex_text(std::span<const std::uint8_t>(result.shell.dcid.data(), result.shell.dcid.size()));
    }

    if (!result.shell.scid.empty()) {
        text << "\n"
             << "  Source Connection ID Length: " << result.shell.scid.size() << "\n"
             << "  Source Connection ID: " << quic_hex_text(std::span<const std::uint8_t>(result.shell.scid.data(), result.shell.scid.size()));
    }

    if (const auto semantics_text = quic_semantics_text(result); !semantics_text.empty()) {
        text << "\n"
             << "  Frame Presence: " << semantics_text;
    }

    if (!result.additional_shell_types.empty()) {
        text << "\n"
             << "  Additional Packet Types: ";
        for (std::size_t index = 0U; index < result.additional_shell_types.size(); ++index) {
            if (index > 0U) {
                text << ", ";
            }
            text << quic_shell_type_text(result.additional_shell_types[index]);
        }
    }

    if (const auto enrichment = format_quic_presentation_enrichment(result); enrichment.has_value() && !enrichment->empty()) {
        text << "\n" << *enrichment;
    }

    return text.str();
}

std::optional<std::string> format_quic_presentation_enrichment(const QuicPresentationResult& result) {
    std::ostringstream text {};
    bool wrote_any = false;

    if (result.sni.has_value() && !result.sni->empty()) {
        text << "  SNI: " << *result.sni;
        wrote_any = true;
    }

    if (result.tls_handshake.has_value()) {
        if (wrote_any) {
            text << '\n';
        }
        text << "  TLS Handshake Type: " << result.tls_handshake->handshake_type_text << "\n"
             << "  TLS Handshake Length: " << result.tls_handshake->handshake_length;
        if (!result.tls_handshake->details_text.empty()) {
            text << "\n" << result.tls_handshake->details_text;
        }
        wrote_any = true;
    }

    if (!wrote_any) {
        return std::nullopt;
    }

    return text.str();
}

QuicStreamPacketPresentation build_quic_stream_packet_presentation(
    const CaptureSession& session,
    const std::size_t flow_index,
    const FlowKeyV4& flow_key,
    std::span<const PacketRef> flow_packets,
    const PacketRef& packet,
    std::span<const std::uint8_t> payload_span,
    std::span<const std::uint8_t> initial_secret_connection_id
) {
    return build_quic_stream_packet_presentation_impl(
        session,
        flow_index,
        flow_key,
        flow_packets,
        packet,
        payload_span,
        initial_secret_connection_id
    );
}

QuicStreamPacketPresentation build_quic_stream_packet_presentation(
    const CaptureSession& session,
    const std::size_t flow_index,
    const FlowKeyV6& flow_key,
    std::span<const PacketRef> flow_packets,
    const PacketRef& packet,
    std::span<const std::uint8_t> payload_span,
    std::span<const std::uint8_t> initial_secret_connection_id
) {
    return build_quic_stream_packet_presentation_impl(
        session,
        flow_index,
        flow_key,
        flow_packets,
        packet,
        payload_span,
        initial_secret_connection_id
    );
}

}  // namespace pfl::session_detail
