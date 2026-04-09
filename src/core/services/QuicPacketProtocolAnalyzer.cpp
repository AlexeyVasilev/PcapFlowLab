#include "core/services/QuicPacketProtocolAnalyzer.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <limits>
#include <optional>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include "core/decode/PacketDecodeSupport.h"
#include "core/io/LinkType.h"
#include "core/services/PacketPayloadService.h"
#include "core/services/QuicInitialParser.h"
#include "core/services/TlsHandshakeDetails.h"

namespace pfl {

namespace {

constexpr std::uint16_t kHttpsPort = 443U;
constexpr std::size_t kMaxConnectionIdLength = 20U;
constexpr std::size_t kMaxFrameSummaryBytes = 512U;
constexpr std::size_t kMaxFrameSummaryCount = 32U;

std::uint32_t read_be32(std::span<const std::uint8_t> bytes, const std::size_t offset) {
    return (static_cast<std::uint32_t>(bytes[offset]) << 24U) |
           (static_cast<std::uint32_t>(bytes[offset + 1U]) << 16U) |
           (static_cast<std::uint32_t>(bytes[offset + 2U]) << 8U) |
           static_cast<std::uint32_t>(bytes[offset + 3U]);
}

std::optional<std::uint64_t> read_varint(std::span<const std::uint8_t> bytes, std::size_t& offset) {
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

std::optional<std::size_t> read_varint_size(std::span<const std::uint8_t> bytes, std::size_t& offset) {
    const auto value = read_varint(bytes, offset);
    if (!value.has_value() || *value > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
        return std::nullopt;
    }

    return static_cast<std::size_t>(*value);
}

bool skip_bytes(std::span<const std::uint8_t> bytes, std::size_t& offset, const std::size_t count) {
    if (offset + count > bytes.size()) {
        return false;
    }

    offset += count;
    return true;
}

bool skip_ack_frame(std::span<const std::uint8_t> bytes, std::size_t& offset, const bool has_ecn) {
    const auto largest_ack = read_varint(bytes, offset);
    const auto ack_delay = read_varint(bytes, offset);
    const auto ack_range_count = read_varint_size(bytes, offset);
    const auto first_ack_range = read_varint(bytes, offset);
    if (!largest_ack.has_value() || !ack_delay.has_value() || !ack_range_count.has_value() || !first_ack_range.has_value()) {
        return false;
    }

    for (std::size_t index = 0U; index < *ack_range_count; ++index) {
        const auto gap = read_varint(bytes, offset);
        const auto ack_range_length = read_varint(bytes, offset);
        if (!gap.has_value() || !ack_range_length.has_value()) {
            return false;
        }
    }

    if (!has_ecn) {
        return true;
    }

    const auto ect0_count = read_varint(bytes, offset);
    const auto ect1_count = read_varint(bytes, offset);
    const auto ecn_ce_count = read_varint(bytes, offset);
    return ect0_count.has_value() && ect1_count.has_value() && ecn_ce_count.has_value();
}

bool skip_stream_frame(std::span<const std::uint8_t> bytes, std::size_t& offset, const std::uint8_t frame_type) {
    if (!read_varint(bytes, offset).has_value()) {
        return false;
    }

    const bool has_offset = (frame_type & 0x04U) != 0U;
    const bool has_length = (frame_type & 0x02U) != 0U;
    if (has_offset && !read_varint(bytes, offset).has_value()) {
        return false;
    }

    if (!has_length) {
        offset = bytes.size();
        return true;
    }

    const auto length = read_varint_size(bytes, offset);
    return length.has_value() && skip_bytes(bytes, offset, *length);
}

bool skip_frame_payload(std::span<const std::uint8_t> bytes, std::size_t& offset, const std::uint8_t frame_type) {
    switch (frame_type) {
    case 0x02U:
        return skip_ack_frame(bytes, offset, false);
    case 0x03U:
        return skip_ack_frame(bytes, offset, true);
    case 0x04U:
        return read_varint(bytes, offset).has_value() &&
               read_varint(bytes, offset).has_value() &&
               read_varint(bytes, offset).has_value();
    case 0x05U:
        return read_varint(bytes, offset).has_value() && read_varint(bytes, offset).has_value();
    case 0x07U: {
        const auto token_length = read_varint_size(bytes, offset);
        return token_length.has_value() && skip_bytes(bytes, offset, *token_length);
    }
    case 0x08U:
    case 0x09U:
    case 0x0AU:
    case 0x0BU:
    case 0x0CU:
    case 0x0DU:
    case 0x0EU:
    case 0x0FU:
        return skip_stream_frame(bytes, offset, frame_type);
    case 0x10U:
    case 0x12U:
    case 0x13U:
    case 0x14U:
    case 0x16U:
    case 0x17U:
    case 0x19U:
        return read_varint(bytes, offset).has_value();
    case 0x11U:
    case 0x15U:
        return read_varint(bytes, offset).has_value() && read_varint(bytes, offset).has_value();
    case 0x18U: {
        const auto sequence_number = read_varint(bytes, offset);
        const auto retire_prior_to = read_varint(bytes, offset);
        if (!sequence_number.has_value() || !retire_prior_to.has_value() || offset >= bytes.size()) {
            return false;
        }

        const auto connection_id_length = static_cast<std::size_t>(bytes[offset++]);
        return skip_bytes(bytes, offset, connection_id_length) && skip_bytes(bytes, offset, 16U);
    }
    case 0x1AU:
    case 0x1BU:
        return skip_bytes(bytes, offset, 8U);
    case 0x1CU: {
        const auto error_code = read_varint(bytes, offset);
        const auto triggering_frame_type = read_varint(bytes, offset);
        const auto reason_length = read_varint_size(bytes, offset);
        return error_code.has_value() && triggering_frame_type.has_value() &&
               reason_length.has_value() && skip_bytes(bytes, offset, *reason_length);
    }
    case 0x1DU: {
        const auto error_code = read_varint(bytes, offset);
        const auto reason_length = read_varint_size(bytes, offset);
        return error_code.has_value() && reason_length.has_value() && skip_bytes(bytes, offset, *reason_length);
    }
    case 0x1EU:
    case 0x01U:
        return true;
    default: {
        const auto extension_length = read_varint_size(bytes, offset);
        if (extension_length.has_value()) {
            return skip_bytes(bytes, offset, *extension_length);
        }
        return false;
    }
    }
}

std::string hex_text(std::span<const std::uint8_t> bytes, const std::size_t max_bytes = 8U) {
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

struct FramePresenceSummary {
    bool ack {false};
    bool crypto {false};
    bool padding {false};
    bool stream {false};
};

std::optional<FramePresenceSummary> summarize_plaintext_frames(std::span<const std::uint8_t> bytes) {
    if (bytes.empty() || bytes.size() > kMaxFrameSummaryBytes) {
        return std::nullopt;
    }

    FramePresenceSummary summary {};
    std::size_t offset = 0U;
    std::size_t frame_count = 0U;
    bool saw_non_padding = false;

    while (offset < bytes.size()) {
        if (++frame_count > kMaxFrameSummaryCount) {
            return std::nullopt;
        }

        const auto frame_type = bytes[offset++];
        if (frame_type == 0x00U) {
            summary.padding = true;
            continue;
        }

        saw_non_padding = true;
        if (frame_type == 0x02U || frame_type == 0x03U) {
            summary.ack = true;
            if (!skip_ack_frame(bytes, offset, frame_type == 0x03U)) {
                return std::nullopt;
            }
            continue;
        }

        if (frame_type == 0x06U) {
            summary.crypto = true;
            const auto crypto_offset = read_varint(bytes, offset);
            const auto crypto_length = read_varint_size(bytes, offset);
            if (!crypto_offset.has_value() || !crypto_length.has_value() || !skip_bytes(bytes, offset, *crypto_length)) {
                return std::nullopt;
            }
            continue;
        }

        if (frame_type >= 0x08U && frame_type <= 0x0FU) {
            summary.stream = true;
            if (!skip_stream_frame(bytes, offset, frame_type)) {
                return std::nullopt;
            }
            continue;
        }

        if (!skip_frame_payload(bytes, offset, frame_type)) {
            return std::nullopt;
        }
    }

    if (!saw_non_padding && !summary.padding) {
        return std::nullopt;
    }

    return summary;
}

std::string frame_presence_text(const FramePresenceSummary& summary) {
    std::vector<std::string> labels {};
    if (summary.ack) {
        labels.emplace_back("ACK");
    }
    if (summary.crypto) {
        labels.emplace_back("CRYPTO");
    }
    if (summary.padding) {
        labels.emplace_back("PADDING");
    }
    if (summary.stream) {
        labels.emplace_back("STREAM");
    }

    if (labels.empty()) {
        return {};
    }

    std::ostringstream text {};
    for (std::size_t index = 0U; index < labels.size(); ++index) {
        if (index > 0U) {
            text << ", ";
        }
        text << labels[index];
    }
    return text.str();
}

struct ParsedQuicPacket {
    std::string header_form {};
    std::string packet_type {};
    std::uint32_t version {0U};
    bool has_version {false};
    std::vector<std::uint8_t> dcid {};
    std::vector<std::uint8_t> scid {};
    std::vector<std::uint32_t> supported_versions {};
    std::optional<FramePresenceSummary> frame_summary {};
    std::optional<std::string> sni {};
    std::optional<TlsHandshakeDetails> tls_handshake {};
};

std::optional<TlsHandshakeDetails> parse_tls_handshake_from_plaintext_payloads(
    std::span<const std::vector<std::uint8_t>> plaintext_payloads
) {
    QuicInitialParser initial_parser {};
    const auto crypto_prefix = initial_parser.extract_crypto_prefix_from_payloads(plaintext_payloads);
    if (!crypto_prefix.has_value()) {
        return std::nullopt;
    }

    const auto handshake = parse_tls_handshake_details(std::span<const std::uint8_t>(crypto_prefix->data(), crypto_prefix->size()));
    if (!handshake.has_value() || handshake->details_text.empty()) {
        return std::nullopt;
    }

    return handshake;
}

std::optional<ParsedQuicPacket> parse_quic_payload(std::span<const std::uint8_t> udp_payload) {
    if (udp_payload.empty()) {
        return std::nullopt;
    }

    const auto first = udp_payload[0];
    const bool long_header = (first & 0x80U) != 0U;

    if (!long_header) {
        if ((first & 0x40U) == 0U || udp_payload.size() < 4U) {
            return std::nullopt;
        }

        return ParsedQuicPacket {
            .header_form = "Short",
            .packet_type = "Protected Payload",
        };
    }

    if (udp_payload.size() < 7U) {
        return std::nullopt;
    }

    ParsedQuicPacket packet {
        .header_form = "Long",
        .version = read_be32(udp_payload, 1U),
        .has_version = true,
    };

    std::size_t offset = 5U;
    const auto dcid_length = static_cast<std::size_t>(udp_payload[offset++]);
    if (dcid_length > kMaxConnectionIdLength || offset + dcid_length + 1U > udp_payload.size()) {
        return std::nullopt;
    }
    packet.dcid.assign(udp_payload.begin() + static_cast<std::ptrdiff_t>(offset),
                       udp_payload.begin() + static_cast<std::ptrdiff_t>(offset + dcid_length));
    offset += dcid_length;

    const auto scid_length = static_cast<std::size_t>(udp_payload[offset++]);
    if (scid_length > kMaxConnectionIdLength || offset + scid_length > udp_payload.size()) {
        return std::nullopt;
    }
    packet.scid.assign(udp_payload.begin() + static_cast<std::ptrdiff_t>(offset),
                       udp_payload.begin() + static_cast<std::ptrdiff_t>(offset + scid_length));
    offset += scid_length;

    if (packet.version == 0U) {
        packet.packet_type = "Version Negotiation";
        while (offset + 4U <= udp_payload.size()) {
            packet.supported_versions.push_back(read_be32(udp_payload, offset));
            offset += 4U;
        }
        return packet;
    }

    if ((first & 0x40U) == 0U) {
        return std::nullopt;
    }

    const auto packet_type_bits = static_cast<std::uint8_t>((first >> 4U) & 0x03U);
    if (packet_type_bits == 0U) {
        packet.packet_type = "Initial";
        const auto token_length = read_varint_size(udp_payload, offset);
        if (!token_length.has_value() || !skip_bytes(udp_payload, offset, *token_length)) {
            return std::nullopt;
        }
    } else if (packet_type_bits == 1U) {
        packet.packet_type = "Protected Payload";
    } else if (packet_type_bits == 2U) {
        packet.packet_type = "Handshake";
    } else {
        packet.packet_type = "Retry";
        if (udp_payload.size() < offset + 16U) {
            return std::nullopt;
        }
        return packet;
    }

    const auto length = read_varint_size(udp_payload, offset);
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
    packet.frame_summary = summarize_plaintext_frames(plaintext_candidate);
    if (packet.frame_summary.has_value() && packet.frame_summary->crypto && !plaintext_candidate.empty()) {
        const std::vector<std::vector<std::uint8_t>> plaintext_payloads {
            std::vector<std::uint8_t>(plaintext_candidate.begin(), plaintext_candidate.end())
        };
        packet.tls_handshake = parse_tls_handshake_from_plaintext_payloads(plaintext_payloads);
    }

    if (packet.packet_type == "Initial") {
        QuicInitialParser initial_parser {};
        if (initial_parser.is_client_initial_packet(udp_payload)) {
            packet.sni = initial_parser.extract_client_initial_sni(udp_payload);
            if (!packet.tls_handshake.has_value()) {
                const auto crypto_prefix = initial_parser.extract_client_initial_crypto_prefix(udp_payload);
                if (crypto_prefix.has_value()) {
                    const auto handshake = parse_tls_handshake_details(
                        std::span<const std::uint8_t>(crypto_prefix->data(), crypto_prefix->size())
                    );
                    if (handshake.has_value() && !handshake->details_text.empty()) {
                        packet.tls_handshake = handshake;
                    }
                }
            }
        }
    }

    return packet;
}

struct UdpPayloadView {
    std::uint16_t src_port {0U};
    std::uint16_t dst_port {0U};
    std::span<const std::uint8_t> payload {};
};

std::optional<UdpPayloadView> extract_udp_payload_view(std::span<const std::uint8_t> packet_bytes, const std::uint32_t data_link_type) {
    const auto envelope = detail::parse_link_layer_payload(packet_bytes, data_link_type);
    if (!envelope.has_value()) {
        return std::nullopt;
    }

    if (envelope->protocol_type == detail::kEtherTypeIpv4) {
        const auto ipv4_offset = envelope->payload_offset;
        if (packet_bytes.size() < ipv4_offset + detail::kIpv4MinimumHeaderSize) {
            return std::nullopt;
        }

        const auto version = static_cast<std::uint8_t>(packet_bytes[ipv4_offset] >> 4U);
        const auto ihl = static_cast<std::size_t>((packet_bytes[ipv4_offset] & 0x0FU) * 4U);
        const auto total_length = static_cast<std::size_t>(detail::read_be16(packet_bytes, ipv4_offset + 2U));
        if (version != 4U || ihl < detail::kIpv4MinimumHeaderSize || total_length < ihl) {
            return std::nullopt;
        }

        const auto packet_end = ipv4_offset + total_length;
        if (packet_bytes.size() < packet_end) {
            return std::nullopt;
        }

        const auto flags_fragment = detail::read_be16(packet_bytes, ipv4_offset + 6U);
        if ((flags_fragment & 0x3FFFU) != 0U || packet_bytes[ipv4_offset + 9U] != detail::kIpProtocolUdp) {
            return std::nullopt;
        }

        const auto udp_offset = ipv4_offset + ihl;
        if (udp_offset + detail::kUdpHeaderSize > packet_end) {
            return std::nullopt;
        }

        const auto udp_length = static_cast<std::size_t>(detail::read_be16(packet_bytes, udp_offset + 4U));
        if (udp_length < detail::kUdpHeaderSize || udp_offset + udp_length > packet_end) {
            return std::nullopt;
        }

        return UdpPayloadView {
            .src_port = detail::read_be16(packet_bytes, udp_offset),
            .dst_port = detail::read_be16(packet_bytes, udp_offset + 2U),
            .payload = packet_bytes.subspan(udp_offset + detail::kUdpHeaderSize, udp_length - detail::kUdpHeaderSize),
        };
    }

    if (envelope->protocol_type == detail::kEtherTypeIpv6) {
        const auto ipv6_offset = envelope->payload_offset;
        if (packet_bytes.size() < ipv6_offset + detail::kIpv6HeaderSize) {
            return std::nullopt;
        }

        const auto version = static_cast<std::uint8_t>(packet_bytes[ipv6_offset] >> 4U);
        if (version != 6U) {
            return std::nullopt;
        }

        const auto ipv6_payload_length = static_cast<std::size_t>(detail::read_be16(packet_bytes, ipv6_offset + 4U));
        const auto packet_end = ipv6_offset + detail::kIpv6HeaderSize + ipv6_payload_length;
        if (packet_bytes.size() < packet_end) {
            return std::nullopt;
        }

        const auto payload = detail::parse_ipv6_payload(packet_bytes, ipv6_offset);
        if (!payload.has_value() || payload->has_fragment_header || payload->next_header != detail::kIpProtocolUdp) {
            return std::nullopt;
        }
        if (payload->payload_offset + detail::kUdpHeaderSize > packet_end) {
            return std::nullopt;
        }

        const auto udp_length = static_cast<std::size_t>(detail::read_be16(packet_bytes, payload->payload_offset + 4U));
        if (udp_length < detail::kUdpHeaderSize || payload->payload_offset + udp_length > packet_end) {
            return std::nullopt;
        }

        return UdpPayloadView {
            .src_port = detail::read_be16(packet_bytes, payload->payload_offset),
            .dst_port = detail::read_be16(packet_bytes, payload->payload_offset + 2U),
            .payload = packet_bytes.subspan(payload->payload_offset + detail::kUdpHeaderSize, udp_length - detail::kUdpHeaderSize),
        };
    }

    return std::nullopt;
}

bool likely_quic_ports(const std::uint16_t src_port, const std::uint16_t dst_port) noexcept {
    return src_port == kHttpsPort || dst_port == kHttpsPort;
}

std::string protocol_text_from_packet(const ParsedQuicPacket& packet) {
    std::ostringstream text {};
    text << "QUIC\n"
         << "  Header Form: " << packet.header_form << "\n"
         << "  Packet Type: " << packet.packet_type;

    if (packet.has_version) {
        text << "\n"
             << "  Version: " << quic_version_text(packet.version);
    }

    if (!packet.dcid.empty() || packet.header_form == "Long") {
        text << "\n"
             << "  Destination Connection ID Length: " << packet.dcid.size();
        if (!packet.dcid.empty()) {
            text << "\n"
                 << "  Destination Connection ID: " << hex_text(packet.dcid);
        }
    }

    if (!packet.scid.empty() || packet.header_form == "Long") {
        text << "\n"
             << "  Source Connection ID Length: " << packet.scid.size();
        if (!packet.scid.empty()) {
            text << "\n"
                 << "  Source Connection ID: " << hex_text(packet.scid);
        }
    }

    if (!packet.supported_versions.empty()) {
        text << "\n"
             << "  Supported Versions: ";
        for (std::size_t index = 0U; index < packet.supported_versions.size(); ++index) {
            if (index > 0U) {
                text << ", ";
            }
            text << quic_version_text(packet.supported_versions[index]);
        }
    }

    if (packet.frame_summary.has_value()) {
        const auto summary_text = frame_presence_text(*packet.frame_summary);
        if (!summary_text.empty()) {
            text << "\n"
                 << "  Frame Presence: " << summary_text;
        }
    }

    if (packet.sni.has_value()) {
        text << "\n"
             << "  SNI: " << *packet.sni;
    }

    if (packet.tls_handshake.has_value()) {
        text << "\n"
             << "  TLS Handshake Type: " << packet.tls_handshake->handshake_type_text << "\n"
             << "  TLS Handshake Length: " << packet.tls_handshake->handshake_length;
        if (!packet.tls_handshake->details_text.empty()) {
            text << "\n" << packet.tls_handshake->details_text;
        }
    }

    return text.str();
}

}  // namespace

std::optional<std::string> QuicPacketProtocolAnalyzer::analyze(std::span<const std::uint8_t> packet_bytes) const {
    return analyze(packet_bytes, kLinkTypeEthernet);
}

std::optional<std::string> QuicPacketProtocolAnalyzer::analyze(std::span<const std::uint8_t> packet_bytes, const std::uint32_t data_link_type) const {
    const auto udp_view = extract_udp_payload_view(packet_bytes, data_link_type);
    if (!udp_view.has_value() || !likely_quic_ports(udp_view->src_port, udp_view->dst_port)) {
        return std::nullopt;
    }

    return analyze_udp_payload(udp_view->payload);
}

std::optional<std::string> QuicPacketProtocolAnalyzer::analyze_udp_payload(std::span<const std::uint8_t> udp_payload) const {
    const auto packet = parse_quic_payload(udp_payload);
    if (!packet.has_value()) {
        return std::nullopt;
    }

    return protocol_text_from_packet(*packet);
}

}  // namespace pfl