#include "app/session/CaptureSession.h"
#include "app/session/SessionFlowHelpers.h"
#include "app/session/SessionFormatting.h"
#include "app/session/SessionOpenHelpers.h"

#include <algorithm>
#include <cassert>
#include <chrono>
#include <array>
#include <iostream>
#include <iomanip>
#include <limits>
#include <map>
#include <span>
#include <sstream>
#include <string_view>
#include <tuple>

#include "../../../core/open_context.h"
#include "core/debug_logging.h"
#include "core/index/CaptureIndex.h"
#include "core/index/CaptureIndexReader.h"
#include "core/index/CaptureIndexWriter.h"
#include "core/reassembly/ReassemblyService.h"
#include "core/io/CaptureFilePacketReader.h"
#include "core/services/CaptureImporter.h"
#include "core/services/DnsPacketProtocolAnalyzer.h"
#include "core/services/FlowExportService.h"
#include "core/services/FlowAnalysisService.h"
#include "core/services/FlowHintService.h"
#include "core/services/HexDumpService.h"
#include "core/services/HttpPacketProtocolAnalyzer.h"
#include "core/services/PacketDetailsService.h"
#include "core/services/PacketPayloadService.h"
#include "core/services/PerfOpenLogger.h"
#include "core/services/QuicPacketProtocolAnalyzer.h"
#include "core/services/QuicInitialParser.h"
#include "core/services/TlsHandshakeDetails.h"
#include "core/services/TlsPacketProtocolAnalyzer.h"

namespace pfl {

namespace {

constexpr std::size_t kSelectedFlowPacketCacheMaxBytes = 16U * 1024U * 1024U;

using session_detail::ListedConnectionRef;
using session_detail::add_protocol_stats;
using session_detail::build_basic_protocol_details_text;
using session_detail::build_open_failure_message;
using session_detail::collect_packets;
using session_detail::fallback_open_failure;
using session_detail::format_endpoint;
using session_detail::format_ipv4_address;
using session_detail::format_ipv6_address;
using session_detail::format_packet_timestamp;
using session_detail::format_tcp_flags_text;
using session_detail::list_connections;
using session_detail::log_open_result;
using session_detail::make_flow_row;
using session_detail::packet_count;
using session_detail::protocol_id;
using session_detail::effective_protocol_hint;
using session_detail::total_bytes;

constexpr std::string_view kNoProtocolDetailsMessage = "No protocol-specific details available for this packet.";
constexpr std::string_view kUnavailableProtocolDetailsMessage = "Protocol details unavailable for this packet.";
constexpr std::string_view kFragmentedProtocolDetailsMessage = "Protocol details are unavailable for fragmented packets until reassembly is implemented.";
constexpr std::string_view kDirectionAToB = "A\xE2\x86\x92" "B";
constexpr std::string_view kDirectionBToA = "B\xE2\x86\x92" "A";
using SuspectedTcpRetransmissionFingerprint = std::tuple<
    std::uint8_t,
    std::uint32_t,
    std::uint32_t,
    std::uint32_t,
    std::uint64_t
>;

struct SeenTcpPayloadCandidate {
    std::uint64_t packet_index {0};
    std::vector<std::uint8_t> payload_bytes {};
};

struct DecodedTcpPayloadPacket {
    PacketRef packet {};
    std::uint64_t sequence_number {0};
    std::uint32_t acknowledgement_number {0};
    std::vector<std::uint8_t> payload_bytes {};
};

struct TcpContributionTracker {
    bool has_contiguous_stream {false};
    bool overlap_tracking_enabled {true};
    std::uint64_t base_sequence {0};
    std::uint64_t next_sequence {0};
    std::uint32_t last_acknowledgement_number {0};
    std::vector<std::uint8_t> contiguous_bytes {};
};

struct TcpPayloadContributionCandidate {
    bool suppress_entire_packet {false};
    std::size_t trim_prefix_bytes {0};
};

struct TcpDirectionalContributionAnalysis {
    std::map<std::uint64_t, TcpPayloadContributionCandidate> contributions {};
    bool tainted_by_gap {false};
    std::uint64_t first_gap_packet_index {0};
};

std::uint64_t stable_payload_hash(std::span<const std::uint8_t> payload) noexcept {
    constexpr std::uint64_t kFnvOffsetBasis = 14695981039346656037ULL;
    constexpr std::uint64_t kFnvPrime = 1099511628211ULL;

    std::uint64_t hash = kFnvOffsetBasis;
    for (const auto byte : payload) {
        hash ^= static_cast<std::uint64_t>(byte);
        hash *= kFnvPrime;
    }

    return hash;
}

std::optional<DecodedTcpPayloadPacket> decode_tcp_payload_packet(
    const CaptureSession& session,
    const std::size_t flow_index,
    const PacketRef& packet,
    PacketDetailsService& details_service
) {
    if (packet.payload_length == 0U) {
        return std::nullopt;
    }

    const auto packet_bytes = session.read_packet_data(packet);
    if (packet_bytes.empty()) {
        return std::nullopt;
    }

    const auto details = details_service.decode(packet_bytes, packet);
    if (!details.has_value() || !details->has_tcp) {
        return std::nullopt;
    }

    auto payload_bytes = session.read_selected_flow_transport_payload(flow_index, packet);
    if (payload_bytes.size() != packet.payload_length || payload_bytes.empty()) {
        return std::nullopt;
    }

    return DecodedTcpPayloadPacket {
        .packet = packet,
        .sequence_number = details->tcp.seq_number,
        .acknowledgement_number = details->tcp.ack_number,
        .payload_bytes = std::move(payload_bytes),
    };
}

template <typename PacketList>
TcpDirectionalContributionAnalysis build_selected_flow_tcp_payload_suppression_for_direction(
    const CaptureSession& session,
    const std::size_t flow_index,
    const PacketList& packets,
    const std::set<std::uint64_t>& exact_duplicate_packet_indices,
    const std::size_t max_packets_to_scan = std::numeric_limits<std::size_t>::max()
) {
    TcpDirectionalContributionAnalysis analysis {};
    PacketDetailsService details_service {};
    TcpContributionTracker tracker {};
    std::size_t processed_packets = 0U;

    const auto mark_gap = [&](const std::uint64_t packet_index) {
        analysis.tainted_by_gap = true;
        analysis.first_gap_packet_index = packet_index;
    };

    for (const auto& packet : packets) {
        if (processed_packets >= max_packets_to_scan) {
            break;
        }
        ++processed_packets;

        const auto decoded = decode_tcp_payload_packet(session, flow_index, packet, details_service);
        if (!decoded.has_value()) {
            continue;
        }

        if (exact_duplicate_packet_indices.contains(packet.packet_index)) {
            analysis.contributions[packet.packet_index].suppress_entire_packet = true;
            continue;
        }

        const auto payload_size = decoded->payload_bytes.size();
        const auto sequence_start = decoded->sequence_number;
        const auto sequence_end = sequence_start + payload_size;

        if (!tracker.has_contiguous_stream) {
            tracker.has_contiguous_stream = true;
            tracker.base_sequence = sequence_start;
            tracker.next_sequence = sequence_end;
            tracker.last_acknowledgement_number = decoded->acknowledgement_number;
            tracker.contiguous_bytes = decoded->payload_bytes;
            continue;
        }

        if (!tracker.overlap_tracking_enabled) {
            continue;
        }

        if (sequence_start == tracker.next_sequence) {
            tracker.next_sequence = sequence_end;
            tracker.last_acknowledgement_number = decoded->acknowledgement_number;
            tracker.contiguous_bytes.insert(
                tracker.contiguous_bytes.end(),
                decoded->payload_bytes.begin(),
                decoded->payload_bytes.end()
            );
            continue;
        }

        if (sequence_start > tracker.next_sequence) {
            tracker.overlap_tracking_enabled = false;
            mark_gap(packet.packet_index);
            break;
        }

        if (sequence_start < tracker.base_sequence) {
            tracker.overlap_tracking_enabled = false;
            continue;
        }

        if (decoded->acknowledgement_number != tracker.last_acknowledgement_number) {
            tracker.overlap_tracking_enabled = false;
            continue;
        }

        const auto overlap_bytes = tracker.next_sequence - sequence_start;
        if (overlap_bytes == 0U || overlap_bytes > payload_size) {
            tracker.overlap_tracking_enabled = false;
            continue;
        }

        const auto start_offset = static_cast<std::size_t>(sequence_start - tracker.base_sequence);
        if (start_offset > tracker.contiguous_bytes.size() || overlap_bytes > tracker.contiguous_bytes.size() - start_offset) {
            tracker.overlap_tracking_enabled = false;
            continue;
        }

        const auto overlap_size = static_cast<std::size_t>(overlap_bytes);
        if (!std::equal(
                decoded->payload_bytes.begin(),
                decoded->payload_bytes.begin() + static_cast<std::ptrdiff_t>(overlap_size),
                tracker.contiguous_bytes.begin() + static_cast<std::ptrdiff_t>(start_offset))) {
            tracker.overlap_tracking_enabled = false;
            continue;
        }

        auto& contribution = analysis.contributions[packet.packet_index];
        if (overlap_size >= payload_size) {
            contribution.suppress_entire_packet = true;
            continue;
        }

        contribution.trim_prefix_bytes = overlap_size;
        tracker.next_sequence = sequence_end;
        tracker.last_acknowledgement_number = decoded->acknowledgement_number;
        tracker.contiguous_bytes.insert(
            tracker.contiguous_bytes.end(),
            decoded->payload_bytes.begin() + static_cast<std::ptrdiff_t>(overlap_size),
            decoded->payload_bytes.end()
        );
    }

    return analysis;
}

PacketRow make_packet_row(const PacketRef& packet, const std::string_view direction_text) {
    return PacketRow {
        .row_number = 0,
        .packet_index = packet.packet_index,
        .direction_text = std::string {direction_text},
        .timestamp_text = format_packet_timestamp(packet),
        .captured_length = packet.captured_length,
        .original_length = packet.original_length,
        .payload_length = packet.payload_length,
        .is_ip_fragmented = packet.is_ip_fragmented,
        .tcp_flags_text = format_tcp_flags_text(packet.tcp_flags),
    };
}

struct StreamPacketCandidate {
    PacketRef packet {};
    std::string_view direction_text {};
    ProtocolId protocol {ProtocolId::unknown};
};

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

std::uint32_t read_be32(std::span<const std::uint8_t> bytes, const std::size_t offset) noexcept {
    return (static_cast<std::uint32_t>(bytes[offset]) << 24U) |
           (static_cast<std::uint32_t>(bytes[offset + 1U]) << 16U) |
           (static_cast<std::uint32_t>(bytes[offset + 2U]) << 8U) |
           static_cast<std::uint32_t>(bytes[offset + 3U]);
}

constexpr std::uint16_t kHttpsPort = 443U;
constexpr std::size_t kMaxQuicConnectionIdLength = 20U;
constexpr std::size_t kMaxQuicFrameSummaryCount = 32U;
constexpr std::size_t kQuicPresentationPacketBudget = 4U;

enum class QuicPresentationShellType : std::uint8_t {
    none,
    initial,
    zero_rtt,
    handshake,
    retry,
    version_negotiation,
    protected_payload,
};

enum class QuicPresentationSemanticType : std::uint8_t {
    ack,
    crypto,
    zero_rtt,
    padding,
    ping,
};

struct QuicPresentationShellMetadata {
    std::string header_form {};
    std::optional<std::uint32_t> version {};
    std::vector<std::uint8_t> dcid {};
    std::vector<std::uint8_t> scid {};
};

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

struct QuicPresentationResult {
    QuicPresentationShellType shell_type {QuicPresentationShellType::none};
    QuicPresentationShellMetadata shell {};
    std::vector<QuicPresentationSemanticType> semantics {};
    std::vector<QuicPresentationShellType> additional_shell_types {};
    std::vector<std::uint64_t> selected_packet_indices {};
    std::vector<std::uint64_t> crypto_packet_indices {};
    std::optional<std::string> sni {};
    std::optional<TlsHandshakeDetails> tls_handshake {};
    bool used_bounded_crypto_assembly {false};
};

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

std::optional<std::string> format_quic_presentation_enrichment(const QuicPresentationResult& result);

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

struct QuicSemanticItemInfo {
    QuicPresentationSemanticType semantic {};
    std::size_t byte_count {0U};
};

std::vector<QuicSemanticItemInfo> quic_semantic_items_from_plaintext(
    std::span<const std::uint8_t> bytes
) {
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
std::optional<std::vector<std::uint8_t>> find_quic_client_initial_connection_id(
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
std::optional<std::vector<std::uint8_t>> find_quic_client_initial_connection_id_for_connection(
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
    return find_quic_client_initial_connection_id(session, packets, flow_index);
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

template <typename FlowKey, typename PacketList>
std::optional<QuicPresentationResult> build_quic_presentation_for_selected_direction(
    const CaptureSession& session,
    const FlowKey& flow_key,
    const PacketList& packets,
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
    const bool is_client_to_server = flow_key.src_port != kHttpsPort && flow_key.dst_port == kHttpsPort;

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
                is_client_to_server,
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
            if (is_client_to_server &&
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

std::string fallback_stream_label(const ProtocolId protocol) {
    switch (protocol) {
    case ProtocolId::tcp:
        return "TCP Payload";
    case ProtocolId::udp:
        return "UDP Payload";
    default:
        return "Payload";
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
    const auto version = read_be16(record_bytes, 1);
    const auto record_length = static_cast<std::size_t>(read_be16(record_bytes, 3));

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

StreamItemRow make_stream_item_row(
    const std::uint64_t stream_item_index,
    const std::string_view direction_text,
    const std::string& label,
    const std::size_t byte_count,
    const std::vector<std::uint64_t>& packet_indices,
    const std::string& payload_hex_text = {},
    const std::string& protocol_text = {}
) {
    return StreamItemRow {
        .stream_item_index = stream_item_index,
        .direction_text = std::string {direction_text},
        .label = label,
        .byte_count = static_cast<std::uint32_t>(byte_count),
        .packet_count = static_cast<std::uint32_t>(packet_indices.size()),
        .packet_indices = packet_indices,
        .payload_hex_text = payload_hex_text,
        .protocol_text = protocol_text,
    };
}

StreamItemRow make_stream_item_row(
    const std::uint64_t stream_item_index,
    const std::string_view direction_text,
    const std::string& label,
    const std::size_t byte_count,
    const PacketRef& packet,
    const std::string& payload_hex_text = {},
    const std::string& protocol_text = {}
) {
    return make_stream_item_row(
        stream_item_index,
        direction_text,
        label,
        byte_count,
        std::vector<std::uint64_t> {packet.packet_index},
        payload_hex_text,
        protocol_text
    );
}

bool append_tls_stream_items(
    std::vector<StreamItemRow>& rows,
    const StreamPacketCandidate& candidate,
    std::span<const std::uint8_t> payload_bytes
) {
    if (!looks_like_tls_record_prefix(payload_bytes)) {
        return false;
    }

    HexDumpService hex_dump_service {};
    std::size_t offset = 0;
    bool emitted_any = false;

    while (offset < payload_bytes.size()) {
        if (!looks_like_tls_record_prefix(payload_bytes, offset)) {
            const auto trailing = payload_bytes.subspan(offset);
            if (!trailing.empty()) {
                rows.push_back(make_stream_item_row(
                    static_cast<std::uint64_t>(rows.size() + 1U),
                    candidate.direction_text,
                    "TLS Payload (partial)",
                    trailing.size(),
                    candidate.packet,
                    hex_dump_service.format(trailing),
                    "TLS\n  Remaining bytes do not form a complete TLS record in this packet."
                ));
            }
            return true;
        }

        const auto record_size = tls_record_size(payload_bytes, offset);
        if (!record_size.has_value()) {
            const auto trailing = payload_bytes.subspan(offset);
            rows.push_back(make_stream_item_row(
                static_cast<std::uint64_t>(rows.size() + 1U),
                candidate.direction_text,
                "TLS Record Fragment (partial)",
                trailing.size(),
                candidate.packet,
                hex_dump_service.format(trailing),
                "TLS\n  Record header is present but the full TLS record body is not available in this packet."
            ));
            return true;
        }

        const auto record_bytes = payload_bytes.subspan(offset, *record_size);
        rows.push_back(make_stream_item_row(
            static_cast<std::uint64_t>(rows.size() + 1U),
            candidate.direction_text,
            tls_stream_label(record_bytes),
            record_bytes.size(),
            candidate.packet,
            hex_dump_service.format(record_bytes),
            tls_record_protocol_text(record_bytes)
        ));
        emitted_any = true;
        offset += *record_size;
    }

    return emitted_any;
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
    std::size_t consumed_bytes = 0;

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

std::string_view bytes_as_text(std::span<const std::uint8_t> bytes) {
    return std::string_view(reinterpret_cast<const char*>(bytes.data()), bytes.size());
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

std::string trim_ascii(const std::string_view value) {
    std::size_t begin = 0U;
    std::size_t end = value.size();

    while (begin < end && (value[begin] == ' ' || value[begin] == '\t' || value[begin] == '\r' || value[begin] == '\n')) {
        ++begin;
    }

    while (end > begin && (value[end - 1U] == ' ' || value[end - 1U] == '\t' || value[end - 1U] == '\r' || value[end - 1U] == '\n')) {
        --end;
    }

    return std::string {value.substr(begin, end - begin)};
}

bool is_http_token_char(const char value) noexcept {
    return std::isalnum(static_cast<unsigned char>(value)) != 0 || value == '-' || value == '_' || value == '.' || value == '/';
}

bool is_plausible_host_char(const char value) noexcept {
    return std::isalnum(static_cast<unsigned char>(value)) != 0 || value == '.' || value == '-' || value == '_';
}

bool is_plausible_host(const std::string_view value) noexcept {
    if (value.empty()) {
        return false;
    }

    for (const auto character : value) {
        if (!is_plausible_host_char(character)) {
            return false;
        }
    }

    return true;
}

std::size_t http_line_end(const std::string_view text, const std::size_t offset) noexcept {
    const auto crlf = text.find("\r\n", offset);
    const auto lf = text.find('\n', offset);
    if (crlf == std::string_view::npos) {
        return lf;
    }
    if (lf == std::string_view::npos) {
        return crlf;
    }
    return (crlf < lf) ? crlf : lf;
}

std::size_t http_next_line_offset(const std::string_view text, const std::size_t end) noexcept {
    if (end == std::string_view::npos || end >= text.size()) {
        return text.size();
    }

    if (text[end] == '\r' && (end + 1U) < text.size() && text[end + 1U] == '\n') {
        return end + 2U;
    }

    return end + 1U;
}

std::optional<std::size_t> http_header_block_size(std::string_view payload_text, const std::size_t offset) noexcept {
    if (offset >= payload_text.size()) {
        return std::nullopt;
    }

    const auto subtext = payload_text.substr(offset);
    const auto crlfcrlf = subtext.find("\r\n\r\n");
    const auto lflf = subtext.find("\n\n");
    if (crlfcrlf == std::string_view::npos && lflf == std::string_view::npos) {
        return std::nullopt;
    }

    if (crlfcrlf != std::string_view::npos && (lflf == std::string_view::npos || crlfcrlf < lflf)) {
        return crlfcrlf + 4U;
    }

    return lflf + 2U;
}

bool looks_like_http_request_line(const std::string_view line) noexcept {
    constexpr std::array<std::string_view, 9> methods {
        "GET ", "POST ", "PUT ", "HEAD ", "OPTIONS ", "DELETE ", "PATCH ", "CONNECT ", "TRACE ",
    };

    for (const auto method : methods) {
        if (line.starts_with(method)) {
            return true;
        }
    }

    return false;
}

bool looks_like_http_response_line(const std::string_view line) noexcept {
    return line.starts_with("HTTP/1.");
}

std::optional<std::string> extract_http_host_header(const std::string_view headers) {
    std::size_t offset = 0U;
    while (offset < headers.size()) {
        const auto end = http_line_end(headers, offset);
        const auto line = headers.substr(offset, ((end == std::string_view::npos) ? headers.size() : end) - offset);
        if (line.empty()) {
            break;
        }

        if (starts_with_ascii_case_insensitive(line, "Host:")) {
            const auto host = trim_ascii(line.substr(5U));
            if (is_plausible_host(host)) {
                return host;
            }
            return std::nullopt;
        }

        if (end == std::string_view::npos) {
            break;
        }
        offset = http_next_line_offset(headers, end);
    }

    return std::nullopt;
}

std::optional<std::string> extract_http_header_value(
    const std::string_view headers,
    const std::string_view header_name
) {
    std::size_t offset = 0U;
    while (offset < headers.size()) {
        const auto end = http_line_end(headers, offset);
        const auto line = headers.substr(offset, ((end == std::string_view::npos) ? headers.size() : end) - offset);
        if (line.empty()) {
            break;
        }

        const auto separator = line.find(':');
        if (separator != std::string_view::npos) {
            const auto name = trim_ascii(line.substr(0U, separator));
            if (starts_with_ascii_case_insensitive(name, header_name) && name.size() == header_name.size()) {
                const auto value = trim_ascii(line.substr(separator + 1U));
                if (!value.empty()) {
                    return value;
                }
                return std::nullopt;
            }
        }

        if (end == std::string_view::npos) {
            break;
        }
        offset = http_next_line_offset(headers, end);
    }

    return std::nullopt;
}

std::optional<std::size_t> parse_http_size_value(
    const std::string_view text,
    const int base
) noexcept {
    const auto value = trim_ascii(text);
    if (value.empty()) {
        return std::nullopt;
    }

    try {
        std::size_t parsed_characters = 0U;
        const auto parsed = std::stoull(value, &parsed_characters, base);
        if (parsed_characters != value.size() || parsed > std::numeric_limits<std::size_t>::max()) {
            return std::nullopt;
        }
        return static_cast<std::size_t>(parsed);
    } catch (...) {
        return std::nullopt;
    }
}

bool http_header_value_contains_token(
    const std::string_view value,
    const std::string_view token
) noexcept {
    std::size_t offset = 0U;
    while (offset < value.size()) {
        const auto separator = value.find(',', offset);
        const auto part = trim_ascii(value.substr(offset, (separator == std::string_view::npos) ? (value.size() - offset) : (separator - offset)));
        if (part.size() == token.size() && starts_with_ascii_case_insensitive(part, token)) {
            return true;
        }
        if (separator == std::string_view::npos) {
            break;
        }
        offset = separator + 1U;
    }
    return false;
}

std::optional<std::size_t> complete_http_chunked_body_size(
    const std::string_view payload_text,
    const std::size_t body_offset
) noexcept {
    std::size_t cursor = body_offset;
    while (cursor < payload_text.size()) {
        const auto line_end = http_line_end(payload_text, cursor);
        if (line_end == std::string_view::npos) {
            return std::nullopt;
        }

        const auto chunk_line = payload_text.substr(cursor, line_end - cursor);
        const auto extension_separator = chunk_line.find(';');
        const auto chunk_size_text = trim_ascii(chunk_line.substr(0U, extension_separator));
        const auto chunk_size = parse_http_size_value(chunk_size_text, 16);
        if (!chunk_size.has_value()) {
            return std::nullopt;
        }

        cursor = http_next_line_offset(payload_text, line_end);
        if (*chunk_size == 0U) {
            while (cursor <= payload_text.size()) {
                const auto trailer_end = http_line_end(payload_text, cursor);
                if (trailer_end == std::string_view::npos) {
                    return std::nullopt;
                }
                const auto trailer_line = payload_text.substr(cursor, trailer_end - cursor);
                cursor = http_next_line_offset(payload_text, trailer_end);
                if (trailer_line.empty()) {
                    return cursor - body_offset;
                }
            }
            return std::nullopt;
        }

        if (*chunk_size > (payload_text.size() - cursor)) {
            return std::nullopt;
        }
        cursor += *chunk_size;

        if (cursor >= payload_text.size()) {
            return std::nullopt;
        }
        if (payload_text[cursor] == '\r') {
            if ((cursor + 1U) >= payload_text.size() || payload_text[cursor + 1U] != '\n') {
                return std::nullopt;
            }
            cursor += 2U;
        } else if (payload_text[cursor] == '\n') {
            cursor += 1U;
        } else {
            return std::nullopt;
        }
    }

    return std::nullopt;
}

std::size_t http_message_size(
    const std::string_view payload_text,
    const std::size_t offset,
    const std::size_t header_size,
    const std::string_view headers_text
) noexcept {
    const auto body_offset = offset + header_size;
    if (body_offset > payload_text.size()) {
        return header_size;
    }

    if (const auto transfer_encoding = extract_http_header_value(headers_text, "Transfer-Encoding");
        transfer_encoding.has_value() && http_header_value_contains_token(*transfer_encoding, "chunked")) {
        if (const auto body_size = complete_http_chunked_body_size(payload_text, body_offset); body_size.has_value()) {
            return header_size + *body_size;
        }
        return header_size;
    }

    if (const auto content_length = extract_http_header_value(headers_text, "Content-Length"); content_length.has_value()) {
        if (const auto body_size = parse_http_size_value(*content_length, 10); body_size.has_value() && *body_size <= (payload_text.size() - body_offset)) {
            return header_size + *body_size;
        }
    }

    return header_size;
}

struct ParsedHttpHeaderBlock {
    std::size_t size {0U};
    std::string label {};
    std::string protocol_text {};
};

std::optional<ParsedHttpHeaderBlock> parse_http_header_block(
    std::span<const std::uint8_t> payload_bytes,
    const std::size_t offset
) {
    const auto payload_text = bytes_as_text(payload_bytes);
    const auto header_size = http_header_block_size(payload_text, offset);
    if (!header_size.has_value()) {
        return std::nullopt;
    }

    const auto header_text = payload_text.substr(offset, *header_size);
    const auto first_line_end = http_line_end(header_text, 0U);
    const auto first_line = header_text.substr(0U, (first_line_end == std::string_view::npos) ? header_text.size() : first_line_end);
    if (first_line.empty()) {
        return std::nullopt;
    }
    const auto headers_text = header_text.substr(http_next_line_offset(header_text, first_line_end));

    std::ostringstream text {};
    text << "HTTP\n";

    if (looks_like_http_request_line(first_line)) {
        const auto method_end = first_line.find(' ');
        if (method_end == std::string_view::npos) {
            return std::nullopt;
        }

        const auto path_start = method_end + 1U;
        const auto path_end = first_line.find(' ', path_start);
        if (path_end == std::string_view::npos || path_end <= path_start) {
            return std::nullopt;
        }

        const auto method = first_line.substr(0U, method_end);
        const auto path = first_line.substr(path_start, path_end - path_start);
        const auto version = first_line.substr(path_end + 1U);
        if (!version.starts_with("HTTP/1.") || path.empty()) {
            return std::nullopt;
        }

        for (const auto character : method) {
            if (!std::isupper(static_cast<unsigned char>(character))) {
                return std::nullopt;
            }
        }
        for (const auto character : version) {
            if (!(is_http_token_char(character) || character == ' ')) {
                return std::nullopt;
            }
        }

        text << "  Message Type: Request\n"
             << "  Method: " << method << "\n"
             << "  Path: " << path << "\n"
             << "  Version: " << version;

        const auto host = extract_http_host_header(headers_text);
        if (host.has_value()) {
            text << "\n"
                 << "  Host: " << *host;
        }

        const auto method_text = std::string {method};
        const auto path_text = std::string {path};
        return ParsedHttpHeaderBlock {
            .size = http_message_size(payload_text, offset, *header_size, headers_text),
            .label = method_text.empty() || path_text.empty()
                ? "HTTP Request"
                : ("HTTP " + method_text + " " + path_text),
            .protocol_text = text.str(),
        };
    }

    if (looks_like_http_response_line(first_line)) {
        const auto version_end = first_line.find(' ');
        if (version_end == std::string_view::npos) {
            return std::nullopt;
        }

        const auto code_start = version_end + 1U;
        if (code_start + 3U > first_line.size()) {
            return std::nullopt;
        }

        const auto version = first_line.substr(0U, version_end);
        const auto code = first_line.substr(code_start, 3U);
        for (const auto character : code) {
            if (!std::isdigit(static_cast<unsigned char>(character))) {
                return std::nullopt;
            }
        }

        text << "  Message Type: Response\n"
             << "  Version: " << version << "\n"
             << "  Status Code: " << code;

        std::string reason_text {};
        const auto reason_start = code_start + 3U;
        if (reason_start < first_line.size() && first_line[reason_start] == ' ') {
            const auto reason = trim_ascii(first_line.substr(reason_start + 1U));
            if (!reason.empty()) {
                reason_text = reason;
                text << "\n"
                     << "  Reason: " << reason;
            }
        }

        if (const auto content_type = extract_http_header_value(headers_text, "Content-Type"); content_type.has_value()) {
            text << "\n"
                 << "  Content-Type: " << *content_type;
        }
        if (const auto content_length = extract_http_header_value(headers_text, "Content-Length"); content_length.has_value()) {
            text << "\n"
                 << "  Content-Length: " << *content_length;
        }

        const auto code_text = std::string {code};
        return ParsedHttpHeaderBlock {
            .size = http_message_size(payload_text, offset, *header_size, headers_text),
            .label = code_text.empty()
                ? "HTTP Response"
                : (reason_text.empty() ? ("HTTP " + code_text) : ("HTTP " + code_text + " " + reason_text)),
            .protocol_text = text.str(),
        };
    }

    return std::nullopt;
}

std::optional<std::string_view> find_protocol_detail_value(
    const std::string_view protocol_text,
    const std::string_view key
) noexcept {
    const auto marker = std::string {"  "} + std::string {key} + ": ";
    const auto marker_pos = protocol_text.find(marker);
    if (marker_pos == std::string_view::npos) {
        return std::nullopt;
    }

    const auto value_start = marker_pos + marker.size();
    const auto value_end = protocol_text.find('\n', value_start);
    const auto value = protocol_text.substr(value_start, (value_end == std::string_view::npos) ? (protocol_text.size() - value_start) : (value_end - value_start));
    if (value.empty()) {
        return std::nullopt;
    }

    return value;
}

std::string http_stream_label_from_protocol_text(const std::string_view protocol_text) {
    if (contains_text(protocol_text, "Message Type: Request")) {
        const auto method = find_protocol_detail_value(protocol_text, "Method");
        const auto path = find_protocol_detail_value(protocol_text, "Path");
        if (method.has_value() && path.has_value()) {
            return "HTTP " + std::string {*method} + " " + std::string {*path};
        }
        return "HTTP Request";
    }

    if (contains_text(protocol_text, "Message Type: Response")) {
        const auto status_code = find_protocol_detail_value(protocol_text, "Status Code");
        const auto reason = find_protocol_detail_value(protocol_text, "Reason");
        if (status_code.has_value()) {
            if (reason.has_value()) {
                return "HTTP " + std::string {*status_code} + " " + std::string {*reason};
            }
            return "HTTP " + std::string {*status_code};
        }
        return "HTTP Response";
    }

    return "HTTP Payload";
}
std::string limited_quality_http_protocol_text() {
    return "HTTP\n  Reassembled bytes do not contain a complete HTTP header block in this direction.";
}

struct DirectionalStreamPolicy {
    bool used_reassembly {false};
    bool explicit_gap_item_emitted {false};
    std::uint64_t first_gap_packet_index {0};
    std::string fallback_label {};
    std::string fallback_protocol_text {};
    std::set<std::uint64_t> covered_packet_indices {};
};

DirectionalStreamPolicy append_http_stream_items_from_reassembly(
    std::vector<StreamItemRow>& rows,
    const CaptureSession& session,
    const std::size_t flow_index,
    const std::string_view direction_text,
    const Direction direction,
    const std::size_t max_packets_to_scan
) {
    DirectionalStreamPolicy policy {};
    constexpr std::size_t kHttpReassemblyMaxBytes = 2U * 1024U * 1024U;

    const auto result = session.reassemble_flow_direction(ReassemblyRequest {
        .flow_index = flow_index,
        .direction = direction,
        .max_packets = max_packets_to_scan,
        .max_bytes = kHttpReassemblyMaxBytes,
    });
    if (!result.has_value() || result->bytes.empty()) {
        return policy;
    }

    const auto payload_bytes = std::span<const std::uint8_t>(result->bytes.data(), result->bytes.size());
    const auto payload_text = bytes_as_text(payload_bytes);
    const auto chunks = build_reassembled_payload_chunks(session, flow_index, *result);
    if (!chunks.has_value() || chunks->empty()) {
        return policy;
    }

    HexDumpService hex_dump_service {};
    std::size_t offset = 0U;
    std::size_t chunk_index = 0U;
    std::size_t chunk_offset = 0U;
    bool emitted_any = false;

    while (offset < payload_bytes.size()) {
        const auto parsed = parse_http_header_block(payload_bytes, offset);
        if (!parsed.has_value()) {
            if (offset == 0U) {
                return policy;
            }

            const auto trailing = payload_bytes.subspan(offset);
            if (!trailing.empty()) {
                const auto packet_indices = consume_reassembled_packet_indices(*chunks, trailing.size(), chunk_index, chunk_offset);
                rows.push_back(make_stream_item_row(
                    static_cast<std::uint64_t>(rows.size() + 1U),
                    direction_text,
                    "HTTP Payload (partial)",
                    trailing.size(),
                    packet_indices,
                    hex_dump_service.format(trailing),
                    limited_quality_http_protocol_text()
                ));
            }
            policy.used_reassembly = true;
            break;
        }

        const auto block_bytes = payload_bytes.subspan(offset, parsed->size);
        const auto packet_indices = consume_reassembled_packet_indices(*chunks, block_bytes.size(), chunk_index, chunk_offset);
        rows.push_back(make_stream_item_row(
            static_cast<std::uint64_t>(rows.size() + 1U),
            direction_text,
            parsed->label,
            block_bytes.size(),
            packet_indices,
            hex_dump_service.format(block_bytes),
            parsed->protocol_text
        ));
        emitted_any = true;
        offset += parsed->size;

        if (offset < payload_text.size()) {
            const auto next_line_end = http_line_end(payload_text, offset);
            const auto next_line = payload_text.substr(offset, ((next_line_end == std::string_view::npos) ? payload_text.size() : next_line_end) - offset);
            if (!looks_like_http_request_line(next_line) && !looks_like_http_response_line(next_line)) {
                const auto trailing = payload_bytes.subspan(offset);
                if (!trailing.empty()) {
                    const auto packet_indices = consume_reassembled_packet_indices(*chunks, trailing.size(), chunk_index, chunk_offset);
                    rows.push_back(make_stream_item_row(
                        static_cast<std::uint64_t>(rows.size() + 1U),
                        direction_text,
                        "HTTP Payload (partial)",
                        trailing.size(),
                        packet_indices,
                        hex_dump_service.format(trailing),
                        limited_quality_http_protocol_text()
                    ));
                }
                policy.used_reassembly = true;
                break;
            }
        }
    }

    policy.used_reassembly = policy.used_reassembly || emitted_any;
    if (policy.used_reassembly) {
        policy.covered_packet_indices.insert(result->packet_indices.begin(), result->packet_indices.end());
    }
    if (result->stopped_at_gap && result->first_gap_packet_index != 0U) {
        rows.push_back(make_stream_item_row(
            static_cast<std::uint64_t>(rows.size() + 1U),
            direction_text,
            "HTTP Gap",
            0U,
            std::vector<std::uint64_t> {result->first_gap_packet_index},
            {},
            tcp_gap_protocol_text("HTTP")
        ));
        policy.used_reassembly = true;
        policy.explicit_gap_item_emitted = true;
        policy.first_gap_packet_index = result->first_gap_packet_index;
        policy.fallback_label = "HTTP Payload";
        policy.fallback_protocol_text = tcp_gap_protocol_text("HTTP");
    }

    return policy;
}

DirectionalStreamPolicy append_tls_stream_items_from_reassembly(
    std::vector<StreamItemRow>& rows,
    const CaptureSession& session,
    const std::size_t flow_index,
    const std::string_view direction_text,
    const Direction direction,
    const std::size_t max_packets_to_scan
) {
    DirectionalStreamPolicy policy {};
    const auto result = session.reassemble_flow_direction(ReassemblyRequest {
        .flow_index = flow_index,
        .direction = direction,
        .max_packets = max_packets_to_scan,
        .max_bytes = 256U * 1024U,
    });
    if (!result.has_value() || result->bytes.empty()) {
        return policy;
    }

    const auto payload_bytes = std::span<const std::uint8_t>(result->bytes.data(), result->bytes.size());
    if (!looks_like_tls_record_prefix(payload_bytes)) {
        return policy;
    }

    const auto chunks = build_reassembled_payload_chunks(session, flow_index, *result);
    if (!chunks.has_value() || chunks->empty()) {
        return policy;
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
                rows.push_back(make_stream_item_row(
                    static_cast<std::uint64_t>(rows.size() + 1U),
                    direction_text,
                    "TLS Payload (partial)",
                    trailing.size(),
                    packet_indices,
                    hex_dump_service.format(trailing),
                    limited_quality_tls_protocol_text(false)
                ));
            }
            policy.used_reassembly = true;
            break;
        }

        const auto record_size = tls_record_size(payload_bytes, offset);
        if (!record_size.has_value()) {
            const auto trailing = payload_bytes.subspan(offset);
            const auto packet_indices = consume_reassembled_packet_indices(*chunks, trailing.size(), chunk_index, chunk_offset);
            rows.push_back(make_stream_item_row(
                static_cast<std::uint64_t>(rows.size() + 1U),
                direction_text,
                "TLS Record Fragment (partial)",
                trailing.size(),
                packet_indices,
                hex_dump_service.format(trailing),
                limited_quality_tls_protocol_text(true)
            ));
            policy.used_reassembly = true;
            break;
        }

        const auto record_bytes = payload_bytes.subspan(offset, *record_size);
        const auto packet_indices = consume_reassembled_packet_indices(*chunks, record_bytes.size(), chunk_index, chunk_offset);
        rows.push_back(make_stream_item_row(
            static_cast<std::uint64_t>(rows.size() + 1U),
            direction_text,
            tls_stream_label(record_bytes),
            record_bytes.size(),
            packet_indices,
            hex_dump_service.format(record_bytes),
            tls_record_protocol_text(record_bytes)
        ));
        emitted_any = true;
        offset += *record_size;
    }

    policy.used_reassembly = policy.used_reassembly || emitted_any;
    if (policy.used_reassembly) {
        policy.covered_packet_indices.insert(result->packet_indices.begin(), result->packet_indices.end());
    }
    if (result->stopped_at_gap && result->first_gap_packet_index != 0U) {
        rows.push_back(make_stream_item_row(
            static_cast<std::uint64_t>(rows.size() + 1U),
            direction_text,
            "TLS Gap",
            0U,
            std::vector<std::uint64_t> {result->first_gap_packet_index},
            {},
            tcp_gap_protocol_text("TLS")
        ));
        policy.used_reassembly = true;
        policy.explicit_gap_item_emitted = true;
        policy.first_gap_packet_index = result->first_gap_packet_index;
        policy.fallback_label = "TLS Payload";
        policy.fallback_protocol_text = tcp_gap_protocol_text("TLS");
    }

    return policy;
}

std::string classify_stream_label(
    const std::vector<std::uint8_t>& packet_bytes,
    const std::uint32_t data_link_type,
    const ProtocolId protocol,
    const bool deep_protocol_details_enabled
) {
    if (deep_protocol_details_enabled) {
        TlsPacketProtocolAnalyzer tls_analyzer {};
        if (const auto tls_details = tls_analyzer.analyze(packet_bytes, data_link_type); tls_details.has_value()) {
            return tls_stream_label_from_protocol_text(*tls_details);
        }

        HttpPacketProtocolAnalyzer http_analyzer {};
        if (const auto http_details = http_analyzer.analyze(packet_bytes, data_link_type); http_details.has_value()) {
            return http_stream_label_from_protocol_text(*http_details);
        }

        DnsPacketProtocolAnalyzer dns_analyzer {};
        if (const auto dns_details = dns_analyzer.analyze(packet_bytes, data_link_type); dns_details.has_value()) {
            const auto text = std::string_view(*dns_details);
            if (contains_text(text, "Message Type: Query")) {
                return "DNS Query";
            }
            if (contains_text(text, "Message Type: Response")) {
                return "DNS Response";
            }
            return "DNS Payload";
        }
    }

    return fallback_stream_label(protocol);
}

std::optional<PacketRef> find_packet_in_connection(const ConnectionV4& connection, std::uint64_t packet_index) {
    for (const auto& packet : connection.flow_a.packets) {
        if (packet.packet_index == packet_index) {
            return packet;
        }
    }

    for (const auto& packet : connection.flow_b.packets) {
        if (packet.packet_index == packet_index) {
            return packet;
        }
    }

    return std::nullopt;
}

std::optional<PacketRef> find_packet_in_connection(const ConnectionV6& connection, std::uint64_t packet_index) {
    for (const auto& packet : connection.flow_a.packets) {
        if (packet.packet_index == packet_index) {
            return packet;
        }
    }

    for (const auto& packet : connection.flow_b.packets) {
        if (packet.packet_index == packet_index) {
            return packet;
        }
    }

    return std::nullopt;
}

template <typename Connection>
std::size_t connection_packet_count(const Connection& connection) noexcept {
    return connection.flow_a.packets.size() + connection.flow_b.packets.size();
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

template <typename FlowKey, typename PacketList>
bool append_quic_stream_items_for_packet(
    std::vector<StreamItemRow>& rows,
    const CaptureSession& session,
    const std::size_t flow_index,
    const FlowKey& flow_key,
    const PacketList& flow_packets,
    const PacketRef& packet,
    const std::string_view direction_text,
    std::span<const std::uint8_t> payload_span,
    HexDumpService& hex_dump_service,
    std::span<const std::uint8_t> initial_secret_connection_id
) {
    const auto context_result = build_quic_presentation_for_selected_direction(
        session,
        flow_key,
        flow_packets,
        std::vector<std::uint64_t> {packet.packet_index},
        initial_secret_connection_id,
        flow_index
    );
    const auto datagram_packets = parse_quic_presentation_datagram(payload_span);

    if (datagram_packets.empty()) {
        return false;
    }

    const auto context_enrichment = context_result.has_value()
        ? format_quic_presentation_enrichment(*context_result)
        : std::optional<std::string> {};
    const bool is_client_to_server = flow_key.src_port != kHttpsPort && flow_key.dst_port == kHttpsPort;
    QuicInitialParser initial_parser {};

    bool emitted_any = false;
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
                    is_client_to_server,
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
                    rows.push_back(make_stream_item_row(
                        static_cast<std::uint64_t>(rows.size() + 1U),
                        direction_text,
                        quic_stream_label_from_result(label_result),
                        semantic_item.byte_count > 0U ? semantic_item.byte_count : packet_slice_length,
                        packet,
                        hex_dump_service.format(payload_span),
                        protocol_text.value_or(std::string {})
                    ));
                    emitted_any = true;
                }
                continue;
            }

            if (should_emit_quic_stream_item(aggregate_result)) {
                rows.push_back(make_stream_item_row(
                    static_cast<std::uint64_t>(rows.size() + 1U),
                    direction_text,
                    quic_stream_label_from_result(aggregate_result),
                    packet_slice_length,
                    packet,
                    hex_dump_service.format(payload_span),
                    protocol_text.value_or(std::string {})
                ));
                emitted_any = true;
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
        rows.push_back(make_stream_item_row(
            static_cast<std::uint64_t>(rows.size() + 1U),
            direction_text,
            quic_stream_label_from_result(result),
            packet_slice_length,
            packet,
            hex_dump_service.format(payload_span),
            protocol_text.value_or(std::string {})
        ));
        emitted_any = true;
    }

    return emitted_any || !datagram_packets.empty();
}

template <typename Connection>
void append_connection_stream_items_bounded(
    std::vector<StreamItemRow>& rows,
    const CaptureSession& session,
    const std::size_t flow_index,
    const Connection& connection,
    const ProtocolId flow_protocol,
    const std::size_t target_count,
    const std::size_t max_packets_to_scan,
    const bool deep_protocol_details_enabled,
    const DirectionalStreamPolicy& direction_policy_a,
    const DirectionalStreamPolicy& direction_policy_b
) {
    HexDumpService hex_dump_service {};
    const auto quic_initial_secret_connection_id =
        flow_protocol == ProtocolId::udp
            ? find_quic_client_initial_connection_id_for_connection(session, connection, flow_index)
            : std::optional<std::vector<std::uint8_t>> {};
    std::size_t index_a = 0U;
    std::size_t index_b = 0U;
    std::size_t scanned_packets = 0U;
    bool gap_item_emitted_a = direction_policy_a.explicit_gap_item_emitted;
    bool gap_item_emitted_b = direction_policy_b.explicit_gap_item_emitted;

    while ((index_a < connection.flow_a.packets.size() || index_b < connection.flow_b.packets.size()) &&
           rows.size() < target_count &&
           scanned_packets < max_packets_to_scan) {
        const bool use_a = index_b >= connection.flow_b.packets.size() ||
            (index_a < connection.flow_a.packets.size() &&
             connection.flow_a.packets[index_a].packet_index <= connection.flow_b.packets[index_b].packet_index);

        const auto& packet = use_a ? connection.flow_a.packets[index_a++] : connection.flow_b.packets[index_b++];
        ++scanned_packets;
        const auto direction_text = use_a ? kDirectionAToB : kDirectionBToA;
        const auto direction = use_a ? Direction::a_to_b : Direction::b_to_a;
        const auto& direction_policy = use_a ? direction_policy_a : direction_policy_b;
        auto& gap_item_emitted = use_a ? gap_item_emitted_a : gap_item_emitted_b;

        if (direction_policy.covered_packet_indices.contains(packet.packet_index)) {
            continue;
        }

        if (packet.payload_length == 0U) {
            continue;
        }

        if (flow_protocol == ProtocolId::tcp && session.should_suppress_selected_flow_tcp_payload(flow_index, packet.packet_index)) {
            continue;
        }

        const auto payload_bytes = session.read_selected_flow_transport_payload(flow_index, packet);
        if (payload_bytes.empty()) {
            continue;
        }

        const auto trim_prefix_bytes = flow_protocol == ProtocolId::tcp
            ? session.selected_flow_tcp_payload_trim_prefix_bytes(flow_index, packet.packet_index)
            : 0U;
        if (trim_prefix_bytes >= payload_bytes.size()) {
            continue;
        }

        const auto candidate = StreamPacketCandidate {
            .packet = packet,
            .direction_text = direction_text,
            .protocol = flow_protocol,
        };

        const auto payload_span = std::span<const std::uint8_t>(
            payload_bytes.data() + static_cast<std::ptrdiff_t>(trim_prefix_bytes),
            payload_bytes.size() - trim_prefix_bytes
        );
        const bool trimmed_tcp_payload = flow_protocol == ProtocolId::tcp && trim_prefix_bytes > 0U;
        const auto gap_packet_index = flow_protocol == ProtocolId::tcp
            ? (direction_policy.first_gap_packet_index != 0U
                ? std::optional<std::uint64_t> {direction_policy.first_gap_packet_index}
                : session.selected_flow_tcp_direction_first_gap_packet_index(flow_index, direction))
            : std::optional<std::uint64_t> {};
        const bool direction_tainted_by_gap = gap_packet_index.has_value() && packet.packet_index >= *gap_packet_index;

        if (direction_tainted_by_gap && !gap_item_emitted) {
            const auto gap_label = direction_policy.fallback_label == "HTTP Payload"
                ? std::string {"HTTP Gap"}
                : direction_policy.fallback_label == "TLS Payload"
                    ? std::string {"TLS Gap"}
                    : std::string {"TCP Gap"};
            const auto gap_protocol = !direction_policy.fallback_protocol_text.empty()
                ? direction_policy.fallback_protocol_text
                : tcp_gap_protocol_text("TCP");
            rows.push_back(make_stream_item_row(
                static_cast<std::uint64_t>(rows.size() + 1U),
                direction_text,
                gap_label,
                0U,
                packet,
                {},
                gap_protocol
            ));
            gap_item_emitted = true;
            if (rows.size() >= target_count) {
                break;
            }
        }

        if (flow_protocol == ProtocolId::tcp && !trimmed_tcp_payload && !direction_tainted_by_gap) {
            if (append_tls_stream_items(rows, candidate, payload_span)) {
                continue;
            }
        }

        if (flow_protocol == ProtocolId::udp) {
            const bool handled_quic = use_a
                ? append_quic_stream_items_for_packet(
                    rows,
                    session,
                    flow_index,
                    connection.flow_a.key,
                    connection.flow_a.packets,
                    packet,
                    direction_text,
                    payload_span,
                    hex_dump_service,
                    quic_initial_secret_connection_id.has_value()
                        ? std::span<const std::uint8_t>(
                            quic_initial_secret_connection_id->data(),
                            quic_initial_secret_connection_id->size())
                        : std::span<const std::uint8_t> {}
                )
                : append_quic_stream_items_for_packet(
                    rows,
                    session,
                    flow_index,
                    connection.flow_b.key,
                    connection.flow_b.packets,
                    packet,
                    direction_text,
                    payload_span,
                    hex_dump_service,
                    quic_initial_secret_connection_id.has_value()
                        ? std::span<const std::uint8_t>(
                            quic_initial_secret_connection_id->data(),
                            quic_initial_secret_connection_id->size())
                        : std::span<const std::uint8_t> {}
                );

            if (handled_quic) {
                continue;
            }
        }

        std::string label = fallback_stream_label(flow_protocol);
        std::string protocol_text {};
        if (direction_tainted_by_gap) {
            if (!direction_policy.fallback_label.empty()) {
                label = direction_policy.fallback_label;
            }
            protocol_text = !direction_policy.fallback_protocol_text.empty()
                ? direction_policy.fallback_protocol_text
                : tcp_gap_protocol_text("TCP");
        } else if (!trimmed_tcp_payload) {
            const auto packet_bytes = session.read_packet_data(packet);
            if (!packet_bytes.empty()) {
                label = classify_stream_label(packet_bytes, packet.data_link_type, flow_protocol, deep_protocol_details_enabled);
            }
        }
        rows.push_back(make_stream_item_row(
            static_cast<std::uint64_t>(rows.size() + 1U),
            direction_text,
            label,
            payload_span.size(),
            packet,
            {},
            protocol_text
        ));
    }
}

template <typename Connection>
std::vector<PacketRow> slice_connection_packets(
    const Connection& connection,
    const std::size_t offset,
    const std::size_t limit
) {
    if (limit == 0U) {
        return {};
    }

    std::vector<PacketRow> rows {};
    const auto total = connection_packet_count(connection);
    if (offset >= total) {
        return rows;
    }

    const auto target = std::min(total, offset + limit);
    rows.reserve(target - offset);

    std::size_t emitted = 0U;
    std::size_t row_number = 0U;
    std::size_t index_a = 0U;
    std::size_t index_b = 0U;

    while ((index_a < connection.flow_a.packets.size() || index_b < connection.flow_b.packets.size()) && row_number < target) {
        const bool use_a = index_b >= connection.flow_b.packets.size() ||
            (index_a < connection.flow_a.packets.size() &&
             connection.flow_a.packets[index_a].packet_index <= connection.flow_b.packets[index_b].packet_index);

        const auto& packet = use_a ? connection.flow_a.packets[index_a++] : connection.flow_b.packets[index_b++];
        const auto direction = use_a ? kDirectionAToB : kDirectionBToA;

        if (row_number >= offset) {
            auto row = make_packet_row(packet, direction);
            row.row_number = row_number + 1U;
            rows.push_back(std::move(row));
            ++emitted;
            if (emitted >= limit) {
                break;
            }
        }

        ++row_number;
    }

    return rows;
}

template <typename Connection>
std::vector<std::uint64_t> collect_suspected_tcp_retransmission_packet_indices(
    const CaptureSession& session,
    const std::size_t flow_index,
    const Connection& connection,
    const std::size_t max_packets_to_scan
) {
    std::map<SuspectedTcpRetransmissionFingerprint, std::vector<SeenTcpPayloadCandidate>> seen_fingerprints {};
    std::vector<std::uint64_t> suspected_packet_indices {};
    PacketDetailsService details_service {};

    auto maybe_mark_packet = [&](const PacketRef& packet, const std::uint8_t direction_id) {
        const auto decoded = decode_tcp_payload_packet(session, flow_index, packet, details_service);
        if (!decoded.has_value()) {
            return;
        }

        const auto payload_hash = stable_payload_hash(decoded->payload_bytes);

        const auto fingerprint = std::make_tuple(
            direction_id,
            static_cast<std::uint32_t>(decoded->sequence_number),
            decoded->acknowledgement_number,
            packet.payload_length,
            payload_hash
        );

        auto& candidates = seen_fingerprints[fingerprint];
        for (const auto& candidate : candidates) {
            if (candidate.payload_bytes == decoded->payload_bytes) {
                suspected_packet_indices.push_back(packet.packet_index);
                return;
            }
        }

        candidates.push_back(SeenTcpPayloadCandidate {
            .packet_index = packet.packet_index,
            .payload_bytes = decoded->payload_bytes,
        });
    };
    std::size_t index_a = 0U;
    std::size_t index_b = 0U;
    std::size_t processed_packets = 0U;
    while ((index_a < connection.flow_a.packets.size() || index_b < connection.flow_b.packets.size())
           && processed_packets < max_packets_to_scan) {
        const bool use_a = index_b >= connection.flow_b.packets.size() ||
            (index_a < connection.flow_a.packets.size() &&
             connection.flow_a.packets[index_a].packet_index <= connection.flow_b.packets[index_b].packet_index);

        const auto& packet = use_a ? connection.flow_a.packets[index_a++] : connection.flow_b.packets[index_b++];
        maybe_mark_packet(packet, use_a ? 0U : 1U);
        ++processed_packets;
    }

    return suspected_packet_indices;
}

template <typename Connection>
std::pair<std::size_t, std::size_t> flow_packet_prefix_direction_counts(
    const Connection& connection,
    const std::size_t max_packets_to_scan
) {
    std::size_t count_a = 0U;
    std::size_t count_b = 0U;
    std::size_t index_a = 0U;
    std::size_t index_b = 0U;
    std::size_t processed_packets = 0U;

    while ((index_a < connection.flow_a.packets.size() || index_b < connection.flow_b.packets.size())
           && processed_packets < max_packets_to_scan) {
        const bool use_a = index_b >= connection.flow_b.packets.size() ||
            (index_a < connection.flow_a.packets.size() &&
             connection.flow_a.packets[index_a].packet_index <= connection.flow_b.packets[index_b].packet_index);

        if (use_a) {
            ++index_a;
            ++count_a;
        } else {
            ++index_b;
            ++count_b;
        }

        ++processed_packets;
    }

    return {count_a, count_b};
}

std::vector<StreamItemRow> build_flow_stream_items_bounded(
    const CaptureSession& session,
    const ListedConnectionRef& connection,
    const std::size_t flow_index,
    const std::size_t max_packets_to_scan,
    const std::size_t target,
    const bool deep_protocol_details_enabled
) {
    const auto flow_protocol = protocol_id(connection);
    std::vector<StreamItemRow> rows {};

    const auto total_packets = connection.family == FlowAddressFamily::ipv4
        ? connection_packet_count(*connection.ipv4)
        : connection_packet_count(*connection.ipv6);
    rows.reserve(std::min(target, total_packets));

    DirectionalStreamPolicy direction_policy_a {};
    DirectionalStreamPolicy direction_policy_b {};
    if (flow_protocol == ProtocolId::tcp) {
        const auto [prefix_count_a, prefix_count_b] = connection.family == FlowAddressFamily::ipv4
            ? flow_packet_prefix_direction_counts(*connection.ipv4, max_packets_to_scan)
            : flow_packet_prefix_direction_counts(*connection.ipv6, max_packets_to_scan);
        direction_policy_a = append_tls_stream_items_from_reassembly(
            rows,
            session,
            flow_index,
            kDirectionAToB,
            Direction::a_to_b,
            prefix_count_a
        );
        direction_policy_b = append_tls_stream_items_from_reassembly(
            rows,
            session,
            flow_index,
            kDirectionBToA,
            Direction::b_to_a,
            prefix_count_b
        );
        if (!direction_policy_a.used_reassembly) {
            direction_policy_a = append_http_stream_items_from_reassembly(
                rows,
                session,
                flow_index,
                kDirectionAToB,
                Direction::a_to_b,
                prefix_count_a
            );
        }
        if (!direction_policy_b.used_reassembly) {
            direction_policy_b = append_http_stream_items_from_reassembly(
                rows,
                session,
                flow_index,
                kDirectionBToA,
                Direction::b_to_a,
                prefix_count_b
            );
        }
    }

    if (rows.size() < target) {
        if (connection.family == FlowAddressFamily::ipv4) {
            append_connection_stream_items_bounded(
                rows,
                session,
                flow_index,
                *connection.ipv4,
                flow_protocol,
                target,
                max_packets_to_scan,
                deep_protocol_details_enabled,
                direction_policy_a,
                direction_policy_b
            );
        } else {
            append_connection_stream_items_bounded(
                rows,
                session,
                flow_index,
                *connection.ipv6,
                flow_protocol,
                target,
                max_packets_to_scan,
                deep_protocol_details_enabled,
                direction_policy_a,
                direction_policy_b
            );
        }
    }

    std::stable_sort(rows.begin(), rows.end(), [](const StreamItemRow& left, const StreamItemRow& right) {
        const auto left_packet_index = left.packet_indices.empty() ? std::numeric_limits<std::uint64_t>::max() : left.packet_indices.front();
        const auto right_packet_index = right.packet_indices.empty() ? std::numeric_limits<std::uint64_t>::max() : right.packet_indices.front();
        return left_packet_index < right_packet_index;
    });

    for (std::size_t index = 0; index < rows.size(); ++index) {
        rows[index].stream_item_index = static_cast<std::uint64_t>(index + 1U);
    }

    return rows;
}

}  // namespace

void CaptureSession::reset_runtime_state() noexcept {
    capture_path_.clear();
    source_capture_path_.clear();
    source_info_ = {};
    state_ = {};
    import_mode_ = ImportMode::fast;
    analysis_settings_ = {};
    deep_protocol_details_enabled_ = false;
    opened_from_index_ = false;
    has_loaded_state_ = false;
    last_open_error_text_.clear();
    selected_flow_packet_cache_.reset();
    selected_flow_tcp_payload_suppression_.reset();
}

bool CaptureSession::open_capture(const std::filesystem::path& path) {
    return open_capture(path, CaptureImportOptions {}, nullptr);
}

bool CaptureSession::open_capture(const std::filesystem::path& path, OpenContext* ctx) {
    return open_capture(path, CaptureImportOptions {}, ctx);
}

bool CaptureSession::open_capture(const std::filesystem::path& path, const CaptureImportOptions& options) {
    return open_capture(path, options, nullptr);
}

bool CaptureSession::open_capture(const std::filesystem::path& path, const CaptureImportOptions& options, OpenContext* ctx) {
    last_open_error_text_.clear();
    partial_open_ = false;
    partial_open_failure_ = {};
    OpenContext local_ctx {};
    OpenContext* effective_ctx = (ctx != nullptr) ? ctx : &local_ctx;
    effective_ctx->clear_failure();
    debug::log_if<debug::kDebugOpen>([&]() {
        std::clog << "open_capture: " << path.string() << " mode="
                  << ((options.mode == ImportMode::deep) ? "deep" : "fast") << '\n';
    });
    const auto started_at = std::chrono::steady_clock::now();
    PerfOpenLogger perf_logger {};
    const auto operation_type = (options.mode == ImportMode::deep)
        ? PerfOpenOperationType::capture_deep
        : PerfOpenOperationType::capture_fast;

    CaptureImporter importer {};
    CaptureState imported_state {};
    const auto import_result = importer.import_capture_result(path, imported_state, options, effective_ctx);

    if (import_result == CaptureImportResult::failure) {
        debug::log_if<debug::kDebugOpen>([&]() {
            std::clog << "open_capture failed: " << path.string() << '\n';
        });
        const auto failureText = build_open_failure_message(effective_ctx, fallback_open_failure("capture import failed"));
        reset_runtime_state();
        last_open_error_text_ = failureText;
        log_open_result(
            perf_logger,
            operation_type,
            path,
            false,
            started_at,
            summary(),
            opened_from_index(),
            has_source_capture()
        );
        return false;
    }

    capture_path_ = path;
    source_capture_path_ = path;
    state_ = imported_state;
    import_mode_ = options.mode;
    analysis_settings_ = options.settings;
    deep_protocol_details_enabled_ = (options.mode == ImportMode::deep);
    opened_from_index_ = false;
    has_loaded_state_ = true;
    partial_open_ = (import_result == CaptureImportResult::partial_success_with_warning);
    partial_open_failure_ = effective_ctx->failure;
    source_info_ = {};
    selected_flow_packet_cache_.reset();
    selected_flow_tcp_payload_suppression_.reset();
    if (!read_capture_source_info(path, source_info_)) {
        source_info_.capture_path = path;
    }

    debug::log_if<debug::kDebugOpen>([&]() {
        std::clog << (partial_open_ ? "open_capture partial: " : "open_capture succeeded: ") << path.string() << '\n';
    });
    log_open_result(
        perf_logger,
        operation_type,
        path,
        true,
        started_at,
        summary(),
        opened_from_index(),
        has_source_capture()
    );
    return true;
}

bool CaptureSession::open_input(const std::filesystem::path& path) {
    return open_input(path, nullptr);
}

bool CaptureSession::open_input(const std::filesystem::path& path, OpenContext* ctx) {
    if (looks_like_index_file(path)) {
        return load_index(path, ctx);
    }

    return open_capture(path, ctx);
}

bool CaptureSession::save_index(const std::filesystem::path& index_path) const {
    if (partial_open_ || !has_source_capture()) {
        return false;
    }

    CaptureIndexWriter writer {};
    return writer.write(index_path, state_, capture_path_);
}

bool CaptureSession::load_index(const std::filesystem::path& index_path) {
    return load_index(index_path, nullptr);
}

bool CaptureSession::load_index(const std::filesystem::path& index_path, OpenContext* ctx) {
    last_open_error_text_.clear();
    OpenContext local_ctx {};
    OpenContext* effective_ctx = (ctx != nullptr) ? ctx : &local_ctx;
    effective_ctx->clear_failure();
    debug::log_if<debug::kDebugIndexLoad>([&]() {
        std::clog << "load_index: " << index_path.string() << '\n';
    });
    const auto started_at = std::chrono::steady_clock::now();
    PerfOpenLogger perf_logger {};

    CaptureIndexReader reader {};
    CaptureState loaded_state {};
    std::filesystem::path loaded_capture_path {};
    CaptureSourceInfo loaded_source_info {};

    if (!reader.read(index_path, loaded_state, loaded_capture_path, &loaded_source_info, effective_ctx)) {
        debug::log_if<debug::kDebugIndexLoad>([&]() {
            std::clog << "load_index failed: " << index_path.string() << '\n';
        });
        const auto fallback_failure = reader.last_error().has_details()
            ? reader.last_error()
            : fallback_open_failure("index read failed");
        const auto failureText = build_open_failure_message(effective_ctx, fallback_failure);
        reset_runtime_state();
        last_open_error_text_ = failureText;
        log_open_result(
            perf_logger,
            PerfOpenOperationType::index_load,
            index_path,
            false,
            started_at,
            summary(),
            opened_from_index(),
            has_source_capture()
        );
        return false;
    }

    capture_path_.clear();
    source_capture_path_ = loaded_capture_path;
    source_info_ = loaded_source_info;
    state_ = loaded_state;
    import_mode_ = ImportMode::fast;
    analysis_settings_ = {};
    deep_protocol_details_enabled_ = false;
    opened_from_index_ = true;
    has_loaded_state_ = true;
    partial_open_ = false;
    partial_open_failure_ = {};
    selected_flow_packet_cache_.reset();
    selected_flow_tcp_payload_suppression_.reset();

    if (validate_capture_source(source_info_)) {
        capture_path_ = source_info_.capture_path;
    }

    debug::log_if<debug::kDebugIndexLoad>([&]() {
        std::clog << "load_index succeeded: " << index_path.string() << '\n';
    });
    log_open_result(
        perf_logger,
        PerfOpenOperationType::index_load,
        index_path,
        true,
        started_at,
        summary(),
        opened_from_index(),
        has_source_capture()
    );
    return true;
}

bool CaptureSession::has_capture() const noexcept {
    return has_loaded_state_;
}

bool CaptureSession::has_source_capture() const noexcept {
    return !capture_path_.empty();
}

bool CaptureSession::opened_from_index() const noexcept {
    return opened_from_index_;
}

bool CaptureSession::is_partial_open() const noexcept {
    return partial_open_;
}

const OpenFailureInfo& CaptureSession::partial_open_failure() const noexcept {
    return partial_open_failure_;
}

const std::string& CaptureSession::last_open_error_text() const noexcept {
    return last_open_error_text_;
}

bool CaptureSession::attach_source_capture(const std::filesystem::path& path) {
    if (!opened_from_index_) {
        return false;
    }

    if (!validate_capture_source(source_info_, path)) {
        return false;
    }

    capture_path_ = path;
    source_capture_path_ = path;
    source_info_.capture_path = path;
    selected_flow_packet_cache_.reset();
    return true;
}

const std::filesystem::path& CaptureSession::capture_path() const noexcept {
    return source_capture_path_;
}

const std::filesystem::path& CaptureSession::attached_source_capture_path() const noexcept {
    return capture_path_;
}

const std::filesystem::path& CaptureSession::expected_source_capture_path() const noexcept {
    return source_capture_path_;
}

const CaptureSummary& CaptureSession::summary() const noexcept {
    return state_.summary;
}

CaptureProtocolSummary CaptureSession::protocol_summary() const noexcept {
    CaptureProtocolSummary summary {};

    for (const auto& connection : list_connections(state_)) {
        if (connection.family == FlowAddressFamily::ipv4) {
            add_protocol_stats(summary.ipv4, connection);
        } else {
            add_protocol_stats(summary.ipv6, connection);
        }

        switch (protocol_id(connection)) {
        case ProtocolId::tcp:
            add_protocol_stats(summary.tcp, connection);
            break;
        case ProtocolId::udp:
            add_protocol_stats(summary.udp, connection);
            break;
        default:
            add_protocol_stats(summary.other, connection);
            break;
        }

        switch (effective_protocol_hint(connection, analysis_settings_)) {
        case FlowProtocolHint::http:
            add_protocol_stats(summary.hint_http, connection);
            break;
        case FlowProtocolHint::tls:
            add_protocol_stats(summary.hint_tls, connection);
            break;
        case FlowProtocolHint::dns:
            add_protocol_stats(summary.hint_dns, connection);
            break;
        case FlowProtocolHint::quic:
            add_protocol_stats(summary.hint_quic, connection);
            break;
        case FlowProtocolHint::ssh:
            add_protocol_stats(summary.hint_ssh, connection);
            break;
        case FlowProtocolHint::stun:
            add_protocol_stats(summary.hint_stun, connection);
            break;
        case FlowProtocolHint::bittorrent:
            add_protocol_stats(summary.hint_bittorrent, connection);
            break;
        case FlowProtocolHint::dhcp:
            add_protocol_stats(summary.hint_dhcp, connection);
            break;
        case FlowProtocolHint::mdns:
            add_protocol_stats(summary.hint_mdns, connection);
            break;
        case FlowProtocolHint::smtp:
            add_protocol_stats(summary.hint_smtp, connection);
            add_protocol_stats(summary.hint_mail_protocols, connection);
            break;
        case FlowProtocolHint::pop3:
            add_protocol_stats(summary.hint_pop3, connection);
            add_protocol_stats(summary.hint_mail_protocols, connection);
            break;
        case FlowProtocolHint::imap:
            add_protocol_stats(summary.hint_imap, connection);
            add_protocol_stats(summary.hint_mail_protocols, connection);
            break;
        case FlowProtocolHint::possible_tls:
            add_protocol_stats(summary.hint_possible_tls, connection);
            break;
        case FlowProtocolHint::possible_quic:
            add_protocol_stats(summary.hint_possible_quic, connection);
            break;
        case FlowProtocolHint::unknown:
        default:
            add_protocol_stats(summary.hint_unknown, connection);
            break;
        }
    }

    return summary;
}

void CaptureSession::set_analysis_settings(const AnalysisSettings& settings) noexcept {
    analysis_settings_ = settings;
}

QuicRecognitionStats CaptureSession::quic_recognition_stats() const noexcept {
    QuicRecognitionStats stats {};

    const auto connections = list_connections(state_);
    for (const auto& connection : connections) {
        const auto protocol_hint = (connection.family == FlowAddressFamily::ipv4)
            ? connection.ipv4->protocol_hint
            : connection.ipv6->protocol_hint;
        if (protocol_hint != FlowProtocolHint::quic) {
            continue;
        }

        ++stats.total_flows;

        const auto& service_hint = (connection.family == FlowAddressFamily::ipv4)
            ? connection.ipv4->service_hint
            : connection.ipv6->service_hint;
        if (service_hint.empty()) {
            ++stats.without_sni;
        } else {
            ++stats.with_sni;
        }

        const auto version_hint = (connection.family == FlowAddressFamily::ipv4)
            ? connection.ipv4->quic_version
            : connection.ipv6->quic_version;
        switch (version_hint) {
        case QuicVersionHint::v1:
            ++stats.version_v1;
            break;
        case QuicVersionHint::draft29:
            ++stats.version_draft29;
            break;
        case QuicVersionHint::v2:
            ++stats.version_v2;
            break;
        case QuicVersionHint::unknown:
        default:
            ++stats.version_unknown;
            break;
        }
    }

#ifndef NDEBUG
    const auto sni_sum = stats.with_sni + stats.without_sni;
    const auto version_sum = stats.version_v1 + stats.version_draft29 + stats.version_v2 + stats.version_unknown;
    assert(sni_sum == stats.total_flows);
    assert(version_sum == stats.total_flows);
#endif

    return stats;
}

TlsRecognitionStats CaptureSession::tls_recognition_stats() const noexcept {
    TlsRecognitionStats stats {};

    const auto connections = list_connections(state_);
    for (const auto& connection : connections) {
        const auto protocol_hint = (connection.family == FlowAddressFamily::ipv4)
            ? connection.ipv4->protocol_hint
            : connection.ipv6->protocol_hint;
        if (protocol_hint != FlowProtocolHint::tls) {
            continue;
        }

        ++stats.total_flows;

        const auto& service_hint = (connection.family == FlowAddressFamily::ipv4)
            ? connection.ipv4->service_hint
            : connection.ipv6->service_hint;
        if (service_hint.empty()) {
            ++stats.without_sni;
        } else {
            ++stats.with_sni;
        }

        const auto version_hint = (connection.family == FlowAddressFamily::ipv4)
            ? connection.ipv4->tls_version
            : connection.ipv6->tls_version;
        switch (version_hint) {
        case TlsVersionHint::tls12:
            ++stats.version_tls12;
            break;
        case TlsVersionHint::tls13:
            ++stats.version_tls13;
            break;
        case TlsVersionHint::unknown:
        default:
            ++stats.version_unknown;
            break;
        }
    }

#ifndef NDEBUG
    const auto sni_sum = stats.with_sni + stats.without_sni;
    const auto version_sum = stats.version_tls12 + stats.version_tls13 + stats.version_unknown;
    assert(sni_sum == stats.total_flows);
    assert(version_sum == stats.total_flows);
#endif

    return stats;
}

CaptureTopSummary CaptureSession::top_summary(const std::size_t limit) const {
    std::map<std::string, TopEndpointRow> endpoints {};
    std::map<std::uint16_t, TopPortRow> ports {};

    for (const auto& connection : list_connections(state_)) {
        const auto connection_packets = packet_count(connection);
        const auto connection_bytes = total_bytes(connection);

        if (connection.family == FlowAddressFamily::ipv4) {
            const auto& key = connection.ipv4->key;

            for (const auto& endpointText : {format_endpoint(key.first), format_endpoint(key.second)}) {
                auto& row = endpoints[endpointText];
                row.endpoint = endpointText;
                row.packet_count += connection_packets;
                row.total_bytes += connection_bytes;
            }

            for (const auto port : {key.first.port, key.second.port}) {
                if (port == 0U) {
                    continue;
                }

                auto& row = ports[port];
                row.port = port;
                row.packet_count += connection_packets;
                row.total_bytes += connection_bytes;
            }
        } else {
            const auto& key = connection.ipv6->key;

            for (const auto& endpointText : {format_endpoint(key.first), format_endpoint(key.second)}) {
                auto& row = endpoints[endpointText];
                row.endpoint = endpointText;
                row.packet_count += connection_packets;
                row.total_bytes += connection_bytes;
            }

            for (const auto port : {key.first.port, key.second.port}) {
                if (port == 0U) {
                    continue;
                }

                auto& row = ports[port];
                row.port = port;
                row.packet_count += connection_packets;
                row.total_bytes += connection_bytes;
            }
        }
    }

    CaptureTopSummary summary {};
    summary.endpoints_by_bytes.reserve(endpoints.size());
    summary.ports_by_bytes.reserve(ports.size());

    for (const auto& [_, row] : endpoints) {
        summary.endpoints_by_bytes.push_back(row);
    }

    for (const auto& [_, row] : ports) {
        summary.ports_by_bytes.push_back(row);
    }

    std::sort(summary.endpoints_by_bytes.begin(), summary.endpoints_by_bytes.end(), [](const TopEndpointRow& left, const TopEndpointRow& right) {
        if (left.total_bytes != right.total_bytes) {
            return left.total_bytes > right.total_bytes;
        }
        if (left.packet_count != right.packet_count) {
            return left.packet_count > right.packet_count;
        }
        return left.endpoint < right.endpoint;
    });

    std::sort(summary.ports_by_bytes.begin(), summary.ports_by_bytes.end(), [](const TopPortRow& left, const TopPortRow& right) {
        if (left.total_bytes != right.total_bytes) {
            return left.total_bytes > right.total_bytes;
        }
        if (left.packet_count != right.packet_count) {
            return left.packet_count > right.packet_count;
        }
        return left.port < right.port;
    });

    if (summary.endpoints_by_bytes.size() > limit) {
        summary.endpoints_by_bytes.resize(limit);
    }

    if (summary.ports_by_bytes.size() > limit) {
        summary.ports_by_bytes.resize(limit);
    }

    return summary;
}

std::vector<std::uint8_t> CaptureSession::read_packet_data(const PacketRef& packet) const {
    if (!has_source_capture()) {
        return {};
    }

    CaptureFilePacketReader reader {capture_path_};
    if (!reader.is_open()) {
        return {};
    }

    return reader.read_packet_data(packet);
}

std::vector<std::uint8_t> CaptureSession::read_transport_payload_direct(const PacketRef& packet) const {
    const auto packet_bytes = read_packet_data(packet);
    if (packet_bytes.empty()) {
        return {};
    }

    PacketPayloadService payload_service {};
    return payload_service.extract_transport_payload(packet_bytes, packet.data_link_type);
}

const CaptureSession::SelectedFlowPacketCacheEntry* CaptureSession::find_selected_flow_packet_cache_entry(
    const std::size_t flow_index,
    const std::uint64_t packet_index
) const noexcept {
    if (!selected_flow_packet_cache_.has_value() || selected_flow_packet_cache_->flow_index != flow_index) {
        return nullptr;
    }

    const auto it = selected_flow_packet_cache_->entry_index_by_packet_index.find(packet_index);
    if (it == selected_flow_packet_cache_->entry_index_by_packet_index.end() ||
        it->second >= selected_flow_packet_cache_->entries.size()) {
        return nullptr;
    }

    return &selected_flow_packet_cache_->entries[it->second];
}

void CaptureSession::prepare_selected_flow_packet_cache(
    const std::size_t flow_index,
    const std::size_t max_packets_to_scan
) const {
    if (!has_source_capture() || max_packets_to_scan == 0U) {
        selected_flow_packet_cache_.reset();
        return;
    }

    const auto connections = list_connections(state_);
    if (flow_index >= connections.size()) {
        selected_flow_packet_cache_.reset();
        return;
    }

    const auto& connection_ref = connections[flow_index];
    const auto flow_protocol = protocol_id(connection_ref);
    if (flow_protocol != ProtocolId::tcp && flow_protocol != ProtocolId::udp) {
        selected_flow_packet_cache_.reset();
        return;
    }

    if (!selected_flow_packet_cache_.has_value() || selected_flow_packet_cache_->flow_index != flow_index) {
        SelectedFlowPacketCache cache {};
        cache.flow_index = flow_index;
        cache.bytes.reserve(std::min(kSelectedFlowPacketCacheMaxBytes, std::size_t {64U} * 1024U));
        selected_flow_packet_cache_ = std::move(cache);
    }

    auto& cache = *selected_flow_packet_cache_;
    if (cache.limit_reached || cache.cached_packet_window_count >= max_packets_to_scan) {
        cache.window_fully_cached = !cache.limit_reached &&
            !cache.has_uncached_payload_entries &&
            cache.cached_packet_window_count >= max_packets_to_scan;
        return;
    }

    const auto append_for_connection = [&](const auto& connection) {
        std::size_t index_a = 0U;
        std::size_t index_b = 0U;
        std::size_t row_number = 0U;

        while ((index_a < connection.flow_a.packets.size() || index_b < connection.flow_b.packets.size()) &&
               row_number < cache.cached_packet_window_count) {
            const bool use_a = index_b >= connection.flow_b.packets.size() ||
                (index_a < connection.flow_a.packets.size() &&
                 connection.flow_a.packets[index_a].packet_index <= connection.flow_b.packets[index_b].packet_index);
            if (use_a) {
                ++index_a;
            } else {
                ++index_b;
            }
            ++row_number;
        }

        while ((index_a < connection.flow_a.packets.size() || index_b < connection.flow_b.packets.size()) &&
               row_number < max_packets_to_scan &&
               !cache.limit_reached) {
            const bool use_a = index_b >= connection.flow_b.packets.size() ||
                (index_a < connection.flow_a.packets.size() &&
                 connection.flow_a.packets[index_a].packet_index <= connection.flow_b.packets[index_b].packet_index);

            const auto& packet = use_a ? connection.flow_a.packets[index_a++] : connection.flow_b.packets[index_b++];
            const auto direction = use_a ? Direction::a_to_b : Direction::b_to_a;

            auto payload_bytes = packet.payload_length == 0U ? std::vector<std::uint8_t> {} : read_transport_payload_direct(packet);
            const bool payload_cached = packet.payload_length == 0U ||
                (!payload_bytes.empty() && payload_bytes.size() == packet.payload_length);
            if (!payload_cached) {
                if (packet.payload_length > 0U) {
                    cache.has_uncached_payload_entries = true;
                }
                payload_bytes.clear();
            }

            const auto additional_bytes = payload_bytes.size();
            if (cache.bytes.size() + additional_bytes > kSelectedFlowPacketCacheMaxBytes) {
                cache.limit_reached = true;
                cache.window_fully_cached = false;
                break;
            }

            const auto cache_offset = cache.bytes.size();
            cache.bytes.insert(cache.bytes.end(), payload_bytes.begin(), payload_bytes.end());

            cache.entry_index_by_packet_index.insert_or_assign(packet.packet_index, cache.entries.size());
            cache.entries.push_back(SelectedFlowPacketCacheEntry {
                .flow_local_packet_number = static_cast<std::uint64_t>(row_number + 1U),
                .packet_index = packet.packet_index,
                .direction = direction,
                .cache_offset = cache_offset,
                .cache_length = additional_bytes,
                .payload_length = packet.payload_length,
                .payload_cached = payload_cached,
            });

            ++row_number;
            cache.cached_packet_window_count = row_number;
        }

        cache.window_fully_cached = !cache.limit_reached &&
            !cache.has_uncached_payload_entries &&
            cache.cached_packet_window_count >= max_packets_to_scan;
    };

    if (connection_ref.family == FlowAddressFamily::ipv4) {
        append_for_connection(*connection_ref.ipv4);
    } else {
        append_for_connection(*connection_ref.ipv6);
    }
}

void CaptureSession::clear_selected_flow_packet_cache() noexcept {
    selected_flow_packet_cache_.reset();
}

std::optional<SelectedFlowPacketCacheInfo> CaptureSession::selected_flow_packet_cache_info() const noexcept {
    if (!selected_flow_packet_cache_.has_value()) {
        return std::nullopt;
    }

    const auto& cache = *selected_flow_packet_cache_;
    return SelectedFlowPacketCacheInfo {
        .flow_index = cache.flow_index,
        .cached_packet_window_count = cache.cached_packet_window_count,
        .cached_packet_contribution_count = cache.entries.size(),
        .total_cached_bytes = cache.bytes.size(),
        .limit_reached = cache.limit_reached,
        .window_fully_cached = cache.window_fully_cached,
    };
}

bool CaptureSession::selected_flow_packet_cache_limit_reached() const noexcept {
    return selected_flow_packet_cache_.has_value() && selected_flow_packet_cache_->limit_reached;
}

std::vector<std::uint8_t> CaptureSession::read_selected_flow_transport_payload(
    const std::size_t flow_index,
    const PacketRef& packet
) const {
    if (const auto* entry = find_selected_flow_packet_cache_entry(flow_index, packet.packet_index); entry != nullptr) {
        if (entry->payload_cached) {
            const auto begin = selected_flow_packet_cache_->bytes.begin() + static_cast<std::ptrdiff_t>(entry->cache_offset);
            const auto end = begin + static_cast<std::ptrdiff_t>(entry->cache_length);
            return std::vector<std::uint8_t>(begin, end);
        }

        return read_transport_payload_direct(packet);
    }

    return read_transport_payload_direct(packet);
}

std::optional<PacketDetails> CaptureSession::read_packet_details(const PacketRef& packet) const {
    const auto bytes = read_packet_data(packet);
    if (bytes.empty()) {
        return std::nullopt;
    }

    PacketDetailsService service {};
    return service.decode(bytes, packet);
}

std::string CaptureSession::read_packet_hex_dump(const PacketRef& packet) const {
    const auto bytes = read_packet_data(packet);
    if (bytes.empty()) {
        return {};
    }

    HexDumpService service {};
    return service.format(bytes);
}

std::string CaptureSession::read_packet_payload_hex_dump(const PacketRef& packet) const {
    const auto bytes = read_packet_data(packet);
    if (bytes.empty()) {
        return {};
    }

    PacketPayloadService payload_service {};
    const auto payload_bytes = payload_service.extract_transport_payload(bytes, packet.data_link_type);

    HexDumpService hex_dump_service {};
    return hex_dump_service.format(payload_bytes);
}

std::string CaptureSession::read_packet_protocol_details_text(const PacketRef& packet) const {
    if (packet.is_ip_fragmented) {
        return std::string {kFragmentedProtocolDetailsMessage};
    }

    const auto bytes = read_packet_data(packet);
    if (bytes.empty()) {
        return std::string {kUnavailableProtocolDetailsMessage};
    }

    TlsPacketProtocolAnalyzer tls_analyzer {};
    if (const auto tls_details = tls_analyzer.analyze(bytes, packet.data_link_type); tls_details.has_value()) {
        return *tls_details;
    }

    QuicPacketProtocolAnalyzer quic_analyzer {};
    if (const auto quic_details = quic_analyzer.analyze(bytes, packet.data_link_type); quic_details.has_value()) {
        return *quic_details;
    }

    DnsPacketProtocolAnalyzer dns_analyzer {};
    if (const auto dns_details = dns_analyzer.analyze(bytes, packet.data_link_type); dns_details.has_value()) {
        return *dns_details;
    }

    HttpPacketProtocolAnalyzer http_analyzer {};
    if (const auto http_details = http_analyzer.analyze(bytes, packet.data_link_type); http_details.has_value()) {
        return *http_details;
    }

    PacketDetailsService details_service {};
    if (const auto details = details_service.decode(bytes, packet); details.has_value()) {
        if (const auto generic_details = build_basic_protocol_details_text(*details); generic_details.has_value()) {
            return *generic_details;
        }
    }

    return std::string {kNoProtocolDetailsMessage};
}
std::optional<ReassemblyResult> CaptureSession::reassemble_flow_direction(const ReassemblyRequest& request) const {
    if (!has_loaded_state_) {
        return std::nullopt;
    }

    if (!has_source_capture()) {
        return std::nullopt;
    }

    if (!flow_packets(request.flow_index).has_value()) {
        return std::nullopt;
    }

    ReassemblyService service {};
    return service.reassemble_tcp_payload(*this, request);
}
std::optional<std::string> CaptureSession::derive_quic_service_hint_for_flow(const std::size_t flow_index) const {
    if (!has_source_capture()) {
        return std::nullopt;
    }

    const auto connections = list_connections(state_);
    if (flow_index >= connections.size()) {
        return std::nullopt;
    }

    constexpr std::size_t kOnDemandQuicHintPacketBudget = 4U;
    FlowHintService hint_service {analysis_settings_, true};

    const auto try_direction = [&](const auto& flow_key, const auto& packets) -> std::optional<std::string> {
        const auto packet_limit = std::min(kOnDemandQuicHintPacketBudget, packets.size());
        for (std::size_t index = 0U; index < packet_limit; ++index) {
            const auto& packet = packets[index];
            if (packet.is_ip_fragmented) {
                continue;
            }

            const auto packet_bytes = read_packet_data(packet);
            if (packet_bytes.empty()) {
                continue;
            }

            const auto hint = hint_service.detect(
                std::span<const std::uint8_t>(packet_bytes.data(), packet_bytes.size()),
                packet.data_link_type,
                flow_key);
            if (!hint.service_hint.empty()) {
                return hint.service_hint;
            }
        }

        return std::nullopt;
    };

    if (connections[flow_index].family == FlowAddressFamily::ipv4) {
        const auto& connection = *connections[flow_index].ipv4;
        if (connection.key.protocol != ProtocolId::udp) {
            return std::nullopt;
        }

        const auto try_flow = [&](const FlowV4& flow, const bool has_flow) -> std::optional<std::string> {
            if (!has_flow || flow.key.src_port == 443 || flow.key.dst_port != 443) {
                return std::nullopt;
            }
            return try_direction(flow.key, flow.packets);
        };

        if (const auto from_flow_a = try_flow(connection.flow_a, connection.has_flow_a); from_flow_a.has_value()) {
            return from_flow_a;
        }

        return try_flow(connection.flow_b, connection.has_flow_b);
    }

    const auto& connection = *connections[flow_index].ipv6;
    if (connection.key.protocol != ProtocolId::udp) {
        return std::nullopt;
    }

    const auto try_flow = [&](const FlowV6& flow, const bool has_flow) -> std::optional<std::string> {
        if (!has_flow || flow.key.src_port == 443 || flow.key.dst_port != 443) {
            return std::nullopt;
        }
        return try_direction(flow.key, flow.packets);
    };

    if (const auto from_flow_a = try_flow(connection.flow_a, connection.has_flow_a); from_flow_a.has_value()) {
        return from_flow_a;
    }

    return try_flow(connection.flow_b, connection.has_flow_b);
}

std::optional<std::string> CaptureSession::derive_quic_protocol_text_for_packet(
    const std::size_t flow_index,
    const std::uint64_t packet_index
) const {
    return derive_quic_protocol_text_for_packet_context(flow_index, std::vector<std::uint64_t> {packet_index});
}

std::optional<std::string> CaptureSession::derive_quic_protocol_text_for_packet_context(
    const std::size_t flow_index,
    const std::vector<std::uint64_t>& packet_indices
) const {
    if (!has_source_capture() || packet_indices.empty()) {
        return std::nullopt;
    }

    const auto connections = list_connections(state_);
    if (flow_index >= connections.size()) {
        return std::nullopt;
    }

    std::vector<std::uint64_t> selected_packet_indices = packet_indices;
    std::sort(selected_packet_indices.begin(), selected_packet_indices.end());
    selected_packet_indices.erase(
        std::unique(selected_packet_indices.begin(), selected_packet_indices.end()),
        selected_packet_indices.end()
    );

    const auto build_for_connection = [&](const auto& connection) -> std::optional<std::string> {
        if (connection.key.protocol != ProtocolId::udp) {
            return std::nullopt;
        }

        const auto initial_secret_connection_id = find_quic_client_initial_connection_id_for_connection(*this, connection, flow_index);
        const auto initial_secret_connection_id_span = initial_secret_connection_id.has_value()
            ? std::span<const std::uint8_t>(initial_secret_connection_id->data(), initial_secret_connection_id->size())
            : std::span<const std::uint8_t> {};

        std::optional<QuicPresentationResult> result {};
        if (connection.has_flow_a) {
            result = build_quic_presentation_for_selected_direction(
                *this,
                connection.flow_a.key,
                connection.flow_a.packets,
                selected_packet_indices,
                initial_secret_connection_id_span,
                flow_index
            );
        }
        if (!result.has_value() && connection.has_flow_b) {
            result = build_quic_presentation_for_selected_direction(
                *this,
                connection.flow_b.key,
                connection.flow_b.packets,
                selected_packet_indices,
                initial_secret_connection_id_span,
                flow_index
            );
        }

        if (!result.has_value()) {
            return std::nullopt;
        }

        return format_quic_presentation_protocol_text(*result);
    };

    if (connections[flow_index].family == FlowAddressFamily::ipv4) {
        return build_for_connection(*connections[flow_index].ipv4);
    }

    return build_for_connection(*connections[flow_index].ipv6);
}

std::optional<std::string> CaptureSession::derive_quic_protocol_details_for_packet(
    const std::size_t flow_index,
    const std::uint64_t packet_index
) const {
    return derive_quic_protocol_details_for_packet_context(flow_index, std::vector<std::uint64_t> {packet_index});
}

std::optional<std::string> CaptureSession::derive_quic_protocol_details_for_packet_context(
    const std::size_t flow_index,
    const std::vector<std::uint64_t>& packet_indices
) const {
    if (!has_source_capture() || packet_indices.empty()) {
        return std::nullopt;
    }

    const auto connections = list_connections(state_);
    if (flow_index >= connections.size()) {
        return std::nullopt;
    }

    std::vector<std::uint64_t> selected_packet_indices = packet_indices;
    std::sort(selected_packet_indices.begin(), selected_packet_indices.end());
    selected_packet_indices.erase(
        std::unique(selected_packet_indices.begin(), selected_packet_indices.end()),
        selected_packet_indices.end()
    );

    const auto build_for_connection = [&](const auto& connection) -> std::optional<std::string> {
        if (connection.key.protocol != ProtocolId::udp) {
            return std::nullopt;
        }

        const auto initial_secret_connection_id = find_quic_client_initial_connection_id_for_connection(*this, connection, flow_index);
        const auto initial_secret_connection_id_span = initial_secret_connection_id.has_value()
            ? std::span<const std::uint8_t>(initial_secret_connection_id->data(), initial_secret_connection_id->size())
            : std::span<const std::uint8_t> {};

        std::optional<QuicPresentationResult> result {};
        if (connection.has_flow_a) {
            result = build_quic_presentation_for_selected_direction(
                *this,
                connection.flow_a.key,
                connection.flow_a.packets,
                selected_packet_indices,
                initial_secret_connection_id_span,
                flow_index
            );
        }
        if (!result.has_value() && connection.has_flow_b) {
            result = build_quic_presentation_for_selected_direction(
                *this,
                connection.flow_b.key,
                connection.flow_b.packets,
                selected_packet_indices,
                initial_secret_connection_id_span,
                flow_index
            );
        }

        if (!result.has_value()) {
            return std::nullopt;
        }

        return format_quic_presentation_enrichment(*result);
    };

    if (connections[flow_index].family == FlowAddressFamily::ipv4) {
        return build_for_connection(*connections[flow_index].ipv4);
    }

    return build_for_connection(*connections[flow_index].ipv6);
}

std::vector<FlowRow> CaptureSession::list_flows() const {
    const auto connections = list_connections(state_);
    std::vector<FlowRow> rows {};
    rows.reserve(connections.size());

    for (std::size_t index = 0; index < connections.size(); ++index) {
        rows.push_back(make_flow_row(index, connections[index], analysis_settings_));
    }

    return rows;
}

std::optional<FlowAnalysisResult> CaptureSession::get_flow_analysis(const std::size_t flow_index) const {
    const auto connections = list_connections(state_);
    if (flow_index >= connections.size()) {
        return std::nullopt;
    }

    FlowAnalysisService service {};
    auto result = connections[flow_index].family == FlowAddressFamily::ipv4
        ? service.analyze(*connections[flow_index].ipv4)
        : service.analyze(*connections[flow_index].ipv6);
    const auto hint = effective_protocol_hint(connections[flow_index], analysis_settings_);
    result.protocol_hint = hint == FlowProtocolHint::unknown ? std::string {} : std::string(flow_protocol_hint_text(hint));
    return result;
}

std::vector<PacketRow> CaptureSession::list_flow_packets(const std::size_t flow_index) const {
    return list_flow_packets(flow_index, 0U, flow_packet_count(flow_index));
}

std::vector<PacketRow> CaptureSession::list_flow_packets(
    const std::size_t flow_index,
    const std::size_t offset,
    const std::size_t limit
) const {
    const auto connections = list_connections(state_);
    if (flow_index >= connections.size()) {
        return {};
    }

    if (connections[flow_index].family == FlowAddressFamily::ipv4) {
        return slice_connection_packets(*connections[flow_index].ipv4, offset, limit);
    }

    return slice_connection_packets(*connections[flow_index].ipv6, offset, limit);
}

std::vector<std::uint64_t> CaptureSession::suspected_tcp_retransmission_packet_indices(const std::size_t flow_index) const {
    return suspected_tcp_retransmission_packet_indices(flow_index, flow_packet_count(flow_index));
}

std::vector<std::uint64_t> CaptureSession::suspected_tcp_retransmission_packet_indices(
    const std::size_t flow_index,
    const std::size_t max_packets_to_scan
) const {
    if (!has_source_capture()) {
        return {};
    }

    prepare_selected_flow_packet_cache(flow_index, max_packets_to_scan);

    const auto connections = list_connections(state_);
    if (flow_index >= connections.size()) {
        return {};
    }

    if (connections[flow_index].family == FlowAddressFamily::ipv4) {
        if (connections[flow_index].ipv4->key.protocol != ProtocolId::tcp) {
            return {};
        }

        return collect_suspected_tcp_retransmission_packet_indices(*this, flow_index, *connections[flow_index].ipv4, max_packets_to_scan);
    }

    if (connections[flow_index].ipv6->key.protocol != ProtocolId::tcp) {
        return {};
    }

    return collect_suspected_tcp_retransmission_packet_indices(*this, flow_index, *connections[flow_index].ipv6, max_packets_to_scan);
}

void CaptureSession::set_selected_flow_tcp_payload_suppression(
    const std::size_t flow_index,
    const std::vector<std::uint64_t>& packet_indices
) noexcept {
    set_selected_flow_tcp_payload_suppression(flow_index, packet_indices, flow_packet_count(flow_index));
}

void CaptureSession::set_selected_flow_tcp_payload_suppression(
    const std::size_t flow_index,
    const std::vector<std::uint64_t>& packet_indices,
    const std::size_t max_packets_to_scan
) noexcept {
    const auto connections = list_connections(state_);
    if (flow_index >= connections.size()) {
        selected_flow_tcp_payload_suppression_.reset();
        return;
    }

    const auto& connection = connections[flow_index];
    if (protocol_id(connection) != ProtocolId::tcp) {
        selected_flow_tcp_payload_suppression_.reset();
        return;
    }

    const std::set<std::uint64_t> exact_duplicate_packet_indices(packet_indices.begin(), packet_indices.end());
    const auto [prefix_count_a, prefix_count_b] = connection.family == FlowAddressFamily::ipv4
        ? flow_packet_prefix_direction_counts(*connection.ipv4, max_packets_to_scan)
        : flow_packet_prefix_direction_counts(*connection.ipv6, max_packets_to_scan);

    const auto direction_a_analysis = connection.family == FlowAddressFamily::ipv4
        ? build_selected_flow_tcp_payload_suppression_for_direction(*this, flow_index, connection.ipv4->flow_a.packets, exact_duplicate_packet_indices, prefix_count_a)
        : build_selected_flow_tcp_payload_suppression_for_direction(*this, flow_index, connection.ipv6->flow_a.packets, exact_duplicate_packet_indices, prefix_count_a);

    const auto direction_b_analysis = connection.family == FlowAddressFamily::ipv4
        ? build_selected_flow_tcp_payload_suppression_for_direction(*this, flow_index, connection.ipv4->flow_b.packets, exact_duplicate_packet_indices, prefix_count_b)
        : build_selected_flow_tcp_payload_suppression_for_direction(*this, flow_index, connection.ipv6->flow_b.packets, exact_duplicate_packet_indices, prefix_count_b);

    auto packet_contributions = direction_a_analysis.contributions;
    for (const auto& [packet_index, contribution] : direction_b_analysis.contributions) {
        packet_contributions[packet_index] = contribution;
    }

    if (packet_contributions.empty() && !direction_a_analysis.tainted_by_gap && !direction_b_analysis.tainted_by_gap) {
        selected_flow_tcp_payload_suppression_.reset();
        return;
    }

    SelectedFlowTcpPayloadSuppression suppression {};
    suppression.flow_index = flow_index;
    suppression.gap_state_a_to_b = SelectedFlowTcpDirectionalGapState {
        .tainted_by_gap = direction_a_analysis.tainted_by_gap,
        .first_gap_packet_index = direction_a_analysis.first_gap_packet_index,
    };
    suppression.gap_state_b_to_a = SelectedFlowTcpDirectionalGapState {
        .tainted_by_gap = direction_b_analysis.tainted_by_gap,
        .first_gap_packet_index = direction_b_analysis.first_gap_packet_index,
    };
    for (const auto& [packet_index, contribution] : packet_contributions) {
        suppression.packet_contributions.insert_or_assign(packet_index, SelectedFlowTcpPayloadContribution {
            .suppress_entire_packet = contribution.suppress_entire_packet,
            .trim_prefix_bytes = contribution.trim_prefix_bytes,
        });
    }
    selected_flow_tcp_payload_suppression_ = std::move(suppression);
}

void CaptureSession::clear_selected_flow_tcp_payload_suppression() noexcept {
    selected_flow_tcp_payload_suppression_.reset();
}

bool CaptureSession::should_suppress_selected_flow_tcp_payload(
    const std::size_t flow_index,
    const std::uint64_t packet_index
) const noexcept {
    if (!selected_flow_tcp_payload_suppression_.has_value() || selected_flow_tcp_payload_suppression_->flow_index != flow_index) {
        return false;
    }

    const auto it = selected_flow_tcp_payload_suppression_->packet_contributions.find(packet_index);
    return it != selected_flow_tcp_payload_suppression_->packet_contributions.end() && it->second.suppress_entire_packet;
}

std::size_t CaptureSession::selected_flow_tcp_payload_trim_prefix_bytes(
    const std::size_t flow_index,
    const std::uint64_t packet_index
) const noexcept {
    if (!selected_flow_tcp_payload_suppression_.has_value() || selected_flow_tcp_payload_suppression_->flow_index != flow_index) {
        return 0U;
    }

    const auto it = selected_flow_tcp_payload_suppression_->packet_contributions.find(packet_index);
    return it == selected_flow_tcp_payload_suppression_->packet_contributions.end()
        ? 0U
        : it->second.trim_prefix_bytes;
}

bool CaptureSession::selected_flow_tcp_direction_tainted_by_gap(
    const std::size_t flow_index,
    const Direction direction
) const noexcept {
    if (!selected_flow_tcp_payload_suppression_.has_value() || selected_flow_tcp_payload_suppression_->flow_index != flow_index) {
        return false;
    }

    const auto& gap_state = direction == Direction::a_to_b
        ? selected_flow_tcp_payload_suppression_->gap_state_a_to_b
        : selected_flow_tcp_payload_suppression_->gap_state_b_to_a;
    return gap_state.tainted_by_gap;
}

std::optional<std::uint64_t> CaptureSession::selected_flow_tcp_direction_first_gap_packet_index(
    const std::size_t flow_index,
    const Direction direction
) const noexcept {
    if (!selected_flow_tcp_payload_suppression_.has_value() || selected_flow_tcp_payload_suppression_->flow_index != flow_index) {
        return std::nullopt;
    }

    const auto& gap_state = direction == Direction::a_to_b
        ? selected_flow_tcp_payload_suppression_->gap_state_a_to_b
        : selected_flow_tcp_payload_suppression_->gap_state_b_to_a;
    if (!gap_state.tainted_by_gap || gap_state.first_gap_packet_index == 0U) {
        return std::nullopt;
    }

    return gap_state.first_gap_packet_index;
}

std::size_t CaptureSession::flow_packet_count(const std::size_t flow_index) const noexcept {
    const auto connections = list_connections(state_);
    if (flow_index >= connections.size()) {
        return 0U;
    }

    if (connections[flow_index].family == FlowAddressFamily::ipv4) {
        return connection_packet_count(*connections[flow_index].ipv4);
    }

    return connection_packet_count(*connections[flow_index].ipv6);
}

std::vector<StreamItemRow> CaptureSession::list_flow_stream_items(const std::size_t flow_index) const {
    return list_flow_stream_items(flow_index, 0U, std::numeric_limits<std::size_t>::max());
}

std::vector<StreamItemRow> CaptureSession::list_flow_stream_items(
    const std::size_t flow_index,
    const std::size_t offset,
    const std::size_t limit
) const {
    if (limit == 0U || !has_source_capture()) {
        return {};
    }

    const auto connections = list_connections(state_);
    if (flow_index >= connections.size()) {
        return {};
    }

    const auto flow_protocol = protocol_id(connections[flow_index]);
    if (flow_protocol != ProtocolId::tcp && flow_protocol != ProtocolId::udp) {
        return {};
    }

    const auto maxTarget = std::numeric_limits<std::size_t>::max();
    const auto target = (offset > maxTarget - limit) ? maxTarget : offset + limit;
    const auto max_packets_to_scan = connections[flow_index].family == FlowAddressFamily::ipv4
        ? connection_packet_count(*connections[flow_index].ipv4)
        : connection_packet_count(*connections[flow_index].ipv6);
    auto rows = build_flow_stream_items_bounded(
        *this,
        connections[flow_index],
        flow_index,
        max_packets_to_scan,
        target,
        deep_protocol_details_enabled_
    );

    if (offset >= rows.size()) {
        return {};
    }

    const auto slice_end = std::min(rows.size(), target);
    return std::vector<StreamItemRow>(rows.begin() + static_cast<std::ptrdiff_t>(offset), rows.begin() + static_cast<std::ptrdiff_t>(slice_end));
}

std::vector<StreamItemRow> CaptureSession::list_flow_stream_items_for_packet_prefix(
    const std::size_t flow_index,
    const std::size_t max_packets_to_scan,
    const std::size_t limit
) const {
    if (limit == 0U || max_packets_to_scan == 0U || !has_source_capture()) {
        return {};
    }

    const auto total_packets = flow_packet_count(flow_index);
    prepare_selected_flow_packet_cache(flow_index, std::min(total_packets, max_packets_to_scan));
    if (total_packets <= max_packets_to_scan) {
        return list_flow_stream_items(flow_index, 0U, limit);
    }

    const auto connections = list_connections(state_);
    if (flow_index >= connections.size()) {
        return {};
    }

    const auto flow_protocol = protocol_id(connections[flow_index]);
    if (flow_protocol != ProtocolId::tcp && flow_protocol != ProtocolId::udp) {
        return {};
    }

    return build_flow_stream_items_bounded(
        *this,
        connections[flow_index],
        flow_index,
        max_packets_to_scan,
        limit,
        deep_protocol_details_enabled_
    );
}
std::size_t CaptureSession::flow_stream_item_count(const std::size_t flow_index) const {
    return list_flow_stream_items(flow_index).size();
}

std::optional<std::vector<PacketRef>> CaptureSession::flow_packets(std::size_t flow_index) const {
    const auto connections = list_connections(state_);
    if (flow_index >= connections.size()) {
        return std::nullopt;
    }

    if (connections[flow_index].family == FlowAddressFamily::ipv4) {
        return collect_packets(*connections[flow_index].ipv4);
    }

    return collect_packets(*connections[flow_index].ipv6);
}

bool CaptureSession::export_flow_to_pcap(std::size_t flow_index, const std::filesystem::path& output_path) const {
    return export_flows_to_pcap({flow_index}, output_path);
}

bool CaptureSession::export_flows_to_pcap(const std::vector<std::size_t>& flow_indices, const std::filesystem::path& output_path) const {
    if (!has_source_capture() || flow_indices.empty()) {
        return false;
    }

    std::vector<PacketRef> packets {};
    for (const auto flow_index : flow_indices) {
        const auto flowPackets = flow_packets(flow_index);
        if (!flowPackets.has_value()) {
            return false;
        }

        packets.insert(packets.end(), flowPackets->begin(), flowPackets->end());
    }

    if (packets.empty()) {
        return false;
    }

    std::sort(packets.begin(), packets.end(), [](const PacketRef& left, const PacketRef& right) {
        return left.packet_index < right.packet_index;
    });
    packets.erase(std::unique(packets.begin(), packets.end(), [](const PacketRef& left, const PacketRef& right) {
        return left.packet_index == right.packet_index;
    }), packets.end());

    FlowExportService service {};
    return service.export_packets_to_pcap(output_path, packets, capture_path());
}

std::optional<PacketRef> CaptureSession::find_packet(std::uint64_t packet_index) const {
    for (const auto* connection : state_.ipv4_connections.list()) {
        const auto packet = find_packet_in_connection(*connection, packet_index);
        if (packet.has_value()) {
            return packet;
        }
    }

    for (const auto* connection : state_.ipv6_connections.list()) {
        const auto packet = find_packet_in_connection(*connection, packet_index);
        if (packet.has_value()) {
            return packet;
        }
    }

    return std::nullopt;
}

CaptureState& CaptureSession::state() noexcept {
    return state_;
}

const CaptureState& CaptureSession::state() const noexcept {
    return state_;
}

}  // namespace pfl









