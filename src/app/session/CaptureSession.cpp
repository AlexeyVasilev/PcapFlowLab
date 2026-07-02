#include "app/session/CaptureSession.h"
#include "app/session/SessionFlowHelpers.h"
#include "app/session/SessionFormatting.h"
#include "app/session/SessionHttpReconstruction.h"
#include "app/session/SessionOpenHelpers.h"
#include "app/session/SessionQuicPresentation.h"
#include "app/session/SessionTlsPresentation.h"
#include "app/session/SessionTcpStreamSupport.h"

#include <algorithm>
#include <cassert>
#include <chrono>
#include <array>
#include <fstream>
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
#include "core/services/TlsPacketProtocolAnalyzer.h"

namespace pfl {

namespace {

constexpr std::size_t kSelectedFlowPacketCacheMaxBytes = 16U * 1024U * 1024U;
constexpr std::size_t kSelectedFlowFullPacketCacheMaxBytes = 8U * 1024U * 1024U;

using session_detail::ListedConnectionRef;
using session_detail::add_protocol_stats;
using session_detail::build_basic_protocol_details_text;
using session_detail::build_open_failure_message;
using session_detail::collect_packets;
using session_detail::fallback_open_failure;
using session_detail::build_tls_stream_items_for_packet;
using session_detail::build_http_stream_items_from_reassembly;
using session_detail::build_tls_stream_items_from_reassembly;
using session_detail::format_endpoint;
using session_detail::format_ipv4_address;
using session_detail::format_ipv6_address;
using session_detail::http_stream_label_from_protocol_text;
using session_detail::format_packet_timestamp;
using session_detail::format_tcp_flags_text;
using session_detail::list_connections;
using session_detail::log_open_result;
using session_detail::make_flow_row;
using session_detail::packet_count;
using session_detail::protocol_id;
using session_detail::effective_protocol_hint;
using session_detail::find_quic_client_initial_connection_id_for_connection;
using session_detail::find_quic_client_initial_connection_id_for_packets;
using session_detail::build_quic_presentation_for_selected_direction;
using session_detail::build_quic_stream_packet_presentation;
using session_detail::QuicPresentationResult;
using session_detail::analyze_selected_flow_tcp_payload_suppression;
using session_detail::collect_suspected_tcp_retransmission_packet_indices;
using session_detail::total_bytes;
using session_detail::format_quic_presentation_enrichment;
using session_detail::format_quic_presentation_protocol_text;
using session_detail::tls_stream_label_from_protocol_text;

constexpr std::string_view kNoProtocolDetailsMessage = "No protocol-specific details available for this packet.";
constexpr std::string_view kUnavailableProtocolDetailsMessage = "Protocol details unavailable for this packet.";
constexpr std::string_view kFragmentedProtocolDetailsMessage = "Protocol details are unavailable for fragmented packets until reassembly is implemented.";
constexpr std::string_view kDirectionAToB = "A\xE2\x86\x92" "B";
constexpr std::string_view kDirectionBToA = "B\xE2\x86\x92" "A";
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

UnrecognizedPacketRow make_unrecognized_packet_row(
    const UnrecognizedPacketRecord& record,
    const std::uint64_t row_number
) {
    return UnrecognizedPacketRow {
        .row_number = row_number,
        .packet_index = record.packet.packet_index,
        .timestamp_text = format_packet_timestamp(record.packet),
        .captured_length = record.packet.captured_length,
        .original_length = record.packet.original_length,
        .reason_text = record.reason_text,
    };
}

struct StreamPacketCandidate {
    PacketRef packet {};
    std::string_view direction_text {};
    ProtocolId protocol {ProtocolId::unknown};
};

bool contains_text(const std::string_view text, const std::string_view needle) noexcept {
    return text.find(needle) != std::string_view::npos;
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

StreamItemRow make_stream_item_row(
    const std::uint64_t stream_item_index,
    const std::string_view direction_text,
    const std::string& label,
    const std::size_t byte_count,
    const std::vector<std::uint64_t>& packet_indices,
    const std::string& summary_text = {},
    const std::string& payload_hex_text = {},
    const std::string& protocol_text = {},
    const bool has_constricted_contribution = false,
    const std::vector<std::string>& constricted_contribution_notes = {},
    const std::vector<std::string>& constricted_packet_notes = {}
) {
    return StreamItemRow {
        .stream_item_index = stream_item_index,
        .direction_text = std::string {direction_text},
        .label = label,
        .byte_count = static_cast<std::uint32_t>(byte_count),
        .packet_count = static_cast<std::uint32_t>(packet_indices.size()),
        .packet_indices = packet_indices,
        .has_constricted_contribution = has_constricted_contribution,
        .constricted_contribution_notes = constricted_contribution_notes,
        .constricted_packet_notes = constricted_packet_notes,
        .summary_text = summary_text,
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
    const std::string& summary_text = {},
    const std::string& payload_hex_text = {},
    const std::string& protocol_text = {},
    const bool has_constricted_contribution = false,
    const std::vector<std::string>& constricted_contribution_notes = {},
    const std::vector<std::string>& constricted_packet_notes = {}
) {
    return make_stream_item_row(
        stream_item_index,
        direction_text,
        label,
        byte_count,
        std::vector<std::uint64_t> {packet.packet_index},
        summary_text,
        payload_hex_text,
        protocol_text,
        has_constricted_contribution,
        constricted_contribution_notes,
        constricted_packet_notes
    );
}

bool append_tls_stream_items(
    std::vector<StreamItemRow>& rows,
    const StreamPacketCandidate& candidate,
    std::span<const std::uint8_t> payload_bytes
) {
    const auto presentation = build_tls_stream_items_for_packet(candidate.packet.packet_index, payload_bytes);
    if (!presentation.handled) {
        return false;
    }

    for (const auto& item : presentation.items) {
        rows.push_back(make_stream_item_row(
            static_cast<std::uint64_t>(rows.size() + 1U),
            candidate.direction_text,
            item.label,
            item.byte_count,
            item.packet_indices,
            {},
            item.payload_hex_text,
            item.protocol_text,
            item.has_constricted_contribution,
            item.constricted_contribution_notes,
            item.constricted_packet_notes
        ));
    }

    return true;
}

std::string tcp_gap_protocol_text(const std::string_view protocol_name) {
    return std::string(protocol_name) + "\n  Semantic parsing stopped for this direction because earlier TCP bytes are missing.\n  Later bytes are shown conservatively.";
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
    const std::span<const PacketRef> direction_packets
) {
    DirectionalStreamPolicy policy {};
    const auto presentation = build_http_stream_items_from_reassembly(session, flow_index, direction, direction_packets);
    for (const auto& item : presentation.items) {
        rows.push_back(make_stream_item_row(
            static_cast<std::uint64_t>(rows.size() + 1U),
            direction_text,
            item.label,
            item.byte_count,
            item.packet_indices,
            {},
            item.payload_hex_text,
            item.protocol_text
        ));
    }
    policy.used_reassembly = presentation.used_reassembly;
    policy.explicit_gap_item_emitted = presentation.explicit_gap_item_emitted;
    policy.first_gap_packet_index = presentation.first_gap_packet_index;
    policy.fallback_label = presentation.fallback_label;
    policy.fallback_protocol_text = presentation.fallback_protocol_text;
    policy.covered_packet_indices = presentation.covered_packet_indices;
    return policy;
}

DirectionalStreamPolicy append_tls_stream_items_from_reassembly(
    std::vector<StreamItemRow>& rows,
    const CaptureSession& session,
    const std::size_t flow_index,
    const std::string_view direction_text,
    const Direction direction,
    std::span<const PacketRef> direction_packets
) {
    DirectionalStreamPolicy policy {};
    const auto presentation = build_tls_stream_items_from_reassembly(session, flow_index, direction, direction_packets);
    for (const auto& item : presentation.items) {
        rows.push_back(make_stream_item_row(
            static_cast<std::uint64_t>(rows.size() + 1U),
            direction_text,
            item.label,
            item.byte_count,
            item.packet_indices,
            {},
            item.payload_hex_text,
            item.protocol_text,
            item.has_constricted_contribution,
            item.constricted_contribution_notes,
            item.constricted_packet_notes
        ));
    }

    policy.used_reassembly = presentation.used_reassembly;
    policy.explicit_gap_item_emitted = presentation.explicit_gap_item_emitted;
    policy.first_gap_packet_index = presentation.first_gap_packet_index;
    policy.fallback_label = presentation.fallback_label;
    policy.fallback_protocol_text = presentation.fallback_protocol_text;
    policy.covered_packet_indices = presentation.covered_packet_indices;

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

struct SelectedFlowWindowPacket {
    PacketRef packet {};
    Direction direction {Direction::a_to_b};
    std::uint64_t flow_local_packet_number {0};
};

template <typename Connection>
std::vector<SelectedFlowWindowPacket> collect_selected_flow_packet_prefix(
    const Connection& connection,
    const std::size_t max_packets_to_scan
) {
    std::vector<SelectedFlowWindowPacket> packets {};
    packets.reserve(std::min(max_packets_to_scan, connection_packet_count(connection)));

    std::size_t index_a = 0U;
    std::size_t index_b = 0U;
    std::uint64_t flow_local_packet_number = 0U;

    while ((index_a < connection.flow_a.packets.size() || index_b < connection.flow_b.packets.size()) &&
           packets.size() < max_packets_to_scan) {
        const bool use_a = index_b >= connection.flow_b.packets.size() ||
            (index_a < connection.flow_a.packets.size() &&
             connection.flow_a.packets[index_a].packet_index <= connection.flow_b.packets[index_b].packet_index);

        const auto& packet = use_a ? connection.flow_a.packets[index_a++] : connection.flow_b.packets[index_b++];
        packets.push_back(SelectedFlowWindowPacket {
            .packet = packet,
            .direction = use_a ? Direction::a_to_b : Direction::b_to_a,
            .flow_local_packet_number = ++flow_local_packet_number,
        });
    }

    return packets;
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
    const auto presentation = build_quic_stream_packet_presentation(
        session,
        flow_index,
        flow_key,
        flow_packets,
        packet,
        payload_span,
        initial_secret_connection_id
    );
    if (!presentation.handled) {
        return false;
    }

    const auto packet_hex_dump = hex_dump_service.format(payload_span);
    bool emitted_any = false;
    for (const auto& item : presentation.items) {
        rows.push_back(make_stream_item_row(
            static_cast<std::uint64_t>(rows.size() + 1U),
            direction_text,
            item.label,
            item.byte_count,
            packet,
            {},
            packet_hex_dump,
            item.protocol_text,
            item.has_constricted_contribution,
            item.constricted_contribution_notes,
            {}
        ));
        emitted_any = true;
    }

    return emitted_any || presentation.handled;
}

std::string join_summary_lines(const std::vector<std::string>& lines) {
    std::ostringstream out {};
    for (std::size_t index = 0; index < lines.size(); ++index) {
        if (index != 0U) {
            out << '\n';
        }
        out << lines[index];
    }
    return out.str();
}

enum class StreamPrefixPrecheckResult : std::uint8_t {
    empty = 0,
    positive = 1,
    negative = 2,
    unknown = 3,
};

struct DirectionPrefixProbe {
    std::vector<std::uint8_t> bytes {};
    std::size_t payload_packets_considered {0U};
};

std::vector<PacketRef> merge_packet_refs_by_index(
    std::span<const PacketRef> packets_a,
    std::span<const PacketRef> packets_b
);

constexpr std::size_t kTlsRecordHeaderSize = 5U;
constexpr std::size_t kStreamPrefixProbeMaxPackets = 4U;
constexpr std::size_t kStreamPrefixProbeMaxBytes = 32U;

bool looks_like_tls_record_prefix_bytes(std::span<const std::uint8_t> payload) noexcept {
    if (payload.size() < kTlsRecordHeaderSize) {
        return false;
    }

    const auto content_type = payload[0];
    if (content_type < 20U || content_type > 23U) {
        return false;
    }

    return payload[1] == 0x03U && payload[2] <= 0x04U;
}

bool looks_like_http_request_line_prefix(const std::string_view line) noexcept {
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

bool looks_like_http_response_line_prefix(const std::string_view line) noexcept {
    return line.starts_with("HTTP/1.");
}

bool looks_binary_non_http_prefix(std::span<const std::uint8_t> bytes) noexcept {
    const auto limit = std::min<std::size_t>(bytes.size(), 8U);
    for (std::size_t index = 0U; index < limit; ++index) {
        const auto value = bytes[index];
        if (value == '\r' || value == '\n' || value == '\t') {
            continue;
        }
        if (value < 0x20U || value > 0x7EU) {
            return true;
        }
    }
    return false;
}

DirectionPrefixProbe collect_direction_transport_prefix_bytes(
    const CaptureSession& session,
    const std::size_t flow_index,
    const std::span<const PacketRef> direction_packets,
    const std::size_t max_packets_to_probe = kStreamPrefixProbeMaxPackets,
    const std::size_t max_bytes_to_collect = kStreamPrefixProbeMaxBytes
) {
    DirectionPrefixProbe probe {};
    probe.bytes.reserve(max_bytes_to_collect);

    const auto packet_limit = std::min(direction_packets.size(), max_packets_to_probe);
    for (std::size_t index = 0U; index < packet_limit && probe.bytes.size() < max_bytes_to_collect; ++index) {
        const auto& packet = direction_packets[index];
        if (packet.payload_length == 0U || session.should_suppress_selected_flow_tcp_payload(flow_index, packet.packet_index)) {
            continue;
        }

        const auto trim_prefix_bytes = session.selected_flow_tcp_payload_trim_prefix_bytes(flow_index, packet.packet_index);
        const auto remaining_needed = max_bytes_to_collect - probe.bytes.size();
        auto payload_bytes = session.read_selected_flow_transport_payload_slice(
            flow_index,
            packet,
            trim_prefix_bytes,
            remaining_needed
        );
        if (payload_bytes.empty()) {
            continue;
        }

        auto payload_span = std::span<const std::uint8_t>(payload_bytes.data(), payload_bytes.size());
        const auto copy_count = std::min(max_bytes_to_collect - probe.bytes.size(), payload_span.size());
        probe.bytes.insert(probe.bytes.end(), payload_span.begin(), payload_span.begin() + static_cast<std::ptrdiff_t>(copy_count));
        ++probe.payload_packets_considered;
    }

    return probe;
}

StreamPrefixPrecheckResult sniff_http_prefix(std::span<const std::uint8_t> bytes) noexcept {
    if (bytes.empty()) {
        return StreamPrefixPrecheckResult::empty;
    }

    if (looks_like_tls_record_prefix_bytes(bytes)) {
        return StreamPrefixPrecheckResult::negative;
    }

    const auto text = std::string_view(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    if (looks_like_http_request_line_prefix(text) || looks_like_http_response_line_prefix(text)) {
        return StreamPrefixPrecheckResult::positive;
    }

    if (bytes.size() < 5U) {
        return StreamPrefixPrecheckResult::unknown;
    }

    if (looks_binary_non_http_prefix(bytes)) {
        return StreamPrefixPrecheckResult::negative;
    }

    const auto leading = static_cast<unsigned char>(text.front());
    if ((leading >= 'A' && leading <= 'Z') || leading == 'H') {
        return StreamPrefixPrecheckResult::unknown;
    }

    return StreamPrefixPrecheckResult::negative;
}

StreamPrefixPrecheckResult sniff_tls_prefix(std::span<const std::uint8_t> bytes) noexcept {
    if (bytes.empty()) {
        return StreamPrefixPrecheckResult::empty;
    }

    if (looks_like_tls_record_prefix_bytes(bytes)) {
        return StreamPrefixPrecheckResult::positive;
    }

    const auto text = std::string_view(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    if (looks_like_http_request_line_prefix(text) || looks_like_http_response_line_prefix(text)) {
        return StreamPrefixPrecheckResult::negative;
    }

    if (bytes.size() < kTlsRecordHeaderSize) {
        return StreamPrefixPrecheckResult::unknown;
    }

    if (looks_binary_non_http_prefix(bytes)) {
        return StreamPrefixPrecheckResult::negative;
    }

    return StreamPrefixPrecheckResult::unknown;
}

bool is_strong_tls_stream_hint(const FlowProtocolHint hint) noexcept {
    return hint == FlowProtocolHint::tls;
}

bool is_strong_http_stream_hint(const FlowProtocolHint hint) noexcept {
    return hint == FlowProtocolHint::http;
}

bool append_arp_stream_item_for_packet(
    std::vector<StreamItemRow>& rows,
    const CaptureSession& session,
    const PacketRef& packet,
    const std::string_view direction_text
) {
    const auto packet_bytes = session.read_packet_data(packet);
    if (packet_bytes.empty()) {
        return false;
    }

    PacketDetailsService details_service {};
    const auto details = details_service.decode(packet_bytes, packet);
    if (!details.has_value() || !details->has_arp) {
        return false;
    }

    const auto presentation = session_detail::describe_arp_packet(*details);
    const auto summary_lines = session_detail::build_basic_summary_lines(*details);
    const auto protocol_text = session_detail::build_basic_protocol_details_text(*details).value_or(std::string {});

    PacketPayloadService payload_service {};
    const auto payload_bytes = payload_service.extract_packet_details_payload(packet_bytes, packet.data_link_type);
    HexDumpService hex_dump_service {};

    rows.push_back(make_stream_item_row(
        static_cast<std::uint64_t>(rows.size() + 1U),
        direction_text,
        presentation.has_value() && !presentation->detail.empty() ? presentation->detail : std::string {"ARP"},
        payload_bytes.size(),
        packet,
        join_summary_lines(summary_lines),
        hex_dump_service.format(std::span<const std::uint8_t>(payload_bytes.data(), payload_bytes.size())),
        protocol_text
    ));
    return true;
}

template <typename Connection>
void append_connection_stream_items_bounded(
    std::vector<StreamItemRow>& rows,
    const CaptureSession& session,
    const std::size_t flow_index,
    const Connection& connection,
    const std::span<const PacketRef> bounded_direction_packets_a,
    const std::span<const PacketRef> bounded_direction_packets_b,
    const ProtocolId flow_protocol,
    const std::size_t target_count,
    const std::size_t max_packets_to_scan,
    const bool deep_protocol_details_enabled,
    const DirectionalStreamPolicy& direction_policy_a,
    const DirectionalStreamPolicy& direction_policy_b
) {
    HexDumpService hex_dump_service {};
    const auto bounded_quic_packets = flow_protocol == ProtocolId::udp
        ? merge_packet_refs_by_index(bounded_direction_packets_a, bounded_direction_packets_b)
        : std::vector<PacketRef> {};
    const auto quic_initial_secret_connection_id =
        flow_protocol == ProtocolId::udp
            ? find_quic_client_initial_connection_id_for_packets(
                session,
                std::span<const PacketRef>(bounded_quic_packets.data(), bounded_quic_packets.size()),
                flow_index)
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
        const auto bounded_direction_packets = use_a ? bounded_direction_packets_a : bounded_direction_packets_b;

        if (direction_policy.covered_packet_indices.contains(packet.packet_index)) {
            continue;
        }

        if (flow_protocol == ProtocolId::arp) {
            append_arp_stream_item_for_packet(rows, session, packet, direction_text);
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
                    bounded_direction_packets,
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
                    bounded_direction_packets,
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
std::optional<PacketRef> connection_packet_at(
    const Connection& connection,
    const std::uint64_t flow_packet_index
) {
    if (flow_packet_index == 0U) {
        return std::nullopt;
    }

    std::uint64_t row_number = 0U;
    std::size_t index_a = 0U;
    std::size_t index_b = 0U;

    while (index_a < connection.flow_a.packets.size() || index_b < connection.flow_b.packets.size()) {
        const bool use_a = index_b >= connection.flow_b.packets.size() ||
            (index_a < connection.flow_a.packets.size() &&
             connection.flow_a.packets[index_a].packet_index <= connection.flow_b.packets[index_b].packet_index);

        const auto& packet = use_a ? connection.flow_a.packets[index_a++] : connection.flow_b.packets[index_b++];
        ++row_number;
        if (row_number == flow_packet_index) {
            return packet;
        }
    }

    return std::nullopt;
}

template <typename Connection>
std::optional<std::uint64_t> connection_packet_number(
    const Connection& connection,
    const std::uint64_t packet_index
) {
    std::uint64_t row_number = 0U;
    std::size_t index_a = 0U;
    std::size_t index_b = 0U;

    while (index_a < connection.flow_a.packets.size() || index_b < connection.flow_b.packets.size()) {
        const bool use_a = index_b >= connection.flow_b.packets.size() ||
            (index_a < connection.flow_a.packets.size() &&
             connection.flow_a.packets[index_a].packet_index <= connection.flow_b.packets[index_b].packet_index);

        const auto& packet = use_a ? connection.flow_a.packets[index_a++] : connection.flow_b.packets[index_b++];
        ++row_number;
        if (packet.packet_index == packet_index) {
            return row_number;
        }
    }

    return std::nullopt;
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

template <typename PacketContainer>
bool packet_prefix_has_visible_tcp_payload(
    const PacketContainer& packets,
    const std::size_t packet_count
) {
    const auto limit = std::min(packet_count, packets.size());
    for (std::size_t index = 0; index < limit; ++index) {
        const auto& packet = packets[index];
        if (packet.payload_length > 0U && !packet.is_ip_fragmented) {
            return true;
        }
    }

    return false;
}

template <typename PacketContainer>
std::size_t count_packet_prefix_visible_tcp_payload(
    const PacketContainer& packets,
    const std::size_t packet_count
) {
    const auto limit = std::min(packet_count, packets.size());
    std::size_t visible_payload_packet_count = 0U;
    for (std::size_t index = 0; index < limit; ++index) {
        const auto& packet = packets[index];
        if (packet.payload_length == 0U || packet.is_ip_fragmented) {
            continue;
        }
        ++visible_payload_packet_count;
    }

    return visible_payload_packet_count;
}

template <typename PacketContainer>
std::vector<PacketRef> collect_packet_prefix_refs(
    const PacketContainer& packets,
    const std::size_t packet_count
) {
    const auto limit = std::min(packet_count, packets.size());
    std::vector<PacketRef> prefix_packets {};
    prefix_packets.reserve(limit);
    for (std::size_t index = 0; index < limit; ++index) {
        prefix_packets.push_back(packets[index]);
    }
    return prefix_packets;
}

std::vector<PacketRef> merge_packet_refs_by_index(
    const std::span<const PacketRef> packets_a,
    const std::span<const PacketRef> packets_b
) {
    std::vector<PacketRef> merged_packets {};
    merged_packets.reserve(packets_a.size() + packets_b.size());
    merged_packets.insert(merged_packets.end(), packets_a.begin(), packets_a.end());
    merged_packets.insert(merged_packets.end(), packets_b.begin(), packets_b.end());
    std::sort(merged_packets.begin(), merged_packets.end(), [](const PacketRef& left, const PacketRef& right) {
        return left.packet_index < right.packet_index;
    });
    return merged_packets;
}

std::size_t count_flow_prefix_visible_tcp_payload(
    const ListedConnectionRef& connection,
    const std::size_t prefix_count_a,
    const std::size_t prefix_count_b
) {
    if (connection.family == FlowAddressFamily::ipv4) {
        return count_packet_prefix_visible_tcp_payload(connection.ipv4->flow_a.packets, prefix_count_a)
            + count_packet_prefix_visible_tcp_payload(connection.ipv4->flow_b.packets, prefix_count_b);
    }

    return count_packet_prefix_visible_tcp_payload(connection.ipv6->flow_a.packets, prefix_count_a)
        + count_packet_prefix_visible_tcp_payload(connection.ipv6->flow_b.packets, prefix_count_b);
}

std::vector<StreamItemRow> build_flow_stream_items_bounded(
    const CaptureSession& session,
    const ListedConnectionRef& connection,
    const std::size_t flow_index,
    const std::size_t max_packets_to_scan,
    const std::size_t target,
    const bool deep_protocol_details_enabled,
    const AnalysisSettings& analysis_settings
) {
    const auto flow_protocol = protocol_id(connection);
    std::vector<StreamItemRow> rows {};

    const auto total_packets = connection.family == FlowAddressFamily::ipv4
        ? connection_packet_count(*connection.ipv4)
        : connection_packet_count(*connection.ipv6);
    rows.reserve(std::min(target, total_packets));

    DirectionalStreamPolicy direction_policy_a {};
    DirectionalStreamPolicy direction_policy_b {};
    const auto [prefix_count_a, prefix_count_b] = connection.family == FlowAddressFamily::ipv4
        ? flow_packet_prefix_direction_counts(*connection.ipv4, max_packets_to_scan)
        : flow_packet_prefix_direction_counts(*connection.ipv6, max_packets_to_scan);
    const auto direction_packets_a = connection.family == FlowAddressFamily::ipv4
        ? std::span<const PacketRef>(
            connection.ipv4->flow_a.packets.data(),
            std::min(prefix_count_a, connection.ipv4->flow_a.packets.size()))
        : std::span<const PacketRef>(
            connection.ipv6->flow_a.packets.data(),
            std::min(prefix_count_a, connection.ipv6->flow_a.packets.size()));
    const auto direction_packets_b = connection.family == FlowAddressFamily::ipv4
        ? std::span<const PacketRef>(
            connection.ipv4->flow_b.packets.data(),
            std::min(prefix_count_b, connection.ipv4->flow_b.packets.size()))
        : std::span<const PacketRef>(
            connection.ipv6->flow_b.packets.data(),
            std::min(prefix_count_b, connection.ipv6->flow_b.packets.size()));
    if (flow_protocol == ProtocolId::tcp) {
        const auto effective_hint = effective_protocol_hint(connection, analysis_settings);
        const auto probe_a = collect_direction_transport_prefix_bytes(session, flow_index, direction_packets_a);
        const auto probe_b = collect_direction_transport_prefix_bytes(session, flow_index, direction_packets_b);
        const auto tls_result_a = sniff_tls_prefix(probe_a.bytes);
        const auto tls_result_b = sniff_tls_prefix(probe_b.bytes);
        const auto http_result_a = sniff_http_prefix(probe_a.bytes);
        const auto http_result_b = sniff_http_prefix(probe_b.bytes);

        const auto should_run_tls = [&](const StreamPrefixPrecheckResult result) {
            if (is_strong_http_stream_hint(effective_hint)) {
                if (result == StreamPrefixPrecheckResult::positive) {
                    return true;
                }
                return false;
            }

            if (result == StreamPrefixPrecheckResult::negative && !is_strong_tls_stream_hint(effective_hint)) {
                return false;
            }

            return true;
        };

        const auto should_run_http = [&](const StreamPrefixPrecheckResult result) {
            if (is_strong_tls_stream_hint(effective_hint)) {
                if (result == StreamPrefixPrecheckResult::positive) {
                    return true;
                }
                return false;
            }

            if (result == StreamPrefixPrecheckResult::negative) {
                return false;
            }

            return true;
        };

        if (should_run_tls(tls_result_a)) {
            direction_policy_a = append_tls_stream_items_from_reassembly(
                rows,
                session,
                flow_index,
                kDirectionAToB,
                Direction::a_to_b,
                direction_packets_a
            );
        }

        if (should_run_tls(tls_result_b)) {
            direction_policy_b = append_tls_stream_items_from_reassembly(
                rows,
                session,
                flow_index,
                kDirectionBToA,
                Direction::b_to_a,
                direction_packets_b
            );
        }
        if (!direction_policy_a.used_reassembly) {
            if (should_run_http(http_result_a)) {
                direction_policy_a = append_http_stream_items_from_reassembly(
                    rows,
                    session,
                    flow_index,
                    kDirectionAToB,
                    Direction::a_to_b,
                    direction_packets_a
                );
            }
        }
        if (!direction_policy_b.used_reassembly) {
            if (should_run_http(http_result_b)) {
                direction_policy_b = append_http_stream_items_from_reassembly(
                    rows,
                    session,
                    flow_index,
                    kDirectionBToA,
                    Direction::b_to_a,
                    direction_packets_b
                );
            }
        }
    }

    if (rows.size() < target) {
        if (connection.family == FlowAddressFamily::ipv4) {
            append_connection_stream_items_bounded(
                rows,
                session,
                flow_index,
                *connection.ipv4,
                direction_packets_a,
                direction_packets_b,
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
                direction_packets_a,
                direction_packets_b,
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

    if (rows.size() > target) {
        rows.resize(target);
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
    selected_flow_full_packet_cache_.reset();
    selected_flow_packet_cache_.reset();
    selected_flow_tcp_prefix_context_.reset();
    listed_connections_cache_.reset();
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
    selected_flow_full_packet_cache_.reset();
    selected_flow_packet_cache_.reset();
    selected_flow_tcp_prefix_context_.reset();
    listed_connections_cache_.reset();
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
    selected_flow_full_packet_cache_.reset();
    selected_flow_packet_cache_.reset();
    selected_flow_tcp_prefix_context_.reset();
    listed_connections_cache_.reset();
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

bool CaptureSession::source_capture_accessible() const noexcept {
    if (capture_path_.empty()) {
        return false;
    }

    std::error_code error {};
    if (!std::filesystem::is_regular_file(capture_path_, error) || error) {
        return false;
    }

    std::ifstream stream {capture_path_, std::ios::binary};
    return stream.is_open();
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
    if (!has_loaded_state_) {
        return false;
    }

    if (!validate_capture_source(source_info_, path)) {
        return false;
    }

    capture_path_ = path;
    source_capture_path_ = path;
    source_info_.capture_path = path;
    selected_flow_full_packet_cache_.reset();
    selected_flow_packet_cache_.reset();
    selected_flow_tcp_prefix_context_.reset();
    selected_flow_tcp_payload_suppression_.reset();
    return true;
}

void CaptureSession::clear_source_capture_attachment() noexcept {
    capture_path_.clear();
    selected_flow_full_packet_cache_.reset();
    selected_flow_packet_cache_.reset();
    selected_flow_tcp_prefix_context_.reset();
    selected_flow_tcp_payload_suppression_.reset();
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

    for (const auto& connection : listed_connections()) {
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
        case FlowProtocolHint::igmp:
        case FlowProtocolHint::igmpv1:
        case FlowProtocolHint::igmpv2:
        case FlowProtocolHint::igmpv3:
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

    const auto& connections = listed_connections();
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

    const auto& connections = listed_connections();
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

    for (const auto& connection : listed_connections()) {
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

    if (const auto* cached_bytes = find_selected_flow_full_packet_cache_bytes(packet.packet_index);
        cached_bytes != nullptr) {
        return *cached_bytes;
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

void CaptureSession::prepare_selected_flow_full_packet_cache(
    const std::size_t flow_index,
    const std::span<const PacketRef> packets
) const {
    if (!has_source_capture() || packets.empty()) {
        selected_flow_full_packet_cache_.reset();
        return;
    }

    if (!selected_flow_full_packet_cache_.has_value() || selected_flow_full_packet_cache_->flow_index != flow_index) {
        SelectedFlowFullPacketCache cache {};
        cache.flow_index = flow_index;
        selected_flow_full_packet_cache_ = std::move(cache);
    }

    auto& cache = *selected_flow_full_packet_cache_;

    std::vector<PacketRef> missing_packets {};
    missing_packets.reserve(packets.size());
    std::set<std::uint64_t> queued_packet_indices {};
    for (const auto& packet : packets) {
        if (!queued_packet_indices.insert(packet.packet_index).second) {
            continue;
        }
        if (cache.packet_bytes_by_packet_index.contains(packet.packet_index)) {
            continue;
        }
        missing_packets.push_back(packet);
    }

    if (missing_packets.empty()) {
        return;
    }

    std::sort(missing_packets.begin(), missing_packets.end(), [](const PacketRef& left, const PacketRef& right) {
        if (left.byte_offset != right.byte_offset) {
            return left.byte_offset < right.byte_offset;
        }
        return left.packet_index < right.packet_index;
    });

    CaptureFilePacketReader reader {capture_path_};
    if (!reader.is_open()) {
        return;
    }

    for (const auto& packet : missing_packets) {
        if (cache.packet_bytes_by_packet_index.contains(packet.packet_index)) {
            continue;
        }

        const auto remaining_budget = kSelectedFlowFullPacketCacheMaxBytes - std::min(
            cache.total_cached_bytes,
            kSelectedFlowFullPacketCacheMaxBytes
        );
        if (remaining_budget == 0U) {
            cache.limit_reached = true;
            break;
        }
        if (static_cast<std::size_t>(packet.captured_length) > remaining_budget) {
            cache.limit_reached = true;
            continue;
        }

        std::vector<std::uint8_t> packet_bytes {};
        if (!reader.read_packet_data(packet, packet_bytes)) {
            continue;
        }

        cache.total_cached_bytes += packet_bytes.size();
        cache.packet_bytes_by_packet_index.insert_or_assign(packet.packet_index, std::move(packet_bytes));
    }

}

const std::vector<std::uint8_t>* CaptureSession::find_selected_flow_full_packet_cache_bytes(
    const std::uint64_t packet_index
) const noexcept {
    if (!selected_flow_full_packet_cache_.has_value()) {
        return nullptr;
    }

    const auto it = selected_flow_full_packet_cache_->packet_bytes_by_packet_index.find(packet_index);
    if (it == selected_flow_full_packet_cache_->packet_bytes_by_packet_index.end()) {
        return nullptr;
    }

    return &it->second;
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

const std::vector<session_detail::ListedConnectionRef>& CaptureSession::listed_connections(bool* cache_hit) const {
    if (listed_connections_cache_.has_value()) {
        if (cache_hit != nullptr) {
            *cache_hit = true;
        }
        return *listed_connections_cache_;
    }

    if (cache_hit != nullptr) {
        *cache_hit = false;
    }
    listed_connections_cache_ = session_detail::list_connections(state_);
    return *listed_connections_cache_;
}

CaptureSession::SelectedFlowTcpPrefixResolution CaptureSession::prepare_selected_flow_tcp_prefix_context(
    const std::size_t flow_index,
    const std::size_t max_packets_to_scan
) const {
    SelectedFlowTcpPrefixResolution resolution {};
    resolution.result = "invalid";

    if (!has_source_capture()) {
        selected_flow_tcp_prefix_context_.reset();
        resolution.result = "no-source";
        return resolution;
    }

    if (max_packets_to_scan == 0U) {
        selected_flow_tcp_prefix_context_.reset();
        resolution.result = "empty-prefix";
        return resolution;
    }

    if (selected_flow_tcp_prefix_context_.has_value() &&
        selected_flow_tcp_prefix_context_->flow_index == flow_index &&
        selected_flow_tcp_prefix_context_->prepared_packet_window_count >= max_packets_to_scan) {
        resolution.context = &*selected_flow_tcp_prefix_context_;
        resolution.result = "ok";
        resolution.reused_existing_context = true;
        return resolution;
    }

    bool listed_connections_cache_hit = false;
    const auto& connections = listed_connections(&listed_connections_cache_hit);
    resolution.listed_connections_cache_hit = listed_connections_cache_hit;
    resolution.listed_connections_called = !listed_connections_cache_hit;
    if (flow_index >= connections.size()) {
        selected_flow_tcp_prefix_context_.reset();
        resolution.result = "invalid-flow-index";
        return resolution;
    }

    const auto& connection = connections[flow_index];
    if (protocol_id(connection) != ProtocolId::tcp) {
        selected_flow_tcp_prefix_context_.reset();
        resolution.result = "non-tcp";
        return resolution;
    }

    SelectedFlowTcpPrefixContext context {};
    context.flow_index = flow_index;
    context.prepared_packet_window_count = max_packets_to_scan;
    context.family = connection.family;
    context.ipv4 = connection.ipv4;
    context.ipv6 = connection.ipv6;

    if (connection.family == FlowAddressFamily::ipv4) {
        const auto [prefix_count_a, prefix_count_b] =
            flow_packet_prefix_direction_counts(*connection.ipv4, max_packets_to_scan);
        context.prefix_count_a = prefix_count_a;
        context.prefix_count_b = prefix_count_b;
        context.payload_packet_count = count_flow_prefix_visible_tcp_payload(connection, context.prefix_count_a, context.prefix_count_b);
        if (context.prefix_count_a + context.prefix_count_b == 0U) {
            selected_flow_tcp_prefix_context_.reset();
            resolution.result = "empty-prefix";
            return resolution;
        }
        if (context.payload_packet_count == 0U) {
            selected_flow_tcp_prefix_context_.reset();
            resolution.result = "no-visible-tcp-payload";
            return resolution;
        }
        context.prefix_packets_a = collect_packet_prefix_refs(connection.ipv4->flow_a.packets, context.prefix_count_a);
        context.prefix_packets_b = collect_packet_prefix_refs(connection.ipv4->flow_b.packets, context.prefix_count_b);
        const auto ordered_prefix = collect_selected_flow_packet_prefix(*connection.ipv4, max_packets_to_scan);
        context.ordered_prefix_packets.reserve(ordered_prefix.size());
        for (const auto& packet : ordered_prefix) {
            context.ordered_prefix_packets.push_back(SelectedFlowTcpPrefixWindowPacket {
                .packet = packet.packet,
                .direction = packet.direction,
                .flow_local_packet_number = packet.flow_local_packet_number,
            });
        }
    } else {
        const auto [prefix_count_a, prefix_count_b] =
            flow_packet_prefix_direction_counts(*connection.ipv6, max_packets_to_scan);
        context.prefix_count_a = prefix_count_a;
        context.prefix_count_b = prefix_count_b;
        context.payload_packet_count = count_flow_prefix_visible_tcp_payload(connection, context.prefix_count_a, context.prefix_count_b);
        if (context.prefix_count_a + context.prefix_count_b == 0U) {
            selected_flow_tcp_prefix_context_.reset();
            resolution.result = "empty-prefix";
            return resolution;
        }
        if (context.payload_packet_count == 0U) {
            selected_flow_tcp_prefix_context_.reset();
            resolution.result = "no-visible-tcp-payload";
            return resolution;
        }
        context.prefix_packets_a = collect_packet_prefix_refs(connection.ipv6->flow_a.packets, context.prefix_count_a);
        context.prefix_packets_b = collect_packet_prefix_refs(connection.ipv6->flow_b.packets, context.prefix_count_b);
        const auto ordered_prefix = collect_selected_flow_packet_prefix(*connection.ipv6, max_packets_to_scan);
        context.ordered_prefix_packets.reserve(ordered_prefix.size());
        for (const auto& packet : ordered_prefix) {
            context.ordered_prefix_packets.push_back(SelectedFlowTcpPrefixWindowPacket {
                .packet = packet.packet,
                .direction = packet.direction,
                .flow_local_packet_number = packet.flow_local_packet_number,
            });
        }
    }

    selected_flow_tcp_prefix_context_ = std::move(context);
    resolution.context = &*selected_flow_tcp_prefix_context_;
    resolution.result = "ok";
    return resolution;
}

void CaptureSession::prepare_selected_flow_packet_cache(
    const std::size_t flow_index,
    const SelectedFlowTcpPrefixContext& context
) const {
    if (!has_source_capture() || context.ordered_prefix_packets.empty()) {
        selected_flow_full_packet_cache_.reset();
        selected_flow_packet_cache_.reset();
        return;
    }

    std::vector<PacketRef> prefix_packet_refs {};
    prefix_packet_refs.reserve(context.ordered_prefix_packets.size());
    for (const auto& window_packet : context.ordered_prefix_packets) {
        prefix_packet_refs.push_back(window_packet.packet);
    }
    prepare_selected_flow_full_packet_cache(flow_index, prefix_packet_refs);

    if (!selected_flow_packet_cache_.has_value() || selected_flow_packet_cache_->flow_index != flow_index) {
        SelectedFlowPacketCache cache {};
        cache.flow_index = flow_index;
        cache.bytes.reserve(std::min(kSelectedFlowPacketCacheMaxBytes, std::size_t {64U} * 1024U));
        selected_flow_packet_cache_ = std::move(cache);
    }

    auto& cache = *selected_flow_packet_cache_;
    if (cache.limit_reached || cache.cached_packet_window_count >= context.prepared_packet_window_count) {
        cache.window_fully_cached = !cache.limit_reached &&
            !cache.has_uncached_payload_entries &&
            cache.cached_packet_window_count >= context.prepared_packet_window_count;
        return;
    }

    for (const auto& window_packet : context.ordered_prefix_packets) {
        if (cache.limit_reached) {
            break;
        }
        if (window_packet.flow_local_packet_number <= cache.cached_packet_window_count) {
            continue;
        }

        const auto& packet = window_packet.packet;
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
            .flow_local_packet_number = window_packet.flow_local_packet_number,
            .packet = packet,
            .packet_index = packet.packet_index,
            .direction = window_packet.direction,
            .cache_offset = cache_offset,
            .cache_length = additional_bytes,
            .payload_length = packet.payload_length,
            .payload_cached = payload_cached,
        });

        cache.cached_packet_window_count = static_cast<std::size_t>(window_packet.flow_local_packet_number);
    }

    cache.window_fully_cached = !cache.limit_reached &&
        !cache.has_uncached_payload_entries &&
        cache.cached_packet_window_count >= context.prepared_packet_window_count;
}

void CaptureSession::prepare_selected_flow_packet_cache(
    const std::size_t flow_index,
    const std::size_t max_packets_to_scan
) const {
    if (!has_source_capture() || max_packets_to_scan == 0U) {
        selected_flow_full_packet_cache_.reset();
        selected_flow_packet_cache_.reset();
        return;
    }

    const auto& connections = listed_connections();
    if (flow_index >= connections.size()) {
        selected_flow_full_packet_cache_.reset();
        selected_flow_packet_cache_.reset();
        return;
    }
    const auto& connection_ref = connections[flow_index];
    const auto prefix_packets = connection_ref.family == FlowAddressFamily::ipv4
        ? collect_selected_flow_packet_prefix(*connection_ref.ipv4, max_packets_to_scan)
        : collect_selected_flow_packet_prefix(*connection_ref.ipv6, max_packets_to_scan);
    std::vector<PacketRef> prefix_packet_refs {};
    prefix_packet_refs.reserve(prefix_packets.size());
    for (const auto& window_packet : prefix_packets) {
        prefix_packet_refs.push_back(window_packet.packet);
    }
    prepare_selected_flow_full_packet_cache(flow_index, prefix_packet_refs);

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

    for (const auto& window_packet : prefix_packets) {
        if (cache.limit_reached) {
            break;
        }
        if (window_packet.flow_local_packet_number <= cache.cached_packet_window_count) {
            continue;
        }

        const auto& packet = window_packet.packet;
        const auto direction = window_packet.direction;
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
            .flow_local_packet_number = window_packet.flow_local_packet_number,
            .packet = packet,
            .packet_index = packet.packet_index,
            .direction = direction,
            .cache_offset = cache_offset,
            .cache_length = additional_bytes,
            .payload_length = packet.payload_length,
            .payload_cached = payload_cached,
        });

        cache.cached_packet_window_count = static_cast<std::size_t>(window_packet.flow_local_packet_number);
    }

    cache.window_fully_cached = !cache.limit_reached &&
        !cache.has_uncached_payload_entries &&
        cache.cached_packet_window_count >= max_packets_to_scan;

}

void CaptureSession::clear_selected_flow_packet_cache() noexcept {
    selected_flow_full_packet_cache_.reset();
    selected_flow_packet_cache_.reset();
    selected_flow_tcp_prefix_context_.reset();
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

std::optional<std::uint64_t> CaptureSession::selected_flow_cached_packet_number(
    const std::size_t flow_index,
    const std::uint64_t packet_index
) const noexcept {
    if (const auto* entry = find_selected_flow_packet_cache_entry(flow_index, packet_index); entry != nullptr) {
        return entry->flow_local_packet_number;
    }

    return std::nullopt;
}

std::optional<PacketRef> CaptureSession::selected_flow_cached_packet_at(
    const std::size_t flow_index,
    const std::uint64_t flow_packet_index
) const noexcept {
    if (!selected_flow_packet_cache_.has_value() || selected_flow_packet_cache_->flow_index != flow_index) {
        return std::nullopt;
    }

    if (flow_packet_index == 0U ||
        flow_packet_index > static_cast<std::uint64_t>(selected_flow_packet_cache_->cached_packet_window_count) ||
        flow_packet_index > static_cast<std::uint64_t>(selected_flow_packet_cache_->entries.size())) {
        return std::nullopt;
    }

    const auto& entry = selected_flow_packet_cache_->entries[static_cast<std::size_t>(flow_packet_index - 1U)];
    if (entry.flow_local_packet_number != flow_packet_index) {
        return std::nullopt;
    }

    return entry.packet;
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

std::vector<std::uint8_t> CaptureSession::read_selected_flow_transport_payload_prefix(
    const std::size_t flow_index,
    const PacketRef& packet,
    const std::size_t max_bytes
) const {
    return read_selected_flow_transport_payload_slice(flow_index, packet, 0U, max_bytes);
}

std::vector<std::uint8_t> CaptureSession::read_selected_flow_transport_payload_slice(
    const std::size_t flow_index,
    const PacketRef& packet,
    const std::size_t payload_offset,
    const std::size_t max_bytes
) const {
    if (max_bytes == 0U) {
        return {};
    }
    if (payload_offset >= packet.payload_length) {
        return {};
    }

    if (const auto* entry = find_selected_flow_packet_cache_entry(flow_index, packet.packet_index); entry != nullptr) {
        if (entry->payload_cached) {
            if (payload_offset >= entry->cache_length) {
                return {};
            }

            const auto slice_length = std::min(entry->cache_length - payload_offset, max_bytes);
            const auto begin = selected_flow_packet_cache_->bytes.begin()
                + static_cast<std::ptrdiff_t>(entry->cache_offset + payload_offset);
            const auto end = begin + static_cast<std::ptrdiff_t>(slice_length);
            return std::vector<std::uint8_t>(begin, end);
        }

        auto payload = read_transport_payload_direct(packet);
        if (payload_offset >= payload.size()) {
            return {};
        }
        if (payload_offset != 0U) {
            payload.erase(payload.begin(), payload.begin() + static_cast<std::ptrdiff_t>(payload_offset));
        }
        if (payload.size() > max_bytes) {
            payload.resize(max_bytes);
        }
        return payload;
    }

    auto payload = read_transport_payload_direct(packet);
    if (payload_offset >= payload.size()) {
        return {};
    }
    if (payload_offset != 0U) {
        payload.erase(payload.begin(), payload.begin() + static_cast<std::ptrdiff_t>(payload_offset));
    }
    if (payload.size() > max_bytes) {
        payload.resize(max_bytes);
    }
    return payload;
}

std::optional<PacketDetails> CaptureSession::read_packet_details(const PacketRef& packet) const {
    const auto bytes = read_packet_data(packet);
    if (bytes.empty()) {
        return std::nullopt;
    }

    PacketDetailsService service {};
    return service.decode_best_effort(bytes, packet);
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
    const auto payload_bytes = payload_service.extract_packet_details_payload(bytes, packet.data_link_type);

    HexDumpService hex_dump_service {};
    return hex_dump_service.format(payload_bytes);
}

std::string CaptureSession::read_packet_protocol_details_text(const PacketRef& packet) const {
    if (packet.is_ip_fragmented) {
        return std::string {kFragmentedProtocolDetailsMessage};
    }

    if (packet.captured_length < packet.original_length) {
        return std::string {kNoProtocolDetailsMessage};
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

    if (const auto details = details_service.decode_best_effort(bytes, packet);
        details.has_value() && (details->has_pbb || details->has_macsec)) {
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

    const auto& connections = listed_connections();
    if (request.flow_index >= connections.size()) {
        return std::nullopt;
    }
    if (protocol_id(connections[request.flow_index]) != ProtocolId::tcp) {
        return std::nullopt;
    }

    ReassemblyService service {};
    return service.reassemble_tcp_payload(*this, request);
}
std::optional<ReassemblyResult> CaptureSession::reassemble_flow_direction(
    const ReassemblyRequest& request,
    const std::span<const PacketRef> direction_packets
) const {
    if (!has_loaded_state_ || !has_source_capture()) {
        return std::nullopt;
    }

    const auto& connections = listed_connections();
    if (request.flow_index >= connections.size()) {
        return std::nullopt;
    }
    if (protocol_id(connections[request.flow_index]) != ProtocolId::tcp) {
        return std::nullopt;
    }

    ReassemblyService service {};
    return service.reassemble_tcp_payload(*this, request, direction_packets);
}
std::optional<std::string> CaptureSession::derive_quic_service_hint_for_flow(const std::size_t flow_index) const {
    if (!has_source_capture()) {
        return std::nullopt;
    }

    const auto& connections = listed_connections();
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

    const auto& connections = listed_connections();
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

    const auto& connections = listed_connections();
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
    const auto& connections = listed_connections();
    std::vector<FlowRow> rows {};
    rows.reserve(connections.size());

    for (std::size_t index = 0; index < connections.size(); ++index) {
        rows.push_back(make_flow_row(index, connections[index], analysis_settings_));
    }

    return rows;
}

std::optional<FlowRow> CaptureSession::flow_row(const std::size_t flow_index) const {
    const auto& connections = listed_connections();
    if (flow_index >= connections.size()) {
        return std::nullopt;
    }

    return make_flow_row(flow_index, connections[flow_index], analysis_settings_);
}

std::optional<FlowAnalysisResult> CaptureSession::get_flow_analysis(const std::size_t flow_index) const {
    const auto& connections = listed_connections();
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
    const auto& connections = listed_connections();
    if (flow_index >= connections.size()) {
        return {};
    }

    return connections[flow_index].family == FlowAddressFamily::ipv4
        ? slice_connection_packets(*connections[flow_index].ipv4, offset, limit)
        : slice_connection_packets(*connections[flow_index].ipv6, offset, limit);
}

std::vector<UnrecognizedPacketRow> CaptureSession::list_unrecognized_packets() const {
    return list_unrecognized_packets(0U, unrecognized_packet_count());
}

std::vector<UnrecognizedPacketRow> CaptureSession::list_unrecognized_packets(
    const std::size_t offset,
    const std::size_t limit
) const {
    if (offset >= state_.unrecognized_packets.size() || limit == 0U) {
        return {};
    }

    const auto slice_end = std::min(state_.unrecognized_packets.size(), offset + limit);
    std::vector<UnrecognizedPacketRow> rows {};
    rows.reserve(slice_end - offset);

    for (std::size_t index = offset; index < slice_end; ++index) {
        rows.push_back(make_unrecognized_packet_row(
            state_.unrecognized_packets[index],
            static_cast<std::uint64_t>(index + 1U)
        ));
    }

    return rows;
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

    const auto prefix_resolution = prepare_selected_flow_tcp_prefix_context(flow_index, max_packets_to_scan);
    if (prefix_resolution.context == nullptr) {
        return {};
    }

    const auto& context = *prefix_resolution.context;

    prepare_selected_flow_packet_cache(flow_index, context);
    return context.family == FlowAddressFamily::ipv4
        ? collect_suspected_tcp_retransmission_packet_indices(
            *this,
            flow_index,
            context.prefix_packets_a,
            context.prefix_packets_b,
            max_packets_to_scan
        )
        : collect_suspected_tcp_retransmission_packet_indices(
            *this,
            flow_index,
            context.prefix_packets_a,
            context.prefix_packets_b,
            max_packets_to_scan
        );
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
    const auto prefix_resolution = prepare_selected_flow_tcp_prefix_context(flow_index, max_packets_to_scan);
    if (prefix_resolution.context == nullptr) {
        selected_flow_tcp_payload_suppression_.reset();
        return;
    }

    const auto& context = *prefix_resolution.context;

    const std::set<std::uint64_t> exact_duplicate_packet_indices(packet_indices.begin(), packet_indices.end());

    const auto analysis = context.family == FlowAddressFamily::ipv4
        ? analyze_selected_flow_tcp_payload_suppression(
            *this,
            flow_index,
            context.prefix_packets_a,
            context.prefix_packets_b,
            exact_duplicate_packet_indices,
            context.prefix_count_a,
            context.prefix_count_b
        )
        : analyze_selected_flow_tcp_payload_suppression(
            *this,
            flow_index,
            context.prefix_packets_a,
            context.prefix_packets_b,
            exact_duplicate_packet_indices,
            context.prefix_count_a,
            context.prefix_count_b
        );

    if (analysis.packet_contributions.empty() &&
        !analysis.gap_state_a_to_b.tainted_by_gap &&
        !analysis.gap_state_b_to_a.tainted_by_gap) {
        selected_flow_tcp_payload_suppression_.reset();
        return;
    }

    SelectedFlowTcpPayloadSuppression suppression {};
    suppression.flow_index = flow_index;
    suppression.gap_state_a_to_b = SelectedFlowTcpDirectionalGapState {
        .tainted_by_gap = analysis.gap_state_a_to_b.tainted_by_gap,
        .first_gap_packet_index = analysis.gap_state_a_to_b.first_gap_packet_index,
    };
    suppression.gap_state_b_to_a = SelectedFlowTcpDirectionalGapState {
        .tainted_by_gap = analysis.gap_state_b_to_a.tainted_by_gap,
        .first_gap_packet_index = analysis.gap_state_b_to_a.first_gap_packet_index,
    };
    for (const auto& [packet_index, contribution] : analysis.packet_contributions) {
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
    const auto& connections = listed_connections();
    if (flow_index >= connections.size()) {
        return 0U;
    }

    if (connections[flow_index].family == FlowAddressFamily::ipv4) {
        return connection_packet_count(*connections[flow_index].ipv4);
    }

    return connection_packet_count(*connections[flow_index].ipv6);
}

std::size_t CaptureSession::unrecognized_packet_count() const noexcept {
    return state_.unrecognized_packets.size();
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

    const auto& connections = listed_connections();
    if (flow_index >= connections.size()) {
        return {};
    }

    const auto flow_protocol = protocol_id(connections[flow_index]);
    if (flow_protocol != ProtocolId::tcp && flow_protocol != ProtocolId::udp && flow_protocol != ProtocolId::arp) {
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
        deep_protocol_details_enabled_,
        analysis_settings_
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
    const auto bounded_packet_budget = std::min(total_packets, max_packets_to_scan);
    const auto prefix_resolution = prepare_selected_flow_tcp_prefix_context(flow_index, bounded_packet_budget);
    if (prefix_resolution.context != nullptr) {
        prepare_selected_flow_packet_cache(flow_index, *prefix_resolution.context);
    } else {
        prepare_selected_flow_packet_cache(flow_index, bounded_packet_budget);
    }
    if (total_packets <= max_packets_to_scan) {
        return list_flow_stream_items(flow_index, 0U, limit);
    }

    const auto& connections = listed_connections();
    if (flow_index >= connections.size()) {
        return {};
    }

    const auto flow_protocol = protocol_id(connections[flow_index]);
    if (flow_protocol != ProtocolId::tcp && flow_protocol != ProtocolId::udp && flow_protocol != ProtocolId::arp) {
        return {};
    }

    auto rows = build_flow_stream_items_bounded(
        *this,
        connections[flow_index],
        flow_index,
        max_packets_to_scan,
        limit,
        deep_protocol_details_enabled_,
        analysis_settings_
    );
    return rows;
}
std::size_t CaptureSession::flow_stream_item_count(const std::size_t flow_index) const {
    return list_flow_stream_items(flow_index).size();
}

std::optional<std::vector<PacketRef>> CaptureSession::flow_packets(std::size_t flow_index) const {
    const auto& connections = listed_connections();
    if (flow_index >= connections.size()) {
        return std::nullopt;
    }

    return connections[flow_index].family == FlowAddressFamily::ipv4
        ? std::optional<std::vector<PacketRef>> {collect_packets(*connections[flow_index].ipv4)}
        : std::optional<std::vector<PacketRef>> {collect_packets(*connections[flow_index].ipv6)};
}

std::optional<PacketRef> CaptureSession::selected_flow_packet_at(
    const std::size_t flow_index,
    const std::uint64_t flow_packet_index
) const {
    if (const auto packet = selected_flow_cached_packet_at(flow_index, flow_packet_index); packet.has_value()) {
        return packet;
    }

    const auto& connections = listed_connections();
    if (flow_index >= connections.size()) {
        return std::nullopt;
    }

    return connections[flow_index].family == FlowAddressFamily::ipv4
        ? connection_packet_at(*connections[flow_index].ipv4, flow_packet_index)
        : connection_packet_at(*connections[flow_index].ipv6, flow_packet_index);
}

std::optional<std::uint64_t> CaptureSession::selected_flow_packet_number(
    const std::size_t flow_index,
    const std::uint64_t packet_index
) const {
    return selected_flow_cached_packet_number(flow_index, packet_index);
}

std::optional<std::uint64_t> CaptureSession::selected_flow_exact_packet_number(
    const std::size_t flow_index,
    const std::uint64_t packet_index
) const {
    const auto& connections = listed_connections();
    if (flow_index >= connections.size()) {
        return std::nullopt;
    }

    return connections[flow_index].family == FlowAddressFamily::ipv4
        ? connection_packet_number(*connections[flow_index].ipv4, packet_index)
        : connection_packet_number(*connections[flow_index].ipv6, packet_index);
}

namespace {

[[nodiscard]] bool ensure_packet_marker_capacity(std::vector<std::uint8_t>& packet_selection, const std::uint64_t packet_index) {
    if (packet_index >= static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
        return false;
    }

    const auto required_size = static_cast<std::size_t>(packet_index + 1U);
    if (required_size > packet_selection.size()) {
        packet_selection.resize(required_size, 0U);
    }
    return true;
}

[[nodiscard]] bool ensure_packet_owner_capacity(std::vector<std::uint32_t>& packet_owner, const std::uint64_t packet_index) {
    if (packet_index >= static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
        return false;
    }

    const auto required_size = static_cast<std::size_t>(packet_index + 1U);
    if (required_size > packet_owner.size()) {
        packet_owner.resize(required_size, 0U);
    }
    return true;
}

[[nodiscard]] bool mark_packet_for_smart_export(std::vector<std::uint8_t>& packet_selection, const PacketRef& packet) {
    if (!ensure_packet_marker_capacity(packet_selection, packet.packet_index)) {
        return false;
    }

    packet_selection[static_cast<std::size_t>(packet.packet_index)] = 1U;
    return true;
}

[[nodiscard]] SmartPacketRetentionOptions retention_options(const SmartFlowExportRequest& request) {
    return SmartPacketRetentionOptions {
        .base_mode = request.base_mode,
        .first_n_packets = request.first_n_packets,
        .first_m_original_bytes = request.first_m_original_bytes,
        .include_last_packet = request.include_last_packet,
        .include_every_kth_packet_after_base = request.include_every_kth_packet_after_base,
        .every_kth_packet = request.every_kth_packet,
    };
}

[[nodiscard]] bool validate_smart_packet_retention_options(const SmartPacketRetentionOptions& options) {
    if (options.base_mode == SmartFlowExportBaseMode::first_n_packets && options.first_n_packets == 0U) {
        return false;
    }

    if (options.base_mode == SmartFlowExportBaseMode::first_m_original_bytes &&
        options.first_m_original_bytes == 0U) {
        return false;
    }

    if (options.base_mode != SmartFlowExportBaseMode::all_packets &&
        options.include_every_kth_packet_after_base &&
        options.every_kth_packet == 0U) {
        return false;
    }

    return true;
}

template <typename MarkSelectedPacketFn>
std::size_t visit_smart_export_base_prefix_packets(
    const std::vector<PacketRef>& flow_packets,
    const SmartPacketRetentionOptions& options,
    MarkSelectedPacketFn&& mark_selected_packet
) {
    switch (options.base_mode) {
    case SmartFlowExportBaseMode::all_packets:
        for (const auto& packet : flow_packets) {
            mark_selected_packet(packet);
        }
        return flow_packets.size();

    case SmartFlowExportBaseMode::first_n_packets: {
        const auto packet_count = static_cast<std::size_t>(
            std::min<std::uint64_t>(options.first_n_packets, static_cast<std::uint64_t>(flow_packets.size()))
        );
        for (std::size_t index = 0; index < packet_count; ++index) {
            mark_selected_packet(flow_packets[index]);
        }
        return packet_count;
    }

    case SmartFlowExportBaseMode::first_m_original_bytes: {
        std::uint64_t accumulated_bytes = 0U;
        std::size_t packet_count = 0U;
        for (const auto& packet : flow_packets) {
            mark_selected_packet(packet);
            accumulated_bytes += packet.original_length;
            ++packet_count;
            if (accumulated_bytes >= options.first_m_original_bytes) {
                break;
            }
        }
        return packet_count;
    }
    }

    return 0U;
}

template <typename MarkSelectedPacketFn>
void visit_smart_export_additional_packets(
    const std::vector<PacketRef>& flow_packets,
    const SmartPacketRetentionOptions& options,
    const std::size_t base_prefix_packet_count,
    MarkSelectedPacketFn&& mark_selected_packet
) {
    if (options.base_mode == SmartFlowExportBaseMode::all_packets || flow_packets.empty()) {
        return;
    }

    if (options.include_last_packet) {
        mark_selected_packet(flow_packets.back());
    }

    if (options.include_every_kth_packet_after_base && options.every_kth_packet > 0U) {
        const auto step = static_cast<std::size_t>(options.every_kth_packet);
        if (base_prefix_packet_count < flow_packets.size()) {
            for (std::size_t after_base_index = step; base_prefix_packet_count + after_base_index - 1U < flow_packets.size(); after_base_index += step) {
                const auto packet_index = base_prefix_packet_count + after_base_index - 1U;
                mark_selected_packet(flow_packets[packet_index]);
            }
        }
    }
}

template <typename VisitPacketFn>
bool visit_smart_export_flow_packets(
    const std::vector<PacketRef>& flow_packets,
    const SmartPacketRetentionOptions& options,
    VisitPacketFn&& visit_packet
) {
    if (flow_packets.empty()) {
        return true;
    }

    if (options.base_mode == SmartFlowExportBaseMode::all_packets) {
        for (const auto& packet : flow_packets) {
            if (!visit_packet(packet, true)) {
                return false;
            }
        }
        return true;
    }

    const auto include_every_kth = options.include_every_kth_packet_after_base && options.every_kth_packet > 0U;
    const auto every_kth_step = static_cast<std::size_t>(options.every_kth_packet);
    const auto packet_count = flow_packets.size();

    if (options.base_mode == SmartFlowExportBaseMode::first_n_packets) {
        const auto base_prefix_packet_count = static_cast<std::size_t>(
            std::min<std::uint64_t>(options.first_n_packets, static_cast<std::uint64_t>(packet_count))
        );
        for (std::size_t index = 0; index < packet_count; ++index) {
            bool selected = index < base_prefix_packet_count;
            if (!selected && options.include_last_packet && index + 1U == packet_count) {
                selected = true;
            }
            if (!selected && include_every_kth && index >= base_prefix_packet_count) {
                const auto after_base_index = index - base_prefix_packet_count + 1U;
                selected = (after_base_index % every_kth_step) == 0U;
            }
            if (!visit_packet(flow_packets[index], selected)) {
                return false;
            }
        }
        return true;
    }

    std::uint64_t accumulated_original_bytes = 0U;
    std::size_t base_prefix_packet_count = packet_count;
    bool base_prefix_complete = false;
    for (std::size_t index = 0; index < packet_count; ++index) {
        bool selected = false;
        if (!base_prefix_complete) {
            selected = true;
            accumulated_original_bytes += flow_packets[index].original_length;
            if (accumulated_original_bytes >= options.first_m_original_bytes) {
                base_prefix_complete = true;
                base_prefix_packet_count = index + 1U;
            }
        }
        if (!selected && options.include_last_packet && index + 1U == packet_count) {
            selected = true;
        }
        if (!selected && include_every_kth && base_prefix_complete && index >= base_prefix_packet_count) {
            const auto after_base_index = index - base_prefix_packet_count + 1U;
            selected = (after_base_index % every_kth_step) == 0U;
        }
        if (!visit_packet(flow_packets[index], selected)) {
            return false;
        }
    }
    return true;
}

struct SmartPerFlowManifestRow {
    std::uint32_t export_flow_id {0};
    std::filesystem::path output_path {};
    std::string family {};
    std::string transport {};
    std::string protocol {};
    std::string protocol_hint {};
    std::string src_ip {};
    std::uint16_t src_port {0};
    std::string dst_ip {};
    std::uint16_t dst_port {0};
    std::uint64_t packet_count {0};
    std::uint64_t captured_bytes {0};
    std::uint64_t original_bytes {0};
    std::string first_timestamp {};
    std::string last_timestamp {};
    std::uint64_t duration_us {0};
    std::uint64_t exported_packet_count {0};
    std::uint64_t exported_captured_bytes {0};
    std::uint64_t exported_original_bytes {0};
};

std::string escape_csv_field(std::string_view text) {
    if (text.find_first_of(",\"\n\r") == std::string_view::npos) {
        return std::string(text);
    }

    std::string escaped;
    escaped.reserve(text.size() + 2U);
    escaped.push_back('"');
    for (const auto ch : text) {
        if (ch == '"') {
            escaped.push_back('"');
        }
        escaped.push_back(ch);
    }
    escaped.push_back('"');
    return escaped;
}

std::string family_text(const FlowAddressFamily family) {
    switch (family) {
    case FlowAddressFamily::ipv4:
        return "IPv4";
    case FlowAddressFamily::ipv6:
        return "IPv6";
    }

    return "unknown";
}

std::string normalize_manifest_protocol(const FlowRow& row) {
    if (!row.protocol_hint.empty()) {
        return row.protocol_hint;
    }
    return "unknown";
}

std::string normalize_manifest_protocol_hint(const FlowRow& row) {
    if (!row.service_hint.empty()) {
        return row.service_hint;
    }
    return "unknown";
}

std::string format_manifest_timestamp(const PacketRef& packet) {
    std::ostringstream stream {};
    stream << packet.ts_sec << '.' << std::setw(6) << std::setfill('0') << packet.ts_usec;
    return stream.str();
}

std::uint64_t packet_timestamp_us(const PacketRef& packet) noexcept {
    return static_cast<std::uint64_t>(packet.ts_sec) * 1'000'000ULL + static_cast<std::uint64_t>(packet.ts_usec);
}

std::string sanitize_filename_component(std::string_view component) {
    std::string sanitized {};
    sanitized.reserve(component.size());

    bool last_was_separator = false;
    for (const auto ch : component) {
        const auto unsigned_ch = static_cast<unsigned char>(ch);
        const bool is_ascii_alnum =
            (unsigned_ch >= static_cast<unsigned char>('0') && unsigned_ch <= static_cast<unsigned char>('9')) ||
            (unsigned_ch >= static_cast<unsigned char>('A') && unsigned_ch <= static_cast<unsigned char>('Z')) ||
            (unsigned_ch >= static_cast<unsigned char>('a') && unsigned_ch <= static_cast<unsigned char>('z'));
        const bool is_safe_symbol = unsigned_ch == static_cast<unsigned char>('_');
        const bool should_keep = is_ascii_alnum || is_safe_symbol;

        if (!should_keep) {
            if (!last_was_separator) {
                sanitized.push_back('_');
                last_was_separator = true;
            }
            continue;
        }

        sanitized.push_back(static_cast<char>(unsigned_ch));
        last_was_separator = false;
    }

    while (!sanitized.empty() && sanitized.front() == '_') {
        sanitized.erase(sanitized.begin());
    }
    while (!sanitized.empty() && sanitized.back() == '_') {
        sanitized.pop_back();
    }

    if (sanitized.empty()) {
        sanitized = "unknown";
    }

    constexpr std::size_t kMaxComponentLength = 32U;
    if (sanitized.size() > kMaxComponentLength) {
        sanitized.resize(kMaxComponentLength);
    }

    return sanitized;
}

std::string sanitize_filename_address_component(std::string_view component) {
    std::string sanitized {};
    sanitized.reserve(component.size());

    bool last_was_separator = false;
    for (const auto ch : component) {
        const auto unsigned_ch = static_cast<unsigned char>(ch);
        const bool is_ascii_alnum =
            (unsigned_ch >= static_cast<unsigned char>('0') && unsigned_ch <= static_cast<unsigned char>('9')) ||
            (unsigned_ch >= static_cast<unsigned char>('A') && unsigned_ch <= static_cast<unsigned char>('Z')) ||
            (unsigned_ch >= static_cast<unsigned char>('a') && unsigned_ch <= static_cast<unsigned char>('z'));
        const bool is_safe_symbol =
            unsigned_ch == static_cast<unsigned char>('_') ||
            unsigned_ch == static_cast<unsigned char>('.');
        const bool should_keep = is_ascii_alnum || is_safe_symbol;

        if (!should_keep) {
            if (!last_was_separator) {
                sanitized.push_back('_');
                last_was_separator = true;
            }
            continue;
        }

        sanitized.push_back(static_cast<char>(unsigned_ch));
        last_was_separator = false;
    }

    while (!sanitized.empty() && sanitized.front() == '_') {
        sanitized.erase(sanitized.begin());
    }
    while (!sanitized.empty() && sanitized.back() == '_') {
        sanitized.pop_back();
    }

    if (sanitized.empty()) {
        sanitized = "unknown";
    }

    if (sanitized.size() > 32U) {
        sanitized.resize(32U);
    }

    return sanitized;
}

std::filesystem::path build_smart_per_flow_output_path(const FlowRow& row, const std::uint32_t export_flow_id, const std::filesystem::path& output_directory) {
    std::ostringstream flow_id_stream {};
    flow_id_stream << std::setw(6) << std::setfill('0') << export_flow_id;

    const auto protocol = sanitize_filename_component(normalize_manifest_protocol(row));
    const auto hint = sanitize_filename_component(normalize_manifest_protocol_hint(row));
    const auto transport = sanitize_filename_component(row.protocol_text.empty() ? std::string("unknown") : row.protocol_text);
    const auto src_ip = sanitize_filename_address_component(row.address_a);
    const auto dst_ip = sanitize_filename_address_component(row.address_b);

    std::ostringstream file_name {};
    file_name << flow_id_stream.str()
              << '_' << protocol
              << '_' << hint
              << '_' << transport
              << '_' << src_ip
              << '_' << row.port_a
              << '-' << dst_ip
              << '_' << row.port_b
              << ".pcap";

    return output_directory / file_name.str();
}

bool write_smart_per_flow_manifest_csv(
    const std::filesystem::path& output_directory,
    std::span<const SmartPerFlowManifestRow> rows,
    std::string* out_error_text
) {
    std::ofstream stream {output_directory / "flows_manifest.csv", std::ios::binary | std::ios::trunc};
    if (!stream.is_open()) {
        if (out_error_text != nullptr) {
            *out_error_text = "Failed to create flows manifest CSV.";
        }
        return false;
    }

    stream << "flow_id,file_name,family,transport,protocol,protocol_hint,src_ip,src_port,dst_ip,dst_port,packet_count,captured_bytes,original_bytes,first_timestamp,last_timestamp,duration_us,exported_packet_count,exported_captured_bytes,exported_original_bytes\n";
    for (const auto& row : rows) {
        stream << row.export_flow_id << ','
               << escape_csv_field(row.output_path.filename().string()) << ','
               << escape_csv_field(row.family) << ','
               << escape_csv_field(row.transport) << ','
               << escape_csv_field(row.protocol) << ','
               << escape_csv_field(row.protocol_hint) << ','
               << escape_csv_field(row.src_ip) << ','
               << row.src_port << ','
               << escape_csv_field(row.dst_ip) << ','
               << row.dst_port << ','
               << row.packet_count << ','
               << row.captured_bytes << ','
               << row.original_bytes << ','
               << escape_csv_field(row.first_timestamp) << ','
               << escape_csv_field(row.last_timestamp) << ','
               << row.duration_us << ','
               << row.exported_packet_count << ','
               << row.exported_captured_bytes << ','
               << row.exported_original_bytes << '\n';
    }

    if (!stream.good()) {
        if (out_error_text != nullptr) {
            *out_error_text = "Failed to write flows manifest CSV.";
        }
        return false;
    }

    return true;
}

[[nodiscard]] std::vector<PacketRef> collect_selected_smart_export_packets(
    const std::vector<PacketRef>& packets,
    const SmartPacketRetentionOptions& options
) {
    if (packets.empty()) {
        return {};
    }

    std::vector<PacketRef> selected_packets {};
    selected_packets.reserve(packets.size());
    visit_smart_export_flow_packets(packets, options, [&selected_packets](const PacketRef& packet, const bool selected) {
        if (selected) {
            selected_packets.push_back(packet);
        }
        return true;
    });
    return selected_packets;
}

[[nodiscard]] std::vector<PacketRef> collect_selected_smart_export_unrecognized_packets(
    const std::vector<UnrecognizedPacketRecord>& records,
    const SmartPacketRetentionOptions& options
) {
    if (records.empty()) {
        return {};
    }

    if (options.base_mode == SmartFlowExportBaseMode::all_packets) {
        std::vector<PacketRef> selected_packets {};
        selected_packets.reserve(records.size());
        for (const auto& record : records) {
            selected_packets.push_back(record.packet);
        }
        return selected_packets;
    }

    std::vector<std::size_t> selected_indices {};
    selected_indices.reserve(records.size());

    std::size_t base_prefix_packet_count = 0U;
    if (options.base_mode == SmartFlowExportBaseMode::first_n_packets) {
        base_prefix_packet_count = static_cast<std::size_t>(
            std::min<std::uint64_t>(options.first_n_packets, static_cast<std::uint64_t>(records.size()))
        );
        for (std::size_t index = 0; index < base_prefix_packet_count; ++index) {
            selected_indices.push_back(index);
        }
    } else {
        std::uint64_t accumulated_original_bytes = 0U;
        for (std::size_t index = 0; index < records.size(); ++index) {
            selected_indices.push_back(index);
            accumulated_original_bytes += records[index].packet.original_length;
            ++base_prefix_packet_count;
            if (accumulated_original_bytes >= options.first_m_original_bytes) {
                break;
            }
        }
    }

    if (options.include_last_packet) {
        selected_indices.push_back(records.size() - 1U);
    }

    if (options.include_every_kth_packet_after_base && options.every_kth_packet > 0U && base_prefix_packet_count < records.size()) {
        const auto step = static_cast<std::size_t>(options.every_kth_packet);
        for (std::size_t after_base_index = step; base_prefix_packet_count + after_base_index - 1U < records.size(); after_base_index += step) {
            selected_indices.push_back(base_prefix_packet_count + after_base_index - 1U);
        }
    }

    std::sort(selected_indices.begin(), selected_indices.end());
    selected_indices.erase(std::unique(selected_indices.begin(), selected_indices.end()), selected_indices.end());

    std::vector<PacketRef> selected_packets {};
    selected_packets.reserve(selected_indices.size());
    for (const auto index : selected_indices) {
        selected_packets.push_back(records[index].packet);
    }
    return selected_packets;
}

}  // namespace

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

bool CaptureSession::export_smart_flows_to_pcap(
    const SmartFlowExportRequest& request,
    const std::filesystem::path& output_path
) const {
    if (!has_source_capture() || request.flow_indices.empty()) {
        return false;
    }

    const auto options = retention_options(request);
    if (!validate_smart_packet_retention_options(options)) {
        return false;
    }

    if (summary().packet_count == 0U) {
        return false;
    }

    std::vector<std::uint8_t> packet_selection {};
    bool marked_any_packet = false;
    bool marking_ok = true;

    for (const auto flow_index : request.flow_indices) {
        const auto packets = flow_packets(flow_index);
        if (!packets.has_value()) {
            return false;
        }

        const auto selected_packets = collect_selected_smart_export_packets(*packets, options);
        for (const auto& packet : selected_packets) {
            if (!mark_packet_for_smart_export(packet_selection, packet)) {
                marking_ok = false;
            }
        }
        if (!marking_ok) {
            return false;
        }
    }

    for (const auto selected : packet_selection) {
        if (selected != 0U) {
            marked_any_packet = true;
            break;
        }
    }

    if (!marked_any_packet) {
        return false;
    }

    FlowExportService service {};
    return service.export_marked_packets_to_pcap(output_path, packet_selection, capture_path());
}

bool CaptureSession::export_smart_packets_to_pcap(
    const SmartPacketListExportRequest& request,
    const std::filesystem::path& output_path
) const {
    if (!has_source_capture() || request.packet_indices.empty()) {
        return false;
    }

    if (!validate_smart_packet_retention_options(request.retention)) {
        return false;
    }

    if (summary().packet_count == 0U) {
        return false;
    }

    std::vector<PacketRef> packets {};
    packets.reserve(request.packet_indices.size());
    for (const auto packet_index : request.packet_indices) {
        const auto packet = find_packet(static_cast<std::uint64_t>(packet_index));
        if (!packet.has_value()) {
            return false;
        }
        packets.push_back(*packet);
    }

    const auto selected_packets = collect_selected_smart_export_packets(packets, request.retention);
    if (selected_packets.empty()) {
        return false;
    }

    FlowExportService service {};
    return service.export_packets_to_pcap(output_path, selected_packets, capture_path());
}

bool CaptureSession::export_smart_unrecognized_packets_to_pcap(
    const SmartPacketRetentionOptions& options,
    const std::filesystem::path& output_path
) const {
    if (!has_source_capture() || state_.unrecognized_packets.empty()) {
        return false;
    }

    if (!validate_smart_packet_retention_options(options)) {
        return false;
    }

    if (summary().packet_count == 0U) {
        return false;
    }

    const auto selected_packets = collect_selected_smart_export_unrecognized_packets(state_.unrecognized_packets, options);
    if (selected_packets.empty()) {
        return false;
    }

    std::vector<std::uint8_t> packet_selection {};
    for (const auto& packet : selected_packets) {
        if (!mark_packet_for_smart_export(packet_selection, packet)) {
            return false;
        }
    }

    FlowExportService service {};
    return service.export_marked_packets_to_pcap(output_path, packet_selection, capture_path());
}

bool CaptureSession::export_smart_flows_to_folder(
    const SmartFlowExportRequest& request,
    const std::filesystem::path& output_directory
) const {
    std::string error_text {};
    return export_smart_flows_to_folder(request, output_directory, SmartPerFlowExportOptions {}, &error_text);
}

bool CaptureSession::export_smart_flows_to_folder(
    const SmartFlowExportRequest& request,
    const std::filesystem::path& output_directory,
    const SmartPerFlowExportOptions& options,
    std::string* out_error_text
) const {
    if (!has_source_capture() || request.flow_indices.empty()) {
        if (out_error_text != nullptr) {
            *out_error_text = "No source capture or no flows were selected for per-flow smart export.";
        }
        return false;
    }

    const auto retention = retention_options(request);
    if (retention.base_mode == SmartFlowExportBaseMode::first_n_packets && retention.first_n_packets == 0U) {
        if (out_error_text != nullptr) {
            *out_error_text = "Per-flow smart export requires a positive packet count.";
        }
        return false;
    }

    if (retention.base_mode == SmartFlowExportBaseMode::first_m_original_bytes &&
        retention.first_m_original_bytes == 0U) {
        if (out_error_text != nullptr) {
            *out_error_text = "Per-flow smart export requires a positive original-byte limit.";
        }
        return false;
    }

    if (retention.base_mode != SmartFlowExportBaseMode::all_packets &&
        retention.include_every_kth_packet_after_base &&
        retention.every_kth_packet == 0U) {
        if (out_error_text != nullptr) {
            *out_error_text = "Per-flow smart export requires a positive K value.";
        }
        return false;
    }

    if (summary().packet_count == 0U) {
        if (out_error_text != nullptr) {
            *out_error_text = "No packets are available for per-flow smart export.";
        }
        return false;
    }

    if (request.flow_indices.size() > static_cast<std::size_t>(std::numeric_limits<std::uint32_t>::max() - 1U)) {
        if (out_error_text != nullptr) {
            *out_error_text = "Too many flows were selected for per-flow smart export.";
        }
        return false;
    }

    if (options.buffer_budget_bytes == 0U) {
        if (out_error_text != nullptr) {
            *out_error_text = "Per-flow smart export buffer budget must be at least 1 byte.";
        }
        return false;
    }

    std::error_code filesystem_error {};
    std::filesystem::create_directories(output_directory, filesystem_error);
    if (filesystem_error) {
        if (out_error_text != nullptr) {
            *out_error_text = "Failed to create destination folder for per-flow smart export.";
        }
        return false;
    }

    const auto listed_flows = list_flows();
    std::vector<std::uint32_t> packet_owner {};
    std::vector<PerFlowExportTarget> targets {};
    std::vector<SmartPerFlowManifestRow> manifest_rows {};
    targets.reserve(request.flow_indices.size());
    manifest_rows.reserve(request.flow_indices.size());

    const auto total_selected_flows = static_cast<std::uint64_t>(request.flow_indices.size());
    std::uint64_t processed_selected_flows = 0U;
    constexpr std::size_t kPreparationCancellationCheckPacketInterval = 4096U;
    if (options.progress_callback) {
        options.progress_callback(SmartPerFlowExportProgress {
            .phase = SmartPerFlowExportPhase::preparing,
            .packets_processed = 0U,
            .total_packets_to_scan = total_selected_flows,
            .exported_packets_written = 0U,
        });
    }

    std::uint32_t next_export_flow_id = 1U;
    for (const auto flow_index : request.flow_indices) {
        if (options.cancel_requested && options.cancel_requested()) {
            if (out_error_text != nullptr) {
                *out_error_text = "Smart export cancelled by user.";
            }
            return false;
        }

        const auto listed_row = std::find_if(listed_flows.begin(), listed_flows.end(), [flow_index](const FlowRow& row) {
            return row.index == flow_index;
        });
        if (listed_row == listed_flows.end()) {
            if (out_error_text != nullptr) {
                *out_error_text = "Failed to resolve a selected flow for per-flow smart export.";
            }
            return false;
        }

        const auto packets = flow_packets(flow_index);
        if (!packets.has_value() || packets->empty()) {
            if (out_error_text != nullptr) {
                *out_error_text = "Failed to load packets for a selected flow during per-flow smart export.";
            }
            return false;
        }

        const auto& row = *listed_row;
        std::uint64_t captured_bytes = 0U;
        for (const auto& packet : *packets) {
            captured_bytes += packet.captured_length;
        }

        const auto first_timestamp = packet_timestamp_us(packets->front());
        const auto last_timestamp = packet_timestamp_us(packets->back());

        manifest_rows.push_back(SmartPerFlowManifestRow {
            .export_flow_id = next_export_flow_id,
            .output_path = build_smart_per_flow_output_path(row, next_export_flow_id, output_directory),
            .family = family_text(row.family),
            .transport = row.protocol_text.empty() ? std::string("unknown") : row.protocol_text,
            .protocol = normalize_manifest_protocol(row),
            .protocol_hint = normalize_manifest_protocol_hint(row),
            .src_ip = row.address_a,
            .src_port = row.port_a,
            .dst_ip = row.address_b,
            .dst_port = row.port_b,
            .packet_count = row.packet_count,
            .captured_bytes = captured_bytes,
            .original_bytes = row.total_bytes,
            .first_timestamp = format_manifest_timestamp(packets->front()),
            .last_timestamp = format_manifest_timestamp(packets->back()),
            .duration_us = last_timestamp >= first_timestamp ? last_timestamp - first_timestamp : 0U,
        });
        targets.push_back(PerFlowExportTarget {
            .export_flow_id = next_export_flow_id,
            .output_path = manifest_rows.back().output_path,
        });

        bool ownership_ok = true;
        bool cancelled = false;
        std::size_t packets_since_cancel_check = 0U;
        auto mark_owned_packet = [&packet_owner, &manifest = manifest_rows.back(), &ownership_ok](const PacketRef& packet) {
            if (!ensure_packet_owner_capacity(packet_owner, packet.packet_index)) {
                ownership_ok = false;
                return;
            }

            auto& owner = packet_owner[static_cast<std::size_t>(packet.packet_index)];
            if (owner == 0U) {
                owner = manifest.export_flow_id;
                ++manifest.exported_packet_count;
                manifest.exported_captured_bytes += packet.captured_length;
                manifest.exported_original_bytes += packet.original_length;
            }
            if (owner != manifest.export_flow_id) {
                ownership_ok = false;
            }
        };

        if (!visit_smart_export_flow_packets(*packets, retention, [&](const PacketRef& packet, const bool selected) {
            if (selected) {
                mark_owned_packet(packet);
            }
            if (!ownership_ok) {
                return false;
            }

            ++packets_since_cancel_check;
            if (options.cancel_requested &&
                packets_since_cancel_check >= kPreparationCancellationCheckPacketInterval &&
                options.cancel_requested()) {
                cancelled = true;
                return false;
            }
            return true;
        })) {
            if (cancelled) {
                if (out_error_text != nullptr) {
                    *out_error_text = "Smart export cancelled by user.";
                }
                return false;
            }
        }
        if (!ownership_ok) {
            if (out_error_text != nullptr) {
                *out_error_text = "Per-flow smart export was interrupted by an internal ownership/state error.";
            }
            return false;
        }

        if (manifest_rows.back().exported_packet_count == 0U) {
            if (out_error_text != nullptr) {
                *out_error_text = "Per-flow smart export selected zero packets for one of the chosen flows.";
            }
            return false;
        }

        ++processed_selected_flows;
        if (options.progress_callback) {
            options.progress_callback(SmartPerFlowExportProgress {
                .phase = SmartPerFlowExportPhase::preparing,
                .packets_processed = processed_selected_flows,
                .total_packets_to_scan = total_selected_flows,
                .exported_packets_written = 0U,
            });
        }

        ++next_export_flow_id;
    }

    if (options.cancel_requested && options.cancel_requested()) {
        if (out_error_text != nullptr) {
            *out_error_text = "Smart export cancelled by user.";
        }
        return false;
    }

    FlowExportService service {};
    const PerFlowExportOptions export_options {
        .buffer_budget_bytes = options.buffer_budget_bytes,
        .max_open_file_handles = 64U,
        .progress_callback = [callback = options.progress_callback](const PerFlowExportProgress& progress) {
            if (callback) {
                callback(SmartPerFlowExportProgress {
                    .phase = SmartPerFlowExportPhase::writing,
                    .packets_processed = progress.packets_processed,
                    .total_packets_to_scan = progress.total_packets_to_scan,
                    .exported_packets_written = progress.exported_packets_written,
                });
            }
        },
        .cancel_requested = options.cancel_requested,
    };
    if (!service.export_owned_packets_to_pcaps(targets, packet_owner, capture_path(), export_options, out_error_text)) {
        return false;
    }

    if (options.cancel_requested && options.cancel_requested()) {
        if (out_error_text != nullptr) {
            *out_error_text = "Smart export cancelled by user.";
        }
        return false;
    }

    return write_smart_per_flow_manifest_csv(output_directory, manifest_rows, out_error_text);
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

    const auto unrecognized_packet = std::find_if(
        state_.unrecognized_packets.begin(),
        state_.unrecognized_packets.end(),
        [packet_index](const UnrecognizedPacketRecord& record) {
            return record.packet.packet_index == packet_index;
        }
    );
    if (unrecognized_packet != state_.unrecognized_packets.end()) {
        return unrecognized_packet->packet;
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

