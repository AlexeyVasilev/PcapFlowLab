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
            item.payload_hex_text,
            item.protocol_text
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
    const std::size_t max_packets_to_scan
) {
    DirectionalStreamPolicy policy {};
    const auto presentation = build_http_stream_items_from_reassembly(session, flow_index, direction, max_packets_to_scan);
    for (const auto& item : presentation.items) {
        rows.push_back(make_stream_item_row(
            static_cast<std::uint64_t>(rows.size() + 1U),
            direction_text,
            item.label,
            item.byte_count,
            item.packet_indices,
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
    const std::size_t max_packets_to_scan
) {
    DirectionalStreamPolicy policy {};
    const auto presentation = build_tls_stream_items_from_reassembly(session, flow_index, direction, max_packets_to_scan);
    for (const auto& item : presentation.items) {
        rows.push_back(make_stream_item_row(
            static_cast<std::uint64_t>(rows.size() + 1U),
            direction_text,
            item.label,
            item.byte_count,
            item.packet_indices,
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
            packet_hex_dump,
            item.protocol_text
        ));
        emitted_any = true;
    }

    return emitted_any || presentation.handled;
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

        return collect_suspected_tcp_retransmission_packet_indices(
            *this,
            flow_index,
            connections[flow_index].ipv4->flow_a.packets,
            connections[flow_index].ipv4->flow_b.packets,
            max_packets_to_scan
        );
    }

    if (connections[flow_index].ipv6->key.protocol != ProtocolId::tcp) {
        return {};
    }

    return collect_suspected_tcp_retransmission_packet_indices(
        *this,
        flow_index,
        connections[flow_index].ipv6->flow_a.packets,
        connections[flow_index].ipv6->flow_b.packets,
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

    const auto analysis = connection.family == FlowAddressFamily::ipv4
        ? analyze_selected_flow_tcp_payload_suppression(
            *this,
            flow_index,
            connection.ipv4->flow_a.packets,
            connection.ipv4->flow_b.packets,
            exact_duplicate_packet_indices,
            prefix_count_a,
            prefix_count_b
        )
        : analyze_selected_flow_tcp_payload_suppression(
            *this,
            flow_index,
            connection.ipv6->flow_a.packets,
            connection.ipv6->flow_b.packets,
            exact_duplicate_packet_indices,
            prefix_count_a,
            prefix_count_b
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

