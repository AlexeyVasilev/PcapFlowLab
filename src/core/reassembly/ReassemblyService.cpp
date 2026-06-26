#include "core/reassembly/ReassemblyService.h"

#include <algorithm>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <variant>

#include "app/session/SelectedFlowDiagnostics.h"
#include "app/session/CaptureSession.h"

namespace pfl {

namespace {

struct ListedConnectionRef {
    FlowAddressFamily family {FlowAddressFamily::ipv4};
    const ConnectionV4* ipv4 {nullptr};
    const ConnectionV6* ipv6 {nullptr};
};

std::uint64_t packet_count(const ListedConnectionRef& connection) noexcept {
    return (connection.family == FlowAddressFamily::ipv4) ? connection.ipv4->packet_count : connection.ipv6->packet_count;
}

std::uint64_t total_bytes(const ListedConnectionRef& connection) noexcept {
    return (connection.family == FlowAddressFamily::ipv4) ? connection.ipv4->total_bytes : connection.ipv6->total_bytes;
}

bool listed_connection_less(const ListedConnectionRef& left, const ListedConnectionRef& right) noexcept {
    if (total_bytes(left) != total_bytes(right)) {
        return total_bytes(left) > total_bytes(right);
    }

    if (packet_count(left) != packet_count(right)) {
        return packet_count(left) > packet_count(right);
    }

    if (left.family != right.family) {
        return left.family < right.family;
    }

    if (left.family == FlowAddressFamily::ipv4) {
        return left.ipv4->key < right.ipv4->key;
    }

    return left.ipv6->key < right.ipv6->key;
}

std::vector<ListedConnectionRef> list_connections(const CaptureState& state) {
    std::vector<ListedConnectionRef> connections {};

    const auto ipv4_connections = state.ipv4_connections.list();
    const auto ipv6_connections = state.ipv6_connections.list();
    connections.reserve(ipv4_connections.size() + ipv6_connections.size());

    for (const auto* connection : ipv4_connections) {
        connections.push_back(ListedConnectionRef {
            .family = FlowAddressFamily::ipv4,
            .ipv4 = connection,
        });
    }

    for (const auto* connection : ipv6_connections) {
        connections.push_back(ListedConnectionRef {
            .family = FlowAddressFamily::ipv6,
            .ipv6 = connection,
        });
    }

    std::sort(connections.begin(), connections.end(), listed_connection_less);
    return connections;
}

ProtocolId protocol_id(const ListedConnectionRef& connection) noexcept {
    return (connection.family == FlowAddressFamily::ipv4) ? connection.ipv4->key.protocol : connection.ipv6->key.protocol;
}

std::vector<PacketRef> collect_direction_packets(const ListedConnectionRef& connection, const Direction direction) {
    const auto select_packets = [direction](const auto& runtime_connection) -> const std::vector<PacketRef>& {
        return direction == Direction::a_to_b ? runtime_connection.flow_a.packets : runtime_connection.flow_b.packets;
    };

    std::vector<PacketRef> packets = (connection.family == FlowAddressFamily::ipv4)
        ? std::vector<PacketRef>(select_packets(*connection.ipv4))
        : std::vector<PacketRef>(select_packets(*connection.ipv6));

    std::sort(packets.begin(), packets.end(), [](const PacketRef& left, const PacketRef& right) {
        return left.packet_index < right.packet_index;
    });
    if (selected_flow_diagnostics::enabled()) {
        std::ostringstream out {};
        out << "collect_direction_packets direction=" << (direction == Direction::a_to_b ? "a_to_b" : "b_to_a")
            << " copied_packets=" << packets.size()
            << " sorted=true";
        selected_flow_diagnostics::log(out.str());
    }
    return packets;
}

void set_flag(ReassemblyResult& result, const ReassemblyQualityFlag flag) noexcept {
    result.quality_flags |= static_cast<std::uint32_t>(flag);
}

std::string format_elapsed_ms(const double elapsed_ms) {
    std::ostringstream out {};
    out << std::fixed << std::setprecision(2) << elapsed_ms << " ms";
    return out.str();
}

std::optional<ReassemblyResult> reassemble_tcp_payload_from_packet_span(
    const CaptureSession& session,
    const ReassemblyRequest& request,
    const std::span<const PacketRef> direction_packets,
    const bool bounded_prefix_path_used,
    const bool full_direction_collect_called
) {
    const auto started_at = std::chrono::steady_clock::now();
    const auto read_counters_before = selected_flow_diagnostics::snapshot_read_counters();
    if (!session.has_source_capture()) {
        return std::nullopt;
    }

    ReassemblyResult result {};
    set_flag(result, ReassemblyQualityFlag::packet_order_only);
    set_flag(result, ReassemblyQualityFlag::may_contain_retransmissions);
    const auto selected_flow_gap_packet_index =
        session.selected_flow_tcp_direction_first_gap_packet_index(request.flow_index, request.direction);

    const auto packet_budget = std::min(request.max_packets, direction_packets.size());
    if (packet_budget < direction_packets.size()) {
        set_flag(result, ReassemblyQualityFlag::truncated_by_packet_budget);
    }

    for (std::size_t index = 0; index < packet_budget; ++index) {
        const auto& packet = direction_packets[index];
        ++result.total_packets_seen;

        if (packet.is_ip_fragmented) {
            set_flag(result, ReassemblyQualityFlag::may_contain_transport_gaps);
            result.stopped_at_gap = true;
            result.first_gap_packet_index = packet.packet_index;
            break;
        }

        if (packet.payload_length == 0U) {
            set_flag(result, ReassemblyQualityFlag::contains_non_payload_packets);
            continue;
        }

        if (selected_flow_gap_packet_index.has_value() && packet.packet_index >= *selected_flow_gap_packet_index) {
            set_flag(result, ReassemblyQualityFlag::may_contain_transport_gaps);
            result.stopped_at_gap = true;
            result.first_gap_packet_index = *selected_flow_gap_packet_index;
            break;
        }

        if (session.should_suppress_selected_flow_tcp_payload(request.flow_index, packet.packet_index)) {
            set_flag(result, ReassemblyQualityFlag::duplicate_tcp_segment_suppressed);
            continue;
        }

        const auto payload = session.read_selected_flow_transport_payload(request.flow_index, packet);
        if (payload.empty() || payload.size() != packet.payload_length) {
            set_flag(result, ReassemblyQualityFlag::may_contain_transport_gaps);
            result.stopped_at_gap = true;
            result.first_gap_packet_index = packet.packet_index;
            break;
        }

        const auto trim_prefix_bytes = session.selected_flow_tcp_payload_trim_prefix_bytes(
            request.flow_index,
            packet.packet_index
        );
        if (trim_prefix_bytes >= payload.size()) {
            set_flag(result, ReassemblyQualityFlag::duplicate_tcp_segment_suppressed);
            continue;
        }

        const auto remaining_budget = request.max_bytes - std::min(request.max_bytes, result.bytes.size());
        if (remaining_budget == 0U) {
            set_flag(result, ReassemblyQualityFlag::truncated_by_byte_budget);
            break;
        }

        const auto contributed_payload_size = payload.size() - trim_prefix_bytes;
        const auto appended_bytes = std::min(remaining_budget, contributed_payload_size);
        result.bytes.insert(
            result.bytes.end(),
            payload.begin() + static_cast<std::ptrdiff_t>(trim_prefix_bytes),
            payload.begin() + static_cast<std::ptrdiff_t>(trim_prefix_bytes + appended_bytes)
        );
        result.packet_indices.push_back(packet.packet_index);
        result.packet_byte_counts.push_back(appended_bytes);
        ++result.payload_packets_used;

        if (trim_prefix_bytes > 0U) {
            set_flag(result, ReassemblyQualityFlag::duplicate_tcp_segment_suppressed);
        }

        if (appended_bytes < contributed_payload_size) {
            set_flag(result, ReassemblyQualityFlag::truncated_by_byte_budget);
            break;
        }
    }

    if (selected_flow_diagnostics::enabled()) {
        std::ostringstream out {};
        out << "reassemble_tcp_payload flow_index=" << request.flow_index
            << " direction=" << (request.direction == Direction::a_to_b ? "a_to_b" : "b_to_a")
            << " bounded_prefix_path_used=" << (bounded_prefix_path_used ? "true" : "false")
            << " full_direction_collect_called=" << (full_direction_collect_called ? "true" : "false")
            << " direction_packet_input_count=" << direction_packets.size()
            << " packet_budget=" << packet_budget
            << " payload_packets_used=" << result.payload_packets_used
            << " total_packets_seen=" << result.total_packets_seen
            << " output_bytes=" << result.bytes.size()
            << " stopped_at_gap=" << (result.stopped_at_gap ? "true" : "false")
            << " elapsed=" << format_elapsed_ms(selected_flow_diagnostics::elapsed_ms(started_at))
            << ' ' << selected_flow_diagnostics::format_read_counter_delta(
                read_counters_before,
                selected_flow_diagnostics::snapshot_read_counters()
            );
        selected_flow_diagnostics::log(out.str());
    }

    return result;
}

}  // namespace

std::optional<ReassemblyResult> ReassemblyService::reassemble_tcp_payload(
    const CaptureSession& session,
    const ReassemblyRequest& request
) const {
    if (!session.has_source_capture()) {
        return std::nullopt;
    }

    const auto connections = list_connections(session.state());
    if (request.flow_index >= connections.size()) {
        return std::nullopt;
    }

    const auto& connection = connections[request.flow_index];
    if (protocol_id(connection) != ProtocolId::tcp) {
        return std::nullopt;
    }

    const auto packets = collect_direction_packets(connection, request.direction);
    return reassemble_tcp_payload_from_packet_span(
        session,
        request,
        std::span<const PacketRef>(packets.data(), packets.size()),
        false,
        true
    );
}

std::optional<ReassemblyResult> ReassemblyService::reassemble_tcp_payload(
    const CaptureSession& session,
    const ReassemblyRequest& request,
    const std::span<const PacketRef> direction_packets
) const {
    if (!std::is_sorted(direction_packets.begin(), direction_packets.end(), [](const PacketRef& left, const PacketRef& right) {
            return left.packet_index < right.packet_index;
        })) {
        std::vector<PacketRef> sorted_packets(direction_packets.begin(), direction_packets.end());
        std::sort(sorted_packets.begin(), sorted_packets.end(), [](const PacketRef& left, const PacketRef& right) {
            return left.packet_index < right.packet_index;
        });
        return reassemble_tcp_payload_from_packet_span(
            session,
            request,
            std::span<const PacketRef>(sorted_packets.data(), sorted_packets.size()),
            true,
            false
        );
    }

    return reassemble_tcp_payload_from_packet_span(session, request, direction_packets, true, false);
}

}  // namespace pfl
