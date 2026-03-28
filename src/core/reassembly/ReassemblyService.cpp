#include "core/reassembly/ReassemblyService.h"

#include <algorithm>
#include <variant>

#include "app/session/CaptureSession.h"
#include "core/services/PacketPayloadService.h"

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
    return packets;
}

void set_flag(ReassemblyResult& result, const ReassemblyQualityFlag flag) noexcept {
    result.quality_flags |= static_cast<std::uint32_t>(flag);
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

    ReassemblyResult result {};
    set_flag(result, ReassemblyQualityFlag::packet_order_only);
    set_flag(result, ReassemblyQualityFlag::may_contain_retransmissions);

    const auto packets = collect_direction_packets(connection, request.direction);
    const auto packet_budget = std::min(request.max_packets, packets.size());
    if (packet_budget < packets.size()) {
        set_flag(result, ReassemblyQualityFlag::truncated_by_packet_budget);
    }

    PacketPayloadService payload_service {};

    for (std::size_t index = 0; index < packet_budget; ++index) {
        const auto& packet = packets[index];
        ++result.total_packets_seen;

        if (packet.is_ip_fragmented) {
            set_flag(result, ReassemblyQualityFlag::may_contain_transport_gaps);
            if (packet.payload_length == 0U) {
                continue;
            }
        }

        if (packet.payload_length == 0U) {
            set_flag(result, ReassemblyQualityFlag::contains_non_payload_packets);
            continue;
        }

        const auto bytes = session.read_packet_data(packet);
        if (bytes.empty()) {
            set_flag(result, ReassemblyQualityFlag::may_contain_transport_gaps);
            continue;
        }

        const auto payload = payload_service.extract_transport_payload(bytes, packet.data_link_type);
        if (payload.empty() || payload.size() != packet.payload_length) {
            set_flag(result, ReassemblyQualityFlag::may_contain_transport_gaps);
            continue;
        }

        const auto remaining_budget = request.max_bytes - std::min(request.max_bytes, result.bytes.size());
        if (remaining_budget == 0U) {
            set_flag(result, ReassemblyQualityFlag::truncated_by_byte_budget);
            break;
        }

        const auto appended_bytes = std::min(remaining_budget, payload.size());
        result.bytes.insert(result.bytes.end(), payload.begin(), payload.begin() + static_cast<std::ptrdiff_t>(appended_bytes));
        result.packet_indices.push_back(packet.packet_index);
        ++result.payload_packets_used;

        if (appended_bytes < payload.size()) {
            set_flag(result, ReassemblyQualityFlag::truncated_by_byte_budget);
            break;
        }
    }

    return result;
}

}  // namespace pfl

