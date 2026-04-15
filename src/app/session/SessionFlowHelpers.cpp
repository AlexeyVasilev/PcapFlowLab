#include "app/session/SessionFlowHelpers.h"

#include <algorithm>

#include "app/session/SessionFormatting.h"
#include "core/domain/FlowHints.h"

namespace pfl::session_detail {

namespace {

FlowProtocolHint protocol_hint(const ListedConnectionRef& connection) noexcept {
    return (connection.family == FlowAddressFamily::ipv4) ? connection.ipv4->protocol_hint : connection.ipv6->protocol_hint;
}

bool has_port_443(const ListedConnectionRef& connection) noexcept {
    if (connection.family == FlowAddressFamily::ipv4) {
        return connection.ipv4->key.first.port == 443U || connection.ipv4->key.second.port == 443U;
    }

    return connection.ipv6->key.first.port == 443U || connection.ipv6->key.second.port == 443U;
}

std::string protocol_text(const ProtocolId protocol) {
    switch (protocol) {
    case ProtocolId::arp:
        return "ARP";
    case ProtocolId::icmp:
        return "ICMP";
    case ProtocolId::tcp:
        return "TCP";
    case ProtocolId::udp:
        return "UDP";
    case ProtocolId::icmpv6:
        return "ICMPv6";
    default:
        return "unknown";
    }
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

}  // namespace

std::uint64_t packet_count(const ListedConnectionRef& connection) noexcept {
    return (connection.family == FlowAddressFamily::ipv4) ? connection.ipv4->packet_count : connection.ipv6->packet_count;
}

std::uint64_t total_bytes(const ListedConnectionRef& connection) noexcept {
    return (connection.family == FlowAddressFamily::ipv4) ? connection.ipv4->total_bytes : connection.ipv6->total_bytes;
}

ProtocolId protocol_id(const ListedConnectionRef& connection) noexcept {
    return (connection.family == FlowAddressFamily::ipv4) ? connection.ipv4->key.protocol : connection.ipv6->key.protocol;
}

FlowProtocolHint effective_protocol_hint(const ListedConnectionRef& connection, const AnalysisSettings& settings) noexcept {
    const auto confirmed_hint = protocol_hint(connection);
    if (confirmed_hint != FlowProtocolHint::unknown) {
        return confirmed_hint;
    }

    if (!settings.use_possible_tls_quic || !has_port_443(connection)) {
        return FlowProtocolHint::unknown;
    }

    switch (protocol_id(connection)) {
    case ProtocolId::tcp:
        return FlowProtocolHint::possible_tls;
    case ProtocolId::udp:
        return FlowProtocolHint::possible_quic;
    default:
        return FlowProtocolHint::unknown;
    }
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

void add_protocol_stats(ProtocolStats& stats, const ListedConnectionRef& connection) noexcept {
    ++stats.flow_count;
    stats.packet_count += packet_count(connection);
    stats.total_bytes += total_bytes(connection);
}

std::vector<PacketRef> collect_packets(const ConnectionV4& connection) {
    std::vector<PacketRef> packets {};
    packets.reserve(connection.flow_a.packets.size() + connection.flow_b.packets.size());
    packets.insert(packets.end(), connection.flow_a.packets.begin(), connection.flow_a.packets.end());
    packets.insert(packets.end(), connection.flow_b.packets.begin(), connection.flow_b.packets.end());
    std::sort(packets.begin(), packets.end(), [](const PacketRef& left, const PacketRef& right) {
        return left.packet_index < right.packet_index;
    });
    return packets;
}

std::vector<PacketRef> collect_packets(const ConnectionV6& connection) {
    std::vector<PacketRef> packets {};
    packets.reserve(connection.flow_a.packets.size() + connection.flow_b.packets.size());
    packets.insert(packets.end(), connection.flow_a.packets.begin(), connection.flow_a.packets.end());
    packets.insert(packets.end(), connection.flow_b.packets.begin(), connection.flow_b.packets.end());
    std::sort(packets.begin(), packets.end(), [](const PacketRef& left, const PacketRef& right) {
        return left.packet_index < right.packet_index;
    });
    return packets;
}

FlowRow make_flow_row(std::size_t index, const ListedConnectionRef& connection, const AnalysisSettings& settings) {
    const auto hint = effective_protocol_hint(connection, settings);
    const auto hint_text = hint == FlowProtocolHint::unknown ? std::string {} : std::string(flow_protocol_hint_text(hint));

    if (connection.family == FlowAddressFamily::ipv4) {
        const auto& key = connection.ipv4->key;
        return FlowRow {
            .index = index,
            .family = FlowAddressFamily::ipv4,
            .key = key,
            .protocol_text = protocol_text(key.protocol),
            .protocol_hint = hint_text,
            .service_hint = connection.ipv4->service_hint,
            .has_fragmented_packets = connection.ipv4->has_fragmented_packets,
            .fragmented_packet_count = connection.ipv4->fragmented_packet_count,
            .address_a = format_ipv4_address(key.first.addr),
            .port_a = key.first.port,
            .endpoint_a = format_endpoint(key.first),
            .address_b = format_ipv4_address(key.second.addr),
            .port_b = key.second.port,
            .endpoint_b = format_endpoint(key.second),
            .packet_count = connection.ipv4->packet_count,
            .total_bytes = connection.ipv4->total_bytes,
        };
    }

    const auto& key = connection.ipv6->key;
    return FlowRow {
        .index = index,
        .family = FlowAddressFamily::ipv6,
        .key = key,
        .protocol_text = protocol_text(key.protocol),
        .protocol_hint = hint_text,
        .service_hint = connection.ipv6->service_hint,
        .has_fragmented_packets = connection.ipv6->has_fragmented_packets,
        .fragmented_packet_count = connection.ipv6->fragmented_packet_count,
        .address_a = format_ipv6_address(key.first.addr),
        .port_a = key.first.port,
        .endpoint_a = format_endpoint(key.first),
        .address_b = format_ipv6_address(key.second.addr),
        .port_b = key.second.port,
        .endpoint_b = format_endpoint(key.second),
        .packet_count = connection.ipv6->packet_count,
        .total_bytes = connection.ipv6->total_bytes,
    };
}

}  // namespace pfl::session_detail
