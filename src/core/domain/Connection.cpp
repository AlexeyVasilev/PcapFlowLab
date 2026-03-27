#include "core/domain/Connection.h"

namespace pfl {

namespace {

void append_packet(FlowV4& flow, const FlowKeyV4& packet_key, const PacketRef& packet) {
    flow.key = packet_key;
    flow.packets.push_back(packet);
    ++flow.packet_count;
    flow.total_bytes += packet.original_length;
}

void append_packet(FlowV6& flow, const FlowKeyV6& packet_key, const PacketRef& packet) {
    flow.key = packet_key;
    flow.packets.push_back(packet);
    ++flow.packet_count;
    flow.total_bytes += packet.original_length;
}

template <typename Connection>
void apply_hints_to_connection(Connection& connection, const FlowHintUpdate& hints) {
    if (connection.protocol_hint == FlowProtocolHint::unknown && hints.protocol_hint != FlowProtocolHint::unknown) {
        connection.protocol_hint = hints.protocol_hint;
    }

    if (connection.service_hint.empty() && !hints.service_hint.empty()) {
        connection.service_hint = hints.service_hint;
    }
}

template <typename Connection>
void update_fragmentation_stats(Connection& connection, const PacketRef& packet) {
    if (!packet.is_ip_fragmented) {
        return;
    }

    connection.has_fragmented_packets = true;
    ++connection.fragmented_packet_count;
}

}  // namespace

void ConnectionV4::add_packet(const FlowKeyV4& packet_key, const PacketRef& packet) {
    ++packet_count;
    total_bytes += packet.original_length;
    update_fragmentation_stats(*this, packet);

    if (!has_flow_a) {
        append_packet(flow_a, packet_key, packet);
        has_flow_a = true;
        return;
    }

    if (packet_key == flow_a.key) {
        append_packet(flow_a, packet_key, packet);
        return;
    }

    if (!has_flow_b) {
        append_packet(flow_b, packet_key, packet);
        has_flow_b = true;
        return;
    }

    if (packet_key == flow_b.key) {
        append_packet(flow_b, packet_key, packet);
        return;
    }

    // Unexpected third direction for this connection. Ignore for now.
}

void ConnectionV4::apply_hints(const FlowHintUpdate& hints) {
    apply_hints_to_connection(*this, hints);
}

void ConnectionV6::add_packet(const FlowKeyV6& packet_key, const PacketRef& packet) {
    ++packet_count;
    total_bytes += packet.original_length;
    update_fragmentation_stats(*this, packet);

    if (!has_flow_a) {
        append_packet(flow_a, packet_key, packet);
        has_flow_a = true;
        return;
    }

    if (packet_key == flow_a.key) {
        append_packet(flow_a, packet_key, packet);
        return;
    }

    if (!has_flow_b) {
        append_packet(flow_b, packet_key, packet);
        has_flow_b = true;
        return;
    }

    if (packet_key == flow_b.key) {
        append_packet(flow_b, packet_key, packet);
        return;
    }

    // Unexpected third direction for this connection. Ignore for now.
}

void ConnectionV6::apply_hints(const FlowHintUpdate& hints) {
    apply_hints_to_connection(*this, hints);
}

}  // namespace pfl
