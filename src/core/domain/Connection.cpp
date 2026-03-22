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

}  // namespace

void ConnectionV4::add_packet(const FlowKeyV4& packet_key, const PacketRef& packet) {
    ++packet_count;
    total_bytes += packet.original_length;

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

void ConnectionV6::add_packet(const FlowKeyV6& packet_key, const PacketRef& packet) {
    ++packet_count;
    total_bytes += packet.original_length;

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

}  // namespace pfl
