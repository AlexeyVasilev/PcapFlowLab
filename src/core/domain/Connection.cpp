#include "core/domain/Connection.h"

namespace pfl {

namespace {

[[nodiscard]] bool is_transport_hint_protocol(const ProtocolId protocol) noexcept {
    return protocol == ProtocolId::tcp || protocol == ProtocolId::udp;
}

[[nodiscard]] bool is_payload_bearing_transport_packet(const PacketRef& packet, const ProtocolId protocol) noexcept {
    return is_transport_hint_protocol(protocol) && packet.payload_length > 0U;
}

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

[[nodiscard]] EndpointKeyV4 endpoint_a_for_flow_key(const FlowKeyV4& key) noexcept {
    return EndpointKeyV4 {
        .addr = key.src_addr,
        .port = key.src_port,
    };
}

[[nodiscard]] EndpointKeyV4 endpoint_b_for_flow_key(const FlowKeyV4& key) noexcept {
    return EndpointKeyV4 {
        .addr = key.dst_addr,
        .port = key.dst_port,
    };
}

[[nodiscard]] EndpointKeyV6 endpoint_a_for_flow_key(const FlowKeyV6& key) noexcept {
    return EndpointKeyV6 {
        .addr = key.src_addr,
        .port = key.src_port,
    };
}

[[nodiscard]] EndpointKeyV6 endpoint_b_for_flow_key(const FlowKeyV6& key) noexcept {
    return EndpointKeyV6 {
        .addr = key.dst_addr,
        .port = key.dst_port,
    };
}

template <typename Connection>
void apply_hints_to_connection(Connection& connection, const FlowHintUpdate& hints) {
    if (connection.protocol_hint == FlowProtocolHint::unknown && hints.protocol_hint != FlowProtocolHint::unknown) {
        connection.protocol_hint = hints.protocol_hint;
    }

    if (connection.service_hint.empty() && !hints.service_hint.empty()) {
        connection.service_hint = hints.service_hint;
    }

    if (connection.quic_version == QuicVersionHint::unknown && hints.quic_version != QuicVersionHint::unknown) {
        connection.quic_version = hints.quic_version;
    }

    if (connection.tls_version == TlsVersionHint::unknown && hints.tls_version != TlsVersionHint::unknown) {
        connection.tls_version = hints.tls_version;
    }
}

template <typename Connection>
[[nodiscard]] bool hint_detection_settled_for_connection(const Connection& connection) noexcept {
    if (!connection.service_hint.empty()) {
        return true;
    }

    switch (connection.protocol_hint) {
    case FlowProtocolHint::ssh:
    case FlowProtocolHint::stun:
    case FlowProtocolHint::bittorrent:
    case FlowProtocolHint::dhcp:
    case FlowProtocolHint::mdns:
    case FlowProtocolHint::smtp:
    case FlowProtocolHint::pop3:
    case FlowProtocolHint::imap:
    case FlowProtocolHint::igmp:
    case FlowProtocolHint::igmpv1:
    case FlowProtocolHint::igmpv2:
    case FlowProtocolHint::igmpv3:
        return true;
    default:
        return false;
    }
}

template <typename Connection>
[[nodiscard]] bool should_attempt_hint_detection_for_connection(const Connection& connection,
                                                                const PacketRef& packet,
                                                                const ProtocolId protocol) noexcept {
    if (hint_detection_settled_for_connection(connection)) {
        return false;
    }

    if (!is_transport_hint_protocol(protocol)) {
        return true;
    }

    if (!is_payload_bearing_transport_packet(packet, protocol)) {
        return false;
    }

    return !connection.hint_search_state.unresolved_payload_attempt_budget_exhausted;
}

template <typename Connection>
void note_hint_detection_attempt_for_connection(Connection& connection,
                                                const PacketRef& packet,
                                                const ProtocolId protocol) noexcept {
    if (!is_payload_bearing_transport_packet(packet, protocol)) {
        return;
    }

    if (hint_detection_settled_for_connection(connection) ||
        connection.hint_search_state.unresolved_payload_attempt_budget_exhausted) {
        return;
    }

    if (connection.hint_search_state.unresolved_payload_attempt_count <
        kMaxUnresolvedHintPayloadAttemptsPerConnection) {
        ++connection.hint_search_state.unresolved_payload_attempt_count;
    }

    if (connection.hint_search_state.unresolved_payload_attempt_count >=
        kMaxUnresolvedHintPayloadAttemptsPerConnection) {
        connection.hint_search_state.unresolved_payload_attempt_budget_exhausted = true;
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

template <typename Connection>
[[nodiscard]] bool has_valid_first_observed_orientation_for_connection(const Connection& connection) noexcept {
    if (!connection.has_flow_a) {
        return connection.packet_count == 0U &&
            connection.total_bytes == 0U &&
            !connection.has_flow_b &&
            connection.flow_a.packet_count == 0U &&
            connection.flow_a.total_bytes == 0U &&
            connection.flow_a.packets.empty() &&
            connection.flow_b.packet_count == 0U &&
            connection.flow_b.total_bytes == 0U &&
            connection.flow_b.packets.empty();
    }

    if (connection.flow_a.packets.empty() ||
        connection.flow_a.packets.size() != connection.flow_a.packet_count ||
        connection.flow_a.packet_count == 0U ||
        make_connection_key(connection.flow_a.key) != connection.key) {
        return false;
    }

    if (!connection.has_flow_b) {
        return connection.flow_b.packet_count == 0U &&
            connection.flow_b.total_bytes == 0U &&
            connection.flow_b.packets.empty() &&
            connection.packet_count == connection.flow_a.packet_count &&
            connection.total_bytes == connection.flow_a.total_bytes;
    }

    return !connection.flow_b.packets.empty() &&
        connection.flow_b.packets.size() == connection.flow_b.packet_count &&
        connection.flow_b.packet_count > 0U &&
        connection.flow_b.key != connection.flow_a.key &&
        make_connection_key(connection.flow_b.key) == connection.key &&
        connection.packet_count == connection.flow_a.packet_count + connection.flow_b.packet_count &&
        connection.total_bytes == connection.flow_a.total_bytes + connection.flow_b.total_bytes;
}

}  // namespace

std::optional<FlowKeyV4> first_observed_flow_key(const ConnectionV4& connection) noexcept {
    if (!connection.has_flow_a) {
        return std::nullopt;
    }
    return connection.flow_a.key;
}

std::optional<FlowKeyV6> first_observed_flow_key(const ConnectionV6& connection) noexcept {
    if (!connection.has_flow_a) {
        return std::nullopt;
    }
    return connection.flow_a.key;
}

std::optional<EndpointKeyV4> first_observed_endpoint_a(const ConnectionV4& connection) noexcept {
    const auto key = first_observed_flow_key(connection);
    if (!key.has_value()) {
        return std::nullopt;
    }
    return endpoint_a_for_flow_key(*key);
}

std::optional<EndpointKeyV4> first_observed_endpoint_b(const ConnectionV4& connection) noexcept {
    const auto key = first_observed_flow_key(connection);
    if (!key.has_value()) {
        return std::nullopt;
    }
    return endpoint_b_for_flow_key(*key);
}

std::optional<EndpointKeyV6> first_observed_endpoint_a(const ConnectionV6& connection) noexcept {
    const auto key = first_observed_flow_key(connection);
    if (!key.has_value()) {
        return std::nullopt;
    }
    return endpoint_a_for_flow_key(*key);
}

std::optional<EndpointKeyV6> first_observed_endpoint_b(const ConnectionV6& connection) noexcept {
    const auto key = first_observed_flow_key(connection);
    if (!key.has_value()) {
        return std::nullopt;
    }
    return endpoint_b_for_flow_key(*key);
}

bool has_valid_first_observed_orientation(const ConnectionV4& connection) noexcept {
    return has_valid_first_observed_orientation_for_connection(connection);
}

bool has_valid_first_observed_orientation(const ConnectionV6& connection) noexcept {
    return has_valid_first_observed_orientation_for_connection(connection);
}

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

bool ConnectionV4::hint_detection_settled() const noexcept {
    return hint_detection_settled_for_connection(*this);
}

bool ConnectionV4::should_attempt_hint_detection(const PacketRef& packet, const ProtocolId protocol) const noexcept {
    return should_attempt_hint_detection_for_connection(*this, packet, protocol);
}

void ConnectionV4::note_hint_detection_attempt(const PacketRef& packet, const ProtocolId protocol) noexcept {
    note_hint_detection_attempt_for_connection(*this, packet, protocol);
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

bool ConnectionV6::hint_detection_settled() const noexcept {
    return hint_detection_settled_for_connection(*this);
}

bool ConnectionV6::should_attempt_hint_detection(const PacketRef& packet, const ProtocolId protocol) const noexcept {
    return should_attempt_hint_detection_for_connection(*this, packet, protocol);
}

void ConnectionV6::note_hint_detection_attempt(const PacketRef& packet, const ProtocolId protocol) noexcept {
    note_hint_detection_attempt_for_connection(*this, packet, protocol);
}

}  // namespace pfl

