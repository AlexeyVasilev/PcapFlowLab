#include "core/domain/Connection.h"

#include "core/domain/IpFragmentation.h"

namespace pfl {

namespace {

[[nodiscard]] bool is_transport_hint_protocol(const ProtocolId protocol) noexcept {
    return protocol == ProtocolId::tcp || protocol == ProtocolId::udp;
}

[[nodiscard]] std::uint8_t encode_pending_tls_client_hello_state(
    const ConnectionFlowSlot slot,
    const std::uint8_t remaining_budget
) noexcept {
    if (remaining_budget == 0U || remaining_budget > kMaxPendingTlsClientHelloSameDirectionPacketBudget) {
        return 0U;
    }
    switch (slot) {
    case ConnectionFlowSlot::flow_a:
        return remaining_budget;
    case ConnectionFlowSlot::flow_b:
        return static_cast<std::uint8_t>(
            kMaxPendingTlsClientHelloSameDirectionPacketBudget + remaining_budget
        );
    case ConnectionFlowSlot::none:
        return 0U;
    }
    return 0U;
}

[[nodiscard]] bool is_payload_bearing_transport_packet(
    const PacketImportMetadata& metadata,
    const ProtocolId protocol
) noexcept {
    return is_transport_hint_protocol(protocol) && metadata.transport_payload_length.value_or(0U) > 0U;
}

[[nodiscard]] std::uint64_t packet_timestamp_us(const PacketRef& packet) noexcept {
    return static_cast<std::uint64_t>(packet.ts_sec) * 1000000ULL +
           static_cast<std::uint64_t>(packet.ts_usec);
}

template <typename Connection>
void update_aggregate_stats(Connection& connection,
                            const PacketRef& packet,
                            const PacketImportMetadata& metadata,
                            const ProtocolId protocol,
                            const bool was_empty) noexcept {
    const auto timestamp_us = packet_timestamp_us(packet);
    if (was_empty) {
        connection.aggregate_stats.first_timestamp_us = timestamp_us;
        connection.aggregate_stats.last_timestamp_us = timestamp_us;
    } else {
        if (timestamp_us < connection.aggregate_stats.first_timestamp_us) {
            connection.aggregate_stats.first_timestamp_us = timestamp_us;
        }
        if (timestamp_us > connection.aggregate_stats.last_timestamp_us) {
            connection.aggregate_stats.last_timestamp_us = timestamp_us;
        }
    }

    connection.aggregate_stats.captured_bytes += packet.captured_length;

    if (packet.captured_length < packet.original_length) {
        ++connection.aggregate_stats.truncated_packet_count;
    }

    if (packet.original_length > connection.aggregate_stats.max_original_packet_length) {
        connection.aggregate_stats.max_original_packet_length = packet.original_length;
    }

    if (packet.captured_length > connection.aggregate_stats.max_captured_packet_length) {
        connection.aggregate_stats.max_captured_packet_length = packet.captured_length;
    }

    if (protocol != ProtocolId::tcp) {
        return;
    }

    const auto tcp_flags = metadata.tcp_flags.value_or(0U);
    if ((tcp_flags & 0x02U) != 0U) {
        ++connection.aggregate_stats.tcp_syn_count;
    }
    if ((tcp_flags & 0x01U) != 0U) {
        ++connection.aggregate_stats.tcp_fin_count;
    }
    if ((tcp_flags & 0x04U) != 0U) {
        ++connection.aggregate_stats.tcp_rst_count;
    }
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
    case FlowProtocolHint::mqtt:
    case FlowProtocolHint::amqp:
    case FlowProtocolHint::ntp:
        return true;
    default:
        return false;
    }
}

template <typename Connection>
[[nodiscard]] bool should_attempt_hint_detection_for_connection(const Connection& connection,
                                                                const PacketImportMetadata& metadata,
                                                                const ProtocolId protocol) noexcept {
    if (hint_detection_settled_for_connection(connection)) {
        return false;
    }

    if (!is_transport_hint_protocol(protocol)) {
        return true;
    }

    if (!is_payload_bearing_transport_packet(metadata, protocol)) {
        return false;
    }

    return !connection.hint_search_state.unresolved_payload_attempt_budget_exhausted;
}

template <typename Connection>
void note_hint_detection_attempt_for_connection(Connection& connection,
                                                const PacketImportMetadata& metadata,
                                                const ProtocolId protocol) noexcept {
    if (!is_payload_bearing_transport_packet(metadata, protocol)) {
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
void update_fragmentation_stats(Connection& connection, const PacketImportMetadata& metadata) {
    if (!is_real_ip_fragment(metadata.ip_fragmentation_kind)) {
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

bool has_pending_tls_client_hello(const ConnectionHintSearchState& state) noexcept {
    return pending_tls_client_hello_remaining_budget(state) > 0U;
}

ConnectionFlowSlot pending_tls_client_hello_flow_slot(const ConnectionHintSearchState& state) noexcept {
    if (state.pending_tls_client_hello_state >= 1U &&
        state.pending_tls_client_hello_state <= kMaxPendingTlsClientHelloSameDirectionPacketBudget) {
        return ConnectionFlowSlot::flow_a;
    }
    if (state.pending_tls_client_hello_state > kMaxPendingTlsClientHelloSameDirectionPacketBudget &&
        state.pending_tls_client_hello_state <=
            static_cast<std::uint8_t>(kMaxPendingTlsClientHelloSameDirectionPacketBudget * 2U)) {
        return ConnectionFlowSlot::flow_b;
    }
    return ConnectionFlowSlot::none;
}

std::uint8_t pending_tls_client_hello_remaining_budget(const ConnectionHintSearchState& state) noexcept {
    if (state.pending_tls_client_hello_state >= 1U &&
        state.pending_tls_client_hello_state <= kMaxPendingTlsClientHelloSameDirectionPacketBudget) {
        return state.pending_tls_client_hello_state;
    }
    if (state.pending_tls_client_hello_state > kMaxPendingTlsClientHelloSameDirectionPacketBudget &&
        state.pending_tls_client_hello_state <=
            static_cast<std::uint8_t>(kMaxPendingTlsClientHelloSameDirectionPacketBudget * 2U)) {
        return static_cast<std::uint8_t>(
            state.pending_tls_client_hello_state - kMaxPendingTlsClientHelloSameDirectionPacketBudget
        );
    }
    return 0U;
}

void set_pending_tls_client_hello(ConnectionHintSearchState& state, const ConnectionFlowSlot slot) noexcept {
    state.pending_tls_client_hello_state = encode_pending_tls_client_hello_state(
        slot,
        kMaxPendingTlsClientHelloSameDirectionPacketBudget
    );
}

bool decrement_pending_tls_client_hello_budget(ConnectionHintSearchState& state) noexcept {
    const auto remaining_budget = pending_tls_client_hello_remaining_budget(state);
    if (remaining_budget == 0U) {
        return false;
    }
    if (remaining_budget == 1U) {
        clear_pending_tls_client_hello(state);
        return true;
    }

    state.pending_tls_client_hello_state = encode_pending_tls_client_hello_state(
        pending_tls_client_hello_flow_slot(state),
        static_cast<std::uint8_t>(remaining_budget - 1U)
    );
    return false;
}

void clear_pending_tls_client_hello(ConnectionHintSearchState& state) noexcept {
    state.pending_tls_client_hello_state = 0U;
}

ConnectionFlowSlot connection_flow_slot(const ConnectionV4& connection, const FlowKeyV4& key) noexcept {
    if (connection.has_flow_a && connection.flow_a.key == key) {
        return ConnectionFlowSlot::flow_a;
    }
    if (connection.has_flow_b && connection.flow_b.key == key) {
        return ConnectionFlowSlot::flow_b;
    }
    return ConnectionFlowSlot::none;
}

ConnectionFlowSlot connection_flow_slot(const ConnectionV6& connection, const FlowKeyV6& key) noexcept {
    if (connection.has_flow_a && connection.flow_a.key == key) {
        return ConnectionFlowSlot::flow_a;
    }
    if (connection.has_flow_b && connection.flow_b.key == key) {
        return ConnectionFlowSlot::flow_b;
    }
    return ConnectionFlowSlot::none;
}

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

void ConnectionV4::add_packet(const FlowKeyV4& packet_key, const PacketRef& packet, const PacketImportMetadata& metadata) {
    const bool was_empty = packet_count == 0U;
    ++packet_count;
    total_bytes += packet.original_length;
    update_aggregate_stats(*this, packet, metadata, packet_key.protocol, was_empty);
    update_fragmentation_stats(*this, metadata);

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

bool ConnectionV4::should_attempt_hint_detection(const PacketImportMetadata& metadata, const ProtocolId protocol) const noexcept {
    return should_attempt_hint_detection_for_connection(*this, metadata, protocol);
}

void ConnectionV4::note_hint_detection_attempt(const PacketImportMetadata& metadata, const ProtocolId protocol) noexcept {
    note_hint_detection_attempt_for_connection(*this, metadata, protocol);
}

void ConnectionV6::add_packet(const FlowKeyV6& packet_key, const PacketRef& packet, const PacketImportMetadata& metadata) {
    const bool was_empty = packet_count == 0U;
    ++packet_count;
    total_bytes += packet.original_length;
    update_aggregate_stats(*this, packet, metadata, packet_key.protocol, was_empty);
    update_fragmentation_stats(*this, metadata);

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

bool ConnectionV6::should_attempt_hint_detection(const PacketImportMetadata& metadata, const ProtocolId protocol) const noexcept {
    return should_attempt_hint_detection_for_connection(*this, metadata, protocol);
}

void ConnectionV6::note_hint_detection_attempt(const PacketImportMetadata& metadata, const ProtocolId protocol) noexcept {
    note_hint_detection_attempt_for_connection(*this, metadata, protocol);
}

}  // namespace pfl

