#include "core/services/PacketIngestor.h"

namespace pfl {

PacketIngestor::PacketIngestor(CaptureState& state) noexcept
    : state_(state) {}

void PacketIngestor::ingest(const IngestedPacketV4& packet) {
    const auto connection_key = make_connection_key(packet.flow_key);
    auto& connection = state_.ipv4_connections.get_or_create(connection_key);
    connection.add_packet(packet.flow_key, packet.packet_ref);

    ++state_.summary.packet_count;
    state_.summary.total_bytes += packet.packet_ref.original_length;
    state_.summary.flow_count = static_cast<std::uint64_t>(state_.ipv4_connections.size() + state_.ipv6_connections.size());
}

void PacketIngestor::ingest(const IngestedPacketV6& packet) {
    const auto connection_key = make_connection_key(packet.flow_key);
    auto& connection = state_.ipv6_connections.get_or_create(connection_key);
    connection.add_packet(packet.flow_key, packet.packet_ref);

    ++state_.summary.packet_count;
    state_.summary.total_bytes += packet.packet_ref.original_length;
    state_.summary.flow_count = static_cast<std::uint64_t>(state_.ipv4_connections.size() + state_.ipv6_connections.size());
}

}  // namespace pfl
