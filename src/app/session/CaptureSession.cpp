#include "app/session/CaptureSession.h"

#include "core/io/CaptureFilePacketReader.h"
#include "core/services/CaptureImporter.h"
#include "core/services/HexDumpService.h"
#include "core/services/PacketDetailsService.h"

namespace pfl {

bool CaptureSession::open_capture(const std::filesystem::path& path) {
    CaptureImporter importer {};
    CaptureState imported_state {};

    if (!importer.import_pcap(path, imported_state)) {
        capture_path_.clear();
        state_ = {};
        return false;
    }

    capture_path_ = path;
    state_ = imported_state;
    return true;
}

bool CaptureSession::has_capture() const noexcept {
    return !capture_path_.empty();
}

const CaptureSummary& CaptureSession::summary() const noexcept {
    return state_.summary;
}

std::vector<std::uint8_t> CaptureSession::read_packet_data(const PacketRef& packet) const {
    if (!has_capture()) {
        return {};
    }

    CaptureFilePacketReader reader {capture_path_};
    if (!reader.is_open()) {
        return {};
    }

    return reader.read_packet_data(packet);
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

std::vector<FlowRowV4> CaptureSession::list_ipv4_flows() const {
    std::vector<FlowRowV4> rows {};
    const auto connections = state_.ipv4_connections.list();
    rows.reserve(connections.size());

    for (const auto* connection : connections) {
        rows.push_back(FlowRowV4 {
            .key = connection->key,
            .packet_count = connection->packet_count,
            .total_bytes = connection->total_bytes,
        });
    }

    return rows;
}

std::vector<FlowRowV6> CaptureSession::list_ipv6_flows() const {
    std::vector<FlowRowV6> rows {};
    const auto connections = state_.ipv6_connections.list();
    rows.reserve(connections.size());

    for (const auto* connection : connections) {
        rows.push_back(FlowRowV6 {
            .key = connection->key,
            .packet_count = connection->packet_count,
            .total_bytes = connection->total_bytes,
        });
    }

    return rows;
}

std::optional<PacketRef> CaptureSession::find_packet(std::uint64_t packet_index) const {
    for (const auto* connection : state_.ipv4_connections.list()) {
        for (const auto& packet : connection->flow_a.packets) {
            if (packet.packet_index == packet_index) {
                return packet;
            }
        }

        for (const auto& packet : connection->flow_b.packets) {
            if (packet.packet_index == packet_index) {
                return packet;
            }
        }
    }

    for (const auto* connection : state_.ipv6_connections.list()) {
        for (const auto& packet : connection->flow_a.packets) {
            if (packet.packet_index == packet_index) {
                return packet;
            }
        }

        for (const auto& packet : connection->flow_b.packets) {
            if (packet.packet_index == packet_index) {
                return packet;
            }
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
