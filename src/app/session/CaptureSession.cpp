#include "app/session/CaptureSession.h"

#include <algorithm>
#include <iomanip>
#include <sstream>

#include "core/index/CaptureIndex.h"
#include "core/index/CaptureIndexReader.h"
#include "core/index/CaptureIndexWriter.h"
#include "core/io/CaptureFilePacketReader.h"
#include "core/services/CaptureImporter.h"
#include "core/services/FlowExportService.h"
#include "core/services/HexDumpService.h"
#include "core/services/PacketDetailsService.h"

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

FlowRow make_flow_row(std::size_t index, const ListedConnectionRef& connection) {
    if (connection.family == FlowAddressFamily::ipv4) {
        return FlowRow {
            .index = index,
            .family = FlowAddressFamily::ipv4,
            .key = connection.ipv4->key,
            .packet_count = connection.ipv4->packet_count,
            .total_bytes = connection.ipv4->total_bytes,
        };
    }

    return FlowRow {
        .index = index,
        .family = FlowAddressFamily::ipv6,
        .key = connection.ipv6->key,
        .packet_count = connection.ipv6->packet_count,
        .total_bytes = connection.ipv6->total_bytes,
    };
}

std::string format_packet_timestamp(const PacketRef& packet) {
    const auto seconds_of_day = packet.ts_sec % 86400U;
    const auto hours = seconds_of_day / 3600U;
    const auto minutes = (seconds_of_day % 3600U) / 60U;
    const auto seconds = seconds_of_day % 60U;

    std::ostringstream timestamp {};
    timestamp << std::setfill('0')
              << std::setw(2) << hours << ':'
              << std::setw(2) << minutes << ':'
              << std::setw(2) << seconds << '.'
              << std::setw(6) << packet.ts_usec;
    return timestamp.str();
}

PacketRow make_packet_row(const PacketRef& packet) {
    return PacketRow {
        .packet_index = packet.packet_index,
        .timestamp_text = format_packet_timestamp(packet),
        .captured_length = packet.captured_length,
        .original_length = packet.original_length,
    };
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

}  // namespace

bool CaptureSession::open_capture(const std::filesystem::path& path) {
    CaptureImporter importer {};
    CaptureState imported_state {};

    if (!importer.import_capture(path, imported_state)) {
        capture_path_.clear();
        state_ = {};
        return false;
    }

    capture_path_ = path;
    state_ = imported_state;
    return true;
}

bool CaptureSession::open_input(const std::filesystem::path& path) {
    if (looks_like_index_file(path)) {
        return load_index(path);
    }

    return open_capture(path);
}

bool CaptureSession::save_index(const std::filesystem::path& index_path) const {
    if (!has_capture()) {
        return false;
    }

    CaptureIndexWriter writer {};
    return writer.write(index_path, state_, capture_path_);
}

bool CaptureSession::load_index(const std::filesystem::path& index_path) {
    CaptureIndexReader reader {};
    CaptureState loaded_state {};
    std::filesystem::path loaded_capture_path {};

    if (!reader.read(index_path, loaded_state, loaded_capture_path)) {
        capture_path_.clear();
        state_ = {};
        return false;
    }

    capture_path_ = loaded_capture_path;
    state_ = loaded_state;
    return true;
}

bool CaptureSession::has_capture() const noexcept {
    return !capture_path_.empty();
}

const std::filesystem::path& CaptureSession::capture_path() const noexcept {
    return capture_path_;
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

std::vector<FlowRow> CaptureSession::list_flows() const {
    const auto connections = list_connections(state_);
    std::vector<FlowRow> rows {};
    rows.reserve(connections.size());

    for (std::size_t index = 0; index < connections.size(); ++index) {
        rows.push_back(make_flow_row(index, connections[index]));
    }

    return rows;
}

std::vector<PacketRow> CaptureSession::list_flow_packets(const std::size_t flow_index) const {
    const auto packets = flow_packets(flow_index);
    if (!packets.has_value()) {
        return {};
    }

    std::vector<PacketRow> rows {};
    rows.reserve(packets->size());

    for (const auto& packet : *packets) {
        rows.push_back(make_packet_row(packet));
    }

    return rows;
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
    if (!has_capture()) {
        return false;
    }

    const auto packets = flow_packets(flow_index);
    if (!packets.has_value()) {
        return false;
    }

    FlowExportService service {};
    return service.export_packets_to_pcap(output_path, *packets, capture_path_);
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
