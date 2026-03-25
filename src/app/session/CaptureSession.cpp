#include "app/session/CaptureSession.h"

#include <algorithm>
#include <array>
#include <iomanip>
#include <map>
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

std::string format_ipv4_address(std::uint32_t address);
std::string format_ipv6_address(const std::array<std::uint8_t, 16>& address);
std::string format_endpoint(const EndpointKeyV4& endpoint);
std::string format_endpoint(const EndpointKeyV6& endpoint);

std::uint64_t packet_count(const ListedConnectionRef& connection) noexcept {
    return (connection.family == FlowAddressFamily::ipv4) ? connection.ipv4->packet_count : connection.ipv6->packet_count;
}

std::uint64_t total_bytes(const ListedConnectionRef& connection) noexcept {
    return (connection.family == FlowAddressFamily::ipv4) ? connection.ipv4->total_bytes : connection.ipv6->total_bytes;
}

ProtocolId protocol_id(const ListedConnectionRef& connection) noexcept {
    return (connection.family == FlowAddressFamily::ipv4) ? connection.ipv4->key.protocol : connection.ipv6->key.protocol;
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

FlowRow make_flow_row(std::size_t index, const ListedConnectionRef& connection) {
    if (connection.family == FlowAddressFamily::ipv4) {
        const auto& key = connection.ipv4->key;
        return FlowRow {
            .index = index,
            .family = FlowAddressFamily::ipv4,
            .key = key,
            .protocol_text = protocol_text(key.protocol),
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

std::string format_tcp_flags_text(const std::uint8_t flags) {
    struct FlagName {
        std::uint8_t mask;
        const char* name;
    };

    constexpr FlagName names[] {
        {0x80U, "CWR"},
        {0x40U, "ECE"},
        {0x20U, "URG"},
        {0x10U, "ACK"},
        {0x08U, "PSH"},
        {0x04U, "RST"},
        {0x02U, "SYN"},
        {0x01U, "FIN"},
    };

    std::ostringstream builder {};
    bool first = true;
    for (const auto& flag : names) {
        if ((flags & flag.mask) == 0U) {
            continue;
        }

        if (!first) {
            builder << '|';
        }

        builder << flag.name;
        first = false;
    }

    return first ? std::string {} : builder.str();
}

std::string format_ipv4_address(const std::uint32_t address) {
    std::ostringstream builder {};
    builder << ((address >> 24U) & 0xFFU) << '.'
            << ((address >> 16U) & 0xFFU) << '.'
            << ((address >> 8U) & 0xFFU) << '.'
            << (address & 0xFFU);
    return builder.str();
}

std::string format_ipv6_address(const std::array<std::uint8_t, 16>& address) {
    std::ostringstream builder {};
    builder << std::hex << std::setfill('0');

    for (std::size_t index = 0; index < 8; ++index) {
        if (index > 0) {
            builder << ':';
        }

        const auto word = static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(address[index * 2U]) << 8U) |
            static_cast<std::uint16_t>(address[index * 2U + 1U])
        );
        builder << std::setw(4) << word;
    }

    return builder.str();
}

std::string format_endpoint(const EndpointKeyV4& endpoint) {
    std::ostringstream builder {};
    builder << format_ipv4_address(endpoint.addr) << ':' << endpoint.port;
    return builder.str();
}

std::string format_endpoint(const EndpointKeyV6& endpoint) {
    std::ostringstream builder {};
    builder << '[' << format_ipv6_address(endpoint.addr) << "]:" << endpoint.port;
    return builder.str();
}

PacketRow make_packet_row(const PacketRef& packet) {
    return PacketRow {
        .packet_index = packet.packet_index,
        .timestamp_text = format_packet_timestamp(packet),
        .captured_length = packet.captured_length,
        .original_length = packet.original_length,
        .payload_length = packet.payload_length,
        .tcp_flags_text = format_tcp_flags_text(packet.tcp_flags),
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

CaptureProtocolSummary CaptureSession::protocol_summary() const noexcept {
    CaptureProtocolSummary summary {};

    for (const auto& connection : list_connections(state_)) {
        if (connection.family == FlowAddressFamily::ipv4) {
            add_protocol_stats(summary.ipv4, connection);
        } else {
            add_protocol_stats(summary.ipv6, connection);
        }

        switch (protocol_id(connection)) {
        case ProtocolId::tcp:
            add_protocol_stats(summary.tcp, connection);
            break;
        case ProtocolId::udp:
            add_protocol_stats(summary.udp, connection);
            break;
        default:
            add_protocol_stats(summary.other, connection);
            break;
        }
    }

    return summary;
}

CaptureTopSummary CaptureSession::top_summary(const std::size_t limit) const {
    std::map<std::string, TopEndpointRow> endpoints {};
    std::map<std::uint16_t, TopPortRow> ports {};

    for (const auto& connection : list_connections(state_)) {
        const auto connection_packets = packet_count(connection);
        const auto connection_bytes = total_bytes(connection);

        if (connection.family == FlowAddressFamily::ipv4) {
            const auto& key = connection.ipv4->key;

            for (const auto& endpointText : {format_endpoint(key.first), format_endpoint(key.second)}) {
                auto& row = endpoints[endpointText];
                row.endpoint = endpointText;
                row.packet_count += connection_packets;
                row.total_bytes += connection_bytes;
            }

            for (const auto port : {key.first.port, key.second.port}) {
                if (port == 0U) {
                    continue;
                }

                auto& row = ports[port];
                row.port = port;
                row.packet_count += connection_packets;
                row.total_bytes += connection_bytes;
            }
        } else {
            const auto& key = connection.ipv6->key;

            for (const auto& endpointText : {format_endpoint(key.first), format_endpoint(key.second)}) {
                auto& row = endpoints[endpointText];
                row.endpoint = endpointText;
                row.packet_count += connection_packets;
                row.total_bytes += connection_bytes;
            }

            for (const auto port : {key.first.port, key.second.port}) {
                if (port == 0U) {
                    continue;
                }

                auto& row = ports[port];
                row.port = port;
                row.packet_count += connection_packets;
                row.total_bytes += connection_bytes;
            }
        }
    }

    CaptureTopSummary summary {};
    summary.endpoints_by_bytes.reserve(endpoints.size());
    summary.ports_by_bytes.reserve(ports.size());

    for (const auto& [_, row] : endpoints) {
        summary.endpoints_by_bytes.push_back(row);
    }

    for (const auto& [_, row] : ports) {
        summary.ports_by_bytes.push_back(row);
    }

    std::sort(summary.endpoints_by_bytes.begin(), summary.endpoints_by_bytes.end(), [](const TopEndpointRow& left, const TopEndpointRow& right) {
        if (left.total_bytes != right.total_bytes) {
            return left.total_bytes > right.total_bytes;
        }
        if (left.packet_count != right.packet_count) {
            return left.packet_count > right.packet_count;
        }
        return left.endpoint < right.endpoint;
    });

    std::sort(summary.ports_by_bytes.begin(), summary.ports_by_bytes.end(), [](const TopPortRow& left, const TopPortRow& right) {
        if (left.total_bytes != right.total_bytes) {
            return left.total_bytes > right.total_bytes;
        }
        if (left.packet_count != right.packet_count) {
            return left.packet_count > right.packet_count;
        }
        return left.port < right.port;
    });

    if (summary.endpoints_by_bytes.size() > limit) {
        summary.endpoints_by_bytes.resize(limit);
    }

    if (summary.ports_by_bytes.size() > limit) {
        summary.ports_by_bytes.resize(limit);
    }

    return summary;
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



