#include "core/index/CaptureIndexWriter.h"

#include <algorithm>
#include <array>
#include <fstream>
#include <limits>
#include <span>
#include <string>
#include <vector>

#include "core/index/CaptureIndex.h"

namespace pfl {

namespace {

bool write_bytes(std::ofstream& stream, std::span<const std::uint8_t> bytes) {
    stream.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    return static_cast<bool>(stream);
}

bool write_u8(std::ofstream& stream, std::uint8_t value) {
    const auto byte = std::array<std::uint8_t, 1> {value};
    return write_bytes(stream, byte);
}

bool write_u16(std::ofstream& stream, std::uint16_t value) {
    const auto bytes = std::array<std::uint8_t, 2> {
        static_cast<std::uint8_t>(value & 0x00FFU),
        static_cast<std::uint8_t>((value >> 8U) & 0x00FFU),
    };
    return write_bytes(stream, bytes);
}

bool write_u32(std::ofstream& stream, std::uint32_t value) {
    const auto bytes = std::array<std::uint8_t, 4> {
        static_cast<std::uint8_t>(value & 0x000000FFU),
        static_cast<std::uint8_t>((value >> 8U) & 0x000000FFU),
        static_cast<std::uint8_t>((value >> 16U) & 0x000000FFU),
        static_cast<std::uint8_t>((value >> 24U) & 0x000000FFU),
    };
    return write_bytes(stream, bytes);
}

bool write_u64(std::ofstream& stream, std::uint64_t value) {
    const auto bytes = std::array<std::uint8_t, 8> {
        static_cast<std::uint8_t>(value & 0x00000000000000FFULL),
        static_cast<std::uint8_t>((value >> 8U) & 0x00000000000000FFULL),
        static_cast<std::uint8_t>((value >> 16U) & 0x00000000000000FFULL),
        static_cast<std::uint8_t>((value >> 24U) & 0x00000000000000FFULL),
        static_cast<std::uint8_t>((value >> 32U) & 0x00000000000000FFULL),
        static_cast<std::uint8_t>((value >> 40U) & 0x00000000000000FFULL),
        static_cast<std::uint8_t>((value >> 48U) & 0x00000000000000FFULL),
        static_cast<std::uint8_t>((value >> 56U) & 0x00000000000000FFULL),
    };
    return write_bytes(stream, bytes);
}

bool write_i64(std::ofstream& stream, std::int64_t value) {
    return write_u64(stream, static_cast<std::uint64_t>(value));
}

bool write_string(std::ofstream& stream, const std::string& value) {
    if (value.size() > static_cast<std::size_t>(std::numeric_limits<std::uint32_t>::max())) {
        return false;
    }

    if (!write_u32(stream, static_cast<std::uint32_t>(value.size()))) {
        return false;
    }

    if (value.empty()) {
        return true;
    }

    const auto bytes = std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(value.data()), value.size());
    return write_bytes(stream, bytes);
}

bool write_capture_summary(std::ofstream& stream, const CaptureSummary& summary) {
    return write_u64(stream, summary.packet_count) &&
           write_u64(stream, summary.flow_count) &&
           write_u64(stream, summary.total_bytes);
}

bool write_packet_ref(std::ofstream& stream, const PacketRef& packet) {
    return write_u64(stream, packet.packet_index) &&
           write_u32(stream, packet.ts_sec) &&
           write_u32(stream, packet.ts_usec) &&
           write_u64(stream, packet.byte_offset) &&
           write_u32(stream, packet.captured_length) &&
           write_u32(stream, packet.original_length);
}

bool write_endpoint_key(std::ofstream& stream, const EndpointKeyV4& endpoint) {
    return write_u32(stream, endpoint.addr) && write_u16(stream, endpoint.port);
}

bool write_endpoint_key(std::ofstream& stream, const EndpointKeyV6& endpoint) {
    const auto address = std::span<const std::uint8_t>(endpoint.addr.data(), endpoint.addr.size());
    return write_bytes(stream, address) && write_u16(stream, endpoint.port);
}

bool write_flow_key(std::ofstream& stream, const FlowKeyV4& key) {
    return write_u32(stream, key.src_addr) &&
           write_u32(stream, key.dst_addr) &&
           write_u16(stream, key.src_port) &&
           write_u16(stream, key.dst_port) &&
           write_u8(stream, static_cast<std::uint8_t>(key.protocol));
}

bool write_flow_key(std::ofstream& stream, const FlowKeyV6& key) {
    const auto source = std::span<const std::uint8_t>(key.src_addr.data(), key.src_addr.size());
    const auto destination = std::span<const std::uint8_t>(key.dst_addr.data(), key.dst_addr.size());
    return write_bytes(stream, source) &&
           write_bytes(stream, destination) &&
           write_u16(stream, key.src_port) &&
           write_u16(stream, key.dst_port) &&
           write_u8(stream, static_cast<std::uint8_t>(key.protocol));
}

bool write_connection_key(std::ofstream& stream, const ConnectionKeyV4& key) {
    return write_endpoint_key(stream, key.first) &&
           write_endpoint_key(stream, key.second) &&
           write_u8(stream, static_cast<std::uint8_t>(key.protocol));
}

bool write_connection_key(std::ofstream& stream, const ConnectionKeyV6& key) {
    return write_endpoint_key(stream, key.first) &&
           write_endpoint_key(stream, key.second) &&
           write_u8(stream, static_cast<std::uint8_t>(key.protocol));
}

bool write_flow(std::ofstream& stream, const FlowV4& flow) {
    if (!write_flow_key(stream, flow.key) ||
        !write_u64(stream, flow.packet_count) ||
        !write_u64(stream, flow.total_bytes) ||
        !write_u64(stream, static_cast<std::uint64_t>(flow.packets.size()))) {
        return false;
    }

    for (const auto& packet : flow.packets) {
        if (!write_packet_ref(stream, packet)) {
            return false;
        }
    }

    return true;
}

bool write_flow(std::ofstream& stream, const FlowV6& flow) {
    if (!write_flow_key(stream, flow.key) ||
        !write_u64(stream, flow.packet_count) ||
        !write_u64(stream, flow.total_bytes) ||
        !write_u64(stream, static_cast<std::uint64_t>(flow.packets.size()))) {
        return false;
    }

    for (const auto& packet : flow.packets) {
        if (!write_packet_ref(stream, packet)) {
            return false;
        }
    }

    return true;
}

bool write_connection(std::ofstream& stream, const ConnectionV4& connection) {
    if (!write_connection_key(stream, connection.key) ||
        !write_u8(stream, connection.has_flow_a ? 1U : 0U) ||
        !write_u8(stream, connection.has_flow_b ? 1U : 0U) ||
        !write_u64(stream, connection.packet_count) ||
        !write_u64(stream, connection.total_bytes)) {
        return false;
    }

    if (connection.has_flow_a && !write_flow(stream, connection.flow_a)) {
        return false;
    }

    if (connection.has_flow_b && !write_flow(stream, connection.flow_b)) {
        return false;
    }

    return true;
}

bool write_connection(std::ofstream& stream, const ConnectionV6& connection) {
    if (!write_connection_key(stream, connection.key) ||
        !write_u8(stream, connection.has_flow_a ? 1U : 0U) ||
        !write_u8(stream, connection.has_flow_b ? 1U : 0U) ||
        !write_u64(stream, connection.packet_count) ||
        !write_u64(stream, connection.total_bytes)) {
        return false;
    }

    if (connection.has_flow_a && !write_flow(stream, connection.flow_a)) {
        return false;
    }

    if (connection.has_flow_b && !write_flow(stream, connection.flow_b)) {
        return false;
    }

    return true;
}

std::vector<const ConnectionV4*> sorted_connections(const ConnectionTableV4& table) {
    auto connections = table.list();
    std::sort(connections.begin(), connections.end(), [](const ConnectionV4* left, const ConnectionV4* right) {
        return left->key < right->key;
    });
    return connections;
}

std::vector<const ConnectionV6*> sorted_connections(const ConnectionTableV6& table) {
    auto connections = table.list();
    std::sort(connections.begin(), connections.end(), [](const ConnectionV6* left, const ConnectionV6* right) {
        return left->key < right->key;
    });
    return connections;
}

}  // namespace

bool CaptureIndexWriter::write(const std::filesystem::path& index_path,
                               const CaptureState& state,
                               const std::filesystem::path& source_capture_path) const {
    CaptureSourceInfo source_info {};
    if (!read_capture_source_info(source_capture_path, source_info)) {
        return false;
    }

    std::ofstream stream(index_path, std::ios::binary | std::ios::trunc);
    if (!stream.is_open()) {
        return false;
    }

    if (!write_u64(stream, kCaptureIndexMagic) ||
        !write_u16(stream, kCaptureIndexVersion) ||
        !write_u16(stream, 0U) ||
        !write_string(stream, source_info.capture_path.generic_string()) ||
        !write_u8(stream, static_cast<std::uint8_t>(source_info.format)) ||
        !write_u64(stream, source_info.file_size) ||
        !write_i64(stream, source_info.last_write_time) ||
        !write_capture_summary(stream, state.summary)) {
        return false;
    }

    const auto ipv4_connections = sorted_connections(state.ipv4_connections);
    const auto ipv6_connections = sorted_connections(state.ipv6_connections);

    if (!write_u64(stream, static_cast<std::uint64_t>(ipv4_connections.size())) ||
        !write_u64(stream, static_cast<std::uint64_t>(ipv6_connections.size()))) {
        return false;
    }

    for (const auto* connection : ipv4_connections) {
        if (!write_connection(stream, *connection)) {
            return false;
        }
    }

    for (const auto* connection : ipv6_connections) {
        if (!write_connection(stream, *connection)) {
            return false;
        }
    }

    stream.flush();
    return static_cast<bool>(stream);
}

}  // namespace pfl



