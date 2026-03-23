#include "core/index/CaptureIndexReader.h"

#include <array>
#include <fstream>
#include <limits>
#include <span>
#include <string>

namespace pfl {

namespace {

bool read_bytes(std::ifstream& stream, std::span<std::uint8_t> bytes) {
    stream.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    return stream.gcount() == static_cast<std::streamsize>(bytes.size());
}

bool read_u8(std::ifstream& stream, std::uint8_t& value) {
    auto bytes = std::array<std::uint8_t, 1> {};
    if (!read_bytes(stream, bytes)) {
        return false;
    }
    value = bytes[0];
    return true;
}

bool read_u16(std::ifstream& stream, std::uint16_t& value) {
    auto bytes = std::array<std::uint8_t, 2> {};
    if (!read_bytes(stream, bytes)) {
        return false;
    }

    value = static_cast<std::uint16_t>(bytes[0]) |
            static_cast<std::uint16_t>(static_cast<std::uint16_t>(bytes[1]) << 8U);
    return true;
}

bool read_u32(std::ifstream& stream, std::uint32_t& value) {
    auto bytes = std::array<std::uint8_t, 4> {};
    if (!read_bytes(stream, bytes)) {
        return false;
    }

    value = static_cast<std::uint32_t>(bytes[0]) |
            (static_cast<std::uint32_t>(bytes[1]) << 8U) |
            (static_cast<std::uint32_t>(bytes[2]) << 16U) |
            (static_cast<std::uint32_t>(bytes[3]) << 24U);
    return true;
}

bool read_u64(std::ifstream& stream, std::uint64_t& value) {
    auto bytes = std::array<std::uint8_t, 8> {};
    if (!read_bytes(stream, bytes)) {
        return false;
    }

    value = static_cast<std::uint64_t>(bytes[0]) |
            (static_cast<std::uint64_t>(bytes[1]) << 8U) |
            (static_cast<std::uint64_t>(bytes[2]) << 16U) |
            (static_cast<std::uint64_t>(bytes[3]) << 24U) |
            (static_cast<std::uint64_t>(bytes[4]) << 32U) |
            (static_cast<std::uint64_t>(bytes[5]) << 40U) |
            (static_cast<std::uint64_t>(bytes[6]) << 48U) |
            (static_cast<std::uint64_t>(bytes[7]) << 56U);
    return true;
}

bool read_i64(std::ifstream& stream, std::int64_t& value) {
    std::uint64_t encoded_value {0};
    if (!read_u64(stream, encoded_value)) {
        return false;
    }

    value = static_cast<std::int64_t>(encoded_value);
    return true;
}

bool read_string(std::ifstream& stream, std::string& value) {
    std::uint32_t length {0};
    if (!read_u32(stream, length)) {
        return false;
    }

    value.assign(length, '\0');
    if (length == 0) {
        return true;
    }

    auto bytes = std::span<std::uint8_t>(reinterpret_cast<std::uint8_t*>(value.data()), value.size());
    return read_bytes(stream, bytes);
}

bool read_capture_summary(std::ifstream& stream, CaptureSummary& summary) {
    return read_u64(stream, summary.packet_count) &&
           read_u64(stream, summary.flow_count) &&
           read_u64(stream, summary.total_bytes);
}

bool read_packet_ref(std::ifstream& stream, PacketRef& packet) {
    return read_u64(stream, packet.packet_index) &&
           read_u32(stream, packet.ts_sec) &&
           read_u32(stream, packet.ts_usec) &&
           read_u64(stream, packet.byte_offset) &&
           read_u32(stream, packet.captured_length) &&
           read_u32(stream, packet.original_length);
}

bool read_endpoint_key(std::ifstream& stream, EndpointKeyV4& endpoint) {
    return read_u32(stream, endpoint.addr) && read_u16(stream, endpoint.port);
}

bool read_endpoint_key(std::ifstream& stream, EndpointKeyV6& endpoint) {
    auto address = std::span<std::uint8_t>(endpoint.addr.data(), endpoint.addr.size());
    return read_bytes(stream, address) && read_u16(stream, endpoint.port);
}

bool read_protocol_id(std::ifstream& stream, ProtocolId& protocol) {
    std::uint8_t value {0};
    if (!read_u8(stream, value)) {
        return false;
    }

    protocol = static_cast<ProtocolId>(value);
    return true;
}

bool read_flow_key(std::ifstream& stream, FlowKeyV4& key) {
    return read_u32(stream, key.src_addr) &&
           read_u32(stream, key.dst_addr) &&
           read_u16(stream, key.src_port) &&
           read_u16(stream, key.dst_port) &&
           read_protocol_id(stream, key.protocol);
}

bool read_flow_key(std::ifstream& stream, FlowKeyV6& key) {
    auto source = std::span<std::uint8_t>(key.src_addr.data(), key.src_addr.size());
    auto destination = std::span<std::uint8_t>(key.dst_addr.data(), key.dst_addr.size());
    return read_bytes(stream, source) &&
           read_bytes(stream, destination) &&
           read_u16(stream, key.src_port) &&
           read_u16(stream, key.dst_port) &&
           read_protocol_id(stream, key.protocol);
}

bool read_connection_key(std::ifstream& stream, ConnectionKeyV4& key) {
    return read_endpoint_key(stream, key.first) &&
           read_endpoint_key(stream, key.second) &&
           read_protocol_id(stream, key.protocol);
}

bool read_connection_key(std::ifstream& stream, ConnectionKeyV6& key) {
    return read_endpoint_key(stream, key.first) &&
           read_endpoint_key(stream, key.second) &&
           read_protocol_id(stream, key.protocol);
}

bool read_packet_refs(std::ifstream& stream, std::vector<PacketRef>& packets) {
    std::uint64_t packet_count {0};
    if (!read_u64(stream, packet_count)) {
        return false;
    }

    if (packet_count > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
        return false;
    }

    packets.clear();
    packets.reserve(static_cast<std::size_t>(packet_count));
    for (std::uint64_t index = 0; index < packet_count; ++index) {
        PacketRef packet {};
        if (!read_packet_ref(stream, packet)) {
            return false;
        }
        packets.push_back(packet);
    }

    return true;
}

bool read_flow(std::ifstream& stream, FlowV4& flow) {
    if (!read_flow_key(stream, flow.key) ||
        !read_u64(stream, flow.packet_count) ||
        !read_u64(stream, flow.total_bytes) ||
        !read_packet_refs(stream, flow.packets)) {
        return false;
    }

    return true;
}

bool read_flow(std::ifstream& stream, FlowV6& flow) {
    if (!read_flow_key(stream, flow.key) ||
        !read_u64(stream, flow.packet_count) ||
        !read_u64(stream, flow.total_bytes) ||
        !read_packet_refs(stream, flow.packets)) {
        return false;
    }

    return true;
}

bool read_connection(std::ifstream& stream, ConnectionV4& connection) {
    std::uint8_t has_flow_a {0};
    std::uint8_t has_flow_b {0};

    if (!read_connection_key(stream, connection.key) ||
        !read_u8(stream, has_flow_a) ||
        !read_u8(stream, has_flow_b) ||
        !read_u64(stream, connection.packet_count) ||
        !read_u64(stream, connection.total_bytes)) {
        return false;
    }

    connection.has_flow_a = has_flow_a != 0;
    connection.has_flow_b = has_flow_b != 0;
    connection.flow_a = {};
    connection.flow_b = {};

    if (connection.has_flow_a && !read_flow(stream, connection.flow_a)) {
        return false;
    }

    if (connection.has_flow_b && !read_flow(stream, connection.flow_b)) {
        return false;
    }

    return true;
}

bool read_connection(std::ifstream& stream, ConnectionV6& connection) {
    std::uint8_t has_flow_a {0};
    std::uint8_t has_flow_b {0};

    if (!read_connection_key(stream, connection.key) ||
        !read_u8(stream, has_flow_a) ||
        !read_u8(stream, has_flow_b) ||
        !read_u64(stream, connection.packet_count) ||
        !read_u64(stream, connection.total_bytes)) {
        return false;
    }

    connection.has_flow_a = has_flow_a != 0;
    connection.has_flow_b = has_flow_b != 0;
    connection.flow_a = {};
    connection.flow_b = {};

    if (connection.has_flow_a && !read_flow(stream, connection.flow_a)) {
        return false;
    }

    if (connection.has_flow_b && !read_flow(stream, connection.flow_b)) {
        return false;
    }

    return true;
}

bool read_source_info(std::ifstream& stream, CaptureSourceInfo& source_info) {
    std::string capture_path {};
    std::uint8_t format {0};

    if (!read_string(stream, capture_path) ||
        !read_u8(stream, format) ||
        !read_u64(stream, source_info.file_size) ||
        !read_i64(stream, source_info.last_write_time)) {
        return false;
    }

    source_info.capture_path = std::filesystem::path(capture_path);
    source_info.format = static_cast<CaptureSourceFormat>(format);
    return true;
}

}  // namespace

bool CaptureIndexReader::read(const std::filesystem::path& index_path,
                              CaptureState& out_state,
                              std::filesystem::path& out_source_capture_path,
                              CaptureSourceInfo* out_source_info) const {
    out_state = {};
    out_source_capture_path.clear();
    if (out_source_info != nullptr) {
        *out_source_info = {};
    }

    std::ifstream stream(index_path, std::ios::binary);
    if (!stream.is_open()) {
        return false;
    }

    std::uint64_t magic {0};
    std::uint16_t version {0};
    std::uint16_t reserved {0};
    CaptureSourceInfo source_info {};

    if (!read_u64(stream, magic) ||
        !read_u16(stream, version) ||
        !read_u16(stream, reserved) ||
        magic != kCaptureIndexMagic ||
        version != kCaptureIndexVersion ||
        !read_source_info(stream, source_info) ||
        !read_capture_summary(stream, out_state.summary)) {
        out_state = {};
        return false;
    }

    std::uint64_t ipv4_connection_count {0};
    std::uint64_t ipv6_connection_count {0};
    if (!read_u64(stream, ipv4_connection_count) ||
        !read_u64(stream, ipv6_connection_count)) {
        out_state = {};
        return false;
    }

    for (std::uint64_t index = 0; index < ipv4_connection_count; ++index) {
        ConnectionV4 connection {};
        if (!read_connection(stream, connection)) {
            out_state = {};
            return false;
        }

        out_state.ipv4_connections.get_or_create(connection.key) = connection;
    }

    for (std::uint64_t index = 0; index < ipv6_connection_count; ++index) {
        ConnectionV6 connection {};
        if (!read_connection(stream, connection)) {
            out_state = {};
            return false;
        }

        out_state.ipv6_connections.get_or_create(connection.key) = connection;
    }

    out_source_capture_path = source_info.capture_path;
    if (out_source_info != nullptr) {
        *out_source_info = source_info;
    }

    return true;
}

}  // namespace pfl
