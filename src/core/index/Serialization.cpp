#include "core/index/Serialization.h"

#include <algorithm>
#include <array>
#include <limits>

namespace pfl::detail {

namespace {

bool write_endpoint_key(std::ostream& stream, const EndpointKeyV4& endpoint) {
    return write_u32(stream, endpoint.addr) && write_u16(stream, endpoint.port);
}

bool write_endpoint_key(std::ostream& stream, const EndpointKeyV6& endpoint) {
    const auto address = std::span<const std::uint8_t>(endpoint.addr.data(), endpoint.addr.size());
    return write_bytes(stream, address) && write_u16(stream, endpoint.port);
}

bool read_endpoint_key(std::istream& stream, EndpointKeyV4& endpoint) {
    return read_u32(stream, endpoint.addr) && read_u16(stream, endpoint.port);
}

bool read_endpoint_key(std::istream& stream, EndpointKeyV6& endpoint) {
    auto address = std::span<std::uint8_t>(endpoint.addr.data(), endpoint.addr.size());
    return read_bytes(stream, address) && read_u16(stream, endpoint.port);
}

bool write_protocol_id(std::ostream& stream, ProtocolId protocol) {
    return write_u8(stream, static_cast<std::uint8_t>(protocol));
}

bool read_protocol_id(std::istream& stream, ProtocolId& protocol) {
    std::uint8_t value {0};
    if (!read_u8(stream, value)) {
        return false;
    }

    protocol = static_cast<ProtocolId>(value);
    return true;
}

bool write_flow_protocol_hint(std::ostream& stream, const FlowProtocolHint hint) {
    return write_u8(stream, static_cast<std::uint8_t>(hint));
}

bool read_flow_protocol_hint(std::istream& stream, FlowProtocolHint& hint) {
    std::uint8_t value {0};
    if (!read_u8(stream, value)) {
        return false;
    }

    hint = static_cast<FlowProtocolHint>(value);
    return true;
}

bool write_flow_key(std::ostream& stream, const FlowKeyV4& key) {
    return write_u32(stream, key.src_addr) &&
           write_u32(stream, key.dst_addr) &&
           write_u16(stream, key.src_port) &&
           write_u16(stream, key.dst_port) &&
           write_protocol_id(stream, key.protocol);
}

bool write_flow_key(std::ostream& stream, const FlowKeyV6& key) {
    const auto source = std::span<const std::uint8_t>(key.src_addr.data(), key.src_addr.size());
    const auto destination = std::span<const std::uint8_t>(key.dst_addr.data(), key.dst_addr.size());
    return write_bytes(stream, source) &&
           write_bytes(stream, destination) &&
           write_u16(stream, key.src_port) &&
           write_u16(stream, key.dst_port) &&
           write_protocol_id(stream, key.protocol);
}

bool read_flow_key(std::istream& stream, FlowKeyV4& key) {
    return read_u32(stream, key.src_addr) &&
           read_u32(stream, key.dst_addr) &&
           read_u16(stream, key.src_port) &&
           read_u16(stream, key.dst_port) &&
           read_protocol_id(stream, key.protocol);
}

bool read_flow_key(std::istream& stream, FlowKeyV6& key) {
    auto source = std::span<std::uint8_t>(key.src_addr.data(), key.src_addr.size());
    auto destination = std::span<std::uint8_t>(key.dst_addr.data(), key.dst_addr.size());
    return read_bytes(stream, source) &&
           read_bytes(stream, destination) &&
           read_u16(stream, key.src_port) &&
           read_u16(stream, key.dst_port) &&
           read_protocol_id(stream, key.protocol);
}

bool write_connection_key(std::ostream& stream, const ConnectionKeyV4& key) {
    return write_endpoint_key(stream, key.first) &&
           write_endpoint_key(stream, key.second) &&
           write_protocol_id(stream, key.protocol);
}

bool write_connection_key(std::ostream& stream, const ConnectionKeyV6& key) {
    return write_endpoint_key(stream, key.first) &&
           write_endpoint_key(stream, key.second) &&
           write_protocol_id(stream, key.protocol);
}

bool read_connection_key(std::istream& stream, ConnectionKeyV4& key) {
    return read_endpoint_key(stream, key.first) &&
           read_endpoint_key(stream, key.second) &&
           read_protocol_id(stream, key.protocol);
}

bool read_connection_key(std::istream& stream, ConnectionKeyV6& key) {
    return read_endpoint_key(stream, key.first) &&
           read_endpoint_key(stream, key.second) &&
           read_protocol_id(stream, key.protocol);
}

bool read_packet_refs(std::istream& stream, std::vector<PacketRef>& packets) {
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

}  // namespace

bool write_bytes(std::ostream& stream, std::span<const std::uint8_t> bytes) {
    stream.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    return static_cast<bool>(stream);
}

bool write_u8(std::ostream& stream, std::uint8_t value) {
    const auto byte = std::array<std::uint8_t, 1> {value};
    return write_bytes(stream, byte);
}

bool write_u16(std::ostream& stream, std::uint16_t value) {
    const auto bytes = std::array<std::uint8_t, 2> {
        static_cast<std::uint8_t>(value & 0x00FFU),
        static_cast<std::uint8_t>((value >> 8U) & 0x00FFU),
    };
    return write_bytes(stream, bytes);
}

bool write_u32(std::ostream& stream, std::uint32_t value) {
    const auto bytes = std::array<std::uint8_t, 4> {
        static_cast<std::uint8_t>(value & 0x000000FFU),
        static_cast<std::uint8_t>((value >> 8U) & 0x000000FFU),
        static_cast<std::uint8_t>((value >> 16U) & 0x000000FFU),
        static_cast<std::uint8_t>((value >> 24U) & 0x000000FFU),
    };
    return write_bytes(stream, bytes);
}

bool write_u64(std::ostream& stream, std::uint64_t value) {
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

bool write_i64(std::ostream& stream, std::int64_t value) {
    return write_u64(stream, static_cast<std::uint64_t>(value));
}

bool write_string(std::ostream& stream, const std::string& value) {
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

bool read_bytes(std::istream& stream, std::span<std::uint8_t> bytes) {
    stream.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    return stream.gcount() == static_cast<std::streamsize>(bytes.size());
}

bool read_u8(std::istream& stream, std::uint8_t& value) {
    auto bytes = std::array<std::uint8_t, 1> {};
    if (!read_bytes(stream, bytes)) {
        return false;
    }

    value = bytes[0];
    return true;
}

bool read_u16(std::istream& stream, std::uint16_t& value) {
    auto bytes = std::array<std::uint8_t, 2> {};
    if (!read_bytes(stream, bytes)) {
        return false;
    }

    value = static_cast<std::uint16_t>(bytes[0]) |
            static_cast<std::uint16_t>(static_cast<std::uint16_t>(bytes[1]) << 8U);
    return true;
}

bool read_u32(std::istream& stream, std::uint32_t& value) {
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

bool read_u64(std::istream& stream, std::uint64_t& value) {
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

bool read_i64(std::istream& stream, std::int64_t& value) {
    std::uint64_t encoded_value {0};
    if (!read_u64(stream, encoded_value)) {
        return false;
    }

    value = static_cast<std::int64_t>(encoded_value);
    return true;
}

bool read_string(std::istream& stream, std::string& value) {
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

bool write_section(std::ostream& stream, const std::uint32_t section_id, std::span<const std::uint8_t> payload) {
    return write_u32(stream, section_id) &&
           write_u64(stream, static_cast<std::uint64_t>(payload.size())) &&
           write_bytes(stream, payload);
}

bool read_section_header(std::istream& stream, std::uint32_t& section_id, std::uint64_t& payload_size) {
    return read_u32(stream, section_id) && read_u64(stream, payload_size);
}

bool read_section_payload(std::istream& stream, const std::uint64_t payload_size, std::vector<std::uint8_t>& payload) {
    if (payload_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()) ||
        payload_size > static_cast<std::uint64_t>(std::numeric_limits<std::streamsize>::max())) {
        return false;
    }

    payload.assign(static_cast<std::size_t>(payload_size), 0U);
    if (payload.empty()) {
        return true;
    }

    return read_bytes(stream, std::span<std::uint8_t>(payload.data(), payload.size()));
}

bool write_capture_source_info(std::ostream& stream, const CaptureSourceInfo& source_info) {
    return write_string(stream, source_info.capture_path.generic_string()) &&
           write_u8(stream, static_cast<std::uint8_t>(source_info.format)) &&
           write_u64(stream, source_info.file_size) &&
           write_i64(stream, source_info.last_write_time) &&
           write_u64(stream, source_info.content_fingerprint);
}

bool read_capture_source_info(std::istream& stream, CaptureSourceInfo& source_info) {
    std::string capture_path {};
    std::uint8_t format {0};

    if (!read_string(stream, capture_path) ||
        !read_u8(stream, format) ||
        !read_u64(stream, source_info.file_size) ||
        !read_i64(stream, source_info.last_write_time) ||
        !read_u64(stream, source_info.content_fingerprint)) {
        return false;
    }

    source_info.capture_path = std::filesystem::path(capture_path);
    source_info.format = static_cast<CaptureSourceFormat>(format);
    return true;
}

bool write_capture_summary(std::ostream& stream, const CaptureSummary& summary) {
    return write_u64(stream, summary.packet_count) &&
           write_u64(stream, summary.flow_count) &&
           write_u64(stream, summary.total_bytes);
}

bool read_capture_summary(std::istream& stream, CaptureSummary& summary) {
    return read_u64(stream, summary.packet_count) &&
           read_u64(stream, summary.flow_count) &&
           read_u64(stream, summary.total_bytes);
}

bool write_packet_ref(std::ostream& stream, const PacketRef& packet) {
    return write_u64(stream, packet.packet_index) &&
           write_u32(stream, packet.ts_sec) &&
           write_u32(stream, packet.ts_usec) &&
           write_u64(stream, packet.byte_offset) &&
           write_u32(stream, packet.captured_length) &&
           write_u32(stream, packet.original_length) &&
           write_u32(stream, packet.payload_length) &&
           write_u8(stream, packet.tcp_flags);
}

bool read_packet_ref(std::istream& stream, PacketRef& packet) {
    return read_u64(stream, packet.packet_index) &&
           read_u32(stream, packet.ts_sec) &&
           read_u32(stream, packet.ts_usec) &&
           read_u64(stream, packet.byte_offset) &&
           read_u32(stream, packet.captured_length) &&
           read_u32(stream, packet.original_length) &&
           read_u32(stream, packet.payload_length) &&
           read_u8(stream, packet.tcp_flags);
}

bool write_flow(std::ostream& stream, const FlowV4& flow) {
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

bool write_flow(std::ostream& stream, const FlowV6& flow) {
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

bool read_flow(std::istream& stream, FlowV4& flow) {
    return read_flow_key(stream, flow.key) &&
           read_u64(stream, flow.packet_count) &&
           read_u64(stream, flow.total_bytes) &&
           read_packet_refs(stream, flow.packets);
}

bool read_flow(std::istream& stream, FlowV6& flow) {
    return read_flow_key(stream, flow.key) &&
           read_u64(stream, flow.packet_count) &&
           read_u64(stream, flow.total_bytes) &&
           read_packet_refs(stream, flow.packets);
}

bool write_connection(std::ostream& stream, const ConnectionV4& connection) {
    if (!write_connection_key(stream, connection.key) ||
        !write_u8(stream, connection.has_flow_a ? 1U : 0U) ||
        !write_u8(stream, connection.has_flow_b ? 1U : 0U) ||
        !write_u64(stream, connection.packet_count) ||
        !write_u64(stream, connection.total_bytes) ||
        !write_flow_protocol_hint(stream, connection.protocol_hint) ||
        !write_string(stream, connection.service_hint)) {
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

bool write_connection(std::ostream& stream, const ConnectionV6& connection) {
    if (!write_connection_key(stream, connection.key) ||
        !write_u8(stream, connection.has_flow_a ? 1U : 0U) ||
        !write_u8(stream, connection.has_flow_b ? 1U : 0U) ||
        !write_u64(stream, connection.packet_count) ||
        !write_u64(stream, connection.total_bytes) ||
        !write_flow_protocol_hint(stream, connection.protocol_hint) ||
        !write_string(stream, connection.service_hint)) {
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

bool read_connection(std::istream& stream, ConnectionV4& connection) {
    std::uint8_t has_flow_a {0};
    std::uint8_t has_flow_b {0};

    if (!read_connection_key(stream, connection.key) ||
        !read_u8(stream, has_flow_a) ||
        !read_u8(stream, has_flow_b) ||
        !read_u64(stream, connection.packet_count) ||
        !read_u64(stream, connection.total_bytes) ||
        !read_flow_protocol_hint(stream, connection.protocol_hint) ||
        !read_string(stream, connection.service_hint)) {
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

bool read_connection(std::istream& stream, ConnectionV6& connection) {
    std::uint8_t has_flow_a {0};
    std::uint8_t has_flow_b {0};

    if (!read_connection_key(stream, connection.key) ||
        !read_u8(stream, has_flow_a) ||
        !read_u8(stream, has_flow_b) ||
        !read_u64(stream, connection.packet_count) ||
        !read_u64(stream, connection.total_bytes) ||
        !read_flow_protocol_hint(stream, connection.protocol_hint) ||
        !read_string(stream, connection.service_hint)) {
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

bool write_connection_table(std::ostream& stream, const ConnectionTableV4& table) {
    const auto connections = sorted_connections(table);
    if (!write_u64(stream, static_cast<std::uint64_t>(connections.size()))) {
        return false;
    }

    for (const auto* connection : connections) {
        if (!write_connection(stream, *connection)) {
            return false;
        }
    }

    return true;
}

bool write_connection_table(std::ostream& stream, const ConnectionTableV6& table) {
    const auto connections = sorted_connections(table);
    if (!write_u64(stream, static_cast<std::uint64_t>(connections.size()))) {
        return false;
    }

    for (const auto* connection : connections) {
        if (!write_connection(stream, *connection)) {
            return false;
        }
    }

    return true;
}

bool read_connection_table(std::istream& stream, ConnectionTableV4& table) {
    std::uint64_t connection_count {0};
    if (!read_u64(stream, connection_count) ||
        connection_count > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
        return false;
    }

    table.clear();
    for (std::uint64_t index = 0; index < connection_count; ++index) {
        ConnectionV4 connection {};
        if (!read_connection(stream, connection)) {
            table.clear();
            return false;
        }

        table.get_or_create(connection.key) = connection;
    }

    return true;
}

bool read_connection_table(std::istream& stream, ConnectionTableV6& table) {
    std::uint64_t connection_count {0};
    if (!read_u64(stream, connection_count) ||
        connection_count > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
        return false;
    }

    table.clear();
    for (std::uint64_t index = 0; index < connection_count; ++index) {
        ConnectionV6 connection {};
        if (!read_connection(stream, connection)) {
            table.clear();
            return false;
        }

        table.get_or_create(connection.key) = connection;
    }

    return true;
}

bool write_capture_state(std::ostream& stream, const CaptureState& state) {
    return write_capture_summary(stream, state.summary) &&
           write_connection_table(stream, state.ipv4_connections) &&
           write_connection_table(stream, state.ipv6_connections);
}

bool read_capture_state(std::istream& stream, CaptureState& state) {
    state = {};
    return read_capture_summary(stream, state.summary) &&
           read_connection_table(stream, state.ipv4_connections) &&
           read_connection_table(stream, state.ipv6_connections);
}

}  // namespace pfl::detail








