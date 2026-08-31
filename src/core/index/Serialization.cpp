#include "core/index/Serialization.h"

#include <algorithm>
#include <array>
#include <limits>
#include <optional>
#include <sstream>
#include <utility>

namespace pfl::detail {

namespace {

constexpr std::uint64_t kSerializationProgressReportInterval = 4096U;

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

bool write_protocol_layer_kind(std::ostream& stream, const ProtocolLayerKind kind) {
    return write_u16(stream, static_cast<std::uint16_t>(kind));
}

bool read_protocol_layer_kind(std::istream& stream, ProtocolLayerKind& kind) {
    std::uint16_t raw_kind {0};
    if (!read_u16(stream, raw_kind)) {
        return false;
    }

    kind = static_cast<ProtocolLayerKind>(raw_kind);
    return true;
}

bool write_protocol_layer_identifier(std::ostream& stream, const ProtocolLayerIdentifier& identifier) {
    return write_u8(stream, static_cast<std::uint8_t>(identifier.kind)) &&
           write_u64(stream, identifier.value);
}

bool read_protocol_layer_identifier(std::istream& stream, ProtocolLayerIdentifier& identifier) {
    std::uint8_t raw_kind {0};
    if (!read_u8(stream, raw_kind) || !read_u64(stream, identifier.value)) {
        return false;
    }

    identifier.kind = static_cast<ProtocolLayerIdentifierKind>(raw_kind);
    return true;
}

bool write_layer_key(std::ostream& stream, const LayerKey& key) {
    return write_protocol_layer_kind(stream, key.kind) &&
           write_protocol_layer_identifier(stream, key.identifier);
}

bool read_layer_key(std::istream& stream, LayerKey& key) {
    return read_protocol_layer_kind(stream, key.kind) &&
           read_protocol_layer_identifier(stream, key.identifier);
}

bool write_protocol_path(std::ostream& stream, const ProtocolPath& path) {
    if (!write_u64(stream, static_cast<std::uint64_t>(path.size()))) {
        return false;
    }

    for (const auto& layer : path.layers()) {
        if (!write_layer_key(stream, layer)) {
            return false;
        }
    }

    return true;
}

bool read_protocol_path(std::istream& stream, ProtocolPath& path) {
    std::uint64_t layer_count {0};
    if (!read_u64(stream, layer_count) ||
        layer_count > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()) ||
        layer_count > static_cast<std::uint64_t>(kMaxProtocolPathLayers)) {
        return false;
    }

    std::vector<LayerKey> layers {};
    layers.reserve(static_cast<std::size_t>(layer_count));
    for (std::uint64_t index = 0; index < layer_count; ++index) {
        LayerKey layer {};
        if (!read_layer_key(stream, layer)) {
            return false;
        }
        layers.push_back(layer);
    }

    path = ProtocolPath {std::move(layers)};
    return true;
}

bool report_serialization_progress(
    const SerializationProgressCallback& callback,
    const std::uint64_t processed,
    const std::uint64_t total
) {
    return !callback || callback(processed, total);
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
           write_protocol_id(stream, key.protocol) &&
           write_u32(stream, key.protocol_path_id);
}

bool write_flow_key(std::ostream& stream, const FlowKeyV6& key) {
    const auto source = std::span<const std::uint8_t>(key.src_addr.data(), key.src_addr.size());
    const auto destination = std::span<const std::uint8_t>(key.dst_addr.data(), key.dst_addr.size());
    return write_bytes(stream, source) &&
           write_bytes(stream, destination) &&
           write_u16(stream, key.src_port) &&
           write_u16(stream, key.dst_port) &&
           write_protocol_id(stream, key.protocol) &&
           write_u32(stream, key.protocol_path_id);
}

bool read_flow_key(std::istream& stream, FlowKeyV4& key) {
    return read_u32(stream, key.src_addr) &&
           read_u32(stream, key.dst_addr) &&
           read_u16(stream, key.src_port) &&
           read_u16(stream, key.dst_port) &&
           read_protocol_id(stream, key.protocol) &&
           read_u32(stream, key.protocol_path_id);
}

bool read_flow_key(std::istream& stream, FlowKeyV6& key) {
    auto source = std::span<std::uint8_t>(key.src_addr.data(), key.src_addr.size());
    auto destination = std::span<std::uint8_t>(key.dst_addr.data(), key.dst_addr.size());
    return read_bytes(stream, source) &&
           read_bytes(stream, destination) &&
           read_u16(stream, key.src_port) &&
           read_u16(stream, key.dst_port) &&
           read_protocol_id(stream, key.protocol) &&
           read_u32(stream, key.protocol_path_id);
}

bool write_connection_key(std::ostream& stream, const ConnectionKeyV4& key) {
    return write_endpoint_key(stream, key.first) &&
           write_endpoint_key(stream, key.second) &&
           write_protocol_id(stream, key.protocol) &&
           write_u32(stream, key.protocol_path_id);
}

bool write_connection_key(std::ostream& stream, const ConnectionKeyV6& key) {
    return write_endpoint_key(stream, key.first) &&
           write_endpoint_key(stream, key.second) &&
           write_protocol_id(stream, key.protocol) &&
           write_u32(stream, key.protocol_path_id);
}

bool read_connection_key(std::istream& stream, ConnectionKeyV4& key) {
    return read_endpoint_key(stream, key.first) &&
           read_endpoint_key(stream, key.second) &&
           read_protocol_id(stream, key.protocol) &&
           read_u32(stream, key.protocol_path_id);
}

bool read_connection_key(std::istream& stream, ConnectionKeyV6& key) {
    return read_endpoint_key(stream, key.first) &&
           read_endpoint_key(stream, key.second) &&
           read_protocol_id(stream, key.protocol) &&
           read_u32(stream, key.protocol_path_id);
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

bool skip_exact_bytes(std::istream& stream, std::uint64_t byte_count) {
    if (byte_count == 0U) {
        return true;
    }

    auto discard = std::array<char, 512> {};
    std::uint64_t remaining = byte_count;
    while (remaining > 0U) {
        const auto chunk_size = std::min<std::uint64_t>(remaining, static_cast<std::uint64_t>(discard.size()));
        stream.read(discard.data(), static_cast<std::streamsize>(chunk_size));
        if (stream.gcount() != static_cast<std::streamsize>(chunk_size)) {
            return false;
        }
        remaining -= chunk_size;
    }

    return true;
}

bool read_bounded_string(std::istream& stream,
                         std::string& value,
                         const std::uint32_t max_length,
                         std::uint32_t& bytes_consumed,
                         const std::uint32_t header_size_limit) {
    std::uint32_t length {0};
    if (!read_u32(stream, length)) {
        return false;
    }

    if (length > max_length ||
        bytes_consumed > header_size_limit ||
        4U > header_size_limit - bytes_consumed ||
        length > (header_size_limit - bytes_consumed - 4U)) {
        return false;
    }

    bytes_consumed += 4U;
    value.assign(length, '\0');
    if (length == 0U) {
        return true;
    }

    auto bytes = std::span<std::uint8_t>(reinterpret_cast<std::uint8_t*>(value.data()), value.size());
    if (!read_bytes(stream, bytes)) {
        return false;
    }

    bytes_consumed += length;
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

std::optional<std::uint32_t> encoded_capture_index_stable_header_size(
    const CaptureIndexStableHeader& header,
    const std::uint32_t extension_size
) noexcept {
    const auto writer_size = header.writer_application_version.size();
    const auto source_path_size = header.source_capture_path_utf8.size();
    if (writer_size > static_cast<std::size_t>(kMaxCaptureIndexStableHeaderStringBytes) ||
        source_path_size > static_cast<std::size_t>(kMaxCaptureIndexStableHeaderStringBytes) ||
        writer_size > static_cast<std::size_t>(std::numeric_limits<std::uint32_t>::max()) ||
        source_path_size > static_cast<std::size_t>(std::numeric_limits<std::uint32_t>::max())) {
        return std::nullopt;
    }

    const auto total_size = static_cast<std::uint64_t>(kCaptureIndexStableHeaderKnownPrefixSize) +
                            static_cast<std::uint64_t>(writer_size) +
                            static_cast<std::uint64_t>(source_path_size) +
                            static_cast<std::uint64_t>(extension_size);
    if (total_size > static_cast<std::uint64_t>(std::numeric_limits<std::uint32_t>::max())) {
        return std::nullopt;
    }

    return static_cast<std::uint32_t>(total_size);
}

bool write_capture_index_stable_header(std::ostream& stream,
                                       const CaptureIndexStableHeader& header,
                                       const std::span<const std::uint8_t> extension_bytes) {
    const auto encoded_size = encoded_capture_index_stable_header_size(
        header,
        static_cast<std::uint32_t>(extension_bytes.size())
    );
    if (!encoded_size.has_value()) {
        return false;
    }

    return write_u64(stream, header.magic) &&
           write_u16(stream, header.container_format_version) &&
           write_u16(stream, header.header_flags) &&
           write_u32(stream, *encoded_size) &&
           write_u32(stream, header.index_revision) &&
           write_string(stream, header.writer_application_version) &&
           write_u8(stream, static_cast<std::uint8_t>(header.source_format)) &&
           write_u64(stream, header.source_file_size) &&
           write_i64(stream, header.source_last_write_time) &&
           write_u64(stream, header.source_content_fingerprint) &&
           write_string(stream, header.source_capture_path_utf8) &&
           write_bytes(stream, extension_bytes);
}

bool read_capture_index_stable_header(std::istream& stream, CaptureIndexStableHeader& header) {
    std::uint8_t raw_source_format {0};
    std::uint32_t bytes_consumed = 0U;

    if (!read_u64(stream, header.magic) ||
        !read_u16(stream, header.container_format_version) ||
        !read_u16(stream, header.header_flags) ||
        !read_u32(stream, header.header_size) ||
        !read_u32(stream, header.index_revision)) {
        return false;
    }

    bytes_consumed = 8U + 2U + 2U + 4U + 4U;
    if (header.header_size < kCaptureIndexStableHeaderKnownPrefixSize) {
        return false;
    }

    if (!read_bounded_string(
            stream,
            header.writer_application_version,
            kMaxCaptureIndexStableHeaderStringBytes,
            bytes_consumed,
            header.header_size) ||
        !read_u8(stream, raw_source_format) ||
        !read_u64(stream, header.source_file_size) ||
        !read_i64(stream, header.source_last_write_time) ||
        !read_u64(stream, header.source_content_fingerprint)) {
        return false;
    }

    bytes_consumed += 1U + 8U + 8U + 8U;
    if (bytes_consumed > header.header_size ||
        !read_bounded_string(
            stream,
            header.source_capture_path_utf8,
            kMaxCaptureIndexStableHeaderStringBytes,
            bytes_consumed,
            header.header_size)) {
        return false;
    }

    header.source_format = static_cast<CaptureSourceFormat>(raw_source_format);
    return skip_exact_bytes(stream, header.header_size - bytes_consumed);
}

std::string filesystem_path_to_generic_utf8(const std::filesystem::path& path) {
    const auto utf8 = path.generic_u8string();
    return std::string(
        reinterpret_cast<const char*>(utf8.data()),
        utf8.size()
    );
}

std::filesystem::path filesystem_path_from_generic_utf8(const std::string_view utf8_path) {
    std::u8string utf8 {};
    utf8.reserve(utf8_path.size());
    for (const char byte : utf8_path) {
        utf8.push_back(static_cast<char8_t>(static_cast<unsigned char>(byte)));
    }

    return std::filesystem::path(utf8);
}

bool write_capture_index_stable_section_header(std::ostream& stream,
                                               const CaptureIndexStableSectionHeader& header) {
    return write_u32(stream, header.section_id) &&
           write_u16(stream, header.section_schema_version) &&
           write_u16(stream, header.section_flags) &&
           write_u64(stream, header.payload_size);
}

bool read_capture_index_stable_section_header(std::istream& stream,
                                              CaptureIndexStableSectionHeader& header) {
    return read_u32(stream, header.section_id) &&
           read_u16(stream, header.section_schema_version) &&
           read_u16(stream, header.section_flags) &&
           read_u64(stream, header.payload_size);
}

bool skip_section_payload(std::istream& stream, const std::uint64_t payload_size) {
    return skip_exact_bytes(stream, payload_size);
}

bool read_bounded_section_payload(std::istream& stream,
                                  const std::uint64_t payload_size,
                                  const std::uint64_t max_payload_size,
                                  std::vector<std::uint8_t>& payload) {
    if (payload_size > max_payload_size ||
        payload_size > static_cast<std::uint64_t>((std::numeric_limits<std::size_t>::max)()) ||
        payload_size > static_cast<std::uint64_t>((std::numeric_limits<std::streamsize>::max)())) {
        return false;
    }

    payload.assign(static_cast<std::size_t>(payload_size), 0U);
    if (payload.empty()) {
        return true;
    }

    return read_bytes(stream, std::span<std::uint8_t>(payload.data(), payload.size()));
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
    return read_bounded_section_payload(
        stream,
        payload_size,
        static_cast<std::uint64_t>((std::numeric_limits<std::streamsize>::max)()),
        payload
    );
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
           write_u32(stream, packet.data_link_type) &&
           write_u32(stream, packet.captured_length) &&
           write_u32(stream, packet.original_length);
}

bool read_packet_ref(std::istream& stream, PacketRef& packet) {
    if (!read_u64(stream, packet.packet_index) ||
        !read_u32(stream, packet.ts_sec) ||
        !read_u32(stream, packet.ts_usec) ||
        !read_u64(stream, packet.byte_offset) ||
        !read_u32(stream, packet.data_link_type) ||
        !read_u32(stream, packet.captured_length) ||
        !read_u32(stream, packet.original_length)) {
        return false;
    }
    return true;
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

template <typename Flow>
bool write_flow_with_progress(
    std::ostream& stream,
    const Flow& flow,
    std::uint64_t& packets_processed,
    const std::uint64_t total_packets,
    const SerializationProgressCallback& progress_callback
) {
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

        ++packets_processed;
        if (((packets_processed % kSerializationProgressReportInterval) == 0U || packets_processed == total_packets) &&
            !report_serialization_progress(progress_callback, packets_processed, total_packets)) {
            return false;
        }
    }

    return true;
}

bool read_flow(std::istream& stream, FlowV4& flow) {
    if (!read_flow_key(stream, flow.key) ||
        !read_u64(stream, flow.packet_count) ||
        !read_u64(stream, flow.total_bytes) ||
        !read_packet_refs(stream, flow.packets)) {
        return false;
    }

    return true;
}

bool read_flow(std::istream& stream, FlowV6& flow) {
    if (!read_flow_key(stream, flow.key) ||
        !read_u64(stream, flow.packet_count) ||
        !read_u64(stream, flow.total_bytes) ||
        !read_packet_refs(stream, flow.packets)) {
        return false;
    }

    return true;
}

bool write_connection_aggregate_stats(std::ostream& stream, const ConnectionAggregateStats& stats) {
    return write_u64(stream, stats.first_timestamp_us) &&
           write_u64(stream, stats.last_timestamp_us) &&
           write_u64(stream, stats.captured_bytes) &&
           write_u64(stream, stats.truncated_packet_count) &&
           write_u64(stream, stats.tcp_syn_count) &&
           write_u64(stream, stats.tcp_fin_count) &&
           write_u64(stream, stats.tcp_rst_count) &&
           write_u32(stream, stats.max_original_packet_length) &&
           write_u32(stream, stats.max_captured_packet_length);
}

bool read_connection_aggregate_stats(std::istream& stream, ConnectionAggregateStats& stats) {
    return read_u64(stream, stats.first_timestamp_us) &&
           read_u64(stream, stats.last_timestamp_us) &&
           read_u64(stream, stats.captured_bytes) &&
           read_u64(stream, stats.truncated_packet_count) &&
           read_u64(stream, stats.tcp_syn_count) &&
           read_u64(stream, stats.tcp_fin_count) &&
           read_u64(stream, stats.tcp_rst_count) &&
           read_u32(stream, stats.max_original_packet_length) &&
           read_u32(stream, stats.max_captured_packet_length);
}

template <typename Connection>
bool write_connection_prefix(std::ostream& stream, const Connection& connection) {
    return write_connection_key(stream, connection.key) &&
           write_u8(stream, connection.has_flow_a ? 1U : 0U) &&
           write_u8(stream, connection.has_flow_b ? 1U : 0U) &&
           write_u64(stream, connection.packet_count) &&
           write_u64(stream, connection.total_bytes) &&
           write_u8(stream, connection.has_fragmented_packets ? 1U : 0U) &&
           write_u64(stream, connection.fragmented_packet_count) &&
           write_flow_protocol_hint(stream, connection.protocol_hint) &&
           write_string(stream, connection.service_hint) &&
           write_u8(stream, static_cast<std::uint8_t>(connection.quic_version)) &&
           write_u8(stream, static_cast<std::uint8_t>(connection.tls_version)) &&
           write_connection_aggregate_stats(stream, connection.aggregate_stats);
}

template <typename Connection>
bool read_connection_prefix(std::istream& stream, Connection& connection) {
    std::uint8_t has_flow_a {0};
    std::uint8_t has_flow_b {0};
    std::uint8_t has_fragmented_packets {0};
    std::uint8_t quic_version {0};
    std::uint8_t tls_version {0};

    if (!read_connection_key(stream, connection.key) ||
        !read_u8(stream, has_flow_a) ||
        !read_u8(stream, has_flow_b) ||
        !read_u64(stream, connection.packet_count) ||
        !read_u64(stream, connection.total_bytes) ||
        !read_u8(stream, has_fragmented_packets) ||
        !read_u64(stream, connection.fragmented_packet_count) ||
        !read_flow_protocol_hint(stream, connection.protocol_hint) ||
        !read_string(stream, connection.service_hint) ||
        !read_u8(stream, quic_version) ||
        !read_u8(stream, tls_version) ||
        !read_connection_aggregate_stats(stream, connection.aggregate_stats)) {
        return false;
    }

    connection.has_flow_a = has_flow_a != 0U;
    connection.has_flow_b = has_flow_b != 0U;
    connection.has_fragmented_packets = has_fragmented_packets != 0U;
    connection.quic_version = static_cast<QuicVersionHint>(quic_version);
    connection.tls_version = static_cast<TlsVersionHint>(tls_version);
    connection.flow_a = {};
    connection.flow_b = {};
    connection.hint_search_state = {};
    return true;
}

bool write_connection(std::ostream& stream, const ConnectionV4& connection) {
    if (!write_connection_prefix(stream, connection)) {
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
    if (!write_connection_prefix(stream, connection)) {
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
    if (!read_connection_prefix(stream, connection)) {
        return false;
    }

    if (!connection.has_flow_a) {
        return false;
    }

    if (connection.has_flow_a && !read_flow(stream, connection.flow_a)) {
        return false;
    }

    if (connection.has_flow_b && !read_flow(stream, connection.flow_b)) {
        return false;
    }

    return has_valid_first_observed_orientation(connection);
}

bool read_connection(std::istream& stream, ConnectionV6& connection) {
    if (!read_connection_prefix(stream, connection)) {
        return false;
    }

    if (!connection.has_flow_a) {
        return false;
    }

    if (connection.has_flow_a && !read_flow(stream, connection.flow_a)) {
        return false;
    }

    if (connection.has_flow_b && !read_flow(stream, connection.flow_b)) {
        return false;
    }

    return has_valid_first_observed_orientation(connection);
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

template <typename Table>
std::uint64_t count_connection_table_packet_refs(const Table& table) {
    std::uint64_t total_packets {0};
    const auto connections = sorted_connections(table);
    for (const auto* connection : connections) {
        if (connection->has_flow_a) {
            total_packets += static_cast<std::uint64_t>(connection->flow_a.packets.size());
        }
        if (connection->has_flow_b) {
            total_packets += static_cast<std::uint64_t>(connection->flow_b.packets.size());
        }
    }
    return total_packets;
}

bool write_connection_table(std::ostream& stream, const ConnectionTableV4& table) {
    return write_connection_table(stream, table, {});
}

bool write_connection_table(std::ostream& stream, const ConnectionTableV6& table) {
    return write_connection_table(stream, table, {});
}

bool write_connection_table(
    std::ostream& stream,
    const ConnectionTableV4& table,
    const SerializationProgressCallback& progress_callback
) {
    const auto connections = sorted_connections(table);
    if (!write_u64(stream, static_cast<std::uint64_t>(connections.size()))) {
        return false;
    }

    const auto total_packets = count_connection_table_packet_refs(table);
    std::uint64_t processed_packets {0};
    if (total_packets == 0U && !report_serialization_progress(progress_callback, 0U, 0U)) {
        return false;
    }

    for (const auto* connection : connections) {
        if (!write_connection_prefix(stream, *connection)) {
            return false;
        }

        if (connection->has_flow_a &&
            !write_flow_with_progress(stream, connection->flow_a, processed_packets, total_packets, progress_callback)) {
            return false;
        }

        if (connection->has_flow_b &&
            !write_flow_with_progress(stream, connection->flow_b, processed_packets, total_packets, progress_callback)) {
            return false;
        }
    }

    if (total_packets > 0U && !report_serialization_progress(progress_callback, processed_packets, total_packets)) {
        return false;
    }

    return true;
}

bool write_connection_table(
    std::ostream& stream,
    const ConnectionTableV6& table,
    const SerializationProgressCallback& progress_callback
) {
    const auto connections = sorted_connections(table);
    if (!write_u64(stream, static_cast<std::uint64_t>(connections.size()))) {
        return false;
    }

    const auto total_packets = count_connection_table_packet_refs(table);
    std::uint64_t processed_packets {0};
    if (total_packets == 0U && !report_serialization_progress(progress_callback, 0U, 0U)) {
        return false;
    }

    for (const auto* connection : connections) {
        if (!write_connection_prefix(stream, *connection)) {
            return false;
        }

        if (connection->has_flow_a &&
            !write_flow_with_progress(stream, connection->flow_a, processed_packets, total_packets, progress_callback)) {
            return false;
        }

        if (connection->has_flow_b &&
            !write_flow_with_progress(stream, connection->flow_b, processed_packets, total_packets, progress_callback)) {
            return false;
        }
    }

    if (total_packets > 0U && !report_serialization_progress(progress_callback, processed_packets, total_packets)) {
        return false;
    }

    return true;
}

template <typename Flow>
void accumulate_flow_packet_statistics(
    const Flow& flow,
    CapturePacketStatistics* const packet_statistics
) {
    if (packet_statistics == nullptr) {
        return;
    }

    for (const auto& packet : flow.packets) {
        observe_capture_packet_statistics(*packet_statistics, packet, true);
    }
}

template <typename Connection, typename Table>
bool read_connection_table_chunk_into(
    std::istream& stream,
    Table& table,
    CapturePacketStatistics* const packet_statistics
) {
    std::uint64_t connection_count {0};
    if (!read_u64(stream, connection_count) ||
        connection_count > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
        return false;
    }

    for (std::uint64_t index = 0; index < connection_count; ++index) {
        Connection connection {};
        if (!read_connection(stream, connection)) {
            return false;
        }

        if (table.find(connection.key) != nullptr) {
            return false;
        }

        if (connection.has_flow_a) {
            accumulate_flow_packet_statistics(connection.flow_a, packet_statistics);
        }
        if (connection.has_flow_b) {
            accumulate_flow_packet_statistics(connection.flow_b, packet_statistics);
        }

        table.get_or_create(connection.key) = std::move(connection);
    }

    return true;
}

bool read_connection_table_chunk(
    std::istream& stream,
    ConnectionTableV4& table,
    CapturePacketStatistics* const packet_statistics
) {
    return read_connection_table_chunk_into<ConnectionV4>(stream, table, packet_statistics);
}

bool read_connection_table_chunk(
    std::istream& stream,
    ConnectionTableV6& table,
    CapturePacketStatistics* const packet_statistics
) {
    return read_connection_table_chunk_into<ConnectionV6>(stream, table, packet_statistics);
}

bool read_connection_table(
    std::istream& stream,
    ConnectionTableV4& table,
    CapturePacketStatistics* const packet_statistics
) {
    table.clear();
    if (!read_connection_table_chunk(stream, table, packet_statistics)) {
        table.clear();
        return false;
    }

    return true;
}

bool read_connection_table(
    std::istream& stream,
    ConnectionTableV6& table,
    CapturePacketStatistics* const packet_statistics
) {
    table.clear();
    if (!read_connection_table_chunk(stream, table, packet_statistics)) {
        table.clear();
        return false;
    }

    return true;
}

bool write_protocol_path_registry(std::ostream& stream, const ProtocolPathRegistry& registry) {
    return write_protocol_path_registry(stream, registry, {});
}

bool write_protocol_path_registry(
    std::ostream& stream,
    const ProtocolPathRegistry& registry,
    const SerializationProgressCallback& progress_callback
) {
    if (!write_u64(stream, static_cast<std::uint64_t>(registry.size()))) {
        return false;
    }

    if (registry.size() == 0U && !report_serialization_progress(progress_callback, 0U, 0U)) {
        return false;
    }

    for (std::size_t index = 0U; index < registry.size(); ++index) {
        const auto id = static_cast<ProtocolPathId>(index + 1U);
        const auto* path = registry.find(id);
        if (path == nullptr || !write_protocol_path(stream, *path)) {
            return false;
        }

        const auto processed = static_cast<std::uint64_t>(index + 1U);
        const auto total = static_cast<std::uint64_t>(registry.size());
        if (((processed % kSerializationProgressReportInterval) == 0U || processed == total) &&
            !report_serialization_progress(progress_callback, processed, total)) {
            return false;
        }
    }

    return true;
}

bool read_protocol_path_registry(std::istream& stream, ProtocolPathRegistry& registry) {
    std::uint64_t path_count {0};
    if (!read_u64(stream, path_count) ||
        path_count > static_cast<std::uint64_t>(std::numeric_limits<ProtocolPathId>::max())) {
        return false;
    }

    registry = {};
    for (std::uint64_t index = 0; index < path_count; ++index) {
        ProtocolPath path {};
        if (!read_protocol_path(stream, path)) {
            registry = {};
            return false;
        }

        const auto expected_id = static_cast<ProtocolPathId>(index + 1U);
        if (registry.intern(std::move(path)) != expected_id) {
            registry = {};
            return false;
        }
    }

    return true;
}

bool write_unrecognized_packet_records(
    std::ostream& stream,
    std::span<const UnrecognizedPacketRecord> records
) {
    return write_unrecognized_packet_records(stream, records, {});
}

bool write_unrecognized_packet_records(
    std::ostream& stream,
    std::span<const UnrecognizedPacketRecord> records,
    const SerializationProgressCallback& progress_callback
) {
    if (!write_u64(stream, static_cast<std::uint64_t>(records.size()))) {
        return false;
    }

    if (records.empty() && !report_serialization_progress(progress_callback, 0U, 0U)) {
        return false;
    }

    for (std::size_t index = 0U; index < records.size(); ++index) {
        const auto& record = records[index];
        if (!write_packet_ref(stream, record.packet) || !write_string(stream, record.reason_text)) {
            return false;
        }

        const auto processed = static_cast<std::uint64_t>(index + 1U);
        const auto total = static_cast<std::uint64_t>(records.size());
        if (((processed % kSerializationProgressReportInterval) == 0U || processed == total) &&
            !report_serialization_progress(progress_callback, processed, total)) {
            return false;
        }
    }

    return true;
}

bool read_unrecognized_packet_records(
    std::istream& stream,
    std::vector<UnrecognizedPacketRecord>& records,
    CapturePacketStatistics* const packet_statistics
) {
    std::uint64_t record_count {0};
    if (!read_u64(stream, record_count) ||
        record_count > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
        return false;
    }

    records.clear();
    records.reserve(static_cast<std::size_t>(record_count));
    for (std::uint64_t index = 0U; index < record_count; ++index) {
        UnrecognizedPacketRecord record {};
        if (!read_packet_ref(stream, record.packet) || !read_string(stream, record.reason_text)) {
            records.clear();
            return false;
        }
        if (packet_statistics != nullptr) {
            observe_capture_packet_statistics(*packet_statistics, record.packet, false);
        }
        records.push_back(std::move(record));
    }

    return true;
}

bool write_capture_packet_locator(
    std::ostream& stream,
    std::span<const CapturePacketLocatorEntry> entries
) {
    if (!write_u64(stream, static_cast<std::uint64_t>(entries.size()))) {
        return false;
    }

    for (const auto& entry : entries) {
        if (!write_u64(stream, entry.packet_index) || !write_u64(stream, entry.file_offset)) {
            return false;
        }
    }

    return true;
}

bool read_capture_packet_locator(
    std::istream& stream,
    std::vector<CapturePacketLocatorEntry>& entries
) {
    std::uint64_t entry_count {0};
    if (!read_u64(stream, entry_count) ||
        entry_count > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
        return false;
    }

    entries.clear();
    entries.reserve(static_cast<std::size_t>(entry_count));

    std::optional<std::uint64_t> previous_packet_index {};
    std::optional<std::uint64_t> previous_file_offset {};
    for (std::uint64_t index = 0U; index < entry_count; ++index) {
        CapturePacketLocatorEntry entry {};
        if (!read_u64(stream, entry.packet_index) || !read_u64(stream, entry.file_offset)) {
            entries.clear();
            return false;
        }

        if ((previous_packet_index.has_value() && entry.packet_index <= *previous_packet_index) ||
            (previous_file_offset.has_value() && entry.file_offset <= *previous_file_offset)) {
            entries.clear();
            return false;
        }

        previous_packet_index = entry.packet_index;
        previous_file_offset = entry.file_offset;
        entries.push_back(entry);
    }

    return true;
}

namespace {

enum class CaptureStatisticsSnapshotPayloadReadStatus : std::uint8_t {
    ok = 0,
    malformed_payload,
    snapshot_semantic_inconsistency,
};

struct CaptureStatisticsSnapshotPayloadReadResult {
    CaptureStatisticsSnapshotPayloadReadStatus status {CaptureStatisticsSnapshotPayloadReadStatus::ok};
    std::optional<CaptureStatisticsSnapshotValidationError> validation_error {};

    [[nodiscard]] explicit operator bool() const noexcept {
        return status == CaptureStatisticsSnapshotPayloadReadStatus::ok;
    }
};

template <typename Enum>
bool write_enum_u8(std::ostream& stream, const Enum value) {
    return write_u8(stream, static_cast<std::uint8_t>(value));
}

template <typename Enum, typename Validator>
bool read_validated_enum_u8(
    std::istream& stream,
    Enum& value,
    Validator is_valid
) {
    std::uint8_t raw_value {0};
    if (!read_u8(stream, raw_value) || !is_valid(raw_value)) {
        return false;
    }

    value = static_cast<Enum>(raw_value);
    return true;
}

bool is_valid_protocol_id(const std::uint8_t value) noexcept {
    switch (static_cast<ProtocolId>(value)) {
    case ProtocolId::unknown:
    case ProtocolId::icmp:
    case ProtocolId::igmp:
    case ProtocolId::tcp:
    case ProtocolId::udp:
    case ProtocolId::esp:
    case ProtocolId::icmpv6:
    case ProtocolId::sctp:
    case ProtocolId::arp:
        return true;
    default:
        return false;
    }
}

bool is_valid_flow_protocol_hint(const std::uint8_t value) noexcept {
    return value <= static_cast<std::uint8_t>(FlowProtocolHint::igmpv3);
}

bool is_valid_capture_statistics_scope(const std::uint8_t value) noexcept {
    return value <= static_cast<std::uint8_t>(CaptureStatisticsScope::reserved_unknown);
}

bool is_valid_capture_statistics_address_family(const std::uint8_t value) noexcept {
    return value <= static_cast<std::uint8_t>(CaptureStatisticsAddressFamily::ipv6);
}

bool write_capture_statistics_endpoint_identity(
    std::ostream& stream,
    const CaptureStatisticsEndpointIdentity& endpoint
) {
    if (std::holds_alternative<EndpointKeyV4>(endpoint)) {
        return write_enum_u8(stream, CaptureStatisticsAddressFamily::ipv4) &&
               write_endpoint_key(stream, std::get<EndpointKeyV4>(endpoint));
    }

    return write_enum_u8(stream, CaptureStatisticsAddressFamily::ipv6) &&
           write_endpoint_key(stream, std::get<EndpointKeyV6>(endpoint));
}

bool read_capture_statistics_endpoint_identity(
    std::istream& stream,
    CaptureStatisticsEndpointIdentity& endpoint
) {
    CaptureStatisticsAddressFamily family {CaptureStatisticsAddressFamily::ipv4};
    if (!read_validated_enum_u8(stream, family, is_valid_capture_statistics_address_family)) {
        return false;
    }

    if (family == CaptureStatisticsAddressFamily::ipv4) {
        EndpointKeyV4 endpoint_v4 {};
        if (!read_endpoint_key(stream, endpoint_v4)) {
            return false;
        }
        endpoint = endpoint_v4;
        return true;
    }

    EndpointKeyV6 endpoint_v6 {};
    if (!read_endpoint_key(stream, endpoint_v6)) {
        return false;
    }
    endpoint = endpoint_v6;
    return true;
}

bool write_capture_statistics_endpoint_identity_for_family(
    std::ostream& stream,
    const CaptureStatisticsEndpointIdentity& endpoint,
    const CaptureStatisticsAddressFamily family
) {
    if (family == CaptureStatisticsAddressFamily::ipv4) {
        return std::holds_alternative<EndpointKeyV4>(endpoint) &&
               write_endpoint_key(stream, std::get<EndpointKeyV4>(endpoint));
    }

    return std::holds_alternative<EndpointKeyV6>(endpoint) &&
           write_endpoint_key(stream, std::get<EndpointKeyV6>(endpoint));
}

bool read_capture_statistics_endpoint_identity_for_family(
    std::istream& stream,
    CaptureStatisticsEndpointIdentity& endpoint,
    const CaptureStatisticsAddressFamily family
) {
    if (family == CaptureStatisticsAddressFamily::ipv4) {
        EndpointKeyV4 endpoint_v4 {};
        if (!read_endpoint_key(stream, endpoint_v4)) {
            return false;
        }
        endpoint = endpoint_v4;
        return true;
    }

    EndpointKeyV6 endpoint_v6 {};
    if (!read_endpoint_key(stream, endpoint_v6)) {
        return false;
    }
    endpoint = endpoint_v6;
    return true;
}

bool write_connection_key_for_capture_statistics_family(
    std::ostream& stream,
    const CaptureStatisticsConnectionKey& connection_key,
    const CaptureStatisticsAddressFamily family
) {
    if (family == CaptureStatisticsAddressFamily::ipv4) {
        return std::holds_alternative<ConnectionKeyV4>(connection_key) &&
               write_connection_key(stream, std::get<ConnectionKeyV4>(connection_key));
    }

    return std::holds_alternative<ConnectionKeyV6>(connection_key) &&
           write_connection_key(stream, std::get<ConnectionKeyV6>(connection_key));
}

bool read_connection_key_for_capture_statistics_family(
    std::istream& stream,
    CaptureStatisticsConnectionKey& connection_key,
    const CaptureStatisticsAddressFamily family
) {
    if (family == CaptureStatisticsAddressFamily::ipv4) {
        ConnectionKeyV4 key {};
        if (!read_connection_key(stream, key) || !is_valid_protocol_id(static_cast<std::uint8_t>(key.protocol))) {
            return false;
        }
        connection_key = key;
        return true;
    }

    ConnectionKeyV6 key {};
    if (!read_connection_key(stream, key) || !is_valid_protocol_id(static_cast<std::uint8_t>(key.protocol))) {
        return false;
    }
    connection_key = key;
    return true;
}

bool write_bounded_string(std::ostream& stream, const std::string& value, const std::uint32_t max_bytes) {
    return value.size() <= max_bytes && write_string(stream, value);
}

bool read_bounded_string(std::istream& stream, std::string& value, const std::uint32_t max_bytes) {
    std::uint32_t length {0};
    if (!read_u32(stream, length) || length > max_bytes) {
        return false;
    }

    value.assign(length, '\0');
    if (length == 0U) {
        return true;
    }

    auto bytes = std::span<std::uint8_t>(reinterpret_cast<std::uint8_t*>(value.data()), value.size());
    return read_bytes(stream, bytes);
}

bool write_capture_statistics_protocol_counters(
    std::ostream& stream,
    const CaptureStatisticsProtocolCounters& counters
) {
    return write_u64(stream, counters.flow_count) &&
           write_u64(stream, counters.packet_count) &&
           write_u64(stream, counters.captured_bytes) &&
           write_u64(stream, counters.original_bytes);
}

bool read_capture_statistics_protocol_counters(
    std::istream& stream,
    CaptureStatisticsProtocolCounters& counters
) {
    return read_u64(stream, counters.flow_count) &&
           read_u64(stream, counters.packet_count) &&
           read_u64(stream, counters.captured_bytes) &&
           read_u64(stream, counters.original_bytes);
}

CaptureStatisticsSnapshotPayloadReadResult finalize_capture_statistics_snapshot_decode(
    std::istream& stream,
    CaptureStatisticsSnapshot& snapshot,
    CaptureStatisticsSnapshot&& decoded
) {
    if (stream.peek() != std::char_traits<char>::eof()) {
        return CaptureStatisticsSnapshotPayloadReadResult {
            .status = CaptureStatisticsSnapshotPayloadReadStatus::malformed_payload,
        };
    }

    const auto validation = validate_capture_statistics_snapshot(decoded);
    if (!validation.ok) {
        return CaptureStatisticsSnapshotPayloadReadResult {
            .status = CaptureStatisticsSnapshotPayloadReadStatus::snapshot_semantic_inconsistency,
            .validation_error = validation.error,
        };
    }

    snapshot = std::move(decoded);
    return {};
}

}  // namespace

bool write_capture_statistics_snapshot(
    std::ostream& stream,
    const CaptureStatisticsSnapshot& snapshot
) {
    if (!write_enum_u8(stream, snapshot.scope) ||
        !write_u64(stream, snapshot.total_packet_count) ||
        !write_u64(stream, snapshot.total_flow_count) ||
        !write_u64(stream, snapshot.total_captured_bytes) ||
        !write_u64(stream, snapshot.total_original_bytes) ||
        !write_u8(stream, snapshot.timestamp_range.available ? 1U : 0U) ||
        !write_u64(stream, snapshot.timestamp_range.earliest_timestamp_us) ||
        !write_u64(stream, snapshot.timestamp_range.latest_timestamp_us) ||
        !write_u64(stream, snapshot.truncated_packet_count) ||
        !write_u32(stream, snapshot.maximum_captured_packet_length) ||
        !write_u32(stream, snapshot.maximum_original_packet_length) ||
        !write_u64(stream, snapshot.captured_packet_size_distribution.maximum_bucket_packet_count) ||
        !write_u32(stream, static_cast<std::uint32_t>(snapshot.captured_packet_size_distribution.buckets.size()))) {
        return false;
    }

    for (const auto& bucket : snapshot.captured_packet_size_distribution.buckets) {
        if (!write_u64(stream, bucket.packet_count)) {
            return false;
        }
    }

    if (!write_u64(stream, snapshot.original_packet_size_distribution.maximum_bucket_packet_count) ||
        !write_u32(stream, static_cast<std::uint32_t>(snapshot.original_packet_size_distribution.buckets.size()))) {
        return false;
    }
    for (const auto& bucket : snapshot.original_packet_size_distribution.buckets) {
        if (!write_u64(stream, bucket.packet_count)) {
            return false;
        }
    }

    if (!write_u64(stream, snapshot.unrecognized_packet_count) ||
        !write_u64(stream, snapshot.unrecognized_captured_bytes) ||
        !write_u64(stream, snapshot.unrecognized_original_bytes) ||
        !write_u64(stream, snapshot.only_a_to_b_flow_count) ||
        !write_u64(stream, snapshot.service_recognized_flow_count) ||
        !write_u64(stream, snapshot.packet_direction_distribution.mostly_a_to_b_flow_count) ||
        !write_u64(stream, snapshot.packet_direction_distribution.balanced_flow_count) ||
        !write_u64(stream, snapshot.packet_direction_distribution.mostly_b_to_a_flow_count) ||
        !write_u64(stream, snapshot.original_byte_direction_distribution.mostly_a_to_b_flow_count) ||
        !write_u64(stream, snapshot.original_byte_direction_distribution.balanced_flow_count) ||
        !write_u64(stream, snapshot.original_byte_direction_distribution.mostly_b_to_a_flow_count) ||
        !write_u64(stream, snapshot.tcp_flags.syn_packet_count) ||
        !write_u64(stream, snapshot.tcp_flags.fin_packet_count) ||
        !write_u64(stream, snapshot.tcp_flags.rst_packet_count) ||
        !write_u64(stream, snapshot.flow_packet_count_histogram.total_flow_count) ||
        !write_u64(stream, snapshot.flow_packet_count_histogram.total_captured_byte_count) ||
        !write_u64(stream, snapshot.flow_packet_count_histogram.total_original_byte_count) ||
        !write_u64(stream, snapshot.flow_packet_count_histogram.maximum_bucket_flow_count) ||
        !write_u64(stream, snapshot.flow_packet_count_histogram.maximum_bucket_captured_byte_count) ||
        !write_u64(stream, snapshot.flow_packet_count_histogram.maximum_bucket_original_byte_count) ||
        !write_u64(stream, snapshot.flow_packet_count_histogram.excluded_zero_packet_flow_count) ||
        !write_u64(stream, snapshot.flow_packet_count_histogram.excluded_zero_packet_captured_byte_count) ||
        !write_u64(stream, snapshot.flow_packet_count_histogram.excluded_zero_packet_original_byte_count) ||
        !write_u32(stream, static_cast<std::uint32_t>(snapshot.flow_packet_count_histogram.buckets.size()))) {
        return false;
    }

    for (const auto& bucket : snapshot.flow_packet_count_histogram.buckets) {
        if (!write_u64(stream, bucket.flow_count) ||
            !write_u64(stream, bucket.captured_byte_count) ||
            !write_u64(stream, bucket.original_byte_count)) {
            return false;
        }
    }

    if (!write_u32(stream, static_cast<std::uint32_t>(snapshot.transport_protocols.size()))) {
        return false;
    }
    for (const auto& row : snapshot.transport_protocols) {
        if (!write_enum_u8(stream, row.category) ||
            !write_capture_statistics_protocol_counters(stream, row.counters)) {
            return false;
        }
    }

    if (!write_u32(stream, static_cast<std::uint32_t>(snapshot.ip_families.size()))) {
        return false;
    }
    for (const auto& row : snapshot.ip_families) {
        if (!write_enum_u8(stream, row.category) ||
            !write_capture_statistics_protocol_counters(stream, row.counters)) {
            return false;
        }
    }

    if (!write_u32(stream, static_cast<std::uint32_t>(snapshot.detected_protocols.size()))) {
        return false;
    }
    for (const auto& row : snapshot.detected_protocols) {
        if (!write_enum_u8(stream, row.category) ||
            !write_capture_statistics_protocol_counters(stream, row.counters)) {
            return false;
        }
    }

    if (!write_u64(stream, snapshot.quic_recognition.flow_count) ||
        !write_u64(stream, snapshot.quic_recognition.with_sni_count) ||
        !write_u64(stream, snapshot.quic_recognition.without_sni_count) ||
        !write_u64(stream, snapshot.quic_recognition.v1_count) ||
        !write_u64(stream, snapshot.quic_recognition.draft29_count) ||
        !write_u64(stream, snapshot.quic_recognition.v2_count) ||
        !write_u64(stream, snapshot.quic_recognition.version_unavailable_count) ||
        !write_u64(stream, snapshot.tls_recognition.flow_count) ||
        !write_u64(stream, snapshot.tls_recognition.with_sni_count) ||
        !write_u64(stream, snapshot.tls_recognition.without_sni_count) ||
        !write_u64(stream, snapshot.tls_recognition.tls12_count) ||
        !write_u64(stream, snapshot.tls_recognition.tls13_count) ||
        !write_u64(stream, snapshot.tls_recognition.version_unavailable_count) ||
        !write_u32(stream, static_cast<std::uint32_t>(snapshot.top_endpoints.size()))) {
        return false;
    }

    for (const auto& row : snapshot.top_endpoints) {
        if (!write_capture_statistics_endpoint_identity(stream, row.endpoint) ||
            !write_u64(stream, row.flow_count) ||
            !write_u64(stream, row.packet_count) ||
            !write_u64(stream, row.captured_bytes) ||
            !write_u64(stream, row.original_bytes)) {
            return false;
        }
    }

    if (!write_u32(stream, static_cast<std::uint32_t>(snapshot.top_ports.size()))) {
        return false;
    }
    for (const auto& row : snapshot.top_ports) {
        if (!write_u16(stream, row.port) ||
            !write_u64(stream, row.flow_count) ||
            !write_u64(stream, row.packet_count) ||
            !write_u64(stream, row.captured_bytes) ||
            !write_u64(stream, row.original_bytes)) {
            return false;
        }
    }

    if (!write_u32(stream, static_cast<std::uint32_t>(snapshot.top_flows.size()))) {
        return false;
    }
    for (const auto& row : snapshot.top_flows) {
        if (!write_u32(stream, row.canonical_flow_ordinal) ||
            !write_enum_u8(stream, row.family) ||
            !write_connection_key_for_capture_statistics_family(stream, row.connection_key, row.family) ||
            !write_capture_statistics_endpoint_identity_for_family(stream, row.endpoint_a, row.family) ||
            !write_capture_statistics_endpoint_identity_for_family(stream, row.endpoint_b, row.family) ||
            !write_u8(stream, static_cast<std::uint8_t>(row.flow_protocol)) ||
            !write_u8(stream, static_cast<std::uint8_t>(row.protocol_hint)) ||
            !write_bounded_string(stream, row.service_hint, kMaxCaptureStatisticsSnapshotServiceHintBytes) ||
            !write_u32(stream, row.protocol_path_id) ||
            !write_u64(stream, row.packet_count) ||
            !write_u64(stream, row.captured_bytes) ||
            !write_u64(stream, row.original_bytes)) {
            return false;
        }
    }

    return true;
}

namespace {

CaptureStatisticsSnapshotPayloadReadResult read_capture_statistics_snapshot_payload(
    std::istream& stream,
    CaptureStatisticsSnapshot& snapshot
) {
    CaptureStatisticsSnapshot decoded {};
    if (!read_validated_enum_u8(stream, decoded.scope, is_valid_capture_statistics_scope) ||
        !read_u64(stream, decoded.total_packet_count) ||
        !read_u64(stream, decoded.total_flow_count) ||
        !read_u64(stream, decoded.total_captured_bytes) ||
        !read_u64(stream, decoded.total_original_bytes)) {
        return CaptureStatisticsSnapshotPayloadReadResult {
            .status = CaptureStatisticsSnapshotPayloadReadStatus::malformed_payload,
        };
    }

    std::uint8_t timestamp_available {0};
    std::uint32_t bucket_count {0};
    if (!read_u8(stream, timestamp_available) ||
        (timestamp_available != 0U && timestamp_available != 1U) ||
        !read_u64(stream, decoded.timestamp_range.earliest_timestamp_us) ||
        !read_u64(stream, decoded.timestamp_range.latest_timestamp_us) ||
        !read_u64(stream, decoded.truncated_packet_count) ||
        !read_u32(stream, decoded.maximum_captured_packet_length) ||
        !read_u32(stream, decoded.maximum_original_packet_length) ||
        !read_u64(stream, decoded.captured_packet_size_distribution.maximum_bucket_packet_count) ||
        !read_u32(stream, bucket_count) ||
        bucket_count != decoded.captured_packet_size_distribution.buckets.size()) {
        return CaptureStatisticsSnapshotPayloadReadResult {
            .status = CaptureStatisticsSnapshotPayloadReadStatus::malformed_payload,
        };
    }
    decoded.timestamp_range.available = timestamp_available != 0U;

    for (auto& bucket : decoded.captured_packet_size_distribution.buckets) {
        if (!read_u64(stream, bucket.packet_count)) {
            return CaptureStatisticsSnapshotPayloadReadResult {
                .status = CaptureStatisticsSnapshotPayloadReadStatus::malformed_payload,
            };
        }
    }

    if (!read_u64(stream, decoded.original_packet_size_distribution.maximum_bucket_packet_count) ||
        !read_u32(stream, bucket_count) ||
        bucket_count != decoded.original_packet_size_distribution.buckets.size()) {
        return CaptureStatisticsSnapshotPayloadReadResult {
            .status = CaptureStatisticsSnapshotPayloadReadStatus::malformed_payload,
        };
    }
    for (auto& bucket : decoded.original_packet_size_distribution.buckets) {
        if (!read_u64(stream, bucket.packet_count)) {
            return CaptureStatisticsSnapshotPayloadReadResult {
                .status = CaptureStatisticsSnapshotPayloadReadStatus::malformed_payload,
            };
        }
    }

    if (!read_u64(stream, decoded.unrecognized_packet_count) ||
        !read_u64(stream, decoded.unrecognized_captured_bytes) ||
        !read_u64(stream, decoded.unrecognized_original_bytes) ||
        !read_u64(stream, decoded.only_a_to_b_flow_count) ||
        !read_u64(stream, decoded.service_recognized_flow_count) ||
        !read_u64(stream, decoded.packet_direction_distribution.mostly_a_to_b_flow_count) ||
        !read_u64(stream, decoded.packet_direction_distribution.balanced_flow_count) ||
        !read_u64(stream, decoded.packet_direction_distribution.mostly_b_to_a_flow_count) ||
        !read_u64(stream, decoded.original_byte_direction_distribution.mostly_a_to_b_flow_count) ||
        !read_u64(stream, decoded.original_byte_direction_distribution.balanced_flow_count) ||
        !read_u64(stream, decoded.original_byte_direction_distribution.mostly_b_to_a_flow_count) ||
        !read_u64(stream, decoded.tcp_flags.syn_packet_count) ||
        !read_u64(stream, decoded.tcp_flags.fin_packet_count) ||
        !read_u64(stream, decoded.tcp_flags.rst_packet_count) ||
        !read_u64(stream, decoded.flow_packet_count_histogram.total_flow_count) ||
        !read_u64(stream, decoded.flow_packet_count_histogram.total_captured_byte_count) ||
        !read_u64(stream, decoded.flow_packet_count_histogram.total_original_byte_count) ||
        !read_u64(stream, decoded.flow_packet_count_histogram.maximum_bucket_flow_count) ||
        !read_u64(stream, decoded.flow_packet_count_histogram.maximum_bucket_captured_byte_count) ||
        !read_u64(stream, decoded.flow_packet_count_histogram.maximum_bucket_original_byte_count) ||
        !read_u64(stream, decoded.flow_packet_count_histogram.excluded_zero_packet_flow_count) ||
        !read_u64(stream, decoded.flow_packet_count_histogram.excluded_zero_packet_captured_byte_count) ||
        !read_u64(stream, decoded.flow_packet_count_histogram.excluded_zero_packet_original_byte_count) ||
        !read_u32(stream, bucket_count) ||
        bucket_count != decoded.flow_packet_count_histogram.buckets.size()) {
        return CaptureStatisticsSnapshotPayloadReadResult {
            .status = CaptureStatisticsSnapshotPayloadReadStatus::malformed_payload,
        };
    }

    for (auto& bucket : decoded.flow_packet_count_histogram.buckets) {
        if (!read_u64(stream, bucket.flow_count) ||
            !read_u64(stream, bucket.captured_byte_count) ||
            !read_u64(stream, bucket.original_byte_count)) {
            return CaptureStatisticsSnapshotPayloadReadResult {
                .status = CaptureStatisticsSnapshotPayloadReadStatus::malformed_payload,
            };
        }
    }

    std::uint32_t row_count {0};
    if (!read_u32(stream, row_count) ||
        row_count > static_cast<std::uint32_t>(std::numeric_limits<std::size_t>::max())) {
        return CaptureStatisticsSnapshotPayloadReadResult {
            .status = CaptureStatisticsSnapshotPayloadReadStatus::malformed_payload,
        };
    }
    decoded.transport_protocols.clear();
    decoded.transport_protocols.reserve(row_count);
    for (std::uint32_t index = 0U; index < row_count; ++index) {
        CaptureStatisticsTransportProtocolRow row {};
        if (!read_validated_enum_u8(stream, row.category, [](const std::uint8_t value) {
                return value <= static_cast<std::uint8_t>(CaptureStatisticsTransportProtocolCategory::other);
            }) ||
            !read_capture_statistics_protocol_counters(stream, row.counters)) {
            return CaptureStatisticsSnapshotPayloadReadResult {
                .status = CaptureStatisticsSnapshotPayloadReadStatus::malformed_payload,
            };
        }
        decoded.transport_protocols.push_back(row);
    }

    if (!read_u32(stream, row_count) ||
        row_count > static_cast<std::uint32_t>(std::numeric_limits<std::size_t>::max())) {
        return CaptureStatisticsSnapshotPayloadReadResult {
            .status = CaptureStatisticsSnapshotPayloadReadStatus::malformed_payload,
        };
    }
    decoded.ip_families.clear();
    decoded.ip_families.reserve(row_count);
    for (std::uint32_t index = 0U; index < row_count; ++index) {
        CaptureStatisticsIpFamilyRow row {};
        if (!read_validated_enum_u8(stream, row.category, [](const std::uint8_t value) {
                return value <= static_cast<std::uint8_t>(CaptureStatisticsIpFamilyCategory::ipv6);
            }) ||
            !read_capture_statistics_protocol_counters(stream, row.counters)) {
            return CaptureStatisticsSnapshotPayloadReadResult {
                .status = CaptureStatisticsSnapshotPayloadReadStatus::malformed_payload,
            };
        }
        decoded.ip_families.push_back(row);
    }

    if (!read_u32(stream, row_count) ||
        row_count > static_cast<std::uint32_t>(std::numeric_limits<std::size_t>::max())) {
        return CaptureStatisticsSnapshotPayloadReadResult {
            .status = CaptureStatisticsSnapshotPayloadReadStatus::malformed_payload,
        };
    }
    decoded.detected_protocols.clear();
    decoded.detected_protocols.reserve(row_count);
    for (std::uint32_t index = 0U; index < row_count; ++index) {
        CaptureStatisticsDetectedProtocolRow row {};
        if (!read_validated_enum_u8(stream, row.category, [](const std::uint8_t value) {
                return value <= static_cast<std::uint8_t>(CaptureStatisticsDetectedProtocolCategory::unknown_without_possible);
            }) ||
            !read_capture_statistics_protocol_counters(stream, row.counters)) {
            return CaptureStatisticsSnapshotPayloadReadResult {
                .status = CaptureStatisticsSnapshotPayloadReadStatus::malformed_payload,
            };
        }
        decoded.detected_protocols.push_back(row);
    }

    if (!read_u64(stream, decoded.quic_recognition.flow_count) ||
        !read_u64(stream, decoded.quic_recognition.with_sni_count) ||
        !read_u64(stream, decoded.quic_recognition.without_sni_count) ||
        !read_u64(stream, decoded.quic_recognition.v1_count) ||
        !read_u64(stream, decoded.quic_recognition.draft29_count) ||
        !read_u64(stream, decoded.quic_recognition.v2_count) ||
        !read_u64(stream, decoded.quic_recognition.version_unavailable_count) ||
        !read_u64(stream, decoded.tls_recognition.flow_count) ||
        !read_u64(stream, decoded.tls_recognition.with_sni_count) ||
        !read_u64(stream, decoded.tls_recognition.without_sni_count) ||
        !read_u64(stream, decoded.tls_recognition.tls12_count) ||
        !read_u64(stream, decoded.tls_recognition.tls13_count) ||
        !read_u64(stream, decoded.tls_recognition.version_unavailable_count) ||
        !read_u32(stream, row_count) ||
        row_count > kCaptureStatisticsSnapshotTopEndpointCapacity) {
        return CaptureStatisticsSnapshotPayloadReadResult {
            .status = CaptureStatisticsSnapshotPayloadReadStatus::malformed_payload,
        };
    }

    decoded.top_endpoints.clear();
    decoded.top_endpoints.reserve(row_count);
    for (std::uint32_t index = 0U; index < row_count; ++index) {
        CaptureStatisticsTopEndpointRow row {};
        if (!read_capture_statistics_endpoint_identity(stream, row.endpoint) ||
            !read_u64(stream, row.flow_count) ||
            !read_u64(stream, row.packet_count) ||
            !read_u64(stream, row.captured_bytes) ||
            !read_u64(stream, row.original_bytes)) {
            return CaptureStatisticsSnapshotPayloadReadResult {
                .status = CaptureStatisticsSnapshotPayloadReadStatus::malformed_payload,
            };
        }
        decoded.top_endpoints.push_back(std::move(row));
    }

    if (!read_u32(stream, row_count) || row_count > kCaptureStatisticsSnapshotTopPortCapacity) {
        return CaptureStatisticsSnapshotPayloadReadResult {
            .status = CaptureStatisticsSnapshotPayloadReadStatus::malformed_payload,
        };
    }
    decoded.top_ports.clear();
    decoded.top_ports.reserve(row_count);
    for (std::uint32_t index = 0U; index < row_count; ++index) {
        CaptureStatisticsTopPortRow row {};
        if (!read_u16(stream, row.port) ||
            !read_u64(stream, row.flow_count) ||
            !read_u64(stream, row.packet_count) ||
            !read_u64(stream, row.captured_bytes) ||
            !read_u64(stream, row.original_bytes)) {
            return CaptureStatisticsSnapshotPayloadReadResult {
                .status = CaptureStatisticsSnapshotPayloadReadStatus::malformed_payload,
            };
        }
        decoded.top_ports.push_back(row);
    }

    if (!read_u32(stream, row_count) || row_count > kCaptureStatisticsSnapshotTopFlowCapacity) {
        return CaptureStatisticsSnapshotPayloadReadResult {
            .status = CaptureStatisticsSnapshotPayloadReadStatus::malformed_payload,
        };
    }
    decoded.top_flows.clear();
    decoded.top_flows.reserve(row_count);
    for (std::uint32_t index = 0U; index < row_count; ++index) {
        CaptureStatisticsTopFlowRow row {};
        if (!read_u32(stream, row.canonical_flow_ordinal) ||
            !read_validated_enum_u8(stream, row.family, is_valid_capture_statistics_address_family) ||
            !read_connection_key_for_capture_statistics_family(stream, row.connection_key, row.family) ||
            !read_capture_statistics_endpoint_identity_for_family(stream, row.endpoint_a, row.family) ||
            !read_capture_statistics_endpoint_identity_for_family(stream, row.endpoint_b, row.family) ||
            !read_validated_enum_u8(stream, row.flow_protocol, is_valid_protocol_id) ||
            !read_validated_enum_u8(stream, row.protocol_hint, is_valid_flow_protocol_hint) ||
            !read_bounded_string(stream, row.service_hint, kMaxCaptureStatisticsSnapshotServiceHintBytes) ||
            !read_u32(stream, row.protocol_path_id) ||
            !read_u64(stream, row.packet_count) ||
            !read_u64(stream, row.captured_bytes) ||
            !read_u64(stream, row.original_bytes)) {
            return CaptureStatisticsSnapshotPayloadReadResult {
                .status = CaptureStatisticsSnapshotPayloadReadStatus::malformed_payload,
            };
        }
        decoded.top_flows.push_back(std::move(row));
    }

    return finalize_capture_statistics_snapshot_decode(stream, snapshot, std::move(decoded));
}

}  // namespace

bool read_capture_statistics_snapshot(
    std::istream& stream,
    CaptureStatisticsSnapshot& snapshot
) {
    return static_cast<bool>(read_capture_statistics_snapshot_payload(stream, snapshot));
}

bool write_v16_capture_statistics_snapshot_section(
    std::ostream& stream,
    const CaptureStatisticsSnapshot& snapshot
) {
    if (!validate_capture_statistics_snapshot(snapshot).ok) {
        return false;
    }

    std::ostringstream payload_stream(std::ios::binary | std::ios::out);
    if (!write_capture_statistics_snapshot(payload_stream, snapshot)) {
        return false;
    }

    const auto payload_bytes = payload_stream.str();
    if (payload_bytes.size() > max_capture_statistics_snapshot_payload_size_bytes()) {
        return false;
    }

    return write_capture_index_stable_section_header(stream, CaptureIndexStableSectionHeader {
        .section_id = static_cast<std::uint32_t>(CaptureIndexSectionId::capture_statistics_snapshot),
        .section_schema_version = kCaptureIndexStableCaptureStatisticsSnapshotSectionSchemaVersion,
        .section_flags = kCaptureIndexStableSectionFlagRequired,
        .payload_size = static_cast<std::uint64_t>(payload_bytes.size()),
    }) && write_bytes(
        stream,
        std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t*>(payload_bytes.data()),
            payload_bytes.size()
        )
    );
}

CaptureStatisticsSnapshotSectionReadResult read_v16_capture_statistics_snapshot_section(
    std::istream& stream,
    CaptureStatisticsSnapshot& snapshot
) {
    snapshot = {};

    CaptureStatisticsSnapshotSectionReadResult result {};
    if (!read_capture_index_stable_section_header(stream, result.section_header)) {
        result.status = CaptureStatisticsSnapshotSectionReadStatus::invalid_section_header;
        return result;
    }

    if (result.section_header.section_id !=
        static_cast<std::uint32_t>(CaptureIndexSectionId::capture_statistics_snapshot)) {
        result.status = CaptureStatisticsSnapshotSectionReadStatus::wrong_section_id;
        return result;
    }

    if (result.section_header.section_flags != kCaptureIndexStableSectionFlagRequired) {
        result.status = CaptureStatisticsSnapshotSectionReadStatus::invalid_section_framing;
        return result;
    }

    if (result.section_header.section_schema_version !=
        kCaptureIndexStableCaptureStatisticsSnapshotSectionSchemaVersion) {
        result.status = CaptureStatisticsSnapshotSectionReadStatus::unsupported_schema_version;
        return result;
    }

    const auto max_payload_size = max_capture_statistics_snapshot_payload_size_bytes();
    if (result.section_header.payload_size > max_payload_size) {
        result.status = CaptureStatisticsSnapshotSectionReadStatus::payload_too_large;
        return result;
    }

    std::vector<std::uint8_t> payload {};
    if (!read_bounded_section_payload(stream, result.section_header.payload_size, max_payload_size, payload)) {
        result.status = CaptureStatisticsSnapshotSectionReadStatus::truncated_payload;
        return result;
    }

    std::string payload_text {};
    payload_text.assign(payload.begin(), payload.end());
    std::istringstream payload_stream(payload_text, std::ios::binary | std::ios::in);
    const auto payload_result = read_capture_statistics_snapshot_payload(payload_stream, snapshot);
    if (payload_result.status == CaptureStatisticsSnapshotPayloadReadStatus::ok) {
        return result;
    }

    snapshot = {};
    if (payload_result.status == CaptureStatisticsSnapshotPayloadReadStatus::snapshot_semantic_inconsistency) {
        result.status = CaptureStatisticsSnapshotSectionReadStatus::snapshot_semantic_inconsistency;
        result.validation_error = payload_result.validation_error;
        return result;
    }

    result.status = CaptureStatisticsSnapshotSectionReadStatus::malformed_snapshot_payload;
    return result;
}

bool write_capture_state(std::ostream& stream, const CaptureState& state) {
    return write_capture_summary(stream, state.summary) &&
           write_protocol_path_registry(stream, state.protocol_path_registry) &&
           write_connection_table(stream, state.ipv4_connections) &&
           write_connection_table(stream, state.ipv6_connections) &&
           write_unrecognized_packet_records(stream, state.unrecognized_packets) &&
           write_capture_packet_locator(stream, state.packet_locator);
}

bool read_capture_state(
    std::istream& stream,
    CaptureState& state,
    CapturePacketStatistics* const packet_statistics
) {
    state = {};
    return read_capture_summary(stream, state.summary) &&
           read_protocol_path_registry(stream, state.protocol_path_registry) &&
           read_connection_table(stream, state.ipv4_connections, packet_statistics) &&
           read_connection_table(stream, state.ipv6_connections, packet_statistics) &&
           read_unrecognized_packet_records(stream, state.unrecognized_packets, packet_statistics) &&
           read_capture_packet_locator(stream, state.packet_locator);
}

}  // namespace pfl::detail












