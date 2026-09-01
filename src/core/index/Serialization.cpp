#include "core/index/Serialization.h"

#include <algorithm>
#include <array>
#include <iterator>
#include <limits>
#include <optional>
#include <sstream>
#include <type_traits>
#include <unordered_map>
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

bool write_protocol_path_display_statistics(
    std::ostream& stream,
    const ProtocolPathDisplayStatistics& statistics
) {
    if (!write_u64(stream, static_cast<std::uint64_t>(statistics.terminal_path_aggregates.size()))) {
        return false;
    }

    for (const auto& row : statistics.terminal_path_aggregates) {
        if (!write_u32(stream, row.protocol_path_id) ||
            !write_u64(stream, row.flow_count) ||
            !write_u64(stream, row.packet_count) ||
            !write_u64(stream, row.original_byte_count)) {
            return false;
        }
    }

    return true;
}

bool read_protocol_path_display_statistics(
    std::istream& stream,
    ProtocolPathDisplayStatistics& statistics
) {
    std::uint64_t row_count {0};
    if (!read_u64(stream, row_count) ||
        row_count > static_cast<std::uint64_t>((std::numeric_limits<std::size_t>::max)())) {
        return false;
    }

    statistics = {};
    statistics.terminal_path_aggregates.reserve(static_cast<std::size_t>(row_count));
    for (std::uint64_t index = 0U; index < row_count; ++index) {
        ProtocolPathDisplayAggregateRow row {};
        if (!read_u32(stream, row.protocol_path_id) ||
            !read_u64(stream, row.flow_count) ||
            !read_u64(stream, row.packet_count) ||
            !read_u64(stream, row.original_byte_count)) {
            statistics = {};
            return false;
        }
        statistics.terminal_path_aggregates.push_back(row);
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

namespace {

constexpr std::uint64_t kProtocolPathDisplayAggregateRowEncodedSize =
    4U + (3U * 8U);

std::optional<std::uint64_t> max_protocol_path_display_statistics_payload_size_bytes(
    const ProtocolPathRegistry& registry
) {
    const auto max_row_count = static_cast<std::uint64_t>(registry.size());
    if (max_row_count > (((std::numeric_limits<std::uint64_t>::max)() - 8U) /
                         kProtocolPathDisplayAggregateRowEncodedSize)) {
        return std::nullopt;
    }

    return 8U + (max_row_count * kProtocolPathDisplayAggregateRowEncodedSize);
}

bool read_exact_section_payload_bytes(
    std::istream& stream,
    const CaptureIndexStableSectionHeader& section_header,
    std::vector<std::uint8_t>& payload
) {
    return read_bounded_section_payload(
        stream,
        section_header.payload_size,
        section_header.payload_size,
        payload
    );
}

ProtocolPathRegistrySectionReadResult read_v16_protocol_path_registry_early_section_payload(
    std::istream& stream,
    const CaptureIndexStableSectionHeader& section_header,
    ProtocolPathRegistry& registry
) {
    registry = {};

    ProtocolPathRegistrySectionReadResult result {};
    result.section_header = section_header;

    if (section_header.section_id !=
        static_cast<std::uint32_t>(CaptureIndexSectionId::protocol_path_registry_early)) {
        result.status = ProtocolPathRegistrySectionReadStatus::wrong_section_id;
        return result;
    }

    if (section_header.section_flags != kCaptureIndexStableSectionFlagRequired) {
        result.status = ProtocolPathRegistrySectionReadStatus::invalid_section_framing;
        return result;
    }

    if (section_header.section_schema_version !=
        kCaptureIndexStableProtocolPathRegistryEarlySectionSchemaVersion) {
        result.status = ProtocolPathRegistrySectionReadStatus::unsupported_schema_version;
        return result;
    }

    std::vector<std::uint8_t> payload {};
    if (!read_exact_section_payload_bytes(stream, section_header, payload)) {
        result.status = ProtocolPathRegistrySectionReadStatus::truncated_payload;
        return result;
    }

    std::istringstream payload_stream(
        std::string(payload.begin(), payload.end()),
        std::ios::binary | std::ios::in
    );
    if (!read_protocol_path_registry(payload_stream, registry) ||
        payload_stream.peek() != std::char_traits<char>::eof()) {
        registry = {};
        result.status = ProtocolPathRegistrySectionReadStatus::malformed_protocol_path_registry_payload;
        return result;
    }

    return result;
}

ProtocolPathDisplayStatisticsSectionReadResult
read_v16_protocol_path_terminal_aggregates_section_payload(
    std::istream& stream,
    const CaptureIndexStableSectionHeader& section_header,
    const ProtocolPathRegistry& registry,
    ProtocolPathDisplayStatistics& statistics
) {
    statistics = {};

    ProtocolPathDisplayStatisticsSectionReadResult result {};
    result.section_header = section_header;

    if (section_header.section_id !=
        static_cast<std::uint32_t>(CaptureIndexSectionId::protocol_path_terminal_aggregates)) {
        result.status = ProtocolPathDisplayStatisticsSectionReadStatus::wrong_section_id;
        return result;
    }

    if (section_header.section_flags != kCaptureIndexStableSectionFlagRequired) {
        result.status = ProtocolPathDisplayStatisticsSectionReadStatus::invalid_section_framing;
        return result;
    }

    if (section_header.section_schema_version !=
        kCaptureIndexStableProtocolPathTerminalAggregatesSectionSchemaVersion) {
        result.status = ProtocolPathDisplayStatisticsSectionReadStatus::unsupported_schema_version;
        return result;
    }

    const auto max_payload_size = max_protocol_path_display_statistics_payload_size_bytes(registry);
    if (!max_payload_size.has_value() || section_header.payload_size > *max_payload_size) {
        result.status =
            ProtocolPathDisplayStatisticsSectionReadStatus::malformed_protocol_path_display_statistics_payload;
        return result;
    }

    std::vector<std::uint8_t> payload {};
    if (!read_exact_section_payload_bytes(stream, section_header, payload)) {
        result.status = ProtocolPathDisplayStatisticsSectionReadStatus::truncated_payload;
        return result;
    }

    std::istringstream payload_stream(
        std::string(payload.begin(), payload.end()),
        std::ios::binary | std::ios::in
    );
    if (!read_protocol_path_display_statistics(payload_stream, statistics) ||
        payload_stream.peek() != std::char_traits<char>::eof()) {
        statistics = {};
        result.status =
            ProtocolPathDisplayStatisticsSectionReadStatus::malformed_protocol_path_display_statistics_payload;
        return result;
    }

    const auto validation = validate_protocol_path_display_statistics(registry, statistics);
    if (!validation.ok) {
        statistics = {};
        result.status =
            ProtocolPathDisplayStatisticsSectionReadStatus::protocol_path_display_statistics_semantic_inconsistency;
        result.validation_error = validation.error;
        return result;
    }

    return result;
}

bool validate_fast_statistics_tier_cross_section_consistency(
    const CaptureIndexV16FastStatisticsTier& tier,
    std::string& error_detail
) {
    const auto display_validation = validate_protocol_path_display_statistics(
        tier.protocol_path_registry,
        tier.protocol_path_display_statistics
    );
    if (!display_validation.ok) {
        error_detail = display_validation.error.has_value()
            ? display_validation.error->message
            : "protocol path display statistics are invalid";
        return false;
    }

    std::uint64_t aggregate_flow_count {0};
    std::uint64_t aggregate_packet_count {0};
    std::uint64_t aggregate_original_byte_count {0};
    for (const auto& row : tier.protocol_path_display_statistics.terminal_path_aggregates) {
        aggregate_flow_count += row.flow_count;
        aggregate_packet_count += row.packet_count;
        aggregate_original_byte_count += row.original_byte_count;
    }

    if (aggregate_flow_count != tier.capture_statistics_snapshot.total_flow_count) {
        error_detail =
            "protocol path terminal aggregate flow counts do not match the snapshot total flow count";
        return false;
    }

    if (aggregate_packet_count > tier.capture_statistics_snapshot.total_packet_count) {
        error_detail =
            "protocol path terminal aggregate packet counts exceed the snapshot total packet count";
        return false;
    }

    if (aggregate_original_byte_count > tier.capture_statistics_snapshot.total_original_bytes) {
        error_detail =
            "protocol path terminal aggregate original-byte counts exceed the snapshot total original-byte count";
        return false;
    }

    for (std::size_t index = 0U; index < tier.capture_statistics_snapshot.top_flows.size(); ++index) {
        const auto& row = tier.capture_statistics_snapshot.top_flows[index];
        if (row.protocol_path_id == kInvalidProtocolPathId) {
            error_detail =
                "top flow row " + std::to_string(index) + " references an invalid protocol path id";
            return false;
        }

        const auto* path = tier.protocol_path_registry.find(row.protocol_path_id);
        if (path == nullptr || path->empty()) {
            error_detail =
                "top flow row " + std::to_string(index) +
                " references a protocol path that is unavailable in the early registry";
            return false;
        }
    }

    return true;
}

bool try_peek_capture_index_stable_section_header(
    std::istream& stream,
    CaptureIndexStableSectionHeader& section_header
) {
    const auto restore_offset = stream.tellg();
    if (restore_offset == std::istream::pos_type(-1)) {
        return false;
    }

    if (!read_capture_index_stable_section_header(stream, section_header)) {
        stream.clear();
        stream.seekg(restore_offset);
        return false;
    }

    stream.clear();
    stream.seekg(restore_offset);
    return static_cast<bool>(stream);
}

CaptureIndexV16FastStatisticsTierReadResult map_snapshot_section_failure(
    const CaptureStatisticsSnapshotSectionReadResult& section_result
) {
    CaptureIndexV16FastStatisticsTierReadResult result {};
    result.failed_section_header = section_result.section_header;

    switch (section_result.status) {
    case CaptureStatisticsSnapshotSectionReadStatus::invalid_section_header:
        result.status = CaptureIndexV16FastStatisticsTierReadStatus::invalid_fast_section_framing;
        break;
    case CaptureStatisticsSnapshotSectionReadStatus::wrong_section_id:
        result.status =
            section_result.section_header.section_id ==
                    static_cast<std::uint32_t>(CaptureIndexSectionId::protocol_path_registry_early)
                || section_result.section_header.section_id ==
                    static_cast<std::uint32_t>(CaptureIndexSectionId::protocol_path_terminal_aggregates)
                ? CaptureIndexV16FastStatisticsTierReadStatus::wrong_fast_section_order
                : CaptureIndexV16FastStatisticsTierReadStatus::missing_capture_statistics_snapshot_section;
        break;
    case CaptureStatisticsSnapshotSectionReadStatus::invalid_section_framing:
        result.status = CaptureIndexV16FastStatisticsTierReadStatus::invalid_fast_section_framing;
        break;
    case CaptureStatisticsSnapshotSectionReadStatus::unsupported_schema_version:
        result.status = CaptureIndexV16FastStatisticsTierReadStatus::unsupported_fast_section_schema;
        break;
    case CaptureStatisticsSnapshotSectionReadStatus::payload_too_large:
    case CaptureStatisticsSnapshotSectionReadStatus::truncated_payload:
        result.status = CaptureIndexV16FastStatisticsTierReadStatus::truncated_fast_section_payload;
        break;
    case CaptureStatisticsSnapshotSectionReadStatus::malformed_snapshot_payload:
        result.status = CaptureIndexV16FastStatisticsTierReadStatus::malformed_capture_statistics_snapshot_payload;
        break;
    case CaptureStatisticsSnapshotSectionReadStatus::snapshot_semantic_inconsistency:
        result.status =
            CaptureIndexV16FastStatisticsTierReadStatus::capture_statistics_snapshot_semantic_inconsistency;
        result.capture_statistics_validation_error = section_result.validation_error;
        break;
    case CaptureStatisticsSnapshotSectionReadStatus::ok:
        break;
    }

    return result;
}

CaptureIndexV16FastStatisticsTierReadResult map_registry_section_failure(
    const ProtocolPathRegistrySectionReadResult& section_result
) {
    CaptureIndexV16FastStatisticsTierReadResult result {};
    result.failed_section_header = section_result.section_header;

    switch (section_result.status) {
    case ProtocolPathRegistrySectionReadStatus::invalid_section_header:
        result.status = CaptureIndexV16FastStatisticsTierReadStatus::invalid_fast_section_framing;
        break;
    case ProtocolPathRegistrySectionReadStatus::wrong_section_id:
        result.status =
            section_result.section_header.section_id ==
                    static_cast<std::uint32_t>(CaptureIndexSectionId::capture_statistics_snapshot)
                ? CaptureIndexV16FastStatisticsTierReadStatus::duplicate_capture_statistics_snapshot_section
                : section_result.section_header.section_id ==
                        static_cast<std::uint32_t>(CaptureIndexSectionId::protocol_path_terminal_aggregates)
                    ? CaptureIndexV16FastStatisticsTierReadStatus::wrong_fast_section_order
                    : CaptureIndexV16FastStatisticsTierReadStatus::missing_protocol_path_registry_early_section;
        break;
    case ProtocolPathRegistrySectionReadStatus::invalid_section_framing:
        result.status = CaptureIndexV16FastStatisticsTierReadStatus::invalid_fast_section_framing;
        break;
    case ProtocolPathRegistrySectionReadStatus::unsupported_schema_version:
        result.status = CaptureIndexV16FastStatisticsTierReadStatus::unsupported_fast_section_schema;
        break;
    case ProtocolPathRegistrySectionReadStatus::truncated_payload:
        result.status = CaptureIndexV16FastStatisticsTierReadStatus::truncated_fast_section_payload;
        break;
    case ProtocolPathRegistrySectionReadStatus::malformed_protocol_path_registry_payload:
        result.status = CaptureIndexV16FastStatisticsTierReadStatus::malformed_protocol_path_registry_payload;
        break;
    case ProtocolPathRegistrySectionReadStatus::ok:
        break;
    }

    return result;
}

CaptureIndexV16FastStatisticsTierReadResult map_display_section_failure(
    const ProtocolPathDisplayStatisticsSectionReadResult& section_result
) {
    CaptureIndexV16FastStatisticsTierReadResult result {};
    result.failed_section_header = section_result.section_header;

    switch (section_result.status) {
    case ProtocolPathDisplayStatisticsSectionReadStatus::invalid_section_header:
        result.status = CaptureIndexV16FastStatisticsTierReadStatus::invalid_fast_section_framing;
        break;
    case ProtocolPathDisplayStatisticsSectionReadStatus::wrong_section_id:
        result.status =
            section_result.section_header.section_id ==
                    static_cast<std::uint32_t>(CaptureIndexSectionId::capture_statistics_snapshot)
                ? CaptureIndexV16FastStatisticsTierReadStatus::duplicate_capture_statistics_snapshot_section
                : section_result.section_header.section_id ==
                        static_cast<std::uint32_t>(CaptureIndexSectionId::protocol_path_registry_early)
                    ? CaptureIndexV16FastStatisticsTierReadStatus::duplicate_protocol_path_registry_early_section
                    : CaptureIndexV16FastStatisticsTierReadStatus::missing_protocol_path_terminal_aggregates_section;
        break;
    case ProtocolPathDisplayStatisticsSectionReadStatus::invalid_section_framing:
        result.status = CaptureIndexV16FastStatisticsTierReadStatus::invalid_fast_section_framing;
        break;
    case ProtocolPathDisplayStatisticsSectionReadStatus::unsupported_schema_version:
        result.status = CaptureIndexV16FastStatisticsTierReadStatus::unsupported_fast_section_schema;
        break;
    case ProtocolPathDisplayStatisticsSectionReadStatus::truncated_payload:
        result.status = CaptureIndexV16FastStatisticsTierReadStatus::truncated_fast_section_payload;
        break;
    case ProtocolPathDisplayStatisticsSectionReadStatus::malformed_protocol_path_display_statistics_payload:
        result.status =
            CaptureIndexV16FastStatisticsTierReadStatus::malformed_protocol_path_terminal_aggregates_payload;
        break;
    case ProtocolPathDisplayStatisticsSectionReadStatus::protocol_path_display_statistics_semantic_inconsistency:
        result.status =
            CaptureIndexV16FastStatisticsTierReadStatus::protocol_path_terminal_aggregates_semantic_inconsistency;
        result.protocol_path_validation_error = section_result.validation_error;
        break;
    case ProtocolPathDisplayStatisticsSectionReadStatus::ok:
        break;
    }

    return result;
}

}  // namespace

bool write_v16_protocol_path_registry_early_section(
    std::ostream& stream,
    const ProtocolPathRegistry& registry
) {
    std::ostringstream payload_stream(std::ios::binary | std::ios::out);
    if (!write_protocol_path_registry(payload_stream, registry)) {
        return false;
    }

    const auto payload_bytes = payload_stream.str();
    return write_capture_index_stable_section_header(stream, CaptureIndexStableSectionHeader {
        .section_id = static_cast<std::uint32_t>(CaptureIndexSectionId::protocol_path_registry_early),
        .section_schema_version = kCaptureIndexStableProtocolPathRegistryEarlySectionSchemaVersion,
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

ProtocolPathRegistrySectionReadResult read_v16_protocol_path_registry_early_section(
    std::istream& stream,
    ProtocolPathRegistry& registry
) {
    registry = {};

    ProtocolPathRegistrySectionReadResult result {};
    if (!read_capture_index_stable_section_header(stream, result.section_header)) {
        result.status = ProtocolPathRegistrySectionReadStatus::invalid_section_header;
        return result;
    }

    return read_v16_protocol_path_registry_early_section_payload(
        stream,
        result.section_header,
        registry
    );
}

bool write_v16_protocol_path_terminal_aggregates_section(
    std::ostream& stream,
    const ProtocolPathDisplayStatistics& statistics
) {
    std::ostringstream payload_stream(std::ios::binary | std::ios::out);
    if (!write_protocol_path_display_statistics(payload_stream, statistics)) {
        return false;
    }

    const auto payload_bytes = payload_stream.str();
    return write_capture_index_stable_section_header(stream, CaptureIndexStableSectionHeader {
        .section_id = static_cast<std::uint32_t>(CaptureIndexSectionId::protocol_path_terminal_aggregates),
        .section_schema_version = kCaptureIndexStableProtocolPathTerminalAggregatesSectionSchemaVersion,
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

ProtocolPathDisplayStatisticsSectionReadResult read_v16_protocol_path_terminal_aggregates_section(
    std::istream& stream,
    const ProtocolPathRegistry& registry,
    ProtocolPathDisplayStatistics& statistics
) {
    statistics = {};

    ProtocolPathDisplayStatisticsSectionReadResult result {};
    if (!read_capture_index_stable_section_header(stream, result.section_header)) {
        result.status = ProtocolPathDisplayStatisticsSectionReadStatus::invalid_section_header;
        return result;
    }

    return read_v16_protocol_path_terminal_aggregates_section_payload(
        stream,
        result.section_header,
        registry,
        statistics
    );
}

bool write_v16_fast_statistics_tier(
    std::ostream& stream,
    const CaptureIndexStableHeader& header,
    const CaptureIndexV16FastStatisticsTier& tier
) {
    if (header.magic != kStableCaptureIndexMagic ||
        header.container_format_version != kCaptureIndexStableContainerFormatVersion ||
        header.index_revision != kCaptureIndexStableV16Revision ||
        !validate_capture_statistics_snapshot(tier.capture_statistics_snapshot).ok ||
        !validate_protocol_path_display_statistics(
            tier.protocol_path_registry,
            tier.protocol_path_display_statistics
        ).ok) {
        return false;
    }

    std::string consistency_error {};
    if (!validate_fast_statistics_tier_cross_section_consistency(tier, consistency_error)) {
        return false;
    }

    return write_capture_index_stable_header(stream, header) &&
           write_v16_capture_statistics_snapshot_section(stream, tier.capture_statistics_snapshot) &&
           write_v16_protocol_path_registry_early_section(stream, tier.protocol_path_registry) &&
           write_v16_protocol_path_terminal_aggregates_section(
               stream,
               tier.protocol_path_display_statistics
           );
}

CaptureIndexV16FastStatisticsTierReadResult read_v16_fast_statistics_tier(
    std::istream& stream,
    CaptureIndexV16FastStatisticsTier& tier
) {
    tier = {};

    CaptureIndexV16FastStatisticsTierReadResult result {};
    if (!read_capture_index_stable_header(stream, result.header)) {
        result.status = CaptureIndexV16FastStatisticsTierReadStatus::invalid_header;
        return result;
    }

    if (result.header.magic != kStableCaptureIndexMagic ||
        result.header.container_format_version != kCaptureIndexStableContainerFormatVersion) {
        result.status = CaptureIndexV16FastStatisticsTierReadStatus::invalid_header;
        return result;
    }

    if (result.header.index_revision != kCaptureIndexStableV16Revision) {
        result.status = CaptureIndexV16FastStatisticsTierReadStatus::unsupported_revision;
        return result;
    }

    const auto stable_header = result.header;

    const auto snapshot_result = read_v16_capture_statistics_snapshot_section(
        stream,
        tier.capture_statistics_snapshot
    );
    if (!snapshot_result) {
        result = map_snapshot_section_failure(snapshot_result);
        result.header = stable_header;
        tier = {};
        return result;
    }

    if (stream.peek() == std::char_traits<char>::eof()) {
        result.status = CaptureIndexV16FastStatisticsTierReadStatus::missing_protocol_path_registry_early_section;
        result.header = stable_header;
        tier = {};
        return result;
    }

    const auto registry_result = read_v16_protocol_path_registry_early_section(
        stream,
        tier.protocol_path_registry
    );
    if (!registry_result) {
        result = map_registry_section_failure(registry_result);
        result.header = stable_header;
        tier = {};
        return result;
    }

    if (stream.peek() == std::char_traits<char>::eof()) {
        result.status =
            CaptureIndexV16FastStatisticsTierReadStatus::missing_protocol_path_terminal_aggregates_section;
        result.header = stable_header;
        tier = {};
        return result;
    }

    const auto display_result = read_v16_protocol_path_terminal_aggregates_section(
        stream,
        tier.protocol_path_registry,
        tier.protocol_path_display_statistics
    );
    if (!display_result) {
        result = map_display_section_failure(display_result);
        result.header = stable_header;
        tier = {};
        return result;
    }

    while (true) {
        CaptureIndexStableSectionHeader next_section_header {};
        if (!try_peek_capture_index_stable_section_header(stream, next_section_header)) {
            break;
        }

        if (next_section_header.section_id ==
            static_cast<std::uint32_t>(CaptureIndexSectionId::protocol_path_terminal_aggregates)) {
            ProtocolPathDisplayStatistics display_chunk {};
            const auto repeated_section_result = read_v16_protocol_path_terminal_aggregates_section(
                stream,
                tier.protocol_path_registry,
                display_chunk
            );
            if (!repeated_section_result) {
                result = map_display_section_failure(repeated_section_result);
                result.header = stable_header;
                tier = {};
                return result;
            }

            tier.protocol_path_display_statistics.terminal_path_aggregates.insert(
                tier.protocol_path_display_statistics.terminal_path_aggregates.end(),
                display_chunk.terminal_path_aggregates.begin(),
                display_chunk.terminal_path_aggregates.end()
            );
            continue;
        }

        if (next_section_header.section_id ==
            static_cast<std::uint32_t>(CaptureIndexSectionId::capture_statistics_snapshot)) {
            result.status =
                CaptureIndexV16FastStatisticsTierReadStatus::duplicate_capture_statistics_snapshot_section;
            result.failed_section_header = next_section_header;
            result.header = stable_header;
            tier = {};
            return result;
        }

        if (next_section_header.section_id ==
            static_cast<std::uint32_t>(CaptureIndexSectionId::protocol_path_registry_early)) {
            result.status =
                CaptureIndexV16FastStatisticsTierReadStatus::duplicate_protocol_path_registry_early_section;
            result.failed_section_header = next_section_header;
            result.header = stable_header;
            tier = {};
            return result;
        }

        break;
    }

    const auto merged_display_validation = validate_protocol_path_display_statistics(
        tier.protocol_path_registry,
        tier.protocol_path_display_statistics
    );
    if (!merged_display_validation.ok) {
        result.status =
            CaptureIndexV16FastStatisticsTierReadStatus::protocol_path_terminal_aggregates_semantic_inconsistency;
        result.protocol_path_validation_error = merged_display_validation.error;
        result.header = stable_header;
        tier = {};
        return result;
    }

    if (!validate_fast_statistics_tier_cross_section_consistency(tier, result.error_detail)) {
        result.status = CaptureIndexV16FastStatisticsTierReadStatus::fast_tier_cross_section_inconsistency;
        result.header = stable_header;
        tier = {};
        return result;
    }

    result.header = stable_header;

    return result;
}

namespace {

bool write_direction(std::ostream& stream, const Direction direction) {
    switch (direction) {
    case Direction::a_to_b:
        return write_u8(stream, 0U);
    case Direction::b_to_a:
        return write_u8(stream, 1U);
    }

    return false;
}

bool read_direction(std::istream& stream, Direction& direction) {
    std::uint8_t raw_direction {0};
    if (!read_u8(stream, raw_direction)) {
        return false;
    }

    switch (raw_direction) {
    case 0U:
        direction = Direction::a_to_b;
        return true;
    case 1U:
        direction = Direction::b_to_a;
        return true;
    default:
        return false;
    }
}

bool checked_add_u64(
    const std::uint64_t left,
    const std::uint64_t right,
    std::uint64_t& result
) noexcept {
    if (left > (std::numeric_limits<std::uint64_t>::max)() - right) {
        return false;
    }
    result = left + right;
    return true;
}

bool checked_multiply_u64(
    const std::uint64_t left,
    const std::uint64_t right,
    std::uint64_t& result
) noexcept {
    if (left == 0U || right == 0U) {
        result = 0U;
        return true;
    }
    if (left > (std::numeric_limits<std::uint64_t>::max)() / right) {
        return false;
    }
    result = left * right;
    return true;
}

std::optional<std::uint64_t> encoded_packetref_extent_length(
    const std::uint64_t packet_count
) noexcept {
    if (packet_count > (std::numeric_limits<std::uint64_t>::max)() / kCaptureIndexV16PacketRefEncodedStrideBytes) {
        return std::nullopt;
    }

    return packet_count * kCaptureIndexV16PacketRefEncodedStrideBytes;
}

std::optional<std::uint64_t> encoded_unrecognized_directory_payload_length(
    const std::uint64_t row_count
) noexcept {
    if (row_count > (((std::numeric_limits<std::uint64_t>::max)() - 8U) /
                     kCaptureIndexV16UnrecognizedDirectoryEncodedStrideBytes)) {
        return std::nullopt;
    }

    return 8U + (row_count * kCaptureIndexV16UnrecognizedDirectoryEncodedStrideBytes);
}

std::optional<std::uint64_t> encoded_packet_locator_payload_length(
    const std::uint64_t entry_count
) noexcept {
    if (entry_count > (((std::numeric_limits<std::uint64_t>::max)() - 8U) /
                       kCaptureIndexV16PacketLocatorEncodedStrideBytes)) {
        return std::nullopt;
    }

    return 8U + (entry_count * kCaptureIndexV16PacketLocatorEncodedStrideBytes);
}

template <typename DirectionalMetadata>
bool write_v16_directional_flow_metadata(std::ostream& stream, const DirectionalMetadata& row) {
    return write_flow_key(stream, row.key) &&
           write_u64(stream, row.packet_count) &&
           write_u64(stream, row.original_byte_count);
}

template <typename DirectionalMetadata>
bool read_v16_directional_flow_metadata(std::istream& stream, DirectionalMetadata& row) {
    return read_flow_key(stream, row.key) &&
           read_u64(stream, row.packet_count) &&
           read_u64(stream, row.original_byte_count);
}

template <typename ConnectionMetadata>
bool write_v16_connection_metadata_payload(
    std::ostream& stream,
    std::span<const ConnectionMetadata> rows
) {
    if (!write_u64(stream, static_cast<std::uint64_t>(rows.size()))) {
        return false;
    }

    for (const auto& row : rows) {
        if (!write_u32(stream, row.canonical_connection_ordinal) ||
            !write_connection_key(stream, row.key) ||
            !write_flow_protocol_hint(stream, row.protocol_hint) ||
            !write_string(stream, row.service_hint) ||
            !write_u8(stream, static_cast<std::uint8_t>(row.quic_version)) ||
            !write_u8(stream, static_cast<std::uint8_t>(row.tls_version)) ||
            !write_u8(stream, row.has_fragmented_packets ? 1U : 0U) ||
            !write_u64(stream, row.fragmented_packet_count) ||
            !write_connection_aggregate_stats(stream, row.aggregate_stats) ||
            !write_u8(stream, row.has_flow_a ? 1U : 0U)) {
            return false;
        }

        if (row.has_flow_a && !write_v16_directional_flow_metadata(stream, row.flow_a)) {
            return false;
        }

        if (!write_u8(stream, row.has_flow_b ? 1U : 0U)) {
            return false;
        }

        if (row.has_flow_b && !write_v16_directional_flow_metadata(stream, row.flow_b)) {
            return false;
        }
    }

    return true;
}

template <typename ConnectionMetadata>
bool read_v16_connection_metadata_payload(
    std::istream& stream,
    std::vector<ConnectionMetadata>& rows
) {
    std::uint64_t row_count {0};
    if (!read_u64(stream, row_count) ||
        row_count > static_cast<std::uint64_t>((std::numeric_limits<std::size_t>::max)())) {
        return false;
    }

    rows.clear();
    rows.reserve(static_cast<std::size_t>(row_count));
    for (std::uint64_t index = 0U; index < row_count; ++index) {
        ConnectionMetadata row {};
        std::uint8_t raw_quic_version {0};
        std::uint8_t raw_tls_version {0};
        std::uint8_t has_fragmented_packets {0};
        std::uint8_t has_flow_a {0};
        std::uint8_t has_flow_b {0};

        if (!read_u32(stream, row.canonical_connection_ordinal) ||
            !read_connection_key(stream, row.key) ||
            !read_flow_protocol_hint(stream, row.protocol_hint) ||
            !read_string(stream, row.service_hint) ||
            !read_u8(stream, raw_quic_version) ||
            !read_u8(stream, raw_tls_version) ||
            !read_u8(stream, has_fragmented_packets) ||
            !read_u64(stream, row.fragmented_packet_count) ||
            !read_connection_aggregate_stats(stream, row.aggregate_stats) ||
            !read_u8(stream, has_flow_a)) {
            return false;
        }

        row.quic_version = static_cast<QuicVersionHint>(raw_quic_version);
        row.tls_version = static_cast<TlsVersionHint>(raw_tls_version);
        row.has_fragmented_packets = has_fragmented_packets != 0U;
        row.has_flow_a = has_flow_a != 0U;

        if (row.has_flow_a && !read_v16_directional_flow_metadata(stream, row.flow_a)) {
            return false;
        }

        if (!read_u8(stream, has_flow_b)) {
            return false;
        }
        row.has_flow_b = has_flow_b != 0U;

        if (row.has_flow_b && !read_v16_directional_flow_metadata(stream, row.flow_b)) {
            return false;
        }

        rows.push_back(std::move(row));
    }

    return stream.peek() == std::char_traits<char>::eof();
}

bool read_v16_protocol_path_membership_payload(
    std::istream& stream,
    std::vector<CaptureIndexV16ProtocolPathMembershipRow>& rows
) {
    std::uint64_t row_count {0};
    if (!read_u64(stream, row_count) ||
        row_count > static_cast<std::uint64_t>((std::numeric_limits<std::size_t>::max)())) {
        return false;
    }

    rows.clear();
    rows.reserve(static_cast<std::size_t>(row_count));
    for (std::uint64_t row_index = 0U; row_index < row_count; ++row_index) {
        CaptureIndexV16ProtocolPathMembershipRow row {};
        std::uint64_t ordinal_count {0};
        if (!read_u32(stream, row.protocol_path_id) ||
            !read_u64(stream, ordinal_count) ||
            ordinal_count > static_cast<std::uint64_t>((std::numeric_limits<std::size_t>::max)())) {
            return false;
        }

        row.canonical_connection_ordinals.reserve(static_cast<std::size_t>(ordinal_count));
        for (std::uint64_t ordinal_index = 0U; ordinal_index < ordinal_count; ++ordinal_index) {
            std::uint32_t ordinal {0};
            if (!read_u32(stream, ordinal)) {
                return false;
            }
            row.canonical_connection_ordinals.push_back(ordinal);
        }

        rows.push_back(std::move(row));
    }

    return stream.peek() == std::char_traits<char>::eof();
}

bool read_v16_packetref_directory_payload(
    std::istream& stream,
    std::vector<CaptureIndexV16PacketRefDirectoryEntry>& rows
) {
    std::uint64_t row_count {0};
    if (!read_u64(stream, row_count) ||
        row_count > static_cast<std::uint64_t>((std::numeric_limits<std::size_t>::max)())) {
        return false;
    }

    rows.clear();
    rows.reserve(static_cast<std::size_t>(row_count));
    for (std::uint64_t row_index = 0U; row_index < row_count; ++row_index) {
        CaptureIndexV16PacketRefDirectoryEntry row {};
        if (!read_u32(stream, row.canonical_connection_ordinal) ||
            !read_direction(stream, row.direction) ||
            !read_u64(stream, row.packet_count) ||
            !read_u32(stream, row.detail_section_occurrence_index) ||
            !read_u64(stream, row.payload_offset) ||
            !read_u64(stream, row.encoded_byte_length)) {
            return false;
        }

        rows.push_back(row);
    }

    return stream.peek() == std::char_traits<char>::eof();
}

bool read_v16_unrecognized_directory_section_catalog_entry(
    std::istream& stream,
    const CaptureIndexStableSectionHeader& section_header,
    const std::uint32_t expected_occurrence_index,
    const std::uint64_t expected_logical_row_start,
    CaptureIndexV16UnrecognizedDirectorySectionInfo& info
) {
    if (section_header.section_id != static_cast<std::uint32_t>(CaptureIndexSectionId::unrecognized_directory) ||
        section_header.section_flags != kCaptureIndexStableSectionFlagRequired ||
        section_header.section_schema_version != kCaptureIndexStableUnrecognizedDirectorySectionSchemaVersion) {
        return false;
    }

    const auto payload_file_offset = stream.tellg();
    if (payload_file_offset == std::istream::pos_type(-1)) {
        return false;
    }

    std::uint64_t row_count {0};
    if (!read_u64(stream, row_count)) {
        return false;
    }

    const auto expected_payload_size = encoded_unrecognized_directory_payload_length(row_count);
    if (!expected_payload_size.has_value() || section_header.payload_size != *expected_payload_size) {
        return false;
    }

    if (!skip_section_payload(stream, section_header.payload_size - 8U)) {
        return false;
    }

    info = CaptureIndexV16UnrecognizedDirectorySectionInfo {
        .section_occurrence_index = expected_occurrence_index,
        .payload_file_offset = static_cast<std::uint64_t>(payload_file_offset),
        .payload_size = section_header.payload_size,
        .logical_row_start = expected_logical_row_start,
        .row_count = row_count,
    };
    return true;
}

bool write_v16_packet_locator_entry(
    std::ostream& stream,
    const CapturePacketLocatorEntry& entry
) {
    return write_u64(stream, entry.packet_index) && write_u64(stream, entry.file_offset);
}

bool read_v16_packet_locator_entry(
    std::istream& stream,
    CapturePacketLocatorEntry& entry
) {
    return read_u64(stream, entry.packet_index) && read_u64(stream, entry.file_offset);
}

bool read_v16_packet_locator_entry_at(
    std::istream& stream,
    const CaptureIndexV16PacketLocatorSectionInfo& section,
    const std::uint64_t local_index,
    CapturePacketLocatorEntry& entry
) {
    if (local_index >= section.entry_count) {
        return false;
    }

    std::uint64_t local_byte_offset {0};
    std::uint64_t row_byte_offset {0};
    if (!checked_multiply_u64(local_index, kCaptureIndexV16PacketLocatorEncodedStrideBytes, local_byte_offset) ||
        !checked_add_u64(8U, local_byte_offset, row_byte_offset) ||
        row_byte_offset > section.payload_size ||
        kCaptureIndexV16PacketLocatorEncodedStrideBytes > section.payload_size ||
        row_byte_offset > section.payload_size - kCaptureIndexV16PacketLocatorEncodedStrideBytes) {
        return false;
    }

    std::uint64_t read_offset {0};
    if (!checked_add_u64(section.payload_file_offset, row_byte_offset, read_offset)) {
        return false;
    }
    stream.clear();
    stream.seekg(static_cast<std::streamoff>(read_offset), std::ios::beg);
    return static_cast<bool>(stream) && read_v16_packet_locator_entry(stream, entry);
}

bool read_v16_packet_locator_section_catalog_entry(
    std::istream& stream,
    const CaptureIndexStableSectionHeader& section_header,
    const std::uint32_t expected_occurrence_index,
    const std::uint64_t expected_logical_entry_start,
    CaptureIndexV16PacketLocatorSectionInfo& info
) {
    if (section_header.section_id != static_cast<std::uint32_t>(CaptureIndexSectionId::packet_locator_v16) ||
        section_header.section_flags != kCaptureIndexStableSectionFlagRequired ||
        section_header.section_schema_version != kCaptureIndexStablePacketLocatorV16SectionSchemaVersion) {
        return false;
    }

    const auto payload_file_offset = stream.tellg();
    if (payload_file_offset == std::istream::pos_type(-1)) {
        return false;
    }

    std::uint64_t entry_count {0};
    if (!read_u64(stream, entry_count)) {
        return false;
    }

    const auto expected_payload_size = encoded_packet_locator_payload_length(entry_count);
    if (!expected_payload_size.has_value() || section_header.payload_size != *expected_payload_size) {
        return false;
    }

    info = CaptureIndexV16PacketLocatorSectionInfo {
        .section_occurrence_index = expected_occurrence_index,
        .payload_file_offset = static_cast<std::uint64_t>(payload_file_offset),
        .payload_size = section_header.payload_size,
        .logical_entry_start = expected_logical_entry_start,
        .entry_count = entry_count,
    };

    if (entry_count > 0U) {
        CapturePacketLocatorEntry first {};
        if (!read_v16_packet_locator_entry(stream, first)) {
            return false;
        }

        CapturePacketLocatorEntry last = first;
        if (entry_count > 1U) {
            std::uint64_t last_local_byte_offset {0};
            std::uint64_t last_row_byte_offset {0};
            if (!checked_multiply_u64(
                    entry_count - 1U,
                    kCaptureIndexV16PacketLocatorEncodedStrideBytes,
                    last_local_byte_offset) ||
                !checked_add_u64(8U, last_local_byte_offset, last_row_byte_offset)) {
                return false;
            }

            std::uint64_t last_entry_file_offset {0};
            if (!checked_add_u64(
                    static_cast<std::uint64_t>(payload_file_offset),
                    last_row_byte_offset,
                    last_entry_file_offset)) {
                return false;
            }
            stream.clear();
            stream.seekg(static_cast<std::streamoff>(last_entry_file_offset), std::ios::beg);
            if (!stream || !read_v16_packet_locator_entry(stream, last) ||
                last.packet_index <= first.packet_index ||
                last.file_offset <= first.file_offset) {
                return false;
            }
        }

        info.first_packet_index = first.packet_index;
        info.last_packet_index = last.packet_index;
        info.first_file_offset = first.file_offset;
        info.last_file_offset = last.file_offset;
    }

    std::uint64_t payload_end_offset {0};
    if (!checked_add_u64(
            static_cast<std::uint64_t>(payload_file_offset),
            section_header.payload_size,
            payload_end_offset)) {
        return false;
    }
    stream.clear();
    stream.seekg(static_cast<std::streamoff>(payload_end_offset), std::ios::beg);
    return static_cast<bool>(stream);
}

std::uint64_t direction_identity_key(
    const std::uint32_t canonical_connection_ordinal,
    const Direction direction
) noexcept {
    return (static_cast<std::uint64_t>(canonical_connection_ordinal) << 1U) |
        (direction == Direction::b_to_a ? 1ULL : 0ULL);
}

template <typename ConnectionMetadata>
bool validate_v16_connection_metadata_row(
    const ConnectionMetadata& row,
    const ProtocolPathRegistry& registry,
    std::string& error_detail
) {
    if (row.key.protocol_path_id == kInvalidProtocolPathId || registry.find(row.key.protocol_path_id) == nullptr) {
        error_detail = "metadata row references an unknown protocol path id";
        return false;
    }

    if (!row.has_flow_a) {
        error_detail = "metadata row is missing required A->B flow metadata";
        return false;
    }

    if (row.has_fragmented_packets != (row.fragmented_packet_count > 0U)) {
        error_detail = "fragmentation presence bit does not match fragmented packet count";
        return false;
    }

    if (row.flow_a.packet_count == 0U || make_connection_key(row.flow_a.key) != row.key) {
        error_detail = "A->B flow metadata is inconsistent with the canonical connection key";
        return false;
    }

    if (!row.has_flow_b) {
        return true;
    }

    if (row.flow_b.packet_count == 0U ||
        row.flow_b.key == row.flow_a.key ||
        make_connection_key(row.flow_b.key) != row.key) {
        error_detail = "B->A flow metadata is inconsistent with the canonical connection key";
        return false;
    }

    return true;
}

bool load_exact_section_payload(
    std::istream& stream,
    const CaptureIndexStableSectionHeader& section_header,
    std::vector<std::uint8_t>& payload
) {
    return read_bounded_section_payload(
        stream,
        section_header.payload_size,
        section_header.payload_size,
        payload
    );
}

template <typename Row>
bool decode_v16_connection_metadata_section(
    std::istream& stream,
    const CaptureIndexStableSectionHeader& section_header,
    const CaptureIndexSectionId expected_id,
    const std::uint16_t expected_schema_version,
    std::vector<Row>& rows
) {
    if (section_header.section_id != static_cast<std::uint32_t>(expected_id) ||
        section_header.section_flags != kCaptureIndexStableSectionFlagRequired ||
        section_header.section_schema_version != expected_schema_version) {
        return false;
    }

    std::vector<std::uint8_t> payload {};
    if (!load_exact_section_payload(stream, section_header, payload)) {
        return false;
    }

    std::istringstream payload_stream(
        std::string(payload.begin(), payload.end()),
        std::ios::binary | std::ios::in
    );
    return read_v16_connection_metadata_payload(payload_stream, rows);
}

bool decode_v16_protocol_path_membership_section(
    std::istream& stream,
    const CaptureIndexStableSectionHeader& section_header,
    std::vector<CaptureIndexV16ProtocolPathMembershipRow>& rows
) {
    if (section_header.section_id != static_cast<std::uint32_t>(CaptureIndexSectionId::protocol_path_membership) ||
        section_header.section_flags != kCaptureIndexStableSectionFlagRequired ||
        section_header.section_schema_version != kCaptureIndexStableProtocolPathMembershipSectionSchemaVersion) {
        return false;
    }

    std::vector<std::uint8_t> payload {};
    if (!load_exact_section_payload(stream, section_header, payload)) {
        return false;
    }

    std::istringstream payload_stream(
        std::string(payload.begin(), payload.end()),
        std::ios::binary | std::ios::in
    );
    return read_v16_protocol_path_membership_payload(payload_stream, rows);
}

bool decode_v16_packetref_directory_section(
    std::istream& stream,
    const CaptureIndexStableSectionHeader& section_header,
    std::vector<CaptureIndexV16PacketRefDirectoryEntry>& rows
) {
    if (section_header.section_id != static_cast<std::uint32_t>(CaptureIndexSectionId::packetref_directory) ||
        section_header.section_flags != kCaptureIndexStableSectionFlagRequired ||
        section_header.section_schema_version != kCaptureIndexStablePacketRefDirectorySectionSchemaVersion) {
        return false;
    }

    std::vector<std::uint8_t> payload {};
    if (!load_exact_section_payload(stream, section_header, payload)) {
        return false;
    }

    std::istringstream payload_stream(
        std::string(payload.begin(), payload.end()),
        std::ios::binary | std::ios::in
    );
    return read_v16_packetref_directory_payload(payload_stream, rows);
}

CaptureIndexV16PacketRefExtentReadResult read_v16_packetref_extent_range_impl(
    std::istream& stream,
    std::span<const CaptureIndexV16PacketRefDetailSectionInfo> detail_sections,
    const CaptureIndexV16PacketRefDirectoryEntry& descriptor,
    const std::uint64_t local_offset,
    const std::uint64_t limit
) {
    CaptureIndexV16PacketRefExtentReadResult result {};

    const auto detail_section_it = std::find_if(
        detail_sections.begin(),
        detail_sections.end(),
        [&](const auto& section) {
            return section.section_occurrence_index == descriptor.detail_section_occurrence_index;
        }
    );
    if (detail_section_it == detail_sections.end()) {
        result.status = CaptureIndexV16PacketRefExtentReadStatus::invalid_detail_section_occurrence;
        result.error_detail = "directory entry referenced a missing packetref detail section occurrence";
        return result;
    }

    const auto expected_length = encoded_packetref_extent_length(descriptor.packet_count);
    if (!expected_length.has_value() || descriptor.encoded_byte_length != *expected_length) {
        result.status = CaptureIndexV16PacketRefExtentReadStatus::invalid_requested_length;
        result.error_detail = "directory entry encoded length does not match packet_count * PacketRef stride";
        return result;
    }

    if (descriptor.payload_offset > detail_section_it->payload_size ||
        descriptor.encoded_byte_length > detail_section_it->payload_size ||
        descriptor.payload_offset > detail_section_it->payload_size - descriptor.encoded_byte_length) {
        result.status = CaptureIndexV16PacketRefExtentReadStatus::section_range_overflow;
        result.error_detail = "directory entry extent lies outside the referenced packetref detail payload";
        return result;
    }

    if (local_offset >= descriptor.packet_count || limit == 0U) {
        return result;
    }

    const auto available_count = descriptor.packet_count - local_offset;
    const auto count_to_read = std::min(limit, available_count);
    const auto prior_count = local_offset > 0U ? 1U : 0U;
    const auto first_record_index = local_offset - prior_count;
    const auto record_count_to_decode = count_to_read + prior_count;

    std::uint64_t byte_offset_from_extent_start {0};
    std::uint64_t byte_length_to_read {0};
    const auto extent_offset = encoded_packetref_extent_length(first_record_index);
    const auto extent_length = encoded_packetref_extent_length(record_count_to_decode);
    if (!extent_offset.has_value() || !extent_length.has_value()) {
        result.status = CaptureIndexV16PacketRefExtentReadStatus::invalid_requested_length;
        result.error_detail = "requested packetref range overflowed";
        return result;
    }
    byte_offset_from_extent_start = *extent_offset;
    byte_length_to_read = *extent_length;
    static_cast<void>(byte_length_to_read);

    const auto read_offset = detail_section_it->payload_file_offset +
        descriptor.payload_offset +
        byte_offset_from_extent_start;
    const auto restore_offset = stream.tellg();
    if (restore_offset == std::istream::pos_type(-1)) {
        stream.clear();
    }

    stream.clear();
    stream.seekg(static_cast<std::streamoff>(read_offset), std::ios::beg);
    if (!stream) {
        result.status = CaptureIndexV16PacketRefExtentReadStatus::section_seek_failed;
        result.error_detail = "failed to seek to the requested packetref detail extent";
        return result;
    }

    std::vector<PacketRef> decoded {};
    decoded.reserve(static_cast<std::size_t>(record_count_to_decode));
    for (std::uint64_t index = 0U; index < record_count_to_decode; ++index) {
        PacketRef packet {};
        if (!read_packet_ref(stream, packet)) {
            result.status = CaptureIndexV16PacketRefExtentReadStatus::truncated_packetref_detail;
            result.error_detail = "packetref detail extent ended before the requested range was fully decoded";
            if (restore_offset != std::istream::pos_type(-1)) {
                stream.clear();
                stream.seekg(restore_offset);
            }
            return result;
        }
        decoded.push_back(packet);
    }

    if (restore_offset != std::istream::pos_type(-1)) {
        stream.clear();
        stream.seekg(restore_offset);
    }

    for (std::size_t index = 1U; index < decoded.size(); ++index) {
        if (decoded[index].packet_index <= decoded[index - 1U].packet_index) {
            result.status = CaptureIndexV16PacketRefExtentReadStatus::packet_index_not_strictly_increasing;
            result.error_detail = "decoded packetref range is not strictly increasing by packet_index";
            return result;
        }
    }

    result.packet_refs.assign(decoded.begin() + static_cast<std::ptrdiff_t>(prior_count), decoded.end());
    return result;
}

CaptureIndexV16UnrecognizedDirectoryRangeReadResult read_v16_unrecognized_directory_range_impl(
    std::istream& stream,
    std::span<const CaptureIndexV16UnrecognizedDirectorySectionInfo> directory_sections,
    const std::uint64_t offset,
    const std::uint64_t limit
) {
    CaptureIndexV16UnrecognizedDirectoryRangeReadResult result {};
    for (const auto& section : directory_sections) {
        std::uint64_t section_end {0};
        if (!checked_add_u64(section.logical_row_start, section.row_count, section_end)) {
            result.status = CaptureIndexV16UnrecognizedDirectoryRangeReadStatus::malformed_directory_payload;
            result.error_detail = "unrecognized directory section logical range overflowed";
            return result;
        }
        result.total_row_count = std::max(result.total_row_count, section_end);
    }

    if (offset > result.total_row_count) {
        result.status = CaptureIndexV16UnrecognizedDirectoryRangeReadStatus::invalid_offset;
        result.error_detail = "requested unrecognized row offset is past the end of the logical row space";
        return result;
    }
    if (limit == 0U || offset == result.total_row_count) {
        return result;
    }

    std::uint64_t requested_end {0};
    if (!checked_add_u64(offset, limit, requested_end)) {
        result.status = CaptureIndexV16UnrecognizedDirectoryRangeReadStatus::invalid_requested_length;
        result.error_detail = "requested unrecognized row range overflowed";
        return result;
    }
    const auto effective_end = std::min(requested_end, result.total_row_count);
    result.rows.reserve(static_cast<std::size_t>(effective_end - offset));

    std::optional<std::uint64_t> prior_packet_index {};
    for (const auto& section : directory_sections) {
        std::uint64_t section_end {0};
        if (!checked_add_u64(section.logical_row_start, section.row_count, section_end)) {
            result.status = CaptureIndexV16UnrecognizedDirectoryRangeReadStatus::malformed_directory_payload;
            result.error_detail = "unrecognized directory section logical range overflowed";
            result.rows.clear();
            return result;
        }
        if (section.logical_row_start >= effective_end || section_end <= offset) {
            continue;
        }

        const auto local_begin = offset > section.logical_row_start ? offset - section.logical_row_start : 0U;
        const auto local_end = std::min(section.row_count, effective_end - section.logical_row_start);
        const auto local_count = local_end - local_begin;

        std::uint64_t row_byte_offset {0};
        std::uint64_t row_byte_length {0};
        std::uint64_t local_begin_byte_offset {0};
        if (!checked_multiply_u64(
                local_begin,
                kCaptureIndexV16UnrecognizedDirectoryEncodedStrideBytes,
                local_begin_byte_offset) ||
            !checked_add_u64(8U, local_begin_byte_offset, row_byte_offset) ||
            !checked_multiply_u64(
                local_count,
                kCaptureIndexV16UnrecognizedDirectoryEncodedStrideBytes,
                row_byte_length) ||
            row_byte_offset > section.payload_size ||
            row_byte_length > section.payload_size ||
            row_byte_offset > section.payload_size - row_byte_length) {
            result.status = CaptureIndexV16UnrecognizedDirectoryRangeReadStatus::section_range_overflow;
            result.error_detail = "requested unrecognized directory range lies outside the referenced section payload";
            result.rows.clear();
            return result;
        }

        const auto read_offset = section.payload_file_offset + row_byte_offset;
        const auto restore_offset = stream.tellg();
        if (restore_offset == std::istream::pos_type(-1)) {
            stream.clear();
        }
        stream.clear();
        stream.seekg(static_cast<std::streamoff>(read_offset), std::ios::beg);
        if (!stream) {
            result.status = CaptureIndexV16UnrecognizedDirectoryRangeReadStatus::section_seek_failed;
            result.error_detail = "failed to seek to the requested unrecognized directory range";
            result.rows.clear();
            return result;
        }

        for (std::uint64_t local_index = 0U; local_index < local_count; ++local_index) {
            CaptureIndexV16UnrecognizedDirectoryEntry row {};
            if (!read_u64(stream, row.row_number) ||
                !read_u64(stream, row.packet_index) ||
                !read_u32(stream, row.ts_sec) ||
                !read_u32(stream, row.ts_usec) ||
                !read_u32(stream, row.captured_length) ||
                !read_u32(stream, row.original_length) ||
                !read_u32(stream, row.reason_section_occurrence_index) ||
                !read_u64(stream, row.reason_payload_offset) ||
                !read_u64(stream, row.reason_byte_length)) {
                if (restore_offset != std::istream::pos_type(-1)) {
                    stream.clear();
                    stream.seekg(restore_offset);
                }
                result.status = CaptureIndexV16UnrecognizedDirectoryRangeReadStatus::truncated_directory_payload;
                result.error_detail = "unrecognized directory payload ended before the requested page was fully decoded";
                result.rows.clear();
                return result;
            }

            const auto expected_row_number = section.logical_row_start + local_begin + local_index + 1U;
            if (row.row_number != expected_row_number) {
                if (restore_offset != std::istream::pos_type(-1)) {
                    stream.clear();
                    stream.seekg(restore_offset);
                }
                result.status = CaptureIndexV16UnrecognizedDirectoryRangeReadStatus::row_number_inconsistency;
                result.error_detail = "unrecognized directory row_number does not match the stable logical row sequence";
                result.rows.clear();
                return result;
            }

            if (prior_packet_index.has_value() && row.packet_index <= *prior_packet_index) {
                if (restore_offset != std::istream::pos_type(-1)) {
                    stream.clear();
                    stream.seekg(restore_offset);
                }
                result.status =
                    CaptureIndexV16UnrecognizedDirectoryRangeReadStatus::packet_index_not_strictly_increasing;
                result.error_detail =
                    "unrecognized directory packet_index sequence is not strictly increasing across the requested page";
                result.rows.clear();
                return result;
            }

            prior_packet_index = row.packet_index;
            result.rows.push_back(row);
        }

        if (restore_offset != std::istream::pos_type(-1)) {
            stream.clear();
            stream.seekg(restore_offset);
        }
    }

    return result;
}

}  // namespace

bool write_v16_ipv4_flow_metadata_section(
    std::ostream& stream,
    std::span<const CaptureIndexV16ConnectionMetadataV4> rows
) {
    std::ostringstream payload_stream(std::ios::binary | std::ios::out);
    if (!write_v16_connection_metadata_payload(payload_stream, rows)) {
        return false;
    }

    const auto payload_bytes = payload_stream.str();
    return write_capture_index_stable_section_header(stream, CaptureIndexStableSectionHeader {
        .section_id = static_cast<std::uint32_t>(CaptureIndexSectionId::ipv4_flow_metadata),
        .section_schema_version = kCaptureIndexStableIpv4FlowMetadataSectionSchemaVersion,
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

bool write_v16_ipv6_flow_metadata_section(
    std::ostream& stream,
    std::span<const CaptureIndexV16ConnectionMetadataV6> rows
) {
    std::ostringstream payload_stream(std::ios::binary | std::ios::out);
    if (!write_v16_connection_metadata_payload(payload_stream, rows)) {
        return false;
    }

    const auto payload_bytes = payload_stream.str();
    return write_capture_index_stable_section_header(stream, CaptureIndexStableSectionHeader {
        .section_id = static_cast<std::uint32_t>(CaptureIndexSectionId::ipv6_flow_metadata),
        .section_schema_version = kCaptureIndexStableIpv6FlowMetadataSectionSchemaVersion,
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

bool write_v16_protocol_path_membership_section(
    std::ostream& stream,
    std::span<const CaptureIndexV16ProtocolPathMembershipRow> rows
) {
    std::ostringstream payload_stream(std::ios::binary | std::ios::out);
    if (!write_u64(payload_stream, static_cast<std::uint64_t>(rows.size()))) {
        return false;
    }

    for (const auto& row : rows) {
        if (!write_u32(payload_stream, row.protocol_path_id) ||
            !write_u64(payload_stream, static_cast<std::uint64_t>(row.canonical_connection_ordinals.size()))) {
            return false;
        }

        for (const auto ordinal : row.canonical_connection_ordinals) {
            if (!write_u32(payload_stream, ordinal)) {
                return false;
            }
        }
    }

    const auto payload_bytes = payload_stream.str();
    return write_capture_index_stable_section_header(stream, CaptureIndexStableSectionHeader {
        .section_id = static_cast<std::uint32_t>(CaptureIndexSectionId::protocol_path_membership),
        .section_schema_version = kCaptureIndexStableProtocolPathMembershipSectionSchemaVersion,
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

bool write_v16_packetref_directory_section(
    std::ostream& stream,
    std::span<const CaptureIndexV16PacketRefDirectoryEntry> rows
) {
    std::ostringstream payload_stream(std::ios::binary | std::ios::out);
    if (!write_u64(payload_stream, static_cast<std::uint64_t>(rows.size()))) {
        return false;
    }

    for (const auto& row : rows) {
        if (!write_u32(payload_stream, row.canonical_connection_ordinal) ||
            !write_direction(payload_stream, row.direction) ||
            !write_u64(payload_stream, row.packet_count) ||
            !write_u32(payload_stream, row.detail_section_occurrence_index) ||
            !write_u64(payload_stream, row.payload_offset) ||
            !write_u64(payload_stream, row.encoded_byte_length)) {
            return false;
        }
    }

    const auto payload_bytes = payload_stream.str();
    return write_capture_index_stable_section_header(stream, CaptureIndexStableSectionHeader {
        .section_id = static_cast<std::uint32_t>(CaptureIndexSectionId::packetref_directory),
        .section_schema_version = kCaptureIndexStablePacketRefDirectorySectionSchemaVersion,
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

bool write_v16_unrecognized_directory_section(
    std::ostream& stream,
    const CaptureIndexV16UnrecognizedDirectorySectionWritePlan& section
) {
    const auto expected_payload_size = encoded_unrecognized_directory_payload_length(
        static_cast<std::uint64_t>(section.rows.size())
    );
    if (!expected_payload_size.has_value() ||
        section.payload_size != *expected_payload_size) {
        return false;
    }

    if (!write_capture_index_stable_section_header(stream, CaptureIndexStableSectionHeader {
            .section_id = static_cast<std::uint32_t>(CaptureIndexSectionId::unrecognized_directory),
            .section_schema_version = kCaptureIndexStableUnrecognizedDirectorySectionSchemaVersion,
            .section_flags = kCaptureIndexStableSectionFlagRequired,
            .payload_size = section.payload_size,
        }) ||
        !write_u64(stream, static_cast<std::uint64_t>(section.rows.size()))) {
        return false;
    }

    for (std::size_t index = 0U; index < section.rows.size(); ++index) {
        const auto& row = section.rows[index];
        const auto expected_row_number = section.logical_row_start + static_cast<std::uint64_t>(index) + 1U;
        if (row.row_number != expected_row_number ||
            !write_u64(stream, row.row_number) ||
            !write_u64(stream, row.packet_index) ||
            !write_u32(stream, row.ts_sec) ||
            !write_u32(stream, row.ts_usec) ||
            !write_u32(stream, row.captured_length) ||
            !write_u32(stream, row.original_length) ||
            !write_u32(stream, row.reason_section_occurrence_index) ||
            !write_u64(stream, row.reason_payload_offset) ||
            !write_u64(stream, row.reason_byte_length)) {
            return false;
        }
    }

    return true;
}

bool write_v16_metadata_tier_sections(
    std::ostream& stream,
    const CaptureIndexV16WritePlan& plan
) {
    if (!write_v16_ipv4_flow_metadata_section(stream, plan.metadata.ipv4_connections) ||
        !write_v16_ipv6_flow_metadata_section(stream, plan.metadata.ipv6_connections) ||
        !write_v16_protocol_path_membership_section(stream, plan.metadata.protocol_path_membership) ||
        !write_v16_packetref_directory_section(stream, plan.metadata.packetref_directory)) {
        return false;
    }

    for (std::size_t section_index = 0U; section_index < plan.unrecognized_directory_sections.size(); ++section_index) {
        const auto& section = plan.unrecognized_directory_sections[section_index];
        if (section.section_occurrence_index != static_cast<std::uint32_t>(section_index) ||
            !write_v16_unrecognized_directory_section(stream, section)) {
            return false;
        }
    }

    return true;
}

bool write_v16_packetref_detail_sections(
    std::ostream& stream,
    std::span<const CaptureIndexV16PacketRefDetailSectionWritePlan> sections
) {
    for (std::size_t section_index = 0U; section_index < sections.size(); ++section_index) {
        const auto& section = sections[section_index];
        if (section.section_occurrence_index != static_cast<std::uint32_t>(section_index)) {
            return false;
        }

        std::uint64_t expected_payload_size {0};
        for (const auto& extent : section.extents) {
            const auto expected_length = encoded_packetref_extent_length(extent.packet_count);
            if (!expected_length.has_value() ||
                extent.encoded_byte_length != *expected_length ||
                extent.detail_section_occurrence_index != section.section_occurrence_index ||
                static_cast<std::uint64_t>(extent.packet_refs.size()) != extent.packet_count ||
                extent.payload_offset != expected_payload_size) {
                return false;
            }

            for (std::size_t packet_index = 1U; packet_index < extent.packet_refs.size(); ++packet_index) {
                if (extent.packet_refs[packet_index].packet_index <= extent.packet_refs[packet_index - 1U].packet_index) {
                    return false;
                }
            }

            expected_payload_size += extent.encoded_byte_length;
        }

        if (expected_payload_size != section.payload_size ||
            !write_capture_index_stable_section_header(stream, CaptureIndexStableSectionHeader {
                .section_id = static_cast<std::uint32_t>(CaptureIndexSectionId::packetref_detail_blocks),
                .section_schema_version = kCaptureIndexStablePacketRefDetailBlocksSectionSchemaVersion,
                .section_flags = kCaptureIndexStableSectionFlagRequired,
                .payload_size = section.payload_size,
            })) {
            return false;
        }

        for (const auto& extent : section.extents) {
            for (const auto& packet : extent.packet_refs) {
                if (!write_packet_ref(stream, packet)) {
                    return false;
                }
            }
        }
    }

    return true;
}

bool write_v16_unrecognized_reason_sections(
    std::ostream& stream,
    std::span<const CaptureIndexV16UnrecognizedReasonSectionWritePlan> sections
) {
    for (std::size_t section_index = 0U; section_index < sections.size(); ++section_index) {
        const auto& section = sections[section_index];
        if (section.section_occurrence_index != static_cast<std::uint32_t>(section_index)) {
            return false;
        }

        std::uint64_t expected_payload_size {0};
        for (const auto& extent : section.extents) {
            std::uint64_t next_payload_size {0};
            if (extent.payload_offset != expected_payload_size ||
                !checked_add_u64(
                    expected_payload_size,
                    static_cast<std::uint64_t>(extent.reason_text.size()),
                    next_payload_size)) {
                return false;
            }
            expected_payload_size = next_payload_size;
        }

        if (expected_payload_size != section.payload_size ||
            !write_capture_index_stable_section_header(stream, CaptureIndexStableSectionHeader {
                .section_id = static_cast<std::uint32_t>(CaptureIndexSectionId::unrecognized_reason_blobs),
                .section_schema_version = kCaptureIndexStableUnrecognizedReasonBlobsSectionSchemaVersion,
                .section_flags = kCaptureIndexStableSectionFlagRequired,
                .payload_size = section.payload_size,
            })) {
            return false;
        }

        for (const auto& extent : section.extents) {
            if (!extent.reason_text.empty() &&
                !write_bytes(
                    stream,
                    std::span<const std::uint8_t>(
                        reinterpret_cast<const std::uint8_t*>(extent.reason_text.data()),
                        extent.reason_text.size()
                    ))) {
                return false;
            }
        }
    }

    return true;
}

bool write_v16_packet_locator_sections(
    std::ostream& stream,
    std::span<const CaptureIndexV16PacketLocatorSectionWritePlan> sections,
    std::span<const CapturePacketLocatorEntry> entries
) {
    std::optional<std::uint64_t> prior_packet_index {};
    std::optional<std::uint64_t> prior_file_offset {};

    for (std::size_t section_index = 0U; section_index < sections.size(); ++section_index) {
        const auto& section = sections[section_index];
        if (section.section_occurrence_index != static_cast<std::uint32_t>(section_index)) {
            return false;
        }

        const auto expected_payload_size = encoded_packet_locator_payload_length(section.entry_count);
        if (!expected_payload_size.has_value() || section.payload_size != *expected_payload_size) {
            return false;
        }
        if (section.logical_entry_start > static_cast<std::uint64_t>(entries.size()) ||
            section.entry_count > static_cast<std::uint64_t>(entries.size()) ||
            section.logical_entry_start > static_cast<std::uint64_t>(entries.size()) - section.entry_count) {
            return false;
        }

        if (!write_capture_index_stable_section_header(stream, CaptureIndexStableSectionHeader {
                .section_id = static_cast<std::uint32_t>(CaptureIndexSectionId::packet_locator_v16),
                .section_schema_version = kCaptureIndexStablePacketLocatorV16SectionSchemaVersion,
                .section_flags = kCaptureIndexStableSectionFlagRequired,
                .payload_size = section.payload_size,
            }) ||
            !write_u64(stream, section.entry_count)) {
            return false;
        }

        const auto begin = static_cast<std::size_t>(section.logical_entry_start);
        const auto end = begin + static_cast<std::size_t>(section.entry_count);
        for (std::size_t index = begin; index < end; ++index) {
            const auto& entry = entries[index];
            if ((prior_packet_index.has_value() && entry.packet_index <= *prior_packet_index) ||
                (prior_file_offset.has_value() && entry.file_offset <= *prior_file_offset) ||
                !write_v16_packet_locator_entry(stream, entry)) {
                return false;
            }
            prior_packet_index = entry.packet_index;
            prior_file_offset = entry.file_offset;
        }
    }

    return true;
}

bool write_capture_index_v16(
    std::ostream& stream,
    const CaptureIndexStableHeader& header,
    const CaptureIndexV16FastStatisticsTier& fast_tier,
    const CaptureIndexV16WritePlan& plan
) {
    CaptureIndexStableHeader v16_header = header;
    v16_header.index_revision = kCaptureIndexStableV16Revision;

    return write_v16_fast_statistics_tier(stream, v16_header, fast_tier) &&
           write_v16_metadata_tier_sections(stream, plan) &&
           write_v16_packetref_detail_sections(stream, plan.packetref_detail_sections) &&
           write_v16_unrecognized_reason_sections(stream, plan.unrecognized_reason_sections) &&
           write_v16_packet_locator_sections(
               stream,
               plan.packet_locator_sections,
               plan.packet_locator_entries
           );
}

CaptureIndexV16MetadataTierReadResult read_v16_metadata_tier(
    std::istream& stream,
    CaptureIndexV16MetadataTier& metadata
) {
    metadata = {};

    CaptureIndexV16MetadataTierReadResult result {};
    const auto fast_result = read_v16_fast_statistics_tier(stream, result.fast_statistics_tier);
    if (!fast_result) {
        result.status =
            fast_result.status == CaptureIndexV16FastStatisticsTierReadStatus::invalid_header
                ? CaptureIndexV16MetadataTierReadStatus::invalid_header
                : fast_result.status == CaptureIndexV16FastStatisticsTierReadStatus::unsupported_revision
                    ? CaptureIndexV16MetadataTierReadStatus::unsupported_revision
                    : CaptureIndexV16MetadataTierReadStatus::invalid_fast_tier;
        result.header = fast_result.header;
        result.failed_section_header = fast_result.failed_section_header;
        result.error_detail = fast_result.error_detail;
        return result;
    }
    result.header = fast_result.header;

    const auto total_flow_count = result.fast_statistics_tier.capture_statistics_snapshot.total_flow_count;
    if (total_flow_count > static_cast<std::uint64_t>((std::numeric_limits<std::size_t>::max)())) {
        result.status = CaptureIndexV16MetadataTierReadStatus::metadata_semantic_inconsistency;
        result.error_detail = "fast snapshot total flow count exceeds local container limits";
        return result;
    }

    auto read_chunked_metadata_family =
        [&](const CaptureIndexSectionId section_id,
            const auto& decode_chunk,
            auto& destination,
            const CaptureIndexV16MetadataTierReadStatus missing_status,
            const CaptureIndexV16MetadataTierReadStatus malformed_status) -> bool {
            CaptureIndexStableSectionHeader next_header {};
            if (!try_peek_capture_index_stable_section_header(stream, next_header)) {
                result.status = missing_status;
                return false;
            }

            if (next_header.section_id != static_cast<std::uint32_t>(section_id)) {
                result.failed_section_header = next_header;
                result.status =
                        next_header.section_id == static_cast<std::uint32_t>(CaptureIndexSectionId::ipv4_flow_metadata) ||
                        next_header.section_id == static_cast<std::uint32_t>(CaptureIndexSectionId::ipv6_flow_metadata) ||
                        next_header.section_id == static_cast<std::uint32_t>(CaptureIndexSectionId::protocol_path_membership) ||
                        next_header.section_id == static_cast<std::uint32_t>(CaptureIndexSectionId::packetref_directory) ||
                        next_header.section_id == static_cast<std::uint32_t>(CaptureIndexSectionId::unrecognized_directory) ||
                        next_header.section_id == static_cast<std::uint32_t>(CaptureIndexSectionId::packetref_detail_blocks) ||
                        next_header.section_id == static_cast<std::uint32_t>(CaptureIndexSectionId::unrecognized_reason_blobs) ||
                        next_header.section_id == static_cast<std::uint32_t>(CaptureIndexSectionId::packet_locator_v16)
                    ? CaptureIndexV16MetadataTierReadStatus::wrong_metadata_section_order
                    : missing_status;
                return false;
            }

            while (true) {
                CaptureIndexStableSectionHeader section_header {};
                if (!try_peek_capture_index_stable_section_header(stream, section_header) ||
                    section_header.section_id != static_cast<std::uint32_t>(section_id)) {
                    break;
                }

                if (!read_capture_index_stable_section_header(stream, section_header)) {
                    result.status = CaptureIndexV16MetadataTierReadStatus::invalid_metadata_section_framing;
                    return false;
                }

                using RowType = typename std::remove_reference_t<decltype(destination)>::value_type;
                std::vector<RowType> chunk_rows {};
                if (!decode_chunk(stream, section_header, chunk_rows)) {
                    result.failed_section_header = section_header;
                    result.status =
                        section_header.section_schema_version !=
                                (section_id == CaptureIndexSectionId::ipv4_flow_metadata
                                     ? kCaptureIndexStableIpv4FlowMetadataSectionSchemaVersion
                                     : section_id == CaptureIndexSectionId::ipv6_flow_metadata
                                         ? kCaptureIndexStableIpv6FlowMetadataSectionSchemaVersion
                                         : section_id == CaptureIndexSectionId::protocol_path_membership
                                             ? kCaptureIndexStableProtocolPathMembershipSectionSchemaVersion
                                             : kCaptureIndexStablePacketRefDirectorySectionSchemaVersion)
                            ? CaptureIndexV16MetadataTierReadStatus::unsupported_metadata_section_schema
                            : malformed_status;
                    return false;
                }

                destination.insert(
                    destination.end(),
                    std::make_move_iterator(chunk_rows.begin()),
                    std::make_move_iterator(chunk_rows.end())
                );
            }

            return true;
        };

    if (!read_chunked_metadata_family(
            CaptureIndexSectionId::ipv4_flow_metadata,
            [](std::istream& payload_stream,
               const CaptureIndexStableSectionHeader& section_header,
               std::vector<CaptureIndexV16ConnectionMetadataV4>& rows) {
                return decode_v16_connection_metadata_section(
                    payload_stream,
                    section_header,
                    CaptureIndexSectionId::ipv4_flow_metadata,
                    kCaptureIndexStableIpv4FlowMetadataSectionSchemaVersion,
                    rows
                );
            },
            metadata.ipv4_connections,
            CaptureIndexV16MetadataTierReadStatus::missing_ipv4_flow_metadata_section,
            CaptureIndexV16MetadataTierReadStatus::malformed_ipv4_flow_metadata_payload)) {
        metadata = {};
        return result;
    }

    if (!read_chunked_metadata_family(
            CaptureIndexSectionId::ipv6_flow_metadata,
            [](std::istream& payload_stream,
               const CaptureIndexStableSectionHeader& section_header,
               std::vector<CaptureIndexV16ConnectionMetadataV6>& rows) {
                return decode_v16_connection_metadata_section(
                    payload_stream,
                    section_header,
                    CaptureIndexSectionId::ipv6_flow_metadata,
                    kCaptureIndexStableIpv6FlowMetadataSectionSchemaVersion,
                    rows
                );
            },
            metadata.ipv6_connections,
            CaptureIndexV16MetadataTierReadStatus::missing_ipv6_flow_metadata_section,
            CaptureIndexV16MetadataTierReadStatus::malformed_ipv6_flow_metadata_payload)) {
        metadata = {};
        return result;
    }

    if (!read_chunked_metadata_family(
            CaptureIndexSectionId::protocol_path_membership,
            [](std::istream& payload_stream,
               const CaptureIndexStableSectionHeader& section_header,
               std::vector<CaptureIndexV16ProtocolPathMembershipRow>& rows) {
                return decode_v16_protocol_path_membership_section(payload_stream, section_header, rows);
            },
            metadata.protocol_path_membership,
            CaptureIndexV16MetadataTierReadStatus::missing_protocol_path_membership_section,
            CaptureIndexV16MetadataTierReadStatus::malformed_protocol_path_membership_payload)) {
        metadata = {};
        return result;
    }

    if (!read_chunked_metadata_family(
            CaptureIndexSectionId::packetref_directory,
            [](std::istream& payload_stream,
               const CaptureIndexStableSectionHeader& section_header,
               std::vector<CaptureIndexV16PacketRefDirectoryEntry>& rows) {
                return decode_v16_packetref_directory_section(payload_stream, section_header, rows);
            },
            metadata.packetref_directory,
            CaptureIndexV16MetadataTierReadStatus::missing_packetref_directory_section,
            CaptureIndexV16MetadataTierReadStatus::malformed_packetref_directory_payload)) {
        metadata = {};
        return result;
    }

    {
        std::uint64_t logical_row_start {0};
        while (true) {
            CaptureIndexStableSectionHeader section_header {};
            if (!try_peek_capture_index_stable_section_header(stream, section_header) ||
                section_header.section_id != static_cast<std::uint32_t>(CaptureIndexSectionId::unrecognized_directory)) {
                break;
            }

            if (!read_capture_index_stable_section_header(stream, section_header)) {
                result.status = CaptureIndexV16MetadataTierReadStatus::invalid_metadata_section_framing;
                metadata = {};
                return result;
            }

            CaptureIndexV16UnrecognizedDirectorySectionInfo section_info {};
            if (!read_v16_unrecognized_directory_section_catalog_entry(
                    stream,
                    section_header,
                    static_cast<std::uint32_t>(metadata.unrecognized_directory_sections.size()),
                    logical_row_start,
                    section_info)) {
                result.failed_section_header = section_header;
                result.status =
                    section_header.section_schema_version != kCaptureIndexStableUnrecognizedDirectorySectionSchemaVersion
                        ? CaptureIndexV16MetadataTierReadStatus::unsupported_metadata_section_schema
                        : CaptureIndexV16MetadataTierReadStatus::malformed_unrecognized_directory_payload;
                metadata = {};
                return result;
            }

            if (!checked_add_u64(logical_row_start, section_info.row_count, logical_row_start)) {
                result.failed_section_header = section_header;
                result.status = CaptureIndexV16MetadataTierReadStatus::unrecognized_directory_semantic_inconsistency;
                result.error_detail = "unrecognized directory logical row range overflowed";
                metadata = {};
                return result;
            }
            metadata.unrecognized_directory_sections.push_back(section_info);
        }
    }

    CaptureIndexStableSectionHeader next_header {};
    if (!try_peek_capture_index_stable_section_header(stream, next_header)) {
        result.status = CaptureIndexV16MetadataTierReadStatus::missing_packetref_detail_blocks_section;
        metadata = {};
        return result;
    }
    if (next_header.section_id != static_cast<std::uint32_t>(CaptureIndexSectionId::packetref_detail_blocks)) {
        result.failed_section_header = next_header;
        result.status = CaptureIndexV16MetadataTierReadStatus::wrong_metadata_section_order;
        metadata = {};
        return result;
    }

    while (true) {
        CaptureIndexStableSectionHeader section_header {};
        if (!try_peek_capture_index_stable_section_header(stream, section_header) ||
            section_header.section_id != static_cast<std::uint32_t>(CaptureIndexSectionId::packetref_detail_blocks)) {
            break;
        }

        if (!read_capture_index_stable_section_header(stream, section_header)) {
            result.status = CaptureIndexV16MetadataTierReadStatus::detail_section_framing_error;
            metadata = {};
            return result;
        }

        if (section_header.section_flags != kCaptureIndexStableSectionFlagRequired ||
            section_header.section_schema_version != kCaptureIndexStablePacketRefDetailBlocksSectionSchemaVersion) {
            result.failed_section_header = section_header;
            result.status =
                section_header.section_schema_version != kCaptureIndexStablePacketRefDetailBlocksSectionSchemaVersion
                    ? CaptureIndexV16MetadataTierReadStatus::unsupported_metadata_section_schema
                    : CaptureIndexV16MetadataTierReadStatus::detail_section_framing_error;
            metadata = {};
            return result;
        }

        const auto payload_file_offset = stream.tellg();
        if (payload_file_offset == std::istream::pos_type(-1) ||
            !skip_section_payload(stream, section_header.payload_size)) {
            result.failed_section_header = section_header;
            result.status = CaptureIndexV16MetadataTierReadStatus::detail_section_framing_error;
            metadata = {};
            return result;
        }

        metadata.packetref_detail_sections.push_back(CaptureIndexV16PacketRefDetailSectionInfo {
            .section_occurrence_index = static_cast<std::uint32_t>(metadata.packetref_detail_sections.size()),
            .payload_file_offset = static_cast<std::uint64_t>(payload_file_offset),
            .payload_size = section_header.payload_size,
        });
    }

    if (metadata.unrecognized_directory_sections.empty()) {
        result.status = CaptureIndexV16MetadataTierReadStatus::missing_unrecognized_directory_section;
        metadata = {};
        return result;
    }

    while (true) {
        CaptureIndexStableSectionHeader section_header {};
        if (!try_peek_capture_index_stable_section_header(stream, section_header) ||
            section_header.section_id != static_cast<std::uint32_t>(CaptureIndexSectionId::unrecognized_reason_blobs)) {
            break;
        }

        if (!read_capture_index_stable_section_header(stream, section_header)) {
            result.status = CaptureIndexV16MetadataTierReadStatus::unrecognized_reason_framing_error;
            metadata = {};
            return result;
        }

        if (section_header.section_flags != kCaptureIndexStableSectionFlagRequired ||
            section_header.section_schema_version != kCaptureIndexStableUnrecognizedReasonBlobsSectionSchemaVersion) {
            result.failed_section_header = section_header;
            result.status =
                section_header.section_schema_version != kCaptureIndexStableUnrecognizedReasonBlobsSectionSchemaVersion
                    ? CaptureIndexV16MetadataTierReadStatus::unsupported_metadata_section_schema
                    : CaptureIndexV16MetadataTierReadStatus::unrecognized_reason_framing_error;
            metadata = {};
            return result;
        }

        const auto payload_file_offset = stream.tellg();
        if (payload_file_offset == std::istream::pos_type(-1) ||
            !skip_section_payload(stream, section_header.payload_size)) {
            result.failed_section_header = section_header;
            result.status = CaptureIndexV16MetadataTierReadStatus::unrecognized_reason_framing_error;
            metadata = {};
            return result;
        }

        metadata.unrecognized_reason_sections.push_back(CaptureIndexV16UnrecognizedReasonSectionInfo {
            .section_occurrence_index = static_cast<std::uint32_t>(metadata.unrecognized_reason_sections.size()),
            .payload_file_offset = static_cast<std::uint64_t>(payload_file_offset),
            .payload_size = section_header.payload_size,
        });
    }

    if (metadata.unrecognized_reason_sections.empty()) {
        result.status = CaptureIndexV16MetadataTierReadStatus::missing_unrecognized_reason_blobs_section;
        metadata = {};
        return result;
    }

    {
        std::uint64_t logical_entry_start {0};
        while (true) {
            CaptureIndexStableSectionHeader section_header {};
            if (!try_peek_capture_index_stable_section_header(stream, section_header) ||
                section_header.section_id != static_cast<std::uint32_t>(CaptureIndexSectionId::packet_locator_v16)) {
                break;
            }

            if (!read_capture_index_stable_section_header(stream, section_header)) {
                result.status = CaptureIndexV16MetadataTierReadStatus::packet_locator_framing_error;
                metadata = {};
                return result;
            }

            CaptureIndexV16PacketLocatorSectionInfo section_info {};
            if (!read_v16_packet_locator_section_catalog_entry(
                    stream,
                    section_header,
                    static_cast<std::uint32_t>(metadata.packet_locator_sections.size()),
                    logical_entry_start,
                    section_info)) {
                result.failed_section_header = section_header;
                result.status =
                    section_header.section_schema_version != kCaptureIndexStablePacketLocatorV16SectionSchemaVersion
                        ? CaptureIndexV16MetadataTierReadStatus::unsupported_metadata_section_schema
                        : CaptureIndexV16MetadataTierReadStatus::packet_locator_framing_error;
                metadata = {};
                return result;
            }

            if (!metadata.packet_locator_sections.empty()) {
                const auto& prior = metadata.packet_locator_sections.back();
                if (prior.last_packet_index.has_value() &&
                    section_info.first_packet_index.has_value() &&
                    (*section_info.first_packet_index <= *prior.last_packet_index ||
                     *section_info.first_file_offset <= *prior.last_file_offset)) {
                    result.status = CaptureIndexV16MetadataTierReadStatus::packet_locator_semantic_inconsistency;
                    result.error_detail =
                        "packet locator section boundaries must be strictly increasing by packet_index and file_offset";
                    metadata = {};
                    return result;
                }
            }

            if (!checked_add_u64(logical_entry_start, section_info.entry_count, logical_entry_start)) {
                result.failed_section_header = section_header;
                result.status = CaptureIndexV16MetadataTierReadStatus::packet_locator_semantic_inconsistency;
                result.error_detail = "packet locator logical entry range overflowed";
                metadata = {};
                return result;
            }
            metadata.packet_locator_sections.push_back(section_info);
        }
    }

    if (metadata.packet_locator_sections.empty()) {
        result.status = CaptureIndexV16MetadataTierReadStatus::missing_packet_locator_section;
        metadata = {};
        return result;
    }

    const auto metadata_end_offset = stream.tellg();
    if (metadata_end_offset == std::istream::pos_type(-1)) {
        result.status = CaptureIndexV16MetadataTierReadStatus::invalid_metadata_section_framing;
        metadata = {};
        return result;
    }

    if (metadata.connection_count() != total_flow_count) {
        result.status = CaptureIndexV16MetadataTierReadStatus::metadata_semantic_inconsistency;
        result.error_detail = "metadata row count does not match the canonical flow count in the fast snapshot";
        metadata = {};
        return result;
    }

    std::vector<bool> seen_ordinals(total_flow_count, false);
    std::unordered_map<ProtocolPathId, std::vector<std::uint32_t>> expected_membership {};
    std::unordered_map<std::uint64_t, std::uint64_t> expected_directory_packet_counts {};
    expected_membership.reserve(metadata.connection_count());
    expected_directory_packet_counts.reserve(metadata.connection_count() * 2U);

    auto validate_metadata_rows =
        [&](const auto& rows) -> bool {
            for (const auto& row : rows) {
                if (row.canonical_connection_ordinal >= total_flow_count ||
                    seen_ordinals[row.canonical_connection_ordinal]) {
                    result.status = CaptureIndexV16MetadataTierReadStatus::metadata_semantic_inconsistency;
                    result.error_detail = "canonical connection ordinals must be unique and dense";
                    return false;
                }

                if (!validate_v16_connection_metadata_row(
                        row,
                        result.fast_statistics_tier.protocol_path_registry,
                        result.error_detail)) {
                    result.status = CaptureIndexV16MetadataTierReadStatus::metadata_semantic_inconsistency;
                    return false;
                }

                seen_ordinals[row.canonical_connection_ordinal] = true;
                expected_membership[row.key.protocol_path_id].push_back(row.canonical_connection_ordinal);
                expected_directory_packet_counts.emplace(
                    direction_identity_key(row.canonical_connection_ordinal, Direction::a_to_b),
                    row.flow_a.packet_count
                );
                if (row.has_flow_b) {
                    expected_directory_packet_counts.emplace(
                        direction_identity_key(row.canonical_connection_ordinal, Direction::b_to_a),
                        row.flow_b.packet_count
                    );
                }
            }

            return true;
        };

    if (!validate_metadata_rows(metadata.ipv4_connections) ||
        !validate_metadata_rows(metadata.ipv6_connections)) {
        metadata = {};
        return result;
    }

    if (std::any_of(seen_ordinals.begin(), seen_ordinals.end(), [](const bool seen) { return !seen; })) {
        result.status = CaptureIndexV16MetadataTierReadStatus::metadata_semantic_inconsistency;
        result.error_detail = "canonical connection ordinals must cover the full [0, total_flow_count) range";
        metadata = {};
        return result;
    }

    std::unordered_map<ProtocolPathId, std::vector<std::uint32_t>> actual_membership {};
    actual_membership.reserve(metadata.protocol_path_membership.size());
    for (const auto& row : metadata.protocol_path_membership) {
        if (row.protocol_path_id == kInvalidProtocolPathId ||
            result.fast_statistics_tier.protocol_path_registry.find(row.protocol_path_id) == nullptr) {
            result.status = CaptureIndexV16MetadataTierReadStatus::protocol_path_membership_semantic_inconsistency;
            result.error_detail = "protocol path membership referenced an unknown protocol path id";
            metadata = {};
            return result;
        }

        auto& ordinals = actual_membership[row.protocol_path_id];
        ordinals.insert(
            ordinals.end(),
            row.canonical_connection_ordinals.begin(),
            row.canonical_connection_ordinals.end()
        );
    }

    for (auto& [path_id, ordinals] : actual_membership) {
        static_cast<void>(path_id);
        if (!std::is_sorted(ordinals.begin(), ordinals.end()) ||
            std::adjacent_find(ordinals.begin(), ordinals.end()) != ordinals.end()) {
            result.status = CaptureIndexV16MetadataTierReadStatus::protocol_path_membership_semantic_inconsistency;
            result.error_detail = "protocol path membership ordinals must be strictly increasing without duplicates";
            metadata = {};
            return result;
        }

        if (std::any_of(ordinals.begin(), ordinals.end(), [&](const std::uint32_t ordinal) {
                return ordinal >= total_flow_count;
            })) {
            result.status = CaptureIndexV16MetadataTierReadStatus::protocol_path_membership_semantic_inconsistency;
            result.error_detail = "protocol path membership ordinal is outside the canonical flow ordinal range";
            metadata = {};
            return result;
        }
    }

    if (actual_membership != expected_membership) {
        result.status = CaptureIndexV16MetadataTierReadStatus::protocol_path_membership_semantic_inconsistency;
        result.error_detail = "protocol path membership rows do not match canonical metadata protocol path ownership";
        metadata = {};
        return result;
    }

    std::unordered_map<std::uint64_t, CaptureIndexV16PacketRefDirectoryEntry> directory_by_identity {};
    directory_by_identity.reserve(metadata.packetref_directory.size());
    for (const auto& row : metadata.packetref_directory) {
        const auto identity = direction_identity_key(row.canonical_connection_ordinal, row.direction);
        if (!directory_by_identity.emplace(identity, row).second) {
            result.status = CaptureIndexV16MetadataTierReadStatus::packetref_directory_semantic_inconsistency;
            result.error_detail = "duplicate packetref directory identity detected";
            metadata = {};
            return result;
        }

        const auto expected_length = encoded_packetref_extent_length(row.packet_count);
        if (!expected_length.has_value() || row.encoded_byte_length != *expected_length) {
            result.status = CaptureIndexV16MetadataTierReadStatus::packetref_directory_semantic_inconsistency;
            result.error_detail = "packetref directory entry encoded length is inconsistent with packet_count";
            metadata = {};
            return result;
        }

        const auto detail_section_it = std::find_if(
            metadata.packetref_detail_sections.begin(),
            metadata.packetref_detail_sections.end(),
            [&](const auto& detail_section) {
                return detail_section.section_occurrence_index == row.detail_section_occurrence_index;
            }
        );
        if (detail_section_it == metadata.packetref_detail_sections.end() ||
            row.payload_offset > detail_section_it->payload_size ||
            row.encoded_byte_length > detail_section_it->payload_size ||
            row.payload_offset > detail_section_it->payload_size - row.encoded_byte_length) {
            result.status = CaptureIndexV16MetadataTierReadStatus::detail_section_range_inconsistency;
            result.error_detail = "packetref directory entry extent is out of bounds for the referenced detail section";
            metadata = {};
            return result;
        }
    }

    if (directory_by_identity.size() != expected_directory_packet_counts.size()) {
        result.status = CaptureIndexV16MetadataTierReadStatus::metadata_directory_inconsistency;
        result.error_detail = "packetref directory entries do not match metadata directional presence";
        metadata = {};
        return result;
    }

    for (const auto& [identity, packet_count] : expected_directory_packet_counts) {
        const auto found = directory_by_identity.find(identity);
        if (found == directory_by_identity.end() || found->second.packet_count != packet_count) {
            result.status = CaptureIndexV16MetadataTierReadStatus::metadata_directory_inconsistency;
            result.error_detail = "packetref directory packet counts do not match metadata directional packet counts";
            metadata = {};
            return result;
        }
    }

    const auto expected_unrecognized_count =
        result.fast_statistics_tier.capture_statistics_snapshot.unrecognized_packet_count;
    const auto actual_unrecognized_count =
        metadata.unrecognized_directory_sections.empty()
            ? 0U
            : metadata.unrecognized_directory_sections.back().logical_row_start +
                metadata.unrecognized_directory_sections.back().row_count;
    if (actual_unrecognized_count != expected_unrecognized_count) {
        result.status = CaptureIndexV16MetadataTierReadStatus::unrecognized_directory_semantic_inconsistency;
        result.error_detail = "unrecognized directory row count does not match the fast snapshot unrecognized packet count";
        metadata = {};
        return result;
    }

    auto validate_orientation =
        [&](const auto& rows) -> bool {
            for (const auto& row : rows) {
                if (!row.has_flow_b) {
                    continue;
                }

                const auto a_identity = direction_identity_key(row.canonical_connection_ordinal, Direction::a_to_b);
                const auto b_identity = direction_identity_key(row.canonical_connection_ordinal, Direction::b_to_a);
                const auto a_it = directory_by_identity.find(a_identity);
                const auto b_it = directory_by_identity.find(b_identity);
                if (a_it == directory_by_identity.end() || b_it == directory_by_identity.end()) {
                    result.status = CaptureIndexV16MetadataTierReadStatus::metadata_directory_inconsistency;
                    result.error_detail = "orientation validation could not resolve both directional packetref extents";
                    return false;
                }

                const auto a_read = read_v16_packetref_extent_range_impl(
                    stream,
                    metadata.packetref_detail_sections,
                    a_it->second,
                    0U,
                    1U
                );
                const auto b_read = read_v16_packetref_extent_range_impl(
                    stream,
                    metadata.packetref_detail_sections,
                    b_it->second,
                    0U,
                    1U
                );
                if (!a_read || !b_read || a_read.packet_refs.empty() || b_read.packet_refs.empty()) {
                    result.status = CaptureIndexV16MetadataTierReadStatus::detail_section_range_inconsistency;
                    result.error_detail = !a_read ? a_read.error_detail : b_read.error_detail;
                    return false;
                }

                if (a_read.packet_refs.front().packet_index >= b_read.packet_refs.front().packet_index) {
                    result.status = CaptureIndexV16MetadataTierReadStatus::orientation_validation_failed;
                    result.error_detail = "metadata orientation does not match the earliest PacketRef ordering";
                    return false;
                }
            }

            return true;
        };

    if (!validate_orientation(metadata.ipv4_connections) ||
        !validate_orientation(metadata.ipv6_connections)) {
        metadata = {};
        return result;
    }

    stream.clear();
    stream.seekg(metadata_end_offset);
    if (!stream) {
        result.status = CaptureIndexV16MetadataTierReadStatus::invalid_metadata_section_framing;
        metadata = {};
        return result;
    }

    return result;
}

CaptureIndexV16PacketRefExtentReadResult read_v16_packetref_extent_range(
    std::istream& stream,
    std::span<const CaptureIndexV16PacketRefDetailSectionInfo> detail_sections,
    const CaptureIndexV16PacketRefDirectoryEntry& descriptor,
    const std::uint64_t local_offset,
    const std::uint64_t limit
) {
    return read_v16_packetref_extent_range_impl(
        stream,
        detail_sections,
        descriptor,
        local_offset,
        limit
    );
}

CaptureIndexV16UnrecognizedDirectoryRangeReadResult read_v16_unrecognized_directory_range(
    std::istream& stream,
    std::span<const CaptureIndexV16UnrecognizedDirectorySectionInfo> directory_sections,
    const std::uint64_t offset,
    const std::uint64_t limit
) {
    return read_v16_unrecognized_directory_range_impl(stream, directory_sections, offset, limit);
}

CaptureIndexV16UnrecognizedReasonReadResult read_v16_unrecognized_reason(
    std::istream& stream,
    std::span<const CaptureIndexV16UnrecognizedReasonSectionInfo> reason_sections,
    const std::uint32_t section_occurrence_index,
    const std::uint64_t payload_offset,
    const std::uint64_t byte_length
) {
    CaptureIndexV16UnrecognizedReasonReadResult result {};

    const auto section_it = std::find_if(
        reason_sections.begin(),
        reason_sections.end(),
        [&](const auto& section) {
            return section.section_occurrence_index == section_occurrence_index;
        }
    );
    if (section_it == reason_sections.end()) {
        result.status = CaptureIndexV16UnrecognizedReasonReadStatus::invalid_reason_section_occurrence;
        result.error_detail = "directory entry referenced a missing unrecognized reason section occurrence";
        return result;
    }

    if (byte_length > kMaxCaptureIndexStableHeaderStringBytes) {
        result.status = CaptureIndexV16UnrecognizedReasonReadStatus::reason_length_too_large;
        result.error_detail = "unrecognized reason length exceeds the stable bounded string read limit";
        return result;
    }

    if (payload_offset > section_it->payload_size ||
        byte_length > section_it->payload_size ||
        payload_offset > section_it->payload_size - byte_length) {
        result.status = CaptureIndexV16UnrecognizedReasonReadStatus::invalid_reason_range;
        result.error_detail = "directory entry reason extent lies outside the referenced reason section payload";
        return result;
    }

    const auto read_offset = section_it->payload_file_offset + payload_offset;
    const auto restore_offset = stream.tellg();
    if (restore_offset == std::istream::pos_type(-1)) {
        stream.clear();
    }

    stream.clear();
    stream.seekg(static_cast<std::streamoff>(read_offset), std::ios::beg);
    if (!stream) {
        result.status = CaptureIndexV16UnrecognizedReasonReadStatus::section_seek_failed;
        result.error_detail = "failed to seek to the requested unrecognized reason payload";
        return result;
    }

    result.reason_text.assign(static_cast<std::size_t>(byte_length), '\0');
    if (byte_length > 0U) {
        auto bytes = std::span<std::uint8_t>(
            reinterpret_cast<std::uint8_t*>(result.reason_text.data()),
            result.reason_text.size()
        );
        if (!read_bytes(stream, bytes)) {
            if (restore_offset != std::istream::pos_type(-1)) {
                stream.clear();
                stream.seekg(restore_offset);
            }
            result.status = CaptureIndexV16UnrecognizedReasonReadStatus::truncated_reason_payload;
            result.error_detail = "reason payload ended before the referenced byte range was fully read";
            result.reason_text.clear();
            return result;
        }
    }

    if (restore_offset != std::istream::pos_type(-1)) {
        stream.clear();
        stream.seekg(restore_offset);
    }

    return result;
}

CaptureIndexV16PacketLocatorLookupReadResult lookup_v16_packet_locator(
    std::istream& stream,
    std::span<const CaptureIndexV16PacketLocatorSectionInfo> locator_sections,
    const std::uint64_t packet_index
) {
    CaptureIndexV16PacketLocatorLookupReadResult result {};

    std::uint64_t expected_logical_entry_start {0};
    for (std::size_t index = 0U; index < locator_sections.size(); ++index) {
        const auto& section = locator_sections[index];
        if (section.section_occurrence_index != static_cast<std::uint32_t>(index) ||
            section.logical_entry_start != expected_logical_entry_start) {
            result.status = CaptureIndexV16PacketLocatorLookupReadStatus::invalid_locator_section_occurrence;
            result.error_detail = "packet locator catalog does not preserve stable occurrence ordering";
            return result;
        }
        if (!checked_add_u64(expected_logical_entry_start, section.entry_count, expected_logical_entry_start)) {
            result.status = CaptureIndexV16PacketLocatorLookupReadStatus::section_range_overflow;
            result.error_detail = "packet locator catalog logical entry count overflowed";
            return result;
        }
    }

    const CaptureIndexV16PacketLocatorSectionInfo* candidate_section {nullptr};
    for (const auto& section : locator_sections) {
        if (section.entry_count == 0U) {
            continue;
        }
        if (!section.first_packet_index.has_value() ||
            !section.last_packet_index.has_value() ||
            !section.first_file_offset.has_value() ||
            !section.last_file_offset.has_value()) {
            result.status = CaptureIndexV16PacketLocatorLookupReadStatus::malformed_packet_locator_payload;
            result.error_detail = "packet locator catalog is missing non-empty section boundary metadata";
            return result;
        }
        if (*section.first_packet_index <= packet_index) {
            candidate_section = &section;
        } else {
            break;
        }
    }

    if (candidate_section == nullptr) {
        result.status = CaptureIndexV16PacketLocatorLookupReadStatus::not_found;
        result.error_detail = "packet index precedes the first available locator anchor";
        return result;
    }

    std::uint64_t low {0};
    std::uint64_t high {candidate_section->entry_count};
    while (low < high) {
        const auto mid = low + ((high - low) / 2U);
        CapturePacketLocatorEntry entry {};
        if (!read_v16_packet_locator_entry_at(stream, *candidate_section, mid, entry)) {
            result.status = CaptureIndexV16PacketLocatorLookupReadStatus::truncated_packet_locator_payload;
            result.error_detail = "packet locator lookup could not read the requested fixed-size entry";
            return result;
        }

        if (entry.packet_index <= packet_index) {
            low = mid + 1U;
        } else {
            high = mid;
        }
    }

    if (low == 0U) {
        result.status = CaptureIndexV16PacketLocatorLookupReadStatus::not_found;
        result.error_detail = "packet index precedes the selected locator section";
        return result;
    }

    const auto found_index = low - 1U;
    CapturePacketLocatorEntry found {};
    if (!read_v16_packet_locator_entry_at(stream, *candidate_section, found_index, found)) {
        result.status = CaptureIndexV16PacketLocatorLookupReadStatus::truncated_packet_locator_payload;
        result.error_detail = "packet locator lookup could not read the resolved fixed-size entry";
        return result;
    }

    if (found_index > 0U) {
        CapturePacketLocatorEntry previous {};
        if (!read_v16_packet_locator_entry_at(stream, *candidate_section, found_index - 1U, previous)) {
            result.status = CaptureIndexV16PacketLocatorLookupReadStatus::truncated_packet_locator_payload;
            result.error_detail = "packet locator lookup could not read the preceding fixed-size entry";
            return result;
        }
        if (found.packet_index <= previous.packet_index || found.file_offset <= previous.file_offset) {
            result.status = CaptureIndexV16PacketLocatorLookupReadStatus::malformed_packet_locator_payload;
            result.error_detail = "packet locator entries touched by lookup are not strictly increasing";
            return result;
        }
    }

    if (found_index + 1U < candidate_section->entry_count) {
        CapturePacketLocatorEntry next {};
        if (!read_v16_packet_locator_entry_at(stream, *candidate_section, found_index + 1U, next)) {
            result.status = CaptureIndexV16PacketLocatorLookupReadStatus::truncated_packet_locator_payload;
            result.error_detail = "packet locator lookup could not read the following fixed-size entry";
            return result;
        }
        if (next.packet_index <= found.packet_index || next.file_offset <= found.file_offset) {
            result.status = CaptureIndexV16PacketLocatorLookupReadStatus::malformed_packet_locator_payload;
            result.error_detail = "packet locator entries touched by lookup are not strictly increasing";
            return result;
        }
    }

    result.entry = found;
    return result;
}

CaptureIndexV16CompleteReadResult read_capture_index_v16(
    std::istream& stream
) {
    CaptureIndexV16CompleteReadResult result {};
    const auto metadata_result = read_v16_metadata_tier(stream, result.metadata);
    result.metadata_status = metadata_result.status;
    result.header = metadata_result.header;
    result.failed_section_header = metadata_result.failed_section_header;
    result.fast_statistics_tier = metadata_result.fast_statistics_tier;
    result.error_detail = metadata_result.error_detail;
    if (!metadata_result) {
        result.status = CaptureIndexV16CompleteReadStatus::invalid_metadata_tier;
        result.metadata = {};
        return result;
    }

    stream.clear();
    if (stream.peek() != std::char_traits<char>::eof()) {
        result.status = CaptureIndexV16CompleteReadStatus::trailing_data;
        result.error_detail = "v16 index contains trailing data after the frozen section topology";
        result.metadata = {};
        return result;
    }

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












