#pragma once

#include <cstdint>
#include <filesystem>
#include <functional>
#include <iosfwd>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "core/domain/CaptureState.h"
#include "core/index/CaptureIndex.h"

namespace pfl::detail {

enum class CaptureIndexSectionId : std::uint32_t {
    source_info = 1,
    summary = 2,
    protocol_paths = 3,
    ipv4_connections = 4,
    ipv6_connections = 5,
    unrecognized_packets = 6,
    packet_locator = 7,
};

inline constexpr std::uint16_t kCaptureIndexStableSectionFlagRequired = 0x0001U;
inline constexpr std::uint16_t kCaptureIndexStableSummarySectionSchemaVersion = 1U;
inline constexpr std::uint16_t kCaptureIndexStableProtocolPathsSectionSchemaVersion = 1U;
inline constexpr std::uint16_t kCaptureIndexStableIpv4ConnectionsSectionSchemaVersion = 2U;
inline constexpr std::uint16_t kCaptureIndexStableIpv6ConnectionsSectionSchemaVersion = 2U;
inline constexpr std::uint16_t kCaptureIndexStableUnrecognizedPacketsSectionSchemaVersion = 2U;
inline constexpr std::uint16_t kCaptureIndexStablePacketLocatorSectionSchemaVersion = 1U;
inline constexpr std::uint32_t kMaxCaptureIndexStableHeaderStringBytes = 1024U * 1024U;
inline constexpr std::uint32_t kCaptureIndexStableHeaderKnownPrefixSize =
    8U + 2U + 2U + 4U + 4U + 4U + 1U + 8U + 8U + 8U + 4U;
inline constexpr std::uint32_t kCaptureIndexStableSectionHeaderEncodedSize = 16U;

// v15+ stable-container wire contract:
// little-endian integrals, UTF-8 length-prefixed strings, and explicit field
// encoding independent of host ABI/padding.
struct CaptureIndexStableHeader {
    std::uint64_t magic {kStableCaptureIndexMagic};
    std::uint16_t container_format_version {kCaptureIndexStableContainerFormatVersion};
    std::uint16_t header_flags {0};
    std::uint32_t header_size {0};
    std::uint32_t index_revision {kCaptureIndexStableIndexRevision};
    std::string writer_application_version {};
    CaptureSourceFormat source_format {CaptureSourceFormat::unknown};
    std::uint64_t source_file_size {0};
    std::int64_t source_last_write_time {0};
    std::uint64_t source_content_fingerprint {0};
    std::string source_capture_path_utf8 {};
};

struct CaptureIndexStableSectionHeader {
    std::uint32_t section_id {0};
    std::uint16_t section_schema_version {0};
    std::uint16_t section_flags {0};
    std::uint64_t payload_size {0};
};

bool write_bytes(std::ostream& stream, std::span<const std::uint8_t> bytes);
bool write_u8(std::ostream& stream, std::uint8_t value);
bool write_u16(std::ostream& stream, std::uint16_t value);
bool write_u32(std::ostream& stream, std::uint32_t value);
bool write_u64(std::ostream& stream, std::uint64_t value);
bool write_i64(std::ostream& stream, std::int64_t value);
bool write_string(std::ostream& stream, const std::string& value);

bool read_bytes(std::istream& stream, std::span<std::uint8_t> bytes);
bool read_u8(std::istream& stream, std::uint8_t& value);
bool read_u16(std::istream& stream, std::uint16_t& value);
bool read_u32(std::istream& stream, std::uint32_t& value);
bool read_u64(std::istream& stream, std::uint64_t& value);
bool read_i64(std::istream& stream, std::int64_t& value);
bool read_string(std::istream& stream, std::string& value);

[[nodiscard]] std::optional<std::uint32_t> encoded_capture_index_stable_header_size(
    const CaptureIndexStableHeader& header,
    std::uint32_t extension_size = 0U
) noexcept;
bool write_capture_index_stable_header(
    std::ostream& stream,
    const CaptureIndexStableHeader& header,
    std::span<const std::uint8_t> extension_bytes = {}
);
bool read_capture_index_stable_header(std::istream& stream, CaptureIndexStableHeader& header);
[[nodiscard]] std::string filesystem_path_to_generic_utf8(const std::filesystem::path& path);
[[nodiscard]] std::filesystem::path filesystem_path_from_generic_utf8(std::string_view utf8_path);
bool write_capture_index_stable_section_header(
    std::ostream& stream,
    const CaptureIndexStableSectionHeader& header
);
bool read_capture_index_stable_section_header(
    std::istream& stream,
    CaptureIndexStableSectionHeader& header
);

bool write_section(std::ostream& stream, std::uint32_t section_id, std::span<const std::uint8_t> payload);
bool read_section_header(std::istream& stream, std::uint32_t& section_id, std::uint64_t& payload_size);
bool read_section_payload(std::istream& stream, std::uint64_t payload_size, std::vector<std::uint8_t>& payload);

bool write_capture_source_info(std::ostream& stream, const CaptureSourceInfo& source_info);
bool read_capture_source_info(std::istream& stream, CaptureSourceInfo& source_info);

bool write_capture_summary(std::ostream& stream, const CaptureSummary& summary);
bool read_capture_summary(std::istream& stream, CaptureSummary& summary);

using SerializationProgressCallback = std::function<bool(std::uint64_t processed, std::uint64_t total)>;

bool write_protocol_path_registry(std::ostream& stream, const ProtocolPathRegistry& registry);
bool write_protocol_path_registry(
    std::ostream& stream,
    const ProtocolPathRegistry& registry,
    const SerializationProgressCallback& progress_callback
);
bool read_protocol_path_registry(std::istream& stream, ProtocolPathRegistry& registry);

bool write_packet_ref(std::ostream& stream, const PacketRef& packet);
bool read_packet_ref(std::istream& stream, PacketRef& packet);

bool write_flow(std::ostream& stream, const FlowV4& flow);
bool write_flow(std::ostream& stream, const FlowV6& flow);
bool read_flow(std::istream& stream, FlowV4& flow);
bool read_flow(std::istream& stream, FlowV6& flow);

bool write_connection(std::ostream& stream, const ConnectionV4& connection);
bool write_connection(std::ostream& stream, const ConnectionV6& connection);
bool read_connection(std::istream& stream, ConnectionV4& connection);
bool read_connection(std::istream& stream, ConnectionV6& connection);

bool write_connection_table(std::ostream& stream, const ConnectionTableV4& table);
bool write_connection_table(std::ostream& stream, const ConnectionTableV6& table);
bool write_connection_table(
    std::ostream& stream,
    const ConnectionTableV4& table,
    const SerializationProgressCallback& progress_callback
);
bool write_connection_table(
    std::ostream& stream,
    const ConnectionTableV6& table,
    const SerializationProgressCallback& progress_callback
);
bool read_connection_table_chunk(
    std::istream& stream,
    ConnectionTableV4& table,
    CapturePacketStatistics* packet_statistics = nullptr
);
bool read_connection_table_chunk(
    std::istream& stream,
    ConnectionTableV6& table,
    CapturePacketStatistics* packet_statistics = nullptr
);
bool read_connection_table(
    std::istream& stream,
    ConnectionTableV4& table,
    CapturePacketStatistics* packet_statistics = nullptr
);
bool read_connection_table(
    std::istream& stream,
    ConnectionTableV6& table,
    CapturePacketStatistics* packet_statistics = nullptr
);

bool write_unrecognized_packet_records(
    std::ostream& stream,
    std::span<const UnrecognizedPacketRecord> records
);
bool write_unrecognized_packet_records(
    std::ostream& stream,
    std::span<const UnrecognizedPacketRecord> records,
    const SerializationProgressCallback& progress_callback
);
bool read_unrecognized_packet_records(
    std::istream& stream,
    std::vector<UnrecognizedPacketRecord>& records,
    CapturePacketStatistics* packet_statistics = nullptr
);

bool write_capture_packet_locator(
    std::ostream& stream,
    std::span<const CapturePacketLocatorEntry> entries
);
bool read_capture_packet_locator(
    std::istream& stream,
    std::vector<CapturePacketLocatorEntry>& entries
);

bool write_capture_state(std::ostream& stream, const CaptureState& state);
bool read_capture_state(
    std::istream& stream,
    CaptureState& state,
    CapturePacketStatistics* packet_statistics = nullptr
);

std::vector<const ConnectionV4*> sorted_connections(const ConnectionTableV4& table);
std::vector<const ConnectionV6*> sorted_connections(const ConnectionTableV6& table);

}  // namespace pfl::detail
