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

#include "core/domain/CaptureStatisticsSnapshot.h"
#include "core/domain/CaptureState.h"
#include "core/index/CaptureIndex.h"
#include "core/index/CaptureIndexV16.h"

namespace pfl::detail {

enum class CaptureIndexSectionId : std::uint32_t {
    source_info = 1,
    summary = 2,
    protocol_paths = 3,
    ipv4_connections = 4,
    ipv6_connections = 5,
    unrecognized_packets = 6,
    packet_locator = 7,
    capture_statistics_snapshot = 8,
    protocol_path_registry_early = 9,
    protocol_path_terminal_aggregates = 10,
    ipv4_flow_metadata = 11,
    ipv6_flow_metadata = 12,
    protocol_path_membership = 13,
    packetref_directory = 14,
    unrecognized_directory = 15,
    packetref_detail_blocks = 16,
    unrecognized_reason_blobs = 17,
    packet_locator_v16 = 18,
};

inline constexpr std::uint16_t kCaptureIndexStableSectionFlagRequired = 0x0001U;
inline constexpr std::uint16_t kCaptureIndexStableSummarySectionSchemaVersion = 1U;
inline constexpr std::uint16_t kCaptureIndexStableProtocolPathsSectionSchemaVersion = 1U;
inline constexpr std::uint16_t kCaptureIndexStableIpv4ConnectionsSectionSchemaVersion = 2U;
inline constexpr std::uint16_t kCaptureIndexStableIpv6ConnectionsSectionSchemaVersion = 2U;
inline constexpr std::uint16_t kCaptureIndexStableUnrecognizedPacketsSectionSchemaVersion = 2U;
inline constexpr std::uint16_t kCaptureIndexStablePacketLocatorSectionSchemaVersion = 1U;
inline constexpr std::uint16_t kCaptureIndexStableCaptureStatisticsSnapshotSectionSchemaVersion = 1U;
inline constexpr std::uint16_t kCaptureIndexStableProtocolPathRegistryEarlySectionSchemaVersion = 1U;
inline constexpr std::uint16_t kCaptureIndexStableProtocolPathTerminalAggregatesSectionSchemaVersion = 1U;
inline constexpr std::uint16_t kCaptureIndexStableIpv4FlowMetadataSectionSchemaVersion = 1U;
inline constexpr std::uint16_t kCaptureIndexStableIpv6FlowMetadataSectionSchemaVersion = 1U;
inline constexpr std::uint16_t kCaptureIndexStableProtocolPathMembershipSectionSchemaVersion = 1U;
inline constexpr std::uint16_t kCaptureIndexStablePacketRefDirectorySectionSchemaVersion = 1U;
inline constexpr std::uint16_t kCaptureIndexStablePacketRefDetailBlocksSectionSchemaVersion = 1U;
inline constexpr std::uint16_t kCaptureIndexStableUnrecognizedDirectorySectionSchemaVersion = 1U;
inline constexpr std::uint16_t kCaptureIndexStableUnrecognizedReasonBlobsSectionSchemaVersion = 1U;
inline constexpr std::uint16_t kCaptureIndexStablePacketLocatorV16SectionSchemaVersion = 1U;
inline constexpr std::uint32_t kMaxCaptureIndexStableHeaderStringBytes = 1024U * 1024U;
inline constexpr std::uint32_t kMaxCaptureStatisticsSnapshotServiceHintBytes = 1024U * 1024U;
inline constexpr std::uint32_t kCaptureIndexStableHeaderKnownPrefixSize =
    8U + 2U + 2U + 4U + 4U + 4U + 1U + 8U + 8U + 8U + 4U;
inline constexpr std::uint32_t kCaptureIndexStableSectionHeaderEncodedSize = 16U;

[[nodiscard]] constexpr std::uint64_t max_capture_statistics_snapshot_payload_size_bytes() noexcept {
    constexpr std::uint64_t kWorstCaseEndpointIdentityBytes = 1U + 18U;
    constexpr std::uint64_t kWorstCaseEndpointIdentityForFamilyBytes = 18U;
    constexpr std::uint64_t kWorstCaseConnectionKeyBytes = 41U;
    constexpr std::uint64_t kProtocolCountersRowBytes = 1U + (4U * 8U);
    constexpr std::uint64_t kPacketSizeDistributionBytes =
        8U + 4U + (static_cast<std::uint64_t>(kCapturePacketSizeStatisticsBucketCount) * 8U);
    constexpr std::uint64_t kFlowPacketHistogramBucketBytes = 3U * 8U;
    constexpr std::uint64_t kTopEndpointRowBytes = kWorstCaseEndpointIdentityBytes + (4U * 8U);
    constexpr std::uint64_t kTopPortRowBytes = 2U + (4U * 8U);
    constexpr std::uint64_t kTopFlowRowBytes =
        4U + 1U + kWorstCaseConnectionKeyBytes +
        kWorstCaseEndpointIdentityForFamilyBytes + kWorstCaseEndpointIdentityForFamilyBytes +
        1U + 1U + 4U + static_cast<std::uint64_t>(kMaxCaptureStatisticsSnapshotServiceHintBytes) +
        4U + (3U * 8U);

    return
        1U + (4U * 8U) +
        1U + (2U * 8U) + 8U + 4U + 4U +
        kPacketSizeDistributionBytes + kPacketSizeDistributionBytes +
        (3U * 8U) + (2U * 8U) + (3U * 8U) + (3U * 8U) + (3U * 8U) +
        (9U * 8U) + 4U +
        (static_cast<std::uint64_t>(kCaptureStatisticsFlowPacketCountHistogramBucketCount) *
         kFlowPacketHistogramBucketBytes) +
        4U + (4U * kProtocolCountersRowBytes) +
        4U + (2U * kProtocolCountersRowBytes) +
        4U + (16U * kProtocolCountersRowBytes) +
        (13U * 8U) +
        4U + (static_cast<std::uint64_t>(kCaptureStatisticsSnapshotTopEndpointCapacity) * kTopEndpointRowBytes) +
        4U + (static_cast<std::uint64_t>(kCaptureStatisticsSnapshotTopPortCapacity) * kTopPortRowBytes) +
        4U + (static_cast<std::uint64_t>(kCaptureStatisticsSnapshotTopFlowCapacity) * kTopFlowRowBytes);
}

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
bool skip_section_payload(std::istream& stream, std::uint64_t payload_size);
bool read_bounded_section_payload(
    std::istream& stream,
    std::uint64_t payload_size,
    std::uint64_t max_payload_size,
    std::vector<std::uint8_t>& payload
);

enum class CaptureStatisticsSnapshotSectionReadStatus : std::uint8_t {
    ok = 0,
    invalid_section_header,
    wrong_section_id,
    invalid_section_framing,
    unsupported_schema_version,
    payload_too_large,
    truncated_payload,
    malformed_snapshot_payload,
    snapshot_semantic_inconsistency,
};

struct CaptureStatisticsSnapshotSectionReadResult {
    CaptureStatisticsSnapshotSectionReadStatus status {CaptureStatisticsSnapshotSectionReadStatus::ok};
    CaptureIndexStableSectionHeader section_header {};
    std::optional<CaptureStatisticsSnapshotValidationError> validation_error {};

    [[nodiscard]] explicit operator bool() const noexcept {
        return status == CaptureStatisticsSnapshotSectionReadStatus::ok;
    }
};

enum class ProtocolPathRegistrySectionReadStatus : std::uint8_t {
    ok = 0,
    invalid_section_header,
    wrong_section_id,
    invalid_section_framing,
    unsupported_schema_version,
    truncated_payload,
    malformed_protocol_path_registry_payload,
};

struct ProtocolPathRegistrySectionReadResult {
    ProtocolPathRegistrySectionReadStatus status {ProtocolPathRegistrySectionReadStatus::ok};
    CaptureIndexStableSectionHeader section_header {};

    [[nodiscard]] explicit operator bool() const noexcept {
        return status == ProtocolPathRegistrySectionReadStatus::ok;
    }
};

enum class ProtocolPathDisplayStatisticsSectionReadStatus : std::uint8_t {
    ok = 0,
    invalid_section_header,
    wrong_section_id,
    invalid_section_framing,
    unsupported_schema_version,
    truncated_payload,
    malformed_protocol_path_display_statistics_payload,
    protocol_path_display_statistics_semantic_inconsistency,
};

struct ProtocolPathDisplayStatisticsSectionReadResult {
    ProtocolPathDisplayStatisticsSectionReadStatus status {
        ProtocolPathDisplayStatisticsSectionReadStatus::ok
    };
    CaptureIndexStableSectionHeader section_header {};
    std::optional<ProtocolPathDisplayStatisticsValidationError> validation_error {};

    [[nodiscard]] explicit operator bool() const noexcept {
        return status == ProtocolPathDisplayStatisticsSectionReadStatus::ok;
    }
};

struct CaptureIndexV16FastStatisticsTier {
    CaptureStatisticsSnapshot capture_statistics_snapshot {};
    ProtocolPathRegistry protocol_path_registry {};
    ProtocolPathDisplayStatistics protocol_path_display_statistics {};

    [[nodiscard]] friend bool operator==(
        const CaptureIndexV16FastStatisticsTier&,
        const CaptureIndexV16FastStatisticsTier&
    ) = default;
};

enum class CaptureIndexV16FastStatisticsTierReadStatus : std::uint8_t {
    ok = 0,
    invalid_header,
    unsupported_revision,
    missing_capture_statistics_snapshot_section,
    duplicate_capture_statistics_snapshot_section,
    missing_protocol_path_registry_early_section,
    duplicate_protocol_path_registry_early_section,
    missing_protocol_path_terminal_aggregates_section,
    wrong_fast_section_order,
    invalid_fast_section_framing,
    unsupported_fast_section_schema,
    truncated_fast_section_payload,
    malformed_capture_statistics_snapshot_payload,
    capture_statistics_snapshot_semantic_inconsistency,
    malformed_protocol_path_registry_payload,
    malformed_protocol_path_terminal_aggregates_payload,
    protocol_path_terminal_aggregates_semantic_inconsistency,
    fast_tier_cross_section_inconsistency,
};

struct CaptureIndexV16FastStatisticsTierReadResult {
    CaptureIndexV16FastStatisticsTierReadStatus status {
        CaptureIndexV16FastStatisticsTierReadStatus::ok
    };
    CaptureIndexStableHeader header {};
    CaptureIndexStableSectionHeader failed_section_header {};
    std::optional<CaptureStatisticsSnapshotValidationError> capture_statistics_validation_error {};
    std::optional<ProtocolPathDisplayStatisticsValidationError> protocol_path_validation_error {};
    std::string error_detail {};

    [[nodiscard]] explicit operator bool() const noexcept {
        return status == CaptureIndexV16FastStatisticsTierReadStatus::ok;
    }
};

enum class CaptureIndexV16MetadataTierReadStatus : std::uint8_t {
    ok = 0,
    invalid_header,
    unsupported_revision,
    invalid_fast_tier,
    missing_ipv4_flow_metadata_section,
    missing_ipv6_flow_metadata_section,
    missing_protocol_path_membership_section,
    missing_packetref_directory_section,
    missing_unrecognized_directory_section,
    missing_packetref_detail_blocks_section,
    missing_unrecognized_reason_blobs_section,
    missing_packet_locator_section,
    wrong_metadata_section_order,
    invalid_metadata_section_framing,
    unsupported_metadata_section_schema,
    truncated_metadata_section_payload,
    malformed_ipv4_flow_metadata_payload,
    malformed_ipv6_flow_metadata_payload,
    malformed_protocol_path_membership_payload,
    malformed_packetref_directory_payload,
    malformed_unrecognized_directory_payload,
    metadata_semantic_inconsistency,
    protocol_path_membership_semantic_inconsistency,
    packetref_directory_semantic_inconsistency,
    unrecognized_directory_semantic_inconsistency,
    metadata_directory_inconsistency,
    detail_section_framing_error,
    detail_section_range_inconsistency,
    unrecognized_reason_framing_error,
    packet_locator_framing_error,
    packet_locator_semantic_inconsistency,
    orientation_validation_failed,
};

struct CaptureIndexV16MetadataTierReadResult {
    CaptureIndexV16MetadataTierReadStatus status {CaptureIndexV16MetadataTierReadStatus::ok};
    CaptureIndexStableHeader header {};
    CaptureIndexStableSectionHeader failed_section_header {};
    CaptureIndexV16FastStatisticsTier fast_statistics_tier {};
    std::string error_detail {};

    [[nodiscard]] explicit operator bool() const noexcept {
        return status == CaptureIndexV16MetadataTierReadStatus::ok;
    }
};

enum class CaptureIndexV16PacketRefExtentReadStatus : std::uint8_t {
    ok = 0,
    invalid_detail_section_occurrence,
    invalid_local_offset,
    invalid_requested_length,
    section_seek_failed,
    section_range_overflow,
    truncated_packetref_detail,
    malformed_packetref_detail,
    packet_index_not_strictly_increasing,
};

struct CaptureIndexV16PacketRefExtentReadResult {
    CaptureIndexV16PacketRefExtentReadStatus status {CaptureIndexV16PacketRefExtentReadStatus::ok};
    std::vector<PacketRef> packet_refs {};
    std::string error_detail {};

    [[nodiscard]] explicit operator bool() const noexcept {
        return status == CaptureIndexV16PacketRefExtentReadStatus::ok;
    }
};

enum class CaptureIndexV16UnrecognizedDirectoryRangeReadStatus : std::uint8_t {
    ok = 0,
    invalid_offset,
    invalid_requested_length,
    invalid_directory_section_occurrence,
    section_seek_failed,
    section_range_overflow,
    truncated_directory_payload,
    malformed_directory_payload,
    row_number_inconsistency,
    packet_index_not_strictly_increasing,
};

struct CaptureIndexV16UnrecognizedDirectoryRangeReadResult {
    CaptureIndexV16UnrecognizedDirectoryRangeReadStatus status {
        CaptureIndexV16UnrecognizedDirectoryRangeReadStatus::ok
    };
    std::vector<CaptureIndexV16UnrecognizedDirectoryEntry> rows {};
    std::uint64_t total_row_count {0};
    std::string error_detail {};

    [[nodiscard]] explicit operator bool() const noexcept {
        return status == CaptureIndexV16UnrecognizedDirectoryRangeReadStatus::ok;
    }
};

enum class CaptureIndexV16UnrecognizedReasonReadStatus : std::uint8_t {
    ok = 0,
    invalid_reason_section_occurrence,
    invalid_reason_range,
    reason_length_too_large,
    section_seek_failed,
    truncated_reason_payload,
};

struct CaptureIndexV16UnrecognizedReasonReadResult {
    CaptureIndexV16UnrecognizedReasonReadStatus status {
        CaptureIndexV16UnrecognizedReasonReadStatus::ok
    };
    std::string reason_text {};
    std::string error_detail {};

    [[nodiscard]] explicit operator bool() const noexcept {
        return status == CaptureIndexV16UnrecognizedReasonReadStatus::ok;
    }
};

enum class CaptureIndexV16PacketLocatorLookupReadStatus : std::uint8_t {
    ok = 0,
    not_found,
    invalid_locator_section_occurrence,
    section_seek_failed,
    section_range_overflow,
    truncated_packet_locator_payload,
    malformed_packet_locator_payload,
};

struct CaptureIndexV16PacketLocatorLookupReadResult {
    CaptureIndexV16PacketLocatorLookupReadStatus status {
        CaptureIndexV16PacketLocatorLookupReadStatus::ok
    };
    std::optional<CapturePacketLocatorEntry> entry {};
    std::string error_detail {};

    [[nodiscard]] explicit operator bool() const noexcept {
        return status == CaptureIndexV16PacketLocatorLookupReadStatus::ok;
    }
};

enum class CaptureIndexV16CompleteReadStatus : std::uint8_t {
    ok = 0,
    invalid_metadata_tier,
    trailing_data,
};

struct CaptureIndexV16CompleteReadResult {
    CaptureIndexV16CompleteReadStatus status {CaptureIndexV16CompleteReadStatus::ok};
    CaptureIndexV16MetadataTierReadStatus metadata_status {CaptureIndexV16MetadataTierReadStatus::ok};
    CaptureIndexStableHeader header {};
    CaptureIndexStableSectionHeader failed_section_header {};
    CaptureIndexV16FastStatisticsTier fast_statistics_tier {};
    CaptureIndexV16MetadataTier metadata {};
    std::string error_detail {};

    [[nodiscard]] explicit operator bool() const noexcept {
        return status == CaptureIndexV16CompleteReadStatus::ok;
    }
};

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
bool write_protocol_path_display_statistics(
    std::ostream& stream,
    const ProtocolPathDisplayStatistics& statistics
);
bool read_protocol_path_display_statistics(
    std::istream& stream,
    ProtocolPathDisplayStatistics& statistics
);

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
bool write_capture_statistics_snapshot(
    std::ostream& stream,
    const CaptureStatisticsSnapshot& snapshot
);
bool read_capture_statistics_snapshot(
    std::istream& stream,
    CaptureStatisticsSnapshot& snapshot
);
bool write_v16_capture_statistics_snapshot_section(
    std::ostream& stream,
    const CaptureStatisticsSnapshot& snapshot
);
CaptureStatisticsSnapshotSectionReadResult read_v16_capture_statistics_snapshot_section(
    std::istream& stream,
    CaptureStatisticsSnapshot& snapshot
);
bool write_v16_protocol_path_registry_early_section(
    std::ostream& stream,
    const ProtocolPathRegistry& registry
);
ProtocolPathRegistrySectionReadResult read_v16_protocol_path_registry_early_section(
    std::istream& stream,
    ProtocolPathRegistry& registry
);
bool write_v16_protocol_path_terminal_aggregates_section(
    std::ostream& stream,
    const ProtocolPathDisplayStatistics& statistics
);
ProtocolPathDisplayStatisticsSectionReadResult read_v16_protocol_path_terminal_aggregates_section(
    std::istream& stream,
    const ProtocolPathRegistry& registry,
    ProtocolPathDisplayStatistics& statistics
);
bool write_v16_fast_statistics_tier(
    std::ostream& stream,
    const CaptureIndexStableHeader& header,
    const CaptureIndexV16FastStatisticsTier& tier
);
CaptureIndexV16FastStatisticsTierReadResult read_v16_fast_statistics_tier(
    std::istream& stream,
    CaptureIndexV16FastStatisticsTier& tier
);
bool write_v16_ipv4_flow_metadata_section(
    std::ostream& stream,
    std::span<const CaptureIndexV16ConnectionMetadataV4> rows
);
bool write_v16_ipv6_flow_metadata_section(
    std::ostream& stream,
    std::span<const CaptureIndexV16ConnectionMetadataV6> rows
);
bool write_v16_protocol_path_membership_section(
    std::ostream& stream,
    std::span<const CaptureIndexV16ProtocolPathMembershipRow> rows
);
bool write_v16_packetref_directory_section(
    std::ostream& stream,
    std::span<const CaptureIndexV16PacketRefDirectoryEntry> rows
);
bool write_v16_unrecognized_directory_section(
    std::ostream& stream,
    const CaptureIndexV16UnrecognizedDirectorySectionWritePlan& section
);
bool write_v16_metadata_tier_sections(
    std::ostream& stream,
    const CaptureIndexV16WritePlan& plan
);
bool write_v16_packetref_detail_sections(
    std::ostream& stream,
    std::span<const CaptureIndexV16PacketRefDetailSectionWritePlan> sections
);
bool write_v16_unrecognized_reason_sections(
    std::ostream& stream,
    std::span<const CaptureIndexV16UnrecognizedReasonSectionWritePlan> sections
);
bool write_v16_packet_locator_sections(
    std::ostream& stream,
    std::span<const CaptureIndexV16PacketLocatorSectionWritePlan> sections,
    std::span<const CapturePacketLocatorEntry> entries
);
bool write_capture_index_v16(
    std::ostream& stream,
    const CaptureIndexStableHeader& header,
    const CaptureIndexV16FastStatisticsTier& fast_tier,
    const CaptureIndexV16WritePlan& plan
);
CaptureIndexV16MetadataTierReadResult read_v16_metadata_tier(
    std::istream& stream,
    CaptureIndexV16MetadataTier& metadata
);
CaptureIndexV16PacketRefExtentReadResult read_v16_packetref_extent_range(
    std::istream& stream,
    std::span<const CaptureIndexV16PacketRefDetailSectionInfo> detail_sections,
    const CaptureIndexV16PacketRefDirectoryEntry& descriptor,
    std::uint64_t local_offset,
    std::uint64_t limit
);
CaptureIndexV16UnrecognizedDirectoryRangeReadResult read_v16_unrecognized_directory_range(
    std::istream& stream,
    std::span<const CaptureIndexV16UnrecognizedDirectorySectionInfo> directory_sections,
    std::uint64_t offset,
    std::uint64_t limit
);
CaptureIndexV16UnrecognizedReasonReadResult read_v16_unrecognized_reason(
    std::istream& stream,
    std::span<const CaptureIndexV16UnrecognizedReasonSectionInfo> reason_sections,
    std::uint32_t section_occurrence_index,
    std::uint64_t payload_offset,
    std::uint64_t byte_length
);
CaptureIndexV16PacketLocatorLookupReadResult lookup_v16_packet_locator(
    std::istream& stream,
    std::span<const CaptureIndexV16PacketLocatorSectionInfo> locator_sections,
    std::uint64_t packet_index
);
CaptureIndexV16CompleteReadResult read_capture_index_v16(
    std::istream& stream
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
