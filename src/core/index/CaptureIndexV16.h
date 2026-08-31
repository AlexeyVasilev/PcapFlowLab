#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "core/domain/Connection.h"
#include "core/domain/Direction.h"
#include "core/domain/PacketRef.h"

namespace pfl {

inline constexpr std::uint64_t kCaptureIndexV16PacketRefEncodedStrideBytes = 36U;

struct CaptureIndexV16DirectionalFlowMetadataV4 {
    FlowKeyV4 key {};
    std::uint64_t packet_count {0};
    std::uint64_t original_byte_count {0};

    [[nodiscard]] friend bool operator==(
        const CaptureIndexV16DirectionalFlowMetadataV4&,
        const CaptureIndexV16DirectionalFlowMetadataV4&
    ) = default;
};

struct CaptureIndexV16DirectionalFlowMetadataV6 {
    FlowKeyV6 key {};
    std::uint64_t packet_count {0};
    std::uint64_t original_byte_count {0};

    [[nodiscard]] friend bool operator==(
        const CaptureIndexV16DirectionalFlowMetadataV6&,
        const CaptureIndexV16DirectionalFlowMetadataV6&
    ) = default;
};

struct CaptureIndexV16ConnectionMetadataV4 {
    std::uint32_t canonical_connection_ordinal {0};
    ConnectionKeyV4 key {};
    FlowProtocolHint protocol_hint {FlowProtocolHint::unknown};
    std::string service_hint {};
    QuicVersionHint quic_version {QuicVersionHint::unknown};
    TlsVersionHint tls_version {TlsVersionHint::unknown};
    bool has_fragmented_packets {false};
    std::uint64_t fragmented_packet_count {0};
    ConnectionAggregateStats aggregate_stats {};
    bool has_flow_a {false};
    CaptureIndexV16DirectionalFlowMetadataV4 flow_a {};
    bool has_flow_b {false};
    CaptureIndexV16DirectionalFlowMetadataV4 flow_b {};

    [[nodiscard]] friend bool operator==(
        const CaptureIndexV16ConnectionMetadataV4&,
        const CaptureIndexV16ConnectionMetadataV4&
    ) = default;
};

struct CaptureIndexV16ConnectionMetadataV6 {
    std::uint32_t canonical_connection_ordinal {0};
    ConnectionKeyV6 key {};
    FlowProtocolHint protocol_hint {FlowProtocolHint::unknown};
    std::string service_hint {};
    QuicVersionHint quic_version {QuicVersionHint::unknown};
    TlsVersionHint tls_version {TlsVersionHint::unknown};
    bool has_fragmented_packets {false};
    std::uint64_t fragmented_packet_count {0};
    ConnectionAggregateStats aggregate_stats {};
    bool has_flow_a {false};
    CaptureIndexV16DirectionalFlowMetadataV6 flow_a {};
    bool has_flow_b {false};
    CaptureIndexV16DirectionalFlowMetadataV6 flow_b {};

    [[nodiscard]] friend bool operator==(
        const CaptureIndexV16ConnectionMetadataV6&,
        const CaptureIndexV16ConnectionMetadataV6&
    ) = default;
};

struct CaptureIndexV16ProtocolPathMembershipRow {
    ProtocolPathId protocol_path_id {kInvalidProtocolPathId};
    std::vector<std::uint32_t> canonical_connection_ordinals {};

    [[nodiscard]] friend bool operator==(
        const CaptureIndexV16ProtocolPathMembershipRow&,
        const CaptureIndexV16ProtocolPathMembershipRow&
    ) = default;
};

struct CaptureIndexV16PacketRefDirectoryEntry {
    std::uint32_t canonical_connection_ordinal {0};
    Direction direction {Direction::a_to_b};
    std::uint64_t packet_count {0};
    std::uint32_t detail_section_occurrence_index {0};
    std::uint64_t payload_offset {0};
    std::uint64_t encoded_byte_length {0};

    [[nodiscard]] friend bool operator==(
        const CaptureIndexV16PacketRefDirectoryEntry&,
        const CaptureIndexV16PacketRefDirectoryEntry&
    ) = default;
};

struct CaptureIndexV16PacketRefDetailSectionInfo {
    std::uint32_t section_occurrence_index {0};
    std::uint64_t payload_file_offset {0};
    std::uint64_t payload_size {0};

    [[nodiscard]] friend bool operator==(
        const CaptureIndexV16PacketRefDetailSectionInfo&,
        const CaptureIndexV16PacketRefDetailSectionInfo&
    ) = default;
};

struct CaptureIndexV16MetadataTier {
    std::vector<CaptureIndexV16ConnectionMetadataV4> ipv4_connections {};
    std::vector<CaptureIndexV16ConnectionMetadataV6> ipv6_connections {};
    std::vector<CaptureIndexV16ProtocolPathMembershipRow> protocol_path_membership {};
    std::vector<CaptureIndexV16PacketRefDirectoryEntry> packetref_directory {};
    std::vector<CaptureIndexV16PacketRefDetailSectionInfo> packetref_detail_sections {};

    [[nodiscard]] std::size_t connection_count() const noexcept {
        return ipv4_connections.size() + ipv6_connections.size();
    }

    [[nodiscard]] friend bool operator==(
        const CaptureIndexV16MetadataTier&,
        const CaptureIndexV16MetadataTier&
    ) = default;
};

struct CaptureIndexV16PacketRefExtentWritePlan {
    std::uint32_t canonical_connection_ordinal {0};
    Direction direction {Direction::a_to_b};
    std::uint64_t packet_count {0};
    std::uint32_t detail_section_occurrence_index {0};
    std::uint64_t payload_offset {0};
    std::uint64_t encoded_byte_length {0};
    std::span<const PacketRef> packet_refs {};
};

struct CaptureIndexV16PacketRefDetailSectionWritePlan {
    std::uint32_t section_occurrence_index {0};
    std::uint64_t payload_size {0};
    std::vector<CaptureIndexV16PacketRefExtentWritePlan> extents {};
};

struct CaptureIndexV16WritePlan {
    CaptureIndexV16MetadataTier metadata {};
    std::vector<CaptureIndexV16PacketRefDetailSectionWritePlan> packetref_detail_sections {};
    std::uint64_t total_packetref_count {0};
};

struct CaptureIndexV16PacketRefDetailLayoutOptions {
    std::uint64_t target_section_payload_bytes {128U * 1024U * 1024U};
};

enum class CaptureIndexV16WritePlanBuildStatus : std::uint8_t {
    ok = 0,
    invalid_protocol_path_id,
    invalid_directional_packet_count,
    invalid_directional_packet_order,
    invalid_first_observed_orientation,
    numeric_overflow,
};

struct CaptureIndexV16WritePlanBuildResult {
    CaptureIndexV16WritePlanBuildStatus status {CaptureIndexV16WritePlanBuildStatus::ok};
    CaptureIndexV16WritePlan plan {};
    std::string error_detail {};

    [[nodiscard]] explicit operator bool() const noexcept {
        return status == CaptureIndexV16WritePlanBuildStatus::ok;
    }
};

}  // namespace pfl
