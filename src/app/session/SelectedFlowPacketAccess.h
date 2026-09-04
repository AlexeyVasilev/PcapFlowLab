#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "core/domain/Connection.h"
#include "core/domain/Direction.h"
#include "core/domain/PacketRef.h"
#include "core/index/CaptureIndexV16.h"

namespace pfl::session_detail {

enum class SelectedFlowPacketAccessStatus : std::uint8_t {
    ok = 0,
    invalid_flow_reference,
    invalid_direction,
    invalid_local_offset,
    invalid_requested_length,
    numeric_overflow,
    malformed_directory_or_extent,
    source_read_failed,
    malformed_packetref,
};

struct SelectedFlowDirectionalPacketCountResult {
    SelectedFlowPacketAccessStatus status {SelectedFlowPacketAccessStatus::ok};
    std::uint64_t packet_count {0};
    std::string error_detail {};

    [[nodiscard]] explicit operator bool() const noexcept {
        return status == SelectedFlowPacketAccessStatus::ok;
    }
};

struct SelectedFlowDirectionalPacketReadResult {
    SelectedFlowPacketAccessStatus status {SelectedFlowPacketAccessStatus::ok};
    std::vector<PacketRef> packet_refs {};
    std::string error_detail {};

    [[nodiscard]] explicit operator bool() const noexcept {
        return status == SelectedFlowPacketAccessStatus::ok;
    }
};

struct SelectedFlowMergedPacket {
    PacketRef packet {};
    Direction direction {Direction::a_to_b};
    std::uint64_t flow_local_packet_number {0};
};

struct SelectedFlowMergedPacketReadResult {
    SelectedFlowPacketAccessStatus status {SelectedFlowPacketAccessStatus::ok};
    std::vector<SelectedFlowMergedPacket> packets {};
    std::uint64_t total_packet_count {0};
    std::string error_detail {};

    [[nodiscard]] explicit operator bool() const noexcept {
        return status == SelectedFlowPacketAccessStatus::ok;
    }
};

struct SelectedFlowPacketLookupResult {
    SelectedFlowPacketAccessStatus status {SelectedFlowPacketAccessStatus::ok};
    std::optional<SelectedFlowMergedPacket> packet {};
    std::string error_detail {};

    [[nodiscard]] explicit operator bool() const noexcept {
        return status == SelectedFlowPacketAccessStatus::ok;
    }
};

struct SelectedFlowDirectionalPacketContext {
    PacketRef packet {};
    Direction direction {Direction::a_to_b};
    std::uint64_t directional_local_offset {0};
};

struct SelectedFlowDirectionalPacketLookupResult {
    SelectedFlowPacketAccessStatus status {SelectedFlowPacketAccessStatus::ok};
    std::optional<SelectedFlowDirectionalPacketContext> packet {};
    std::string error_detail {};

    [[nodiscard]] explicit operator bool() const noexcept {
        return status == SelectedFlowPacketAccessStatus::ok;
    }
};

class SelectedFlowPacketAccessSource {
public:
    virtual ~SelectedFlowPacketAccessSource() = default;

    [[nodiscard]] virtual SelectedFlowDirectionalPacketCountResult directional_packet_count(Direction direction) const = 0;
    [[nodiscard]] virtual SelectedFlowDirectionalPacketReadResult read_direction(
        Direction direction,
        std::uint64_t local_offset,
        std::uint64_t limit
    ) const = 0;
};

class ResidentSelectedFlowPacketAccessSource final : public SelectedFlowPacketAccessSource {
public:
    ResidentSelectedFlowPacketAccessSource(const ConnectionV4& connection);
    ResidentSelectedFlowPacketAccessSource(const ConnectionV6& connection);
    ResidentSelectedFlowPacketAccessSource(
        std::span<const PacketRef> packets_a,
        std::uint64_t packet_count_a,
        std::span<const PacketRef> packets_b,
        std::uint64_t packet_count_b
    );

    [[nodiscard]] SelectedFlowDirectionalPacketCountResult directional_packet_count(Direction direction) const override;
    [[nodiscard]] SelectedFlowDirectionalPacketReadResult read_direction(
        Direction direction,
        std::uint64_t local_offset,
        std::uint64_t limit
    ) const override;

private:
    [[nodiscard]] SelectedFlowDirectionalPacketReadResult read_direction_from_span(
        std::span<const PacketRef> packets,
        std::uint64_t authoritative_count,
        std::string_view direction_name,
        std::uint64_t local_offset,
        std::uint64_t limit
    ) const;

    std::span<const PacketRef> packets_a_ {};
    std::span<const PacketRef> packets_b_ {};
    std::uint64_t packet_count_a_ {0};
    std::uint64_t packet_count_b_ {0};
};

class CaptureIndexV16SelectedFlowPacketAccessSource final : public SelectedFlowPacketAccessSource {
public:
    CaptureIndexV16SelectedFlowPacketAccessSource(
        std::filesystem::path index_path,
        const CaptureIndexV16MetadataTier& metadata,
        std::uint32_t canonical_connection_ordinal
    );

    [[nodiscard]] SelectedFlowDirectionalPacketCountResult directional_packet_count(Direction direction) const override;
    [[nodiscard]] SelectedFlowDirectionalPacketReadResult read_direction(
        Direction direction,
        std::uint64_t local_offset,
        std::uint64_t limit
    ) const override;

private:
    struct DirectionState {
        bool present {false};
        std::uint64_t packet_count {0};
        std::optional<CaptureIndexV16PacketRefDirectoryEntry> descriptor {};
    };

    [[nodiscard]] SelectedFlowDirectionalPacketReadResult read_direction_from_state(
        const DirectionState& state,
        std::string_view direction_name,
        std::uint64_t local_offset,
        std::uint64_t limit
    ) const;

    std::filesystem::path index_path_ {};
    std::vector<CaptureIndexV16PacketRefDetailSectionInfo> detail_sections_ {};
    DirectionState state_a_ {};
    DirectionState state_b_ {};
    SelectedFlowPacketAccessStatus initialization_status_ {SelectedFlowPacketAccessStatus::ok};
    std::string initialization_error_detail {};
};

[[nodiscard]] SelectedFlowMergedPacketReadResult read_selected_flow_merged_range(
    const SelectedFlowPacketAccessSource& source,
    std::uint64_t merged_offset,
    std::uint64_t limit
);

[[nodiscard]] SelectedFlowPacketLookupResult selected_flow_packet_at(
    const SelectedFlowPacketAccessSource& source,
    std::uint64_t flow_local_packet_number
);

[[nodiscard]] SelectedFlowPacketLookupResult selected_flow_packet_context_for_packet_index(
    const SelectedFlowPacketAccessSource& source,
    std::uint64_t packet_index
);

[[nodiscard]] SelectedFlowDirectionalPacketLookupResult selected_flow_directional_packet_context_for_packet_index(
    const SelectedFlowPacketAccessSource& source,
    Direction direction,
    std::uint64_t packet_index
);

}  // namespace pfl::session_detail
