#include "app/session/SelectedFlowPacketAccess.h"

#include <algorithm>
#include <fstream>
#include <limits>
#include <optional>
#include <string_view>

#include "core/index/Serialization.h"

namespace pfl::session_detail {

namespace {

[[nodiscard]] bool checked_add_u64(
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

[[nodiscard]] std::string direction_name(const Direction direction) {
    switch (direction) {
    case Direction::a_to_b:
        return "A->B";
    case Direction::b_to_a:
        return "B->A";
    }
    return "unknown";
}

struct DirectionCursor {
    Direction direction {Direction::a_to_b};
    std::uint64_t total_count {0};
    std::uint64_t next_offset {0};
    std::vector<PacketRef> buffer {};
    std::size_t buffer_index {0};
    std::optional<std::uint64_t> last_packet_index {};
};

[[nodiscard]] const PacketRef* cursor_current_packet(const DirectionCursor& cursor) noexcept {
    return cursor.buffer_index < cursor.buffer.size() ? &cursor.buffer[cursor.buffer_index] : nullptr;
}

[[nodiscard]] SelectedFlowPacketAccessStatus map_v16_extent_status(
    const detail::CaptureIndexV16PacketRefExtentReadStatus status
) noexcept {
    switch (status) {
    case detail::CaptureIndexV16PacketRefExtentReadStatus::ok:
        return SelectedFlowPacketAccessStatus::ok;
    case detail::CaptureIndexV16PacketRefExtentReadStatus::invalid_local_offset:
        return SelectedFlowPacketAccessStatus::invalid_local_offset;
    case detail::CaptureIndexV16PacketRefExtentReadStatus::invalid_requested_length:
        return SelectedFlowPacketAccessStatus::invalid_requested_length;
    case detail::CaptureIndexV16PacketRefExtentReadStatus::section_seek_failed:
        return SelectedFlowPacketAccessStatus::source_read_failed;
    case detail::CaptureIndexV16PacketRefExtentReadStatus::invalid_detail_section_occurrence:
    case detail::CaptureIndexV16PacketRefExtentReadStatus::section_range_overflow:
        return SelectedFlowPacketAccessStatus::malformed_directory_or_extent;
    case detail::CaptureIndexV16PacketRefExtentReadStatus::truncated_packetref_detail:
    case detail::CaptureIndexV16PacketRefExtentReadStatus::malformed_packetref_detail:
    case detail::CaptureIndexV16PacketRefExtentReadStatus::packet_index_not_strictly_increasing:
        return SelectedFlowPacketAccessStatus::malformed_packetref;
    }
    return SelectedFlowPacketAccessStatus::malformed_packetref;
}

struct DirectionalPacketProbeResult {
    SelectedFlowPacketAccessStatus status {SelectedFlowPacketAccessStatus::ok};
    std::optional<PacketRef> packet {};
    std::string error_detail {};

    [[nodiscard]] explicit operator bool() const noexcept {
        return status == SelectedFlowPacketAccessStatus::ok;
    }
};

[[nodiscard]] DirectionalPacketProbeResult directional_packet_at(
    const SelectedFlowPacketAccessSource& source,
    const Direction direction,
    const std::uint64_t directional_packet_count,
    const std::uint64_t local_offset
) {
    if (local_offset >= directional_packet_count) {
        return DirectionalPacketProbeResult {
            .status = SelectedFlowPacketAccessStatus::invalid_local_offset,
            .error_detail = direction_name(direction) + " directional packet probe offset is past the end",
        };
    }

    const auto read_offset = local_offset == 0U ? 0U : local_offset - 1U;
    const auto read_limit = local_offset == 0U ? 1U : 2U;
    const auto read_result = source.read_direction(direction, read_offset, read_limit);
    if (!read_result) {
        return DirectionalPacketProbeResult {
            .status = read_result.status,
            .error_detail = read_result.error_detail,
        };
    }
    if (read_result.packet_refs.size() != static_cast<std::size_t>(read_limit)) {
        return DirectionalPacketProbeResult {
            .status = SelectedFlowPacketAccessStatus::malformed_directory_or_extent,
            .error_detail = direction_name(direction) + " selected-flow provider returned fewer packets than a bounded probe requested",
        };
    }
    if (read_result.packet_refs.size() == 2U &&
        read_result.packet_refs[1].packet_index <= read_result.packet_refs[0].packet_index) {
        return DirectionalPacketProbeResult {
            .status = SelectedFlowPacketAccessStatus::malformed_packetref,
            .error_detail = direction_name(direction) + " packet sequence is not strictly increasing at the probed offset",
        };
    }

    return DirectionalPacketProbeResult {
        .packet = read_result.packet_refs.back(),
    };
}

struct DirectionalLowerBoundResult {
    SelectedFlowPacketAccessStatus status {SelectedFlowPacketAccessStatus::ok};
    std::uint64_t local_offset {0};
    std::optional<PacketRef> packet {};
    std::string error_detail {};

    [[nodiscard]] explicit operator bool() const noexcept {
        return status == SelectedFlowPacketAccessStatus::ok;
    }
};

[[nodiscard]] DirectionalLowerBoundResult directional_lower_bound(
    const SelectedFlowPacketAccessSource& source,
    const Direction direction,
    const std::uint64_t directional_packet_count,
    const std::uint64_t packet_index
) {
    std::uint64_t low = 0U;
    std::uint64_t high = directional_packet_count;

    while (low < high) {
        const auto mid = low + ((high - low) / 2U);
        const auto probe = directional_packet_at(source, direction, directional_packet_count, mid);
        if (!probe) {
            return DirectionalLowerBoundResult {
                .status = probe.status,
                .error_detail = probe.error_detail,
            };
        }
        if (!probe.packet.has_value()) {
            return DirectionalLowerBoundResult {
                .status = SelectedFlowPacketAccessStatus::malformed_directory_or_extent,
                .error_detail = direction_name(direction) + " bounded probe did not return a packet",
            };
        }

        if (probe.packet->packet_index < packet_index) {
            low = mid + 1U;
        } else {
            high = mid;
        }
    }

    DirectionalLowerBoundResult result {
        .local_offset = low,
    };
    if (low < directional_packet_count) {
        const auto probe = directional_packet_at(source, direction, directional_packet_count, low);
        if (!probe) {
            return DirectionalLowerBoundResult {
                .status = probe.status,
                .error_detail = probe.error_detail,
            };
        }
        result.packet = probe.packet;
    }
    return result;
}

struct MergedPartitionResult {
    SelectedFlowPacketAccessStatus status {SelectedFlowPacketAccessStatus::ok};
    std::uint64_t offset_a {0};
    std::uint64_t offset_b {0};
    std::string error_detail {};

    [[nodiscard]] explicit operator bool() const noexcept {
        return status == SelectedFlowPacketAccessStatus::ok;
    }
};

[[nodiscard]] DirectionalPacketProbeResult probe_partition_packet(
    const SelectedFlowPacketAccessSource& source,
    const Direction direction,
    const std::uint64_t directional_packet_count,
    const std::uint64_t local_offset
) {
    if (local_offset >= directional_packet_count) {
        return {};
    }
    return directional_packet_at(source, direction, directional_packet_count, local_offset);
}

[[nodiscard]] MergedPartitionResult find_merged_partition(
    const SelectedFlowPacketAccessSource& source,
    const std::uint64_t count_a,
    const std::uint64_t count_b,
    const std::uint64_t merged_offset
) {
    const auto lower_bound_a = merged_offset > count_b ? merged_offset - count_b : 0U;
    const auto upper_bound_a = std::min(merged_offset, count_a);
    std::uint64_t low = lower_bound_a;
    std::uint64_t high = upper_bound_a;

    while (low <= high) {
        const auto offset_a = low + ((high - low) / 2U);
        const auto offset_b = merged_offset - offset_a;

        const auto left_a = offset_a == 0U
            ? DirectionalPacketProbeResult {}
            : directional_packet_at(source, Direction::a_to_b, count_a, offset_a - 1U);
        if (!left_a) {
            return MergedPartitionResult {
                .status = left_a.status,
                .error_detail = left_a.error_detail,
            };
        }
        const auto right_a = probe_partition_packet(source, Direction::a_to_b, count_a, offset_a);
        if (!right_a) {
            return MergedPartitionResult {
                .status = right_a.status,
                .error_detail = right_a.error_detail,
            };
        }
        const auto left_b = offset_b == 0U
            ? DirectionalPacketProbeResult {}
            : directional_packet_at(source, Direction::b_to_a, count_b, offset_b - 1U);
        if (!left_b) {
            return MergedPartitionResult {
                .status = left_b.status,
                .error_detail = left_b.error_detail,
            };
        }
        const auto right_b = probe_partition_packet(source, Direction::b_to_a, count_b, offset_b);
        if (!right_b) {
            return MergedPartitionResult {
                .status = right_b.status,
                .error_detail = right_b.error_detail,
            };
        }

        if (left_a.packet.has_value() && right_b.packet.has_value()) {
            if (left_a.packet->packet_index == right_b.packet->packet_index) {
                return MergedPartitionResult {
                    .status = SelectedFlowPacketAccessStatus::malformed_packetref,
                    .error_detail = "selected-flow provider exposed the same packet_index in both directions",
                };
            }
            if (left_a.packet->packet_index > right_b.packet->packet_index) {
                if (offset_a == 0U) {
                    break;
                }
                high = offset_a - 1U;
                continue;
            }
        }

        if (left_b.packet.has_value() && right_a.packet.has_value()) {
            if (left_b.packet->packet_index == right_a.packet->packet_index) {
                return MergedPartitionResult {
                    .status = SelectedFlowPacketAccessStatus::malformed_packetref,
                    .error_detail = "selected-flow provider exposed the same packet_index in both directions",
                };
            }
            if (left_b.packet->packet_index > right_a.packet->packet_index) {
                low = offset_a + 1U;
                continue;
            }
        }

        return MergedPartitionResult {
            .offset_a = offset_a,
            .offset_b = offset_b,
        };
    }

    return MergedPartitionResult {
        .status = SelectedFlowPacketAccessStatus::malformed_packetref,
        .error_detail = "selected-flow directional packet sequences could not be partitioned by packet_index",
    };
}

inline constexpr std::uint64_t kDirectionalMergeChunkSize = 128U;

[[nodiscard]] SelectedFlowDirectionalPacketReadResult fetch_direction_chunk(
    const SelectedFlowPacketAccessSource& source,
    DirectionCursor& cursor,
    const std::uint64_t chunk_size
) {
    if (cursor.next_offset >= cursor.total_count) {
        cursor.buffer.clear();
        cursor.buffer_index = 0U;
        return {};
    }

    const auto read_result = source.read_direction(
        cursor.direction,
        cursor.next_offset,
        std::min(chunk_size, cursor.total_count - cursor.next_offset)
    );
    if (!read_result) {
        return read_result;
    }
    if (read_result.packet_refs.empty()) {
        return SelectedFlowDirectionalPacketReadResult {
            .status = SelectedFlowPacketAccessStatus::malformed_directory_or_extent,
            .error_detail = direction_name(cursor.direction) + " selected-flow provider returned an empty chunk before reaching the advertised directional packet count",
        };
    }

    for (std::size_t index = 1U; index < read_result.packet_refs.size(); ++index) {
        if (read_result.packet_refs[index].packet_index <= read_result.packet_refs[index - 1U].packet_index) {
            return SelectedFlowDirectionalPacketReadResult {
                .status = SelectedFlowPacketAccessStatus::malformed_packetref,
                .error_detail = direction_name(cursor.direction) + " packet sequence is not strictly increasing within a directional chunk",
            };
        }
    }

    if (cursor.last_packet_index.has_value() &&
        !read_result.packet_refs.empty() &&
        read_result.packet_refs.front().packet_index <= *cursor.last_packet_index) {
        return SelectedFlowDirectionalPacketReadResult {
            .status = SelectedFlowPacketAccessStatus::malformed_packetref,
            .error_detail = direction_name(cursor.direction) + " packet sequence is not strictly increasing across range boundaries",
        };
    }

    cursor.next_offset += static_cast<std::uint64_t>(read_result.packet_refs.size());
    if (!read_result.packet_refs.empty()) {
        cursor.last_packet_index = read_result.packet_refs.back().packet_index;
    }
    cursor.buffer = read_result.packet_refs;
    cursor.buffer_index = 0U;
    return {};
}

[[nodiscard]] std::optional<CaptureIndexV16PacketRefDirectoryEntry> find_v16_direction_descriptor(
    std::span<const CaptureIndexV16PacketRefDirectoryEntry> directory,
    const bool present,
    const std::uint64_t packet_count,
    const std::uint32_t canonical_connection_ordinal,
    const Direction direction,
    SelectedFlowPacketAccessStatus& status,
    std::string& error_detail
) {
    const auto descriptor_it = std::find_if(
        directory.begin(),
        directory.end(),
        [&](const auto& row) {
            return row.canonical_connection_ordinal == canonical_connection_ordinal &&
                row.direction == direction;
        }
    );
    const auto descriptor_found = descriptor_it != directory.end();

    if (!present) {
        if (descriptor_found) {
            status = SelectedFlowPacketAccessStatus::malformed_directory_or_extent;
            error_detail = "v16 directory contains an extent for a direction that is not present in metadata";
        }
        return std::nullopt;
    }

    if (!descriptor_found) {
        status = SelectedFlowPacketAccessStatus::malformed_directory_or_extent;
        error_detail = "v16 metadata references a direction without a packetref directory entry";
        return std::nullopt;
    }

    if (descriptor_it->packet_count != packet_count) {
        status = SelectedFlowPacketAccessStatus::malformed_directory_or_extent;
        error_detail = "v16 packetref directory packet_count does not match directional metadata";
        return std::nullopt;
    }

    return *descriptor_it;
}

}  // namespace

ResidentSelectedFlowPacketAccessSource::ResidentSelectedFlowPacketAccessSource(const ConnectionV4& connection)
    : ResidentSelectedFlowPacketAccessSource(
        std::span<const PacketRef>(connection.flow_a.packets.data(), connection.flow_a.packets.size()),
        connection.flow_a.packet_count,
        std::span<const PacketRef>(connection.flow_b.packets.data(), connection.flow_b.packets.size()),
        connection.flow_b.packet_count) {}

ResidentSelectedFlowPacketAccessSource::ResidentSelectedFlowPacketAccessSource(const ConnectionV6& connection)
    : ResidentSelectedFlowPacketAccessSource(
        std::span<const PacketRef>(connection.flow_a.packets.data(), connection.flow_a.packets.size()),
        connection.flow_a.packet_count,
        std::span<const PacketRef>(connection.flow_b.packets.data(), connection.flow_b.packets.size()),
        connection.flow_b.packet_count) {}

ResidentSelectedFlowPacketAccessSource::ResidentSelectedFlowPacketAccessSource(
    const std::span<const PacketRef> packets_a,
    const std::uint64_t packet_count_a,
    const std::span<const PacketRef> packets_b,
    const std::uint64_t packet_count_b
)
    : packets_a_(packets_a),
      packets_b_(packets_b),
      packet_count_a_(packet_count_a),
      packet_count_b_(packet_count_b) {}

SelectedFlowDirectionalPacketCountResult ResidentSelectedFlowPacketAccessSource::directional_packet_count(
    const Direction direction
) const {
    switch (direction) {
    case Direction::a_to_b:
        if (packet_count_a_ != static_cast<std::uint64_t>(packets_a_.size())) {
            return SelectedFlowDirectionalPacketCountResult {
                .status = SelectedFlowPacketAccessStatus::malformed_directory_or_extent,
                .error_detail = "resident A->B flow packet_count does not match resident PacketRef storage",
            };
        }
        return SelectedFlowDirectionalPacketCountResult {
            .packet_count = packet_count_a_,
        };
    case Direction::b_to_a:
        if (packet_count_b_ != static_cast<std::uint64_t>(packets_b_.size())) {
            return SelectedFlowDirectionalPacketCountResult {
                .status = SelectedFlowPacketAccessStatus::malformed_directory_or_extent,
                .error_detail = "resident B->A flow packet_count does not match resident PacketRef storage",
            };
        }
        return SelectedFlowDirectionalPacketCountResult {
            .packet_count = packet_count_b_,
        };
    }

    return SelectedFlowDirectionalPacketCountResult {
        .status = SelectedFlowPacketAccessStatus::invalid_direction,
        .error_detail = "unrecognized selected-flow direction",
    };
}

SelectedFlowDirectionalPacketReadResult ResidentSelectedFlowPacketAccessSource::read_direction(
    const Direction direction,
    const std::uint64_t local_offset,
    const std::uint64_t limit
) const {
    switch (direction) {
    case Direction::a_to_b:
        return read_direction_from_span(packets_a_, packet_count_a_, "A->B", local_offset, limit);
    case Direction::b_to_a:
        return read_direction_from_span(packets_b_, packet_count_b_, "B->A", local_offset, limit);
    }

    return SelectedFlowDirectionalPacketReadResult {
        .status = SelectedFlowPacketAccessStatus::invalid_direction,
        .error_detail = "unrecognized selected-flow direction",
    };
}

SelectedFlowDirectionalPacketReadResult ResidentSelectedFlowPacketAccessSource::read_direction_from_span(
    const std::span<const PacketRef> packets,
    const std::uint64_t authoritative_count,
    const std::string_view direction_name_text,
    const std::uint64_t local_offset,
    const std::uint64_t limit
) const {
    if (authoritative_count != static_cast<std::uint64_t>(packets.size())) {
        return SelectedFlowDirectionalPacketReadResult {
            .status = SelectedFlowPacketAccessStatus::malformed_directory_or_extent,
            .error_detail = std::string("resident ") + std::string(direction_name_text) +
                " flow packet_count does not match resident PacketRef storage",
        };
    }

    if (local_offset > authoritative_count) {
        return SelectedFlowDirectionalPacketReadResult {
            .status = SelectedFlowPacketAccessStatus::invalid_local_offset,
            .error_detail = std::string(direction_name_text) + " local offset is past the end of the directional packet sequence",
        };
    }
    if (limit == 0U || local_offset == authoritative_count) {
        return {};
    }

    const auto available = authoritative_count - local_offset;
    const auto count_to_copy = std::min(limit, available);
    if (count_to_copy > static_cast<std::uint64_t>((std::numeric_limits<std::size_t>::max)())) {
        return SelectedFlowDirectionalPacketReadResult {
            .status = SelectedFlowPacketAccessStatus::numeric_overflow,
            .error_detail = "requested directional packet range exceeds addressable memory",
        };
    }

    const auto begin = packets.begin() + static_cast<std::ptrdiff_t>(local_offset);
    const auto end = begin + static_cast<std::ptrdiff_t>(count_to_copy);
    return SelectedFlowDirectionalPacketReadResult {
        .packet_refs = std::vector<PacketRef>(begin, end),
    };
}

CaptureIndexV16SelectedFlowPacketAccessSource::CaptureIndexV16SelectedFlowPacketAccessSource(
    std::filesystem::path index_path,
    const CaptureIndexV16MetadataTier& metadata,
    const std::uint32_t canonical_connection_ordinal
)
    : index_path_(std::move(index_path)),
      detail_sections_(metadata.packetref_detail_sections) {
    const auto ipv4_it = std::find_if(
        metadata.ipv4_connections.begin(),
        metadata.ipv4_connections.end(),
        [&](const auto& row) {
            return row.canonical_connection_ordinal == canonical_connection_ordinal;
        }
    );
    const auto ipv6_it = std::find_if(
        metadata.ipv6_connections.begin(),
        metadata.ipv6_connections.end(),
        [&](const auto& row) {
            return row.canonical_connection_ordinal == canonical_connection_ordinal;
        }
    );

    const auto has_ipv4 = ipv4_it != metadata.ipv4_connections.end();
    const auto has_ipv6 = ipv6_it != metadata.ipv6_connections.end();
    if (has_ipv4 == has_ipv6) {
        initialization_status_ = SelectedFlowPacketAccessStatus::invalid_flow_reference;
        initialization_error_detail = "v16 metadata did not resolve to exactly one canonical selected flow";
        return;
    }

    if (has_ipv4) {
        state_a_.present = ipv4_it->has_flow_a;
        state_a_.packet_count = ipv4_it->flow_a.packet_count;
        state_a_.descriptor = find_v16_direction_descriptor(
            metadata.packetref_directory,
            state_a_.present,
            state_a_.packet_count,
            canonical_connection_ordinal,
            Direction::a_to_b,
            initialization_status_,
            initialization_error_detail
        );
        state_b_.present = ipv4_it->has_flow_b;
        state_b_.packet_count = ipv4_it->flow_b.packet_count;
        state_b_.descriptor = find_v16_direction_descriptor(
            metadata.packetref_directory,
            state_b_.present,
            state_b_.packet_count,
            canonical_connection_ordinal,
            Direction::b_to_a,
            initialization_status_,
            initialization_error_detail
        );
        return;
    }

    state_a_.present = ipv6_it->has_flow_a;
    state_a_.packet_count = ipv6_it->flow_a.packet_count;
    state_a_.descriptor = find_v16_direction_descriptor(
        metadata.packetref_directory,
        state_a_.present,
        state_a_.packet_count,
        canonical_connection_ordinal,
        Direction::a_to_b,
        initialization_status_,
        initialization_error_detail
    );
    state_b_.present = ipv6_it->has_flow_b;
    state_b_.packet_count = ipv6_it->flow_b.packet_count;
    state_b_.descriptor = find_v16_direction_descriptor(
        metadata.packetref_directory,
        state_b_.present,
        state_b_.packet_count,
        canonical_connection_ordinal,
        Direction::b_to_a,
        initialization_status_,
        initialization_error_detail
    );
}

SelectedFlowDirectionalPacketCountResult CaptureIndexV16SelectedFlowPacketAccessSource::directional_packet_count(
    const Direction direction
) const {
    if (initialization_status_ != SelectedFlowPacketAccessStatus::ok) {
        return SelectedFlowDirectionalPacketCountResult {
            .status = initialization_status_,
            .error_detail = initialization_error_detail,
        };
    }

    switch (direction) {
    case Direction::a_to_b:
        return SelectedFlowDirectionalPacketCountResult {
            .packet_count = state_a_.packet_count,
        };
    case Direction::b_to_a:
        return SelectedFlowDirectionalPacketCountResult {
            .packet_count = state_b_.packet_count,
        };
    }

    return SelectedFlowDirectionalPacketCountResult {
        .status = SelectedFlowPacketAccessStatus::invalid_direction,
        .error_detail = "unrecognized selected-flow direction",
    };
}

SelectedFlowDirectionalPacketReadResult CaptureIndexV16SelectedFlowPacketAccessSource::read_direction(
    const Direction direction,
    const std::uint64_t local_offset,
    const std::uint64_t limit
) const {
    if (initialization_status_ != SelectedFlowPacketAccessStatus::ok) {
        return SelectedFlowDirectionalPacketReadResult {
            .status = initialization_status_,
            .error_detail = initialization_error_detail,
        };
    }

    switch (direction) {
    case Direction::a_to_b:
        return read_direction_from_state(state_a_, "A->B", local_offset, limit);
    case Direction::b_to_a:
        return read_direction_from_state(state_b_, "B->A", local_offset, limit);
    }

    return SelectedFlowDirectionalPacketReadResult {
        .status = SelectedFlowPacketAccessStatus::invalid_direction,
        .error_detail = "unrecognized selected-flow direction",
    };
}

SelectedFlowDirectionalPacketReadResult CaptureIndexV16SelectedFlowPacketAccessSource::read_direction_from_state(
    const DirectionState& state,
    const std::string_view direction_name_text,
    const std::uint64_t local_offset,
    const std::uint64_t limit
) const {
    if (local_offset > state.packet_count) {
        return SelectedFlowDirectionalPacketReadResult {
            .status = SelectedFlowPacketAccessStatus::invalid_local_offset,
            .error_detail = std::string(direction_name_text) + " local offset is past the end of the directional packet sequence",
        };
    }
    if (limit == 0U || local_offset == state.packet_count) {
        return {};
    }
    if (!state.present) {
        return SelectedFlowDirectionalPacketReadResult {
            .status = SelectedFlowPacketAccessStatus::invalid_flow_reference,
            .error_detail = std::string(direction_name_text) + " direction is absent for the selected v16 flow",
        };
    }
    if (!state.descriptor.has_value()) {
        return SelectedFlowDirectionalPacketReadResult {
            .status = SelectedFlowPacketAccessStatus::malformed_directory_or_extent,
            .error_detail = std::string(direction_name_text) + " direction is missing a v16 packetref directory descriptor",
        };
    }

    std::ifstream stream(index_path_, std::ios::binary | std::ios::in);
    if (!stream.is_open()) {
        return SelectedFlowDirectionalPacketReadResult {
            .status = SelectedFlowPacketAccessStatus::source_read_failed,
            .error_detail = "failed to open the v16 index file for selected-flow PacketRef access",
        };
    }

    const auto read_result = detail::read_v16_packetref_extent_range(
        stream,
        detail_sections_,
        *state.descriptor,
        local_offset,
        limit
    );
    return SelectedFlowDirectionalPacketReadResult {
        .status = map_v16_extent_status(read_result.status),
        .packet_refs = read_result.packet_refs,
        .error_detail = read_result.error_detail,
    };
}

SelectedFlowMergedPacketReadResult read_selected_flow_merged_range(
    const SelectedFlowPacketAccessSource& source,
    const std::uint64_t merged_offset,
    const std::uint64_t limit
) {
    SelectedFlowMergedPacketReadResult result {};

    const auto count_a = source.directional_packet_count(Direction::a_to_b);
    if (!count_a) {
        result.status = count_a.status;
        result.error_detail = count_a.error_detail;
        return result;
    }

    const auto count_b = source.directional_packet_count(Direction::b_to_a);
    if (!count_b) {
        result.status = count_b.status;
        result.error_detail = count_b.error_detail;
        return result;
    }

    if (!checked_add_u64(count_a.packet_count, count_b.packet_count, result.total_packet_count)) {
        result.status = SelectedFlowPacketAccessStatus::numeric_overflow;
        result.error_detail = "selected-flow merged packet count overflowed";
        return result;
    }

    if (merged_offset > result.total_packet_count) {
        result.status = SelectedFlowPacketAccessStatus::invalid_local_offset;
        result.error_detail = "merged selected-flow offset is past the end of the flow";
        return result;
    }
    if (limit == 0U || merged_offset == result.total_packet_count) {
        return result;
    }

    std::uint64_t target = 0U;
    if (!checked_add_u64(merged_offset, limit, target)) {
        target = result.total_packet_count;
    } else {
        target = std::min(target, result.total_packet_count);
    }

    const auto packet_count_to_return = std::min<std::uint64_t>(limit, result.total_packet_count - merged_offset);
    if (packet_count_to_return > static_cast<std::uint64_t>((std::numeric_limits<std::size_t>::max)())) {
        result.status = SelectedFlowPacketAccessStatus::numeric_overflow;
        result.error_detail = "requested merged selected-flow packet range exceeds addressable memory";
        return result;
    }
    result.packets.reserve(static_cast<std::size_t>(packet_count_to_return));

    const auto partition = find_merged_partition(
        source,
        count_a.packet_count,
        count_b.packet_count,
        merged_offset
    );
    if (!partition) {
        result.status = partition.status;
        result.error_detail = partition.error_detail;
        return result;
    }

    DirectionCursor cursor_a {
        .direction = Direction::a_to_b,
        .total_count = count_a.packet_count,
        .next_offset = partition.offset_a,
    };
    DirectionCursor cursor_b {
        .direction = Direction::b_to_a,
        .total_count = count_b.packet_count,
        .next_offset = partition.offset_b,
    };

    auto ensure_cursor = [&](DirectionCursor& cursor) -> std::optional<SelectedFlowDirectionalPacketReadResult> {
        if (cursor_current_packet(cursor) != nullptr || cursor.next_offset >= cursor.total_count) {
            return std::nullopt;
        }
        const auto fetch_result = fetch_direction_chunk(source, cursor, kDirectionalMergeChunkSize);
        if (!fetch_result) {
            return fetch_result;
        }
        return std::nullopt;
    };

    std::uint64_t merged_index = merged_offset;
    while (merged_index < target) {
        if (const auto failure = ensure_cursor(cursor_a); failure.has_value()) {
            result.status = failure->status;
            result.error_detail = failure->error_detail;
            result.packets.clear();
            result.total_packet_count = 0U;
            return result;
        }
        if (const auto failure = ensure_cursor(cursor_b); failure.has_value()) {
            result.status = failure->status;
            result.error_detail = failure->error_detail;
            result.packets.clear();
            result.total_packet_count = 0U;
            return result;
        }

        const auto* packet_a = cursor_current_packet(cursor_a);
        const auto* packet_b = cursor_current_packet(cursor_b);
        if (packet_a == nullptr && packet_b == nullptr) {
            break;
        }
        if (packet_a != nullptr && packet_b != nullptr && packet_a->packet_index == packet_b->packet_index) {
            result.status = SelectedFlowPacketAccessStatus::malformed_packetref;
            result.error_detail = "selected-flow provider exposed the same packet_index in both directions";
            result.packets.clear();
            result.total_packet_count = 0U;
            return result;
        }

        const auto use_a = packet_b == nullptr || (packet_a != nullptr && packet_a->packet_index < packet_b->packet_index);
        auto& cursor = use_a ? cursor_a : cursor_b;
        const auto* packet = use_a ? packet_a : packet_b;
        ++merged_index;

        result.packets.push_back(SelectedFlowMergedPacket {
            .packet = *packet,
            .direction = cursor.direction,
            .flow_local_packet_number = merged_index,
        });

        ++cursor.buffer_index;
    }

    return result;
}

SelectedFlowPacketLookupResult selected_flow_packet_at(
    const SelectedFlowPacketAccessSource& source,
    const std::uint64_t flow_local_packet_number
) {
    if (flow_local_packet_number == 0U) {
        return SelectedFlowPacketLookupResult {
            .status = SelectedFlowPacketAccessStatus::invalid_local_offset,
            .error_detail = "selected-flow packet numbers are one-based",
        };
    }

    auto read_result = read_selected_flow_merged_range(source, flow_local_packet_number - 1U, 1U);
    SelectedFlowPacketLookupResult result {
        .status = read_result.status,
        .error_detail = read_result.error_detail,
    };
    if (!read_result) {
        return result;
    }
    if (!read_result.packets.empty()) {
        result.packet = read_result.packets.front();
    }
    return result;
}

SelectedFlowPacketLookupResult selected_flow_packet_context_for_packet_index(
    const SelectedFlowPacketAccessSource& source,
    const std::uint64_t packet_index
) {
    SelectedFlowPacketLookupResult result {};

    const auto count_a = source.directional_packet_count(Direction::a_to_b);
    if (!count_a) {
        result.status = count_a.status;
        result.error_detail = count_a.error_detail;
        return result;
    }

    const auto count_b = source.directional_packet_count(Direction::b_to_a);
    if (!count_b) {
        result.status = count_b.status;
        result.error_detail = count_b.error_detail;
        return result;
    }

    std::uint64_t total_count = 0U;
    if (!checked_add_u64(count_a.packet_count, count_b.packet_count, total_count)) {
        result.status = SelectedFlowPacketAccessStatus::numeric_overflow;
        result.error_detail = "selected-flow merged packet count overflowed";
        return result;
    }
    static_cast<void>(total_count);

    const auto lower_a = directional_lower_bound(
        source,
        Direction::a_to_b,
        count_a.packet_count,
        packet_index
    );
    if (!lower_a) {
        result.status = lower_a.status;
        result.error_detail = lower_a.error_detail;
        return result;
    }

    const auto lower_b = directional_lower_bound(
        source,
        Direction::b_to_a,
        count_b.packet_count,
        packet_index
    );
    if (!lower_b) {
        result.status = lower_b.status;
        result.error_detail = lower_b.error_detail;
        return result;
    }

    const auto found_a = lower_a.packet.has_value() && lower_a.packet->packet_index == packet_index;
    const auto found_b = lower_b.packet.has_value() && lower_b.packet->packet_index == packet_index;
    if (found_a && found_b) {
        result.status = SelectedFlowPacketAccessStatus::malformed_packetref;
        result.error_detail = "selected-flow provider exposed the same packet_index in both directions";
        return result;
    }
    if (!found_a && !found_b) {
        return result;
    }

    if (found_a) {
        std::uint64_t packets_in_a_through_target = 0U;
        if (!checked_add_u64(lower_a.local_offset, 1U, packets_in_a_through_target)) {
            result.status = SelectedFlowPacketAccessStatus::numeric_overflow;
            result.error_detail = "selected-flow packet ordinal overflowed";
            return result;
        }
        std::uint64_t flow_local_packet_number = 0U;
        if (!checked_add_u64(packets_in_a_through_target, lower_b.local_offset, flow_local_packet_number)) {
            result.status = SelectedFlowPacketAccessStatus::numeric_overflow;
            result.error_detail = "selected-flow packet ordinal overflowed";
            return result;
        }
        result.packet = SelectedFlowMergedPacket {
            .packet = *lower_a.packet,
            .direction = Direction::a_to_b,
            .flow_local_packet_number = flow_local_packet_number,
        };
        return result;
    }

    std::uint64_t packets_in_b_through_target = 0U;
    if (!checked_add_u64(lower_b.local_offset, 1U, packets_in_b_through_target)) {
        result.status = SelectedFlowPacketAccessStatus::numeric_overflow;
        result.error_detail = "selected-flow packet ordinal overflowed";
        return result;
    }
    std::uint64_t flow_local_packet_number = 0U;
    if (!checked_add_u64(packets_in_b_through_target, lower_a.local_offset, flow_local_packet_number)) {
        result.status = SelectedFlowPacketAccessStatus::numeric_overflow;
        result.error_detail = "selected-flow packet ordinal overflowed";
        return result;
    }
    result.packet = SelectedFlowMergedPacket {
        .packet = *lower_b.packet,
        .direction = Direction::b_to_a,
        .flow_local_packet_number = flow_local_packet_number,
    };
    return result;
}

SelectedFlowDirectionalPacketLookupResult selected_flow_directional_packet_context_for_packet_index(
    const SelectedFlowPacketAccessSource& source,
    const Direction direction,
    const std::uint64_t packet_index
) {
    SelectedFlowDirectionalPacketLookupResult result {};

    const auto count = source.directional_packet_count(direction);
    if (!count) {
        result.status = count.status;
        result.error_detail = count.error_detail;
        return result;
    }

    const auto lower = directional_lower_bound(
        source,
        direction,
        count.packet_count,
        packet_index
    );
    if (!lower) {
        result.status = lower.status;
        result.error_detail = lower.error_detail;
        return result;
    }

    if (!lower.packet.has_value() || lower.packet->packet_index != packet_index) {
        return result;
    }

    result.packet = SelectedFlowDirectionalPacketContext {
        .packet = *lower.packet,
        .direction = direction,
        .directional_local_offset = lower.local_offset,
    };
    return result;
}

}  // namespace pfl::session_detail
