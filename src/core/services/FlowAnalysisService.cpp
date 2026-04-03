#include "core/services/FlowAnalysisService.h"

#include <algorithm>
#include <iomanip>
#include <optional>
#include <sstream>
#include <vector>

namespace pfl {

namespace {

constexpr std::size_t kSequencePreviewLimit = 20U;

std::uint64_t packet_timestamp_us(const PacketRef& packet) noexcept {
    return (static_cast<std::uint64_t>(packet.ts_sec) * 1000000ULL) + static_cast<std::uint64_t>(packet.ts_usec);
}

std::string format_packet_timestamp(const PacketRef& packet) {
    const auto seconds_of_day = packet.ts_sec % 86400U;
    const auto hours = seconds_of_day / 3600U;
    const auto minutes = (seconds_of_day % 3600U) / 60U;
    const auto seconds = seconds_of_day % 60U;

    std::ostringstream timestamp {};
    timestamp << std::setfill('0')
              << std::setw(2) << hours << ':'
              << std::setw(2) << minutes << ':'
              << std::setw(2) << seconds << '.'
              << std::setw(6) << packet.ts_usec;
    return timestamp.str();
}

struct PacketPreviewCandidate {
    const PacketRef* packet {nullptr};
    const char* direction_text {""};
};

template <typename Flow>
void update_time_bounds(const Flow& flow, std::optional<std::uint64_t>& first_us, std::optional<std::uint64_t>& last_us) {
    for (const auto& packet : flow.packets) {
        const auto timestamp_us = packet_timestamp_us(packet);
        if (!first_us.has_value() || timestamp_us < *first_us) {
            first_us = timestamp_us;
        }
        if (!last_us.has_value() || timestamp_us > *last_us) {
            last_us = timestamp_us;
        }
    }
}

template <typename Connection>
std::vector<FlowAnalysisSequencePreviewRow> build_sequence_preview_rows(const Connection& connection) {
    std::vector<PacketPreviewCandidate> ordered_packets {};
    ordered_packets.reserve(connection.flow_a.packets.size() + connection.flow_b.packets.size());

    for (const auto& packet : connection.flow_a.packets) {
        ordered_packets.push_back(PacketPreviewCandidate {
            .packet = &packet,
            .direction_text = "A->B",
        });
    }

    for (const auto& packet : connection.flow_b.packets) {
        ordered_packets.push_back(PacketPreviewCandidate {
            .packet = &packet,
            .direction_text = "B->A",
        });
    }

    std::stable_sort(ordered_packets.begin(), ordered_packets.end(), [](const PacketPreviewCandidate& left, const PacketPreviewCandidate& right) {
        const auto left_timestamp = packet_timestamp_us(*left.packet);
        const auto right_timestamp = packet_timestamp_us(*right.packet);
        if (left_timestamp != right_timestamp) {
            return left_timestamp < right_timestamp;
        }

        return left.packet->packet_index < right.packet->packet_index;
    });

    const auto preview_count = std::min(kSequencePreviewLimit, ordered_packets.size());
    std::vector<FlowAnalysisSequencePreviewRow> rows {};
    rows.reserve(preview_count);

    std::optional<std::uint64_t> previous_timestamp_us {};
    for (std::size_t index = 0; index < preview_count; ++index) {
        const auto& candidate = ordered_packets[index];
        const auto current_timestamp_us = packet_timestamp_us(*candidate.packet);
        const auto delta_time_us = previous_timestamp_us.has_value() && current_timestamp_us >= *previous_timestamp_us
            ? current_timestamp_us - *previous_timestamp_us
            : 0U;

        rows.push_back(FlowAnalysisSequencePreviewRow {
            .flow_packet_number = static_cast<std::uint64_t>(index + 1U),
            .direction_text = candidate.direction_text,
            .delta_time_us = delta_time_us,
            .captured_length = candidate.packet->captured_length,
            .payload_length = candidate.packet->payload_length,
            .timestamp_text = format_packet_timestamp(*candidate.packet),
        });

        previous_timestamp_us = current_timestamp_us;
    }

    return rows;
}

template <typename Connection>
FlowAnalysisResult analyze_connection(const Connection& connection) {
    FlowAnalysisResult result {};
    result.total_packets = connection.packet_count;
    result.total_bytes = connection.total_bytes;
    result.packets_a_to_b = connection.flow_a.packet_count;
    result.packets_b_to_a = connection.flow_b.packet_count;
    result.bytes_a_to_b = connection.flow_a.total_bytes;
    result.bytes_b_to_a = connection.flow_b.total_bytes;
    result.protocol_hint = connection.protocol_hint == FlowProtocolHint::unknown
        ? std::string {}
        : std::string {flow_protocol_hint_text(connection.protocol_hint)};
    result.service_hint = connection.service_hint;

    std::optional<std::uint64_t> first_us {};
    std::optional<std::uint64_t> last_us {};
    update_time_bounds(connection.flow_a, first_us, last_us);
    update_time_bounds(connection.flow_b, first_us, last_us);

    if (first_us.has_value() && last_us.has_value() && *last_us >= *first_us) {
        result.duration_us = *last_us - *first_us;
    }

    result.sequence_preview_rows = build_sequence_preview_rows(connection);

    return result;
}

}  // namespace

FlowAnalysisResult FlowAnalysisService::analyze(const ConnectionV4& connection) const {
    return analyze_connection(connection);
}

FlowAnalysisResult FlowAnalysisService::analyze(const ConnectionV6& connection) const {
    return analyze_connection(connection);
}

}  // namespace pfl
