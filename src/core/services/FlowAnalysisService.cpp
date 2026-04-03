#include "core/services/FlowAnalysisService.h"

#include <algorithm>
#include <array>
#include <cmath>
#include <iomanip>
#include <optional>
#include <sstream>
#include <vector>

namespace pfl {

namespace {

constexpr std::size_t kSequencePreviewLimit = 20U;

struct PacketSizeBucketSpec {
    const char* label;
    std::uint32_t min_length;
    std::optional<std::uint32_t> max_length;
};

constexpr std::array<PacketSizeBucketSpec, 7> kPacketSizeBuckets {{
    {"0-63", 0U, 63U},
    {"64-127", 64U, 127U},
    {"128-255", 128U, 255U},
    {"256-511", 256U, 511U},
    {"512-1023", 512U, 1023U},
    {"1024-1518", 1024U, 1518U},
    {"1519+", 1519U, std::nullopt},
}};

struct InterArrivalBucketSpec {
    const char* label;
    std::uint64_t min_delta_us;
    std::optional<std::uint64_t> max_delta_us;
};

constexpr std::array<InterArrivalBucketSpec, 6> kInterArrivalBuckets {{
    {"0-99 us", 0U, 99U},
    {"100-999 us", 100U, 999U},
    {"1-9.9 ms", 1000U, 9999U},
    {"10-99 ms", 10000U, 99999U},
    {"100-999 ms", 100000U, 999999U},
    {"1 s+", 1000000U, std::nullopt},
}};

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

std::string format_ratio_number(const double value) {
    std::ostringstream stream {};
    const double rounded_value = std::round(value * 10.0) / 10.0;
    if (std::fabs(rounded_value - std::round(rounded_value)) < 0.05) {
        stream << static_cast<std::uint64_t>(std::llround(rounded_value));
    } else {
        stream << std::fixed << std::setprecision(1) << rounded_value;
    }

    return stream.str();
}

std::string format_direction_ratio_text(const std::uint64_t a_to_b, const std::uint64_t b_to_a) {
    if (a_to_b == 0U && b_to_a == 0U) {
        return "0 : 0";
    }

    if (a_to_b == 0U) {
        return "0 : 1";
    }

    if (b_to_a == 0U) {
        return "1 : 0";
    }

    if (a_to_b >= b_to_a) {
        return format_ratio_number(static_cast<double>(a_to_b) / static_cast<double>(b_to_a)) + " : 1";
    }

    return "1 : " + format_ratio_number(static_cast<double>(b_to_a) / static_cast<double>(a_to_b));
}

std::string derive_dominant_direction_text(const std::uint64_t a_to_b_packets, const std::uint64_t b_to_a_packets) {
    if (a_to_b_packets == 0U && b_to_a_packets == 0U) {
        return "Balanced";
    }

    if (a_to_b_packets == 0U) {
        return "Mostly B->A";
    }

    if (b_to_a_packets == 0U) {
        return "Mostly A->B";
    }

    const auto larger = std::max(a_to_b_packets, b_to_a_packets);
    const auto smaller = std::min(a_to_b_packets, b_to_a_packets);
    if (larger <= (smaller * 2U)) {
        return "Balanced";
    }

    return a_to_b_packets > b_to_a_packets ? "Mostly A->B" : "Mostly B->A";
}

struct PacketPreviewCandidate {
    const PacketRef* packet {nullptr};
    const char* direction_text {""};
};

template <typename Connection>
std::vector<const PacketRef*> build_time_ordered_packet_refs(const Connection& connection) {
    std::vector<const PacketRef*> ordered_packets {};
    ordered_packets.reserve(connection.flow_a.packets.size() + connection.flow_b.packets.size());

    for (const auto& packet : connection.flow_a.packets) {
        ordered_packets.push_back(&packet);
    }

    for (const auto& packet : connection.flow_b.packets) {
        ordered_packets.push_back(&packet);
    }

    std::stable_sort(ordered_packets.begin(), ordered_packets.end(), [](const PacketRef* left, const PacketRef* right) {
        const auto left_timestamp = packet_timestamp_us(*left);
        const auto right_timestamp = packet_timestamp_us(*right);
        if (left_timestamp != right_timestamp) {
            return left_timestamp < right_timestamp;
        }

        return left->packet_index < right->packet_index;
    });

    return ordered_packets;
}

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

std::size_t packet_size_bucket_index(const std::uint32_t captured_length) {
    for (std::size_t index = 0; index < kPacketSizeBuckets.size(); ++index) {
        const auto& bucket = kPacketSizeBuckets[index];
        if (captured_length < bucket.min_length) {
            continue;
        }

        if (!bucket.max_length.has_value() || captured_length <= *bucket.max_length) {
            return index;
        }
    }

    return kPacketSizeBuckets.size() - 1U;
}

std::size_t inter_arrival_bucket_index(const std::uint64_t delta_us) {
    for (std::size_t index = 0; index < kInterArrivalBuckets.size(); ++index) {
        const auto& bucket = kInterArrivalBuckets[index];
        if (delta_us < bucket.min_delta_us) {
            continue;
        }

        if (!bucket.max_delta_us.has_value() || delta_us <= *bucket.max_delta_us) {
            return index;
        }
    }

    return kInterArrivalBuckets.size() - 1U;
}

template <typename Flow>
void accumulate_packet_size_histogram(
    const Flow& flow,
    std::array<std::uint64_t, kPacketSizeBuckets.size()>& counts
) {
    for (const auto& packet : flow.packets) {
        counts[packet_size_bucket_index(packet.captured_length)] += 1U;
    }
}

template <typename Connection>
std::vector<FlowAnalysisPacketSizeHistogramRow> build_packet_size_histogram_rows(const Connection& connection) {
    std::array<std::uint64_t, kPacketSizeBuckets.size()> counts {};
    accumulate_packet_size_histogram(connection.flow_a, counts);
    accumulate_packet_size_histogram(connection.flow_b, counts);

    std::vector<FlowAnalysisPacketSizeHistogramRow> rows {};
    rows.reserve(kPacketSizeBuckets.size());
    for (std::size_t index = 0; index < kPacketSizeBuckets.size(); ++index) {
        rows.push_back(FlowAnalysisPacketSizeHistogramRow {
            .bucket_label = kPacketSizeBuckets[index].label,
            .packet_count = counts[index],
        });
    }

    return rows;
}

std::vector<FlowAnalysisInterArrivalHistogramRow> build_inter_arrival_histogram_rows(
    const std::vector<const PacketRef*>& ordered_packets
) {
    std::array<std::uint64_t, kInterArrivalBuckets.size()> counts {};
    if (ordered_packets.size() < 2U) {
        std::vector<FlowAnalysisInterArrivalHistogramRow> rows {};
        rows.reserve(kInterArrivalBuckets.size());
        for (const auto& bucket : kInterArrivalBuckets) {
            rows.push_back(FlowAnalysisInterArrivalHistogramRow {
                .bucket_label = bucket.label,
                .packet_count = 0U,
            });
        }
        return rows;
    }

    std::uint64_t previous_timestamp_us = packet_timestamp_us(*ordered_packets.front());
    for (std::size_t index = 1; index < ordered_packets.size(); ++index) {
        const auto current_timestamp_us = packet_timestamp_us(*ordered_packets[index]);
        const auto delta_us = current_timestamp_us >= previous_timestamp_us
            ? current_timestamp_us - previous_timestamp_us
            : 0U;
        counts[inter_arrival_bucket_index(delta_us)] += 1U;
        previous_timestamp_us = current_timestamp_us;
    }

    std::vector<FlowAnalysisInterArrivalHistogramRow> rows {};
    rows.reserve(kInterArrivalBuckets.size());
    for (std::size_t index = 0; index < kInterArrivalBuckets.size(); ++index) {
        rows.push_back(FlowAnalysisInterArrivalHistogramRow {
            .bucket_label = kInterArrivalBuckets[index].label,
            .packet_count = counts[index],
        });
    }

    return rows;
}

template <typename Connection>
FlowAnalysisResult analyze_connection(const Connection& connection) {
    FlowAnalysisResult result {};
    result.total_packets = connection.packet_count;
    result.total_bytes = connection.total_bytes;
    result.average_packet_size_bytes = result.total_packets > 0U
        ? static_cast<double>(result.total_bytes) / static_cast<double>(result.total_packets)
        : 0.0;
    result.packets_a_to_b = connection.flow_a.packet_count;
    result.packets_b_to_a = connection.flow_b.packet_count;
    result.bytes_a_to_b = connection.flow_a.total_bytes;
    result.bytes_b_to_a = connection.flow_b.total_bytes;
    result.packet_ratio_text = format_direction_ratio_text(result.packets_a_to_b, result.packets_b_to_a);
    result.byte_ratio_text = format_direction_ratio_text(result.bytes_a_to_b, result.bytes_b_to_a);
    result.dominant_direction_text = derive_dominant_direction_text(result.packets_a_to_b, result.packets_b_to_a);
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

    const auto ordered_packets = build_time_ordered_packet_refs(connection);
    result.timeline_packet_count_considered = static_cast<std::uint64_t>(ordered_packets.size());
    if (!ordered_packets.empty()) {
        result.first_packet_timestamp_text = format_packet_timestamp(*ordered_packets.front());
        result.last_packet_timestamp_text = format_packet_timestamp(*ordered_packets.back());
        result.min_packet_size_bytes = ordered_packets.front()->captured_length;
        result.max_packet_size_bytes = ordered_packets.front()->captured_length;
    }

    std::optional<std::uint64_t> previous_timestamp_us {};
    std::uint64_t inter_arrival_delta_sum_us = 0U;
    std::uint64_t inter_arrival_delta_count = 0U;
    for (const auto* packet : ordered_packets) {
        result.min_packet_size_bytes = std::min(result.min_packet_size_bytes, packet->captured_length);
        result.max_packet_size_bytes = std::max(result.max_packet_size_bytes, packet->captured_length);
        const auto current_timestamp_us = packet_timestamp_us(*packet);
        if (previous_timestamp_us.has_value() && current_timestamp_us >= *previous_timestamp_us) {
            const auto delta_us = current_timestamp_us - *previous_timestamp_us;
            result.largest_gap_us = std::max(result.largest_gap_us, delta_us);
            inter_arrival_delta_sum_us += delta_us;
            inter_arrival_delta_count += 1U;
        }

        previous_timestamp_us = current_timestamp_us;
    }

    if (result.duration_us > 0U) {
        result.packets_per_second =
            (static_cast<double>(result.total_packets) * 1000000.0) / static_cast<double>(result.duration_us);
        result.bytes_per_second =
            (static_cast<double>(result.total_bytes) * 1000000.0) / static_cast<double>(result.duration_us);
    }

    if (inter_arrival_delta_count > 0U) {
        result.average_inter_arrival_us =
            static_cast<double>(inter_arrival_delta_sum_us) / static_cast<double>(inter_arrival_delta_count);
    }

    result.inter_arrival_histogram_rows = build_inter_arrival_histogram_rows(ordered_packets);
    result.packet_size_histogram_rows = build_packet_size_histogram_rows(connection);
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
