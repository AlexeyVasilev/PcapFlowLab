#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "core/domain/Connection.h"

namespace pfl {

struct FlowAnalysisSequencePreviewRow {
    std::uint64_t flow_packet_number {0};
    std::string direction_text {};
    std::uint64_t delta_time_us {0};
    std::uint32_t captured_length {0};
    std::uint32_t payload_length {0};
    std::string timestamp_text {};
};

struct FlowAnalysisPacketSizeHistogramRow {
    std::string bucket_label {};
    std::uint64_t packet_count {0};
};

struct FlowAnalysisInterArrivalHistogramRow {
    std::string bucket_label {};
    std::uint64_t packet_count {0};
};

struct FlowAnalysisResult {
    std::uint64_t total_packets {0};
    std::uint64_t total_bytes {0};
    std::uint64_t duration_us {0};
    double packets_per_second {0.0};
    double bytes_per_second {0.0};
    double average_packet_size_bytes {0.0};
    double average_inter_arrival_us {0.0};
    std::uint64_t largest_gap_us {0};
    std::uint64_t timeline_packet_count_considered {0};
    std::uint64_t packets_a_to_b {0};
    std::uint64_t packets_b_to_a {0};
    std::uint64_t bytes_a_to_b {0};
    std::uint64_t bytes_b_to_a {0};
    std::string packet_ratio_text {};
    std::string byte_ratio_text {};
    std::string dominant_direction_text {};
    std::uint32_t min_packet_size_bytes {0};
    std::uint32_t max_packet_size_bytes {0};
    std::string first_packet_timestamp_text {};
    std::string last_packet_timestamp_text {};
    std::string protocol_hint {};
    std::string service_hint {};
    std::string protocol_panel_version_text {};
    std::string protocol_panel_service_text {};
    std::string protocol_panel_fallback_text {};
    std::uint64_t tcp_syn_packets {0};
    std::uint64_t tcp_fin_packets {0};
    std::uint64_t tcp_rst_packets {0};
    std::uint64_t burst_count {0};
    std::uint64_t longest_burst_packet_count {0};
    std::uint64_t largest_burst_bytes {0};
    std::uint64_t idle_gap_count {0};
    std::uint64_t largest_idle_gap_us {0};
    bool has_tcp_control_counts {false};
    std::vector<FlowAnalysisInterArrivalHistogramRow> inter_arrival_histogram_rows {};
    std::vector<FlowAnalysisPacketSizeHistogramRow> packet_size_histogram_rows {};
    std::vector<FlowAnalysisSequencePreviewRow> sequence_preview_rows {};
};

class FlowAnalysisService {
public:
    [[nodiscard]] FlowAnalysisResult analyze(const ConnectionV4& connection) const;
    [[nodiscard]] FlowAnalysisResult analyze(const ConnectionV6& connection) const;
};

}  // namespace pfl
