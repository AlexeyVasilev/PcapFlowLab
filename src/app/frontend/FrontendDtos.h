#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "app/session/FlowRows.h"
#include "core/domain/CaptureSummary.h"

namespace pfl {

enum class FrontendOpenMode : std::uint8_t {
    fast,
    deep,
};

struct FrontendSourceAvailabilityDto {
    bool has_source_capture {false};
    bool source_capture_accessible {false};
    bool opened_from_index {false};
    bool partial_open {false};
    bool byte_backed_inspection_available {false};
    std::string active_source_capture_path {};
    std::string expected_source_capture_path {};
};

struct FrontendOpenResult {
    bool opened {false};
    bool opened_from_index {false};
    bool partial_open {false};
    bool has_source_capture {false};
    bool source_capture_accessible {false};
    std::string input_path {};
    std::string active_source_capture_path {};
    std::string expected_source_capture_path {};
    std::string error_text {};
    FrontendSourceAvailabilityDto source_availability {};
};

struct FrontendProtocolHintStatsDto {
    std::string group {};
    std::string protocol_label {};
    std::uint64_t flow_count {0};
    std::uint64_t packet_count {0};
    std::uint64_t captured_bytes {0};
    std::uint64_t original_bytes {0};
};

struct FrontendTopEndpointDto {
    std::string endpoint_label {};
    std::uint64_t packet_count {0};
    std::uint64_t total_bytes {0};
};

struct FrontendTopPortDto {
    std::uint16_t port {0};
    std::uint64_t packet_count {0};
    std::uint64_t total_bytes {0};
};

struct FrontendOverviewDto {
    bool has_capture {false};
    CaptureSummary summary {};
    std::uint64_t captured_bytes {0};
    std::uint64_t original_bytes {0};
    CaptureProtocolSummary protocol_summary {};
    QuicRecognitionStats quic_recognition {};
    TlsRecognitionStats tls_recognition {};
    std::vector<FrontendProtocolHintStatsDto> protocol_hints {};
    std::vector<FrontendTopEndpointDto> top_endpoints {};
    std::vector<FrontendTopPortDto> top_ports {};
};

struct FrontendFlowDto {
    std::size_t flow_index {0};
    FlowAddressFamily family {FlowAddressFamily::ipv4};
    std::string protocol_text {};
    std::string protocol_hint {};
    std::string protocol_hint_display {};
    std::string service_hint {};
    bool has_fragmented_packets {false};
    std::uint64_t fragmented_packet_count {0};
    std::string address_a {};
    std::uint16_t port_a {0};
    std::string endpoint_a {};
    std::string address_b {};
    std::uint16_t port_b {0};
    std::string endpoint_b {};
    std::uint64_t packet_count {0};
    std::uint64_t total_bytes {0};
    std::string wireshark_display_filter {};
};

struct FrontendPacketDto {
    std::uint64_t row_number {0};
    std::uint64_t packet_index {0};
    std::string direction_text {};
    std::string timestamp_text {};
    std::uint32_t captured_length {0};
    std::uint32_t original_length {0};
    std::uint32_t payload_length {0};
    bool is_ip_fragmented {false};
    bool suspected_tcp_retransmission {false};
    std::string tcp_flags_text {};
};

struct FrontendSelectedFlowPacketsResult {
    bool has_capture {false};
    bool has_selected_flow {false};
    std::size_t flow_index {0};
    std::size_t offset {0};
    std::size_t limit {0};
    std::size_t total_count {0};
    std::vector<FrontendPacketDto> packets {};
};

struct FrontendStreamItemDto {
    std::uint64_t stream_item_index {0};
    std::string direction_text {};
    std::string label {};
    std::uint32_t byte_count {0};
    std::uint32_t packet_count {0};
    std::vector<std::uint64_t> source_packet_indices {};
    std::string source_packets_text {};
    bool has_constricted_contribution {false};
    std::vector<std::string> constricted_contribution_notes {};
    std::vector<std::string> constricted_packet_notes {};
};

struct FrontendSelectedFlowStreamResult {
    bool has_capture {false};
    bool has_selected_flow {false};
    bool source_capture_accessible {false};
    bool stream_available {false};
    bool stream_partially_loaded {false};
    bool packet_window_partial {false};
    bool can_load_more {false};
    std::size_t flow_index {0};
    std::size_t packet_window_count {0};
    std::size_t total_flow_packet_count {0};
    std::size_t requested_item_limit {0};
    std::size_t loaded_item_count {0};
    std::size_t total_item_count {0};
    std::string unavailable_text {};
    std::string error_text {};
    FrontendSourceAvailabilityDto source_availability {};
    std::vector<FrontendStreamItemDto> items {};
};

struct FrontendPacketDetailsDto {
    bool has_capture {false};
    bool has_selected_flow {false};
    bool packet_found {false};
    bool source_capture_accessible {false};
    bool details_available {false};
    bool raw_preview_available {false};
    bool raw_preview_truncated {false};
    bool payload_preview_available {false};
    bool payload_preview_truncated {false};
    bool payload_preview_no_payload {false};
    std::size_t flow_index {0};
    std::uint64_t packet_index {0};
    std::string details_title {};
    std::string payload_tab_title {};
    std::string timestamp_text {};
    std::uint32_t captured_length {0};
    std::uint32_t original_length {0};
    std::uint32_t payload_length {0};
    bool is_ip_fragmented {false};
    std::string tcp_flags_text {};
    std::string link_summary_text {};
    std::string network_summary_text {};
    std::string transport_summary_text {};
    std::string protocol_details_text {};
    std::string raw_preview_text {};
    std::string raw_preview_unavailable_text {};
    std::string payload_preview_text {};
    std::string payload_preview_unavailable_text {};
    std::string unavailable_text {};
    std::string error_text {};
    FrontendSourceAvailabilityDto source_availability {};
};

struct FrontendAnalysisSequencePreviewRowDto {
    std::uint64_t flow_packet_number {0};
    std::string direction_text {};
    std::string delta_time_text {};
    std::string timestamp_text {};
    std::uint32_t captured_length {0};
    std::uint32_t original_length {0};
    std::uint32_t payload_length {0};
};

struct FrontendSelectedFlowAnalysisDto {
    bool has_capture {false};
    bool has_selected_flow {false};
    bool analysis_available {false};
    bool has_tcp_control_counts {false};
    std::size_t flow_index {0};
    std::uint64_t total_packets {0};
    std::uint64_t total_bytes {0};
    std::uint64_t captured_bytes {0};
    std::uint64_t packets_a_to_b {0};
    std::uint64_t packets_b_to_a {0};
    std::uint64_t bytes_a_to_b {0};
    std::uint64_t bytes_b_to_a {0};
    std::uint64_t tcp_syn_packets {0};
    std::uint64_t tcp_fin_packets {0};
    std::uint64_t tcp_rst_packets {0};
    std::string endpoint_summary_text {};
    std::string protocol_text {};
    std::string protocol_hint_display {};
    std::string service_hint_text {};
    std::string protocol_version_text {};
    std::string protocol_service_text {};
    std::string protocol_fallback_text {};
    std::string first_packet_time_text {};
    std::string last_packet_time_text {};
    std::string duration_text {};
    std::string largest_gap_text {};
    std::string packets_considered_text {};
    std::string total_packets_text {};
    std::string total_bytes_text {};
    std::string captured_bytes_text {};
    std::string packets_a_to_b_text {};
    std::string packets_b_to_a_text {};
    std::string bytes_a_to_b_text {};
    std::string bytes_b_to_a_text {};
    std::string packet_ratio_text {};
    std::string byte_ratio_text {};
    std::string packet_direction_text {};
    std::string data_direction_text {};
    std::string packets_per_second_text {};
    std::string packets_per_second_a_to_b_text {};
    std::string packets_per_second_b_to_a_text {};
    std::string bytes_per_second_text {};
    std::string bytes_per_second_a_to_b_text {};
    std::string bytes_per_second_b_to_a_text {};
    std::string average_packet_size_text {};
    std::string average_packet_size_a_to_b_text {};
    std::string average_packet_size_b_to_a_text {};
    std::string average_inter_arrival_text {};
    std::string min_packet_size_text {};
    std::string min_packet_size_a_to_b_text {};
    std::string min_packet_size_b_to_a_text {};
    std::string max_packet_size_text {};
    std::string max_packet_size_a_to_b_text {};
    std::string max_packet_size_b_to_a_text {};
    std::string tcp_syn_packets_text {};
    std::string tcp_fin_packets_text {};
    std::string tcp_rst_packets_text {};
    std::string burst_count_text {};
    std::string longest_burst_packet_count_text {};
    std::string largest_burst_bytes_text {};
    std::string idle_gap_count_text {};
    std::string largest_idle_gap_text {};
    std::string unavailable_text {};
    std::string error_text {};
    std::vector<FrontendAnalysisSequencePreviewRowDto> sequence_preview_rows {};
};

}  // namespace pfl
