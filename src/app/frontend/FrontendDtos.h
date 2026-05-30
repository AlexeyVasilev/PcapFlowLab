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

struct FrontendOverviewDto {
    bool has_capture {false};
    CaptureSummary summary {};
    std::uint64_t captured_bytes {0};
    std::uint64_t original_bytes {0};
    CaptureProtocolSummary protocol_summary {};
    QuicRecognitionStats quic_recognition {};
    TlsRecognitionStats tls_recognition {};
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

}  // namespace pfl
