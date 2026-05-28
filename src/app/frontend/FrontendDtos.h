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
};

struct FrontendOverviewDto {
    bool has_capture {false};
    CaptureSummary summary {};
    CaptureProtocolSummary protocol_summary {};
    QuicRecognitionStats quic_recognition {};
    TlsRecognitionStats tls_recognition {};
};

struct FrontendFlowDto {
    std::size_t flow_index {0};
    FlowAddressFamily family {FlowAddressFamily::ipv4};
    std::string protocol_text {};
    std::string protocol_hint {};
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
    std::size_t flow_index {0};
    std::uint64_t packet_index {0};
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
};

}  // namespace pfl
