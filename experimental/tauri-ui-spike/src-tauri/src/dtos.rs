use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenCaptureResultDto {
    pub opened: bool,
    pub opened_from_index: bool,
    pub partial_open: bool,
    pub has_source_capture: bool,
    pub source_capture_accessible: bool,
    pub input_path: String,
    pub active_source_capture_path: String,
    pub expected_source_capture_path: String,
    pub error_text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolStatsDto {
    pub flow_count: u64,
    pub packet_count: u64,
    pub captured_bytes: u64,
    pub original_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverviewSummaryDto {
    pub packet_count: u64,
    pub flow_count: u64,
    pub total_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverviewProtocolSummaryDto {
    pub tcp: ProtocolStatsDto,
    pub udp: ProtocolStatsDto,
    pub other: ProtocolStatsDto,
    pub ipv4: ProtocolStatsDto,
    pub ipv6: ProtocolStatsDto,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuicRecognitionDto {
    pub total_flows: u64,
    pub with_sni: u64,
    pub without_sni: u64,
    pub version_v1: u64,
    pub version_draft29: u64,
    pub version_v2: u64,
    pub version_unknown: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsRecognitionDto {
    pub total_flows: u64,
    pub with_sni: u64,
    pub without_sni: u64,
    pub version_tls12: u64,
    pub version_tls13: u64,
    pub version_unknown: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverviewDto {
    pub has_capture: bool,
    pub summary: OverviewSummaryDto,
    pub protocol_summary: OverviewProtocolSummaryDto,
    pub quic_recognition: QuicRecognitionDto,
    pub tls_recognition: TlsRecognitionDto,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowDto {
    pub flow_index: usize,
    pub family: String,
    pub protocol_text: String,
    pub protocol_hint: String,
    pub service_hint: String,
    pub has_fragmented_packets: bool,
    pub fragmented_packet_count: u64,
    pub address_a: String,
    pub port_a: u16,
    pub endpoint_a: String,
    pub address_b: String,
    pub port_b: u16,
    pub endpoint_b: String,
    pub packet_count: u64,
    pub total_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketDto {
    pub row_number: u64,
    pub packet_index: u64,
    pub direction_text: String,
    pub timestamp_text: String,
    pub captured_length: u32,
    pub original_length: u32,
    pub payload_length: u32,
    pub is_ip_fragmented: bool,
    pub suspected_tcp_retransmission: bool,
    pub tcp_flags_text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectedFlowPacketsDto {
    pub has_capture: bool,
    pub has_selected_flow: bool,
    pub flow_index: usize,
    pub offset: usize,
    pub limit: usize,
    pub total_count: usize,
    pub packets: Vec<PacketDto>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamItemDto {
    pub stream_item_index: u64,
    pub direction_text: String,
    pub label: String,
    pub byte_count: u32,
    pub packet_count: u32,
    pub source_packets_text: String,
    pub has_constricted_contribution: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectedFlowStreamDto {
    pub has_capture: bool,
    pub has_selected_flow: bool,
    pub source_capture_accessible: bool,
    pub stream_available: bool,
    pub stream_partially_loaded: bool,
    pub packet_window_partial: bool,
    pub can_load_more: bool,
    pub flow_index: usize,
    pub packet_window_count: usize,
    pub total_flow_packet_count: usize,
    pub requested_item_limit: usize,
    pub loaded_item_count: usize,
    pub total_item_count: usize,
    pub unavailable_text: String,
    pub error_text: String,
    pub items: Vec<StreamItemDto>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectionResultDto {
    pub selected: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketDetailsDto {
    pub has_capture: bool,
    pub has_selected_flow: bool,
    pub packet_found: bool,
    pub source_capture_accessible: bool,
    pub details_available: bool,
    pub raw_preview_available: bool,
    pub raw_preview_truncated: bool,
    pub payload_preview_available: bool,
    pub payload_preview_truncated: bool,
    pub flow_index: usize,
    pub packet_index: u64,
    pub timestamp_text: String,
    pub captured_length: u32,
    pub original_length: u32,
    pub payload_length: u32,
    pub is_ip_fragmented: bool,
    pub tcp_flags_text: String,
    pub link_summary_text: String,
    pub network_summary_text: String,
    pub transport_summary_text: String,
    pub protocol_details_text: String,
    pub raw_preview_text: String,
    pub raw_preview_unavailable_text: String,
    pub payload_preview_text: String,
    pub payload_preview_unavailable_text: String,
    pub unavailable_text: String,
    pub error_text: String,
}
