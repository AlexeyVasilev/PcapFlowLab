use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceAvailabilityDto {
    pub has_source_capture: bool,
    pub source_capture_accessible: bool,
    pub opened_from_index: bool,
    pub partial_open: bool,
    pub byte_backed_inspection_available: bool,
    pub active_source_capture_path: String,
    pub expected_source_capture_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenCaptureResultDto {
    pub opened: bool,
    pub cancelled: bool,
    pub opened_from_index: bool,
    pub partial_open: bool,
    pub partial_open_warning_text: String,
    pub has_source_capture: bool,
    pub source_capture_accessible: bool,
    pub input_path: String,
    pub active_source_capture_path: String,
    pub expected_source_capture_path: String,
    pub error_text: String,
    pub source_availability: SourceAvailabilityDto,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenCaptureStartResultDto {
    pub started: bool,
    pub error_text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenCaptureProgressDto {
    pub in_progress: bool,
    pub cancel_requested: bool,
    pub opening_as_index: bool,
    pub packets_processed: u64,
    pub bytes_processed: u64,
    pub total_bytes: u64,
    pub percent: f64,
    pub input_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenCapturePollResultDto {
    pub ready: bool,
    pub progress: OpenCaptureProgressDto,
    pub result: OpenCaptureResultDto,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenCaptureCancelResultDto {
    pub cancelled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttachSourceCaptureResultDto {
    pub attached: bool,
    pub error_text: String,
    pub source_availability: SourceAvailabilityDto,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaveIndexResultDto {
    pub saved: bool,
    pub output_path: String,
    pub error_text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettingsDto {
    pub http_use_path_as_service_hint: bool,
    pub use_possible_tls_quic: bool,
    pub show_wireshark_filter_for_selected_flow: bool,
    pub validate_selected_packet_checksums: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportCurrentFlowResultDto {
    pub exported: bool,
    pub output_path: String,
    pub error_text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportSelectedFlowsResultDto {
    pub exported: bool,
    pub output_path: String,
    pub error_text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportAllFlowsInfoCsvResultDto {
    pub exported: bool,
    pub output_path: String,
    pub error_text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmartExportResultDto {
    pub exported: bool,
    pub output_path: String,
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
    pub captured_bytes: u64,
    pub original_bytes: u64,
    pub total_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverviewProtocolSummaryDto {
    pub tcp: ProtocolStatsDto,
    pub udp: ProtocolStatsDto,
    pub sctp: ProtocolStatsDto,
    pub other: ProtocolStatsDto,
    pub ipv4: ProtocolStatsDto,
    pub ipv6: ProtocolStatsDto,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnrecognizedPacketStatisticsDto {
    pub packet_count: u64,
    pub captured_bytes: u64,
    pub original_bytes: u64,
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
pub struct ProtocolHintStatsDto {
    pub group: String,
    pub protocol_label: String,
    pub flow_count: u64,
    pub packet_count: u64,
    pub captured_bytes: u64,
    pub original_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopEndpointDto {
    pub endpoint_label: String,
    pub packet_count: u64,
    pub total_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopPortDto {
    pub port: u16,
    pub packet_count: u64,
    pub total_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolPathStatsDto {
    pub node_id: u64,
    pub parent_node_id: u64,
    pub depth: usize,
    pub layer_text: String,
    pub path_text: String,
    pub compact_text: String,
    pub badges: Vec<ProtocolPathBadgeDto>,
    pub has_children: bool,
    pub is_terminal: bool,
    pub flow_count: u64,
    pub packet_count: u64,
    pub original_byte_count: u64,
    pub flow_percent: f64,
    pub packet_percent: f64,
    pub original_byte_percent: f64,
    pub flow_count_text: String,
    pub packet_count_text: String,
    pub original_byte_count_text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolPathPresentationDto {
    pub protocol_path_id: u32,
    pub path_text: String,
    pub compact_text: String,
    pub badges: Vec<ProtocolPathBadgeDto>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverviewDto {
    pub has_capture: bool,
    pub unrecognized_packet_count: u64,
    pub unrecognized_packets: Option<UnrecognizedPacketStatisticsDto>,
    pub summary: OverviewSummaryDto,
    pub protocol_summary: OverviewProtocolSummaryDto,
    pub quic_recognition: QuicRecognitionDto,
    pub tls_recognition: TlsRecognitionDto,
    pub protocol_hints: Vec<ProtocolHintStatsDto>,
    pub top_endpoints: Vec<TopEndpointDto>,
    pub top_ports: Vec<TopPortDto>,
    pub protocol_path_statistics_default_mode: u8,
    pub protocol_path_presentations: Vec<ProtocolPathPresentationDto>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowDto {
    pub flow_index: usize,
    pub family: String,
    pub protocol_text: String,
    pub protocol_hint: String,
    pub protocol_hint_display: String,
    pub service_hint: String,
    pub protocol_path_id: u32,
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
    pub wireshark_display_filter: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolPathBadgeDto {
    pub short_label: String,
    pub full_name: String,
    pub tooltip: String,
    pub color_key: String,
    pub background_color: String,
    pub border_color: String,
    pub text_color: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolPathLegendEntryDto {
    pub short_label: String,
    pub full_name: String,
    pub tooltip: String,
    pub color_key: String,
    pub background_color: String,
    pub border_color: String,
    pub text_color: String,
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
pub struct UnrecognizedPacketDto {
    pub row_number: u64,
    pub packet_index: u64,
    pub timestamp_text: String,
    pub captured_length: u32,
    pub original_length: u32,
    pub reason_text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnrecognizedPacketsDto {
    pub has_capture: bool,
    pub offset: usize,
    pub limit: usize,
    pub total_count: usize,
    pub packets: Vec<UnrecognizedPacketDto>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamItemDto {
    pub stream_item_index: u64,
    pub direction_text: String,
    pub label: String,
    pub byte_count: u32,
    pub packet_count: u32,
    pub source_packet_indices: Vec<u64>,
    pub source_packets_text: String,
    pub has_constricted_contribution: bool,
    pub header_secondary_text: String,
    pub badge_text: String,
    pub summary_text: String,
    pub payload_tab_title: String,
    pub payload_preview_text: String,
    pub payload_preview_unavailable_text: String,
    pub protocol_details_text: String,
    pub constricted_contribution_notes: Vec<String>,
    pub constricted_packet_notes: Vec<String>,
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
    pub source_availability: SourceAvailabilityDto,
    pub items: Vec<StreamItemDto>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectionResultDto {
    pub selected: bool,
    pub updated_flow: Option<FlowDto>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketSummaryFieldDto {
    pub label: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketSummaryLayerDto {
    pub id: String,
    pub title: String,
    pub fields: Vec<PacketSummaryFieldDto>,
    pub children: Vec<PacketSummaryLayerDto>,
    pub expanded_by_default: bool,
    pub warning: bool,
    pub marker_text: String,
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
    pub payload_preview_no_payload: bool,
    pub checksum_validation_enabled: bool,
    pub flow_index: usize,
    pub packet_index: u64,
    pub details_title: String,
    pub summary_text: String,
    pub payload_tab_title: String,
    pub timestamp_text: String,
    pub captured_length: u32,
    pub original_length: u32,
    pub payload_length: u32,
    pub is_ip_fragmented: bool,
    pub tcp_flags_text: String,
    pub link_summary_text: String,
    pub network_summary_text: String,
    pub transport_summary_text: String,
    pub summary_layers: Vec<PacketSummaryLayerDto>,
    pub protocol_details_text: String,
    pub raw_preview_text: String,
    pub raw_preview_unavailable_text: String,
    pub payload_preview_text: String,
    pub payload_preview_unavailable_text: String,
    pub checksum_summary_lines: Vec<String>,
    pub checksum_warning_lines: Vec<String>,
    pub unavailable_text: String,
    pub error_text: String,
    pub source_availability: SourceAvailabilityDto,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisSequencePreviewRowDto {
    pub flow_packet_number: u64,
    pub direction_text: String,
    pub delta_time_text: String,
    pub timestamp_text: String,
    pub captured_length: u32,
    pub original_length: u32,
    pub payload_length: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisHistogramRowDto {
    pub bucket_label: String,
    pub count_all: u64,
    pub count_a_to_b: u64,
    pub count_b_to_a: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisRatePointDto {
    pub relative_time_us: u64,
    pub data_per_second: f64,
    pub packets_per_second: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisSequenceExportResultDto {
    pub exported: bool,
    pub output_path: String,
    pub error_text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectedFlowAnalysisDto {
    pub has_capture: bool,
    pub has_selected_flow: bool,
    pub analysis_available: bool,
    pub has_tcp_control_counts: bool,
    pub flow_index: usize,
    pub total_packets: u64,
    pub total_bytes: u64,
    pub captured_bytes: u64,
    pub packets_a_to_b: u64,
    pub packets_b_to_a: u64,
    pub bytes_a_to_b: u64,
    pub bytes_b_to_a: u64,
    pub tcp_syn_packets: u64,
    pub tcp_fin_packets: u64,
    pub tcp_rst_packets: u64,
    pub endpoint_summary_text: String,
    pub protocol_text: String,
    pub protocol_hint_display: String,
    pub service_hint_text: String,
    pub protocol_version_text: String,
    pub protocol_service_text: String,
    pub protocol_fallback_text: String,
    pub first_packet_time_text: String,
    pub last_packet_time_text: String,
    pub duration_text: String,
    pub largest_gap_text: String,
    pub packets_considered_text: String,
    pub total_packets_text: String,
    pub total_bytes_text: String,
    pub captured_bytes_text: String,
    pub packets_a_to_b_text: String,
    pub packets_b_to_a_text: String,
    pub bytes_a_to_b_text: String,
    pub bytes_b_to_a_text: String,
    pub packet_ratio_text: String,
    pub byte_ratio_text: String,
    pub packet_direction_text: String,
    pub data_direction_text: String,
    pub packets_per_second_text: String,
    pub packets_per_second_a_to_b_text: String,
    pub packets_per_second_b_to_a_text: String,
    pub bytes_per_second_text: String,
    pub bytes_per_second_a_to_b_text: String,
    pub bytes_per_second_b_to_a_text: String,
    pub average_packet_size_text: String,
    pub average_packet_size_a_to_b_text: String,
    pub average_packet_size_b_to_a_text: String,
    pub average_inter_arrival_text: String,
    pub min_packet_size_text: String,
    pub min_packet_size_a_to_b_text: String,
    pub min_packet_size_b_to_a_text: String,
    pub max_packet_size_text: String,
    pub max_packet_size_a_to_b_text: String,
    pub max_packet_size_b_to_a_text: String,
    pub tcp_syn_packets_text: String,
    pub tcp_fin_packets_text: String,
    pub tcp_rst_packets_text: String,
    pub burst_count_text: String,
    pub longest_burst_packet_count_text: String,
    pub largest_burst_bytes_text: String,
    pub idle_gap_count_text: String,
    pub largest_idle_gap_text: String,
    pub rate_graph_available: bool,
    pub rate_graph_status_text: String,
    pub rate_graph_window_text: String,
    pub rate_graph_points_a_to_b: Vec<AnalysisRatePointDto>,
    pub rate_graph_points_b_to_a: Vec<AnalysisRatePointDto>,
    pub unavailable_text: String,
    pub error_text: String,
    pub inter_arrival_histogram_rows: Vec<AnalysisHistogramRowDto>,
    pub packet_size_histogram_rows: Vec<AnalysisHistogramRowDto>,
    pub sequence_preview_rows: Vec<AnalysisSequencePreviewRowDto>,
}
