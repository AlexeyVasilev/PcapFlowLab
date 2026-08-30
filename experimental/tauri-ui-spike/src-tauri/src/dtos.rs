use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceAvailabilityDto {
    pub has_source_capture: bool,
    pub source_capture_accessible: bool,
    pub opened_from_index: bool,
    pub partial_open: bool,
    pub byte_backed_inspection_available: bool,
    pub flow_grouping_ignores_vlan_and_mpls_layers: bool,
    pub flow_grouping_ignores_gtpu_teids: bool,
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
    pub ignore_vlan_and_mpls_layers_when_grouping_flows: bool,
    pub ignore_gtpu_teids_when_grouping_inner_flows: bool,
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
pub struct ExportProtocolPathTreeResultDto {
    pub exported: bool,
    pub output_path: String,
    pub error_text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ByteExportFormatDto {
    pub stable_id: String,
    pub label: String,
    pub suggested_extension: String,
    pub binary_output: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ByteExportResultDto {
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
pub struct AdvancedFlowFilterParseIssueDto {
    pub status: String,
    pub line: usize,
    pub column: Option<usize>,
    pub key: String,
    pub token: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvancedFlowFilterCompileIssueDto {
    pub status: String,
    pub category: String,
    pub predicate_index: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvancedFlowFilterQueryResultDto {
    pub status: String,
    pub matching_flow_indices: Vec<usize>,
    pub result_count_before_limit: usize,
    pub configured_rule_count: usize,
    pub active_rule_count: usize,
    pub parse_status: String,
    pub parse_issue: Option<AdvancedFlowFilterParseIssueDto>,
    pub compile_status: String,
    pub compile_issue: Option<AdvancedFlowFilterCompileIssueDto>,
    pub invalid_flow_index: Option<usize>,
    pub error_text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvancedFlowFilterFileReadResultDto {
    pub loaded: bool,
    pub path: String,
    pub display_name: String,
    pub text: String,
    pub error_kind: String,
    pub error_text: String,
    pub max_file_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvancedFlowFilterDocumentWorkflowStateDto {
    pub canonical_text: String,
    pub source_path: String,
    pub display_name: String,
    pub is_file_backed: bool,
    pub has_unsaved_changes: bool,
    pub has_unsaved_configuration: bool,
    pub can_clear_unsaved_changes: bool,
    pub clear_available: bool,
    pub configured_rule_count: usize,
    pub active_rule_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvancedFlowFilterFiniteOptionDto {
    pub stable_id: String,
    pub label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvancedFlowFilterFiniteSectionDto {
    pub enabled: bool,
    pub include: Vec<String>,
    pub exclude: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvancedFlowFilterPortRowDto {
    pub scope_id: String,
    pub range_enabled: bool,
    pub primary_text: String,
    pub secondary_text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvancedFlowFilterPortSectionDto {
    pub enabled: bool,
    pub include: Vec<AdvancedFlowFilterPortRowDto>,
    pub exclude: Vec<AdvancedFlowFilterPortRowDto>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvancedFlowFilterIpAddressRowDto {
    pub scope_id: String,
    pub subnet_enabled: bool,
    pub address_text: String,
    pub prefix_text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvancedFlowFilterIpAddressSectionDto {
    pub enabled: bool,
    pub include: Vec<AdvancedFlowFilterIpAddressRowDto>,
    pub exclude: Vec<AdvancedFlowFilterIpAddressRowDto>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvancedFlowFilterTrafficRowDto {
    pub metric_id: String,
    pub unit_id: String,
    pub min_text: String,
    pub max_text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvancedFlowFilterTimeRowDto {
    pub metric_id: String,
    pub from_text: String,
    pub to_text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvancedFlowFilterTimeSectionDto {
    pub enabled: bool,
    pub ranges: Vec<AdvancedFlowFilterTimeRowDto>,
    pub duration: AdvancedFlowFilterTrafficRowDto,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvancedFlowFilterTrafficSectionDto {
    pub enabled: bool,
    pub packet_distribution: AdvancedFlowFilterFiniteSectionDto,
    pub data_distribution: AdvancedFlowFilterFiniteSectionDto,
    pub primary: Vec<AdvancedFlowFilterTrafficRowDto>,
    pub directional_packets: Vec<AdvancedFlowFilterTrafficRowDto>,
    pub directional_original_bytes: Vec<AdvancedFlowFilterTrafficRowDto>,
    pub additional: Vec<AdvancedFlowFilterTrafficRowDto>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvancedFlowFilterServiceTextRowDto {
    pub operator_id: String,
    pub case_sensitive: bool,
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvancedFlowFilterServiceSectionDto {
    pub enabled: bool,
    pub include_recognized: bool,
    pub include_unrecognized: bool,
    pub include_text: Vec<AdvancedFlowFilterServiceTextRowDto>,
    pub exclude_recognized: bool,
    pub exclude_unrecognized: bool,
    pub exclude_text: Vec<AdvancedFlowFilterServiceTextRowDto>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvancedFlowFilterProtocolPathRowDto {
    pub selector_mode_id: String,
    pub predicate_text: String,
    pub compact_text: String,
    pub full_text: String,
    pub applicability_known: bool,
    pub applicable: bool,
    pub status_text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvancedFlowFilterProtocolPathSectionDto {
    pub enabled: bool,
    pub include: Vec<AdvancedFlowFilterProtocolPathRowDto>,
    pub exclude: Vec<AdvancedFlowFilterProtocolPathRowDto>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvancedFlowFilterContainsLayerOptionDto {
    pub stable_id: String,
    pub label: String,
    pub object_name_suffix: String,
    pub identifier_label: String,
    pub preferred_input_format_id: String,
    pub exact_value_placeholder: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvancedFlowFilterContainsLayerRowDto {
    pub layer_stable_id: String,
    pub identifier_mode_id: String,
    pub exact_value_text: String,
    pub compact_text: String,
    pub applicability_known: bool,
    pub applicable: bool,
    pub status_text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvancedFlowFilterContainsLayerSectionDto {
    pub enabled: bool,
    pub include: Vec<AdvancedFlowFilterContainsLayerRowDto>,
    pub exclude: Vec<AdvancedFlowFilterContainsLayerRowDto>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvancedFlowFilterStructuredOptionCatalogDto {
    pub address_family: Vec<AdvancedFlowFilterFiniteOptionDto>,
    pub flow_protocol: Vec<AdvancedFlowFilterFiniteOptionDto>,
    pub detected_protocol: Vec<AdvancedFlowFilterFiniteOptionDto>,
    pub tls_version: Vec<AdvancedFlowFilterFiniteOptionDto>,
    pub quic_version: Vec<AdvancedFlowFilterFiniteOptionDto>,
    pub directionality: Vec<AdvancedFlowFilterFiniteOptionDto>,
    pub traffic_distribution: Vec<AdvancedFlowFilterFiniteOptionDto>,
    pub endpoint_scope: Vec<AdvancedFlowFilterFiniteOptionDto>,
    pub protocol_path_selector_mode: Vec<AdvancedFlowFilterFiniteOptionDto>,
    pub contains_layer_identifier_mode: Vec<AdvancedFlowFilterFiniteOptionDto>,
    pub contains_layer_kind: Vec<AdvancedFlowFilterContainsLayerOptionDto>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvancedFlowFilterStructuredDocumentDto {
    pub canonical_text: String,
    pub address_family: AdvancedFlowFilterFiniteSectionDto,
    pub flow_protocol: AdvancedFlowFilterFiniteSectionDto,
    pub detected_protocol: AdvancedFlowFilterFiniteSectionDto,
    pub tls_version: AdvancedFlowFilterFiniteSectionDto,
    pub quic_version: AdvancedFlowFilterFiniteSectionDto,
    pub directionality: AdvancedFlowFilterFiniteSectionDto,
    pub ports: AdvancedFlowFilterPortSectionDto,
    pub ip_addresses: AdvancedFlowFilterIpAddressSectionDto,
    pub time: AdvancedFlowFilterTimeSectionDto,
    pub traffic: AdvancedFlowFilterTrafficSectionDto,
    pub service: AdvancedFlowFilterServiceSectionDto,
    pub protocol_path: AdvancedFlowFilterProtocolPathSectionDto,
    pub contains_layer: AdvancedFlowFilterContainsLayerSectionDto,
    pub has_unsupported_configured_sections: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvancedFlowFilterStructuredUpdateIssueDto {
    pub section_id: String,
    pub group: String,
    pub value_id: String,
    pub row_index: Option<usize>,
    pub field_id: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvancedFlowFilterStructuredDocumentResultDto {
    pub status: String,
    pub document: Option<AdvancedFlowFilterStructuredDocumentDto>,
    pub option_catalog: AdvancedFlowFilterStructuredOptionCatalogDto,
    pub configured_rule_count: usize,
    pub active_rule_count: usize,
    pub parse_status: String,
    pub parse_issue: Option<AdvancedFlowFilterParseIssueDto>,
    pub compile_status: String,
    pub compile_issue: Option<AdvancedFlowFilterCompileIssueDto>,
    pub update_issue: Option<AdvancedFlowFilterStructuredUpdateIssueDto>,
    pub error_text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolStatsDto {
    pub flow_count: u64,
    pub packet_count: u64,
    pub captured_bytes: u64,
    pub captured_bytes_text: String,
    pub original_bytes: u64,
    pub original_bytes_text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverviewSummaryDto {
    pub packet_count: u64,
    pub flow_count: u64,
    pub captured_bytes: u64,
    pub captured_bytes_text: String,
    pub original_bytes: u64,
    pub original_bytes_text: String,
    pub total_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WholeCaptureTotalsDto {
    pub packet_count: u64,
    pub captured_bytes: u64,
    pub captured_bytes_text: String,
    pub original_bytes: u64,
    pub original_bytes_text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureTimeStatisticsDto {
    pub available: bool,
    pub capture_start_timestamp_us: Option<u64>,
    pub capture_start_text: String,
    pub capture_end_timestamp_us: Option<u64>,
    pub capture_end_text: String,
    pub duration_us: Option<u64>,
    pub duration_text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureMetricsDto {
    pub average_captured_packet_size: Option<f64>,
    pub average_captured_packet_size_text: String,
    pub average_original_packet_size: Option<f64>,
    pub average_original_packet_size_text: String,
    pub average_packet_rate: Option<f64>,
    pub average_packet_rate_text: String,
    pub average_captured_data_rate: Option<f64>,
    pub average_captured_data_rate_text: String,
    pub average_original_data_rate: Option<f64>,
    pub average_original_data_rate_text: String,
    pub truncated_packet_count: u64,
    pub truncated_packet_fraction: f64,
    pub truncated_packets_text: String,
    pub not_captured_bytes: u64,
    pub not_captured_bytes_text: String,
    pub capture_completeness: Option<f64>,
    pub capture_completeness_text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowCharacteristicsDto {
    pub total_flow_count: u64,
    pub only_a_to_b_flow_count: u64,
    pub only_a_to_b_flow_fraction: f64,
    pub only_a_to_b_flows_text: String,
    pub service_recognized_flow_count: u64,
    pub service_recognized_flow_fraction: f64,
    pub service_recognized_flows_text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectionDistributionRowDto {
    pub stable_id: String,
    pub label: String,
    pub flow_count: u64,
    pub flow_fraction: f64,
    pub flow_count_text: String,
    pub percent_text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectionDistributionDto {
    pub total_flow_count: u64,
    pub help_text: String,
    pub rows: Vec<DirectionDistributionRowDto>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpFlagStatisticsRowDto {
    pub stable_id: String,
    pub label: String,
    pub packet_count: u64,
    pub packet_fraction: f64,
    pub packet_count_text: String,
    pub percent_text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpFlagStatisticsDto {
    pub has_tcp_packets: bool,
    pub total_tcp_packet_count: u64,
    pub help_text: String,
    pub rows: Vec<TcpFlagStatisticsRowDto>,
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
    pub captured_bytes_text: String,
    pub original_bytes: u64,
    pub original_bytes_text: String,
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
    pub flow_count_text: String,
    pub packet_count: u64,
    pub packet_count_text: String,
    pub captured_bytes: u64,
    pub captured_bytes_text: String,
    pub original_bytes: u64,
    pub original_bytes_text: String,
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
pub struct FlowPacketCountHistogramBucketDto {
    pub bucket_id: String,
    pub label: String,
    pub lower_bound_inclusive: u64,
    pub upper_bound_inclusive: Option<u64>,
    pub flow_count: u64,
    pub flow_count_with_total_percent_text: String,
    pub captured_byte_count: u64,
    pub captured_byte_count_text: String,
    pub captured_byte_count_with_total_percent_text: String,
    pub original_byte_count: u64,
    pub original_byte_count_text: String,
    pub original_byte_count_with_total_percent_text: String,
    pub total_flow_fraction: f64,
    pub total_captured_byte_fraction: f64,
    pub total_original_byte_fraction: f64,
    pub normalized_flow_fraction: f64,
    pub normalized_captured_byte_fraction: f64,
    pub normalized_original_byte_fraction: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapturePacketSizeStatisticsBucketDto {
    pub bucket_id: String,
    pub label: String,
    pub lower_bound_inclusive: u32,
    pub upper_bound_inclusive: Option<u32>,
    pub captured_packet_count: u64,
    pub captured_packet_count_text: String,
    pub captured_total_fraction: f64,
    pub captured_total_percent_text: String,
    pub captured_normalized_fraction: f64,
    pub original_packet_count: u64,
    pub original_packet_count_text: String,
    pub original_total_fraction: f64,
    pub original_total_percent_text: String,
    pub original_normalized_fraction: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapturePacketSizeStatisticsDto {
    pub has_capture: bool,
    pub total_packet_count: u64,
    pub maximum_captured_bucket_packet_count: u64,
    pub maximum_original_bucket_packet_count: u64,
    pub maximum_captured_packet_length: u32,
    pub maximum_captured_packet_length_text: String,
    pub maximum_original_packet_length: u32,
    pub maximum_original_packet_length_text: String,
    pub buckets: Vec<CapturePacketSizeStatisticsBucketDto>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowPacketCountHistogramDto {
    pub has_capture: bool,
    pub total_flow_count: u64,
    pub total_captured_byte_count: u64,
    pub total_original_byte_count: u64,
    pub maximum_bucket_flow_count: u64,
    pub maximum_bucket_captured_byte_count: u64,
    pub maximum_bucket_original_byte_count: u64,
    pub excluded_zero_packet_flow_count: u64,
    pub excluded_zero_packet_captured_byte_count: u64,
    pub excluded_zero_packet_original_byte_count: u64,
    pub buckets: Vec<FlowPacketCountHistogramBucketDto>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolHintStatisticsDto {
    pub has_capture: bool,
    pub protocol_hints: Vec<ProtocolHintStatsDto>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuicTlsStatisticsDto {
    pub has_capture: bool,
    pub quic_recognition: QuicRecognitionDto,
    pub tls_recognition: TlsRecognitionDto,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopEndpointPortStatisticsDto {
    pub has_capture: bool,
    pub limit: usize,
    pub top_endpoints: Vec<TopEndpointDto>,
    pub top_ports: Vec<TopPortDto>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolPathStatsDto {
    pub node_id: u64,
    pub parent_node_id: u64,
    pub depth: usize,
    pub layer_text: String,
    pub path_text: String,
    pub compact_text: String,
    pub advanced_filter_predicate_text: String,
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
pub struct SupportedProtocolCatalogRowDto {
    pub category_id: String,
    pub category_label: String,
    pub protocol_id: String,
    pub protocol: String,
    pub recognition_status_id: String,
    pub recognition_status_label: String,
    pub service_status_id: String,
    pub service_status_label: String,
    pub packet_summary_status_id: String,
    pub packet_summary_status_label: String,
    pub stream_status_id: String,
    pub stream_status_label: String,
    pub notes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupportedProtocolCatalogDto {
    pub rows: Vec<SupportedProtocolCatalogRowDto>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverviewDto {
    pub has_capture: bool,
    pub unrecognized_packet_count: u64,
    pub unrecognized_packets: Option<UnrecognizedPacketStatisticsDto>,
    pub summary: OverviewSummaryDto,
    pub whole_capture_totals: WholeCaptureTotalsDto,
    pub capture_time: CaptureTimeStatisticsDto,
    pub capture_metrics: CaptureMetricsDto,
    pub flow_characteristics: FlowCharacteristicsDto,
    pub packet_direction_distribution: DirectionDistributionDto,
    pub original_byte_direction_distribution: DirectionDistributionDto,
    pub tcp_flag_statistics: TcpFlagStatisticsDto,
    pub statistics_partial_open_warning_text: String,
    pub protocol_summary: OverviewProtocolSummaryDto,
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
    pub payload_length: Option<u32>,
    pub is_ip_fragmented: Option<bool>,
    pub suspected_tcp_retransmission: bool,
    pub tcp_flags_text: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectedFlowPacketsDto {
    pub has_capture: bool,
    pub has_selected_flow: bool,
    pub flow_index: usize,
    pub offset: usize,
    pub limit: usize,
    pub total_count: usize,
    pub updated_flow: Option<FlowDto>,
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
    pub summary_layers: Vec<PacketSummaryLayerDto>,
    pub stream_item_data: StreamItemDataDto,
    pub payload_tab_title: String,
    pub payload_preview_text: String,
    pub payload_preview_unavailable_text: String,
    pub constricted_contribution_notes: Vec<String>,
    pub constricted_packet_notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamItemDataDto {
    pub available: bool,
    pub semantic_kind: String,
    pub source_kind: String,
    pub state: String,
    pub assembly_kind: String,
    pub available_length: u64,
    pub declared_length: Option<u64>,
    pub contributing_unit_kind: Option<String>,
    pub contributing_unit_count: Option<u64>,
    pub logical_offset: Option<u64>,
    pub status_text: String,
    pub formatted_text: String,
    pub unavailable_text: String,
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
    pub checksum_validation_enabled: bool,
    pub flow_index: usize,
    pub packet_index: u64,
    pub details_title: String,
    pub summary_text: String,
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
    pub byte_view_descriptors: Vec<PacketByteViewDescriptorDto>,
    pub selected_byte_view: PacketByteViewContentDto,
    pub checksum_summary_lines: Vec<String>,
    pub checksum_warning_lines: Vec<String>,
    pub unavailable_text: String,
    pub error_text: String,
    pub source_availability: SourceAvailabilityDto,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketByteViewDescriptorDto {
    pub stable_id: String,
    pub label: String,
    pub parent_stable_id: Option<String>,
    pub depth: usize,
    pub owner_kind: String,
    pub role: String,
    pub available_length: u32,
    pub declared_length: Option<u32>,
    pub state: String,
    pub supports_payload_only: bool,
    pub payload_available_length: Option<u32>,
    pub payload_declared_length: Option<u32>,
    pub payload_state: Option<String>,
    pub quic_crypto_stream_offset: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketByteViewContentDto {
    pub available: bool,
    pub stable_id: String,
    pub label: String,
    pub mode: String,
    pub available_length: u32,
    pub declared_length: Option<u32>,
    pub state: String,
    pub status_text: String,
    pub formatted_text: String,
    pub unavailable_text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisSequencePreviewRowDto {
    pub flow_packet_number: u64,
    pub direction_text: String,
    pub delta_time_text: String,
    pub timestamp_text: String,
    pub captured_length: u32,
    pub original_length: u32,
    pub payload_length: Option<u32>,
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
    pub max_captured_packet_size_text: String,
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
