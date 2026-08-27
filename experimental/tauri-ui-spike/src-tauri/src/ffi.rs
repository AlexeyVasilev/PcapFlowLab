use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_uchar};

use crate::dtos::{
    AdvancedFlowFilterDocumentWorkflowStateDto, AdvancedFlowFilterQueryResultDto, AdvancedFlowFilterStructuredDocumentDto, AdvancedFlowFilterStructuredDocumentResultDto, AnalysisSequenceExportResultDto, AttachSourceCaptureResultDto, ByteExportFormatDto, ByteExportResultDto, CapturePacketSizeStatisticsDto, ExportAllFlowsInfoCsvResultDto, ExportCurrentFlowResultDto, ExportProtocolPathTreeResultDto, ExportSelectedFlowsResultDto, FlowDto, FlowPacketCountHistogramDto, OpenCaptureCancelResultDto, OpenCapturePollResultDto, OpenCaptureResultDto, OpenCaptureStartResultDto, OverviewDto, PacketByteViewContentDto, PacketDetailsDto, ProtocolHintStatisticsDto, QuicTlsStatisticsDto, SaveIndexResultDto, SelectedFlowAnalysisDto,
    ProtocolPathLegendEntryDto, ProtocolPathStatsDto, SelectedFlowPacketsDto, SelectedFlowStreamDto, SelectionResultDto, StreamItemDto, SupportedProtocolCatalogDto, TopEndpointPortStatisticsDto, UnrecognizedPacketsDto,
    SettingsDto,
    SmartExportResultDto,
};

#[repr(C)]
struct PflFrontendSessionAdapterHandle {
    _private: [u8; 0],
}

#[link(name = "pfl_tauri_bridge", kind = "static")]
extern "C" {
    fn pfl_frontend_session_adapter_new() -> *mut PflFrontendSessionAdapterHandle;
    fn pfl_frontend_session_adapter_free(handle: *mut PflFrontendSessionAdapterHandle);
    fn pfl_frontend_session_adapter_open_capture_json(
        handle: *mut PflFrontendSessionAdapterHandle,
        path_utf8: *const c_char,
    ) -> *mut c_char;
    fn pfl_frontend_session_adapter_start_open_capture_json(
        handle: *mut PflFrontendSessionAdapterHandle,
        path_utf8: *const c_char,
    ) -> *mut c_char;
    fn pfl_frontend_session_adapter_poll_open_capture_json(
        handle: *mut PflFrontendSessionAdapterHandle,
    ) -> *mut c_char;
    fn pfl_frontend_session_adapter_cancel_open_capture_json(
        handle: *mut PflFrontendSessionAdapterHandle,
    ) -> *mut c_char;
    fn pfl_frontend_session_adapter_attach_source_capture_json(
        handle: *mut PflFrontendSessionAdapterHandle,
        path_utf8: *const c_char,
    ) -> *mut c_char;
    fn pfl_frontend_session_adapter_save_index_json(
        handle: *mut PflFrontendSessionAdapterHandle,
        path_utf8: *const c_char,
    ) -> *mut c_char;
    fn pfl_frontend_session_adapter_get_settings_json(
        handle: *mut PflFrontendSessionAdapterHandle,
    ) -> *mut c_char;
    fn pfl_frontend_session_adapter_get_capture_packet_size_statistics_json(
        handle: *mut PflFrontendSessionAdapterHandle,
    ) -> *mut c_char;
    fn pfl_frontend_session_adapter_get_flow_packet_count_histogram_json(
        handle: *mut PflFrontendSessionAdapterHandle,
    ) -> *mut c_char;
    fn pfl_frontend_session_adapter_get_protocol_hint_statistics_json(
        handle: *mut PflFrontendSessionAdapterHandle,
    ) -> *mut c_char;
    fn pfl_frontend_session_adapter_get_quic_tls_statistics_json(
        handle: *mut PflFrontendSessionAdapterHandle,
    ) -> *mut c_char;
    fn pfl_frontend_session_adapter_get_top_endpoint_port_statistics_json(
        handle: *mut PflFrontendSessionAdapterHandle,
        limit: usize,
    ) -> *mut c_char;
    fn pfl_frontend_session_adapter_get_protocol_path_legend_json(
        handle: *mut PflFrontendSessionAdapterHandle,
    ) -> *mut c_char;
    fn pfl_frontend_session_adapter_get_supported_protocol_catalog_json(
        handle: *mut PflFrontendSessionAdapterHandle,
    ) -> *mut c_char;
    fn pfl_frontend_session_adapter_get_protocol_path_statistics_json(
        handle: *mut PflFrontendSessionAdapterHandle,
        mode: c_uchar,
    ) -> *mut c_char;
    fn pfl_frontend_session_adapter_get_protocol_path_summary_flow_indices_json(
        handle: *mut PflFrontendSessionAdapterHandle,
        mode: c_uchar,
        node_id: u64,
    ) -> *mut c_char;
    fn pfl_frontend_session_adapter_get_advanced_flow_filter_protocol_path_row_json(
        handle: *mut PflFrontendSessionAdapterHandle,
        mode: c_uchar,
        node_id: u64,
    ) -> *mut c_char;
    fn pfl_frontend_session_adapter_query_advanced_flows_text_json(
        handle: *mut PflFrontendSessionAdapterHandle,
        filter_text_utf8: *const c_char,
        candidate_flow_indices: *const usize,
        candidate_flow_index_count: usize,
    ) -> *mut c_char;
    fn pfl_frontend_session_adapter_parse_advanced_flow_filter_structured_document_json(
        handle: *mut PflFrontendSessionAdapterHandle,
        filter_text_utf8: *const c_char,
    ) -> *mut c_char;
    fn pfl_frontend_session_adapter_get_advanced_flow_filter_document_workflow_state_json(
        handle: *mut PflFrontendSessionAdapterHandle,
    ) -> *mut c_char;
    fn pfl_frontend_session_adapter_update_advanced_flow_filter_structured_section_json(
        handle: *mut PflFrontendSessionAdapterHandle,
        filter_text_utf8: *const c_char,
        section_id_utf8: *const c_char,
        enabled: c_uchar,
        include_ids_utf8: *const *const c_char,
        include_id_count: usize,
        exclude_ids_utf8: *const *const c_char,
        exclude_id_count: usize,
    ) -> *mut c_char;
    fn pfl_frontend_session_adapter_apply_advanced_flow_filter_structured_document_json(
        handle: *mut PflFrontendSessionAdapterHandle,
        filter_text_utf8: *const c_char,
        address_family_enabled: c_uchar,
        address_family_include_ids_utf8: *const *const c_char,
        address_family_include_id_count: usize,
        address_family_exclude_ids_utf8: *const *const c_char,
        address_family_exclude_id_count: usize,
        flow_protocol_enabled: c_uchar,
        flow_protocol_include_ids_utf8: *const *const c_char,
        flow_protocol_include_id_count: usize,
        flow_protocol_exclude_ids_utf8: *const *const c_char,
        flow_protocol_exclude_id_count: usize,
        detected_protocol_enabled: c_uchar,
        detected_protocol_include_ids_utf8: *const *const c_char,
        detected_protocol_include_id_count: usize,
        detected_protocol_exclude_ids_utf8: *const *const c_char,
        detected_protocol_exclude_id_count: usize,
        tls_version_enabled: c_uchar,
        tls_version_include_ids_utf8: *const *const c_char,
        tls_version_include_id_count: usize,
        tls_version_exclude_ids_utf8: *const *const c_char,
        tls_version_exclude_id_count: usize,
        quic_version_enabled: c_uchar,
        quic_version_include_ids_utf8: *const *const c_char,
        quic_version_include_id_count: usize,
        quic_version_exclude_ids_utf8: *const *const c_char,
        quic_version_exclude_id_count: usize,
        directionality_enabled: c_uchar,
        directionality_include_ids_utf8: *const *const c_char,
        directionality_include_id_count: usize,
        directionality_exclude_ids_utf8: *const *const c_char,
        directionality_exclude_id_count: usize,
        ports_enabled: c_uchar,
        ports_include_scope_ids_utf8: *const *const c_char,
        ports_include_range_enabled: *const c_uchar,
        ports_include_primary_text_utf8: *const *const c_char,
        ports_include_secondary_text_utf8: *const *const c_char,
        ports_include_count: usize,
        ports_exclude_scope_ids_utf8: *const *const c_char,
        ports_exclude_range_enabled: *const c_uchar,
        ports_exclude_primary_text_utf8: *const *const c_char,
        ports_exclude_secondary_text_utf8: *const *const c_char,
        ports_exclude_count: usize,
        ip_addresses_enabled: c_uchar,
        ip_include_scope_ids_utf8: *const *const c_char,
        ip_include_subnet_enabled: *const c_uchar,
        ip_include_address_text_utf8: *const *const c_char,
        ip_include_prefix_text_utf8: *const *const c_char,
        ip_include_count: usize,
        ip_exclude_scope_ids_utf8: *const *const c_char,
        ip_exclude_subnet_enabled: *const c_uchar,
        ip_exclude_address_text_utf8: *const *const c_char,
        ip_exclude_prefix_text_utf8: *const *const c_char,
        ip_exclude_count: usize,
        traffic_enabled: c_uchar,
        traffic_primary_metric_ids_utf8: *const *const c_char,
        traffic_primary_unit_ids_utf8: *const *const c_char,
        traffic_primary_min_text_utf8: *const *const c_char,
        traffic_primary_max_text_utf8: *const *const c_char,
        traffic_primary_count: usize,
        traffic_additional_metric_ids_utf8: *const *const c_char,
        traffic_additional_unit_ids_utf8: *const *const c_char,
        traffic_additional_min_text_utf8: *const *const c_char,
        traffic_additional_max_text_utf8: *const *const c_char,
        traffic_additional_count: usize,
        service_enabled: c_uchar,
        service_include_recognized: c_uchar,
        service_include_unrecognized: c_uchar,
        service_include_operator_ids_utf8: *const *const c_char,
        service_include_case_sensitive: *const c_uchar,
        service_include_text_utf8: *const *const c_char,
        service_include_text_count: usize,
        service_exclude_recognized: c_uchar,
        service_exclude_unrecognized: c_uchar,
        service_exclude_operator_ids_utf8: *const *const c_char,
        service_exclude_case_sensitive: *const c_uchar,
        service_exclude_text_utf8: *const *const c_char,
        service_exclude_text_count: usize,
        protocol_path_enabled: c_uchar,
        protocol_path_include_selector_mode_ids_utf8: *const *const c_char,
        protocol_path_include_predicate_text_utf8: *const *const c_char,
        protocol_path_include_count: usize,
        protocol_path_exclude_selector_mode_ids_utf8: *const *const c_char,
        protocol_path_exclude_predicate_text_utf8: *const *const c_char,
        protocol_path_exclude_count: usize,
        contains_layer_enabled: c_uchar,
        contains_layer_include_layer_stable_ids_utf8: *const *const c_char,
        contains_layer_include_identifier_mode_ids_utf8: *const *const c_char,
        contains_layer_include_exact_value_text_utf8: *const *const c_char,
        contains_layer_include_count: usize,
        contains_layer_exclude_layer_stable_ids_utf8: *const *const c_char,
        contains_layer_exclude_identifier_mode_ids_utf8: *const *const c_char,
        contains_layer_exclude_exact_value_text_utf8: *const *const c_char,
        contains_layer_exclude_count: usize,
    ) -> *mut c_char;
    fn pfl_frontend_session_adapter_apply_advanced_flow_filter_document_text_json(
        handle: *mut PflFrontendSessionAdapterHandle,
        filter_text_utf8: *const c_char,
    ) -> *mut c_char;
    fn pfl_frontend_session_adapter_accept_opened_advanced_flow_filter_document_text_json(
        handle: *mut PflFrontendSessionAdapterHandle,
        filter_text_utf8: *const c_char,
        source_path_utf8: *const c_char,
    ) -> *mut c_char;
    fn pfl_frontend_session_adapter_accept_saved_advanced_flow_filter_document_text_json(
        handle: *mut PflFrontendSessionAdapterHandle,
        filter_text_utf8: *const c_char,
        source_path_utf8: *const c_char,
    ) -> *mut c_char;
    fn pfl_frontend_session_adapter_clear_advanced_flow_filter_unsaved_changes_json(
        handle: *mut PflFrontendSessionAdapterHandle,
    ) -> *mut c_char;
    fn pfl_frontend_session_adapter_clear_advanced_flow_filter_document_json(
        handle: *mut PflFrontendSessionAdapterHandle,
    ) -> *mut c_char;
    fn pfl_frontend_advanced_flow_filter_max_file_bytes() -> usize;
    fn pfl_frontend_session_adapter_export_protocol_path_tree_json(
        handle: *mut PflFrontendSessionAdapterHandle,
        mode: c_uchar,
        path_utf8: *const c_char,
    ) -> *mut c_char;
    fn pfl_frontend_session_adapter_get_byte_export_formats_json(
        handle: *mut PflFrontendSessionAdapterHandle,
    ) -> *mut c_char;
    fn pfl_frontend_session_adapter_export_selected_flow_packet_byte_view_json(
        handle: *mut PflFrontendSessionAdapterHandle,
        packet_index: u64,
        stable_id_utf8: *const c_char,
        format_id_utf8: *const c_char,
        path_utf8: *const c_char,
        flow_packet_index: u64,
        loaded_packet_window_count: u64,
    ) -> *mut c_char;
    fn pfl_frontend_session_adapter_export_unrecognized_packet_byte_view_json(
        handle: *mut PflFrontendSessionAdapterHandle,
        packet_index: u64,
        stable_id_utf8: *const c_char,
        format_id_utf8: *const c_char,
        path_utf8: *const c_char,
    ) -> *mut c_char;
    fn pfl_frontend_session_adapter_export_selected_flow_stream_item_data_json(
        handle: *mut PflFrontendSessionAdapterHandle,
        max_packets_to_scan: usize,
        limit: usize,
        stream_item_index: u64,
        format_id_utf8: *const c_char,
        path_utf8: *const c_char,
    ) -> *mut c_char;
    fn pfl_frontend_session_adapter_update_settings_json(
        handle: *mut PflFrontendSessionAdapterHandle,
        http_use_path_as_service_hint: c_uchar,
        use_possible_tls_quic: c_uchar,
        ignore_vlan_and_mpls_layers_when_grouping_flows: c_uchar,
        ignore_gtpu_teids_when_grouping_inner_flows: c_uchar,
        show_wireshark_filter_for_selected_flow: c_uchar,
        validate_selected_packet_checksums: c_uchar,
    ) -> *mut c_char;
    fn pfl_frontend_session_adapter_export_current_flow_json(
        handle: *mut PflFrontendSessionAdapterHandle,
        path_utf8: *const c_char,
    ) -> *mut c_char;
    fn pfl_frontend_session_adapter_export_selected_flows_json(
        handle: *mut PflFrontendSessionAdapterHandle,
        path_utf8: *const c_char,
        flow_indices: *const usize,
        flow_index_count: usize,
    ) -> *mut c_char;
    fn pfl_frontend_session_adapter_export_all_flows_info_csv_json(
        handle: *mut PflFrontendSessionAdapterHandle,
        path_utf8: *const c_char,
    ) -> *mut c_char;
    fn pfl_frontend_session_adapter_export_smart_flows_json(
        handle: *mut PflFrontendSessionAdapterHandle,
        path_utf8: *const c_char,
        flow_indices: *const usize,
        flow_index_count: usize,
        output_mode: c_uchar,
        base_mode: c_uchar,
        first_n_packets: u64,
        first_m_original_bytes: u64,
        include_last_packet: c_uchar,
        include_every_kth_packet_after_base: c_uchar,
        every_kth_packet: u64,
        per_flow_buffer_budget_bytes: usize,
    ) -> *mut c_char;
    fn pfl_frontend_session_adapter_export_smart_unrecognized_packets_json(
        handle: *mut PflFrontendSessionAdapterHandle,
        path_utf8: *const c_char,
        base_mode: c_uchar,
        first_n_packets: u64,
        first_m_original_bytes: u64,
        include_last_packet: c_uchar,
        include_every_kth_packet_after_base: c_uchar,
        every_kth_packet: u64,
    ) -> *mut c_char;
    fn pfl_frontend_session_adapter_get_overview_json(
        handle: *mut PflFrontendSessionAdapterHandle,
    ) -> *mut c_char;
    fn pfl_frontend_session_adapter_get_flows_json(
        handle: *mut PflFrontendSessionAdapterHandle,
    ) -> *mut c_char;
    fn pfl_frontend_session_adapter_select_flow_json(
        handle: *mut PflFrontendSessionAdapterHandle,
        flow_index: usize,
    ) -> *mut c_char;
    fn pfl_frontend_session_adapter_get_selected_flow_packets_json(
        handle: *mut PflFrontendSessionAdapterHandle,
        offset: usize,
        limit: usize,
    ) -> *mut c_char;
    fn pfl_frontend_session_adapter_get_unrecognized_packets_json(
        handle: *mut PflFrontendSessionAdapterHandle,
        offset: usize,
        limit: usize,
    ) -> *mut c_char;
    fn pfl_frontend_session_adapter_get_selected_flow_stream_json(
        handle: *mut PflFrontendSessionAdapterHandle,
        max_packets_to_scan: usize,
        limit: usize,
    ) -> *mut c_char;
    fn pfl_frontend_session_adapter_get_selected_flow_stream_item_details_json(
        handle: *mut PflFrontendSessionAdapterHandle,
        max_packets_to_scan: usize,
        limit: usize,
        stream_item_index: u64,
    ) -> *mut c_char;
    fn pfl_frontend_session_adapter_get_selected_flow_packet_details_json(
        handle: *mut PflFrontendSessionAdapterHandle,
        packet_index: u64,
        flow_packet_index: u64,
        loaded_packet_window_count: u64,
    ) -> *mut c_char;
    fn pfl_frontend_session_adapter_get_selected_flow_packet_byte_view_content_json(
        handle: *mut PflFrontendSessionAdapterHandle,
        packet_index: u64,
        stable_id_utf8: *const c_char,
        flow_packet_index: u64,
        loaded_packet_window_count: u64,
    ) -> *mut c_char;
    fn pfl_frontend_session_adapter_get_unrecognized_packet_details_json(
        handle: *mut PflFrontendSessionAdapterHandle,
        packet_index: u64,
    ) -> *mut c_char;
    fn pfl_frontend_session_adapter_get_unrecognized_packet_byte_view_content_json(
        handle: *mut PflFrontendSessionAdapterHandle,
        packet_index: u64,
        stable_id_utf8: *const c_char,
    ) -> *mut c_char;
    fn pfl_frontend_session_adapter_get_selected_flow_analysis_json(
        handle: *mut PflFrontendSessionAdapterHandle,
    ) -> *mut c_char;
    fn pfl_frontend_session_adapter_export_selected_flow_analysis_sequence_csv_json(
        handle: *mut PflFrontendSessionAdapterHandle,
        path_utf8: *const c_char,
    ) -> *mut c_char;
    fn pfl_frontend_string_free(value: *mut c_char);
}

pub struct CppFrontendSessionAdapter {
    handle: *mut PflFrontendSessionAdapterHandle,
}

unsafe impl Send for CppFrontendSessionAdapter {}

struct OwnedBridgeJson {
    ptr: *mut c_char,
}

impl OwnedBridgeJson {
    fn new(ptr: *mut c_char) -> Result<Self, String> {
        if ptr.is_null() {
            return Err("Bridge returned no data.".to_string());
        }

        Ok(Self { ptr })
    }

    fn as_c_str(&self) -> &CStr {
        unsafe { CStr::from_ptr(self.ptr) }
    }
}

impl Drop for OwnedBridgeJson {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            unsafe {
                pfl_frontend_string_free(self.ptr);
            }
            self.ptr = std::ptr::null_mut();
        }
    }
}

impl CppFrontendSessionAdapter {
    pub fn new() -> Result<Self, String> {
        let handle = unsafe { pfl_frontend_session_adapter_new() };
        if handle.is_null() {
            return Err("Failed to create frontend adapter.".to_string());
        }

        Ok(Self { handle })
    }

    pub fn open_capture(&mut self, path: &str) -> Result<OpenCaptureResultDto, String> {
        let path = CString::new(path).map_err(|_| "Capture path contains an embedded NUL byte.".to_string())?;
        let json = unsafe { pfl_frontend_session_adapter_open_capture_json(self.handle, path.as_ptr()) };
        parse_json_owned::<OpenCaptureResultDto>(json)
    }

    pub fn start_open_capture(&mut self, path: &str) -> Result<OpenCaptureStartResultDto, String> {
        let path = CString::new(path).map_err(|_| "Capture path contains an embedded NUL byte.".to_string())?;
        let json = unsafe { pfl_frontend_session_adapter_start_open_capture_json(self.handle, path.as_ptr()) };
        parse_json_owned::<OpenCaptureStartResultDto>(json)
    }

    pub fn poll_open_capture(&mut self) -> Result<OpenCapturePollResultDto, String> {
        let json = unsafe { pfl_frontend_session_adapter_poll_open_capture_json(self.handle) };
        parse_json_owned::<OpenCapturePollResultDto>(json)
    }

    pub fn cancel_open_capture(&mut self) -> Result<OpenCaptureCancelResultDto, String> {
        let json = unsafe { pfl_frontend_session_adapter_cancel_open_capture_json(self.handle) };
        parse_json_owned::<OpenCaptureCancelResultDto>(json)
    }

    pub fn attach_source_capture(&mut self, path: &str) -> Result<AttachSourceCaptureResultDto, String> {
        let path = CString::new(path).map_err(|_| "Source capture path contains an embedded NUL byte.".to_string())?;
        let json = unsafe { pfl_frontend_session_adapter_attach_source_capture_json(self.handle, path.as_ptr()) };
        parse_json_owned::<AttachSourceCaptureResultDto>(json)
    }

    pub fn save_index(&self, path: &str) -> Result<SaveIndexResultDto, String> {
        let path = CString::new(path).map_err(|_| "Index path contains an embedded NUL byte.".to_string())?;
        let json = unsafe { pfl_frontend_session_adapter_save_index_json(self.handle, path.as_ptr()) };
        parse_json_owned::<SaveIndexResultDto>(json)
    }

    pub fn get_settings(&self) -> Result<SettingsDto, String> {
        let json = unsafe { pfl_frontend_session_adapter_get_settings_json(self.handle) };
        parse_json_owned::<SettingsDto>(json)
    }

    pub fn get_capture_packet_size_statistics(&self) -> Result<CapturePacketSizeStatisticsDto, String> {
        let json = unsafe { pfl_frontend_session_adapter_get_capture_packet_size_statistics_json(self.handle) };
        parse_json_owned::<CapturePacketSizeStatisticsDto>(json)
    }

    pub fn get_flow_packet_count_histogram(&self) -> Result<FlowPacketCountHistogramDto, String> {
        let json = unsafe { pfl_frontend_session_adapter_get_flow_packet_count_histogram_json(self.handle) };
        parse_json_owned::<FlowPacketCountHistogramDto>(json)
    }

    pub fn get_protocol_hint_statistics(&self) -> Result<ProtocolHintStatisticsDto, String> {
        let json = unsafe { pfl_frontend_session_adapter_get_protocol_hint_statistics_json(self.handle) };
        parse_json_owned::<ProtocolHintStatisticsDto>(json)
    }

    pub fn get_quic_tls_statistics(&self) -> Result<QuicTlsStatisticsDto, String> {
        let json = unsafe { pfl_frontend_session_adapter_get_quic_tls_statistics_json(self.handle) };
        parse_json_owned::<QuicTlsStatisticsDto>(json)
    }

    pub fn get_top_endpoint_port_statistics(&self, limit: usize) -> Result<TopEndpointPortStatisticsDto, String> {
        let json = unsafe { pfl_frontend_session_adapter_get_top_endpoint_port_statistics_json(self.handle, limit) };
        parse_json_owned::<TopEndpointPortStatisticsDto>(json)
    }

    pub fn get_protocol_path_legend(&self) -> Result<Vec<ProtocolPathLegendEntryDto>, String> {
        let json = unsafe { pfl_frontend_session_adapter_get_protocol_path_legend_json(self.handle) };
        parse_json_owned::<Vec<ProtocolPathLegendEntryDto>>(json)
    }

    pub fn get_supported_protocol_catalog(&self) -> Result<SupportedProtocolCatalogDto, String> {
        let json = unsafe { pfl_frontend_session_adapter_get_supported_protocol_catalog_json(self.handle) };
        parse_json_owned::<SupportedProtocolCatalogDto>(json)
    }

    pub fn get_protocol_path_statistics(&self, mode: u8) -> Result<Vec<ProtocolPathStatsDto>, String> {
        let json = unsafe { pfl_frontend_session_adapter_get_protocol_path_statistics_json(self.handle, mode) };
        parse_json_owned::<Vec<ProtocolPathStatsDto>>(json)
    }

    pub fn get_protocol_path_summary_flow_indices(
        &self,
        mode: u8,
        node_id: u64,
    ) -> Result<Vec<usize>, String> {
        let json = unsafe {
            pfl_frontend_session_adapter_get_protocol_path_summary_flow_indices_json(
                self.handle,
                mode,
                node_id,
            )
        };
        parse_json_owned::<Vec<usize>>(json)
    }

    pub fn get_advanced_flow_filter_protocol_path_row(
        &self,
        mode: u8,
        node_id: u64,
    ) -> Result<crate::dtos::AdvancedFlowFilterProtocolPathRowDto, String> {
        let json = unsafe {
            pfl_frontend_session_adapter_get_advanced_flow_filter_protocol_path_row_json(
                self.handle,
                mode,
                node_id,
            )
        };
        let row = parse_json_owned::<crate::dtos::AdvancedFlowFilterProtocolPathRowDto>(json)?;
        if row.selector_mode_id.is_empty() || row.predicate_text.is_empty() {
            return Err("Failed to build the selected Protocol Path filter row.".to_string());
        }
        Ok(row)
    }

    pub fn query_advanced_flows_text(
        &self,
        filter_text: &str,
        candidate_flow_indices: Option<&[usize]>,
    ) -> Result<AdvancedFlowFilterQueryResultDto, String> {
        let filter_text = CString::new(filter_text)
            .map_err(|_| "Advanced filter text contains an embedded NUL byte.".to_string())?;
        let candidate_ptr = candidate_flow_indices
            .map(|indices| indices.as_ptr())
            .unwrap_or(std::ptr::null());
        let candidate_count = candidate_flow_indices
            .map(|indices| indices.len())
            .unwrap_or(0);
        let json = unsafe {
            pfl_frontend_session_adapter_query_advanced_flows_text_json(
                self.handle,
                filter_text.as_ptr(),
                candidate_ptr,
                candidate_count,
            )
        };
        parse_json_owned::<AdvancedFlowFilterQueryResultDto>(json)
    }

    pub fn parse_advanced_flow_filter_structured_document(
        &self,
        filter_text: &str,
    ) -> Result<AdvancedFlowFilterStructuredDocumentResultDto, String> {
        let filter_text = CString::new(filter_text)
            .map_err(|_| "Advanced filter text contains an embedded NUL byte.".to_string())?;
        let json = unsafe {
            pfl_frontend_session_adapter_parse_advanced_flow_filter_structured_document_json(
                self.handle,
                filter_text.as_ptr(),
            )
        };
        parse_json_owned::<AdvancedFlowFilterStructuredDocumentResultDto>(json)
    }

    pub fn get_advanced_flow_filter_document_workflow_state(
        &self,
    ) -> Result<AdvancedFlowFilterDocumentWorkflowStateDto, String> {
        let json = unsafe {
            pfl_frontend_session_adapter_get_advanced_flow_filter_document_workflow_state_json(
                self.handle,
            )
        };
        parse_json_owned::<AdvancedFlowFilterDocumentWorkflowStateDto>(json)
    }

    pub fn update_advanced_flow_filter_structured_section(
        &self,
        filter_text: &str,
        section_id: &str,
        enabled: bool,
        include_ids: &[String],
        exclude_ids: &[String],
    ) -> Result<AdvancedFlowFilterStructuredDocumentResultDto, String> {
        let filter_text = CString::new(filter_text)
            .map_err(|_| "Advanced filter text contains an embedded NUL byte.".to_string())?;
        let section_id = CString::new(section_id)
            .map_err(|_| "Section ID contains an embedded NUL byte.".to_string())?;

        let include_cstrings = include_ids
            .iter()
            .map(|value| CString::new(value.as_str()).map_err(|_| "Include stable ID contains an embedded NUL byte.".to_string()))
            .collect::<Result<Vec<_>, _>>()?;
        let include_ptrs = include_cstrings
            .iter()
            .map(|value| value.as_ptr())
            .collect::<Vec<_>>();

        let exclude_cstrings = exclude_ids
            .iter()
            .map(|value| CString::new(value.as_str()).map_err(|_| "Exclude stable ID contains an embedded NUL byte.".to_string()))
            .collect::<Result<Vec<_>, _>>()?;
        let exclude_ptrs = exclude_cstrings
            .iter()
            .map(|value| value.as_ptr())
            .collect::<Vec<_>>();

        let json = unsafe {
            pfl_frontend_session_adapter_update_advanced_flow_filter_structured_section_json(
                self.handle,
                filter_text.as_ptr(),
                section_id.as_ptr(),
                if enabled { 1 } else { 0 },
                include_ptrs.as_ptr(),
                include_ptrs.len(),
                exclude_ptrs.as_ptr(),
                exclude_ptrs.len(),
            )
        };
        parse_json_owned::<AdvancedFlowFilterStructuredDocumentResultDto>(json)
    }

    pub fn apply_advanced_flow_filter_structured_document(
        &self,
        filter_text: &str,
        document: &AdvancedFlowFilterStructuredDocumentDto,
    ) -> Result<AdvancedFlowFilterStructuredDocumentResultDto, String> {
        let filter_text = CString::new(filter_text)
            .map_err(|_| "Advanced filter text contains an embedded NUL byte.".to_string())?;

        let collect_strings = |values: &[String], label: &str| -> Result<(Vec<CString>, Vec<*const c_char>), String> {
            let cstrings = values
                .iter()
                .map(|value| CString::new(value.as_str()).map_err(|_| format!("{label} contains an embedded NUL byte.")))
                .collect::<Result<Vec<_>, _>>()?;
            let ptrs = cstrings.iter().map(|value| value.as_ptr()).collect::<Vec<_>>();
            Ok((cstrings, ptrs))
        };

        let collect_port_rows = |rows: &[crate::dtos::AdvancedFlowFilterPortRowDto]| -> Result<_, String> {
            let scope_cstrings = rows
                .iter()
                .map(|row| CString::new(row.scope_id.as_str()).map_err(|_| "Port scope contains an embedded NUL byte.".to_string()))
                .collect::<Result<Vec<_>, _>>()?;
            let primary_cstrings = rows
                .iter()
                .map(|row| CString::new(row.primary_text.as_str()).map_err(|_| "Port text contains an embedded NUL byte.".to_string()))
                .collect::<Result<Vec<_>, _>>()?;
            let secondary_cstrings = rows
                .iter()
                .map(|row| CString::new(row.secondary_text.as_str()).map_err(|_| "Port text contains an embedded NUL byte.".to_string()))
                .collect::<Result<Vec<_>, _>>()?;
            let scope_ptrs = scope_cstrings.iter().map(|value| value.as_ptr()).collect::<Vec<_>>();
            let primary_ptrs = primary_cstrings.iter().map(|value| value.as_ptr()).collect::<Vec<_>>();
            let secondary_ptrs = secondary_cstrings.iter().map(|value| value.as_ptr()).collect::<Vec<_>>();
            let range_flags = rows
                .iter()
                .map(|row| if row.range_enabled { 1_u8 } else { 0_u8 })
                .collect::<Vec<_>>();
            Ok((scope_cstrings, primary_cstrings, secondary_cstrings, scope_ptrs, primary_ptrs, secondary_ptrs, range_flags))
        };

        let collect_ip_rows = |rows: &[crate::dtos::AdvancedFlowFilterIpAddressRowDto]| -> Result<_, String> {
            let scope_cstrings = rows
                .iter()
                .map(|row| CString::new(row.scope_id.as_str()).map_err(|_| "IP scope contains an embedded NUL byte.".to_string()))
                .collect::<Result<Vec<_>, _>>()?;
            let address_cstrings = rows
                .iter()
                .map(|row| CString::new(row.address_text.as_str()).map_err(|_| "IP address text contains an embedded NUL byte.".to_string()))
                .collect::<Result<Vec<_>, _>>()?;
            let prefix_cstrings = rows
                .iter()
                .map(|row| CString::new(row.prefix_text.as_str()).map_err(|_| "IP prefix text contains an embedded NUL byte.".to_string()))
                .collect::<Result<Vec<_>, _>>()?;
            let scope_ptrs = scope_cstrings.iter().map(|value| value.as_ptr()).collect::<Vec<_>>();
            let address_ptrs = address_cstrings.iter().map(|value| value.as_ptr()).collect::<Vec<_>>();
            let prefix_ptrs = prefix_cstrings.iter().map(|value| value.as_ptr()).collect::<Vec<_>>();
            let subnet_flags = rows
                .iter()
                .map(|row| if row.subnet_enabled { 1_u8 } else { 0_u8 })
                .collect::<Vec<_>>();
            Ok((scope_cstrings, address_cstrings, prefix_cstrings, scope_ptrs, address_ptrs, prefix_ptrs, subnet_flags))
        };

        let collect_traffic_rows = |rows: &[crate::dtos::AdvancedFlowFilterTrafficRowDto]| -> Result<_, String> {
            let metric_cstrings = rows
                .iter()
                .map(|row| CString::new(row.metric_id.as_str()).map_err(|_| "Traffic metric ID contains an embedded NUL byte.".to_string()))
                .collect::<Result<Vec<_>, _>>()?;
            let unit_cstrings = rows
                .iter()
                .map(|row| CString::new(row.unit_id.as_str()).map_err(|_| "Traffic unit ID contains an embedded NUL byte.".to_string()))
                .collect::<Result<Vec<_>, _>>()?;
            let min_cstrings = rows
                .iter()
                .map(|row| CString::new(row.min_text.as_str()).map_err(|_| "Traffic Min text contains an embedded NUL byte.".to_string()))
                .collect::<Result<Vec<_>, _>>()?;
            let max_cstrings = rows
                .iter()
                .map(|row| CString::new(row.max_text.as_str()).map_err(|_| "Traffic Max text contains an embedded NUL byte.".to_string()))
                .collect::<Result<Vec<_>, _>>()?;
            let metric_ptrs = metric_cstrings.iter().map(|value| value.as_ptr()).collect::<Vec<_>>();
            let unit_ptrs = unit_cstrings.iter().map(|value| value.as_ptr()).collect::<Vec<_>>();
            let min_ptrs = min_cstrings.iter().map(|value| value.as_ptr()).collect::<Vec<_>>();
            let max_ptrs = max_cstrings.iter().map(|value| value.as_ptr()).collect::<Vec<_>>();
            Ok((metric_cstrings, unit_cstrings, min_cstrings, max_cstrings, metric_ptrs, unit_ptrs, min_ptrs, max_ptrs))
        };

        let collect_service_rows = |rows: &[crate::dtos::AdvancedFlowFilterServiceTextRowDto]| -> Result<_, String> {
            let operator_cstrings = rows
                .iter()
                .map(|row| CString::new(row.operator_id.as_str()).map_err(|_| "Service operator ID contains an embedded NUL byte.".to_string()))
                .collect::<Result<Vec<_>, _>>()?;
            let text_cstrings = rows
                .iter()
                .map(|row| CString::new(row.text.as_str()).map_err(|_| "Service text contains an embedded NUL byte.".to_string()))
                .collect::<Result<Vec<_>, _>>()?;
            let operator_ptrs = operator_cstrings.iter().map(|value| value.as_ptr()).collect::<Vec<_>>();
            let text_ptrs = text_cstrings.iter().map(|value| value.as_ptr()).collect::<Vec<_>>();
            let case_sensitive_flags = rows
                .iter()
                .map(|row| if row.case_sensitive { 1_u8 } else { 0_u8 })
                .collect::<Vec<_>>();
            Ok((operator_cstrings, text_cstrings, operator_ptrs, text_ptrs, case_sensitive_flags))
        };

        let collect_protocol_path_rows = |rows: &[crate::dtos::AdvancedFlowFilterProtocolPathRowDto]| -> Result<_, String> {
            let selector_mode_cstrings = rows
                .iter()
                .map(|row| CString::new(row.selector_mode_id.as_str()).map_err(|_| "Protocol Path selector mode contains an embedded NUL byte.".to_string()))
                .collect::<Result<Vec<_>, _>>()?;
            let predicate_text_cstrings = rows
                .iter()
                .map(|row| CString::new(row.predicate_text.as_str()).map_err(|_| "Protocol Path predicate text contains an embedded NUL byte.".to_string()))
                .collect::<Result<Vec<_>, _>>()?;
            let selector_mode_ptrs = selector_mode_cstrings.iter().map(|value| value.as_ptr()).collect::<Vec<_>>();
            let predicate_text_ptrs = predicate_text_cstrings.iter().map(|value| value.as_ptr()).collect::<Vec<_>>();
            Ok((selector_mode_cstrings, predicate_text_cstrings, selector_mode_ptrs, predicate_text_ptrs))
        };

        let collect_contains_layer_rows = |rows: &[crate::dtos::AdvancedFlowFilterContainsLayerRowDto]| -> Result<_, String> {
            let layer_cstrings = rows
                .iter()
                .map(|row| CString::new(row.layer_stable_id.as_str()).map_err(|_| "Contains Layer stable ID contains an embedded NUL byte.".to_string()))
                .collect::<Result<Vec<_>, _>>()?;
            let mode_cstrings = rows
                .iter()
                .map(|row| CString::new(row.identifier_mode_id.as_str()).map_err(|_| "Contains Layer mode ID contains an embedded NUL byte.".to_string()))
                .collect::<Result<Vec<_>, _>>()?;
            let exact_value_cstrings = rows
                .iter()
                .map(|row| CString::new(row.exact_value_text.as_str()).map_err(|_| "Contains Layer exact value contains an embedded NUL byte.".to_string()))
                .collect::<Result<Vec<_>, _>>()?;
            let layer_ptrs = layer_cstrings.iter().map(|value| value.as_ptr()).collect::<Vec<_>>();
            let mode_ptrs = mode_cstrings.iter().map(|value| value.as_ptr()).collect::<Vec<_>>();
            let exact_value_ptrs = exact_value_cstrings.iter().map(|value| value.as_ptr()).collect::<Vec<_>>();
            Ok((layer_cstrings, mode_cstrings, exact_value_cstrings, layer_ptrs, mode_ptrs, exact_value_ptrs))
        };

        let (address_family_include_cstrings, address_family_include_ptrs) =
            collect_strings(&document.address_family.include, "Address-family include ID")?;
        let (address_family_exclude_cstrings, address_family_exclude_ptrs) =
            collect_strings(&document.address_family.exclude, "Address-family exclude ID")?;
        let (flow_protocol_include_cstrings, flow_protocol_include_ptrs) =
            collect_strings(&document.flow_protocol.include, "Flow-protocol include ID")?;
        let (flow_protocol_exclude_cstrings, flow_protocol_exclude_ptrs) =
            collect_strings(&document.flow_protocol.exclude, "Flow-protocol exclude ID")?;
        let (detected_protocol_include_cstrings, detected_protocol_include_ptrs) =
            collect_strings(&document.detected_protocol.include, "Detected-protocol include ID")?;
        let (detected_protocol_exclude_cstrings, detected_protocol_exclude_ptrs) =
            collect_strings(&document.detected_protocol.exclude, "Detected-protocol exclude ID")?;
        let (tls_version_include_cstrings, tls_version_include_ptrs) =
            collect_strings(&document.tls_version.include, "TLS-version include ID")?;
        let (tls_version_exclude_cstrings, tls_version_exclude_ptrs) =
            collect_strings(&document.tls_version.exclude, "TLS-version exclude ID")?;
        let (quic_version_include_cstrings, quic_version_include_ptrs) =
            collect_strings(&document.quic_version.include, "QUIC-version include ID")?;
        let (quic_version_exclude_cstrings, quic_version_exclude_ptrs) =
            collect_strings(&document.quic_version.exclude, "QUIC-version exclude ID")?;
        let (directionality_include_cstrings, directionality_include_ptrs) =
            collect_strings(&document.directionality.include, "Directionality include ID")?;
        let (directionality_exclude_cstrings, directionality_exclude_ptrs) =
            collect_strings(&document.directionality.exclude, "Directionality exclude ID")?;

        let filter_text_ptr = filter_text.as_ptr();

        let (ports_include_scope_cstrings, ports_include_primary_cstrings, ports_include_secondary_cstrings,
            ports_include_scope_ptrs, ports_include_primary_ptrs, ports_include_secondary_ptrs, ports_include_range_flags) =
            collect_port_rows(&document.ports.include)?;
        let (ports_exclude_scope_cstrings, ports_exclude_primary_cstrings, ports_exclude_secondary_cstrings,
            ports_exclude_scope_ptrs, ports_exclude_primary_ptrs, ports_exclude_secondary_ptrs, ports_exclude_range_flags) =
            collect_port_rows(&document.ports.exclude)?;
        let (ip_include_scope_cstrings, ip_include_address_cstrings, ip_include_prefix_cstrings,
            ip_include_scope_ptrs, ip_include_address_ptrs, ip_include_prefix_ptrs, ip_include_subnet_flags) =
            collect_ip_rows(&document.ip_addresses.include)?;
        let (ip_exclude_scope_cstrings, ip_exclude_address_cstrings, ip_exclude_prefix_cstrings,
            ip_exclude_scope_ptrs, ip_exclude_address_ptrs, ip_exclude_prefix_ptrs, ip_exclude_subnet_flags) =
            collect_ip_rows(&document.ip_addresses.exclude)?;
        let (traffic_primary_metric_cstrings, traffic_primary_unit_cstrings, traffic_primary_min_cstrings, traffic_primary_max_cstrings,
            traffic_primary_metric_ptrs, traffic_primary_unit_ptrs, traffic_primary_min_ptrs, traffic_primary_max_ptrs) =
            collect_traffic_rows(&document.traffic.primary)?;
        let (traffic_additional_metric_cstrings, traffic_additional_unit_cstrings, traffic_additional_min_cstrings, traffic_additional_max_cstrings,
            traffic_additional_metric_ptrs, traffic_additional_unit_ptrs, traffic_additional_min_ptrs, traffic_additional_max_ptrs) =
            collect_traffic_rows(&document.traffic.additional)?;
        let (service_include_operator_cstrings, service_include_text_cstrings,
            service_include_operator_ptrs, service_include_text_ptrs, service_include_case_sensitive_flags) =
            collect_service_rows(&document.service.include_text)?;
        let (service_exclude_operator_cstrings, service_exclude_text_cstrings,
            service_exclude_operator_ptrs, service_exclude_text_ptrs, service_exclude_case_sensitive_flags) =
            collect_service_rows(&document.service.exclude_text)?;
        let (protocol_path_include_selector_mode_cstrings, protocol_path_include_predicate_text_cstrings,
            protocol_path_include_selector_mode_ptrs, protocol_path_include_predicate_text_ptrs) =
            collect_protocol_path_rows(&document.protocol_path.include)?;
        let (protocol_path_exclude_selector_mode_cstrings, protocol_path_exclude_predicate_text_cstrings,
            protocol_path_exclude_selector_mode_ptrs, protocol_path_exclude_predicate_text_ptrs) =
            collect_protocol_path_rows(&document.protocol_path.exclude)?;
        let (contains_layer_include_layer_cstrings, contains_layer_include_mode_cstrings, contains_layer_include_value_cstrings,
            contains_layer_include_layer_ptrs, contains_layer_include_mode_ptrs, contains_layer_include_value_ptrs) =
            collect_contains_layer_rows(&document.contains_layer.include)?;
        let (contains_layer_exclude_layer_cstrings, contains_layer_exclude_mode_cstrings, contains_layer_exclude_value_cstrings,
            contains_layer_exclude_layer_ptrs, contains_layer_exclude_mode_ptrs, contains_layer_exclude_value_ptrs) =
            collect_contains_layer_rows(&document.contains_layer.exclude)?;

        // Keep all CString owners alive while the synchronous C ABI call borrows their buffers.
        let keep_alive = (
            filter_text,
            address_family_include_cstrings,
            address_family_exclude_cstrings,
            flow_protocol_include_cstrings,
            flow_protocol_exclude_cstrings,
            detected_protocol_include_cstrings,
            detected_protocol_exclude_cstrings,
            tls_version_include_cstrings,
            tls_version_exclude_cstrings,
            quic_version_include_cstrings,
            quic_version_exclude_cstrings,
            directionality_include_cstrings,
            directionality_exclude_cstrings,
            ports_include_scope_cstrings,
            ports_include_primary_cstrings,
            ports_include_secondary_cstrings,
            ports_exclude_scope_cstrings,
            ports_exclude_primary_cstrings,
            ports_exclude_secondary_cstrings,
            ip_include_scope_cstrings,
            ip_include_address_cstrings,
            ip_include_prefix_cstrings,
            ip_exclude_scope_cstrings,
            ip_exclude_address_cstrings,
            ip_exclude_prefix_cstrings,
            traffic_primary_metric_cstrings,
            traffic_primary_unit_cstrings,
            traffic_primary_min_cstrings,
            traffic_primary_max_cstrings,
            traffic_additional_metric_cstrings,
            traffic_additional_unit_cstrings,
            traffic_additional_min_cstrings,
            traffic_additional_max_cstrings,
            service_include_operator_cstrings,
            service_include_text_cstrings,
            service_exclude_operator_cstrings,
            service_exclude_text_cstrings,
            protocol_path_include_selector_mode_cstrings,
            protocol_path_include_predicate_text_cstrings,
            protocol_path_exclude_selector_mode_cstrings,
            protocol_path_exclude_predicate_text_cstrings,
            contains_layer_include_layer_cstrings,
            contains_layer_include_mode_cstrings,
            contains_layer_include_value_cstrings,
            contains_layer_exclude_layer_cstrings,
            contains_layer_exclude_mode_cstrings,
            contains_layer_exclude_value_cstrings,
        );

        let json = unsafe {
            pfl_frontend_session_adapter_apply_advanced_flow_filter_structured_document_json(
                self.handle,
                filter_text_ptr,
                if document.address_family.enabled { 1 } else { 0 },
                address_family_include_ptrs.as_ptr(),
                address_family_include_ptrs.len(),
                address_family_exclude_ptrs.as_ptr(),
                address_family_exclude_ptrs.len(),
                if document.flow_protocol.enabled { 1 } else { 0 },
                flow_protocol_include_ptrs.as_ptr(),
                flow_protocol_include_ptrs.len(),
                flow_protocol_exclude_ptrs.as_ptr(),
                flow_protocol_exclude_ptrs.len(),
                if document.detected_protocol.enabled { 1 } else { 0 },
                detected_protocol_include_ptrs.as_ptr(),
                detected_protocol_include_ptrs.len(),
                detected_protocol_exclude_ptrs.as_ptr(),
                detected_protocol_exclude_ptrs.len(),
                if document.tls_version.enabled { 1 } else { 0 },
                tls_version_include_ptrs.as_ptr(),
                tls_version_include_ptrs.len(),
                tls_version_exclude_ptrs.as_ptr(),
                tls_version_exclude_ptrs.len(),
                if document.quic_version.enabled { 1 } else { 0 },
                quic_version_include_ptrs.as_ptr(),
                quic_version_include_ptrs.len(),
                quic_version_exclude_ptrs.as_ptr(),
                quic_version_exclude_ptrs.len(),
                if document.directionality.enabled { 1 } else { 0 },
                directionality_include_ptrs.as_ptr(),
                directionality_include_ptrs.len(),
                directionality_exclude_ptrs.as_ptr(),
                directionality_exclude_ptrs.len(),
                if document.ports.enabled { 1 } else { 0 },
                ports_include_scope_ptrs.as_ptr(),
                ports_include_range_flags.as_ptr(),
                ports_include_primary_ptrs.as_ptr(),
                ports_include_secondary_ptrs.as_ptr(),
                ports_include_scope_ptrs.len(),
                ports_exclude_scope_ptrs.as_ptr(),
                ports_exclude_range_flags.as_ptr(),
                ports_exclude_primary_ptrs.as_ptr(),
                ports_exclude_secondary_ptrs.as_ptr(),
                ports_exclude_scope_ptrs.len(),
                if document.ip_addresses.enabled { 1 } else { 0 },
                ip_include_scope_ptrs.as_ptr(),
                ip_include_subnet_flags.as_ptr(),
                ip_include_address_ptrs.as_ptr(),
                ip_include_prefix_ptrs.as_ptr(),
                ip_include_scope_ptrs.len(),
                ip_exclude_scope_ptrs.as_ptr(),
                ip_exclude_subnet_flags.as_ptr(),
                ip_exclude_address_ptrs.as_ptr(),
                ip_exclude_prefix_ptrs.as_ptr(),
                ip_exclude_scope_ptrs.len(),
                if document.traffic.enabled { 1 } else { 0 },
                traffic_primary_metric_ptrs.as_ptr(),
                traffic_primary_unit_ptrs.as_ptr(),
                traffic_primary_min_ptrs.as_ptr(),
                traffic_primary_max_ptrs.as_ptr(),
                traffic_primary_metric_ptrs.len(),
                traffic_additional_metric_ptrs.as_ptr(),
                traffic_additional_unit_ptrs.as_ptr(),
                traffic_additional_min_ptrs.as_ptr(),
                traffic_additional_max_ptrs.as_ptr(),
                traffic_additional_metric_ptrs.len(),
                if document.service.enabled { 1 } else { 0 },
                if document.service.include_recognized { 1 } else { 0 },
                if document.service.include_unrecognized { 1 } else { 0 },
                service_include_operator_ptrs.as_ptr(),
                service_include_case_sensitive_flags.as_ptr(),
                service_include_text_ptrs.as_ptr(),
                service_include_operator_ptrs.len(),
                if document.service.exclude_recognized { 1 } else { 0 },
                if document.service.exclude_unrecognized { 1 } else { 0 },
                service_exclude_operator_ptrs.as_ptr(),
                service_exclude_case_sensitive_flags.as_ptr(),
                service_exclude_text_ptrs.as_ptr(),
                service_exclude_operator_ptrs.len(),
                if document.protocol_path.enabled { 1 } else { 0 },
                protocol_path_include_selector_mode_ptrs.as_ptr(),
                protocol_path_include_predicate_text_ptrs.as_ptr(),
                protocol_path_include_selector_mode_ptrs.len(),
                protocol_path_exclude_selector_mode_ptrs.as_ptr(),
                protocol_path_exclude_predicate_text_ptrs.as_ptr(),
                protocol_path_exclude_selector_mode_ptrs.len(),
                if document.contains_layer.enabled { 1 } else { 0 },
                contains_layer_include_layer_ptrs.as_ptr(),
                contains_layer_include_mode_ptrs.as_ptr(),
                contains_layer_include_value_ptrs.as_ptr(),
                contains_layer_include_layer_ptrs.len(),
                contains_layer_exclude_layer_ptrs.as_ptr(),
                contains_layer_exclude_mode_ptrs.as_ptr(),
                contains_layer_exclude_value_ptrs.as_ptr(),
                contains_layer_exclude_layer_ptrs.len(),
            )
        };
        drop(keep_alive);
        parse_json_owned::<AdvancedFlowFilterStructuredDocumentResultDto>(json)
    }

    pub fn apply_advanced_flow_filter_document_text(
        &mut self,
        filter_text: &str,
    ) -> Result<AdvancedFlowFilterDocumentWorkflowStateDto, String> {
        let filter_text = CString::new(filter_text)
            .map_err(|_| "Advanced filter text contains an embedded NUL byte.".to_string())?;
        let json = unsafe {
            pfl_frontend_session_adapter_apply_advanced_flow_filter_document_text_json(
                self.handle,
                filter_text.as_ptr(),
            )
        };
        parse_json_owned::<AdvancedFlowFilterDocumentWorkflowStateDto>(json)
    }

    pub fn accept_opened_advanced_flow_filter_document_text(
        &mut self,
        filter_text: &str,
        source_path: &str,
    ) -> Result<AdvancedFlowFilterDocumentWorkflowStateDto, String> {
        let filter_text = CString::new(filter_text)
            .map_err(|_| "Advanced filter text contains an embedded NUL byte.".to_string())?;
        let source_path = CString::new(source_path)
            .map_err(|_| "Advanced filter source path contains an embedded NUL byte.".to_string())?;
        let json = unsafe {
            pfl_frontend_session_adapter_accept_opened_advanced_flow_filter_document_text_json(
                self.handle,
                filter_text.as_ptr(),
                source_path.as_ptr(),
            )
        };
        parse_json_owned::<AdvancedFlowFilterDocumentWorkflowStateDto>(json)
    }

    pub fn accept_saved_advanced_flow_filter_document_text(
        &mut self,
        filter_text: &str,
        source_path: &str,
    ) -> Result<AdvancedFlowFilterDocumentWorkflowStateDto, String> {
        let filter_text = CString::new(filter_text)
            .map_err(|_| "Advanced filter text contains an embedded NUL byte.".to_string())?;
        let source_path = CString::new(source_path)
            .map_err(|_| "Advanced filter source path contains an embedded NUL byte.".to_string())?;
        let json = unsafe {
            pfl_frontend_session_adapter_accept_saved_advanced_flow_filter_document_text_json(
                self.handle,
                filter_text.as_ptr(),
                source_path.as_ptr(),
            )
        };
        parse_json_owned::<AdvancedFlowFilterDocumentWorkflowStateDto>(json)
    }

    pub fn clear_advanced_flow_filter_unsaved_changes(
        &mut self,
    ) -> Result<AdvancedFlowFilterDocumentWorkflowStateDto, String> {
        let json = unsafe {
            pfl_frontend_session_adapter_clear_advanced_flow_filter_unsaved_changes_json(
                self.handle,
            )
        };
        parse_json_owned::<AdvancedFlowFilterDocumentWorkflowStateDto>(json)
    }

    pub fn clear_advanced_flow_filter_document(
        &mut self,
    ) -> Result<AdvancedFlowFilterDocumentWorkflowStateDto, String> {
        let json = unsafe {
            pfl_frontend_session_adapter_clear_advanced_flow_filter_document_json(self.handle)
        };
        parse_json_owned::<AdvancedFlowFilterDocumentWorkflowStateDto>(json)
    }

    pub fn advanced_flow_filter_max_file_bytes() -> usize {
        unsafe { pfl_frontend_advanced_flow_filter_max_file_bytes() }
    }

    pub fn update_settings(
        &mut self,
        http_use_path_as_service_hint: bool,
        use_possible_tls_quic: bool,
        ignore_vlan_and_mpls_layers_when_grouping_flows: bool,
        ignore_gtpu_teids_when_grouping_inner_flows: bool,
        show_wireshark_filter_for_selected_flow: bool,
        validate_selected_packet_checksums: bool,
    ) -> Result<SettingsDto, String> {
        let json = unsafe {
            pfl_frontend_session_adapter_update_settings_json(
                self.handle,
                if http_use_path_as_service_hint { 1 } else { 0 },
                if use_possible_tls_quic { 1 } else { 0 },
                if ignore_vlan_and_mpls_layers_when_grouping_flows { 1 } else { 0 },
                if ignore_gtpu_teids_when_grouping_inner_flows { 1 } else { 0 },
                if show_wireshark_filter_for_selected_flow { 1 } else { 0 },
                if validate_selected_packet_checksums { 1 } else { 0 },
            )
        };
        parse_json_owned::<SettingsDto>(json)
    }

    pub fn export_current_flow(&self, path: &str) -> Result<ExportCurrentFlowResultDto, String> {
        let path = CString::new(path).map_err(|_| "Export path contains an embedded NUL byte.".to_string())?;
        let json = unsafe { pfl_frontend_session_adapter_export_current_flow_json(self.handle, path.as_ptr()) };
        parse_json_owned::<ExportCurrentFlowResultDto>(json)
    }

    pub fn export_selected_flows(
        &self,
        path: &str,
        flow_indices: &[usize],
    ) -> Result<ExportSelectedFlowsResultDto, String> {
        let path = CString::new(path).map_err(|_| "Export path contains an embedded NUL byte.".to_string())?;
        let json = unsafe {
            pfl_frontend_session_adapter_export_selected_flows_json(
                self.handle,
                path.as_ptr(),
                flow_indices.as_ptr(),
                flow_indices.len(),
            )
        };
        parse_json_owned::<ExportSelectedFlowsResultDto>(json)
    }

    pub fn export_all_flows_info_csv(
        &self,
        path: &str,
    ) -> Result<ExportAllFlowsInfoCsvResultDto, String> {
        let path = CString::new(path).map_err(|_| "Export path contains an embedded NUL byte.".to_string())?;
        let json = unsafe {
            pfl_frontend_session_adapter_export_all_flows_info_csv_json(self.handle, path.as_ptr())
        };
        parse_json_owned::<ExportAllFlowsInfoCsvResultDto>(json)
    }

    pub fn export_protocol_path_tree(
        &self,
        mode: u8,
        path: &str,
    ) -> Result<ExportProtocolPathTreeResultDto, String> {
        let path = CString::new(path).map_err(|_| "Export path contains an embedded NUL byte.".to_string())?;
        let json = unsafe {
            pfl_frontend_session_adapter_export_protocol_path_tree_json(self.handle, mode, path.as_ptr())
        };
        parse_json_owned::<ExportProtocolPathTreeResultDto>(json)
    }

    pub fn get_byte_export_formats(&self) -> Result<Vec<ByteExportFormatDto>, String> {
        let json = unsafe { pfl_frontend_session_adapter_get_byte_export_formats_json(self.handle) };
        parse_json_owned::<Vec<ByteExportFormatDto>>(json)
    }

    pub fn export_selected_flow_packet_byte_view(
        &self,
        packet_index: u64,
        stable_id: &str,
        format_id: &str,
        path: &str,
        flow_packet_index: u64,
        loaded_packet_window_count: u64,
    ) -> Result<ByteExportResultDto, String> {
        let stable_id = CString::new(stable_id).map_err(|_| "Byte-view id contains an embedded NUL byte.".to_string())?;
        let format_id = CString::new(format_id).map_err(|_| "Format id contains an embedded NUL byte.".to_string())?;
        let path = CString::new(path).map_err(|_| "Export path contains an embedded NUL byte.".to_string())?;
        let json = unsafe {
            pfl_frontend_session_adapter_export_selected_flow_packet_byte_view_json(
                self.handle,
                packet_index,
                stable_id.as_ptr(),
                format_id.as_ptr(),
                path.as_ptr(),
                flow_packet_index,
                loaded_packet_window_count,
            )
        };
        parse_json_owned::<ByteExportResultDto>(json)
    }

    pub fn export_unrecognized_packet_byte_view(
        &self,
        packet_index: u64,
        stable_id: &str,
        format_id: &str,
        path: &str,
    ) -> Result<ByteExportResultDto, String> {
        let stable_id = CString::new(stable_id).map_err(|_| "Byte-view id contains an embedded NUL byte.".to_string())?;
        let format_id = CString::new(format_id).map_err(|_| "Format id contains an embedded NUL byte.".to_string())?;
        let path = CString::new(path).map_err(|_| "Export path contains an embedded NUL byte.".to_string())?;
        let json = unsafe {
            pfl_frontend_session_adapter_export_unrecognized_packet_byte_view_json(
                self.handle,
                packet_index,
                stable_id.as_ptr(),
                format_id.as_ptr(),
                path.as_ptr(),
            )
        };
        parse_json_owned::<ByteExportResultDto>(json)
    }

    pub fn export_selected_flow_stream_item_data(
        &self,
        max_packets_to_scan: usize,
        limit: usize,
        stream_item_index: u64,
        format_id: &str,
        path: &str,
    ) -> Result<ByteExportResultDto, String> {
        let format_id = CString::new(format_id).map_err(|_| "Format id contains an embedded NUL byte.".to_string())?;
        let path = CString::new(path).map_err(|_| "Export path contains an embedded NUL byte.".to_string())?;
        let json = unsafe {
            pfl_frontend_session_adapter_export_selected_flow_stream_item_data_json(
                self.handle,
                max_packets_to_scan,
                limit,
                stream_item_index,
                format_id.as_ptr(),
                path.as_ptr(),
            )
        };
        parse_json_owned::<ByteExportResultDto>(json)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn export_smart_flows(
        &self,
        path: &str,
        flow_indices: &[usize],
        output_mode: u8,
        base_mode: u8,
        first_n_packets: u64,
        first_m_original_bytes: u64,
        include_last_packet: bool,
        include_every_kth_packet_after_base: bool,
        every_kth_packet: u64,
        per_flow_buffer_budget_bytes: usize,
    ) -> Result<SmartExportResultDto, String> {
        let path = CString::new(path).map_err(|_| "Export path contains an embedded NUL byte.".to_string())?;
        let json = unsafe {
            pfl_frontend_session_adapter_export_smart_flows_json(
                self.handle,
                path.as_ptr(),
                flow_indices.as_ptr(),
                flow_indices.len(),
                output_mode,
                base_mode,
                first_n_packets,
                first_m_original_bytes,
                if include_last_packet { 1 } else { 0 },
                if include_every_kth_packet_after_base { 1 } else { 0 },
                every_kth_packet,
                per_flow_buffer_budget_bytes,
            )
        };
        parse_json_owned::<SmartExportResultDto>(json)
    }

    pub fn export_smart_unrecognized_packets(
        &self,
        path: &str,
        base_mode: u8,
        first_n_packets: u64,
        first_m_original_bytes: u64,
        include_last_packet: bool,
        include_every_kth_packet_after_base: bool,
        every_kth_packet: u64,
    ) -> Result<SmartExportResultDto, String> {
        let path = CString::new(path).map_err(|_| "Export path contains an embedded NUL byte.".to_string())?;
        let json = unsafe {
            pfl_frontend_session_adapter_export_smart_unrecognized_packets_json(
                self.handle,
                path.as_ptr(),
                base_mode,
                first_n_packets,
                first_m_original_bytes,
                if include_last_packet { 1 } else { 0 },
                if include_every_kth_packet_after_base { 1 } else { 0 },
                every_kth_packet,
            )
        };
        parse_json_owned::<SmartExportResultDto>(json)
    }

    pub fn get_overview(&self) -> Result<OverviewDto, String> {
        let json = unsafe { pfl_frontend_session_adapter_get_overview_json(self.handle) };
        parse_json_owned::<OverviewDto>(json)
    }

    pub fn get_flows(&self) -> Result<Vec<FlowDto>, String> {
        let json = unsafe { pfl_frontend_session_adapter_get_flows_json(self.handle) };
        parse_json_owned::<Vec<FlowDto>>(json)
    }

    pub fn select_flow(&mut self, flow_index: usize) -> Result<SelectionResultDto, String> {
        let json = unsafe { pfl_frontend_session_adapter_select_flow_json(self.handle, flow_index) };
        parse_json_owned::<SelectionResultDto>(json)
    }

    pub fn get_selected_flow_packets(
        &self,
        offset: usize,
        limit: usize,
    ) -> Result<SelectedFlowPacketsDto, String> {
        let json = unsafe {
            pfl_frontend_session_adapter_get_selected_flow_packets_json(self.handle, offset, limit)
        };
        parse_json_owned::<SelectedFlowPacketsDto>(json)
    }

    pub fn get_unrecognized_packets(
        &self,
        offset: usize,
        limit: usize,
    ) -> Result<UnrecognizedPacketsDto, String> {
        let json = unsafe {
            pfl_frontend_session_adapter_get_unrecognized_packets_json(self.handle, offset, limit)
        };
        parse_json_owned::<UnrecognizedPacketsDto>(json)
    }

    pub fn get_selected_flow_stream(
        &self,
        max_packets_to_scan: usize,
        limit: usize,
    ) -> Result<SelectedFlowStreamDto, String> {
        let json = unsafe {
            pfl_frontend_session_adapter_get_selected_flow_stream_json(self.handle, max_packets_to_scan, limit)
        };
        parse_json_owned::<SelectedFlowStreamDto>(json)
    }

    pub fn get_selected_flow_stream_item_details(
        &self,
        max_packets_to_scan: usize,
        limit: usize,
        stream_item_index: u64,
    ) -> Result<StreamItemDto, String> {
        let json = unsafe {
            pfl_frontend_session_adapter_get_selected_flow_stream_item_details_json(
                self.handle,
                max_packets_to_scan,
                limit,
                stream_item_index,
            )
        };
        parse_json_owned::<StreamItemDto>(json)
    }

    pub fn get_selected_flow_packet_details(
        &self,
        packet_index: u64,
        flow_packet_index: u64,
        loaded_packet_window_count: u64,
    ) -> Result<PacketDetailsDto, String> {
        let json = unsafe {
            pfl_frontend_session_adapter_get_selected_flow_packet_details_json(
                self.handle,
                packet_index,
                flow_packet_index,
                loaded_packet_window_count,
            )
        };
        parse_json_owned::<PacketDetailsDto>(json)
    }

    pub fn get_selected_flow_packet_byte_view_content(
        &self,
        packet_index: u64,
        stable_id: &str,
        flow_packet_index: u64,
        loaded_packet_window_count: u64,
    ) -> Result<PacketByteViewContentDto, String> {
        let stable_id = CString::new(stable_id)
            .map_err(|_| "Stable byte-view id contains an embedded NUL byte.".to_string())?;
        let json = unsafe {
            pfl_frontend_session_adapter_get_selected_flow_packet_byte_view_content_json(
                self.handle,
                packet_index,
                stable_id.as_ptr(),
                flow_packet_index,
                loaded_packet_window_count,
            )
        };
        parse_json_owned::<PacketByteViewContentDto>(json)
    }

    pub fn get_unrecognized_packet_details(
        &self,
        packet_index: u64,
    ) -> Result<PacketDetailsDto, String> {
        let json = unsafe {
            pfl_frontend_session_adapter_get_unrecognized_packet_details_json(self.handle, packet_index)
        };
        parse_json_owned::<PacketDetailsDto>(json)
    }

    pub fn get_unrecognized_packet_byte_view_content(
        &self,
        packet_index: u64,
        stable_id: &str,
    ) -> Result<PacketByteViewContentDto, String> {
        let stable_id = CString::new(stable_id)
            .map_err(|_| "Stable byte-view id contains an embedded NUL byte.".to_string())?;
        let json = unsafe {
            pfl_frontend_session_adapter_get_unrecognized_packet_byte_view_content_json(
                self.handle,
                packet_index,
                stable_id.as_ptr(),
            )
        };
        parse_json_owned::<PacketByteViewContentDto>(json)
    }

    pub fn get_selected_flow_analysis(&self) -> Result<SelectedFlowAnalysisDto, String> {
        let json = unsafe { pfl_frontend_session_adapter_get_selected_flow_analysis_json(self.handle) };
        parse_json_owned::<SelectedFlowAnalysisDto>(json)
    }

    pub fn export_selected_flow_analysis_sequence_csv(
        &self,
        path: &str,
    ) -> Result<AnalysisSequenceExportResultDto, String> {
        let path = CString::new(path).map_err(|_| "Export path contains an embedded NUL byte.".to_string())?;
        let json = unsafe {
            pfl_frontend_session_adapter_export_selected_flow_analysis_sequence_csv_json(
                self.handle,
                path.as_ptr(),
            )
        };
        parse_json_owned::<AnalysisSequenceExportResultDto>(json)
    }
}

impl Drop for CppFrontendSessionAdapter {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe {
                pfl_frontend_session_adapter_free(self.handle);
            }
            self.handle = std::ptr::null_mut();
        }
    }
}

fn parse_json_owned<T>(json_ptr: *mut c_char) -> Result<T, String>
where
    T: serde::de::DeserializeOwned,
{
    let owned_json = OwnedBridgeJson::new(json_ptr)?;
    let json = owned_json
        .as_c_str()
        .to_str()
        .map_err(|err| err.to_string())?;

    serde_json::from_str::<T>(json).map_err(|err| err.to_string())
}
