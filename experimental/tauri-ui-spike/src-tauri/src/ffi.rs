use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_uchar};

use crate::dtos::{
    AdvancedFlowFilterQueryResultDto, AdvancedFlowFilterStructuredDocumentResultDto, AnalysisSequenceExportResultDto, AttachSourceCaptureResultDto, ByteExportFormatDto, ByteExportResultDto, CapturePacketSizeStatisticsDto, ExportAllFlowsInfoCsvResultDto, ExportCurrentFlowResultDto, ExportProtocolPathTreeResultDto, ExportSelectedFlowsResultDto, FlowDto, FlowPacketCountHistogramDto, OpenCaptureCancelResultDto, OpenCapturePollResultDto, OpenCaptureResultDto, OpenCaptureStartResultDto, OverviewDto, PacketByteViewContentDto, PacketDetailsDto, ProtocolHintStatisticsDto, QuicTlsStatisticsDto, SaveIndexResultDto, SelectedFlowAnalysisDto,
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
