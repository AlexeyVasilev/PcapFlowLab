use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_uchar};

use crate::dtos::{
    AnalysisSequenceExportResultDto, AttachSourceCaptureResultDto, ExportCurrentFlowResultDto, ExportSelectedFlowsResultDto, FlowDto, OpenCaptureResultDto, OverviewDto, PacketDetailsDto, SaveIndexResultDto, SelectedFlowAnalysisDto,
    SelectedFlowPacketsDto, SelectedFlowStreamDto, SelectionResultDto,
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
        open_mode: c_uchar,
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
    fn pfl_frontend_session_adapter_update_settings_json(
        handle: *mut PflFrontendSessionAdapterHandle,
        http_use_path_as_service_hint: c_uchar,
        use_possible_tls_quic: c_uchar,
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
    fn pfl_frontend_session_adapter_get_selected_flow_stream_json(
        handle: *mut PflFrontendSessionAdapterHandle,
        max_packets_to_scan: usize,
        limit: usize,
    ) -> *mut c_char;
    fn pfl_frontend_session_adapter_get_selected_flow_packet_details_json(
        handle: *mut PflFrontendSessionAdapterHandle,
        packet_index: u64,
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

#[repr(u8)]
#[derive(Copy, Clone)]
pub enum OpenMode {
    Fast = 0,
    Deep = 1,
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

    pub fn open_capture(
        &mut self,
        path: &str,
        open_mode: OpenMode,
    ) -> Result<OpenCaptureResultDto, String> {
        let path = CString::new(path).map_err(|_| "Capture path contains an embedded NUL byte.".to_string())?;
        let json = unsafe {
            pfl_frontend_session_adapter_open_capture_json(self.handle, path.as_ptr(), open_mode as c_uchar)
        };
        parse_json_owned::<OpenCaptureResultDto>(json)
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

    pub fn update_settings(
        &mut self,
        http_use_path_as_service_hint: bool,
        use_possible_tls_quic: bool,
        show_wireshark_filter_for_selected_flow: bool,
        validate_selected_packet_checksums: bool,
    ) -> Result<SettingsDto, String> {
        let json = unsafe {
            pfl_frontend_session_adapter_update_settings_json(
                self.handle,
                if http_use_path_as_service_hint { 1 } else { 0 },
                if use_possible_tls_quic { 1 } else { 0 },
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

    pub fn get_selected_flow_packet_details(&self, packet_index: u64) -> Result<PacketDetailsDto, String> {
        let json = unsafe {
            pfl_frontend_session_adapter_get_selected_flow_packet_details_json(self.handle, packet_index)
        };
        parse_json_owned::<PacketDetailsDto>(json)
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
