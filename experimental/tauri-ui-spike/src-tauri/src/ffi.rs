use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_uchar};

use crate::dtos::{
    FlowDto, OpenCaptureResultDto, OverviewDto, PacketDetailsDto, SelectedFlowPacketsDto, SelectedFlowStreamDto,
    SelectionResultDto,
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
    fn pfl_frontend_string_free(value: *mut c_char);
}

pub enum OpenMode {
    Fast = 0,
    Deep = 1,
}

pub struct CppFrontendSessionAdapter {
    handle: *mut PflFrontendSessionAdapterHandle,
}

unsafe impl Send for CppFrontendSessionAdapter {}

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
    if json_ptr.is_null() {
        return Err("Bridge returned no data.".to_string());
    }

    let json = unsafe { CStr::from_ptr(json_ptr) }
        .to_str()
        .map_err(|err| err.to_string())?
        .to_owned();

    unsafe {
        pfl_frontend_string_free(json_ptr);
    }

    serde_json::from_str::<T>(&json).map_err(|err| err.to_string())
}
