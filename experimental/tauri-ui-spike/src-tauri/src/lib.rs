mod dtos;
mod ffi;

use std::sync::Mutex;

use dtos::{
    FlowDto, OpenCaptureResultDto, OverviewDto, SelectedFlowPacketsDto, SelectionResultDto,
};
use ffi::{CppFrontendSessionAdapter, OpenMode};
use tauri::State;

struct AdapterState {
    adapter: CppFrontendSessionAdapter,
}

#[tauri::command(rename_all = "snake_case")]
fn open_capture(
    state: State<'_, Mutex<AdapterState>>,
    path: String,
    open_mode: String,
) -> Result<OpenCaptureResultDto, String> {
    let mut state = state
        .lock()
        .map_err(|_| "Failed to lock adapter state.".to_string())?;
    let mode = match open_mode.as_str() {
        "deep" => OpenMode::Deep,
        _ => OpenMode::Fast,
    };

    state.adapter.open_capture(&path, mode)
}

#[tauri::command]
fn get_overview(state: State<'_, Mutex<AdapterState>>) -> Result<OverviewDto, String> {
    let state = state
        .lock()
        .map_err(|_| "Failed to lock adapter state.".to_string())?;
    state.adapter.get_overview()
}

#[tauri::command]
fn get_flows(state: State<'_, Mutex<AdapterState>>) -> Result<Vec<FlowDto>, String> {
    let state = state
        .lock()
        .map_err(|_| "Failed to lock adapter state.".to_string())?;
    state.adapter.get_flows()
}

#[tauri::command(rename_all = "snake_case")]
fn select_flow(
    state: State<'_, Mutex<AdapterState>>,
    flow_index: usize,
) -> Result<SelectionResultDto, String> {
    let mut state = state
        .lock()
        .map_err(|_| "Failed to lock adapter state.".to_string())?;
    state.adapter.select_flow(flow_index)
}

#[tauri::command(rename_all = "snake_case")]
fn get_selected_flow_packets(
    state: State<'_, Mutex<AdapterState>>,
    offset: usize,
    limit: usize,
) -> Result<SelectedFlowPacketsDto, String> {
    let state = state
        .lock()
        .map_err(|_| "Failed to lock adapter state.".to_string())?;
    state.adapter.get_selected_flow_packets(offset, limit)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let adapter = CppFrontendSessionAdapter::new()
        .expect("failed to create FrontendSessionAdapter bridge");

    tauri::Builder::default()
        .manage(Mutex::new(AdapterState { adapter }))
        .invoke_handler(tauri::generate_handler![
            open_capture,
            get_overview,
            get_flows,
            select_flow,
            get_selected_flow_packets
        ])
        .run(tauri::generate_context!())
        .expect("error while running Tauri UI spike");
}
