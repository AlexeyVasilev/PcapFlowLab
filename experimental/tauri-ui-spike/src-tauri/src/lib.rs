mod dtos;
mod ffi;

use std::path::PathBuf;
use std::sync::Mutex;

use dtos::{
    AnalysisSequenceExportResultDto, AttachSourceCaptureResultDto, FlowDto, OpenCaptureResultDto, OverviewDto, PacketDetailsDto, SelectedFlowAnalysisDto,
    SelectedFlowPacketsDto, SelectedFlowStreamDto, SelectionResultDto,
};
use ffi::{CppFrontendSessionAdapter, OpenMode};
use tauri::{AppHandle, State};
use tauri_plugin_dialog::DialogExt;

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
fn pick_open_path(app: AppHandle) -> Result<Option<String>, String> {
    let selected_path = app
        .dialog()
        .file()
        .add_filter("All supported captures and indexes", &["pcap", "pcapng", "idx", "pflidx"])
        .add_filter("PCAP files", &["pcap"])
        .add_filter("PCAPNG files", &["pcapng"])
        .add_filter("Index files", &["idx", "pflidx"])
        .blocking_pick_file();

    Ok(selected_path.map(|path| {
        let display_fallback = path.to_string();
        path.into_path()
            .map(|resolved| resolved.to_string_lossy().into_owned())
            .unwrap_or(display_fallback)
    }))
}

#[tauri::command]
fn pick_source_capture_path(app: AppHandle) -> Result<Option<String>, String> {
    let selected_path = app
        .dialog()
        .file()
        .add_filter("Supported capture files", &["pcap", "pcapng"])
        .add_filter("PCAP files", &["pcap"])
        .add_filter("PCAPNG files", &["pcapng"])
        .blocking_pick_file();

    Ok(selected_path.map(|path| {
        let display_fallback = path.to_string();
        path.into_path()
            .map(|resolved| resolved.to_string_lossy().into_owned())
            .unwrap_or(display_fallback)
    }))
}

#[tauri::command]
fn pick_save_analysis_sequence_csv_path(app: AppHandle) -> Result<Option<String>, String> {
    let selected_path = app
        .dialog()
        .file()
        .add_filter("CSV files", &["csv"])
        .set_file_name("flow-sequence.csv")
        .blocking_save_file();

    Ok(selected_path.map(|path| {
        let display_fallback = path.to_string();
        path.into_path()
            .map(|resolved| ensure_csv_extension(resolved).to_string_lossy().into_owned())
            .unwrap_or(display_fallback)
    }))
}

fn ensure_csv_extension(path: PathBuf) -> PathBuf {
    if path.extension().is_some() {
        return path;
    }

    path.with_extension("csv")
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

#[tauri::command(rename_all = "snake_case")]
fn get_selected_flow_stream(
    state: State<'_, Mutex<AdapterState>>,
    max_packets_to_scan: usize,
    limit: usize,
) -> Result<SelectedFlowStreamDto, String> {
    let state = state
        .lock()
        .map_err(|_| "Failed to lock adapter state.".to_string())?;
    state.adapter.get_selected_flow_stream(max_packets_to_scan, limit)
}

#[tauri::command(rename_all = "snake_case")]
fn get_selected_flow_packet_details(
    state: State<'_, Mutex<AdapterState>>,
    packet_index: u64,
) -> Result<PacketDetailsDto, String> {
    let state = state
        .lock()
        .map_err(|_| "Failed to lock adapter state.".to_string())?;
    state.adapter.get_selected_flow_packet_details(packet_index)
}

#[tauri::command(rename_all = "snake_case")]
fn get_selected_flow_analysis(
    state: State<'_, Mutex<AdapterState>>,
) -> Result<SelectedFlowAnalysisDto, String> {
    let state = state
        .lock()
        .map_err(|_| "Failed to lock adapter state.".to_string())?;
    state.adapter.get_selected_flow_analysis()
}

#[tauri::command(rename_all = "snake_case")]
fn attach_source_capture(
    state: State<'_, Mutex<AdapterState>>,
    path: String,
) -> Result<AttachSourceCaptureResultDto, String> {
    let mut state = state
        .lock()
        .map_err(|_| "Failed to lock adapter state.".to_string())?;
    state.adapter.attach_source_capture(&path)
}

#[tauri::command(rename_all = "snake_case")]
fn export_selected_flow_analysis_sequence_csv(
    state: State<'_, Mutex<AdapterState>>,
    path: String,
) -> Result<AnalysisSequenceExportResultDto, String> {
    let state = state
        .lock()
        .map_err(|_| "Failed to lock adapter state.".to_string())?;
    state.adapter.export_selected_flow_analysis_sequence_csv(&path)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let adapter = CppFrontendSessionAdapter::new()
        .expect("failed to create FrontendSessionAdapter bridge");

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(Mutex::new(AdapterState { adapter }))
        .invoke_handler(tauri::generate_handler![
            pick_open_path,
            pick_source_capture_path,
            pick_save_analysis_sequence_csv_path,
            open_capture,
            attach_source_capture,
            get_overview,
            get_flows,
            select_flow,
            get_selected_flow_packets,
            get_selected_flow_stream,
            get_selected_flow_packet_details,
            get_selected_flow_analysis,
            export_selected_flow_analysis_sequence_csv
        ])
        .run(tauri::generate_context!())
        .expect("error while running Tauri UI spike");
}
