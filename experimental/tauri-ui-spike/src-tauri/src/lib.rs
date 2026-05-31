mod dtos;
mod ffi;

use std::path::PathBuf;
use std::sync::Mutex;

use dtos::{
    AnalysisSequenceExportResultDto, AttachSourceCaptureResultDto, ExportCurrentFlowResultDto, ExportSelectedFlowsResultDto, FlowDto, OpenCaptureResultDto, OverviewDto, PacketDetailsDto, SaveIndexResultDto, SelectedFlowAnalysisDto,
    SelectedFlowPacketsDto, SelectedFlowStreamDto, SelectionResultDto,
    SettingsDto,
    SmartExportResultDto,
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
fn pick_open_capture_path(app: AppHandle) -> Result<Option<String>, String> {
    let selected_path = app
        .dialog()
        .file()
        .add_filter("Capture files", &["pcap", "pcapng"])
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
fn pick_open_index_path(app: AppHandle) -> Result<Option<String>, String> {
    let selected_path = app
        .dialog()
        .file()
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
fn pick_save_index_path(app: AppHandle) -> Result<Option<String>, String> {
    let selected_path = app
        .dialog()
        .file()
        .add_filter("Index files", &["idx"])
        .set_file_name("analysis.idx")
        .blocking_save_file();

    Ok(selected_path.map(|path| {
        let display_fallback = path.to_string();
        path.into_path()
            .map(|resolved| ensure_extension(resolved, "idx").to_string_lossy().into_owned())
            .unwrap_or(display_fallback)
    }))
}

#[tauri::command]
fn pick_save_flow_export_path(app: AppHandle) -> Result<Option<String>, String> {
    let selected_path = app
        .dialog()
        .file()
        .add_filter("PCAP files", &["pcap"])
        .set_file_name("flow-export.pcap")
        .blocking_save_file();

    Ok(selected_path.map(|path| {
        let display_fallback = path.to_string();
        path.into_path()
            .map(|resolved| ensure_extension(resolved, "pcap").to_string_lossy().into_owned())
            .unwrap_or(display_fallback)
    }))
}

#[tauri::command]
fn pick_smart_export_destination_folder(app: AppHandle) -> Result<Option<String>, String> {
    let selected_path = app.dialog().file().blocking_pick_folder();

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
            .map(|resolved| ensure_extension(resolved, "csv").to_string_lossy().into_owned())
            .unwrap_or(display_fallback)
    }))
}

fn ensure_extension(path: PathBuf, extension: &str) -> PathBuf {
    if path.extension().is_some() {
        return path;
    }

    path.with_extension(extension)
}

#[tauri::command]
fn get_overview(state: State<'_, Mutex<AdapterState>>) -> Result<OverviewDto, String> {
    let state = state
        .lock()
        .map_err(|_| "Failed to lock adapter state.".to_string())?;
    state.adapter.get_overview()
}

#[tauri::command]
fn get_settings(state: State<'_, Mutex<AdapterState>>) -> Result<SettingsDto, String> {
    let state = state
        .lock()
        .map_err(|_| "Failed to lock adapter state.".to_string())?;
    state.adapter.get_settings()
}

#[tauri::command(rename_all = "snake_case")]
fn update_settings(
    state: State<'_, Mutex<AdapterState>>,
    http_use_path_as_service_hint: bool,
    use_possible_tls_quic: bool,
    show_wireshark_filter_for_selected_flow: bool,
    validate_selected_packet_checksums: bool,
) -> Result<SettingsDto, String> {
    let mut state = state
        .lock()
        .map_err(|_| "Failed to lock adapter state.".to_string())?;
    state.adapter.update_settings(
        http_use_path_as_service_hint,
        use_possible_tls_quic,
        show_wireshark_filter_for_selected_flow,
        validate_selected_packet_checksums,
    )
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
fn save_index(
    state: State<'_, Mutex<AdapterState>>,
    path: String,
) -> Result<SaveIndexResultDto, String> {
    let state = state
        .lock()
        .map_err(|_| "Failed to lock adapter state.".to_string())?;
    state.adapter.save_index(&path)
}

#[tauri::command(rename_all = "snake_case")]
fn export_current_flow(
    state: State<'_, Mutex<AdapterState>>,
    path: String,
) -> Result<ExportCurrentFlowResultDto, String> {
    let state = state
        .lock()
        .map_err(|_| "Failed to lock adapter state.".to_string())?;
    state.adapter.export_current_flow(&path)
}

#[tauri::command(rename_all = "snake_case")]
fn export_selected_flows(
    state: State<'_, Mutex<AdapterState>>,
    path: String,
    flow_indices: Vec<usize>,
) -> Result<ExportSelectedFlowsResultDto, String> {
    let state = state
        .lock()
        .map_err(|_| "Failed to lock adapter state.".to_string())?;
    state.adapter.export_selected_flows(&path, &flow_indices)
}

#[tauri::command(rename_all = "snake_case")]
#[allow(clippy::too_many_arguments)]
fn export_smart_flows(
    state: State<'_, Mutex<AdapterState>>,
    path: String,
    flow_indices: Vec<usize>,
    output_mode: u8,
    base_mode: u8,
    first_n_packets: u64,
    first_m_original_bytes: u64,
    include_last_packet: bool,
    include_every_kth_packet_after_base: bool,
    every_kth_packet: u64,
    per_flow_buffer_budget_bytes: usize,
) -> Result<SmartExportResultDto, String> {
    let state = state
        .lock()
        .map_err(|_| "Failed to lock adapter state.".to_string())?;
    state.adapter.export_smart_flows(
        &path,
        &flow_indices,
        output_mode,
        base_mode,
        first_n_packets,
        first_m_original_bytes,
        include_last_packet,
        include_every_kth_packet_after_base,
        every_kth_packet,
        per_flow_buffer_budget_bytes,
    )
}

#[tauri::command(rename_all = "snake_case")]
fn exit_app(app: AppHandle) -> Result<(), String> {
    app.exit(0);
    Ok(())
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
            pick_open_capture_path,
            pick_open_index_path,
            pick_source_capture_path,
            pick_save_index_path,
            pick_save_flow_export_path,
            pick_smart_export_destination_folder,
            pick_save_analysis_sequence_csv_path,
            open_capture,
            attach_source_capture,
            save_index,
            export_current_flow,
            export_selected_flows,
            export_smart_flows,
            exit_app,
            get_overview,
            get_settings,
            update_settings,
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
