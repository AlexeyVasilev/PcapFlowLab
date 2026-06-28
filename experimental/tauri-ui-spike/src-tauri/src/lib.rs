mod dtos;
mod ffi;

use std::path::PathBuf;
use std::fs::OpenOptions;
use std::io::Write;
#[cfg(target_os = "linux")]
use std::process::Command;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use dtos::{
    AnalysisSequenceExportResultDto, AttachSourceCaptureResultDto, ExportCurrentFlowResultDto, ExportSelectedFlowsResultDto, FlowDto, OpenCaptureCancelResultDto, OpenCapturePollResultDto, OpenCaptureResultDto, OpenCaptureStartResultDto, OverviewDto, PacketDetailsDto, SaveIndexResultDto, SelectedFlowAnalysisDto,
    SelectedFlowPacketsDto, SelectedFlowStreamDto, SelectionResultDto, StreamItemDto, UnrecognizedPacketsDto,
    SettingsDto,
    SmartExportResultDto,
};
use ffi::{CppFrontendSessionAdapter, OpenMode};
use tauri::{AppHandle, State};
#[cfg(not(target_os = "linux"))]
use tauri_plugin_dialog::DialogExt;

const MEMORY_LOG_ENV: &str = "PFL_TAURI_MEMORY_LOG";
const MEMORY_LOG_FILE_NAME: &str = "tauri_memory_log.csv";

struct AdapterState {
    adapter: CppFrontendSessionAdapter,
}

fn memory_diagnostics_enabled_flag() -> bool {
    matches!(std::env::var(MEMORY_LOG_ENV).ok().as_deref(), Some("1"))
}

fn memory_log_path() -> Result<PathBuf, String> {
    let current_dir = std::env::current_dir()
        .map_err(|error| format!("Failed to resolve current directory for memory log: {error}"))?;
    Ok(current_dir.join(MEMORY_LOG_FILE_NAME))
}

fn csv_escape(value: &str) -> String {
    let needs_quotes = value.contains(',')
        || value.contains('"')
        || value.contains('\n')
        || value.contains('\r');
    if !needs_quotes {
        return value.to_string();
    }

    format!("\"{}\"", value.replace('"', "\"\""))
}

#[cfg(target_os = "windows")]
fn current_process_working_set_bytes() -> u64 {
    use std::ffi::c_void;
    use std::mem::size_of;

    #[repr(C)]
    struct ProcessMemoryCounters {
        cb: u32,
        page_fault_count: u32,
        peak_working_set_size: usize,
        working_set_size: usize,
        quota_peak_paged_pool_usage: usize,
        quota_paged_pool_usage: usize,
        quota_peak_non_paged_pool_usage: usize,
        quota_non_paged_pool_usage: usize,
        pagefile_usage: usize,
        peak_pagefile_usage: usize,
    }

    unsafe extern "system" {
        fn GetCurrentProcess() -> *mut c_void;
        fn K32GetProcessMemoryInfo(
            process: *mut c_void,
            counters: *mut ProcessMemoryCounters,
            cb: u32,
        ) -> i32;
    }

    let mut counters = ProcessMemoryCounters {
        cb: size_of::<ProcessMemoryCounters>() as u32,
        page_fault_count: 0,
        peak_working_set_size: 0,
        working_set_size: 0,
        quota_peak_paged_pool_usage: 0,
        quota_paged_pool_usage: 0,
        quota_peak_non_paged_pool_usage: 0,
        quota_non_paged_pool_usage: 0,
        pagefile_usage: 0,
        peak_pagefile_usage: 0,
    };

    let success = unsafe {
        K32GetProcessMemoryInfo(
            GetCurrentProcess(),
            &mut counters,
            size_of::<ProcessMemoryCounters>() as u32,
        )
    };

    if success == 0 {
        0
    } else {
        counters.working_set_size as u64
    }
}

#[cfg(not(target_os = "windows"))]
fn current_process_working_set_bytes() -> u64 {
    0
}

#[tauri::command(rename_all = "snake_case")]
fn memory_diagnostics_enabled() -> bool {
    memory_diagnostics_enabled_flag()
}

#[tauri::command(rename_all = "snake_case")]
#[allow(clippy::too_many_arguments)]
fn memory_diagnostics_log(
    phase: String,
    open_path: String,
    open_path_short: String,
    open_state: String,
    active_tab: String,
    flow_view_tab: String,
    flow_count: usize,
    visible_flow_count: usize,
    total_analysis_flow_count: usize,
    checked_flow_count: usize,
    packet_count: usize,
    stream_item_count: usize,
    analysis_sequence_row_count: usize,
    packet_size_histogram_row_count: usize,
    inter_arrival_histogram_row_count: usize,
    rendered_flow_dom_row_count: usize,
    rendered_packet_dom_row_count: usize,
    rendered_stream_dom_row_count: usize,
    rendered_analysis_flow_dom_row_count: usize,
    rendered_analysis_sequence_dom_row_count: usize,
    rendered_transport_dom_row_count: usize,
    rendered_protocol_hint_dom_row_count: usize,
    rendered_top_endpoints_dom_row_count: usize,
    rendered_top_ports_dom_row_count: usize,
    flow_virtual_window_start: usize,
    flow_virtual_window_end: usize,
    analysis_flow_virtual_window_start: usize,
    analysis_flow_virtual_window_end: usize,
    flow_virtualization_active: bool,
    analysis_flow_virtualization_active: bool,
    packet_request_offset: usize,
    packet_request_limit: usize,
    packet_request_row_count: usize,
    packet_request_total_count: usize,
    overview_loaded: bool,
    packet_details_loaded: bool,
    analysis_loaded: bool,
    selected_flow_index: isize,
    selected_packet_index: i64,
) -> Result<(), String> {
    if !memory_diagnostics_enabled_flag() {
        return Ok(());
    }

    let log_path = memory_log_path()?;
    let file_exists = log_path.exists();
    let file_was_empty = !file_exists || std::fs::metadata(&log_path)
        .map(|metadata| metadata.len() == 0)
        .unwrap_or(true);

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .map_err(|error| format!("Failed to open memory log '{}': {error}", log_path.display()))?;

    if file_was_empty {
        writeln!(
            file,
            "timestamp_unix_ms,phase,open_path,open_path_short,open_state,active_tab,flow_view_tab,flow_count,visible_flow_count,total_analysis_flow_count,checked_flow_count,packet_count,stream_item_count,analysis_sequence_row_count,packet_size_histogram_row_count,inter_arrival_histogram_row_count,rendered_flow_dom_row_count,rendered_packet_dom_row_count,rendered_stream_dom_row_count,rendered_analysis_flow_dom_row_count,rendered_analysis_sequence_dom_row_count,rendered_transport_dom_row_count,rendered_protocol_hint_dom_row_count,rendered_top_endpoints_dom_row_count,rendered_top_ports_dom_row_count,flow_virtual_window_start,flow_virtual_window_end,analysis_flow_virtual_window_start,analysis_flow_virtual_window_end,flow_virtualization_active,analysis_flow_virtualization_active,packet_request_offset,packet_request_limit,packet_request_row_count,packet_request_total_count,overview_loaded,packet_details_loaded,analysis_loaded,selected_flow_index,selected_packet_index,process_working_set_bytes"
        )
        .map_err(|error| format!("Failed to write memory log header: {error}"))?;
    }

    let timestamp_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0);
    let process_working_set_bytes = current_process_working_set_bytes();

    writeln!(
        file,
        "{timestamp_unix_ms},{phase},{open_path},{open_path_short},{open_state},{active_tab},{flow_view_tab},{flow_count},{visible_flow_count},{total_analysis_flow_count},{checked_flow_count},{packet_count},{stream_item_count},{analysis_sequence_row_count},{packet_size_histogram_row_count},{inter_arrival_histogram_row_count},{rendered_flow_dom_row_count},{rendered_packet_dom_row_count},{rendered_stream_dom_row_count},{rendered_analysis_flow_dom_row_count},{rendered_analysis_sequence_dom_row_count},{rendered_transport_dom_row_count},{rendered_protocol_hint_dom_row_count},{rendered_top_endpoints_dom_row_count},{rendered_top_ports_dom_row_count},{flow_virtual_window_start},{flow_virtual_window_end},{analysis_flow_virtual_window_start},{analysis_flow_virtual_window_end},{flow_virtualization_active},{analysis_flow_virtualization_active},{packet_request_offset},{packet_request_limit},{packet_request_row_count},{packet_request_total_count},{overview_loaded},{packet_details_loaded},{analysis_loaded},{selected_flow_index},{selected_packet_index},{process_working_set_bytes}",
        phase = csv_escape(&phase),
        open_path = csv_escape(&open_path),
        open_path_short = csv_escape(&open_path_short),
        open_state = csv_escape(&open_state),
        active_tab = csv_escape(&active_tab),
        flow_view_tab = csv_escape(&flow_view_tab),
    )
    .map_err(|error| format!("Failed to append memory log row: {error}"))?;

    Ok(())
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

#[tauri::command(rename_all = "snake_case")]
fn start_open_capture(
    state: State<'_, Mutex<AdapterState>>,
    path: String,
    open_mode: String,
) -> Result<OpenCaptureStartResultDto, String> {
    let mut state = state
        .lock()
        .map_err(|_| "Failed to lock adapter state.".to_string())?;
    let mode = match open_mode.as_str() {
        "deep" => OpenMode::Deep,
        _ => OpenMode::Fast,
    };

    state.adapter.start_open_capture(&path, mode)
}

#[tauri::command(rename_all = "snake_case")]
fn poll_open_capture(
    state: State<'_, Mutex<AdapterState>>,
) -> Result<OpenCapturePollResultDto, String> {
    let mut state = state
        .lock()
        .map_err(|_| "Failed to lock adapter state.".to_string())?;
    state.adapter.poll_open_capture()
}

#[tauri::command(rename_all = "snake_case")]
fn cancel_open_capture(
    state: State<'_, Mutex<AdapterState>>,
) -> Result<OpenCaptureCancelResultDto, String> {
    let mut state = state
        .lock()
        .map_err(|_| "Failed to lock adapter state.".to_string())?;
    state.adapter.cancel_open_capture()
}

#[tauri::command]
fn pick_open_path(_app: AppHandle) -> Result<Option<String>, String> {
    #[cfg(target_os = "linux")]
    {
        return run_zenity_file_dialog(&[
            "--file-selection".to_string(),
            "--title=Open Capture or Index".to_string(),
            "--file-filter=All supported captures and indexes | *.pcap *.pcapng *.idx *.pflidx".to_string(),
            "--file-filter=PCAP files | *.pcap".to_string(),
            "--file-filter=PCAPNG files | *.pcapng".to_string(),
            "--file-filter=Index files | *.idx *.pflidx".to_string(),
        ]);
    }

    #[cfg(not(target_os = "linux"))]
    {
        let selected_path = _app
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
}

#[tauri::command]
fn pick_open_capture_path(_app: AppHandle) -> Result<Option<String>, String> {
    #[cfg(target_os = "linux")]
    {
        return run_zenity_file_dialog(&[
            "--file-selection".to_string(),
            "--title=Open Capture".to_string(),
            "--file-filter=Capture files | *.pcap *.pcapng".to_string(),
            "--file-filter=PCAP files | *.pcap".to_string(),
            "--file-filter=PCAPNG files | *.pcapng".to_string(),
        ]);
    }

    #[cfg(not(target_os = "linux"))]
    {
        let selected_path = _app
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
}

#[tauri::command]
fn pick_open_index_path(_app: AppHandle) -> Result<Option<String>, String> {
    #[cfg(target_os = "linux")]
    {
        return run_zenity_file_dialog(&[
            "--file-selection".to_string(),
            "--title=Open Index".to_string(),
            "--file-filter=Index files | *.idx *.pflidx".to_string(),
        ]);
    }

    #[cfg(not(target_os = "linux"))]
    {
        let selected_path = _app
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
}

#[tauri::command]
fn pick_source_capture_path(_app: AppHandle) -> Result<Option<String>, String> {
    #[cfg(target_os = "linux")]
    {
        return run_zenity_file_dialog(&[
            "--file-selection".to_string(),
            "--title=Locate Source Capture".to_string(),
            "--file-filter=Supported capture files | *.pcap *.pcapng".to_string(),
            "--file-filter=PCAP files | *.pcap".to_string(),
            "--file-filter=PCAPNG files | *.pcapng".to_string(),
        ]);
    }

    #[cfg(not(target_os = "linux"))]
    {
        let selected_path = _app
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
}

#[tauri::command]
fn pick_save_index_path(_app: AppHandle) -> Result<Option<String>, String> {
    #[cfg(target_os = "linux")]
    {
        return Ok(run_zenity_file_dialog(&[
            "--file-selection".to_string(),
            "--save".to_string(),
            "--confirm-overwrite".to_string(),
            "--title=Save Index".to_string(),
            format!("--filename={}", current_dir_prefill("analysis.idx")),
            "--file-filter=Index files | *.idx".to_string(),
        ])?.map(|path| ensure_extension(PathBuf::from(path), "idx").to_string_lossy().into_owned()));
    }

    #[cfg(not(target_os = "linux"))]
    {
        let selected_path = _app
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
}

#[tauri::command]
fn pick_save_flow_export_path(_app: AppHandle) -> Result<Option<String>, String> {
    #[cfg(target_os = "linux")]
    {
        return Ok(run_zenity_file_dialog(&[
            "--file-selection".to_string(),
            "--save".to_string(),
            "--confirm-overwrite".to_string(),
            "--title=Export Flow".to_string(),
            format!("--filename={}", current_dir_prefill("flow-export.pcap")),
            "--file-filter=PCAP files | *.pcap".to_string(),
        ])?.map(|path| ensure_extension(PathBuf::from(path), "pcap").to_string_lossy().into_owned()));
    }

    #[cfg(not(target_os = "linux"))]
    {
        let selected_path = _app
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
}

#[tauri::command]
fn pick_smart_export_destination_folder(_app: AppHandle) -> Result<Option<String>, String> {
    #[cfg(target_os = "linux")]
    {
        return run_zenity_file_dialog(&[
            "--file-selection".to_string(),
            "--directory".to_string(),
            "--title=Select Destination Folder".to_string(),
        ]);
    }

    #[cfg(not(target_os = "linux"))]
    {
        let selected_path = _app.dialog().file().blocking_pick_folder();

        Ok(selected_path.map(|path| {
            let display_fallback = path.to_string();
            path.into_path()
                .map(|resolved| resolved.to_string_lossy().into_owned())
                .unwrap_or(display_fallback)
        }))
    }
}

#[tauri::command]
fn pick_save_analysis_sequence_csv_path(_app: AppHandle) -> Result<Option<String>, String> {
    #[cfg(target_os = "linux")]
    {
        return Ok(run_zenity_file_dialog(&[
            "--file-selection".to_string(),
            "--save".to_string(),
            "--confirm-overwrite".to_string(),
            "--title=Export Sequence CSV".to_string(),
            format!("--filename={}", current_dir_prefill("flow-sequence.csv")),
            "--file-filter=CSV files | *.csv".to_string(),
        ])?.map(|path| ensure_extension(PathBuf::from(path), "csv").to_string_lossy().into_owned()));
    }

    #[cfg(not(target_os = "linux"))]
    {
        let selected_path = _app
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
}

fn ensure_extension(path: PathBuf, extension: &str) -> PathBuf {
    if path.extension().is_some() {
        return path;
    }

    path.with_extension(extension)
}

#[cfg(target_os = "linux")]
fn trim_dialog_output(output: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(output).trim().to_string();
    if text.is_empty() {
        None
    } else {
        Some(text)
    }
}

#[cfg(target_os = "linux")]
fn run_zenity_file_dialog(args: &[String]) -> Result<Option<String>, String> {
    let output = Command::new("zenity")
        .args(args)
        .output()
        .map_err(|error| format!("Failed to launch zenity: {error}"))?;

    match output.status.code() {
        Some(0) => Ok(trim_dialog_output(&output.stdout)),
        Some(1) => Ok(None),
        Some(code) => {
            let stderr_text = String::from_utf8_lossy(&output.stderr).trim().to_string();
            if stderr_text.is_empty() {
                Err(format!("Zenity exited with status code {code}."))
            } else {
                Err(format!("Zenity exited with status code {code}: {stderr_text}"))
            }
        }
        None => Err("Zenity was terminated before it returned a result.".to_string()),
    }
}

#[cfg(target_os = "linux")]
fn current_dir_prefill(file_name: &str) -> String {
    let base_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    base_dir.join(file_name).to_string_lossy().into_owned()
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
fn get_unrecognized_packets(
    state: State<'_, Mutex<AdapterState>>,
    offset: usize,
    limit: usize,
) -> Result<UnrecognizedPacketsDto, String> {
    let state = state
        .lock()
        .map_err(|_| "Failed to lock adapter state.".to_string())?;
    state.adapter.get_unrecognized_packets(offset, limit)
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
fn get_selected_flow_stream_item_details(
    state: State<'_, Mutex<AdapterState>>,
    max_packets_to_scan: usize,
    limit: usize,
    stream_item_index: u64,
) -> Result<StreamItemDto, String> {
    let state = state
        .lock()
        .map_err(|_| "Failed to lock adapter state.".to_string())?;
    state
        .adapter
        .get_selected_flow_stream_item_details(max_packets_to_scan, limit, stream_item_index)
}

#[tauri::command(rename_all = "snake_case")]
fn get_selected_flow_packet_details(
    state: State<'_, Mutex<AdapterState>>,
    packet_index: u64,
    flow_packet_index: u64,
) -> Result<PacketDetailsDto, String> {
    let state = state
        .lock()
        .map_err(|_| "Failed to lock adapter state.".to_string())?;
    state.adapter.get_selected_flow_packet_details(packet_index, flow_packet_index)
}

#[tauri::command(rename_all = "snake_case")]
fn get_unrecognized_packet_details(
    state: State<'_, Mutex<AdapterState>>,
    packet_index: u64,
) -> Result<PacketDetailsDto, String> {
    let state = state
        .lock()
        .map_err(|_| "Failed to lock adapter state.".to_string())?;
    state.adapter.get_unrecognized_packet_details(packet_index)
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
            memory_diagnostics_enabled,
            memory_diagnostics_log,
            pick_open_path,
            pick_open_capture_path,
            pick_open_index_path,
            pick_source_capture_path,
            pick_save_index_path,
            pick_save_flow_export_path,
            pick_smart_export_destination_folder,
            pick_save_analysis_sequence_csv_path,
            open_capture,
            start_open_capture,
            poll_open_capture,
            cancel_open_capture,
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
            get_unrecognized_packets,
            get_selected_flow_stream,
            get_selected_flow_stream_item_details,
            get_selected_flow_packet_details,
            get_unrecognized_packet_details,
            get_selected_flow_analysis,
            export_selected_flow_analysis_sequence_csv
        ])
        .run(tauri::generate_context!())
        .expect("error while running Tauri UI spike");
}
