#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    pcap_flow_lab_tauri_spike_lib::run();
}
