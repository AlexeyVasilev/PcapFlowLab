#pragma once

#include <cstddef>
#include <cstdint>

struct PflFrontendSessionAdapterHandle;

extern "C" {

PflFrontendSessionAdapterHandle* pfl_frontend_session_adapter_new();
void pfl_frontend_session_adapter_free(PflFrontendSessionAdapterHandle* handle);

char* pfl_frontend_session_adapter_open_capture_json(
    PflFrontendSessionAdapterHandle* handle,
    const char* path_utf8,
    std::uint8_t open_mode
);
char* pfl_frontend_session_adapter_start_open_capture_json(
    PflFrontendSessionAdapterHandle* handle,
    const char* path_utf8,
    std::uint8_t open_mode
);
char* pfl_frontend_session_adapter_poll_open_capture_json(PflFrontendSessionAdapterHandle* handle);
char* pfl_frontend_session_adapter_cancel_open_capture_json(PflFrontendSessionAdapterHandle* handle);
char* pfl_frontend_session_adapter_attach_source_capture_json(
    PflFrontendSessionAdapterHandle* handle,
    const char* path_utf8
);
char* pfl_frontend_session_adapter_save_index_json(
    PflFrontendSessionAdapterHandle* handle,
    const char* path_utf8
);
char* pfl_frontend_session_adapter_get_settings_json(PflFrontendSessionAdapterHandle* handle);
char* pfl_frontend_session_adapter_get_protocol_path_legend_json(PflFrontendSessionAdapterHandle* handle);
char* pfl_frontend_session_adapter_update_settings_json(
    PflFrontendSessionAdapterHandle* handle,
    std::uint8_t http_use_path_as_service_hint,
    std::uint8_t use_possible_tls_quic,
    std::uint8_t show_wireshark_filter_for_selected_flow,
    std::uint8_t validate_selected_packet_checksums
);
char* pfl_frontend_session_adapter_export_current_flow_json(
    PflFrontendSessionAdapterHandle* handle,
    const char* path_utf8
);
char* pfl_frontend_session_adapter_export_selected_flows_json(
    PflFrontendSessionAdapterHandle* handle,
    const char* path_utf8,
    const std::size_t* flow_indices,
    std::size_t flow_index_count
);
char* pfl_frontend_session_adapter_export_smart_flows_json(
    PflFrontendSessionAdapterHandle* handle,
    const char* path_utf8,
    const std::size_t* flow_indices,
    std::size_t flow_index_count,
    std::uint8_t output_mode,
    std::uint8_t base_mode,
    std::uint64_t first_n_packets,
    std::uint64_t first_m_original_bytes,
    std::uint8_t include_last_packet,
    std::uint8_t include_every_kth_packet_after_base,
    std::uint64_t every_kth_packet,
    std::size_t per_flow_buffer_budget_bytes
);

char* pfl_frontend_session_adapter_get_overview_json(PflFrontendSessionAdapterHandle* handle);
char* pfl_frontend_session_adapter_get_flows_json(PflFrontendSessionAdapterHandle* handle);
char* pfl_frontend_session_adapter_select_flow_json(PflFrontendSessionAdapterHandle* handle, std::size_t flow_index);
char* pfl_frontend_session_adapter_get_selected_flow_packets_json(
    PflFrontendSessionAdapterHandle* handle,
    std::size_t offset,
    std::size_t limit
);
char* pfl_frontend_session_adapter_get_unrecognized_packets_json(
    PflFrontendSessionAdapterHandle* handle,
    std::size_t offset,
    std::size_t limit
);
char* pfl_frontend_session_adapter_get_selected_flow_stream_json(
    PflFrontendSessionAdapterHandle* handle,
    std::size_t max_packets_to_scan,
    std::size_t limit
);
char* pfl_frontend_session_adapter_get_selected_flow_stream_item_details_json(
    PflFrontendSessionAdapterHandle* handle,
    std::size_t max_packets_to_scan,
    std::size_t limit,
    std::uint64_t stream_item_index
);
char* pfl_frontend_session_adapter_get_selected_flow_packet_details_json(
    PflFrontendSessionAdapterHandle* handle,
    std::uint64_t packet_index,
    std::uint64_t flow_packet_index
);
char* pfl_frontend_session_adapter_get_unrecognized_packet_details_json(
    PflFrontendSessionAdapterHandle* handle,
    std::uint64_t packet_index
);
char* pfl_frontend_session_adapter_get_selected_flow_analysis_json(PflFrontendSessionAdapterHandle* handle);
char* pfl_frontend_session_adapter_export_selected_flow_analysis_sequence_csv_json(
    PflFrontendSessionAdapterHandle* handle,
    const char* path_utf8
);

void pfl_frontend_string_free(char* value);

}
