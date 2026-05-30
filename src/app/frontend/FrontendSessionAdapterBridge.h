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
char* pfl_frontend_session_adapter_attach_source_capture_json(
    PflFrontendSessionAdapterHandle* handle,
    const char* path_utf8
);
char* pfl_frontend_session_adapter_save_index_json(
    PflFrontendSessionAdapterHandle* handle,
    const char* path_utf8
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

char* pfl_frontend_session_adapter_get_overview_json(PflFrontendSessionAdapterHandle* handle);
char* pfl_frontend_session_adapter_get_flows_json(PflFrontendSessionAdapterHandle* handle);
char* pfl_frontend_session_adapter_select_flow_json(PflFrontendSessionAdapterHandle* handle, std::size_t flow_index);
char* pfl_frontend_session_adapter_get_selected_flow_packets_json(
    PflFrontendSessionAdapterHandle* handle,
    std::size_t offset,
    std::size_t limit
);
char* pfl_frontend_session_adapter_get_selected_flow_stream_json(
    PflFrontendSessionAdapterHandle* handle,
    std::size_t max_packets_to_scan,
    std::size_t limit
);
char* pfl_frontend_session_adapter_get_selected_flow_packet_details_json(
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
