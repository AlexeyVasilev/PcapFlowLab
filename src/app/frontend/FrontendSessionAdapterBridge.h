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

char* pfl_frontend_session_adapter_get_overview_json(PflFrontendSessionAdapterHandle* handle);
char* pfl_frontend_session_adapter_get_flows_json(PflFrontendSessionAdapterHandle* handle);
char* pfl_frontend_session_adapter_select_flow_json(PflFrontendSessionAdapterHandle* handle, std::size_t flow_index);
char* pfl_frontend_session_adapter_get_selected_flow_packets_json(
    PflFrontendSessionAdapterHandle* handle,
    std::size_t offset,
    std::size_t limit
);

void pfl_frontend_string_free(char* value);

}
