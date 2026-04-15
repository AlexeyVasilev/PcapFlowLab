#pragma once

#include <chrono>
#include <filesystem>
#include <string>

#include "core/domain/CaptureSummary.h"
#include "core/open_failure_info.h"
#include "core/services/PerfOpenLogger.h"

struct OpenContext;

namespace pfl::session_detail {

OpenFailureInfo fallback_open_failure(const char* reason);

std::string build_open_failure_message(const OpenContext* ctx, const OpenFailureInfo& fallback_failure);

void log_open_result(
    const PerfOpenLogger& logger,
    PerfOpenOperationType operation_type,
    const std::filesystem::path& input_path,
    bool success,
    std::chrono::steady_clock::time_point started_at,
    const CaptureSummary& summary,
    bool opened_from_index,
    bool has_source_capture
);

}  // namespace pfl::session_detail
