#pragma once

#include <cstddef>
#include <chrono>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "app/session/CaptureSession.h"
#include "cli/CliCommandSupport.h"

namespace pfl::cli {

struct ExportFlowsCommandOptions {
    std::filesystem::path input_path {};
    std::optional<std::filesystem::path> settings_path {};
    std::optional<std::filesystem::path> source_capture_path {};
    bool unrecognized_packets {false};
    std::optional<std::size_t> packet_limit {};
    bool all_flows {false};
    std::optional<std::vector<std::size_t>> selected_flow_indices {};
    std::string text_filter {};
    std::optional<std::size_t> limit {};
    SmartFlowExportBaseMode base_mode {SmartFlowExportBaseMode::all_packets};
    bool include_last_packet {false};
    bool include_every_kth_packet_after_base {false};
    std::uint64_t first_n_packets {0U};
    std::uint64_t first_m_original_bytes {0U};
    std::uint64_t every_kth_packet {0U};
    std::optional<std::filesystem::path> out_path {};
    std::optional<std::filesystem::path> out_dir_path {};
    std::size_t buffer_memory_bytes {128U * 1024U * 1024U};
    CliProgressMode progress_mode {CliProgressMode::auto_mode};
    bool force {false};
};

struct ExportFlowsCommandParseResult {
    bool ok {false};
    std::optional<ExportFlowsCommandOptions> options {};
    std::string error_text {};
};

struct ExportFlowsCommandExecutionResult {
    int exit_code {1};
    std::string stdout_text {};
    std::string stderr_text {};
};

enum class SmartExportCliProgressPhase {
    none,
    single_file,
    per_flow_preparing,
    per_flow_writing,
};

struct SmartExportCliProgressRenderState {
    SmartExportCliProgressPhase last_phase {SmartExportCliProgressPhase::none};
    std::chrono::steady_clock::time_point last_emit_time {};
    std::string last_emitted_line {};
    bool has_emitted_for_phase {false};
    bool phase_completion_emitted {false};
};

[[nodiscard]] std::string render_export_flows_command_help();
[[nodiscard]] ExportFlowsCommandParseResult parse_export_flows_command_arguments(
    std::span<const std::string_view> args
);
[[nodiscard]] ExportFlowsCommandExecutionResult execute_export_flows_command(
    const ExportFlowsCommandOptions& options
);
[[nodiscard]] std::optional<std::string> render_throttled_smart_single_file_progress_line(
    const SmartSingleFileExportProgress& progress,
    SmartExportCliProgressRenderState& state,
    std::chrono::steady_clock::time_point now
);
[[nodiscard]] std::optional<std::string> render_throttled_smart_per_flow_progress_line(
    const SmartPerFlowExportProgress& progress,
    SmartExportCliProgressRenderState& state,
    std::chrono::steady_clock::time_point now
);

}  // namespace pfl::cli
