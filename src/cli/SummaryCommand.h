#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "app/frontend/FrontendDtos.h"
#include "app/session/FlowRows.h"

namespace pfl::cli {

enum class SummaryDispatchKind : std::uint8_t {
    summary,
    legacy,
};

enum class SummaryCommandProgressMode : std::uint8_t {
    auto_mode,
    on,
    off,
};

struct SummaryDispatchDecision {
    SummaryDispatchKind kind {SummaryDispatchKind::summary};
    std::string_view legacy_command {};
    std::vector<std::string_view> summary_args {};
};

struct SummaryCommandOptions {
    std::filesystem::path input_path {};
    std::optional<std::filesystem::path> settings_path {};
    bool extended {false};
    bool protocol_path_tree {false};
    ProtocolPathStatisticsMode protocol_path_mode {ProtocolPathStatisticsMode::kind_overview};
    std::optional<std::filesystem::path> out_index_path {};
    std::optional<std::filesystem::path> out_protocol_path_tree_path {};
    SummaryCommandProgressMode progress_mode {SummaryCommandProgressMode::auto_mode};
    bool force {false};
};

struct SummaryCommandParseResult {
    bool ok {false};
    std::optional<SummaryCommandOptions> options {};
    std::string error_text {};
};

struct SummaryCommandExecutionResult {
    int exit_code {1};
    std::string stdout_text {};
    std::string stderr_text {};
};

struct CliInvocationResult {
    bool handled {false};
    int exit_code {1};
    std::string stdout_text {};
    std::string stderr_text {};
};

[[nodiscard]] bool is_legacy_cli_command_name(std::string_view name) noexcept;
[[nodiscard]] SummaryDispatchDecision classify_cli_invocation(std::span<const std::string_view> args);
[[nodiscard]] SummaryCommandParseResult parse_summary_command_arguments(std::span<const std::string_view> args);
[[nodiscard]] SummaryCommandExecutionResult execute_summary_command(const SummaryCommandOptions& options);
[[nodiscard]] std::string render_global_cli_help();
[[nodiscard]] std::string render_summary_command_help();
[[nodiscard]] CliInvocationResult process_cli_invocation(std::span<const std::string_view> args);
[[nodiscard]] bool should_enable_summary_progress(
    SummaryCommandProgressMode mode,
    bool stderr_is_terminal
) noexcept;
[[nodiscard]] std::string render_protocol_path_preview_text(
    std::span<const FrontendProtocolPathStatsDto> rows,
    ProtocolPathStatisticsMode mode,
    std::size_t max_rows = 25U
);

}  // namespace pfl::cli
