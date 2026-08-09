#pragma once

#include <cstddef>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "app/session/SessionFlowHelpers.h"
#include "cli/CliCommandSupport.h"

namespace pfl::cli {

struct FlowsCommandOptions {
    std::filesystem::path input_path {};
    std::optional<std::filesystem::path> settings_path {};
    std::optional<std::vector<std::size_t>> selected_flow_indices {};
    std::string text_filter {};
    std::optional<session_detail::FlowQuerySortSpec> sort {};
    std::optional<std::size_t> limit {};
    std::optional<std::filesystem::path> out_flows_list_path {};
    CliProgressMode progress_mode {CliProgressMode::auto_mode};
    bool force {false};
};

struct FlowsCommandParseResult {
    bool ok {false};
    std::optional<FlowsCommandOptions> options {};
    std::string error_text {};
};

struct FlowsCommandExecutionResult {
    int exit_code {1};
    std::string stdout_text {};
    std::string stderr_text {};
};

[[nodiscard]] std::string render_flows_command_help();
[[nodiscard]] FlowsCommandParseResult parse_flows_command_arguments(std::span<const std::string_view> args);
[[nodiscard]] FlowsCommandExecutionResult execute_flows_command(
    const FlowsCommandOptions& options,
    const CliRuntimeEnvironment& environment
);
[[nodiscard]] FlowsCommandExecutionResult execute_flows_command(const FlowsCommandOptions& options);

}  // namespace pfl::cli
