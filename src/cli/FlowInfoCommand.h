#pragma once

#include <cstddef>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <string_view>

#include "cli/CliCommandSupport.h"

namespace pfl::cli {

struct FlowInfoCommandOptions {
    std::filesystem::path input_path {};
    std::optional<std::filesystem::path> settings_path {};
    std::size_t flow_index {0};
    CliProgressMode progress_mode {CliProgressMode::auto_mode};
};

struct FlowInfoCommandParseResult {
    bool ok {false};
    std::optional<FlowInfoCommandOptions> options {};
    std::string error_text {};
};

struct FlowInfoCommandExecutionResult {
    int exit_code {1};
    std::string stdout_text {};
    std::string stderr_text {};
};

[[nodiscard]] std::string render_flow_info_command_help();
[[nodiscard]] FlowInfoCommandParseResult parse_flow_info_command_arguments(std::span<const std::string_view> args);
[[nodiscard]] FlowInfoCommandExecutionResult execute_flow_info_command(const FlowInfoCommandOptions& options);

}  // namespace pfl::cli
