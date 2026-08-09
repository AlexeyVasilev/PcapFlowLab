#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <string_view>

#include "cli/CliCommandSupport.h"

namespace pfl::cli {

struct PacketInfoCommandOptions {
    std::filesystem::path input_path {};
    std::optional<std::filesystem::path> settings_path {};
    std::optional<std::filesystem::path> source_capture_path {};
    std::optional<std::size_t> flow_index {};
    std::optional<std::uint64_t> packet_in_flow {};
    std::optional<std::uint64_t> packet_in_file {};
    bool include_bytes {false};
    CliProgressMode progress_mode {CliProgressMode::auto_mode};
};

struct PacketInfoCommandParseResult {
    bool ok {false};
    std::optional<PacketInfoCommandOptions> options {};
    std::string error_text {};
};

struct PacketInfoCommandExecutionResult {
    int exit_code {1};
    std::string stdout_text {};
    std::string stderr_text {};
};

[[nodiscard]] std::string render_packet_info_command_help();
[[nodiscard]] PacketInfoCommandParseResult parse_packet_info_command_arguments(std::span<const std::string_view> args);
[[nodiscard]] PacketInfoCommandExecutionResult execute_packet_info_command(
    const PacketInfoCommandOptions& options,
    const CliRuntimeEnvironment& environment
);
[[nodiscard]] PacketInfoCommandExecutionResult execute_packet_info_command(const PacketInfoCommandOptions& options);

}  // namespace pfl::cli
