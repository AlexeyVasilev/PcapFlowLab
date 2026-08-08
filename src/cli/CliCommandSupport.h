#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "app/frontend/FrontendDtos.h"
#include "app/frontend/FrontendSessionAdapter.h"

namespace pfl::cli {

enum class CliProgressMode : std::uint8_t {
    auto_mode = 0,
    on,
    off,
};

struct CliOutputTarget {
    std::string_view label {};
    std::filesystem::path path {};
};

struct CliOutputPreflightResult {
    bool ok {false};
    std::string error_text {};
};

struct CliInvocationResult {
    bool handled {false};
    int exit_code {1};
    std::string stdout_text {};
    std::string stderr_text {};
};

[[nodiscard]] bool contains_option(
    std::span<const std::string_view> options,
    std::string_view candidate
) noexcept;
[[nodiscard]] bool contains_help_option(std::span<const std::string_view> args) noexcept;
[[nodiscard]] std::optional<std::size_t> parse_cli_positive_size(std::string_view value) noexcept;
[[nodiscard]] std::optional<std::size_t> parse_cli_flow_number(std::string_view value) noexcept;
[[nodiscard]] std::optional<std::vector<std::size_t>> parse_cli_flow_numbers(std::string_view value) noexcept;
[[nodiscard]] std::optional<CliProgressMode> parse_cli_progress_mode(std::string_view value) noexcept;
[[nodiscard]] bool stderr_supports_interactive_updates() noexcept;
[[nodiscard]] bool should_enable_cli_progress(
    CliProgressMode mode,
    bool stderr_is_terminal
) noexcept;
[[nodiscard]] CliOutputPreflightResult preflight_output_targets(
    const std::filesystem::path& input_path,
    std::span<const CliOutputTarget> outputs,
    bool force,
    std::optional<std::string_view> distinct_outputs_error_text = std::nullopt
);
[[nodiscard]] FrontendOpenResult open_input_with_progress(
    FrontendSessionAdapter& adapter,
    const std::filesystem::path& input_path,
    CliProgressMode progress_mode,
    bool stderr_is_terminal,
    std::string& stderr_text
);

}  // namespace pfl::cli
