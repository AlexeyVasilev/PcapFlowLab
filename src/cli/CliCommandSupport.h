#pragma once

#include <compare>
#include <cstdint>
#include <filesystem>
#include <functional>
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

using CliProgressSink = std::function<void(std::string_view)>;

struct CliRuntimeEnvironment {
    bool stderr_is_terminal {false};
    CliProgressSink progress_sink {};
};

struct CliOutputTarget {
    std::string_view label {};
    std::filesystem::path path {};
};

struct CliOutputPreflightResult {
    bool ok {false};
    std::string error_text {};
};

struct CliFlowNumberRange {
    std::size_t first {0U};
    std::size_t last {0U};

    auto operator<=>(const CliFlowNumberRange&) const = default;
};

struct CliFlowNumberResolutionResult {
    bool ok {false};
    std::vector<std::size_t> flow_indices {};
    std::optional<std::size_t> invalid_flow_index {};
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
[[nodiscard]] std::optional<std::vector<CliFlowNumberRange>> parse_cli_flow_numbers(std::string_view value) noexcept;
[[nodiscard]] CliFlowNumberResolutionResult resolve_cli_flow_numbers(
    std::span<const CliFlowNumberRange> ranges,
    std::size_t flow_count
);
[[nodiscard]] std::optional<CliProgressMode> parse_cli_progress_mode(std::string_view value) noexcept;
[[nodiscard]] bool stderr_supports_interactive_updates() noexcept;
[[nodiscard]] bool should_enable_cli_progress(
    CliProgressMode mode,
    bool stderr_is_terminal
) noexcept;
[[nodiscard]] FrontendOpenProgressDto normalize_successful_open_progress(
    const FrontendOpenProgressDto& progress,
    const FrontendOpenResult& result
) noexcept;
[[nodiscard]] std::string render_open_progress_text(const FrontendOpenProgressDto& progress);
[[nodiscard]] std::string render_interactive_progress_update(
    std::string_view current_line,
    std::size_t previous_visible_length
);
[[nodiscard]] CliOutputPreflightResult preflight_output_targets(
    const std::filesystem::path& input_path,
    std::span<const CliOutputTarget> outputs,
    bool force,
    std::span<const std::filesystem::path> protected_input_paths = {},
    std::optional<std::string_view> distinct_outputs_error_text = std::nullopt
);
[[nodiscard]] FrontendOpenResult open_input_with_progress(
    FrontendSessionAdapter& adapter,
    const std::filesystem::path& input_path,
    CliProgressMode progress_mode,
    const CliRuntimeEnvironment& environment,
    std::string& stderr_text
);

}  // namespace pfl::cli
