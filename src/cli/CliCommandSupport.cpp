#include "cli/CliCommandSupport.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <limits>
#include <sstream>
#include <system_error>
#include <thread>
#include <vector>

#include "app/session/SessionFlowHelpers.h"

#if defined(_WIN32)
#include <io.h>
#else
#include <unistd.h>
#endif

namespace pfl::cli {
namespace {

using Clock = std::chrono::steady_clock;

bool all_ascii_digits(const std::string_view text) noexcept {
    return !text.empty() && std::all_of(text.begin(), text.end(), [](const char ch) {
        return ch >= '0' && ch <= '9';
    });
}

std::filesystem::path normalized_comparison_path(const std::filesystem::path& path) {
    if (path.empty()) {
        return {};
    }

    std::error_code error {};
    const auto current_path = std::filesystem::current_path(error);
    error.clear();
    const auto absolute_path = current_path.empty() ? path : (current_path / path);

    if (std::filesystem::exists(absolute_path, error) && !error) {
        error.clear();
        const auto canonical_path = std::filesystem::weakly_canonical(absolute_path, error);
        if (!error) {
            return canonical_path.lexically_normal();
        }
    }

    return absolute_path.lexically_normal();
}

bool is_existing_directory(const std::filesystem::path& path) {
    std::error_code error {};
    return std::filesystem::is_directory(path, error) && !error;
}

std::string render_open_progress_text(const FrontendOpenProgressDto& progress) {
    std::ostringstream out {};
    out << "Opening " << (progress.opening_as_index ? "index" : "capture") << ": ";
    const auto percent = std::clamp(progress.percent * 100.0, 0.0, 100.0);
    out << static_cast<int>(percent + 0.5) << '%';
    if (progress.total_bytes > 0U) {
        out << " ("
            << session_detail::format_statistics_compact_size_value(progress.bytes_processed)
            << " / "
            << session_detail::format_statistics_compact_size_value(progress.total_bytes)
            << ')';
    }
    return out.str();
}

}  // namespace

bool contains_option(
    const std::span<const std::string_view> options,
    const std::string_view candidate
) noexcept {
    return std::find(options.begin(), options.end(), candidate) != options.end();
}

bool contains_help_option(const std::span<const std::string_view> args) noexcept {
    for (const auto arg : args) {
        if (arg == "-h" || arg == "--help") {
            return true;
        }
    }
    return false;
}

std::optional<std::size_t> parse_cli_positive_size(const std::string_view value) noexcept {
    if (!all_ascii_digits(value)) {
        return std::nullopt;
    }

    std::size_t parsed_value = 0U;
    for (const auto ch : value) {
        const auto digit = static_cast<std::size_t>(ch - '0');
        if (parsed_value > (std::numeric_limits<std::size_t>::max() - digit) / 10U) {
            return std::nullopt;
        }
        parsed_value = parsed_value * 10U + digit;
    }

    if (parsed_value == 0U) {
        return std::nullopt;
    }

    return parsed_value;
}

std::optional<std::size_t> parse_cli_flow_number(const std::string_view value) noexcept {
    const auto flow_number = parse_cli_positive_size(value);
    if (!flow_number.has_value()) {
        return std::nullopt;
    }

    return *flow_number - 1U;
}

std::optional<std::vector<std::size_t>> parse_cli_flow_numbers(const std::string_view value) noexcept {
    if (value.empty()) {
        return std::nullopt;
    }

    std::vector<std::size_t> flow_indices {};
    std::size_t start = 0U;
    while (start < value.size()) {
        const auto comma = value.find(',', start);
        const auto token = value.substr(start, comma == std::string_view::npos ? value.size() - start : comma - start);
        if (token.empty()) {
            return std::nullopt;
        }

        const auto dash = token.find('-');
        if (dash == std::string_view::npos) {
            const auto flow_index = parse_cli_flow_number(token);
            if (!flow_index.has_value()) {
                return std::nullopt;
            }
            flow_indices.push_back(*flow_index);
        } else {
            if (token.find('-', dash + 1U) != std::string_view::npos) {
                return std::nullopt;
            }

            const auto lower_text = token.substr(0U, dash);
            const auto upper_text = token.substr(dash + 1U);
            const auto lower = parse_cli_positive_size(lower_text);
            const auto upper = parse_cli_positive_size(upper_text);
            if (!lower.has_value() || !upper.has_value() || *upper < *lower) {
                return std::nullopt;
            }

            for (std::size_t flow_number = *lower; flow_number <= *upper; ++flow_number) {
                flow_indices.push_back(flow_number - 1U);
                if (flow_number == std::numeric_limits<std::size_t>::max()) {
                    break;
                }
            }
        }

        if (comma == std::string_view::npos) {
            break;
        }
        start = comma + 1U;
    }

    std::sort(flow_indices.begin(), flow_indices.end());
    flow_indices.erase(std::unique(flow_indices.begin(), flow_indices.end()), flow_indices.end());
    return flow_indices;
}

std::optional<CliProgressMode> parse_cli_progress_mode(const std::string_view value) noexcept {
    if (value == "auto") {
        return CliProgressMode::auto_mode;
    }
    if (value == "on") {
        return CliProgressMode::on;
    }
    if (value == "off") {
        return CliProgressMode::off;
    }
    return std::nullopt;
}

bool stderr_supports_interactive_updates() noexcept {
#if defined(_WIN32)
    return _isatty(_fileno(stderr)) != 0;
#else
    return isatty(fileno(stderr)) != 0;
#endif
}

bool should_enable_cli_progress(
    const CliProgressMode mode,
    const bool stderr_is_terminal
) noexcept {
    switch (mode) {
    case CliProgressMode::on:
        return true;
    case CliProgressMode::off:
        return false;
    case CliProgressMode::auto_mode:
    default:
        return stderr_is_terminal;
    }
}

CliOutputPreflightResult preflight_output_targets(
    const std::filesystem::path& input_path,
    const std::span<const CliOutputTarget> outputs,
    const bool force,
    const std::optional<std::string_view> distinct_outputs_error_text
) {
    CliOutputPreflightResult result {
        .ok = true,
    };

    const auto normalized_input_path = normalized_comparison_path(input_path);
    std::vector<std::filesystem::path> normalized_output_paths {};
    normalized_output_paths.reserve(outputs.size());

    for (const auto& output : outputs) {
        const auto normalized_output_path = normalized_comparison_path(output.path);
        normalized_output_paths.push_back(normalized_output_path);

        if (!normalized_input_path.empty() && normalized_output_path == normalized_input_path) {
            result.ok = false;
            result.error_text = std::string {output.label} + " cannot overwrite the input path.";
            return result;
        }

        const auto parent_path = output.path.parent_path();
        if (!parent_path.empty()) {
            std::error_code error {};
            const bool parent_exists = std::filesystem::exists(parent_path, error);
            if (error || !parent_exists || !std::filesystem::is_directory(parent_path, error) || error) {
                result.ok = false;
                result.error_text = std::string {output.label} + " parent directory does not exist.";
                return result;
            }
        }

        std::error_code exists_error {};
        const bool output_exists = std::filesystem::exists(output.path, exists_error);
        if (exists_error) {
            result.ok = false;
            result.error_text = std::string {output.label} + " path is not usable.";
            return result;
        }
        if (output_exists && is_existing_directory(output.path)) {
            result.ok = false;
            result.error_text = std::string {output.label} + " must be a regular file path.";
            return result;
        }
        if (output_exists && !force) {
            result.ok = false;
            result.error_text = std::string {output.label} + " already exists. Re-run with --force to overwrite.";
            return result;
        }
    }

    if (distinct_outputs_error_text.has_value()) {
        for (std::size_t left = 0U; left < normalized_output_paths.size(); ++left) {
            for (std::size_t right = left + 1U; right < normalized_output_paths.size(); ++right) {
                if (normalized_output_paths[left] == normalized_output_paths[right]) {
                    result.ok = false;
                    result.error_text = std::string {*distinct_outputs_error_text};
                    return result;
                }
            }
        }
    }

    return result;
}

FrontendOpenResult open_input_with_progress(
    FrontendSessionAdapter& adapter,
    const std::filesystem::path& input_path,
    const CliProgressMode progress_mode,
    const bool stderr_is_terminal,
    std::string& stderr_text
) {
    if (!should_enable_cli_progress(progress_mode, stderr_is_terminal)) {
        return adapter.open_capture(input_path);
    }

    const auto start_result = adapter.start_open_capture(input_path);
    if (!start_result.started) {
        return FrontendOpenResult {
            .opened = false,
            .error_text = start_result.error_text,
        };
    }

    const bool interactive = stderr_is_terminal;
    const auto update_interval = interactive ? std::chrono::milliseconds {120} : std::chrono::milliseconds {250};
    auto last_update = Clock::time_point {};
    std::string last_line {};
    bool emitted_progress = false;

    while (true) {
        const auto poll = adapter.poll_open_capture();
        if (poll.ready) {
            if (interactive && emitted_progress) {
                stderr_text += '\n';
            }
            return poll.result;
        }

        const auto now = Clock::now();
        if (last_update.time_since_epoch().count() == 0 || now - last_update >= update_interval) {
            const auto line = render_open_progress_text(poll.progress);
            if (line != last_line) {
                if (interactive) {
                    stderr_text += '\r';
                    stderr_text += line;
                } else {
                    stderr_text += line;
                    stderr_text += '\n';
                }
                last_line = line;
                emitted_progress = true;
            }
            last_update = now;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds {50});
    }
}

}  // namespace pfl::cli
