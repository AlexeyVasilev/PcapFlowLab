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

std::string render_open_progress_text_impl(const FrontendOpenProgressDto& progress) {
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

std::string render_interactive_progress_update_impl(
    const std::string_view current_line,
    const std::size_t previous_visible_length
) {
    std::string update {};
    if (previous_visible_length > 0U) {
        update.reserve(previous_visible_length + current_line.size() + 2U);
        update += '\r';
        update.append(previous_visible_length, ' ');
        update += '\r';
    } else {
        update.reserve(current_line.size() + 1U);
        update += '\r';
    }
    update += current_line;
    return update;
}

void emit_progress_text(
    const CliProgressSink& sink,
    const std::string_view text
) {
    if (!sink || text.empty()) {
        return;
    }

    sink(text);
}

}  // namespace

std::string render_open_progress_text(const FrontendOpenProgressDto& progress) {
    return render_open_progress_text_impl(progress);
}

std::string render_interactive_progress_update(
    const std::string_view current_line,
    const std::size_t previous_visible_length
) {
    return render_interactive_progress_update_impl(current_line, previous_visible_length);
}

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

std::optional<std::vector<CliFlowNumberRange>> parse_cli_flow_numbers(const std::string_view value) noexcept {
    if (value.empty()) {
        return std::nullopt;
    }

    std::vector<CliFlowNumberRange> ranges {};
    std::size_t start = 0U;
    while (start < value.size()) {
        const auto comma = value.find(',', start);
        const auto token = value.substr(start, comma == std::string_view::npos ? value.size() - start : comma - start);
        if (token.empty()) {
            return std::nullopt;
        }

        const auto dash = token.find('-');
        if (dash == std::string_view::npos) {
            const auto flow_number = parse_cli_positive_size(token);
            if (!flow_number.has_value()) {
                return std::nullopt;
            }
            ranges.push_back(CliFlowNumberRange {
                .first = *flow_number,
                .last = *flow_number,
            });
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

            ranges.push_back(CliFlowNumberRange {
                .first = *lower,
                .last = *upper,
            });
        }

        if (comma == std::string_view::npos) {
            break;
        }
        start = comma + 1U;
    }

    return ranges;
}

CliFlowNumberResolutionResult resolve_cli_flow_numbers(
    const std::span<const CliFlowNumberRange> ranges,
    const std::size_t flow_count
) {
    CliFlowNumberResolutionResult result {
        .ok = false,
        .flow_indices = {},
        .invalid_flow_index = std::nullopt,
    };

    std::vector<std::size_t> flow_indices {};
    for (const auto& range : ranges) {
        if (range.first == 0U || range.last == 0U || range.last < range.first) {
            result.invalid_flow_index = 0U;
            return result;
        }

        if (range.first > flow_count) {
            result.invalid_flow_index = range.first - 1U;
            return result;
        }

        if (range.last > flow_count) {
            result.invalid_flow_index = flow_count;
            return result;
        }

        for (std::size_t flow_number = range.first; flow_number <= range.last; ++flow_number) {
            flow_indices.push_back(flow_number - 1U);
            if (flow_number == std::numeric_limits<std::size_t>::max()) {
                break;
            }
        }
    }

    std::sort(flow_indices.begin(), flow_indices.end());
    flow_indices.erase(std::unique(flow_indices.begin(), flow_indices.end()), flow_indices.end());
    result.ok = true;
    result.flow_indices = std::move(flow_indices);
    return result;
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

FrontendOpenProgressDto normalize_successful_open_progress(
    const FrontendOpenProgressDto& progress,
    const FrontendOpenResult& result
) noexcept {
    if (!result.opened || result.partial_open || result.cancelled) {
        return progress;
    }

    auto normalized = progress;
    normalized.in_progress = false;
    normalized.percent = 1.0;
    if (normalized.total_bytes > 0U) {
        normalized.bytes_processed = std::max(normalized.bytes_processed, normalized.total_bytes);
    }
    return normalized;
}

CliOutputPreflightResult preflight_output_targets(
    const std::filesystem::path& input_path,
    const std::span<const CliOutputTarget> outputs,
    const bool force,
    const std::span<const std::filesystem::path> protected_input_paths,
    const std::optional<std::string_view> distinct_outputs_error_text
) {
    CliOutputPreflightResult result {
        .ok = true,
    };

    std::vector<std::filesystem::path> normalized_protected_input_paths {};
    normalized_protected_input_paths.reserve(protected_input_paths.size() + 1U);
    normalized_protected_input_paths.push_back(normalized_comparison_path(input_path));
    for (const auto& protected_input_path : protected_input_paths) {
        normalized_protected_input_paths.push_back(normalized_comparison_path(protected_input_path));
    }

    std::vector<std::filesystem::path> normalized_output_paths {};
    normalized_output_paths.reserve(outputs.size());

    for (const auto& output : outputs) {
        const auto normalized_output_path = normalized_comparison_path(output.path);
        normalized_output_paths.push_back(normalized_output_path);

        for (const auto& normalized_input_path : normalized_protected_input_paths) {
            if (!normalized_input_path.empty() && normalized_output_path == normalized_input_path) {
                result.ok = false;
                result.error_text = std::string {output.label} + " cannot overwrite an input or configuration path.";
                return result;
            }
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
    const CliRuntimeEnvironment& environment,
    [[maybe_unused]] std::string& stderr_text
) {
    const bool progress_enabled = should_enable_cli_progress(progress_mode, environment.stderr_is_terminal);
    if (!progress_enabled || !environment.progress_sink) {
        return adapter.open_capture(input_path);
    }

    const auto start_result = adapter.start_open_capture(input_path);
    if (!start_result.started) {
        return FrontendOpenResult {
            .opened = false,
            .error_text = start_result.error_text,
        };
    }

    const bool interactive = environment.stderr_is_terminal;
    const auto update_interval = interactive ? std::chrono::milliseconds {120} : std::chrono::milliseconds {250};
    auto last_update = Clock::time_point {};
    std::string last_line {};
    std::size_t last_visible_length = 0U;
    bool emitted_progress = false;

    while (true) {
        const auto poll = adapter.poll_open_capture();
        if (poll.ready) {
            const auto final_progress = normalize_successful_open_progress(poll.progress, poll.result);
            const bool completed_successfully = poll.result.opened && !poll.result.partial_open && !poll.result.cancelled;
            if (completed_successfully) {
                const auto line = render_open_progress_text(final_progress);
                if (line != last_line) {
                    if (interactive) {
                        emit_progress_text(
                            environment.progress_sink,
                            render_interactive_progress_update(line, last_visible_length)
                        );
                    } else {
                        emit_progress_text(environment.progress_sink, line + '\n');
                    }
                    last_line = line;
                    last_visible_length = line.size();
                    emitted_progress = true;
                }
            }
            if (interactive && emitted_progress) {
                emit_progress_text(environment.progress_sink, "\n");
            }
            return poll.result;
        }

        const auto now = Clock::now();
        if (last_update.time_since_epoch().count() == 0 || now - last_update >= update_interval) {
            const auto line = render_open_progress_text(poll.progress);
            if (line != last_line) {
                if (interactive) {
                    emit_progress_text(
                        environment.progress_sink,
                        render_interactive_progress_update(line, last_visible_length)
                    );
                } else {
                    emit_progress_text(environment.progress_sink, line + '\n');
                }
                last_line = line;
                last_visible_length = line.size();
                emitted_progress = true;
            }
            last_update = now;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds {50});
    }
}

}  // namespace pfl::cli
