#include "cli/ExportFlowsCommand.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <filesystem>
#include <limits>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

#include "app/frontend/FrontendSessionAdapter.h"
#include "app/frontend/FrontendSettingsJson.h"
#include "app/session/SessionFlowHelpers.h"
#include "core/index/CaptureIndex.h"

namespace pfl::cli {
namespace {

constexpr std::size_t kMebibyte = 1024U * 1024U;
constexpr auto kSmartExportProgressThrottleInterval = std::chrono::milliseconds(750);

struct ExportExecutionEnvironment {
    bool stderr_is_terminal {false};
};

struct DirectoryPreflightResult {
    bool ok {false};
    std::string error_text {};
};

std::string render_export_flows_examples() {
    std::ostringstream out {};
    out << "Examples\n";
    out << "  pcap-flow-lab export-flows capture.pcap --flow-number 42 --out flow-42.pcap\n";
    out << "  pcap-flow-lab export-flows capture.pcap --flow-numbers 1-10,24 --out selected.pcap\n";
    out << "  pcap-flow-lab export-flows capture.pcap --filter TLS --first-packets 30 --include-last-packet --out tls-sample.pcap\n";
    out << "  pcap-flow-lab export-flows capture.pcap --unrecognized-packets --out unrecognized.pcap\n";
    out << "  pcap-flow-lab export-flows capture.pcap --unrecognized-packets --packet-limit 1000 --out unrecognized-first-1000.pcap\n";
    out << "  pcap-flow-lab export-flows capture.idx --source-capture original.pcapng --flow-numbers 10-20 --first-packets 50 --out selected.pcap\n";
    return out.str();
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

bool paths_refer_to_same_target(const std::filesystem::path& left, const std::filesystem::path& right) {
    return !left.empty() && !right.empty() && normalized_comparison_path(left) == normalized_comparison_path(right);
}

bool is_non_empty_directory(const std::filesystem::path& path) {
    std::error_code error {};
    if (!std::filesystem::is_directory(path, error) || error) {
        return false;
    }

    const auto iterator = std::filesystem::directory_iterator(path, error);
    if (error) {
        return false;
    }

    return iterator != std::filesystem::directory_iterator {};
}

DirectoryPreflightResult preflight_output_directory(
    const std::filesystem::path& input_path,
    const std::filesystem::path& output_directory,
    const bool force
) {
    DirectoryPreflightResult result {
        .ok = true,
    };

    if (output_directory.empty()) {
        result.ok = false;
        result.error_text = "Exactly one of --out or --out-dir is required.";
        return result;
    }

    const auto normalized_input_path = normalized_comparison_path(input_path);
    const auto normalized_output_path = normalized_comparison_path(output_directory);
    if (!normalized_input_path.empty() && normalized_output_path == normalized_input_path) {
        result.ok = false;
        result.error_text = "--out-dir cannot target the input path.";
        return result;
    }

    const auto parent_path = output_directory.parent_path();
    if (!parent_path.empty()) {
        std::error_code error {};
        const bool parent_exists = std::filesystem::exists(parent_path, error);
        if (error || !parent_exists || !std::filesystem::is_directory(parent_path, error) || error) {
            result.ok = false;
            result.error_text = "--out-dir parent directory does not exist.";
            return result;
        }
    }

    std::error_code exists_error {};
    const bool output_exists = std::filesystem::exists(output_directory, exists_error);
    if (exists_error) {
        result.ok = false;
        result.error_text = "--out-dir path is not usable.";
        return result;
    }

    if (!output_exists) {
        return result;
    }

    std::error_code directory_error {};
    if (!std::filesystem::is_directory(output_directory, directory_error) || directory_error) {
        result.ok = false;
        result.error_text = "--out-dir must be a directory path.";
        return result;
    }

    if (is_non_empty_directory(output_directory) && !force) {
        result.ok = false;
        result.error_text = "--out-dir already exists and is not empty. Re-run with --force to export into it.";
        return result;
    }

    return result;
}

std::string render_smart_single_file_progress_line(const SmartSingleFileExportProgress& progress) {
    std::ostringstream out {};
    out << "Smart export: scanned "
        << session_detail::format_statistics_count_value(progress.packets_processed);
    if (progress.total_packets_to_scan > 0U) {
        out << " / " << session_detail::format_statistics_count_value(progress.total_packets_to_scan);
    }
    out << " packets, wrote "
        << session_detail::format_statistics_count_value(progress.exported_packets_written);
    if (progress.total_selected_packets > 0U) {
        out << " of " << session_detail::format_statistics_count_value(progress.total_selected_packets);
    }
    out << '.';
    return out.str();
}

std::string render_smart_per_flow_progress_line(const SmartPerFlowExportProgress& progress) {
    std::ostringstream out {};
    if (progress.phase == SmartPerFlowExportPhase::preparing) {
        out << "Preparing per-flow export: prepared "
            << session_detail::format_statistics_count_value(progress.packets_processed);
        if (progress.total_packets_to_scan > 0U) {
            out << " / " << session_detail::format_statistics_count_value(progress.total_packets_to_scan);
        }
        out << " flows.";
        return out.str();
    }

    out << "Writing per-flow export: scanned "
        << session_detail::format_statistics_count_value(progress.packets_processed);
    if (progress.total_packets_to_scan > 0U) {
        out << " / " << session_detail::format_statistics_count_value(progress.total_packets_to_scan);
    }
    out << " packets, wrote "
        << session_detail::format_statistics_count_value(progress.exported_packets_written)
        << '.';
    return out.str();
}

bool is_completed_single_file_progress(const SmartSingleFileExportProgress& progress) {
    return progress.total_packets_to_scan > 0U
        && progress.packets_processed >= progress.total_packets_to_scan
        && progress.exported_packets_written >= progress.total_selected_packets;
}

bool is_completed_per_flow_progress(const SmartPerFlowExportProgress& progress) {
    return progress.total_packets_to_scan > 0U
        && progress.packets_processed >= progress.total_packets_to_scan;
}

std::optional<std::string> maybe_emit_throttled_progress_line(
    const SmartExportCliProgressPhase phase,
    const std::string& line,
    const bool completed,
    SmartExportCliProgressRenderState& state,
    const std::chrono::steady_clock::time_point now
) {
    if (line.empty()) {
        return std::nullopt;
    }

    const bool phase_changed = state.last_phase != phase;
    if (phase_changed) {
        state.last_phase = phase;
        state.has_emitted_for_phase = false;
        state.phase_completion_emitted = false;
        state.last_emitted_line.clear();
    }

    if (state.has_emitted_for_phase && line == state.last_emitted_line) {
        if (!completed || state.phase_completion_emitted) {
            return std::nullopt;
        }
    }

    bool should_emit = false;
    if (!state.has_emitted_for_phase) {
        should_emit = true;
    } else if (completed && !state.phase_completion_emitted) {
        should_emit = true;
    } else if (line != state.last_emitted_line
               && (now - state.last_emit_time) >= kSmartExportProgressThrottleInterval) {
        should_emit = true;
    }

    if (!should_emit) {
        return std::nullopt;
    }

    state.has_emitted_for_phase = true;
    state.phase_completion_emitted = completed;
    state.last_emit_time = now;
    state.last_emitted_line = line;
    return line;
}

void append_progress_line(
    std::string& stderr_text,
    const std::optional<std::string>& line
) {
    if (!line.has_value() || line->empty()) {
        return;
    }

    stderr_text += *line;
    stderr_text += '\n';
}

SmartFlowExportRequest build_export_request(const ExportFlowsCommandOptions& options, std::vector<std::size_t> flow_indices) {
    return SmartFlowExportRequest {
        .flow_indices = std::move(flow_indices),
        .base_mode = options.base_mode,
        .first_n_packets = options.first_n_packets,
        .first_m_original_bytes = options.first_m_original_bytes,
        .include_last_packet = options.include_last_packet,
        .include_every_kth_packet_after_base = options.include_every_kth_packet_after_base,
        .every_kth_packet = options.every_kth_packet,
    };
}

FrontendSmartExportOptions build_unrecognized_export_options(const ExportFlowsCommandOptions& options) {
    FrontendSmartExportOptions export_options {};
    export_options.output_mode = FrontendSmartExportOutputMode::single_file;
    if (options.packet_limit.has_value()) {
        export_options.base_mode = FrontendSmartExportBaseMode::first_n_packets;
        export_options.first_n_packets = static_cast<std::uint64_t>(*options.packet_limit);
    } else {
        export_options.base_mode = FrontendSmartExportBaseMode::all_packets;
    }
    return export_options;
}

session_detail::FlowQuery build_flow_query(const ExportFlowsCommandOptions& options) {
    session_detail::FlowQuery query {};
    if (!options.all_flows) {
        query.selected_flow_indices = options.selected_flow_indices;
        query.text_filter = options.text_filter;
    }
    query.limit = options.limit;
    return query;
}

ExportFlowsCommandExecutionResult execute_export_flows_command_with_environment(
    const ExportFlowsCommandOptions& options,
    const ExportExecutionEnvironment& environment
) {
    const bool input_looks_like_index = looks_like_index_file(options.input_path);
    if (input_looks_like_index && options.settings_path.has_value()) {
        return {
            .exit_code = 1,
            .stdout_text = {},
            .stderr_text = "--settings is valid only for raw capture input.\n",
        };
    }

    if (!input_looks_like_index && options.source_capture_path.has_value()) {
        return {
            .exit_code = 1,
            .stdout_text = {},
            .stderr_text = "--source-capture is valid only for index input.\n",
        };
    }

    if (options.settings_path.has_value()) {
        std::error_code error {};
        if (!std::filesystem::exists(*options.settings_path, error) || error) {
            return {
                .exit_code = 1,
                .stdout_text = {},
                .stderr_text = "Settings file does not exist: " + options.settings_path->string() + '\n',
            };
        }
    }

    if (options.out_path.has_value()) {
        std::array<CliOutputTarget, 1> outputs {{
            CliOutputTarget {
                .label = "--out",
                .path = *options.out_path,
            },
        }};
        const auto preflight = preflight_output_targets(
            options.input_path,
            std::span<const CliOutputTarget>(outputs.data(), 1U),
            options.force
        );
        if (!preflight.ok) {
            return {
                .exit_code = 1,
                .stdout_text = {},
                .stderr_text = preflight.error_text + '\n',
            };
        }

        if (options.source_capture_path.has_value() &&
            paths_refer_to_same_target(*options.out_path, *options.source_capture_path)) {
            return {
                .exit_code = 1,
                .stdout_text = {},
                .stderr_text = "Output file must not overwrite the source capture.\n",
            };
        }
    }

    if (options.out_dir_path.has_value()) {
        const auto preflight = preflight_output_directory(
            options.input_path,
            *options.out_dir_path,
            options.force
        );
        if (!preflight.ok) {
            return {
                .exit_code = 1,
                .stdout_text = {},
                .stderr_text = preflight.error_text + '\n',
            };
        }
    }

    FrontendSettingsDto effective_settings {};
    if (options.settings_path.has_value()) {
        const auto parse_result = parse_frontend_settings_json_file(*options.settings_path);
        if (!parse_result.ok) {
            return {
                .exit_code = 1,
                .stdout_text = {},
                .stderr_text = parse_result.error_text + '\n',
            };
        }
        effective_settings = parse_result.settings;
    }

    FrontendSessionAdapter adapter {};
    if (options.settings_path.has_value()) {
        [[maybe_unused]] const auto updated_settings = adapter.update_settings(effective_settings);
    }

    std::string stderr_text {};
    const auto open_result = open_input_with_progress(
        adapter,
        options.input_path,
        options.progress_mode,
        environment.stderr_is_terminal,
        stderr_text
    );
    if (!open_result.opened) {
        if (stderr_text.find('\r') != std::string::npos && !stderr_text.empty() && stderr_text.back() != '\n') {
            stderr_text += '\n';
        }
        stderr_text += open_result.error_text.empty()
            ? "Failed to open input: " + options.input_path.string() + '\n'
            : open_result.error_text + '\n';
        return {
            .exit_code = 1,
            .stdout_text = {},
            .stderr_text = std::move(stderr_text),
        };
    }

    if (open_result.partial_open && !open_result.partial_open_warning_text.empty()) {
        stderr_text += open_result.partial_open_warning_text;
        stderr_text += '\n';
    }

    if (options.source_capture_path.has_value()) {
        const auto attach_result = adapter.attach_source_capture(*options.source_capture_path);
        if (!attach_result.attached) {
            stderr_text += attach_result.error_text.empty()
                ? "Failed to attach the source capture.\n"
                : attach_result.error_text + '\n';
            return {
                .exit_code = 1,
                .stdout_text = {},
                .stderr_text = std::move(stderr_text),
            };
        }
    }

    const auto source_availability = adapter.source_availability();
    if (!source_availability.source_capture_accessible) {
        stderr_text += "Index packet export requires a valid source capture. Re-run with --source-capture <path> or open the original capture directly.\n";
        return {
            .exit_code = 1,
            .stdout_text = {},
            .stderr_text = std::move(stderr_text),
        };
    }

    if (options.out_path.has_value() &&
        !source_availability.active_source_capture_path.empty() &&
        paths_refer_to_same_target(*options.out_path, std::filesystem::path {source_availability.active_source_capture_path})) {
        stderr_text += "Output file must not overwrite the source capture.\n";
        return {
            .exit_code = 1,
            .stdout_text = {},
            .stderr_text = std::move(stderr_text),
        };
    }

    if (options.unrecognized_packets) {
        const auto unrecognized_result = adapter.get_unrecognized_packets(0U, 0U);
        const auto available_unrecognized_count = unrecognized_result.total_count;
        if (available_unrecognized_count == 0U) {
            stderr_text += "No unrecognized packets to export.\n";
            return {
                .exit_code = 1,
                .stdout_text = {},
                .stderr_text = std::move(stderr_text),
            };
        }

        const auto exported_packet_count = options.packet_limit.has_value()
            ? std::min(available_unrecognized_count, *options.packet_limit)
            : available_unrecognized_count;
        const auto exported_packet_count_text = session_detail::format_statistics_count_value(exported_packet_count);

        SmartExportCliProgressRenderState progress_state {};
        SmartSingleFileExportOptions export_options {};
        const auto progress_enabled = should_enable_cli_progress(options.progress_mode, environment.stderr_is_terminal);
        if (progress_enabled) {
            export_options.progress_callback = [&](const SmartSingleFileExportProgress& progress) {
                append_progress_line(
                    stderr_text,
                    render_throttled_smart_single_file_progress_line(
                        progress,
                        progress_state,
                        std::chrono::steady_clock::now()
                    )
                );
            };
        }

        const auto export_result = adapter.export_smart_unrecognized_packets(
            *options.out_path,
            build_unrecognized_export_options(options),
            export_options
        );
        if (!export_result.exported) {
            const auto error_text = export_result.error_text == "No unrecognized packets available for smart export."
                ? "No unrecognized packets to export."
                : export_result.error_text;
            stderr_text += error_text.empty()
                ? "Failed to export unrecognized packets.\n"
                : error_text + '\n';
            return {
                .exit_code = 1,
                .stdout_text = {},
                .stderr_text = std::move(stderr_text),
            };
        }

        stderr_text += "Exported " + exported_packet_count_text + " unrecognized packets to: " + export_result.output_path + '\n';
        return {
            .exit_code = 0,
            .stdout_text = {},
            .stderr_text = std::move(stderr_text),
        };
    }

    const auto query_result = adapter.query_flows(build_flow_query(options));
    if (query_result.status == session_detail::FlowQueryStatus::invalid_limit) {
        return {
            .exit_code = 1,
            .stdout_text = {},
            .stderr_text = "Invalid --limit value.\n",
        };
    }
    if (query_result.status == session_detail::FlowQueryStatus::invalid_flow_index) {
        const auto canonical_number = query_result.invalid_flow_index.has_value()
            ? session_detail::format_statistics_count_value(*query_result.invalid_flow_index + 1U)
            : std::string {"unknown"};
        return {
            .exit_code = 1,
            .stdout_text = {},
            .stderr_text = "Requested flow number is outside the available canonical flow range: " + canonical_number + '\n',
        };
    }
    if (query_result.ordered_flow_indices.empty()) {
        return {
            .exit_code = 1,
            .stdout_text = {},
            .stderr_text = "No flows matched the export selection.\n",
        };
    }

    if (options.out_path.has_value() &&
        !options.force &&
        std::filesystem::exists(*options.out_path)) {
        // Shared preflight already handled this before open; keep runtime path side-effect free if race-free preflight changed.
    }

    const auto progress_enabled = should_enable_cli_progress(options.progress_mode, environment.stderr_is_terminal);
    const auto exported_flow_count_text = session_detail::format_statistics_count_value(query_result.ordered_flow_indices.size());

    if (options.out_path.has_value() &&
        options.base_mode == SmartFlowExportBaseMode::all_packets) {
        const auto export_result = adapter.export_flows_to_pcap(*options.out_path, query_result.ordered_flow_indices);
        if (!export_result.exported) {
            stderr_text += export_result.error_text.empty()
                ? "Failed to export flows.\n"
                : export_result.error_text + '\n';
            return {
                .exit_code = 1,
                .stdout_text = {},
                .stderr_text = std::move(stderr_text),
            };
        }

        stderr_text += "Exported " + exported_flow_count_text + " flows to: " + export_result.output_path + '\n';
        return {
            .exit_code = 0,
            .stdout_text = {},
            .stderr_text = std::move(stderr_text),
        };
    }

    auto request = build_export_request(options, query_result.ordered_flow_indices);

    if (options.out_path.has_value()) {
        SmartExportCliProgressRenderState progress_state {};
        SmartSingleFileExportOptions export_options {};
        if (progress_enabled) {
            export_options.progress_callback = [&](const SmartSingleFileExportProgress& progress) {
                append_progress_line(
                    stderr_text,
                    render_throttled_smart_single_file_progress_line(
                        progress,
                        progress_state,
                        std::chrono::steady_clock::now()
                    )
                );
            };
        }

        const auto export_result = adapter.export_smart_flows_to_pcap(*options.out_path, request, export_options);
        if (!export_result.exported) {
            stderr_text += export_result.error_text.empty()
                ? "Failed to export flows.\n"
                : export_result.error_text + '\n';
            return {
                .exit_code = 1,
                .stdout_text = {},
                .stderr_text = std::move(stderr_text),
            };
        }

        stderr_text += "Exported " + exported_flow_count_text + " flows to: " + export_result.output_path + '\n';
        return {
            .exit_code = 0,
            .stdout_text = {},
            .stderr_text = std::move(stderr_text),
        };
    }

    SmartExportCliProgressRenderState progress_state {};
    SmartPerFlowExportOptions export_options {
        .buffer_budget_bytes = options.buffer_memory_bytes,
    };
    if (progress_enabled) {
        export_options.progress_callback = [&](const SmartPerFlowExportProgress& progress) {
            append_progress_line(
                stderr_text,
                render_throttled_smart_per_flow_progress_line(
                    progress,
                    progress_state,
                    std::chrono::steady_clock::now()
                )
            );
        };
    }

    const auto export_result = adapter.export_smart_flows_to_folder(*options.out_dir_path, request, export_options);
    if (!export_result.exported) {
        stderr_text += export_result.error_text.empty()
            ? "Failed to export flows.\n"
            : export_result.error_text + '\n';
        return {
            .exit_code = 1,
            .stdout_text = {},
            .stderr_text = std::move(stderr_text),
        };
    }

    stderr_text += "Exported " + exported_flow_count_text + " flows to: " + export_result.output_path + '\n';
    return {
        .exit_code = 0,
        .stdout_text = {},
        .stderr_text = std::move(stderr_text),
    };
}

}  // namespace

std::string render_export_flows_command_help() {
    std::ostringstream out {};
    out << "PcapFlowLab CLI - export-flows\n\n";
    out << "Export packet data for selected canonical flows.\n\n";
    out << "Usage\n";
    out << "  pcap-flow-lab export-flows <input> [options]\n";
    out << "  pcap-flow-lab export-flows --input <input> [options]\n\n";
    out << "Flow selection\n";
    out << "  --flow-number <N>\n";
    out << "  --flow-numbers <ranges>\n";
    out << "  --filter <text>\n";
    out << "  --all-flows\n";
    out << "  --limit <N>\n";
    out << "    Flow numbers are one-based canonical identities.\n";
    out << "    --limit limits flows, not packets.\n\n";
    out << "  --unrecognized-packets\n";
    out << "  --packet-limit <N>\n";
    out << "    Alternative mode for exporting unrecognized packets.\n";
    out << "    --packet-limit limits the number of unrecognized packets exported.\n\n";
    out << "Packet retention\n";
    out << "  --all-packets\n";
    out << "  --first-packets <N>\n";
    out << "  --first-original-bytes <N>\n";
    out << "  --include-last-packet\n";
    out << "  --every-kth-packet <K>\n\n";
    out << "Output\n";
    out << "  --out <path>\n";
    out << "  --out-dir <path>\n";
    out << "  --buffer-memory-mib <N>\n";
    out << "    --out writes one classic PCAP. --out-dir writes one PCAP per flow plus flows_manifest.csv.\n";
    out << "    Unrecognized-packet mode requires --out.\n\n";
    out << "Input and import\n";
    out << "  --input <path>\n";
    out << "  --source-capture <path>\n";
    out << "    Valid only for index input that requires packet bytes.\n";
    out << "  --settings <settings.json>\n";
    out << "    Applies to raw capture import and is invalid for index input.\n\n";
    out << "Runtime\n";
    out << "  --progress <auto|on|off>\n";
    out << "  --force\n\n";
    out << "Help\n";
    out << "  -h, --help\n\n";
    out << "Notes\n";
    out << "  A selection mode is required: a flow selector or --unrecognized-packets.\n";
    out << "  Flow selectors are --flow-number, --flow-numbers, --filter, and --all-flows.\n";
    out << "  --unrecognized-packets is an alternative selector mode and is mutually exclusive with flow selectors.\n";
    out << "  If no packet base mode is supplied, the effective default is --all-packets.\n\n";
    out << render_export_flows_examples();
    return out.str();
}

std::optional<std::string> render_throttled_smart_single_file_progress_line(
    const SmartSingleFileExportProgress& progress,
    SmartExportCliProgressRenderState& state,
    const std::chrono::steady_clock::time_point now
) {
    return maybe_emit_throttled_progress_line(
        SmartExportCliProgressPhase::single_file,
        render_smart_single_file_progress_line(progress),
        is_completed_single_file_progress(progress),
        state,
        now
    );
}

std::optional<std::string> render_throttled_smart_per_flow_progress_line(
    const SmartPerFlowExportProgress& progress,
    SmartExportCliProgressRenderState& state,
    const std::chrono::steady_clock::time_point now
) {
    return maybe_emit_throttled_progress_line(
        progress.phase == SmartPerFlowExportPhase::preparing
            ? SmartExportCliProgressPhase::per_flow_preparing
            : SmartExportCliProgressPhase::per_flow_writing,
        render_smart_per_flow_progress_line(progress),
        is_completed_per_flow_progress(progress),
        state,
        now
    );
}

ExportFlowsCommandParseResult parse_export_flows_command_arguments(const std::span<const std::string_view> args) {
    ExportFlowsCommandOptions options {};
    bool positional_input_seen = false;
    bool explicit_input_seen = false;
    bool explicit_settings_seen = false;
    bool explicit_source_capture_seen = false;
    bool unrecognized_packets_seen = false;
    bool packet_limit_seen = false;
    bool flow_number_seen = false;
    bool flow_numbers_seen = false;
    bool filter_seen = false;
    bool all_flows_seen = false;
    bool limit_seen = false;
    bool all_packets_seen = false;
    bool first_packets_seen = false;
    bool first_original_bytes_seen = false;
    bool include_last_packet_seen = false;
    bool every_kth_packet_seen = false;
    bool out_seen = false;
    bool out_dir_seen = false;
    bool buffer_memory_seen = false;
    bool progress_seen = false;
    bool force_seen = false;

    for (std::size_t index = 0U; index < args.size(); ++index) {
        const auto token = args[index];

        if (token == "--force") {
            if (force_seen) {
                return {.ok = false, .options = std::nullopt, .error_text = "Duplicate --force is invalid."};
            }
            force_seen = true;
            options.force = true;
            continue;
        }

        if (token == "--input") {
            if (explicit_input_seen) {
                return {.ok = false, .options = std::nullopt, .error_text = "Duplicate --input is invalid."};
            }
            if (positional_input_seen) {
                return {.ok = false, .options = std::nullopt, .error_text = "Positional input and --input are mutually exclusive input forms. Using both in the same invocation is invalid."};
            }
            if (index + 1U >= args.size()) {
                return {.ok = false, .options = std::nullopt, .error_text = "--input requires a path."};
            }
            explicit_input_seen = true;
            options.input_path = std::filesystem::path {std::string {args[++index]}};
            continue;
        }

        if (token == "--settings") {
            if (explicit_settings_seen) {
                return {.ok = false, .options = std::nullopt, .error_text = "Duplicate --settings is invalid."};
            }
            if (index + 1U >= args.size()) {
                return {.ok = false, .options = std::nullopt, .error_text = "--settings requires a path."};
            }
            explicit_settings_seen = true;
            options.settings_path = std::filesystem::path {std::string {args[++index]}};
            continue;
        }

        if (token == "--source-capture") {
            if (explicit_source_capture_seen) {
                return {.ok = false, .options = std::nullopt, .error_text = "Duplicate --source-capture is invalid."};
            }
            if (index + 1U >= args.size()) {
                return {.ok = false, .options = std::nullopt, .error_text = "--source-capture requires a path."};
            }
            explicit_source_capture_seen = true;
            options.source_capture_path = std::filesystem::path {std::string {args[++index]}};
            continue;
        }

        if (token == "--unrecognized-packets") {
            if (unrecognized_packets_seen) {
                return {.ok = false, .options = std::nullopt, .error_text = "Duplicate --unrecognized-packets is invalid."};
            }
            if (flow_number_seen || flow_numbers_seen || filter_seen || all_flows_seen || limit_seen) {
                return {.ok = false, .options = std::nullopt, .error_text = "--unrecognized-packets is mutually exclusive with flow selectors and --limit."};
            }
            unrecognized_packets_seen = true;
            options.unrecognized_packets = true;
            continue;
        }

        if (token == "--packet-limit") {
            if (packet_limit_seen) {
                return {.ok = false, .options = std::nullopt, .error_text = "Duplicate --packet-limit is invalid."};
            }
            if (index + 1U >= args.size()) {
                return {.ok = false, .options = std::nullopt, .error_text = "--packet-limit requires a positive unrecognized packet count."};
            }
            const auto packet_limit = parse_cli_positive_size(args[++index]);
            if (!packet_limit.has_value()) {
                return {.ok = false, .options = std::nullopt, .error_text = "Invalid --packet-limit value. Expected a positive unrecognized packet count."};
            }
            packet_limit_seen = true;
            options.packet_limit = *packet_limit;
            continue;
        }

        if (token == "--flow-number") {
            if (flow_number_seen) {
                return {.ok = false, .options = std::nullopt, .error_text = "Duplicate --flow-number is invalid."};
            }
            if (unrecognized_packets_seen) {
                return {.ok = false, .options = std::nullopt, .error_text = "--flow-number is invalid with --unrecognized-packets."};
            }
            if (flow_numbers_seen) {
                return {.ok = false, .options = std::nullopt, .error_text = "--flow-number and --flow-numbers are mutually exclusive."};
            }
            if (all_flows_seen) {
                return {.ok = false, .options = std::nullopt, .error_text = "--all-flows is mutually exclusive with explicit flow-number selectors."};
            }
            if (index + 1U >= args.size()) {
                return {.ok = false, .options = std::nullopt, .error_text = "--flow-number requires a positive one-based flow number."};
            }
            const auto flow_index = parse_cli_flow_number(args[++index]);
            if (!flow_index.has_value()) {
                return {.ok = false, .options = std::nullopt, .error_text = "Invalid --flow-number value. Expected a positive one-based flow number."};
            }
            flow_number_seen = true;
            options.selected_flow_indices = std::vector<std::size_t> {*flow_index};
            continue;
        }

        if (token == "--flow-numbers") {
            if (flow_numbers_seen) {
                return {.ok = false, .options = std::nullopt, .error_text = "Duplicate --flow-numbers is invalid."};
            }
            if (unrecognized_packets_seen) {
                return {.ok = false, .options = std::nullopt, .error_text = "--flow-numbers is invalid with --unrecognized-packets."};
            }
            if (flow_number_seen) {
                return {.ok = false, .options = std::nullopt, .error_text = "--flow-number and --flow-numbers are mutually exclusive."};
            }
            if (all_flows_seen) {
                return {.ok = false, .options = std::nullopt, .error_text = "--all-flows is mutually exclusive with explicit flow-number selectors."};
            }
            if (index + 1U >= args.size()) {
                return {.ok = false, .options = std::nullopt, .error_text = "--flow-numbers requires one or more positive one-based ranges."};
            }
            const auto parsed = parse_cli_flow_numbers(args[++index]);
            if (!parsed.has_value()) {
                return {.ok = false, .options = std::nullopt, .error_text = "Invalid --flow-numbers value. Expected inclusive positive one-based ranges such as 1-10,24,31-35."};
            }
            flow_numbers_seen = true;
            options.selected_flow_indices = *parsed;
            continue;
        }

        if (token == "--filter") {
            if (filter_seen) {
                return {.ok = false, .options = std::nullopt, .error_text = "Duplicate --filter is invalid."};
            }
            if (unrecognized_packets_seen) {
                return {.ok = false, .options = std::nullopt, .error_text = "--filter is invalid with --unrecognized-packets."};
            }
            if (all_flows_seen) {
                return {.ok = false, .options = std::nullopt, .error_text = "--all-flows is mutually exclusive with --filter."};
            }
            if (index + 1U >= args.size()) {
                return {.ok = false, .options = std::nullopt, .error_text = "--filter requires a text query."};
            }
            filter_seen = true;
            options.text_filter = std::string {args[++index]};
            continue;
        }

        if (token == "--all-flows") {
            if (all_flows_seen) {
                return {.ok = false, .options = std::nullopt, .error_text = "Duplicate --all-flows is invalid."};
            }
            if (unrecognized_packets_seen) {
                return {.ok = false, .options = std::nullopt, .error_text = "--all-flows is invalid with --unrecognized-packets."};
            }
            if (flow_number_seen || flow_numbers_seen) {
                return {.ok = false, .options = std::nullopt, .error_text = "--all-flows is mutually exclusive with explicit flow-number selectors."};
            }
            if (filter_seen) {
                return {.ok = false, .options = std::nullopt, .error_text = "--all-flows is mutually exclusive with --filter."};
            }
            all_flows_seen = true;
            options.all_flows = true;
            continue;
        }

        if (token == "--limit") {
            if (limit_seen) {
                return {.ok = false, .options = std::nullopt, .error_text = "Duplicate --limit is invalid."};
            }
            if (unrecognized_packets_seen) {
                return {.ok = false, .options = std::nullopt, .error_text = "--limit is invalid with --unrecognized-packets. Use --packet-limit instead."};
            }
            if (index + 1U >= args.size()) {
                return {.ok = false, .options = std::nullopt, .error_text = "--limit requires a positive flow count."};
            }
            const auto limit = parse_cli_positive_size(args[++index]);
            if (!limit.has_value()) {
                return {.ok = false, .options = std::nullopt, .error_text = "Invalid --limit value. Expected a positive flow count."};
            }
            limit_seen = true;
            options.limit = *limit;
            continue;
        }

        if (token == "--all-packets") {
            if (all_packets_seen) {
                return {.ok = false, .options = std::nullopt, .error_text = "Duplicate --all-packets is invalid."};
            }
            if (unrecognized_packets_seen) {
                return {.ok = false, .options = std::nullopt, .error_text = "--all-packets is invalid with --unrecognized-packets."};
            }
            if (first_packets_seen || first_original_bytes_seen) {
                return {.ok = false, .options = std::nullopt, .error_text = "--all-packets, --first-packets, and --first-original-bytes are mutually exclusive."};
            }
            all_packets_seen = true;
            options.base_mode = SmartFlowExportBaseMode::all_packets;
            continue;
        }

        if (token == "--first-packets") {
            if (first_packets_seen) {
                return {.ok = false, .options = std::nullopt, .error_text = "Duplicate --first-packets is invalid."};
            }
            if (unrecognized_packets_seen) {
                return {.ok = false, .options = std::nullopt, .error_text = "--first-packets is invalid with --unrecognized-packets."};
            }
            if (all_packets_seen || first_original_bytes_seen) {
                return {.ok = false, .options = std::nullopt, .error_text = "--all-packets, --first-packets, and --first-original-bytes are mutually exclusive."};
            }
            if (index + 1U >= args.size()) {
                return {.ok = false, .options = std::nullopt, .error_text = "--first-packets requires a positive packet count."};
            }
            const auto first_packets = parse_cli_positive_size(args[++index]);
            if (!first_packets.has_value()) {
                return {.ok = false, .options = std::nullopt, .error_text = "Invalid --first-packets value. Expected a positive packet count."};
            }
            first_packets_seen = true;
            options.base_mode = SmartFlowExportBaseMode::first_n_packets;
            options.first_n_packets = static_cast<std::uint64_t>(*first_packets);
            continue;
        }

        if (token == "--first-original-bytes") {
            if (first_original_bytes_seen) {
                return {.ok = false, .options = std::nullopt, .error_text = "Duplicate --first-original-bytes is invalid."};
            }
            if (unrecognized_packets_seen) {
                return {.ok = false, .options = std::nullopt, .error_text = "--first-original-bytes is invalid with --unrecognized-packets."};
            }
            if (all_packets_seen || first_packets_seen) {
                return {.ok = false, .options = std::nullopt, .error_text = "--all-packets, --first-packets, and --first-original-bytes are mutually exclusive."};
            }
            if (index + 1U >= args.size()) {
                return {.ok = false, .options = std::nullopt, .error_text = "--first-original-bytes requires a positive original-byte threshold."};
            }
            const auto first_original_bytes = parse_cli_positive_size(args[++index]);
            if (!first_original_bytes.has_value()) {
                return {.ok = false, .options = std::nullopt, .error_text = "Invalid --first-original-bytes value. Expected a positive original-byte threshold."};
            }
            first_original_bytes_seen = true;
            options.base_mode = SmartFlowExportBaseMode::first_m_original_bytes;
            options.first_m_original_bytes = static_cast<std::uint64_t>(*first_original_bytes);
            continue;
        }

        if (token == "--include-last-packet") {
            if (include_last_packet_seen) {
                return {.ok = false, .options = std::nullopt, .error_text = "Duplicate --include-last-packet is invalid."};
            }
            if (unrecognized_packets_seen) {
                return {.ok = false, .options = std::nullopt, .error_text = "--include-last-packet is invalid with --unrecognized-packets."};
            }
            include_last_packet_seen = true;
            options.include_last_packet = true;
            continue;
        }

        if (token == "--every-kth-packet") {
            if (every_kth_packet_seen) {
                return {.ok = false, .options = std::nullopt, .error_text = "Duplicate --every-kth-packet is invalid."};
            }
            if (unrecognized_packets_seen) {
                return {.ok = false, .options = std::nullopt, .error_text = "--every-kth-packet is invalid with --unrecognized-packets."};
            }
            if (index + 1U >= args.size()) {
                return {.ok = false, .options = std::nullopt, .error_text = "--every-kth-packet requires a positive packet interval."};
            }
            const auto every_kth_packet = parse_cli_positive_size(args[++index]);
            if (!every_kth_packet.has_value()) {
                return {.ok = false, .options = std::nullopt, .error_text = "Invalid --every-kth-packet value. Expected a positive packet interval."};
            }
            every_kth_packet_seen = true;
            options.include_every_kth_packet_after_base = true;
            options.every_kth_packet = static_cast<std::uint64_t>(*every_kth_packet);
            continue;
        }

        if (token == "--out") {
            if (out_seen) {
                return {.ok = false, .options = std::nullopt, .error_text = "Duplicate --out is invalid."};
            }
            if (out_dir_seen) {
                return {.ok = false, .options = std::nullopt, .error_text = "Exactly one of --out or --out-dir is required."};
            }
            if (index + 1U >= args.size()) {
                return {.ok = false, .options = std::nullopt, .error_text = "--out requires a path."};
            }
            out_seen = true;
            options.out_path = std::filesystem::path {std::string {args[++index]}};
            continue;
        }

        if (token == "--out-dir") {
            if (out_dir_seen) {
                return {.ok = false, .options = std::nullopt, .error_text = "Duplicate --out-dir is invalid."};
            }
            if (unrecognized_packets_seen) {
                return {.ok = false, .options = std::nullopt, .error_text = "--out-dir is invalid with --unrecognized-packets. Use --out <path>."};
            }
            if (out_seen) {
                return {.ok = false, .options = std::nullopt, .error_text = "Exactly one of --out or --out-dir is required."};
            }
            if (index + 1U >= args.size()) {
                return {.ok = false, .options = std::nullopt, .error_text = "--out-dir requires a path."};
            }
            out_dir_seen = true;
            options.out_dir_path = std::filesystem::path {std::string {args[++index]}};
            continue;
        }

        if (token == "--buffer-memory-mib") {
            if (buffer_memory_seen) {
                return {.ok = false, .options = std::nullopt, .error_text = "Duplicate --buffer-memory-mib is invalid."};
            }
            if (unrecognized_packets_seen) {
                return {.ok = false, .options = std::nullopt, .error_text = "--buffer-memory-mib is invalid with --unrecognized-packets."};
            }
            if (index + 1U >= args.size()) {
                return {.ok = false, .options = std::nullopt, .error_text = "--buffer-memory-mib requires a positive integer number of MiB."};
            }
            const auto buffer_memory_mib = parse_cli_positive_size(args[++index]);
            if (!buffer_memory_mib.has_value()) {
                return {.ok = false, .options = std::nullopt, .error_text = "Invalid --buffer-memory-mib value. Expected a positive integer number of MiB."};
            }
            if (*buffer_memory_mib > std::numeric_limits<std::size_t>::max() / kMebibyte) {
                return {.ok = false, .options = std::nullopt, .error_text = "Invalid --buffer-memory-mib value. It is too large for the current platform."};
            }
            buffer_memory_seen = true;
            options.buffer_memory_bytes = *buffer_memory_mib * kMebibyte;
            continue;
        }

        if (token == "--progress") {
            if (progress_seen) {
                return {.ok = false, .options = std::nullopt, .error_text = "Duplicate --progress is invalid."};
            }
            if (index + 1U >= args.size()) {
                return {.ok = false, .options = std::nullopt, .error_text = "--progress requires one of: auto, on, off."};
            }
            const auto mode = parse_cli_progress_mode(args[++index]);
            if (!mode.has_value()) {
                return {.ok = false, .options = std::nullopt, .error_text = "Invalid --progress value. Expected one of: auto, on, off."};
            }
            progress_seen = true;
            options.progress_mode = *mode;
            continue;
        }

        if (!token.empty() && token.front() == '-') {
            if (token == "--sort" || token == "--format" || token == "--columns") {
                return {
                    .ok = false,
                    .options = std::nullopt,
                    .error_text = std::string {token} + " is not implemented for export-flows."
                };
            }
            return {
                .ok = false,
                .options = std::nullopt,
                .error_text = "Unknown export-flows option: " + std::string {token}
            };
        }

        if (explicit_input_seen || positional_input_seen) {
            return {.ok = false, .options = std::nullopt, .error_text = "export-flows accepts exactly one input path."};
        }

        positional_input_seen = true;
        options.input_path = std::filesystem::path {std::string {token}};
    }

    if (options.input_path.empty()) {
        return {.ok = false, .options = std::nullopt, .error_text = "export-flows requires an input path."};
    }

    if (!options.unrecognized_packets && options.packet_limit.has_value()) {
        return {.ok = false, .options = std::nullopt, .error_text = "--packet-limit is valid only with --unrecognized-packets."};
    }

    const bool has_selector =
        options.unrecognized_packets ||
        options.all_flows ||
        options.selected_flow_indices.has_value() ||
        !options.text_filter.empty();
    if (!has_selector) {
        return {.ok = false, .options = std::nullopt, .error_text = "export-flows requires at least one selector: --unrecognized-packets, --flow-number, --flow-numbers, --filter, or --all-flows."};
    }

    if (options.unrecognized_packets) {
        if (flow_number_seen) {
            return {.ok = false, .options = std::nullopt, .error_text = "--flow-number is invalid with --unrecognized-packets."};
        }
        if (flow_numbers_seen) {
            return {.ok = false, .options = std::nullopt, .error_text = "--flow-numbers is invalid with --unrecognized-packets."};
        }
        if (filter_seen) {
            return {.ok = false, .options = std::nullopt, .error_text = "--filter is invalid with --unrecognized-packets."};
        }
        if (all_flows_seen) {
            return {.ok = false, .options = std::nullopt, .error_text = "--all-flows is invalid with --unrecognized-packets."};
        }
        if (limit_seen) {
            return {.ok = false, .options = std::nullopt, .error_text = "--limit is invalid with --unrecognized-packets. Use --packet-limit instead."};
        }
        if (all_packets_seen) {
            return {.ok = false, .options = std::nullopt, .error_text = "--all-packets is invalid with --unrecognized-packets."};
        }
        if (first_packets_seen) {
            return {.ok = false, .options = std::nullopt, .error_text = "--first-packets is invalid with --unrecognized-packets."};
        }
        if (first_original_bytes_seen) {
            return {.ok = false, .options = std::nullopt, .error_text = "--first-original-bytes is invalid with --unrecognized-packets."};
        }
        if (include_last_packet_seen) {
            return {.ok = false, .options = std::nullopt, .error_text = "--include-last-packet is invalid with --unrecognized-packets."};
        }
        if (every_kth_packet_seen) {
            return {.ok = false, .options = std::nullopt, .error_text = "--every-kth-packet is invalid with --unrecognized-packets."};
        }
        if (options.out_dir_path.has_value()) {
            return {.ok = false, .options = std::nullopt, .error_text = "--out-dir is invalid with --unrecognized-packets. Use --out <path>."};
        }
        if (buffer_memory_seen) {
            return {.ok = false, .options = std::nullopt, .error_text = "--buffer-memory-mib is invalid with --unrecognized-packets."};
        }
    }

    if (!options.out_path.has_value() && !options.out_dir_path.has_value()) {
        return {.ok = false, .options = std::nullopt, .error_text = "Exactly one of --out or --out-dir is required."};
    }

    if (options.out_path.has_value() && options.out_dir_path.has_value()) {
        return {.ok = false, .options = std::nullopt, .error_text = "Exactly one of --out or --out-dir is required."};
    }

    if (buffer_memory_seen && !options.out_dir_path.has_value()) {
        return {.ok = false, .options = std::nullopt, .error_text = "--buffer-memory-mib is valid only with --out-dir."};
    }

    const bool bounded_base_mode =
        options.base_mode == SmartFlowExportBaseMode::first_n_packets ||
        options.base_mode == SmartFlowExportBaseMode::first_m_original_bytes;
    if (!bounded_base_mode && (options.include_last_packet || options.include_every_kth_packet_after_base)) {
        return {.ok = false, .options = std::nullopt, .error_text = "--include-last-packet and --every-kth-packet require --first-packets or --first-original-bytes."};
    }

    return {
        .ok = true,
        .options = options,
        .error_text = {},
    };
}

ExportFlowsCommandExecutionResult execute_export_flows_command(const ExportFlowsCommandOptions& options) {
    return execute_export_flows_command_with_environment(
        options,
        ExportExecutionEnvironment {
            .stderr_is_terminal = stderr_supports_interactive_updates(),
        }
    );
}

}  // namespace pfl::cli
