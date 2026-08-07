#include "cli/SummaryCommand.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <sstream>
#include <string>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

#include "app/frontend/FrontendSessionAdapter.h"
#include "app/frontend/FrontendSettingsJson.h"
#include "app/session/ProtocolPathTextExport.h"
#include "app/session/SessionFlowHelpers.h"
#include "core/index/CaptureIndex.h"

#if defined(_WIN32)
#include <io.h>
#else
#include <unistd.h>
#endif

namespace pfl::cli {
namespace {

using Clock = std::chrono::steady_clock;

constexpr std::array<std::string_view, 8> kSummaryInvalidSelectorOptions {
    "--filter",
    "--flow-number",
    "--flow-numbers",
    "--sort",
    "--limit",
    "--packets-in-flow",
    "--packets-in-file",
    "--source-capture",
};

constexpr std::array<std::string_view, 3> kSummaryUnsupportedOptions {
    "--out-flows-list",
    "--format",
    "--source-capture",
};

constexpr std::array<std::string_view, 8> kLegacyCliCommands {
    "flows",
    "inspect-packet",
    "hex",
    "export-flow",
    "save-index",
    "load-index-summary",
    "chunked-import",
    "resume-import",
};

struct TableColumn {
    std::string header {};
    bool right_align {false};
};

struct OutputPreflightResult {
    bool ok {false};
    std::string error_text {};
};

struct SummaryExecutionEnvironment {
    bool stderr_is_terminal {false};
};

bool contains_option(
    const std::span<const std::string_view> options,
    const std::string_view candidate
) noexcept {
    return std::find(options.begin(), options.end(), candidate) != options.end();
}

bool stderr_supports_interactive_updates() noexcept {
#if defined(_WIN32)
    return _isatty(_fileno(stderr)) != 0;
#else
    return isatty(fileno(stderr)) != 0;
#endif
}

std::string input_kind_display_text(const FrontendInputKind kind) {
    switch (kind) {
    case FrontendInputKind::classic_pcap:
        return "PCAP";
    case FrontendInputKind::pcapng:
        return "PCAPNG";
    case FrontendInputKind::pcap_flow_lab_index:
        return "PcapFlowLab Index";
    case FrontendInputKind::unknown:
    default:
        return "Unknown";
    }
}

std::string basename_for_display(const std::string_view path_text) {
    return std::filesystem::path {std::string {path_text}}.filename().string();
}

std::string pad_right(const std::string_view text, const std::size_t width) {
    if (text.size() >= width) {
        return std::string {text};
    }
    return std::string {text} + std::string(width - text.size(), ' ');
}

std::string pad_left(const std::string_view text, const std::size_t width) {
    if (text.size() >= width) {
        return std::string {text};
    }
    return std::string(width - text.size(), ' ') + std::string {text};
}

std::string render_table(
    const std::vector<TableColumn>& columns,
    const std::vector<std::vector<std::string>>& rows
) {
    if (columns.empty()) {
        return {};
    }

    std::vector<std::size_t> widths {};
    widths.reserve(columns.size());
    for (const auto& column : columns) {
        widths.push_back(column.header.size());
    }

    for (const auto& row : rows) {
        for (std::size_t index = 0; index < columns.size() && index < row.size(); ++index) {
            widths[index] = std::max(widths[index], row[index].size());
        }
    }

    std::ostringstream out {};
    for (std::size_t index = 0; index < columns.size(); ++index) {
        if (index > 0U) {
            out << "  ";
        }
        out << (columns[index].right_align
            ? pad_left(columns[index].header, widths[index])
            : pad_right(columns[index].header, widths[index]));
    }
    out << '\n';

    for (const auto& row : rows) {
        for (std::size_t index = 0; index < columns.size(); ++index) {
            if (index > 0U) {
                out << "  ";
            }
            const std::string_view cell = index < row.size() ? std::string_view {row[index]} : std::string_view {};
            out << (columns[index].right_align ? pad_left(cell, widths[index]) : pad_right(cell, widths[index]));
        }
        out << '\n';
    }

    return out.str();
}

void append_key_value_line(
    std::ostringstream& out,
    const std::string_view key,
    const std::string_view value,
    const std::size_t label_width
) {
    out << "  " << pad_right(std::string {key} + ":", label_width) << value << '\n';
}

std::optional<ProtocolPathStatisticsMode> parse_protocol_path_mode(const std::string_view value) noexcept {
    if (value == "kind-overview") {
        return ProtocolPathStatisticsMode::kind_overview;
    }
    if (value == "identity-tree") {
        return ProtocolPathStatisticsMode::identity_tree;
    }
    if (value == "terminal-paths") {
        return ProtocolPathStatisticsMode::terminal_paths;
    }
    return std::nullopt;
}

std::optional<SummaryCommandProgressMode> parse_progress_mode(const std::string_view value) noexcept {
    if (value == "auto") {
        return SummaryCommandProgressMode::auto_mode;
    }
    if (value == "on") {
        return SummaryCommandProgressMode::on;
    }
    if (value == "off") {
        return SummaryCommandProgressMode::off;
    }
    return std::nullopt;
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

std::string render_basic_summary_text(const FrontendOverviewDto& overview) {
    constexpr std::array<std::string_view, 4> input_labels {
        "File",
        "Type",
        "File size",
        "Source capture",
    };
    constexpr std::array<std::string_view, 5> capture_labels {
        "Flows",
        "Packets",
        "Captured bytes",
        "Original bytes",
        "Unrecognized packets",
    };

    const auto longest_label_width = [](const auto& labels) {
        std::size_t width = 0U;
        for (const auto label : labels) {
            width = std::max(width, label.size() + 3U);
        }
        return width;
    };

    const auto input_label_width = longest_label_width(input_labels);
    const auto capture_label_width = longest_label_width(capture_labels);

    std::ostringstream out {};
    out << "PcapFlowLab Summary\n\n";

    out << "Input\n";
    append_key_value_line(out, "File", basename_for_display(overview.input_metadata.input_path), input_label_width);
    append_key_value_line(out, "Type", input_kind_display_text(overview.input_metadata.input_kind), input_label_width);
    append_key_value_line(
        out,
        "File size",
        session_detail::format_statistics_compact_size_value(overview.input_metadata.input_file_size),
        input_label_width
    );
    if (overview.input_metadata.input_kind == FrontendInputKind::pcap_flow_lab_index &&
        overview.input_metadata.source_capture_path.has_value()) {
        auto source_capture = basename_for_display(*overview.input_metadata.source_capture_path);
        if (!overview.input_metadata.source_capture_accessible) {
            source_capture += " (not available)";
        }
        append_key_value_line(out, "Source capture", source_capture, input_label_width);
    }

    out << "\nCapture\n";
    append_key_value_line(
        out,
        "Flows",
        session_detail::format_statistics_count_value(overview.summary.flow_count),
        capture_label_width
    );
    append_key_value_line(
        out,
        "Packets",
        session_detail::format_statistics_count_value(overview.whole_capture_totals.packet_count),
        capture_label_width
    );
    append_key_value_line(out, "Captured bytes", overview.whole_capture_totals.captured_bytes_text, capture_label_width);
    append_key_value_line(out, "Original bytes", overview.whole_capture_totals.original_bytes_text, capture_label_width);
    append_key_value_line(
        out,
        "Unrecognized packets",
        session_detail::format_statistics_count_value(overview.unrecognized_packet_count),
        capture_label_width
    );

    out << "\nTransport Summary\n\n";
    out << render_table(
        {
            {.header = "Transport", .right_align = false},
            {.header = "Flows", .right_align = true},
            {.header = "Packets", .right_align = true},
            {.header = "Captured Bytes", .right_align = true},
            {.header = "Original Bytes", .right_align = true},
        },
        {
            {
                "TCP",
                session_detail::format_statistics_count_value(overview.protocol_summary.tcp.flow_count),
                session_detail::format_statistics_count_value(overview.protocol_summary.tcp.packet_count),
                overview.protocol_summary.tcp.captured_bytes_text,
                overview.protocol_summary.tcp.original_bytes_text,
            },
            {
                "UDP",
                session_detail::format_statistics_count_value(overview.protocol_summary.udp.flow_count),
                session_detail::format_statistics_count_value(overview.protocol_summary.udp.packet_count),
                overview.protocol_summary.udp.captured_bytes_text,
                overview.protocol_summary.udp.original_bytes_text,
            },
            {
                "SCTP",
                session_detail::format_statistics_count_value(overview.protocol_summary.sctp.flow_count),
                session_detail::format_statistics_count_value(overview.protocol_summary.sctp.packet_count),
                overview.protocol_summary.sctp.captured_bytes_text,
                overview.protocol_summary.sctp.original_bytes_text,
            },
            {
                "Other",
                session_detail::format_statistics_count_value(overview.protocol_summary.other.flow_count),
                session_detail::format_statistics_count_value(overview.protocol_summary.other.packet_count),
                overview.protocol_summary.other.captured_bytes_text,
                overview.protocol_summary.other.original_bytes_text,
            },
        });

    out << "\nIP Family Summary\n\n";
    out << render_table(
        {
            {.header = "Family", .right_align = false},
            {.header = "Flows", .right_align = true},
            {.header = "Packets", .right_align = true},
            {.header = "Captured Bytes", .right_align = true},
            {.header = "Original Bytes", .right_align = true},
        },
        {
            {
                "IPv4",
                session_detail::format_statistics_count_value(overview.protocol_summary.ipv4.flow_count),
                session_detail::format_statistics_count_value(overview.protocol_summary.ipv4.packet_count),
                overview.protocol_summary.ipv4.captured_bytes_text,
                overview.protocol_summary.ipv4.original_bytes_text,
            },
            {
                "IPv6",
                session_detail::format_statistics_count_value(overview.protocol_summary.ipv6.flow_count),
                session_detail::format_statistics_count_value(overview.protocol_summary.ipv6.packet_count),
                overview.protocol_summary.ipv6.captured_bytes_text,
                overview.protocol_summary.ipv6.original_bytes_text,
            },
        });

    return out.str();
}

std::string render_extended_summary_text(const FrontendSessionAdapter& adapter) {
    std::ostringstream out {};

    const auto packet_size_statistics = adapter.get_capture_packet_size_statistics();
    out << "\nPacket Size Distribution\n\n";
    std::vector<std::vector<std::string>> packet_size_rows {};
    packet_size_rows.reserve(packet_size_statistics.buckets.size());
    for (const auto& bucket : packet_size_statistics.buckets) {
        packet_size_rows.push_back({
            bucket.label,
            bucket.packet_count_text,
            bucket.total_percent_text,
        });
    }
    out << render_table(
        {
            {.header = "Captured Size", .right_align = false},
            {.header = "Packets", .right_align = true},
            {.header = "Percent", .right_align = true},
        },
        packet_size_rows);

    const auto histogram = adapter.get_flow_packet_count_histogram();
    out << "\nFlows by Packet Count\n\n";
    std::vector<std::vector<std::string>> histogram_rows {};
    histogram_rows.reserve(histogram.buckets.size());
    for (const auto& bucket : histogram.buckets) {
        histogram_rows.push_back({
            bucket.label,
            bucket.flow_count_with_total_percent_text,
            bucket.original_byte_count_with_total_percent_text,
        });
    }
    out << render_table(
        {
            {.header = "Packets / Flow", .right_align = false},
            {.header = "Flows", .right_align = true},
            {.header = "Original Bytes", .right_align = true},
        },
        histogram_rows);

    const auto protocol_hints = adapter.get_protocol_hint_statistics();
    out << "\nDetected Protocol Hints\n\n";
    std::vector<std::vector<std::string>> hint_rows {};
    for (const auto& row : protocol_hints.protocol_hints) {
        if (row.flow_count == 0U && row.packet_count == 0U && row.captured_bytes == 0U && row.original_bytes == 0U) {
            continue;
        }
        hint_rows.push_back({
            row.protocol_label,
            row.flow_count_text,
            row.packet_count_text,
            row.captured_bytes_text,
            row.original_bytes_text,
        });
    }
    if (hint_rows.empty()) {
        out << "None\n";
    } else {
        out << render_table(
            {
                {.header = "Protocol Hint", .right_align = false},
                {.header = "Flows", .right_align = true},
                {.header = "Packets", .right_align = true},
                {.header = "Captured Bytes", .right_align = true},
                {.header = "Original Bytes", .right_align = true},
            },
            hint_rows);
    }

    const auto top_statistics = adapter.get_top_endpoint_port_statistics(5U);
    out << "\nTop Endpoints and Ports\n\n";
    out << "Top Endpoints\n\n";
    std::vector<std::vector<std::string>> endpoint_rows {};
    endpoint_rows.reserve(top_statistics.top_endpoints.size());
    for (const auto& row : top_statistics.top_endpoints) {
        endpoint_rows.push_back({
            row.endpoint_label,
            session_detail::format_statistics_count_value(row.packet_count),
            session_detail::format_statistics_compact_size_value(row.total_bytes),
        });
    }
    out << render_table(
        {
            {.header = "Endpoint", .right_align = false},
            {.header = "Packets", .right_align = true},
            {.header = "Original Bytes", .right_align = true},
        },
        endpoint_rows);

    out << "\nTop Ports\n\n";
    std::vector<std::vector<std::string>> port_rows {};
    port_rows.reserve(top_statistics.top_ports.size());
    for (const auto& row : top_statistics.top_ports) {
        port_rows.push_back({
            std::to_string(row.port),
            session_detail::format_statistics_count_value(row.packet_count),
            session_detail::format_statistics_compact_size_value(row.total_bytes),
        });
    }
    out << render_table(
        {
            {.header = "Port", .right_align = false},
            {.header = "Packets", .right_align = true},
            {.header = "Original Bytes", .right_align = true},
        },
        port_rows);

    return out.str();
}

OutputPreflightResult preflight_output_paths(const SummaryCommandOptions& options) {
    OutputPreflightResult result {
        .ok = true,
    };

    std::vector<std::pair<std::string_view, std::filesystem::path>> outputs {};
    if (options.out_index_path.has_value()) {
        outputs.push_back({"--out-index", *options.out_index_path});
    }
    if (options.out_protocol_path_tree_path.has_value()) {
        outputs.push_back({"--out-protocol-path-tree", *options.out_protocol_path_tree_path});
    }

    const auto normalized_input_path = normalized_comparison_path(options.input_path);

    for (const auto& [label, output_path] : outputs) {
        const auto normalized_output_path = normalized_comparison_path(output_path);
        if (!normalized_input_path.empty() && normalized_output_path == normalized_input_path) {
            result.ok = false;
            result.error_text = std::string {label} + " cannot overwrite the input path.";
            return result;
        }

        const auto parent_path = output_path.parent_path();
        if (!parent_path.empty()) {
            std::error_code error {};
            const bool parent_exists = std::filesystem::exists(parent_path, error);
            if (error || !parent_exists || !std::filesystem::is_directory(parent_path, error) || error) {
                result.ok = false;
                result.error_text = std::string {label} + " parent directory does not exist.";
                return result;
            }
        }

        std::error_code exists_error {};
        const bool output_exists = std::filesystem::exists(output_path, exists_error);
        if (exists_error) {
            result.ok = false;
            result.error_text = std::string {label} + " path is not usable.";
            return result;
        }
        if (output_exists && is_existing_directory(output_path)) {
            result.ok = false;
            result.error_text = std::string {label} + " must be a regular file path.";
            return result;
        }
        if (output_exists && !options.force) {
            result.ok = false;
            result.error_text = std::string {label} + " already exists. Re-run with --force to overwrite.";
            return result;
        }
    }

    if (options.out_index_path.has_value() && options.out_protocol_path_tree_path.has_value()) {
        if (normalized_comparison_path(*options.out_index_path)
            == normalized_comparison_path(*options.out_protocol_path_tree_path)) {
            result.ok = false;
            result.error_text = "--out-index and --out-protocol-path-tree must not target the same path.";
            return result;
        }
    }

    return result;
}

std::string render_open_progress_text(const FrontendOpenProgressDto& progress) {
    std::ostringstream out {};
    out << "Opening " << (progress.opening_as_index ? "index" : "capture") << ": ";
    const auto percent = std::clamp(progress.percent * 100.0, 0.0, 100.0);
    out << static_cast<int>(percent + 0.5);
    out << '%';
    if (progress.total_bytes > 0U) {
        out << " ("
            << session_detail::format_statistics_compact_size_value(progress.bytes_processed)
            << " / "
            << session_detail::format_statistics_compact_size_value(progress.total_bytes)
            << ')';
    }
    return out.str();
}

FrontendOpenResult open_summary_input(
    FrontendSessionAdapter& adapter,
    const SummaryCommandOptions& options,
    std::string& stderr_text,
    const SummaryExecutionEnvironment& environment
) {
    if (!should_enable_summary_progress(options.progress_mode, environment.stderr_is_terminal)) {
        return adapter.open_capture(options.input_path);
    }

    const auto start_result = adapter.start_open_capture(options.input_path);
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

SummaryCommandExecutionResult execute_summary_command_with_environment(
    const SummaryCommandOptions& options,
    const SummaryExecutionEnvironment& environment
) {
    const bool input_looks_like_index = looks_like_index_file(options.input_path);
    if (input_looks_like_index && options.settings_path.has_value()) {
        return {
            .exit_code = 1,
            .stdout_text = {},
            .stderr_text = "--settings is valid only for raw capture input.\n",
        };
    }
    if (input_looks_like_index && options.out_index_path.has_value()) {
        return {
            .exit_code = 1,
            .stdout_text = {},
            .stderr_text = "--out-index is valid only for raw capture input.\n",
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

    const auto preflight = preflight_output_paths(options);
    if (!preflight.ok) {
        return {
            .exit_code = 1,
            .stdout_text = {},
            .stderr_text = preflight.error_text + '\n',
        };
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
    const auto open_result = open_summary_input(adapter, options, stderr_text, environment);
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

    std::ostringstream stdout_builder {};
    stdout_builder << render_basic_summary_text(adapter.get_overview());

    if (options.extended) {
        stdout_builder << render_extended_summary_text(adapter);
    }

    if (options.protocol_path_tree) {
        stdout_builder << '\n'
            << render_protocol_path_preview_text(
                adapter.get_protocol_path_statistics(options.protocol_path_mode),
                options.protocol_path_mode
            );
    }

    if (open_result.partial_open && !open_result.partial_open_warning_text.empty()) {
        stderr_text += open_result.partial_open_warning_text;
        stderr_text += '\n';
    }

    if (options.out_index_path.has_value()) {
        const auto save_result = adapter.save_index(*options.out_index_path);
        if (!save_result.saved) {
            stderr_text += save_result.error_text.empty()
                ? "Failed to write index.\n"
                : save_result.error_text + '\n';
            return {
                .exit_code = 1,
                .stdout_text = stdout_builder.str(),
                .stderr_text = std::move(stderr_text),
            };
        }
        stderr_text += "Index written to: " + save_result.output_path + '\n';
    }

    if (options.out_protocol_path_tree_path.has_value()) {
        const auto export_result = adapter.export_protocol_path_tree(
            options.protocol_path_mode,
            *options.out_protocol_path_tree_path
        );
        if (!export_result.exported) {
            stderr_text += export_result.error_text.empty()
                ? "Failed to export Protocol Path Tree.\n"
                : export_result.error_text + '\n';
            return {
                .exit_code = 1,
                .stdout_text = stdout_builder.str(),
                .stderr_text = std::move(stderr_text),
            };
        }
        stderr_text += "Protocol Path Tree written to: " + export_result.output_path + '\n';
    }

    auto stdout_text = stdout_builder.str();
    if (!stdout_text.empty() && stdout_text.back() != '\n') {
        stdout_text.push_back('\n');
    }

    return {
        .exit_code = 0,
        .stdout_text = std::move(stdout_text),
        .stderr_text = std::move(stderr_text),
    };
}

}  // namespace

bool is_legacy_cli_command_name(const std::string_view name) noexcept {
    return name == "finalize-import" || contains_option(kLegacyCliCommands, name);
}

SummaryDispatchDecision classify_cli_invocation(const std::span<const std::string_view> args) {
    if (args.empty()) {
        return {};
    }

    if (args.front() == "summary") {
        return SummaryDispatchDecision {
            .kind = SummaryDispatchKind::summary,
            .legacy_command = {},
            .summary_args = std::vector<std::string_view>(args.begin() + 1, args.end()),
        };
    }

    if (is_legacy_cli_command_name(args.front())) {
        return SummaryDispatchDecision {
            .kind = SummaryDispatchKind::legacy,
            .legacy_command = args.front(),
            .summary_args = {},
        };
    }

    return SummaryDispatchDecision {
        .kind = SummaryDispatchKind::summary,
        .legacy_command = {},
        .summary_args = std::vector<std::string_view>(args.begin(), args.end()),
    };
}

SummaryCommandParseResult parse_summary_command_arguments(const std::span<const std::string_view> args) {
    SummaryCommandOptions options {};
    bool positional_input_seen = false;
    bool explicit_input_seen = false;
    bool explicit_settings_seen = false;
    bool out_index_seen = false;
    bool out_protocol_path_tree_seen = false;
    bool protocol_path_mode_seen = false;
    bool progress_seen = false;

    for (std::size_t index = 0; index < args.size(); ++index) {
        const auto token = args[index];

        if (token == "--extended") {
            options.extended = true;
            continue;
        }

        if (token == "--protocol-path-tree") {
            options.protocol_path_tree = true;
            continue;
        }

        if (token == "--force") {
            options.force = true;
            continue;
        }

        if (token == "--input") {
            if (explicit_input_seen) {
                return {
                    .ok = false,
                    .options = std::nullopt,
                    .error_text = "Duplicate --input is invalid.",
                };
            }
            if (positional_input_seen) {
                return {
                    .ok = false,
                    .options = std::nullopt,
                    .error_text = "Positional input and --input are mutually exclusive input forms. Using both in the same invocation is invalid.",
                };
            }
            if (index + 1U >= args.size()) {
                return {
                    .ok = false,
                    .options = std::nullopt,
                    .error_text = "--input requires a path.",
                };
            }
            explicit_input_seen = true;
            options.input_path = std::filesystem::path {std::string {args[++index]}};
            continue;
        }

        if (token == "--settings") {
            if (explicit_settings_seen) {
                return {
                    .ok = false,
                    .options = std::nullopt,
                    .error_text = "Duplicate --settings is invalid.",
                };
            }
            if (index + 1U >= args.size()) {
                return {
                    .ok = false,
                    .options = std::nullopt,
                    .error_text = "--settings requires a path.",
                };
            }
            explicit_settings_seen = true;
            options.settings_path = std::filesystem::path {std::string {args[++index]}};
            continue;
        }

        if (token == "--out-index") {
            if (out_index_seen) {
                return {
                    .ok = false,
                    .options = std::nullopt,
                    .error_text = "Duplicate --out-index is invalid.",
                };
            }
            if (index + 1U >= args.size()) {
                return {
                    .ok = false,
                    .options = std::nullopt,
                    .error_text = "--out-index requires a path.",
                };
            }
            out_index_seen = true;
            options.out_index_path = std::filesystem::path {std::string {args[++index]}};
            continue;
        }

        if (token == "--out-protocol-path-tree") {
            if (out_protocol_path_tree_seen) {
                return {
                    .ok = false,
                    .options = std::nullopt,
                    .error_text = "Duplicate --out-protocol-path-tree is invalid.",
                };
            }
            if (index + 1U >= args.size()) {
                return {
                    .ok = false,
                    .options = std::nullopt,
                    .error_text = "--out-protocol-path-tree requires a path.",
                };
            }
            out_protocol_path_tree_seen = true;
            options.out_protocol_path_tree_path = std::filesystem::path {std::string {args[++index]}};
            continue;
        }

        if (token == "--progress") {
            if (progress_seen) {
                return {
                    .ok = false,
                    .options = std::nullopt,
                    .error_text = "Duplicate --progress is invalid.",
                };
            }
            if (index + 1U >= args.size()) {
                return {
                    .ok = false,
                    .options = std::nullopt,
                    .error_text = "--progress requires one of: auto, on, off.",
                };
            }
            const auto mode = parse_progress_mode(args[++index]);
            if (!mode.has_value()) {
                return {
                    .ok = false,
                    .options = std::nullopt,
                    .error_text = "Invalid --progress value. Expected one of: auto, on, off.",
                };
            }
            progress_seen = true;
            options.progress_mode = *mode;
            continue;
        }

        if (token == "--protocol-path-mode") {
            if (index + 1U >= args.size()) {
                return {
                    .ok = false,
                    .options = std::nullopt,
                    .error_text = "--protocol-path-mode requires one of: kind-overview, identity-tree, terminal-paths.",
                };
            }
            const auto mode = parse_protocol_path_mode(args[++index]);
            if (!mode.has_value()) {
                return {
                    .ok = false,
                    .options = std::nullopt,
                    .error_text = "Invalid --protocol-path-mode value. Expected one of: kind-overview, identity-tree, terminal-paths.",
                };
            }
            protocol_path_mode_seen = true;
            options.protocol_path_mode = *mode;
            continue;
        }

        if (!token.empty() && token.front() == '-') {
            if (contains_option(kSummaryInvalidSelectorOptions, token)) {
                return {
                    .ok = false,
                    .options = std::nullopt,
                    .error_text = "summary does not accept " + std::string {token} + "; summary is always whole-capture.",
                };
            }
            if (contains_option(kSummaryUnsupportedOptions, token)) {
                return {
                    .ok = false,
                    .options = std::nullopt,
                    .error_text = std::string {token} + " is not implemented for summary yet.",
                };
            }
            return {
                .ok = false,
                .options = std::nullopt,
                .error_text = "Unknown summary option: " + std::string {token},
            };
        }

        if (explicit_input_seen || positional_input_seen) {
            return {
                .ok = false,
                .options = std::nullopt,
                .error_text = "summary accepts exactly one input path.",
            };
        }

        positional_input_seen = true;
        options.input_path = std::filesystem::path {std::string {token}};
    }

    if (options.input_path.empty()) {
        return {
            .ok = false,
            .options = std::nullopt,
            .error_text = "summary requires an input path.",
        };
    }

    if (protocol_path_mode_seen &&
        !options.protocol_path_tree &&
        !options.out_protocol_path_tree_path.has_value()) {
        return {
            .ok = false,
            .options = std::nullopt,
            .error_text = "--protocol-path-mode is valid only when --protocol-path-tree or --out-protocol-path-tree is also present.",
        };
    }

    return {
        .ok = true,
        .options = options,
        .error_text = {},
    };
}

bool should_enable_summary_progress(
    const SummaryCommandProgressMode mode,
    const bool stderr_is_terminal
) noexcept {
    switch (mode) {
    case SummaryCommandProgressMode::on:
        return true;
    case SummaryCommandProgressMode::off:
        return false;
    case SummaryCommandProgressMode::auto_mode:
    default:
        return stderr_is_terminal;
    }
}

std::string render_protocol_path_preview_text(
    const std::span<const FrontendProtocolPathStatsDto> rows,
    const ProtocolPathStatisticsMode mode,
    const std::size_t max_rows
) {
    constexpr std::string_view layer_header = "Layer";
    constexpr std::string_view flows_header = "Flows";
    constexpr std::string_view packets_header = "Packets";
    constexpr std::string_view original_bytes_header = "Original Bytes";

    const auto row_count = std::min(rows.size(), max_rows);
    std::vector<std::string> layer_cells {};
    layer_cells.reserve(row_count);

    std::size_t layer_width = layer_header.size();
    std::size_t flows_width = flows_header.size();
    std::size_t packets_width = packets_header.size();
    std::size_t original_bytes_width = original_bytes_header.size();

    for (std::size_t index = 0; index < row_count; ++index) {
        const auto& row = rows[index];
        const std::string_view base_text = !row.layer_text.empty()
            ? std::string_view {row.layer_text}
            : std::string_view {row.path_text};
        const auto layer_text = mode == ProtocolPathStatisticsMode::terminal_paths
            ? std::string {base_text}
            : std::string(row.depth * 2U, ' ') + std::string {base_text};
        layer_cells.push_back(layer_text);
        layer_width = std::max(layer_width, layer_text.size());
        flows_width = std::max(flows_width, row.flow_count_text.size());
        packets_width = std::max(packets_width, row.packet_count_text.size());
        original_bytes_width = std::max(original_bytes_width, row.original_byte_count_text.size());
    }

    std::ostringstream out {};
    out << "Protocol Path Tree\n";
    out << "Mode: " << session_detail::protocol_path_statistics_mode_text(mode) << "\n\n";
    out << pad_right(layer_header, layer_width) << "  "
        << pad_left(flows_header, flows_width) << "  "
        << pad_left(packets_header, packets_width) << "  "
        << pad_left(original_bytes_header, original_bytes_width) << '\n';

    for (std::size_t index = 0; index < row_count; ++index) {
        const auto& row = rows[index];
        out << pad_right(layer_cells[index], layer_width) << "  "
            << pad_left(row.flow_count_text, flows_width) << "  "
            << pad_left(row.packet_count_text, packets_width) << "  "
            << pad_left(row.original_byte_count_text, original_bytes_width) << '\n';
    }

    if (rows.size() > max_rows) {
        out << '\n'
            << "... " << (rows.size() - max_rows) << " additional rows not shown.\n"
            << "Use --out-protocol-path-tree <file> to export the complete Protocol Path Tree.\n";
    }

    return out.str();
}

SummaryCommandExecutionResult execute_summary_command(const SummaryCommandOptions& options) {
    return execute_summary_command_with_environment(
        options,
        SummaryExecutionEnvironment {
            .stderr_is_terminal = stderr_supports_interactive_updates(),
        }
    );
}

}  // namespace pfl::cli
