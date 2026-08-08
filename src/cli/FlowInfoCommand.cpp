#include "cli/FlowInfoCommand.h"

#include <algorithm>
#include <sstream>
#include <string>
#include <vector>

#include "app/frontend/FrontendSessionAdapter.h"
#include "app/frontend/FrontendSettingsJson.h"
#include "app/session/SessionFlowHelpers.h"
#include "core/index/CaptureIndex.h"

namespace pfl::cli {
namespace {

struct TableColumn {
    std::string header {};
    bool right_align {false};
};

std::string trim_ascii(const std::string_view text) {
    std::size_t start = 0U;
    while (start < text.size() && text[start] == ' ') {
        ++start;
    }

    std::size_t end = text.size();
    while (end > start && text[end - 1U] == ' ') {
        --end;
    }

    return std::string {text.substr(start, end - start)};
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
        for (std::size_t index = 0U; index < columns.size() && index < row.size(); ++index) {
            widths[index] = std::max(widths[index], row[index].size());
        }
    }

    std::ostringstream out {};
    for (std::size_t index = 0U; index < columns.size(); ++index) {
        if (index > 0U) {
            out << "  ";
        }
        const auto padded = columns[index].right_align
            ? pad_left(columns[index].header, widths[index])
            : pad_right(columns[index].header, widths[index]);
        if (index + 1U == columns.size()) {
            out << trim_ascii(padded);
        } else {
            out << padded;
        }
    }
    out << '\n';

    for (const auto& row : rows) {
        for (std::size_t index = 0U; index < columns.size(); ++index) {
            if (index > 0U) {
                out << "  ";
            }
            const std::string_view cell = index < row.size() ? std::string_view {row[index]} : std::string_view {};
            const auto padded = columns[index].right_align ? pad_left(cell, widths[index]) : pad_right(cell, widths[index]);
            if (index + 1U == columns.size()) {
                out << trim_ascii(padded);
            } else {
                out << padded;
            }
        }
        out << '\n';
    }

    return out.str();
}

void append_key_value_line(
    std::ostringstream& out,
    const std::string_view key,
    const std::string_view value
) {
    out << key << ": " << value << '\n';
}

std::string render_flow_info_report(const FrontendFlowInfoDto& info) {
    std::ostringstream out {};
    out << "Flow " << (info.flow_index + 1U) << "\n\n";

    out << "Identity\n";
    append_key_value_line(out, "Endpoints", info.endpoint_summary_text);
    append_key_value_line(out, "Family", info.family_text);
    append_key_value_line(out, "Protocol", info.protocol_text);
    append_key_value_line(out, "Protocol Hint", info.protocol_hint_display);
    append_key_value_line(out, "Service", info.service_hint_text.empty() ? std::string_view {"-"} : std::string_view {info.service_hint_text});
    append_key_value_line(out, "Protocol Path", info.protocol_path_text.empty() ? std::string_view {"-"} : std::string_view {info.protocol_path_text});
    out << '\n';

    out << "Traffic\n";
    append_key_value_line(out, "Packets", info.total_packets_text);
    append_key_value_line(out, "Original Bytes", info.total_bytes_text);
    append_key_value_line(out, "Captured Bytes", info.captured_bytes_text);
    append_key_value_line(out, "Max Captured Packet Size", info.max_captured_packet_size_text);
    out << '\n';

    out << "Direction\n";
    out << render_table(
        {
            {.header = "Metric", .right_align = false},
            {.header = "A->B", .right_align = true},
            {.header = "B->A", .right_align = true},
            {.header = "Total", .right_align = true},
        },
        {
            {
                "Packets",
                info.packets_a_to_b_text,
                info.packets_b_to_a_text,
                info.total_direction_packets_text,
            },
            {
                "Original Bytes",
                info.bytes_a_to_b_text,
                info.bytes_b_to_a_text,
                info.total_direction_bytes_text,
            },
        }
    );
    append_key_value_line(out, "Packet Direction", info.packet_direction_text);
    append_key_value_line(out, "Data Direction", info.data_direction_text);
    out << '\n';

    out << "Packet Size Histogram\n";
    std::vector<std::vector<std::string>> histogram_rows {};
    histogram_rows.reserve(info.packet_size_histogram_rows.size());
    for (const auto& row : info.packet_size_histogram_rows) {
        histogram_rows.push_back({
            row.bucket_label,
            session_detail::format_statistics_count_value(row.count_all),
            session_detail::format_statistics_count_value(row.count_a_to_b),
            session_detail::format_statistics_count_value(row.count_b_to_a),
        });
    }
    out << render_table(
        {
            {.header = "Bucket", .right_align = false},
            {.header = "All", .right_align = true},
            {.header = "A -> B", .right_align = true},
            {.header = "B -> A", .right_align = true},
        },
        histogram_rows
    );
    out << '\n';

    out << "Timing\n";
    append_key_value_line(out, "First Packet", info.first_packet_time_text);
    append_key_value_line(out, "Last Packet", info.last_packet_time_text);
    append_key_value_line(out, "Duration", info.duration_text);
    append_key_value_line(out, "Largest Gap", info.largest_gap_text);
    return out.str();
}

}  // namespace

std::string render_flow_info_command_help() {
    std::ostringstream out {};
    out << "PcapFlowLab CLI - flow-info\n\n";
    out << "Show detailed analysis for exactly one canonical flow.\n\n";
    out << "Usage\n";
    out << "  pcap-flow-lab flow-info <input> --flow-number <N> [options]\n";
    out << "  pcap-flow-lab flow-info --input <input> --flow-number <N> [options]\n\n";
    out << "Input and selection\n";
    out << "  --input <path>\n";
    out << "  --flow-number <N>\n";
    out << "  --settings <settings.json>\n";
    out << "    Applies to raw capture import and is invalid for index input.\n\n";
    out << "Runtime\n";
    out << "  --progress <auto|on|off>\n\n";
    out << "Help\n";
    out << "  -h, --help\n\n";
    out << "Examples\n";
    out << "  pcap-flow-lab flow-info capture.pcap --flow-number 42\n";
    out << "  pcap-flow-lab flow-info --input capture.idx --flow-number 7\n";
    out << "  pcap-flow-lab flow-info capture.pcap --flow-number 42 --settings settings.json\n";
    return out.str();
}

FlowInfoCommandParseResult parse_flow_info_command_arguments(const std::span<const std::string_view> args) {
    FlowInfoCommandOptions options {};
    bool positional_input_seen = false;
    bool explicit_input_seen = false;
    bool settings_seen = false;
    bool flow_number_seen = false;
    bool progress_seen = false;

    for (std::size_t index = 0U; index < args.size(); ++index) {
        const auto token = args[index];

        if (token == "--input") {
            if (explicit_input_seen) {
                return {.ok = false, .options = std::nullopt, .error_text = "Duplicate --input is invalid."};
            }
            if (positional_input_seen) {
                return {
                    .ok = false,
                    .options = std::nullopt,
                    .error_text = "Positional input and --input are mutually exclusive input forms. Using both in the same invocation is invalid.",
                };
            }
            if (index + 1U >= args.size()) {
                return {.ok = false, .options = std::nullopt, .error_text = "--input requires a path."};
            }
            explicit_input_seen = true;
            options.input_path = std::filesystem::path {std::string {args[++index]}};
            continue;
        }

        if (token == "--flow-number") {
            if (flow_number_seen) {
                return {.ok = false, .options = std::nullopt, .error_text = "Duplicate --flow-number is invalid."};
            }
            if (index + 1U >= args.size()) {
                return {.ok = false, .options = std::nullopt, .error_text = "--flow-number requires a positive 1-based value."};
            }
            const auto flow_index = parse_cli_flow_number(args[++index]);
            if (!flow_index.has_value()) {
                return {.ok = false, .options = std::nullopt, .error_text = "--flow-number requires a positive 1-based value."};
            }
            flow_number_seen = true;
            options.flow_index = *flow_index;
            continue;
        }

        if (token == "--settings") {
            if (settings_seen) {
                return {.ok = false, .options = std::nullopt, .error_text = "Duplicate --settings is invalid."};
            }
            if (index + 1U >= args.size()) {
                return {.ok = false, .options = std::nullopt, .error_text = "--settings requires a path."};
            }
            settings_seen = true;
            options.settings_path = std::filesystem::path {std::string {args[++index]}};
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
            if (token == "--flow-numbers") {
                return {.ok = false, .options = std::nullopt, .error_text = "flow-info accepts exactly one canonical flow via --flow-number."};
            }
            if (token == "--filter" || token == "--sort" || token == "--limit" ||
                token == "--packets-in-flow" || token == "--packets-in-file") {
                return {.ok = false, .options = std::nullopt, .error_text = "flow-info does not accept " + std::string {token} + '.'};
            }
            if (token == "--source-capture" || token == "--format" || token == "--columns" || token == "--out") {
                return {.ok = false, .options = std::nullopt, .error_text = "flow-info does not accept " + std::string {token} + '.'};
            }
            return {.ok = false, .options = std::nullopt, .error_text = "Unknown flow-info option: " + std::string {token}};
        }

        if (explicit_input_seen || positional_input_seen) {
            return {.ok = false, .options = std::nullopt, .error_text = "flow-info accepts exactly one input path."};
        }

        positional_input_seen = true;
        options.input_path = std::filesystem::path {std::string {token}};
    }

    if (options.input_path.empty()) {
        return {.ok = false, .options = std::nullopt, .error_text = "flow-info requires an input path."};
    }
    if (!flow_number_seen) {
        return {.ok = false, .options = std::nullopt, .error_text = "flow-info requires exactly one --flow-number value."};
    }

    return {
        .ok = true,
        .options = options,
        .error_text = {},
    };
}

FlowInfoCommandExecutionResult execute_flow_info_command(const FlowInfoCommandOptions& options) {
    const bool input_looks_like_index = looks_like_index_file(options.input_path);
    if (input_looks_like_index && options.settings_path.has_value()) {
        return {
            .exit_code = 1,
            .stdout_text = {},
            .stderr_text = "--settings is valid only for raw capture input.\n",
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

    FrontendSettingsDto settings {};
    if (options.settings_path.has_value()) {
        const auto parse_result = parse_frontend_settings_json_file(*options.settings_path);
        if (!parse_result.ok) {
            return {
                .exit_code = 1,
                .stdout_text = {},
                .stderr_text = parse_result.error_text + '\n',
            };
        }
        settings = parse_result.settings;
    }

    FrontendSessionAdapter adapter {};
    if (options.settings_path.has_value()) {
        [[maybe_unused]] const auto updated_settings = adapter.update_settings(settings);
    }

    std::string stderr_text {};
    const auto open_result = open_input_with_progress(
        adapter,
        options.input_path,
        options.progress_mode,
        stderr_supports_interactive_updates(),
        stderr_text
    );
    if (!open_result.opened) {
        if (!open_result.error_text.empty()) {
            stderr_text += open_result.error_text;
            if (stderr_text.empty() || stderr_text.back() != '\n') {
                stderr_text.push_back('\n');
            }
        }
        return {
            .exit_code = 1,
            .stdout_text = {},
            .stderr_text = std::move(stderr_text),
        };
    }

    if (open_result.partial_open && !open_result.partial_open_warning_text.empty()) {
        if (!stderr_text.empty() && stderr_text.back() != '\n') {
            stderr_text.push_back('\n');
        }
        stderr_text += open_result.partial_open_warning_text;
        if (stderr_text.back() != '\n') {
            stderr_text.push_back('\n');
        }
    }

    const auto info = adapter.get_flow_info(options.flow_index);
    if (!info.has_capture) {
        return {
            .exit_code = 1,
            .stdout_text = {},
            .stderr_text = info.error_text.empty() ? "No capture is open.\n" : info.error_text + '\n',
        };
    }
    if (!info.flow_available) {
        std::ostringstream out {};
        out << "Flow " << (options.flow_index + 1U) << " is out of range for this input.\n";
        return {
            .exit_code = 1,
            .stdout_text = {},
            .stderr_text = out.str(),
        };
    }
    if (!info.analysis_available) {
        const auto error_text = !info.unavailable_text.empty() ? info.unavailable_text : info.error_text;
        return {
            .exit_code = 1,
            .stdout_text = {},
            .stderr_text = error_text.empty() ? "Analysis is unavailable for the requested flow.\n" : error_text + '\n',
        };
    }

    return {
        .exit_code = 0,
        .stdout_text = render_flow_info_report(info),
        .stderr_text = std::move(stderr_text),
    };
}

}  // namespace pfl::cli
