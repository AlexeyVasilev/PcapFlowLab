#include "cli/FlowsCommand.h"

#include <algorithm>
#include <array>
#include <limits>
#include <sstream>
#include <string>
#include <vector>

#include "app/frontend/FrontendSessionAdapter.h"
#include "app/frontend/FrontendSettingsJson.h"
#include "app/session/SessionFlowHelpers.h"
#include "core/index/CaptureIndex.h"

namespace pfl::cli {
namespace {

constexpr std::size_t kDefaultFlowsPreviewLimit = 25U;

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
        const auto cell = columns[index].right_align
            ? pad_left(columns[index].header, widths[index])
            : pad_right(columns[index].header, widths[index]);
        if (index + 1U == columns.size()) {
            out << trim_ascii(cell);
        } else {
            out << cell;
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

std::string render_flows_examples() {
    std::ostringstream out {};
    out << "Examples\n";
    out << "  pcap-flow-lab flows capture.pcap\n";
    out << "  pcap-flow-lab flows capture.idx --filter TLS --sort bytes:desc\n";
    out << "  pcap-flow-lab flows capture.pcap --flow-number 42\n";
    out << "  pcap-flow-lab flows capture.pcap --flow-numbers 1-10,24,31-35\n";
    out << "  pcap-flow-lab flows capture.idx --out-flows-list flows.csv\n";
    return out.str();
}

bool all_ascii_digits(const std::string_view text) noexcept {
    return !text.empty() && std::all_of(text.begin(), text.end(), [](const char ch) {
        return ch >= '0' && ch <= '9';
    });
}

std::optional<std::size_t> parse_positive_size_t(const std::string_view text) noexcept {
    if (!all_ascii_digits(text)) {
        return std::nullopt;
    }

    std::size_t value = 0U;
    for (const auto ch : text) {
        const auto digit = static_cast<std::size_t>(ch - '0');
        if (value > (std::numeric_limits<std::size_t>::max() - digit) / 10U) {
            return std::nullopt;
        }
        value = value * 10U + digit;
    }

    if (value == 0U) {
        return std::nullopt;
    }

    return value;
}

std::optional<std::vector<std::size_t>> parse_flow_number_ranges(const std::string_view text) noexcept {
    if (text.empty()) {
        return std::nullopt;
    }

    std::vector<std::size_t> flow_indices {};
    std::size_t start = 0U;
    while (start < text.size()) {
        const auto comma = text.find(',', start);
        const auto token = text.substr(start, comma == std::string_view::npos ? text.size() - start : comma - start);
        if (token.empty()) {
            return std::nullopt;
        }

        const auto dash = token.find('-');
        if (dash == std::string_view::npos) {
            const auto flow_number = parse_positive_size_t(token);
            if (!flow_number.has_value()) {
                return std::nullopt;
            }
            flow_indices.push_back(*flow_number - 1U);
        } else {
            if (token.find('-', dash + 1U) != std::string_view::npos) {
                return std::nullopt;
            }

            const auto lower_text = token.substr(0U, dash);
            const auto upper_text = token.substr(dash + 1U);
            const auto lower = parse_positive_size_t(lower_text);
            const auto upper = parse_positive_size_t(upper_text);
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

std::optional<session_detail::FlowQuerySortSpec> parse_sort_spec(const std::string_view text) noexcept {
    const auto colon = text.find(':');
    if (colon == std::string_view::npos || colon == 0U || colon + 1U >= text.size()) {
        return std::nullopt;
    }
    if (text.find(':', colon + 1U) != std::string_view::npos) {
        return std::nullopt;
    }

    const auto key_text = text.substr(0U, colon);
    const auto direction_text = text.substr(colon + 1U);

    std::optional<session_detail::FlowQuerySortKey> key {};
    if (key_text == "number") {
        key = session_detail::FlowQuerySortKey::canonical_index;
    } else if (key_text == "protocol") {
        key = session_detail::FlowQuerySortKey::protocol;
    } else if (key_text == "service") {
        key = session_detail::FlowQuerySortKey::service;
    } else if (key_text == "endpoint-a") {
        key = session_detail::FlowQuerySortKey::endpoint_a;
    } else if (key_text == "endpoint-b") {
        key = session_detail::FlowQuerySortKey::endpoint_b;
    } else if (key_text == "packets") {
        key = session_detail::FlowQuerySortKey::packets;
    } else if (key_text == "bytes") {
        key = session_detail::FlowQuerySortKey::bytes;
    } else {
        return std::nullopt;
    }

    std::optional<session_detail::FlowQuerySortDirection> direction {};
    if (direction_text == "asc") {
        direction = session_detail::FlowQuerySortDirection::ascending;
    } else if (direction_text == "desc") {
        direction = session_detail::FlowQuerySortDirection::descending;
    } else {
        return std::nullopt;
    }

    return session_detail::FlowQuerySortSpec {
        .key = *key,
        .direction = *direction,
    };
}

std::string render_flows_table(
    const FrontendSessionAdapter& adapter,
    const std::span<const std::size_t> flow_indices
) {
    std::vector<std::vector<std::string>> rows {};
    rows.reserve(flow_indices.size());

    for (const auto flow_index : flow_indices) {
        const auto row = adapter.flow_row(flow_index);
        if (!row.has_value()) {
            return {};
        }

        rows.push_back({
            session_detail::format_statistics_count_value(flow_index + 1U),
            row->endpoint_a,
            row->endpoint_b,
            row->protocol_text,
            session_detail::format_flow_protocol_hint_display(row->protocol_hint),
            row->service_hint,
            adapter.protocol_path_compact_text(row->protocol_path_id),
            session_detail::format_statistics_count_value(row->packet_count),
            session_detail::format_statistics_compact_size_value(row->total_bytes),
        });
    }

    return render_table(
        {
            {.header = "No.", .right_align = true},
            {.header = "Endpoint A", .right_align = false},
            {.header = "Endpoint B", .right_align = false},
            {.header = "Protocol", .right_align = false},
            {.header = "Protocol Hint", .right_align = false},
            {.header = "Service", .right_align = false},
            {.header = "Path", .right_align = false},
            {.header = "Packets", .right_align = true},
            {.header = "Original Bytes", .right_align = true},
        },
        rows
    );
}

FlowsCommandExecutionResult execute_flows_command_with_environment(
    const FlowsCommandOptions& options,
    const bool stderr_is_terminal
) {
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

    std::array<CliOutputTarget, 1> outputs {{
        CliOutputTarget {
            .label = "--out-flows-list",
            .path = options.out_flows_list_path.value_or(std::filesystem::path {}),
        },
    }};
    const auto output_count = options.out_flows_list_path.has_value() ? std::size_t {1U} : std::size_t {0U};
    const auto preflight = preflight_output_targets(
        options.input_path,
        std::span<const CliOutputTarget>(outputs.data(), output_count),
        options.force
    );
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
    const auto open_result = open_input_with_progress(
        adapter,
        options.input_path,
        options.progress_mode,
        stderr_is_terminal,
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

    session_detail::FlowQuery query {};
    query.selected_flow_indices = options.selected_flow_indices;
    query.text_filter = options.text_filter;
    query.sort = options.sort;
    query.limit = options.limit;

    const auto query_result = adapter.query_flows(query);
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

    const bool explicit_limit_supplied = options.limit.has_value();
    const auto rendered_count = explicit_limit_supplied
        ? query_result.ordered_flow_indices.size()
        : std::min(query_result.ordered_flow_indices.size(), kDefaultFlowsPreviewLimit);
    const auto rendered_rows = std::span<const std::size_t>(
        query_result.ordered_flow_indices.data(),
        rendered_count
    );

    std::ostringstream stdout_builder {};
    stdout_builder << "Flows\n\n";
    if (query_result.ordered_flow_indices.empty()) {
        stdout_builder << "No matching flows.\n";
    } else {
        const auto table = render_flows_table(adapter, rendered_rows);
        if (table.empty()) {
            return {
                .exit_code = 1,
                .stdout_text = {},
                .stderr_text = "Failed to render flow metadata.\n",
            };
        }
        stdout_builder << table;

        const auto count_before_limit = query_result.result_count_before_limit;
        const bool default_preview_truncated =
            !explicit_limit_supplied && count_before_limit > kDefaultFlowsPreviewLimit;

        if (explicit_limit_supplied || default_preview_truncated) {
            stdout_builder << '\n'
                << "Showing "
                << session_detail::format_statistics_count_value(rendered_count)
                << " of "
                << session_detail::format_statistics_count_value(count_before_limit)
                << " flows.\n";
        }

        if (default_preview_truncated) {
            stdout_builder
                << "Use --limit <N> to show more rows or --out-flows-list <path> to export the result.\n";
        }
    }

    if (options.out_flows_list_path.has_value()) {
        const auto export_result = adapter.export_flows_info_csv(
            *options.out_flows_list_path,
            query_result.ordered_flow_indices
        );
        if (!export_result.exported) {
            stderr_text += export_result.error_text.empty()
                ? "Failed to export flows list.\n"
                : export_result.error_text + '\n';
            return {
                .exit_code = 1,
                .stdout_text = stdout_builder.str(),
                .stderr_text = std::move(stderr_text),
            };
        }
        stderr_text += "Flows list written to: " + export_result.output_path + '\n';
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

std::string render_flows_command_help() {
    std::ostringstream out {};
    out << "PcapFlowLab CLI - flows\n\n";
    out << "List, filter, sort, and export flow metadata.\n\n";
    out << "Usage\n";
    out << "  pcap-flow-lab flows <input> [options]\n";
    out << "  pcap-flow-lab flows --input <input> [options]\n\n";
    out << "Input and import\n";
    out << "  --input <path>\n";
    out << "  --settings <settings.json>\n";
    out << "    Applies to raw capture import and is invalid for index input.\n\n";
    out << "Selection\n";
    out << "  --flow-number <N>\n";
    out << "  --flow-numbers <ranges>\n";
    out << "  --filter <text>\n";
    out << "  --sort <number|protocol|service|endpoint-a|endpoint-b|packets|bytes>:<asc|desc>\n";
    out << "  --limit <N>\n\n";
    out << "Output\n";
    out << "  --out-flows-list <path>\n\n";
    out << "Runtime\n";
    out << "  --progress <auto|on|off>\n";
    out << "  --force\n\n";
    out << "Help\n";
    out << "  -h, --help\n\n";
    out << "Notes\n";
    out << "  Flow numbers are one-based canonical identities.\n";
    out << "  stdout shows a default preview of 25 rows when --limit is not supplied.\n";
    out << "  Example range: 1-10,24,31-35\n\n";
    out << render_flows_examples();
    return out.str();
}

FlowsCommandParseResult parse_flows_command_arguments(const std::span<const std::string_view> args) {
    FlowsCommandOptions options {};
    bool positional_input_seen = false;
    bool explicit_input_seen = false;
    bool explicit_settings_seen = false;
    bool flow_number_seen = false;
    bool flow_numbers_seen = false;
    bool filter_seen = false;
    bool sort_seen = false;
    bool limit_seen = false;
    bool out_flows_list_seen = false;
    bool progress_seen = false;

    for (std::size_t index = 0U; index < args.size(); ++index) {
        const auto token = args[index];

        if (token == "--force") {
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

        if (token == "--flow-number") {
            if (flow_number_seen) {
                return {.ok = false, .options = std::nullopt, .error_text = "Duplicate --flow-number is invalid."};
            }
            if (flow_numbers_seen) {
                return {.ok = false, .options = std::nullopt, .error_text = "--flow-number and --flow-numbers are mutually exclusive."};
            }
            if (index + 1U >= args.size()) {
                return {.ok = false, .options = std::nullopt, .error_text = "--flow-number requires a positive one-based flow number."};
            }
            const auto flow_number = parse_positive_size_t(args[++index]);
            if (!flow_number.has_value()) {
                return {.ok = false, .options = std::nullopt, .error_text = "Invalid --flow-number value. Expected a positive one-based flow number."};
            }
            flow_number_seen = true;
            options.selected_flow_indices = std::vector<std::size_t> {*flow_number - 1U};
            continue;
        }

        if (token == "--flow-numbers") {
            if (flow_numbers_seen) {
                return {.ok = false, .options = std::nullopt, .error_text = "Duplicate --flow-numbers is invalid."};
            }
            if (flow_number_seen) {
                return {.ok = false, .options = std::nullopt, .error_text = "--flow-number and --flow-numbers are mutually exclusive."};
            }
            if (index + 1U >= args.size()) {
                return {.ok = false, .options = std::nullopt, .error_text = "--flow-numbers requires one or more positive one-based ranges."};
            }
            const auto parsed = parse_flow_number_ranges(args[++index]);
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
            if (index + 1U >= args.size()) {
                return {.ok = false, .options = std::nullopt, .error_text = "--filter requires a text query."};
            }
            filter_seen = true;
            options.text_filter = std::string {args[++index]};
            continue;
        }

        if (token == "--sort") {
            if (sort_seen) {
                return {.ok = false, .options = std::nullopt, .error_text = "Duplicate --sort is invalid."};
            }
            if (index + 1U >= args.size()) {
                return {.ok = false, .options = std::nullopt, .error_text = "--sort requires <field>:<asc|desc>."};
            }
            const auto sort = parse_sort_spec(args[++index]);
            if (!sort.has_value()) {
                return {.ok = false, .options = std::nullopt, .error_text = "Invalid --sort value. Expected one of: number, protocol, service, endpoint-a, endpoint-b, packets, bytes with :asc or :desc."};
            }
            sort_seen = true;
            options.sort = *sort;
            continue;
        }

        if (token == "--limit") {
            if (limit_seen) {
                return {.ok = false, .options = std::nullopt, .error_text = "Duplicate --limit is invalid."};
            }
            if (index + 1U >= args.size()) {
                return {.ok = false, .options = std::nullopt, .error_text = "--limit requires a positive flow count."};
            }
            const auto limit = parse_positive_size_t(args[++index]);
            if (!limit.has_value()) {
                return {.ok = false, .options = std::nullopt, .error_text = "Invalid --limit value. Expected a positive flow count."};
            }
            limit_seen = true;
            options.limit = *limit;
            continue;
        }

        if (token == "--out-flows-list") {
            if (out_flows_list_seen) {
                return {.ok = false, .options = std::nullopt, .error_text = "Duplicate --out-flows-list is invalid."};
            }
            if (index + 1U >= args.size()) {
                return {.ok = false, .options = std::nullopt, .error_text = "--out-flows-list requires a path."};
            }
            out_flows_list_seen = true;
            options.out_flows_list_path = std::filesystem::path {std::string {args[++index]}};
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
            if (token == "--source-capture" || token == "--format" || token == "--columns") {
                return {
                    .ok = false,
                    .options = std::nullopt,
                    .error_text = std::string {token} + " is not implemented for flows."
                };
            }
            return {
                .ok = false,
                .options = std::nullopt,
                .error_text = "Unknown flows option: " + std::string {token}
            };
        }

        if (explicit_input_seen || positional_input_seen) {
            return {.ok = false, .options = std::nullopt, .error_text = "flows accepts exactly one input path."};
        }

        positional_input_seen = true;
        options.input_path = std::filesystem::path {std::string {token}};
    }

    if (options.input_path.empty()) {
        return {.ok = false, .options = std::nullopt, .error_text = "flows requires an input path."};
    }

    return {
        .ok = true,
        .options = options,
        .error_text = {},
    };
}

FlowsCommandExecutionResult execute_flows_command(const FlowsCommandOptions& options) {
    return execute_flows_command_with_environment(options, stderr_supports_interactive_updates());
}

}  // namespace pfl::cli
