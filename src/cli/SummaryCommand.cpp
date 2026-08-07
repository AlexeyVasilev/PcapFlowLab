#include "cli/SummaryCommand.h"

#include <algorithm>
#include <array>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "app/frontend/FrontendSessionAdapter.h"
#include "app/session/ProtocolPathTextExport.h"
#include "app/session/SessionFlowHelpers.h"

namespace pfl::cli {
namespace {

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

constexpr std::array<std::string_view, 7> kSummaryUnsupportedOptions {
    "--settings",
    "--out-index",
    "--out-flows-list",
    "--out-protocol-path-tree",
    "--progress",
    "--force",
    "--format",
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

bool contains_option(
    const std::span<const std::string_view> options,
    const std::string_view candidate
) noexcept {
    return std::find(options.begin(), options.end(), candidate) != options.end();
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
    bool protocol_path_mode_seen = false;

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

    if (protocol_path_mode_seen && !options.protocol_path_tree) {
        return {
            .ok = false,
            .options = std::nullopt,
            .error_text = "--protocol-path-mode is valid only when --protocol-path-tree is also present.",
        };
    }

    return {
        .ok = true,
        .options = options,
        .error_text = {},
    };
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
    FrontendSessionAdapter adapter {};
    const auto open_result = adapter.open_capture(options.input_path);
    if (!open_result.opened) {
        return {
            .exit_code = 1,
            .stdout_text = {},
            .stderr_text = open_result.error_text.empty()
                ? "Failed to open input: " + options.input_path.string() + '\n'
                : open_result.error_text + '\n',
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

    auto stdout_text = stdout_builder.str();
    if (!stdout_text.empty() && stdout_text.back() != '\n') {
        stdout_text.push_back('\n');
    }

    std::string stderr_text {};
    if (open_result.partial_open && !open_result.partial_open_warning_text.empty()) {
        stderr_text = open_result.partial_open_warning_text + '\n';
    }

    return {
        .exit_code = 0,
        .stdout_text = std::move(stdout_text),
        .stderr_text = std::move(stderr_text),
    };
}

}  // namespace pfl::cli
