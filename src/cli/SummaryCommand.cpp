#include "cli/SummaryCommand.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <ctime>
#include <fstream>
#include <optional>
#include <sstream>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#include "app/frontend/FrontendSessionAdapter.h"
#include "app/frontend/FrontendStatisticsOverview.h"
#include "app/frontend/FrontendStatisticsReport.h"
#include "app/frontend/FrontendSettingsJson.h"
#include "app/session/ProtocolPathTextExport.h"
#include "app/session/SessionFlowHelpers.h"
#include "cli/ExportFlowsCommand.h"
#include "cli/FlowInfoCommand.h"
#include "cli/FlowsCommand.h"
#include "cli/PacketInfoCommand.h"
#include "../../core/open_context.h"
#include "core/domain/CaptureStatisticsSnapshot.h"
#include "core/index/CaptureIndex.h"
#include "core/index/CaptureIndexReader.h"

#ifndef PFL_APP_VERSION
#define PFL_APP_VERSION "0.0.0"
#endif

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

constexpr std::array<std::string_view, 2> kSummaryUnsupportedOptions {
    "--format",
    "--source-capture",
};

constexpr std::array<std::string_view, 2> kHelpOptions {
    "-h",
    "--help",
};

constexpr std::string_view kSharedUnavailableText {"—"};
constexpr std::string_view kCliUnavailableText {"-"};
constexpr std::size_t kStatisticsReportTopEndpointPortLimit =
    kCaptureStatisticsSnapshotTopEndpointCapacity;

struct TableColumn {
    std::string header {};
    bool right_align {false};
};

struct OutputPreflightResult {
    bool ok {false};
    std::string error_text {};
};

struct SummaryStatisticsDtos {
    FrontendCapturePacketSizeStatisticsDto packet_size_statistics {};
    FrontendFlowPacketCountHistogramDto flow_packet_count_histogram {};
    FrontendProtocolHintStatisticsDto protocol_hint_statistics {};
    FrontendQuicTlsStatisticsDto quic_tls_statistics {};
    FrontendTopEndpointPortStatisticsDto top_endpoint_port_statistics {};
};

std::string render_command_list() {
    std::ostringstream out {};
    out << "Commands\n";
    out << "  summary             Show whole-capture or whole-index overview and statistics.\n";
    out << "  flows               List, filter, sort, and export flow metadata.\n";
    out << "  export-flows        Export packet data for selected canonical flows.\n";
    out << "  flow-info           Show detailed analysis for exactly one canonical flow.\n";
    out << "  packet-info         Inspect exactly one captured packet.\n";
    return out.str();
}

std::string cli_table_text(const std::string_view text) {
    return text == kSharedUnavailableText
        ? std::string {kCliUnavailableText}
        : std::string {text};
}

std::string_view canonicalize_cli_command_name(const std::string_view command) noexcept {
    if (command == "flow") {
        return "flows";
    }
    if (command == "export-flow") {
        return "export-flows";
    }
    if (command == "flows-info") {
        return "flow-info";
    }
    if (command == "packets-info") {
        return "packet-info";
    }
    return command;
}

std::string render_summary_examples() {
    std::ostringstream out {};
    out << "Examples\n";
    out << "  pcap-flow-lab capture.pcap\n";
    out << "  pcap-flow-lab summary capture.pcap --extended\n";
    out << "  pcap-flow-lab summary capture.pcap --out-flows-list flows.csv\n";
    out << "  pcap-flow-lab summary capture.idx --protocol-path-tree --protocol-path-mode identity-tree\n";
    out << "  pcap-flow-lab summary capture.pcap --out-index capture.pflidx\n";
    out << "  pcap-flow-lab summary capture.idx --out-protocol-path-tree protocol-path.txt\n";
    out << "  pcap-flow-lab summary capture.idx --out-statistics-html statistics.html\n";
    out << "  pcap-flow-lab summary capture.idx --out-statistics-markdown statistics.md\n";
    return out.str();
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

template <std::size_t N>
std::size_t longest_label_width(const std::array<std::string_view, N>& labels) {
    std::size_t width = 0U;
    for (const auto label : labels) {
        width = std::max(width, label.size() + 3U);
    }
    return width;
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

std::string render_basic_summary_text(
    const FrontendOverviewDto& overview,
    const bool render_source_capture_availability = true
) {
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
    constexpr std::array<std::string_view, 3> capture_time_labels {
        "Start",
        "End",
        "Duration",
    };

    const auto input_label_width = longest_label_width(input_labels);
    const auto capture_label_width = longest_label_width(capture_labels);
    const auto capture_time_label_width = longest_label_width(capture_time_labels);

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
        if (render_source_capture_availability && !overview.input_metadata.source_capture_accessible) {
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

    out << "\nCapture Time\n";
    append_key_value_line(out, "Start", overview.capture_time.capture_start_text, capture_time_label_width);
    append_key_value_line(out, "End", overview.capture_time.capture_end_text, capture_time_label_width);
    append_key_value_line(out, "Duration", overview.capture_time.duration_text, capture_time_label_width);

    if (!overview.statistics_partial_open_warning_text.empty()) {
        out << "\nWarning\n";
        out << "  " << overview.statistics_partial_open_warning_text << '\n';
    }

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

SummaryStatisticsDtos build_summary_statistics_dtos(
    const FrontendSessionAdapter& adapter,
    const std::size_t top_endpoint_port_limit = 5U
) {
    return SummaryStatisticsDtos {
        .packet_size_statistics = adapter.get_capture_packet_size_statistics(),
        .flow_packet_count_histogram = adapter.get_flow_packet_count_histogram(),
        .protocol_hint_statistics = adapter.get_protocol_hint_statistics(),
        .quic_tls_statistics = adapter.get_quic_tls_statistics(),
        .top_endpoint_port_statistics = adapter.get_top_endpoint_port_statistics(top_endpoint_port_limit),
    };
}

CaptureSourceInfo source_info_from_stable_header(const detail::CaptureIndexStableHeader& header) {
    return CaptureSourceInfo {
        .capture_path = detail::filesystem_path_from_generic_utf8(header.source_capture_path_utf8),
        .format = header.source_format,
        .file_size = header.source_file_size,
        .last_write_time = header.source_last_write_time,
        .content_fingerprint = header.source_content_fingerprint,
    };
}

std::uint64_t file_size_or_zero(const std::filesystem::path& path) {
    std::error_code error {};
    const auto size = std::filesystem::file_size(path, error);
    return error ? 0U : static_cast<std::uint64_t>(size);
}

FrontendOpenProgressDto make_fast_v16_summary_progress_dto(
    const std::filesystem::path& input_path,
    const OpenProgress& progress,
    const bool in_progress
) {
    return FrontendOpenProgressDto {
        .in_progress = in_progress,
        .opening_as_index = true,
        .packets_processed = progress.packets_processed,
        .bytes_processed = progress.bytes_processed,
        .total_bytes = progress.total_bytes,
        .percent = std::clamp(progress.percent(), 0.0, 1.0),
        .input_path = input_path.string(),
    };
}

void emit_summary_progress_line(
    const CliRuntimeEnvironment& environment,
    const bool interactive,
    const std::string& line,
    std::string& last_line,
    std::size_t& last_visible_length,
    bool& emitted_progress
) {
    if (line == last_line) {
        return;
    }

    if (interactive) {
        environment.progress_sink(render_interactive_progress_update(line, last_visible_length));
        last_visible_length = line.size();
    } else {
        environment.progress_sink(line + '\n');
    }

    last_line = line;
    emitted_progress = true;
}

void emit_fast_v16_summary_progress_completion(
    const std::filesystem::path& input_path,
    const CliRuntimeEnvironment& environment,
    const bool interactive,
    const OpenProgress& progress,
    std::string& last_line,
    std::size_t& last_visible_length,
    bool& emitted_progress
) {
    auto completion_progress = progress;
    if (completion_progress.total_bytes > 0U) {
        completion_progress.bytes_processed =
            std::max(completion_progress.bytes_processed, completion_progress.total_bytes);
    }
    const auto final_line = render_open_progress_text(
        make_fast_v16_summary_progress_dto(input_path, completion_progress, false)
    );
    emit_summary_progress_line(
        environment,
        interactive,
        final_line,
        last_line,
        last_visible_length,
        emitted_progress
    );
}

FrontendProtocolStatsDto make_frontend_protocol_stats(const ProtocolStats& stats) {
    return FrontendProtocolStatsDto {
        .flow_count = stats.flow_count,
        .packet_count = stats.packet_count,
        .captured_bytes = stats.captured_bytes,
        .captured_bytes_text = session_detail::format_statistics_compact_size_value(stats.captured_bytes),
        .original_bytes = stats.original_bytes,
        .original_bytes_text = session_detail::format_statistics_compact_size_value(stats.original_bytes),
    };
}

CaptureProtocolPathSummary build_fast_protocol_path_summary(
    const detail::CaptureIndexV16FastStatisticsTier& tier,
    const ProtocolPathStatisticsMode mode
) {
    return session_detail::build_protocol_path_summary_from_display_statistics(
        tier.protocol_path_registry,
        tier.protocol_path_display_statistics,
        tier.capture_statistics_snapshot.total_flow_count,
        tier.capture_statistics_snapshot.total_packet_count,
        tier.capture_statistics_snapshot.total_original_bytes,
        mode
    );
}

FrontendOverviewDto build_fast_v16_overview(
    const std::filesystem::path& index_path,
    const std::uint64_t index_file_size,
    const detail::CaptureIndexStableHeader& header,
    const detail::CaptureIndexV16FastStatisticsTier& tier
) {
    const auto& snapshot = tier.capture_statistics_snapshot;
    const auto packet_statistics = session_detail::project_packet_statistics_from_snapshot(snapshot);
    const auto general_statistics = session_detail::project_general_statistics_from_snapshot(snapshot);
    const AnalysisSettings analysis_settings {};
    const auto protocol_summary =
        session_detail::project_protocol_summary(general_statistics, analysis_settings.use_possible_tls_quic);
    const auto source_info = source_info_from_stable_header(header);
    const auto captured_bytes = protocol_summary.tcp.captured_bytes + protocol_summary.udp.captured_bytes +
        protocol_summary.sctp.captured_bytes + protocol_summary.other.captured_bytes;
    const auto original_bytes = protocol_summary.tcp.original_bytes + protocol_summary.udp.original_bytes +
        protocol_summary.sctp.original_bytes + protocol_summary.other.original_bytes;

    FrontendInputMetadataDto input_metadata {
        .input_path = index_path.string(),
        .input_kind = FrontendInputKind::pcap_flow_lab_index,
        .input_file_size = index_file_size,
        .source_capture_accessible = false,
    };
    if (!header.source_capture_path_utf8.empty()) {
        input_metadata.source_capture_path = source_info.capture_path.string();
    }

    return FrontendOverviewDto {
        .has_capture = true,
        .summary = FrontendOverviewSummaryDto {
            .packet_count = snapshot.total_packet_count,
            .flow_count = snapshot.total_flow_count,
            .captured_bytes = captured_bytes,
            .captured_bytes_text = session_detail::format_statistics_compact_size_value(captured_bytes),
            .original_bytes = original_bytes,
            .original_bytes_text = session_detail::format_statistics_compact_size_value(original_bytes),
            .total_bytes = snapshot.total_original_bytes,
        },
        .whole_capture_totals = FrontendWholeCaptureTotalsDto {
            .packet_count = snapshot.total_packet_count,
            .captured_bytes = snapshot.total_captured_bytes,
            .captured_bytes_text = session_detail::format_statistics_compact_size_value(snapshot.total_captured_bytes),
            .original_bytes = snapshot.total_original_bytes,
            .original_bytes_text = session_detail::format_statistics_compact_size_value(snapshot.total_original_bytes),
        },
        .input_metadata = std::move(input_metadata),
        .capture_time = build_frontend_capture_time_statistics(packet_statistics),
        .capture_metrics = build_frontend_capture_metrics(packet_statistics),
        .flow_characteristics = build_frontend_flow_characteristics(general_statistics.flow_characteristics),
        .packet_direction_distribution = build_frontend_packet_direction_distribution(
            general_statistics.flow_characteristics,
            general_statistics.packet_direction_distribution
        ),
        .original_byte_direction_distribution = build_frontend_original_byte_direction_distribution(
            general_statistics.flow_characteristics,
            general_statistics.original_byte_direction_distribution
        ),
        .tcp_flag_statistics = build_frontend_tcp_flag_statistics(
            general_statistics.tcp_flags,
            protocol_summary.tcp.packet_count
        ),
        .statistics_partial_open_warning_text =
            build_frontend_statistics_partial_open_warning_text(snapshot.scope == CaptureStatisticsScope::partial),
        .captured_bytes = captured_bytes,
        .original_bytes = original_bytes,
        .unrecognized_packet_count = snapshot.unrecognized_packet_count,
        .unrecognized_packets = snapshot.unrecognized_packet_count > 0U
            ? std::optional<FrontendUnrecognizedPacketStatisticsDto> {
                FrontendUnrecognizedPacketStatisticsDto {
                    .packet_count = snapshot.unrecognized_packet_count,
                    .captured_bytes = snapshot.unrecognized_captured_bytes,
                    .captured_bytes_text =
                        session_detail::format_statistics_compact_size_value(snapshot.unrecognized_captured_bytes),
                    .original_bytes = snapshot.unrecognized_original_bytes,
                    .original_bytes_text =
                        session_detail::format_statistics_compact_size_value(snapshot.unrecognized_original_bytes),
                }
            }
            : std::nullopt,
        .protocol_summary = FrontendOverviewProtocolSummaryDto {
            .tcp = make_frontend_protocol_stats(protocol_summary.tcp),
            .udp = make_frontend_protocol_stats(protocol_summary.udp),
            .sctp = make_frontend_protocol_stats(protocol_summary.sctp),
            .other = make_frontend_protocol_stats(protocol_summary.other),
            .ipv4 = make_frontend_protocol_stats(protocol_summary.ipv4),
            .ipv6 = make_frontend_protocol_stats(protocol_summary.ipv6),
        },
        .protocol_path_statistics_default_mode = ProtocolPathStatisticsMode::kind_overview,
    };
}

SummaryStatisticsDtos build_fast_v16_summary_statistics_dtos(
    const detail::CaptureIndexV16FastStatisticsTier& tier,
    const std::size_t top_endpoint_port_limit = 5U
) {
    const auto packet_statistics =
        session_detail::project_packet_statistics_from_snapshot(tier.capture_statistics_snapshot);
    const auto general_statistics =
        session_detail::project_general_statistics_from_snapshot(tier.capture_statistics_snapshot);
    const AnalysisSettings analysis_settings {};
    const auto protocol_summary =
        session_detail::project_protocol_summary(general_statistics, analysis_settings.use_possible_tls_quic);
    const auto top_summary =
        session_detail::slice_top_summary(general_statistics.top_summary, top_endpoint_port_limit);

    return SummaryStatisticsDtos {
        .packet_size_statistics = build_frontend_capture_packet_size_statistics(packet_statistics),
        .flow_packet_count_histogram =
            build_frontend_flow_packet_count_histogram(general_statistics.flow_packet_count_histogram),
        .protocol_hint_statistics = build_frontend_protocol_hint_statistics(protocol_summary),
        .quic_tls_statistics = FrontendQuicTlsStatisticsDto {
            .has_capture = true,
            .quic_recognition = general_statistics.quic_tls_summary.quic,
            .tls_recognition = general_statistics.quic_tls_summary.tls,
        },
        .top_endpoint_port_statistics = FrontendTopEndpointPortStatisticsDto {
            .has_capture = true,
            .limit = top_endpoint_port_limit,
            .top_endpoints = build_frontend_top_endpoints(top_summary),
            .top_ports = build_frontend_top_ports(top_summary),
            .top_flows = build_frontend_top_flows(
                std::span<const TopFlowRow>(
                    top_summary.flows_by_original_bytes.data(),
                    top_summary.flows_by_original_bytes.size()
                ),
                tier.protocol_path_registry,
                analysis_settings
            ),
        },
    };
}

bool summary_statistics_report_requested(const SummaryCommandOptions& options) noexcept {
    return options.out_statistics_html_path.has_value() ||
        options.out_statistics_markdown_path.has_value();
}

std::string format_report_generation_timestamp_utc(const std::chrono::system_clock::time_point timestamp) {
    const auto time = std::chrono::system_clock::to_time_t(timestamp);
    std::tm utc {};
#if defined(_WIN32)
    gmtime_s(&utc, &time);
#else
    gmtime_r(&time, &utc);
#endif
    char buffer[32] {};
    if (std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S UTC", &utc) == 0U) {
        return {};
    }
    return buffer;
}

std::string statistics_report_scope_text(const FrontendOverviewDto& overview) {
    return overview.statistics_partial_open_warning_text.empty() ? "Complete" : "Partial";
}

FrontendStatisticsReportMetadata make_cli_statistics_report_metadata(
    const FrontendOverviewDto& overview,
    const std::optional<std::uint32_t> index_revision = std::nullopt
) {
    return FrontendStatisticsReportMetadata {
        .application_name = "Pcap Flow Lab",
        .application_version = PFL_APP_VERSION,
        .client_name = "CLI",
        .generated_at_utc = format_report_generation_timestamp_utc(std::chrono::system_clock::now()),
        .statistics_scope = statistics_report_scope_text(overview),
        .index_revision = index_revision,
    };
}

FrontendStatisticsReportInput make_statistics_report_input(
    FrontendStatisticsReportMetadata metadata,
    FrontendOverviewDto overview,
    SummaryStatisticsDtos statistics,
    std::vector<FrontendProtocolPathStatsDto> protocol_path_identity_tree
) {
    return FrontendStatisticsReportInput {
        .metadata = std::move(metadata),
        .overview = std::move(overview),
        .packet_size_statistics = std::move(statistics.packet_size_statistics),
        .flow_packet_count_histogram = std::move(statistics.flow_packet_count_histogram),
        .protocol_hint_statistics = std::move(statistics.protocol_hint_statistics),
        .quic_tls_statistics = std::move(statistics.quic_tls_statistics),
        .top_endpoint_port_statistics = std::move(statistics.top_endpoint_port_statistics),
        .protocol_path_identity_tree = std::move(protocol_path_identity_tree),
    };
}

bool write_text_file(
    const std::filesystem::path& path,
    const std::string& text,
    const std::string_view error_context,
    std::string& error_text
) {
    std::ofstream stream {path, std::ios::binary | std::ios::trunc};
    if (!stream.is_open()) {
        error_text = std::string {error_context} + ": " + path.string();
        return false;
    }
    stream.write(text.data(), static_cast<std::streamsize>(text.size()));
    if (!stream.good()) {
        error_text = std::string {error_context} + ": " + path.string();
        return false;
    }
    return true;
}

std::string render_extended_summary_text(
    const SummaryStatisticsDtos& statistics,
    const FrontendOverviewDto& overview
) {
    std::ostringstream out {};

    constexpr std::array<std::string_view, 8> capture_metrics_labels {
        "Average captured packet size",
        "Average original packet size",
        "Average packet rate",
        "Average captured data rate",
        "Average original data rate",
        "Truncated packets",
        "Not captured bytes",
        "Capture completeness",
    };
    constexpr std::array<std::string_view, 2> flow_characteristics_labels {
        "Only A -> B flows",
        "Service recognized",
    };
    constexpr std::array<std::string_view, 2> packet_size_labels {
        "Maximum captured packet size",
        "Maximum original packet size",
    };
    constexpr std::array<std::string_view, 1> quic_tls_labels {
        "Flows",
    };
    constexpr std::array<std::string_view, 2> quic_recognition_labels {
        "Recognized Initial",
        "Unrecognized",
    };
    constexpr std::array<std::string_view, 4> quic_version_labels {
        "v1",
        "draft-29",
        "v2",
        "Version unavailable",
    };
    constexpr std::array<std::string_view, 2> tls_sni_labels {
        "With SNI",
        "Without SNI",
    };
    constexpr std::array<std::string_view, 3> tls_version_labels {
        "TLS 1.2",
        "TLS 1.3",
        "Version unavailable",
    };

    const auto capture_metrics_label_width = longest_label_width(capture_metrics_labels);
    const auto flow_characteristics_label_width = longest_label_width(flow_characteristics_labels);
    const auto packet_size_label_width = longest_label_width(packet_size_labels);
    const auto quic_tls_label_width = longest_label_width(quic_tls_labels);
    const auto quic_recognition_label_width = longest_label_width(quic_recognition_labels);
    const auto quic_version_label_width = longest_label_width(quic_version_labels);
    const auto tls_sni_label_width = longest_label_width(tls_sni_labels);
    const auto tls_version_label_width = longest_label_width(tls_version_labels);

    out << "\nCapture Metrics\n";
    append_key_value_line(
        out,
        "Average captured packet size",
        overview.capture_metrics.average_captured_packet_size_text,
        capture_metrics_label_width
    );
    append_key_value_line(
        out,
        "Average original packet size",
        overview.capture_metrics.average_original_packet_size_text,
        capture_metrics_label_width
    );
    append_key_value_line(
        out,
        "Average packet rate",
        overview.capture_metrics.average_packet_rate_text,
        capture_metrics_label_width
    );
    append_key_value_line(
        out,
        "Average captured data rate",
        overview.capture_metrics.average_captured_data_rate_text,
        capture_metrics_label_width
    );
    append_key_value_line(
        out,
        "Average original data rate",
        overview.capture_metrics.average_original_data_rate_text,
        capture_metrics_label_width
    );
    append_key_value_line(
        out,
        "Truncated packets",
        overview.capture_metrics.truncated_packets_text,
        capture_metrics_label_width
    );
    append_key_value_line(
        out,
        "Not captured bytes",
        overview.capture_metrics.not_captured_bytes_text,
        capture_metrics_label_width
    );
    append_key_value_line(
        out,
        "Capture completeness",
        overview.capture_metrics.capture_completeness_text,
        capture_metrics_label_width
    );

    out << "\nFlow Characteristics\n";
    append_key_value_line(
        out,
        "Only A -> B flows",
        overview.flow_characteristics.only_a_to_b_flows_text,
        flow_characteristics_label_width
    );
    append_key_value_line(
        out,
        "Service recognized",
        overview.flow_characteristics.service_recognized_flows_text,
        flow_characteristics_label_width
    );

    out << "\nDirection Distribution\n\n";
    out << "Packet Direction\n\n";
    std::vector<std::vector<std::string>> packet_direction_rows {};
    packet_direction_rows.reserve(overview.packet_direction_distribution.rows.size());
    for (const auto& row : overview.packet_direction_distribution.rows) {
        packet_direction_rows.push_back({
            row.label,
            row.flow_count_text,
            row.percent_text,
        });
    }
    out << render_table(
        {
            {.header = "Group", .right_align = false},
            {.header = "Flows", .right_align = true},
            {.header = "Percent", .right_align = true},
        },
        packet_direction_rows);

    out << "\nData Direction (Original Bytes)\n\n";
    std::vector<std::vector<std::string>> original_byte_direction_rows {};
    original_byte_direction_rows.reserve(overview.original_byte_direction_distribution.rows.size());
    for (const auto& row : overview.original_byte_direction_distribution.rows) {
        original_byte_direction_rows.push_back({
            row.label,
            row.flow_count_text,
            row.percent_text,
        });
    }
    out << render_table(
        {
            {.header = "Group", .right_align = false},
            {.header = "Flows", .right_align = true},
            {.header = "Percent", .right_align = true},
        },
        original_byte_direction_rows);

    out << "\nTCP Flags\n\n";
    std::vector<std::vector<std::string>> tcp_flag_rows {};
    tcp_flag_rows.reserve(overview.tcp_flag_statistics.rows.size());
    for (const auto& row : overview.tcp_flag_statistics.rows) {
        tcp_flag_rows.push_back({
            row.label,
            row.packet_count_text,
            row.percent_text,
        });
    }
    out << render_table(
        {
            {.header = "Flag", .right_align = false},
            {.header = "Packets", .right_align = true},
            {.header = "Percent", .right_align = true},
        },
        tcp_flag_rows);
    if (!overview.tcp_flag_statistics.help_text.empty()) {
        out << '\n' << overview.tcp_flag_statistics.help_text << '\n';
    }

    const auto& packet_size_statistics = statistics.packet_size_statistics;
    out << "\nPacket Size Distribution\n\n";
    std::vector<std::vector<std::string>> packet_size_rows {};
    packet_size_rows.reserve(packet_size_statistics.buckets.size());
    for (const auto& bucket : packet_size_statistics.buckets) {
        packet_size_rows.push_back({
            bucket.label,
            bucket.captured_packet_count_text,
            bucket.captured_total_percent_text,
            bucket.original_packet_count_text,
            bucket.original_total_percent_text,
        });
    }
    out << render_table(
        {
            {.header = "Packet Size", .right_align = false},
            {.header = "Captured Packets", .right_align = true},
            {.header = "Captured %", .right_align = true},
            {.header = "Original Packets", .right_align = true},
            {.header = "Original %", .right_align = true},
        },
        packet_size_rows);
    out << '\n';
    append_key_value_line(
        out,
        "Maximum captured packet size",
        packet_size_statistics.maximum_captured_packet_length_text,
        packet_size_label_width
    );
    append_key_value_line(
        out,
        "Maximum original packet size",
        packet_size_statistics.maximum_original_packet_length_text,
        packet_size_label_width
    );

    const auto& histogram = statistics.flow_packet_count_histogram;
    out << "\nFlows by Packet Count\n\n";
    std::vector<std::vector<std::string>> histogram_rows {};
    histogram_rows.reserve(histogram.buckets.size());
    for (const auto& bucket : histogram.buckets) {
        histogram_rows.push_back({
            bucket.label,
            bucket.flow_count_with_total_percent_text,
            bucket.captured_byte_count_with_total_percent_text,
            bucket.original_byte_count_with_total_percent_text,
        });
    }
    out << render_table(
        {
            {.header = "Packets / Flow", .right_align = false},
            {.header = "Flows", .right_align = true},
            {.header = "Captured Bytes", .right_align = true},
            {.header = "Original Bytes", .right_align = true},
        },
        histogram_rows);

    const auto& protocol_hints = statistics.protocol_hint_statistics;
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

    const auto& quic_tls_statistics = statistics.quic_tls_statistics;
    out << "\nQUIC and TLS\n\n";
    out << "QUIC\n";
    append_key_value_line(
        out,
        "Flows",
        session_detail::format_statistics_count_value(quic_tls_statistics.quic_recognition.total_flows),
        quic_tls_label_width
    );
    out << "  Initial recognition\n";
    append_key_value_line(
        out,
        "Recognized Initial",
        build_frontend_count_with_total_percent_text(
            quic_tls_statistics.quic_recognition.with_sni,
            quic_tls_statistics.quic_recognition.total_flows
        ),
        quic_recognition_label_width
    );
    append_key_value_line(
        out,
        "Unrecognized",
        build_frontend_count_with_total_percent_text(
            quic_tls_statistics.quic_recognition.without_sni,
            quic_tls_statistics.quic_recognition.total_flows
        ),
        quic_recognition_label_width
    );
    out << "  Version\n";
    append_key_value_line(
        out,
        "v1",
        session_detail::format_statistics_count_value(quic_tls_statistics.quic_recognition.version_v1),
        quic_version_label_width
    );
    append_key_value_line(
        out,
        "draft-29",
        session_detail::format_statistics_count_value(quic_tls_statistics.quic_recognition.version_draft29),
        quic_version_label_width
    );
    append_key_value_line(
        out,
        "v2",
        session_detail::format_statistics_count_value(quic_tls_statistics.quic_recognition.version_v2),
        quic_version_label_width
    );
    append_key_value_line(
        out,
        "Version unavailable",
        session_detail::format_statistics_count_value(quic_tls_statistics.quic_recognition.version_unknown),
        quic_version_label_width
    );

    out << "\nTLS\n";
    append_key_value_line(
        out,
        "Flows",
        session_detail::format_statistics_count_value(quic_tls_statistics.tls_recognition.total_flows),
        quic_tls_label_width
    );
    out << "  SNI\n";
    append_key_value_line(
        out,
        "With SNI",
        build_frontend_count_with_total_percent_text(
            quic_tls_statistics.tls_recognition.with_sni,
            quic_tls_statistics.tls_recognition.total_flows
        ),
        tls_sni_label_width
    );
    append_key_value_line(
        out,
        "Without SNI",
        build_frontend_count_with_total_percent_text(
            quic_tls_statistics.tls_recognition.without_sni,
            quic_tls_statistics.tls_recognition.total_flows
        ),
        tls_sni_label_width
    );
    out << "  Version\n";
    append_key_value_line(
        out,
        "TLS 1.2",
        session_detail::format_statistics_count_value(quic_tls_statistics.tls_recognition.version_tls12),
        tls_version_label_width
    );
    append_key_value_line(
        out,
        "TLS 1.3",
        session_detail::format_statistics_count_value(quic_tls_statistics.tls_recognition.version_tls13),
        tls_version_label_width
    );
    append_key_value_line(
        out,
        "Version unavailable",
        session_detail::format_statistics_count_value(quic_tls_statistics.tls_recognition.version_unknown),
        tls_version_label_width
    );

    const auto& top_statistics = statistics.top_endpoint_port_statistics;
    out << "\nTop Flows by Original Bytes\n\n";
    std::vector<std::vector<std::string>> top_flow_rows {};
    top_flow_rows.reserve(top_statistics.top_flows.size());
    for (const auto& row : top_statistics.top_flows) {
        top_flow_rows.push_back({
            row.flow_index_text,
            row.endpoint_a,
            row.endpoint_b,
            row.protocol_text,
            row.detected_protocol_text,
            cli_table_text(row.service_text),
            row.protocol_path_compact_text,
            row.packet_count_text,
            row.captured_bytes_text,
            row.original_bytes_text,
        });
    }
    out << render_table(
        {
            {.header = "Flow", .right_align = false},
            {.header = "Endpoint A", .right_align = false},
            {.header = "Endpoint B", .right_align = false},
            {.header = "Protocol", .right_align = false},
            {.header = "Detected Protocol", .right_align = false},
            {.header = "Service", .right_align = false},
            {.header = "Protocol Path", .right_align = false},
            {.header = "Packets", .right_align = true},
            {.header = "Captured", .right_align = true},
            {.header = "Original", .right_align = true},
        },
        top_flow_rows);

    out << "\nTop Endpoints and Ports\n\n";
    out << "Top Endpoints\n\n";
    std::vector<std::vector<std::string>> endpoint_rows {};
    endpoint_rows.reserve(top_statistics.top_endpoints.size());
    for (const auto& row : top_statistics.top_endpoints) {
        endpoint_rows.push_back({
            row.endpoint_label,
            row.flow_count_text,
            row.packet_count_text,
            row.total_bytes_text,
        });
    }
    out << render_table(
        {
            {.header = "Endpoint", .right_align = false},
            {.header = "Flows", .right_align = true},
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
            row.flow_count_text,
            row.packet_count_text,
            row.total_bytes_text,
        });
    }
    out << render_table(
        {
            {.header = "Port", .right_align = false},
            {.header = "Flows", .right_align = true},
            {.header = "Packets", .right_align = true},
            {.header = "Original Bytes", .right_align = true},
        },
        port_rows);

    return out.str();
}

OutputPreflightResult preflight_output_paths(const SummaryCommandOptions& options) {
    std::array<CliOutputTarget, 5> outputs {};
    std::size_t output_count = 0U;
    if (options.out_index_path.has_value()) {
        outputs[output_count++] = CliOutputTarget {
            .label = "--out-index",
            .path = *options.out_index_path,
        };
    }
    if (options.out_flows_list_path.has_value()) {
        outputs[output_count++] = CliOutputTarget {
            .label = "--out-flows-list",
            .path = *options.out_flows_list_path,
        };
    }
    if (options.out_protocol_path_tree_path.has_value()) {
        outputs[output_count++] = CliOutputTarget {
            .label = "--out-protocol-path-tree",
            .path = *options.out_protocol_path_tree_path,
        };
    }
    if (options.out_statistics_html_path.has_value()) {
        outputs[output_count++] = CliOutputTarget {
            .label = "--out-statistics-html",
            .path = *options.out_statistics_html_path,
        };
    }
    if (options.out_statistics_markdown_path.has_value()) {
        outputs[output_count++] = CliOutputTarget {
            .label = "--out-statistics-markdown",
            .path = *options.out_statistics_markdown_path,
        };
    }

    const auto generic_result = preflight_output_targets(
        options.input_path,
        std::span<const CliOutputTarget>(outputs.data(), output_count),
        options.force,
        std::span<const std::filesystem::path> {},
        std::string_view {"Summary side outputs must target distinct paths."}
    );

    return OutputPreflightResult {
        .ok = generic_result.ok,
        .error_text = generic_result.error_text,
    };
}

FrontendOpenResult open_summary_input(
    FrontendSessionAdapter& adapter,
    const SummaryCommandOptions& options,
    std::string& stderr_text,
    const CliRuntimeEnvironment& environment
) {
    return open_input_with_progress(
        adapter,
        options.input_path,
        options.progress_mode,
        environment,
        stderr_text
    );
}

bool summary_options_allow_fast_v16_index_path(const SummaryCommandOptions& options) noexcept {
    return !options.settings_path.has_value() &&
        !options.out_index_path.has_value() &&
        !options.out_flows_list_path.has_value();
}

SummaryCommandExecutionResult execute_fast_v16_index_summary_command(
    const SummaryCommandOptions& options,
    const CliRuntimeEnvironment& environment
) {
    CaptureIndexReader reader {};
    detail::CaptureIndexV16FastStatisticsTier fast_tier {};
    detail::CaptureIndexV16FastStatisticsTierReadResult read_result {};
    OpenContext open_context {};
    const bool progress_enabled =
        should_enable_summary_progress(options.progress_mode, environment.stderr_is_terminal) &&
        static_cast<bool>(environment.progress_sink);
    const bool interactive_progress = progress_enabled && environment.stderr_is_terminal;
    std::string last_progress_line_text {};
    std::size_t last_progress_visible_length = 0U;
    bool emitted_progress = false;

    if (progress_enabled) {
        open_context.on_progress = [&](const OpenProgress& progress) {
            emit_summary_progress_line(
                environment,
                interactive_progress,
                render_open_progress_text(make_fast_v16_summary_progress_dto(options.input_path, progress, true)),
                last_progress_line_text,
                last_progress_visible_length,
                emitted_progress
            );
        };
    }

    if (!reader.read_v16_fast_statistics(
            options.input_path,
            fast_tier,
            read_result,
            progress_enabled ? &open_context : nullptr)) {
        if (interactive_progress && emitted_progress) {
            environment.progress_sink("\n");
        }
        const auto& error = reader.last_error();
        return {
            .exit_code = 1,
            .stdout_text = {},
            .stderr_text = error.reason.empty()
                ? "Failed to open input: " + options.input_path.string() + '\n'
                : error.reason + '\n',
        };
    }

    if (progress_enabled) {
        emit_fast_v16_summary_progress_completion(
            options.input_path,
            environment,
            interactive_progress,
            open_context.progress,
            last_progress_line_text,
            last_progress_visible_length,
            emitted_progress
        );
        if (interactive_progress && emitted_progress) {
            environment.progress_sink("\n");
        }
    }

    const auto overview = build_fast_v16_overview(
        options.input_path,
        file_size_or_zero(options.input_path),
        read_result.header,
        fast_tier
    );
    const auto statistics = build_fast_v16_summary_statistics_dtos(fast_tier);
    const auto report_statistics = summary_statistics_report_requested(options)
        ? build_fast_v16_summary_statistics_dtos(fast_tier, kStatisticsReportTopEndpointPortLimit)
        : SummaryStatisticsDtos {};

    std::ostringstream stdout_builder {};
    stdout_builder << render_basic_summary_text(overview, false);

    if (options.extended) {
        stdout_builder << render_extended_summary_text(statistics, overview);
    }

    if (options.protocol_path_tree) {
        stdout_builder << '\n'
            << render_protocol_path_preview_text(
                build_frontend_protocol_path_statistics(
                    build_fast_protocol_path_summary(fast_tier, options.protocol_path_mode)
                ),
                options.protocol_path_mode
            );
    }

    std::string stderr_text {};
    if (!overview.statistics_partial_open_warning_text.empty()) {
        stderr_text += overview.statistics_partial_open_warning_text;
        stderr_text += '\n';
    }

    if (options.out_protocol_path_tree_path.has_value()) {
        std::string error_text {};
        if (!session_detail::export_protocol_path_tree_text(
                build_fast_protocol_path_summary(fast_tier, options.protocol_path_mode),
                *options.out_protocol_path_tree_path,
                session_detail::TextExportOverwritePolicy::overwrite_existing,
                &error_text)) {
            stderr_text += error_text.empty()
                ? "Failed to export Protocol Path Tree.\n"
                : error_text + '\n';
            return {
                .exit_code = 1,
                .stdout_text = stdout_builder.str(),
                .stderr_text = std::move(stderr_text),
            };
        }
        stderr_text += "Protocol Path Tree written to: " + options.out_protocol_path_tree_path->string() + '\n';
    }

    if (summary_statistics_report_requested(options)) {
        const auto report = build_frontend_statistics_report_data(make_statistics_report_input(
            make_cli_statistics_report_metadata(overview, read_result.header.index_revision),
            overview,
            report_statistics,
            build_frontend_protocol_path_statistics(
                build_fast_protocol_path_summary(fast_tier, ProtocolPathStatisticsMode::identity_tree)
            )
        ));

        if (options.out_statistics_markdown_path.has_value()) {
            const auto markdown = render_frontend_statistics_report_markdown(report);
            std::string error_text {};
            if (!write_text_file(
                    *options.out_statistics_markdown_path,
                    markdown,
                    "Failed to write Statistics Markdown report",
                    error_text)) {
                stderr_text += error_text + '\n';
                return {
                    .exit_code = 1,
                    .stdout_text = stdout_builder.str(),
                    .stderr_text = std::move(stderr_text),
                };
            }
            stderr_text += "Statistics Markdown report written to: " +
                options.out_statistics_markdown_path->string() + '\n';
        }

        if (options.out_statistics_html_path.has_value()) {
            const auto html = render_frontend_statistics_report_html(report);
            std::string error_text {};
            if (!write_text_file(
                    *options.out_statistics_html_path,
                    html,
                    "Failed to write Statistics HTML report",
                    error_text)) {
                stderr_text += error_text + '\n';
                return {
                    .exit_code = 1,
                    .stdout_text = stdout_builder.str(),
                    .stderr_text = std::move(stderr_text),
                };
            }
            stderr_text += "Statistics HTML report written to: " +
                options.out_statistics_html_path->string() + '\n';
        }
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

SummaryCommandExecutionResult execute_summary_command_with_environment(
    const SummaryCommandOptions& options,
    const CliRuntimeEnvironment& environment
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

    if (input_looks_like_index && summary_options_allow_fast_v16_index_path(options)) {
        return execute_fast_v16_index_summary_command(options, environment);
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
    const auto overview = adapter.get_overview();
    stdout_builder << render_basic_summary_text(overview);

    if (options.extended) {
        stdout_builder << render_extended_summary_text(build_summary_statistics_dtos(adapter), overview);
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

    if (options.out_flows_list_path.has_value()) {
        const auto export_result = adapter.export_all_flows_info_csv(*options.out_flows_list_path);
        if (!export_result.exported) {
            stderr_text += export_result.error_text.empty()
                ? "Failed to export flow list.\n"
                : export_result.error_text + '\n';
            return {
                .exit_code = 1,
                .stdout_text = stdout_builder.str(),
                .stderr_text = std::move(stderr_text),
            };
        }
        stderr_text += "Flow list written to: " + export_result.output_path + '\n';
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

    if (summary_statistics_report_requested(options)) {
        const auto report = build_frontend_statistics_report_data(make_statistics_report_input(
            make_cli_statistics_report_metadata(overview),
            overview,
            build_summary_statistics_dtos(adapter, kStatisticsReportTopEndpointPortLimit),
            adapter.get_protocol_path_statistics(ProtocolPathStatisticsMode::identity_tree)
        ));

        if (options.out_statistics_markdown_path.has_value()) {
            const auto markdown = render_frontend_statistics_report_markdown(report);
            std::string error_text {};
            if (!write_text_file(
                    *options.out_statistics_markdown_path,
                    markdown,
                    "Failed to write Statistics Markdown report",
                    error_text)) {
                stderr_text += error_text + '\n';
                return {
                    .exit_code = 1,
                    .stdout_text = stdout_builder.str(),
                    .stderr_text = std::move(stderr_text),
                };
            }
            stderr_text += "Statistics Markdown report written to: " +
                options.out_statistics_markdown_path->string() + '\n';
        }

        if (options.out_statistics_html_path.has_value()) {
            const auto html = render_frontend_statistics_report_html(report);
            std::string error_text {};
            if (!write_text_file(
                    *options.out_statistics_html_path,
                    html,
                    "Failed to write Statistics HTML report",
                    error_text)) {
                stderr_text += error_text + '\n';
                return {
                    .exit_code = 1,
                    .stdout_text = stdout_builder.str(),
                    .stderr_text = std::move(stderr_text),
                };
            }
            stderr_text += "Statistics HTML report written to: " +
                options.out_statistics_html_path->string() + '\n';
        }
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

std::string render_global_cli_help() {
    std::ostringstream out {};
    out << "Pcap Flow Lab " << PFL_APP_VERSION << "\n\n";
    out << "Usage\n";
    out << "  pcap-flow-lab <capture-or-index> [summary options]\n";
    out << "  pcap-flow-lab summary <input> [options]\n";
    out << "  pcap-flow-lab summary --input <input> [options]\n";
    out << "  pcap-flow-lab -h\n";
    out << "  pcap-flow-lab --help\n\n";
    out << render_command_list() << '\n';
    out << "Command-specific help\n";
    out << "  pcap-flow-lab <command> --help\n";
    return out.str();
}

std::string render_summary_command_help() {
    std::ostringstream out {};
    out << "PcapFlowLab CLI - summary\n\n";
    out << "Show whole-capture or whole-index overview and statistics.\n\n";
    out << "Usage\n";
    out << "  pcap-flow-lab summary <input> [options]\n";
    out << "  pcap-flow-lab summary --input <input> [options]\n";
    out << "  pcap-flow-lab <input> [summary options]\n\n";
    out << "Input and import\n";
    out << "  --input <path>\n";
    out << "  --settings <settings.json>\n";
    out << "    Applies to raw capture import and is invalid for index input.\n\n";
    out << "Presentation\n";
    out << "  --extended\n";
    out << "  --protocol-path-tree\n";
    out << "  --protocol-path-mode <kind-overview|identity-tree|terminal-paths>\n\n";
    out << "Side outputs\n";
    out << "  --out-index <path>\n";
    out << "  --out-flows-list <path>\n";
    out << "  --out-protocol-path-tree <path>\n";
    out << "  --out-statistics-html <path>\n";
    out << "  --out-statistics-markdown <path>\n\n";
    out << "Runtime\n";
    out << "  --progress <auto|on|off>\n";
    out << "  --force\n\n";
    out << "Help\n";
    out << "  -h, --help\n\n";
    out << render_summary_examples();
    return out.str();
}

SummaryDispatchDecision classify_cli_invocation(const std::span<const std::string_view> args) {
    if (args.empty()) {
        return {};
    }

    const auto command = canonicalize_cli_command_name(args.front());

    if (command == "summary") {
        return SummaryDispatchDecision {
            .kind = SummaryDispatchKind::summary,
            .summary_args = std::vector<std::string_view>(args.begin() + 1, args.end()),
        };
    }

    if (command == "flows") {
        return SummaryDispatchDecision {
            .kind = SummaryDispatchKind::flows,
            .summary_args = std::vector<std::string_view>(args.begin() + 1, args.end()),
        };
    }

    if (command == "export-flows") {
        return SummaryDispatchDecision {
            .kind = SummaryDispatchKind::export_flows,
            .summary_args = std::vector<std::string_view>(args.begin() + 1, args.end()),
        };
    }

    if (command == "flow-info") {
        return SummaryDispatchDecision {
            .kind = SummaryDispatchKind::flow_info,
            .summary_args = std::vector<std::string_view>(args.begin() + 1, args.end()),
        };
    }

    if (command == "packet-info") {
        return SummaryDispatchDecision {
            .kind = SummaryDispatchKind::packet_info,
            .summary_args = std::vector<std::string_view>(args.begin() + 1, args.end()),
        };
    }

    return SummaryDispatchDecision {
        .kind = SummaryDispatchKind::summary,
        .summary_args = std::vector<std::string_view>(args.begin(), args.end()),
    };
}

SummaryCommandParseResult parse_summary_command_arguments(const std::span<const std::string_view> args) {
    SummaryCommandOptions options {};
    bool positional_input_seen = false;
    bool explicit_input_seen = false;
    bool explicit_settings_seen = false;
    bool out_index_seen = false;
    bool out_flows_list_seen = false;
    bool out_protocol_path_tree_seen = false;
    bool out_statistics_html_seen = false;
    bool out_statistics_markdown_seen = false;
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

        if (token == "--out-flows-list") {
            if (out_flows_list_seen) {
                return {
                    .ok = false,
                    .options = std::nullopt,
                    .error_text = "Duplicate --out-flows-list is invalid.",
                };
            }
            if (index + 1U >= args.size()) {
                return {
                    .ok = false,
                    .options = std::nullopt,
                    .error_text = "--out-flows-list requires a path.",
                };
            }
            out_flows_list_seen = true;
            options.out_flows_list_path = std::filesystem::path {std::string {args[++index]}};
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

        if (token == "--out-statistics-html") {
            if (out_statistics_html_seen) {
                return {
                    .ok = false,
                    .options = std::nullopt,
                    .error_text = "Duplicate --out-statistics-html is invalid.",
                };
            }
            if (index + 1U >= args.size()) {
                return {
                    .ok = false,
                    .options = std::nullopt,
                    .error_text = "--out-statistics-html requires a path.",
                };
            }
            out_statistics_html_seen = true;
            options.out_statistics_html_path = std::filesystem::path {std::string {args[++index]}};
            continue;
        }

        if (token == "--out-statistics-markdown") {
            if (out_statistics_markdown_seen) {
                return {
                    .ok = false,
                    .options = std::nullopt,
                    .error_text = "Duplicate --out-statistics-markdown is invalid.",
                };
            }
            if (index + 1U >= args.size()) {
                return {
                    .ok = false,
                    .options = std::nullopt,
                    .error_text = "--out-statistics-markdown requires a path.",
                };
            }
            out_statistics_markdown_seen = true;
            options.out_statistics_markdown_path = std::filesystem::path {std::string {args[++index]}};
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
            const auto mode = parse_cli_progress_mode(args[++index]);
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
    return should_enable_cli_progress(mode, stderr_is_terminal);
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
        CliRuntimeEnvironment {
            .stderr_is_terminal = pfl::cli::stderr_supports_interactive_updates(),
        }
    );
}

CliInvocationResult process_cli_invocation(
    const std::span<const std::string_view> args,
    const CliRuntimeEnvironment& environment
) {
    if (args.empty()) {
        return {
            .handled = true,
            .exit_code = 1,
            .stdout_text = {},
            .stderr_text = render_global_cli_help(),
        };
    }

    if (contains_option(kHelpOptions, args.front())) {
        return {
            .handled = true,
            .exit_code = 0,
            .stdout_text = render_global_cli_help(),
            .stderr_text = {},
        };
    }

    const auto dispatch = classify_cli_invocation(args);
    if (dispatch.kind != SummaryDispatchKind::summary) {
        if (dispatch.kind == SummaryDispatchKind::flows) {
            if (contains_help_option(dispatch.summary_args)) {
                return {
                    .handled = true,
                    .exit_code = 0,
                    .stdout_text = render_flows_command_help(),
                    .stderr_text = {},
                };
            }

            const auto parse_result = parse_flows_command_arguments(dispatch.summary_args);
            if (!parse_result.ok || !parse_result.options.has_value()) {
                std::string stderr_text {};
                if (!parse_result.error_text.empty()) {
                    stderr_text += parse_result.error_text;
                    stderr_text += '\n';
                    stderr_text += '\n';
                }
                stderr_text += render_flows_command_help();
                return {
                    .handled = true,
                    .exit_code = 1,
                    .stdout_text = {},
                    .stderr_text = std::move(stderr_text),
                };
            }

            const auto result = execute_flows_command(*parse_result.options, environment);
            return {
                .handled = true,
                .exit_code = result.exit_code,
                .stdout_text = result.stdout_text,
                .stderr_text = result.stderr_text,
            };
        }

        if (dispatch.kind == SummaryDispatchKind::export_flows) {
            if (contains_help_option(dispatch.summary_args)) {
                return {
                    .handled = true,
                    .exit_code = 0,
                    .stdout_text = render_export_flows_command_help(),
                    .stderr_text = {},
                };
            }

            const auto parse_result = parse_export_flows_command_arguments(dispatch.summary_args);
            if (!parse_result.ok || !parse_result.options.has_value()) {
                std::string stderr_text {};
                if (!parse_result.error_text.empty()) {
                    stderr_text += parse_result.error_text;
                    stderr_text += '\n';
                    stderr_text += '\n';
                }
                stderr_text += render_export_flows_command_help();
                return {
                    .handled = true,
                    .exit_code = 1,
                    .stdout_text = {},
                    .stderr_text = std::move(stderr_text),
                };
            }

            const auto result = execute_export_flows_command(*parse_result.options, environment);
            return {
                .handled = true,
                .exit_code = result.exit_code,
                .stdout_text = result.stdout_text,
                .stderr_text = result.stderr_text,
            };
        }

        if (dispatch.kind == SummaryDispatchKind::flow_info) {
            if (contains_help_option(dispatch.summary_args)) {
                return {
                    .handled = true,
                    .exit_code = 0,
                    .stdout_text = render_flow_info_command_help(),
                    .stderr_text = {},
                };
            }

            const auto parse_result = parse_flow_info_command_arguments(dispatch.summary_args);
            if (!parse_result.ok || !parse_result.options.has_value()) {
                std::string stderr_text {};
                if (!parse_result.error_text.empty()) {
                    stderr_text += parse_result.error_text;
                    stderr_text += '\n';
                    stderr_text += '\n';
                }
                stderr_text += render_flow_info_command_help();
                return {
                    .handled = true,
                    .exit_code = 1,
                    .stdout_text = {},
                    .stderr_text = std::move(stderr_text),
                };
            }

            const auto result = execute_flow_info_command(*parse_result.options, environment);
            return {
                .handled = true,
                .exit_code = result.exit_code,
                .stdout_text = result.stdout_text,
                .stderr_text = result.stderr_text,
            };
        }

        if (dispatch.kind == SummaryDispatchKind::packet_info) {
            if (contains_help_option(dispatch.summary_args)) {
                return {
                    .handled = true,
                    .exit_code = 0,
                    .stdout_text = render_packet_info_command_help(),
                    .stderr_text = {},
                };
            }

            const auto parse_result = parse_packet_info_command_arguments(dispatch.summary_args);
            if (!parse_result.ok || !parse_result.options.has_value()) {
                std::string stderr_text {};
                if (!parse_result.error_text.empty()) {
                    stderr_text += parse_result.error_text;
                    stderr_text += '\n';
                    stderr_text += '\n';
                }
                stderr_text += render_packet_info_command_help();
                return {
                    .handled = true,
                    .exit_code = 1,
                    .stdout_text = {},
                    .stderr_text = std::move(stderr_text),
                };
            }

            const auto result = execute_packet_info_command(*parse_result.options, environment);
            return {
                .handled = true,
                .exit_code = result.exit_code,
                .stdout_text = result.stdout_text,
                .stderr_text = result.stderr_text,
            };
        }

        return {
            .handled = true,
            .exit_code = 1,
            .stdout_text = {},
            .stderr_text = render_global_cli_help(),
        };
    }

    if (contains_help_option(dispatch.summary_args)) {
        return {
            .handled = true,
            .exit_code = 0,
            .stdout_text = render_summary_command_help(),
            .stderr_text = {},
        };
    }

    const auto parse_result = parse_summary_command_arguments(dispatch.summary_args);
    if (!parse_result.ok || !parse_result.options.has_value()) {
        std::string stderr_text {};
        if (!parse_result.error_text.empty()) {
            stderr_text += parse_result.error_text;
            stderr_text += '\n';
            stderr_text += '\n';
        }
        stderr_text += render_summary_command_help();
        return {
            .handled = true,
            .exit_code = 1,
            .stdout_text = {},
            .stderr_text = std::move(stderr_text),
        };
    }

    const auto result = execute_summary_command_with_environment(*parse_result.options, environment);
    return {
        .handled = true,
        .exit_code = result.exit_code,
        .stdout_text = result.stdout_text,
        .stderr_text = result.stderr_text,
    };
}

CliInvocationResult process_cli_invocation(const std::span<const std::string_view> args) {
    return process_cli_invocation(
        args,
        CliRuntimeEnvironment {
            .stderr_is_terminal = stderr_supports_interactive_updates(),
        }
    );
}

}  // namespace pfl::cli
