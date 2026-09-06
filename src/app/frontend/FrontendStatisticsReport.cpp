#include "app/frontend/FrontendStatisticsReport.h"

#include <algorithm>
#include <sstream>
#include <string_view>
#include <utility>

#include "app/session/SessionFlowHelpers.h"

namespace pfl {
namespace {

constexpr std::string_view kMissingReportValue {"-"};

std::string report_value_or_missing(const std::string_view value) {
    return value.empty() ? std::string {kMissingReportValue} : std::string {value};
}

std::string input_kind_report_text(const FrontendInputKind kind) {
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

void add_field(
    FrontendStatisticsReportSection& section,
    std::string name,
    std::string value
) {
    section.fields.push_back(FrontendStatisticsReportField {
        .name = std::move(name),
        .value = report_value_or_missing(value),
    });
}

void add_note(FrontendStatisticsReportSection& section, std::string text) {
    if (!text.empty()) {
        section.notes.push_back(std::move(text));
    }
}

FrontendStatisticsReportSection make_protocol_summary_section(const FrontendOverviewDto& overview) {
    FrontendStatisticsReportSection section {
        .title = "Protocol Summary",
    };
    section.tables.push_back(FrontendStatisticsReportTable {
        .title = "Transport",
        .headers = {"Transport", "Flows", "Packets", "Captured Bytes", "Original Bytes"},
        .rows = {
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
        },
    });
    section.tables.push_back(FrontendStatisticsReportTable {
        .title = "IP Family",
        .headers = {"Family", "Flows", "Packets", "Captured Bytes", "Original Bytes"},
        .rows = {
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
        },
    });
    return section;
}

FrontendStatisticsReportSection make_direction_distribution_section(
    const FrontendDirectionDistributionDto& packet_distribution,
    const FrontendDirectionDistributionDto& byte_distribution
) {
    FrontendStatisticsReportSection section {
        .title = "Direction Distribution",
    };
    add_note(section, packet_distribution.help_text);
    if (byte_distribution.help_text != packet_distribution.help_text) {
        add_note(section, byte_distribution.help_text);
    }

    auto make_rows = [](const FrontendDirectionDistributionDto& distribution) {
        std::vector<std::vector<std::string>> rows {};
        rows.reserve(distribution.rows.size());
        for (const auto& row : distribution.rows) {
            rows.push_back({
                row.label,
                row.flow_count_text,
                row.percent_text,
            });
        }
        return rows;
    };

    section.tables.push_back(FrontendStatisticsReportTable {
        .title = "Packet Direction",
        .headers = {"Distribution", "Flows", "Percent"},
        .rows = make_rows(packet_distribution),
    });
    section.tables.push_back(FrontendStatisticsReportTable {
        .title = "Data Direction (Original Bytes)",
        .headers = {"Distribution", "Flows", "Percent"},
        .rows = make_rows(byte_distribution),
    });
    return section;
}

FrontendStatisticsReportSection make_tcp_flags_section(const FrontendTcpFlagStatisticsDto& statistics) {
    FrontendStatisticsReportSection section {
        .title = "TCP Flags",
    };
    add_note(section, statistics.help_text);

    std::vector<std::vector<std::string>> rows {};
    rows.reserve(statistics.rows.size());
    for (const auto& row : statistics.rows) {
        rows.push_back({
            row.label,
            row.packet_count_text,
            row.percent_text,
        });
    }
    section.tables.push_back(FrontendStatisticsReportTable {
        .title = {},
        .headers = {"Flag", "Packets", "Percent"},
        .rows = std::move(rows),
    });
    return section;
}

FrontendStatisticsReportSection make_packet_size_distribution_section(
    const FrontendCapturePacketSizeStatisticsDto& statistics
) {
    FrontendStatisticsReportSection section {
        .title = "Packet Size Distribution",
    };
    add_field(section, "Maximum captured packet size", statistics.maximum_captured_packet_length_text);
    add_field(section, "Maximum original packet size", statistics.maximum_original_packet_length_text);

    std::vector<std::vector<std::string>> rows {};
    rows.reserve(statistics.buckets.size());
    for (const auto& bucket : statistics.buckets) {
        rows.push_back({
            bucket.label,
            bucket.captured_packet_count_text,
            bucket.captured_total_percent_text,
            bucket.original_packet_count_text,
            bucket.original_total_percent_text,
        });
    }
    section.tables.push_back(FrontendStatisticsReportTable {
        .title = "Packet Size Buckets",
        .headers = {"Size", "Captured Packets", "Captured %", "Original Packets", "Original %"},
        .rows = std::move(rows),
    });
    return section;
}

FrontendStatisticsReportSection make_flow_packet_count_histogram_section(
    const FrontendFlowPacketCountHistogramDto& histogram
) {
    FrontendStatisticsReportSection section {
        .title = "Flows by Packet Count",
    };
    if (histogram.excluded_zero_packet_flow_count > 0U) {
        add_note(
            section,
            "Zero-packet flows are excluded from packet-count histogram buckets."
        );
    }

    std::vector<std::vector<std::string>> rows {};
    rows.reserve(histogram.buckets.size());
    for (const auto& bucket : histogram.buckets) {
        rows.push_back({
            bucket.label,
            bucket.flow_count_with_total_percent_text,
            bucket.captured_byte_count_with_total_percent_text,
            bucket.original_byte_count_with_total_percent_text,
        });
    }
    section.tables.push_back(FrontendStatisticsReportTable {
        .title = "Flow Packet Count Buckets",
        .headers = {"Packet Count", "Flows", "Captured Bytes", "Original Bytes"},
        .rows = std::move(rows),
    });
    return section;
}

FrontendStatisticsReportSection make_protocol_hints_section(
    const FrontendProtocolHintStatisticsDto& statistics
) {
    FrontendStatisticsReportSection section {
        .title = "Detected Protocol Hints",
    };

    std::vector<std::vector<std::string>> rows {};
    rows.reserve(statistics.protocol_hints.size());
    for (const auto& row : statistics.protocol_hints) {
        rows.push_back({
            row.protocol_label,
            row.flow_count_text,
            row.packet_count_text,
            row.captured_bytes_text,
            row.original_bytes_text,
        });
    }
    if (rows.empty()) {
        add_note(section, "None");
    }
    section.tables.push_back(FrontendStatisticsReportTable {
        .title = {},
        .headers = {"Protocol", "Flows", "Packets", "Captured Bytes", "Original Bytes"},
        .rows = std::move(rows),
    });
    return section;
}

void append_quic_recognition_tables(
    FrontendStatisticsReportSection& section,
    const QuicRecognitionStats& statistics
) {
    section.tables.push_back(FrontendStatisticsReportTable {
        .title = "QUIC Recognition",
        .headers = {"Metric", "Flows"},
        .rows = {
            {"Recognized flows", session_detail::format_statistics_count_value(statistics.total_flows)},
            {"With SNI", session_detail::format_statistics_count_value(statistics.with_sni)},
            {"Without SNI", session_detail::format_statistics_count_value(statistics.without_sni)},
        },
    });
    section.tables.push_back(FrontendStatisticsReportTable {
        .title = "QUIC Versions",
        .headers = {"Version", "Flows"},
        .rows = {
            {"QUIC v1", session_detail::format_statistics_count_value(statistics.version_v1)},
            {"QUIC draft-29", session_detail::format_statistics_count_value(statistics.version_draft29)},
            {"QUIC v2", session_detail::format_statistics_count_value(statistics.version_v2)},
            {"Unknown QUIC", session_detail::format_statistics_count_value(statistics.version_unknown)},
        },
    });
}

void append_tls_recognition_tables(
    FrontendStatisticsReportSection& section,
    const TlsRecognitionStats& statistics
) {
    section.tables.push_back(FrontendStatisticsReportTable {
        .title = "TLS Recognition",
        .headers = {"Metric", "Flows"},
        .rows = {
            {"Recognized flows", session_detail::format_statistics_count_value(statistics.total_flows)},
            {"With SNI", session_detail::format_statistics_count_value(statistics.with_sni)},
            {"Without SNI", session_detail::format_statistics_count_value(statistics.without_sni)},
        },
    });
    section.tables.push_back(FrontendStatisticsReportTable {
        .title = "TLS Versions",
        .headers = {"Version", "Flows"},
        .rows = {
            {"TLS 1.2", session_detail::format_statistics_count_value(statistics.version_tls12)},
            {"TLS 1.3", session_detail::format_statistics_count_value(statistics.version_tls13)},
            {"Unknown TLS/SSL", session_detail::format_statistics_count_value(statistics.version_unknown)},
        },
    });
}

FrontendStatisticsReportSection make_quic_tls_section(const FrontendQuicTlsStatisticsDto& statistics) {
    FrontendStatisticsReportSection section {
        .title = "QUIC and TLS",
    };
    append_quic_recognition_tables(section, statistics.quic_recognition);
    append_tls_recognition_tables(section, statistics.tls_recognition);
    return section;
}

FrontendStatisticsReportSection make_top_endpoint_port_section(
    const FrontendTopEndpointPortStatisticsDto& statistics
) {
    FrontendStatisticsReportSection section {
        .title = "Top Endpoints and Ports",
    };

    std::vector<std::vector<std::string>> endpoint_rows {};
    endpoint_rows.reserve(statistics.top_endpoints.size());
    for (const auto& row : statistics.top_endpoints) {
        endpoint_rows.push_back({
            row.endpoint_label,
            row.flow_count_text,
            row.packet_count_text,
            row.total_bytes_text,
        });
    }

    std::vector<std::vector<std::string>> port_rows {};
    port_rows.reserve(statistics.top_ports.size());
    for (const auto& row : statistics.top_ports) {
        port_rows.push_back({
            std::to_string(row.port),
            row.flow_count_text,
            row.packet_count_text,
            row.total_bytes_text,
        });
    }

    section.tables.push_back(FrontendStatisticsReportTable {
        .title = "Top Endpoints",
        .headers = {"Endpoint", "Flows", "Packets", "Original Bytes"},
        .rows = std::move(endpoint_rows),
    });
    section.tables.push_back(FrontendStatisticsReportTable {
        .title = "Top Ports",
        .headers = {"Port", "Flows", "Packets", "Original Bytes"},
        .rows = std::move(port_rows),
    });
    return section;
}

FrontendStatisticsReportSection make_top_flows_section(
    const FrontendTopEndpointPortStatisticsDto& statistics
) {
    FrontendStatisticsReportSection section {
        .title = "Top Flows by Original Bytes",
    };

    std::vector<std::vector<std::string>> rows {};
    rows.reserve(statistics.top_flows.size());
    for (const auto& row : statistics.top_flows) {
        rows.push_back({
            row.flow_index_text,
            row.endpoint_a,
            row.endpoint_b,
            row.protocol_text,
            row.detected_protocol_text,
            row.service_text,
            row.protocol_path_compact_text,
            row.packet_count_text,
            row.captured_bytes_text,
            row.original_bytes_text,
        });
    }
    section.tables.push_back(FrontendStatisticsReportTable {
        .title = {},
        .headers = {
            "#",
            "Endpoint A",
            "Endpoint B",
            "Protocol",
            "Detected",
            "Service",
            "Path",
            "Packets",
            "Captured Bytes",
            "Original Bytes",
        },
        .rows = std::move(rows),
    });
    return section;
}

FrontendStatisticsReportSection make_protocol_path_identity_tree_section(
    const std::vector<FrontendProtocolPathStatsDto>& rows
) {
    FrontendStatisticsReportSection section {
        .title = "Protocol Path Statistics - Identity Tree",
    };

    std::vector<std::vector<std::string>> table_rows {};
    table_rows.reserve(rows.size());
    for (const auto& row : rows) {
        const std::string_view base_text = !row.layer_text.empty()
            ? std::string_view {row.layer_text}
            : std::string_view {row.path_text};
        table_rows.push_back({
            std::string(row.depth * 2U, ' ') + std::string {base_text},
            row.flow_count_text,
            row.packet_count_text,
            row.original_byte_count_text,
        });
    }

    section.tables.push_back(FrontendStatisticsReportTable {
        .title = {},
        .headers = {"Layer", "Flows", "Packets", "Original Bytes"},
        .rows = std::move(table_rows),
    });
    return section;
}

std::string markdown_escape_cell(const std::string_view value) {
    std::string escaped {};
    escaped.reserve(value.size());
    for (const char ch : value) {
        switch (ch) {
        case '\\':
            escaped += "\\\\";
            break;
        case '|':
            escaped += "\\|";
            break;
        case '\r':
        case '\n':
            escaped.push_back(' ');
            break;
        default:
            escaped.push_back(ch);
            break;
        }
    }
    return escaped;
}

std::string html_escape(const std::string_view value) {
    std::string escaped {};
    escaped.reserve(value.size());
    for (const char ch : value) {
        switch (ch) {
        case '&':
            escaped += "&amp;";
            break;
        case '<':
            escaped += "&lt;";
            break;
        case '>':
            escaped += "&gt;";
            break;
        case '"':
            escaped += "&quot;";
            break;
        case '\'':
            escaped += "&#39;";
            break;
        default:
            escaped.push_back(ch);
            break;
        }
    }
    return escaped;
}

void append_markdown_table(std::ostringstream& out, const FrontendStatisticsReportTable& table) {
    if (!table.title.empty()) {
        out << "### " << table.title << "\n\n";
    }
    if (table.headers.empty()) {
        return;
    }

    out << '|';
    for (const auto& header : table.headers) {
        out << ' ' << markdown_escape_cell(header) << " |";
    }
    out << "\n|";
    for ([[maybe_unused]] const auto& header : table.headers) {
        out << " --- |";
    }
    out << '\n';

    for (const auto& row : table.rows) {
        out << '|';
        for (std::size_t index = 0U; index < table.headers.size(); ++index) {
            const std::string_view cell = index < row.size()
                ? std::string_view {row[index]}
                : std::string_view {};
            out << ' ' << markdown_escape_cell(cell) << " |";
        }
        out << '\n';
    }
    out << '\n';
}

void append_html_table(std::ostringstream& out, const FrontendStatisticsReportTable& table) {
    if (!table.title.empty()) {
        out << "<h3>" << html_escape(table.title) << "</h3>\n";
    }
    if (table.headers.empty()) {
        return;
    }
    out << "<table>\n<thead><tr>";
    for (const auto& header : table.headers) {
        out << "<th>" << html_escape(header) << "</th>";
    }
    out << "</tr></thead>\n<tbody>\n";
    for (const auto& row : table.rows) {
        out << "<tr>";
        for (std::size_t index = 0U; index < table.headers.size(); ++index) {
            const std::string_view cell = index < row.size()
                ? std::string_view {row[index]}
                : std::string_view {};
            out << "<td>" << html_escape(cell) << "</td>";
        }
        out << "</tr>\n";
    }
    out << "</tbody>\n</table>\n";
}

}  // namespace

FrontendStatisticsReportData build_frontend_statistics_report_data(
    const FrontendStatisticsReportInput& input
) {
    const auto& overview = input.overview;
    FrontendStatisticsReportData report {
        .title = "PcapFlowLab Statistics Report",
    };
    report.sections.reserve(18U);

    {
        const auto& metadata = input.metadata;
        FrontendStatisticsReportSection section {
            .title = "Report Information",
        };
        add_field(section, "Application", metadata.application_name);
        add_field(section, "Version", metadata.application_version);
        add_field(section, "Client", metadata.client_name);
        add_field(section, "Generated at", metadata.generated_at_utc);
        add_field(section, "Statistics scope", metadata.statistics_scope);
        if (metadata.index_revision.has_value()) {
            add_field(section, "Index revision", std::to_string(*metadata.index_revision));
        }
        report.sections.push_back(std::move(section));
    }

    {
        FrontendStatisticsReportSection section {
            .title = "Input",
        };
        add_field(section, "Input path", overview.input_metadata.input_path);
        add_field(section, "Input type", input_kind_report_text(overview.input_metadata.input_kind));
        add_field(
            section,
            "Input file size",
            session_detail::format_statistics_compact_size_value(overview.input_metadata.input_file_size)
        );
        if (overview.input_metadata.source_capture_path.has_value()) {
            add_field(section, "Recorded source capture", *overview.input_metadata.source_capture_path);
        }
        report.sections.push_back(std::move(section));
    }

    {
        FrontendStatisticsReportSection section {
            .title = "Overview",
        };
        add_field(section, "Flows", session_detail::format_statistics_count_value(overview.summary.flow_count));
        add_field(
            section,
            "Packets",
            session_detail::format_statistics_count_value(overview.whole_capture_totals.packet_count)
        );
        add_field(section, "Original bytes", overview.whole_capture_totals.original_bytes_text);
        add_field(section, "Captured bytes", overview.whole_capture_totals.captured_bytes_text);
        add_note(section, overview.statistics_partial_open_warning_text);
        report.sections.push_back(std::move(section));
    }

    {
        FrontendStatisticsReportSection section {
            .title = "Capture Time",
        };
        add_field(section, "Start", overview.capture_time.capture_start_text);
        add_field(section, "End", overview.capture_time.capture_end_text);
        add_field(section, "Duration", overview.capture_time.duration_text);
        report.sections.push_back(std::move(section));
    }

    report.sections.push_back(make_protocol_summary_section(overview));

    {
        FrontendStatisticsReportSection section {
            .title = "Unrecognized Packets",
        };
        if (overview.unrecognized_packets.has_value()) {
            add_field(
                section,
                "Packets",
                session_detail::format_statistics_count_value(overview.unrecognized_packets->packet_count)
            );
            add_field(section, "Captured bytes", overview.unrecognized_packets->captured_bytes_text);
            add_field(section, "Original bytes", overview.unrecognized_packets->original_bytes_text);
        } else {
            add_field(section, "Packets", session_detail::format_statistics_count_value(overview.unrecognized_packet_count));
            add_field(section, "Captured bytes", session_detail::format_statistics_compact_size_value(0U));
            add_field(section, "Original bytes", session_detail::format_statistics_compact_size_value(0U));
        }
        report.sections.push_back(std::move(section));
    }

    report.sections.push_back(make_packet_size_distribution_section(input.packet_size_statistics));
    report.sections.push_back(make_flow_packet_count_histogram_section(input.flow_packet_count_histogram));
    report.sections.push_back(make_protocol_hints_section(input.protocol_hint_statistics));

    {
        const auto& metrics = overview.capture_metrics;
        FrontendStatisticsReportSection section {
            .title = "Capture Metrics",
        };
        add_field(section, "Average captured packet size", metrics.average_captured_packet_size_text);
        add_field(section, "Average original packet size", metrics.average_original_packet_size_text);
        add_field(section, "Average packet rate", metrics.average_packet_rate_text);
        add_field(section, "Average captured data rate", metrics.average_captured_data_rate_text);
        add_field(section, "Average original data rate", metrics.average_original_data_rate_text);
        add_field(section, "Truncated packets", metrics.truncated_packets_text);
        add_field(section, "Not captured bytes", metrics.not_captured_bytes_text);
        add_field(section, "Capture completeness", metrics.capture_completeness_text);
        report.sections.push_back(std::move(section));
    }

    {
        const auto& characteristics = overview.flow_characteristics;
        FrontendStatisticsReportSection section {
            .title = "Flow Characteristics",
        };
        add_field(section, "Only A -> B flows", characteristics.only_a_to_b_flows_text);
        add_field(section, "Service recognized", characteristics.service_recognized_flows_text);
        report.sections.push_back(std::move(section));
    }

    report.sections.push_back(make_direction_distribution_section(
        overview.packet_direction_distribution,
        overview.original_byte_direction_distribution
    ));
    report.sections.push_back(make_tcp_flags_section(overview.tcp_flag_statistics));
    report.sections.push_back(make_quic_tls_section(input.quic_tls_statistics));
    report.sections.push_back(make_top_flows_section(input.top_endpoint_port_statistics));
    report.sections.push_back(make_top_endpoint_port_section(input.top_endpoint_port_statistics));
    report.sections.push_back(make_protocol_path_identity_tree_section(input.protocol_path_identity_tree));

    return report;
}

std::string render_frontend_statistics_report_markdown(
    const FrontendStatisticsReportData& report
) {
    std::ostringstream out {};
    out << "# " << report.title << "\n\n";
    for (const auto& section : report.sections) {
        out << "## " << section.title << "\n\n";

        if (!section.fields.empty()) {
            out << "| Field | Value |\n";
            out << "| --- | --- |\n";
            for (const auto& field : section.fields) {
                out << "| " << markdown_escape_cell(field.name)
                    << " | " << markdown_escape_cell(field.value) << " |\n";
            }
            out << '\n';
        }

        for (const auto& note : section.notes) {
            out << markdown_escape_cell(note) << "\n\n";
        }

        for (const auto& table : section.tables) {
            append_markdown_table(out, table);
        }
    }
    return out.str();
}

std::string render_frontend_statistics_report_html(
    const FrontendStatisticsReportData& report
) {
    std::ostringstream out {};
    out << "<!doctype html>\n";
    out << "<html lang=\"en\">\n";
    out << "<head>\n";
    out << "<meta charset=\"utf-8\">\n";
    out << "<title>" << html_escape(report.title) << "</title>\n";
    out << "<style>\n";
    out << "body{font-family:Arial,sans-serif;margin:2rem;line-height:1.45;color:#162033;background:#fff;}\n";
    out << "h1{font-size:1.8rem;margin:0 0 1.25rem;}\n";
    out << "h2{font-size:1.25rem;margin:1.75rem 0 .65rem;border-bottom:1px solid #d8e1ef;padding-bottom:.2rem;}\n";
    out << "h3{font-size:1rem;margin:1rem 0 .35rem;}\n";
    out << "table{border-collapse:collapse;width:100%;margin:.35rem 0 1rem;}\n";
    out << "th,td{border:1px solid #d8e1ef;padding:.35rem .5rem;text-align:left;vertical-align:top;white-space:pre-wrap;}\n";
    out << "th{background:#eef4fb;font-weight:600;}\n";
    out << "p{margin:.35rem 0;color:#4e617d;}\n";
    out << "</style>\n";
    out << "</head>\n<body>\n";
    out << "<h1>" << html_escape(report.title) << "</h1>\n";
    for (const auto& section : report.sections) {
        out << "<section>\n";
        out << "<h2>" << html_escape(section.title) << "</h2>\n";

        if (!section.fields.empty()) {
            out << "<table>\n<tbody>\n";
            for (const auto& field : section.fields) {
                out << "<tr><th>" << html_escape(field.name) << "</th><td>"
                    << html_escape(field.value) << "</td></tr>\n";
            }
            out << "</tbody>\n</table>\n";
        }

        for (const auto& note : section.notes) {
            out << "<p>" << html_escape(note) << "</p>\n";
        }

        for (const auto& table : section.tables) {
            append_html_table(out, table);
        }
        out << "</section>\n";
    }
    out << "</body>\n</html>\n";
    return out.str();
}

}  // namespace pfl
