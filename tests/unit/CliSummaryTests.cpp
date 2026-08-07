#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

#include "TestSupport.h"
#include "PcapTestUtils.h"
#include "app/frontend/FrontendSessionAdapter.h"
#include "app/session/FlowRows.h"
#include "app/session/SessionFlowHelpers.h"
#include "cli/SummaryCommand.h"

namespace pfl::tests {

namespace {

std::filesystem::path fixture_path(const std::filesystem::path& relative_path) {
    return std::filesystem::path(__FILE__).parent_path().parent_path() / "data" / relative_path;
}

bool contains_text(const std::string_view haystack, const std::string_view needle) {
    return haystack.find(needle) != std::string_view::npos;
}

bool has_no_tabs_or_trailing_spaces(const std::string_view text) {
    std::size_t line_start = 0U;
    while (line_start < text.size()) {
        const auto line_end = text.find('\n', line_start);
        const auto line = text.substr(
            line_start,
            line_end == std::string_view::npos ? text.size() - line_start : line_end - line_start
        );
        if (line.find('\t') != std::string_view::npos) {
            return false;
        }
        if (!line.empty() && line.back() == ' ') {
            return false;
        }
        if (line_end == std::string_view::npos) {
            break;
        }
        line_start = line_end + 1U;
    }
    return true;
}

bool has_no_ansi_escape_sequences(const std::string_view text) {
    return text.find('\x1b') == std::string_view::npos;
}

std::vector<std::uint8_t> unrecognized_ethernet_frame() {
    return {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
        0x12, 0x34,
        0xde, 0xad, 0xbe, 0xef,
    };
}

void expect_summary_dispatch_and_parse_rules() {
    {
        const std::vector<std::string_view> args {"capture.pcap"};
        const auto decision = cli::classify_cli_invocation(args);
        PFL_EXPECT(decision.kind == cli::SummaryDispatchKind::summary);
        PFL_REQUIRE(decision.summary_args.size() == 1U);
        PFL_EXPECT(decision.summary_args[0] == "capture.pcap");
    }

    {
        const std::vector<std::string_view> args {"summary", "capture.pcap"};
        const auto decision = cli::classify_cli_invocation(args);
        PFL_EXPECT(decision.kind == cli::SummaryDispatchKind::summary);
        PFL_REQUIRE(decision.summary_args.size() == 1U);
        PFL_EXPECT(decision.summary_args[0] == "capture.pcap");
    }

    {
        const std::vector<std::string_view> args {"--input", "capture.pcap"};
        const auto decision = cli::classify_cli_invocation(args);
        PFL_EXPECT(decision.kind == cli::SummaryDispatchKind::summary);
        PFL_REQUIRE(decision.summary_args.size() == 2U);
        PFL_EXPECT(decision.summary_args[0] == "--input");
        PFL_EXPECT(decision.summary_args[1] == "capture.pcap");
    }

    {
        const std::vector<std::string_view> args {"flows", "capture.pcap"};
        const auto decision = cli::classify_cli_invocation(args);
        PFL_EXPECT(decision.kind == cli::SummaryDispatchKind::legacy);
        PFL_EXPECT(decision.legacy_command == "flows");
    }

    {
        const std::vector<std::string_view> args {"capture.pcap", "--input", "capture.pcap"};
        const auto parse_result = cli::parse_summary_command_arguments(args);
        PFL_EXPECT(!parse_result.ok);
        PFL_EXPECT(contains_text(parse_result.error_text, "mutually exclusive"));
    }

    {
        const std::vector<std::string_view> args {};
        const auto parse_result = cli::parse_summary_command_arguments(args);
        PFL_EXPECT(!parse_result.ok);
        PFL_EXPECT(contains_text(parse_result.error_text, "requires an input path"));
    }

    {
        const std::vector<std::string_view> args {"capture.pcap", "--unknown"};
        const auto parse_result = cli::parse_summary_command_arguments(args);
        PFL_EXPECT(!parse_result.ok);
        PFL_EXPECT(contains_text(parse_result.error_text, "Unknown summary option"));
    }

    {
        const std::vector<std::string_view> args {"capture.pcap", "--settings", "settings.json"};
        const auto parse_result = cli::parse_summary_command_arguments(args);
        PFL_EXPECT(!parse_result.ok);
        PFL_EXPECT(contains_text(parse_result.error_text, "not implemented"));
    }

    {
        const std::vector<std::string_view> args {"capture.pcap", "--protocol-path-mode", "identity-tree"};
        const auto parse_result = cli::parse_summary_command_arguments(args);
        PFL_EXPECT(!parse_result.ok);
        PFL_EXPECT(contains_text(parse_result.error_text, "valid only when --protocol-path-tree"));
    }

    {
        const std::vector<std::string_view> args {
            "capture.pcap",
            "--protocol-path-tree",
            "--protocol-path-mode",
            "terminal-paths",
        };
        const auto parse_result = cli::parse_summary_command_arguments(args);
        PFL_REQUIRE(parse_result.ok);
        PFL_REQUIRE(parse_result.options.has_value());
        PFL_EXPECT(parse_result.options->protocol_path_tree);
        PFL_EXPECT(parse_result.options->protocol_path_mode == ProtocolPathStatisticsMode::terminal_paths);
    }

    {
        const std::vector<std::string_view> args {"capture.pcap", "--filter", "TLS"};
        const auto parse_result = cli::parse_summary_command_arguments(args);
        PFL_EXPECT(!parse_result.ok);
        PFL_EXPECT(contains_text(parse_result.error_text, "always whole-capture"));
    }
}

void expect_basic_summary_rendering() {
    const auto recognized_packet = make_ethernet_ipv4_tcp_packet(ipv4(10, 70, 0, 1), ipv4(10, 70, 0, 2), 7001, 443);
    const auto unrecognized_packet = unrecognized_ethernet_frame();
    const std::vector<std::pair<std::uint32_t, std::vector<std::uint8_t>>> packets {
        {100U, recognized_packet},
        {200U, unrecognized_packet},
    };
    const auto capture_path = write_temp_pcap(
        "pfl_cli_summary_basic_capture.pcap",
        make_classic_pcap(packets)
    );

    cli::SummaryCommandOptions options {};
    options.input_path = capture_path;
    const auto execution_result = cli::execute_summary_command(options);
    PFL_EXPECT(execution_result.exit_code == 0);
    PFL_EXPECT(execution_result.stderr_text.empty());
    PFL_EXPECT(contains_text(execution_result.stdout_text, "PcapFlowLab Summary"));
    PFL_EXPECT(contains_text(execution_result.stdout_text, "Input"));
    PFL_EXPECT(contains_text(execution_result.stdout_text, capture_path.filename().string()));
    PFL_EXPECT(contains_text(execution_result.stdout_text, "Type:"));
    PFL_EXPECT(contains_text(execution_result.stdout_text, "PCAP"));
    PFL_EXPECT(contains_text(execution_result.stdout_text, "File size:"));
    PFL_EXPECT(contains_text(execution_result.stdout_text, "Capture"));
    PFL_EXPECT(contains_text(execution_result.stdout_text, "Flows:"));
    PFL_EXPECT(contains_text(execution_result.stdout_text, "Packets:"));
    PFL_EXPECT(contains_text(execution_result.stdout_text, "Captured bytes:"));
    PFL_EXPECT(contains_text(execution_result.stdout_text, "Original bytes:"));
    PFL_EXPECT(contains_text(execution_result.stdout_text, "Unrecognized packets:"));
    PFL_EXPECT(contains_text(execution_result.stdout_text, "Transport Summary"));
    PFL_EXPECT(contains_text(execution_result.stdout_text, "TCP"));
    PFL_EXPECT(contains_text(execution_result.stdout_text, "UDP"));
    PFL_EXPECT(contains_text(execution_result.stdout_text, "SCTP"));
    PFL_EXPECT(contains_text(execution_result.stdout_text, "Other"));
    PFL_EXPECT(contains_text(execution_result.stdout_text, "IP Family Summary"));
    PFL_EXPECT(contains_text(execution_result.stdout_text, "IPv4"));
    PFL_EXPECT(contains_text(execution_result.stdout_text, "IPv6"));
    PFL_EXPECT(has_no_tabs_or_trailing_spaces(execution_result.stdout_text));
    PFL_EXPECT(has_no_ansi_escape_sequences(execution_result.stdout_text));

    FrontendSessionAdapter adapter {};
    PFL_REQUIRE(adapter.open_capture(capture_path).opened);
    const auto overview = adapter.get_overview();
    PFL_EXPECT(overview.whole_capture_totals.packet_count == 2U);
    PFL_EXPECT(overview.whole_capture_totals.packet_count > overview.summary.packet_count);
    PFL_EXPECT(overview.whole_capture_totals.captured_bytes > overview.summary.captured_bytes);
    PFL_EXPECT(overview.whole_capture_totals.original_bytes > overview.summary.original_bytes);
    PFL_EXPECT(contains_text(
        execution_result.stdout_text,
        "Packets:   " + session_detail::format_statistics_count_value(overview.whole_capture_totals.packet_count)
    ));
    PFL_EXPECT(contains_text(
        execution_result.stdout_text,
        "Unrecognized packets:   " + session_detail::format_statistics_count_value(overview.unrecognized_packet_count)
    ));
    PFL_EXPECT(contains_text(execution_result.stdout_text, overview.whole_capture_totals.captured_bytes_text));
    PFL_EXPECT(contains_text(execution_result.stdout_text, overview.whole_capture_totals.original_bytes_text));
    const auto recognized_transport_packet_total =
        overview.protocol_summary.tcp.packet_count +
        overview.protocol_summary.udp.packet_count +
        overview.protocol_summary.sctp.packet_count +
        overview.protocol_summary.other.packet_count;
    PFL_EXPECT(recognized_transport_packet_total < overview.whole_capture_totals.packet_count);
}

void expect_index_summary_rendering_without_source_capture() {
    const auto recognized_packet = make_ethernet_ipv4_udp_packet(ipv4(10, 71, 0, 1), ipv4(10, 71, 0, 2), 7101, 53);
    const std::vector<std::pair<std::uint32_t, std::vector<std::uint8_t>>> packets {
        {100U, recognized_packet},
    };
    const auto capture_path = write_temp_pcap(
        "pfl_cli_summary_index_source.pcap",
        make_classic_pcap(packets)
    );

    FrontendSessionAdapter raw_adapter {};
    PFL_REQUIRE(raw_adapter.open_capture(capture_path).opened);

    const auto index_path = std::filesystem::temp_directory_path() / "pfl_cli_summary_index.idx";
    std::filesystem::remove(index_path);
    PFL_REQUIRE(raw_adapter.save_index(index_path).saved);
    std::filesystem::remove(capture_path);

    cli::SummaryCommandOptions options {};
    options.input_path = index_path;
    const auto execution_result = cli::execute_summary_command(options);
    PFL_EXPECT(execution_result.exit_code == 0);
    PFL_EXPECT(contains_text(execution_result.stdout_text, "PcapFlowLab Index"));
    PFL_EXPECT(contains_text(execution_result.stdout_text, "Source capture:"));
    PFL_EXPECT(contains_text(execution_result.stdout_text, "not available"));
    PFL_EXPECT(has_no_tabs_or_trailing_spaces(execution_result.stdout_text));

    FrontendSessionAdapter index_adapter {};
    PFL_REQUIRE(index_adapter.open_capture(index_path).opened);
    const auto overview = index_adapter.get_overview();
    PFL_EXPECT(overview.whole_capture_totals.packet_count == 1U);
    PFL_EXPECT(contains_text(
        execution_result.stdout_text,
        "Packets:   " + session_detail::format_statistics_count_value(overview.whole_capture_totals.packet_count)
    ));
}

void expect_extended_summary_rendering() {
    const auto tcp_ab = make_ethernet_ipv4_tcp_packet(ipv4(10, 72, 0, 1), ipv4(10, 72, 0, 2), 7201, 80);
    const auto tcp_ba = make_ethernet_ipv4_tcp_packet(ipv4(10, 72, 0, 2), ipv4(10, 72, 0, 1), 80, 7201);
    const auto udp_ac = make_ethernet_ipv4_udp_packet(ipv4(10, 72, 0, 1), ipv4(10, 72, 0, 3), 7202, 53);
    const auto udp_de = make_ethernet_ipv4_udp_packet(ipv4(10, 72, 0, 4), ipv4(10, 72, 0, 5), 7203, 22);
    const std::vector<std::pair<std::uint32_t, std::vector<std::uint8_t>>> packets {
        {100U, tcp_ab},
        {200U, tcp_ba},
        {300U, udp_ac},
        {400U, udp_de},
    };
    const auto capture_path = write_temp_pcap(
        "pfl_cli_summary_extended_capture.pcap",
        make_classic_pcap(packets)
    );

    cli::SummaryCommandOptions options {};
    options.input_path = capture_path;
    options.extended = true;
    const auto execution_result = cli::execute_summary_command(options);
    PFL_EXPECT(execution_result.exit_code == 0);
    PFL_EXPECT(contains_text(execution_result.stdout_text, "Packet Size Distribution"));
    PFL_EXPECT(contains_text(execution_result.stdout_text, "Captured Size"));
    PFL_EXPECT(contains_text(execution_result.stdout_text, "0-63"));
    PFL_EXPECT(contains_text(execution_result.stdout_text, "Flows by Packet Count"));
    PFL_EXPECT(contains_text(execution_result.stdout_text, "Packets / Flow"));
    PFL_EXPECT(contains_text(execution_result.stdout_text, "Detected Protocol Hints"));
    PFL_EXPECT(contains_text(execution_result.stdout_text, "Unknown"));
    PFL_EXPECT(!contains_text(execution_result.stdout_text, "Possible TLS"));
    PFL_EXPECT(contains_text(execution_result.stdout_text, "Top Endpoints and Ports"));
    PFL_EXPECT(contains_text(execution_result.stdout_text, "Top Endpoints"));
    PFL_EXPECT(contains_text(execution_result.stdout_text, "Top Ports"));
    PFL_EXPECT(has_no_tabs_or_trailing_spaces(execution_result.stdout_text));
}

void expect_protocol_path_preview_rendering() {
    std::vector<FrontendProtocolPathStatsDto> small_rows {
        {
            .node_id = 1U,
            .depth = 0U,
            .layer_text = "Ethernet II",
            .path_text = "Ethernet II",
            .flow_count_text = "2 (100%)",
            .packet_count_text = "4 (100%)",
            .original_byte_count_text = "256 B (100%)",
        },
        {
            .node_id = 2U,
            .parent_node_id = 1U,
            .depth = 1U,
            .layer_text = "IPv4",
            .path_text = "Ethernet II > IPv4",
            .flow_count_text = "2 (100%)",
            .packet_count_text = "4 (100%)",
            .original_byte_count_text = "256 B (100%)",
        },
    };

    const auto identity_preview = cli::render_protocol_path_preview_text(
        small_rows,
        ProtocolPathStatisticsMode::identity_tree
    );
    PFL_EXPECT(contains_text(identity_preview, "Protocol Path Tree"));
    PFL_EXPECT(contains_text(identity_preview, "Mode: Identity tree"));
    PFL_EXPECT(contains_text(identity_preview, "  IPv4"));
    PFL_EXPECT(!contains_text(identity_preview, "additional rows not shown"));

    const auto terminal_preview = cli::render_protocol_path_preview_text(
        small_rows,
        ProtocolPathStatisticsMode::terminal_paths
    );
    PFL_EXPECT(contains_text(terminal_preview, "Mode: Terminal paths"));
    PFL_EXPECT(!contains_text(terminal_preview, "  IPv4"));

    std::vector<FrontendProtocolPathStatsDto> large_rows {};
    for (std::uint64_t index = 0U; index < 30U; ++index) {
        large_rows.push_back(FrontendProtocolPathStatsDto {
            .node_id = index + 1U,
            .depth = static_cast<std::size_t>(index % 3U),
            .layer_text = "Layer " + std::to_string(index + 1U),
            .path_text = "Path " + std::to_string(index + 1U),
            .flow_count_text = "1 (10%)",
            .packet_count_text = "2 (20%)",
            .original_byte_count_text = "128 B (30%)",
        });
    }

    const auto truncated_preview = cli::render_protocol_path_preview_text(
        large_rows,
        ProtocolPathStatisticsMode::kind_overview
    );
    PFL_EXPECT(contains_text(truncated_preview, "... 5 additional rows not shown."));
    PFL_EXPECT(contains_text(truncated_preview, "Use --out-protocol-path-tree <file> to export the complete Protocol Path Tree."));
    PFL_EXPECT(!contains_text(truncated_preview, "Layer 30"));
}

void expect_protocol_path_summary_execution() {
    cli::SummaryCommandOptions options {};
    options.input_path = fixture_path("parsing/packet_byte_views/01_ethernet_ipv4_udp.pcap");
    options.protocol_path_tree = true;
    const auto execution_result = cli::execute_summary_command(options);
    PFL_EXPECT(execution_result.exit_code == 0);
    PFL_EXPECT(contains_text(execution_result.stdout_text, "Protocol Path Tree"));
    PFL_EXPECT(contains_text(execution_result.stdout_text, "Mode: Kind overview"));
    PFL_EXPECT(!contains_text(execution_result.stdout_text, "additional rows not shown"));
}

}  // namespace

void run_cli_summary_tests() {
    expect_summary_dispatch_and_parse_rules();
    expect_basic_summary_rendering();
    expect_index_summary_rendering_without_source_capture();
    expect_extended_summary_rendering();
    expect_protocol_path_preview_rendering();
    expect_protocol_path_summary_execution();
}

}  // namespace pfl::tests
