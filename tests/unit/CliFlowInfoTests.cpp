#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include <vector>

#include "TestSupport.h"
#include "PcapTestUtils.h"
#include "app/frontend/FrontendSessionAdapter.h"
#include "app/session/SessionFlowHelpers.h"
#include "cli/FlowInfoCommand.h"
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

std::filesystem::path write_temp_text_file(const std::string& filename, const std::string& text) {
    const auto path = std::filesystem::temp_directory_path() / filename;
    std::ofstream stream {path, std::ios::binary | std::ios::trunc};
    stream << text;
    return path;
}

cli::CliInvocationResult invoke_cli(const std::vector<std::string>& args_storage) {
    std::vector<std::string_view> args {};
    args.reserve(args_storage.size());
    for (const auto& arg : args_storage) {
        args.push_back(arg);
    }
    return cli::process_cli_invocation(args);
}

std::string settings_json(
    const bool ignore_gtpu_teids_when_grouping_inner_flows = false,
    const bool ignore_vlan_and_mpls_layers_when_grouping_flows = false,
    const bool validate_selected_packet_checksums = false
) {
    return std::string {"{"}
        + "\"ignore_vlan_and_mpls_layers_when_grouping_flows\":"
        + (ignore_vlan_and_mpls_layers_when_grouping_flows ? "true" : "false") + ','
        + "\"ignore_gtpu_teids_when_grouping_inner_flows\":"
        + (ignore_gtpu_teids_when_grouping_inner_flows ? "true" : "false") + ','
        + "\"validate_selected_packet_checksums\":"
        + (validate_selected_packet_checksums ? "true" : "false")
        + "}";
}

std::vector<std::uint8_t> make_http_request_payload() {
    constexpr char request[] =
        "GET /flow-info HTTP/1.1\r\n"
        "Host: cli-flow-info.example\r\n"
        "\r\n";
    return std::vector<std::uint8_t>(request, request + sizeof(request) - 1U);
}

std::vector<std::uint8_t> make_http_response_payload() {
    constexpr char response[] =
        "HTTP/1.1 200 OK\r\n"
        "Content-Length: 0\r\n"
        "\r\n";
    return std::vector<std::uint8_t>(response, response + sizeof(response) - 1U);
}

std::filesystem::path build_cli_flow_info_capture_path() {
    const auto request_one = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
        ipv4(10, 1, 0, 10),
        ipv4(10, 1, 0, 20),
        41000,
        80,
        make_http_request_payload(),
        0x18
    );
    const auto response_one = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
        ipv4(10, 1, 0, 20),
        ipv4(10, 1, 0, 10),
        80,
        41000,
        make_http_response_payload(),
        0x18
    );
    const auto request_two = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
        ipv4(10, 1, 0, 10),
        ipv4(10, 1, 0, 20),
        41000,
        80,
        make_http_request_payload(),
        0x18
    );
    const auto other_flow = make_ethernet_ipv4_udp_packet(
        ipv4(10, 2, 0, 1),
        ipv4(10, 2, 0, 2),
        53000,
        53
    );

    return write_temp_pcap(
        "pfl_cli_flow_info_capture.pcap",
        make_classic_pcap_with_captured_lengths({
            {.ts_usec = 100U, .captured_bytes = request_one, .original_length = static_cast<std::uint32_t>(request_one.size())},
            {.ts_usec = 300U, .captured_bytes = response_one, .original_length = static_cast<std::uint32_t>(response_one.size())},
            {.ts_usec = 900U, .captured_bytes = std::vector<std::uint8_t>(request_two.begin(), request_two.begin() + 54), .original_length = static_cast<std::uint32_t>(request_two.size())},
            {.ts_usec = 1200U, .captured_bytes = other_flow, .original_length = static_cast<std::uint32_t>(other_flow.size())},
        })
    );
}

void expect_flow_info_help_and_parser_behavior() {
    {
        const std::vector<std::string> args {"flow-info", "-h"};
        const auto result = invoke_cli(args);
        PFL_EXPECT(result.handled);
        PFL_EXPECT(result.exit_code == 0);
        PFL_EXPECT(result.stderr_text.empty());
        PFL_EXPECT(contains_text(result.stdout_text, "PcapFlowLab CLI - flow-info"));
        PFL_EXPECT(contains_text(result.stdout_text, "pcap-flow-lab flow-info <input> --flow-number <N> [options]"));
        PFL_EXPECT(contains_text(result.stdout_text, "--input <path>"));
        PFL_EXPECT(contains_text(result.stdout_text, "--flow-number <N>"));
        PFL_EXPECT(contains_text(result.stdout_text, "--settings <settings.json>"));
        PFL_EXPECT(!contains_text(result.stdout_text, "--flow-numbers"));
        PFL_EXPECT(!contains_text(result.stdout_text, "--source-capture"));
        PFL_EXPECT(!contains_text(result.stdout_text, "--format"));
        PFL_EXPECT(!contains_text(result.stdout_text, "\\--input"));
        PFL_EXPECT(!contains_text(result.stdout_text, "\\<input>"));
        PFL_EXPECT(has_no_tabs_or_trailing_spaces(result.stdout_text));
        PFL_EXPECT(has_no_ansi_escape_sequences(result.stdout_text));
    }

    {
        const std::vector<std::string> args {"flow-info", "--help", "--unknown"};
        const auto result = invoke_cli(args);
        PFL_EXPECT(result.handled);
        PFL_EXPECT(result.exit_code == 0);
        PFL_EXPECT(result.stderr_text.empty());
        PFL_EXPECT(contains_text(result.stdout_text, "PcapFlowLab CLI - flow-info"));
    }

    {
        const auto canonical = invoke_cli({"flow-info", "--help"});
        const auto alias = invoke_cli({"flows-info", "--help"});
        PFL_EXPECT(canonical.handled);
        PFL_EXPECT(alias.handled);
        PFL_EXPECT(canonical.exit_code == 0);
        PFL_EXPECT(alias.exit_code == 0);
        PFL_EXPECT(alias.stdout_text == canonical.stdout_text);
        PFL_EXPECT(alias.stderr_text == canonical.stderr_text);
        PFL_EXPECT(contains_text(alias.stdout_text, "pcap-flow-lab flow-info <input> --flow-number <N> [options]"));
    }

    {
        const std::vector<std::string_view> args {"capture.pcap", "--flow-number", "7"};
        const auto parse_result = cli::parse_flow_info_command_arguments(args);
        PFL_REQUIRE(parse_result.ok);
        PFL_REQUIRE(parse_result.options.has_value());
        PFL_EXPECT(parse_result.options->input_path == std::filesystem::path("capture.pcap"));
        PFL_EXPECT(parse_result.options->flow_index == 6U);
    }

    {
        const std::vector<std::string_view> args {"--input", "capture.pcap", "--flow-number", "7"};
        const auto parse_result = cli::parse_flow_info_command_arguments(args);
        PFL_REQUIRE(parse_result.ok);
        PFL_REQUIRE(parse_result.options.has_value());
        PFL_EXPECT(parse_result.options->input_path == std::filesystem::path("capture.pcap"));
        PFL_EXPECT(parse_result.options->flow_index == 6U);
    }

    {
        const std::vector<std::string_view> args {"capture.pcap", "--input", "capture.pcap", "--flow-number", "1"};
        const auto parse_result = cli::parse_flow_info_command_arguments(args);
        PFL_EXPECT(!parse_result.ok);
        PFL_EXPECT(contains_text(parse_result.error_text, "mutually exclusive"));
    }

    {
        const std::vector<std::string_view> args {"capture.pcap"};
        const auto parse_result = cli::parse_flow_info_command_arguments(args);
        PFL_EXPECT(!parse_result.ok);
        PFL_EXPECT(contains_text(parse_result.error_text, "--flow-number"));
    }

    {
        const std::vector<std::string_view> args {"capture.pcap", "--flow-number", "0"};
        const auto parse_result = cli::parse_flow_info_command_arguments(args);
        PFL_EXPECT(!parse_result.ok);
        PFL_EXPECT(contains_text(parse_result.error_text, "positive 1-based"));
    }

    {
        const std::vector<std::string_view> args {"capture.pcap", "--flow-number", "1", "--flow-number", "2"};
        const auto parse_result = cli::parse_flow_info_command_arguments(args);
        PFL_EXPECT(!parse_result.ok);
        PFL_EXPECT(contains_text(parse_result.error_text, "Duplicate --flow-number"));
    }

    {
        const std::vector<std::string_view> args {"capture.pcap", "--flow-numbers", "1-2"};
        const auto parse_result = cli::parse_flow_info_command_arguments(args);
        PFL_EXPECT(!parse_result.ok);
        PFL_EXPECT(contains_text(parse_result.error_text, "exactly one canonical flow"));
    }
}

void expect_shared_flow_info_model_and_cli_output() {
    const auto capture_path = build_cli_flow_info_capture_path();
    const auto request_one = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
        ipv4(10, 1, 0, 10),
        ipv4(10, 1, 0, 20),
        41000,
        80,
        make_http_request_payload(),
        0x18
    );
    const auto response_one = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
        ipv4(10, 1, 0, 20),
        ipv4(10, 1, 0, 10),
        80,
        41000,
        make_http_response_payload(),
        0x18
    );
    const auto expected_max_captured_packet_size_text = session_detail::format_statistics_size_value(
        std::max<std::size_t>(request_one.size(), response_one.size())
    );
    const auto expected_captured_bytes =
        static_cast<std::uint64_t>(request_one.size()) +
        static_cast<std::uint64_t>(response_one.size()) +
        54U;

    FrontendSessionAdapter adapter {};
    PFL_REQUIRE(adapter.open_capture(capture_path).opened);

    const auto row = adapter.flow_row(0U);
    PFL_REQUIRE(row.has_value());

    const auto info = adapter.get_flow_info(0U);
    PFL_EXPECT(info.has_capture);
    PFL_EXPECT(info.flow_available);
    PFL_EXPECT(info.analysis_available);
    PFL_EXPECT(info.flow_index == 0U);
    PFL_EXPECT(info.endpoint_a == row->endpoint_a);
    PFL_EXPECT(info.endpoint_b == row->endpoint_b);
    PFL_EXPECT(info.protocol_text == row->protocol_text);
    PFL_EXPECT(info.protocol_hint_display == session_detail::format_flow_protocol_hint_display(row->protocol_hint));
    PFL_EXPECT(info.total_packets == 3U);
    PFL_EXPECT(info.total_packets_text == "3");
    PFL_EXPECT(info.packets_a_to_b == 2U);
    PFL_EXPECT(info.packets_b_to_a == 1U);
    PFL_EXPECT(info.captured_bytes == expected_captured_bytes);
    PFL_EXPECT(!info.captured_bytes_text.empty());
    PFL_EXPECT(info.captured_bytes < info.total_bytes);
    PFL_EXPECT(!info.protocol_path_text.empty());
    PFL_EXPECT(info.max_captured_packet_size_text == expected_max_captured_packet_size_text);
    PFL_EXPECT(!info.packet_direction_text.empty());
    PFL_EXPECT(!info.data_direction_text.empty());
    PFL_EXPECT(!info.packet_size_histogram_rows.empty());

    {
        const std::vector<std::string> args {
            "flow-info",
            capture_path.string(),
            "--flow-number",
            "1",
            "--progress",
            "off",
        };
        const auto result = invoke_cli(args);
        PFL_EXPECT(result.handled);
        PFL_EXPECT(result.exit_code == 0);
        PFL_EXPECT(result.stderr_text.empty());
        PFL_EXPECT(contains_text(result.stdout_text, "Flow 1"));
        PFL_EXPECT(contains_text(result.stdout_text, "\nIdentity\n"));
        PFL_EXPECT(contains_text(result.stdout_text, "\nTraffic\n"));
        PFL_EXPECT(contains_text(result.stdout_text, "\nDirection\n"));
        PFL_EXPECT(contains_text(result.stdout_text, "\nPacket Size Histogram\n"));
        PFL_EXPECT(contains_text(result.stdout_text, "\nTiming\n"));
        PFL_EXPECT(contains_text(result.stdout_text, "Endpoints: "));
        PFL_EXPECT(!contains_text(result.stdout_text, "Endpoint A: "));
        PFL_EXPECT(!contains_text(result.stdout_text, "Endpoint B: "));
        PFL_EXPECT(contains_text(result.stdout_text, "Detected Protocol: "));
        PFL_EXPECT(!contains_text(result.stdout_text, "Protocol Hint: "));
        PFL_EXPECT(contains_text(result.stdout_text, "Protocol Path: "));
        PFL_EXPECT(contains_text(
            result.stdout_text,
            "Max Captured Packet Size: " + expected_max_captured_packet_size_text
        ));
        PFL_EXPECT(contains_text(result.stdout_text, "First Packet: "));
        PFL_EXPECT(contains_text(result.stdout_text, "Last Packet: "));
        PFL_EXPECT(!contains_text(result.stdout_text, "First Seen: "));
        PFL_EXPECT(!contains_text(result.stdout_text, "Last Seen: "));
        PFL_EXPECT(contains_text(result.stdout_text, "Packet Direction: "));
        PFL_EXPECT(contains_text(result.stdout_text, "Data Direction: "));
        PFL_EXPECT(contains_text(result.stdout_text, "A -> B"));
        PFL_EXPECT(contains_text(result.stdout_text, "B -> A"));
        PFL_EXPECT(!contains_text(result.stdout_text, "max: "));
        PFL_EXPECT(has_no_tabs_or_trailing_spaces(result.stdout_text));
        PFL_EXPECT(has_no_ansi_escape_sequences(result.stdout_text));
    }
}

void expect_flow_info_runtime_and_index_behavior() {
    const auto capture_path = build_cli_flow_info_capture_path();

    {
        const std::vector<std::string> args {
            "flow-info",
            fixture_path("parsing/mdns/01_mdns_ipv4_ptr_query.pcap").string(),
            "--flow-number",
            "1",
            "--progress",
            "off",
        };
        const auto result = invoke_cli(args);
        PFL_EXPECT(result.handled);
        PFL_EXPECT(result.exit_code == 0);
        PFL_EXPECT(contains_text(result.stdout_text, "Detected Protocol: mDNS"));
        PFL_EXPECT(contains_text(result.stdout_text, "Service: _demo-service._tcp.local"));
        PFL_EXPECT(!contains_text(result.stdout_text, "Detected Protocol: MDNS"));
    }

    {
        const auto canonical = invoke_cli({
            "flow-info",
            capture_path.string(),
            "--flow-number",
            "1",
            "--progress",
            "off",
        });
        const auto alias = invoke_cli({
            "flows-info",
            capture_path.string(),
            "--flow-number",
            "1",
            "--progress",
            "off",
        });
        PFL_EXPECT(alias.handled);
        PFL_EXPECT(alias.exit_code == canonical.exit_code);
        PFL_EXPECT(alias.stdout_text == canonical.stdout_text);
        PFL_EXPECT(alias.stderr_text == canonical.stderr_text);
    }

    {
        const std::vector<std::string> args {
            "flow-info",
            capture_path.string(),
            "--flow-number",
            "99",
        };
        const auto result = invoke_cli(args);
        PFL_EXPECT(result.handled);
        PFL_EXPECT(result.exit_code == 1);
        PFL_EXPECT(result.stdout_text.empty());
        PFL_EXPECT(contains_text(result.stderr_text, "Flow 99 is out of range"));
        PFL_EXPECT(!contains_text(result.stderr_text, "PcapFlowLab CLI - flow-info"));
    }

    {
        const auto settings_path = write_temp_text_file(
            "pfl_cli_flow_info_settings.json",
            settings_json(false, false, true)
        );
        const std::vector<std::string> args {
            "flow-info",
            capture_path.string(),
            "--flow-number",
            "1",
            "--settings",
            settings_path.string(),
        };
        const auto result = invoke_cli(args);
        PFL_EXPECT(result.handled);
        PFL_EXPECT(result.exit_code == 0);
        PFL_EXPECT(contains_text(result.stdout_text, "Flow 1"));
    }

    std::filesystem::path index_path = std::filesystem::temp_directory_path() / "pfl_cli_flow_info.idx";
    std::filesystem::remove(index_path);
    {
        FrontendSessionAdapter adapter {};
        PFL_REQUIRE(adapter.open_capture(capture_path).opened);
        PFL_REQUIRE(adapter.save_index(index_path).saved);
    }
    std::filesystem::remove(capture_path);

    std::string raw_stdout {};
    {
        const auto raw_capture_path = build_cli_flow_info_capture_path();
        const std::vector<std::string> args {
            "flow-info",
            raw_capture_path.string(),
            "--flow-number",
            "1",
            "--progress",
            "off",
        };
        const auto result = invoke_cli(args);
        PFL_EXPECT(result.handled);
        PFL_EXPECT(result.exit_code == 0);
        raw_stdout = result.stdout_text;
    }

    {
        const std::vector<std::string> args {
            "flow-info",
            index_path.string(),
            "--flow-number",
            "1",
            "--progress",
            "off",
        };
        const auto result = invoke_cli(args);
        PFL_EXPECT(result.handled);
        PFL_EXPECT(result.exit_code == 0);
        PFL_EXPECT(result.stderr_text.empty());
        PFL_EXPECT(result.stdout_text == raw_stdout);
        PFL_EXPECT(contains_text(result.stdout_text, "Endpoints: "));
        PFL_EXPECT(!contains_text(result.stdout_text, "Endpoint A: "));
        PFL_EXPECT(!contains_text(result.stdout_text, "Endpoint B: "));
        PFL_EXPECT(contains_text(result.stdout_text, "Detected Protocol: "));
        PFL_EXPECT(!contains_text(result.stdout_text, "Protocol Hint: "));
        PFL_EXPECT(contains_text(result.stdout_text, "First Packet: "));
        PFL_EXPECT(contains_text(result.stdout_text, "Last Packet: "));
        PFL_EXPECT(!contains_text(result.stdout_text, "First Seen: "));
        PFL_EXPECT(!contains_text(result.stdout_text, "Last Seen: "));
        PFL_EXPECT(contains_text(result.stdout_text, "A -> B"));
        PFL_EXPECT(contains_text(result.stdout_text, "B -> A"));
    }

    {
        const auto settings_path = write_temp_text_file(
            "pfl_cli_flow_info_index_settings.json",
            settings_json()
        );
        const std::vector<std::string> args {
            "flow-info",
            index_path.string(),
            "--flow-number",
            "1",
            "--settings",
            settings_path.string(),
        };
        const auto result = invoke_cli(args);
        PFL_EXPECT(result.handled);
        PFL_EXPECT(result.exit_code == 1);
        PFL_EXPECT(result.stdout_text.empty());
        PFL_EXPECT(contains_text(result.stderr_text, "--settings is valid only for raw capture input"));
    }
}

}  // namespace

void run_cli_flow_info_tests() {
    expect_flow_info_help_and_parser_behavior();
    expect_shared_flow_info_model_and_cli_output();
    expect_flow_info_runtime_and_index_behavior();
}

}  // namespace pfl::tests
