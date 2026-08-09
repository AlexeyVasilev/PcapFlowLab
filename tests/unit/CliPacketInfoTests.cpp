#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "TestSupport.h"
#include "PcapTestUtils.h"
#include "app/frontend/FrontendSessionAdapter.h"
#include "app/session/SessionFlowHelpers.h"
#include "cli/PacketInfoCommand.h"
#include "cli/SummaryCommand.h"
#include "core/services/HexDumpService.h"

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
        "GET /packet-info HTTP/1.1\r\n"
        "Host: cli-packet-info.example\r\n"
        "\r\n";
    return std::vector<std::uint8_t>(request, request + sizeof(request) - 1U);
}

std::vector<std::uint8_t> make_http_response_payload() {
    constexpr char response[] =
        "HTTP/1.1 204 No Content\r\n"
        "Content-Length: 0\r\n"
        "\r\n";
    return std::vector<std::uint8_t>(response, response + sizeof(response) - 1U);
}

std::vector<std::uint8_t> unrecognized_ethernet_frame() {
    return {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
        0x12, 0x34,
        0xde, 0xad, 0xbe, 0xef,
    };
}

std::filesystem::path build_cli_packet_info_capture_path(
    const std::string& file_name = "pfl_cli_packet_info_capture.pcap"
) {
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
        file_name,
        make_classic_pcap_with_captured_lengths({
            {.ts_usec = 100U, .captured_bytes = request_one, .original_length = static_cast<std::uint32_t>(request_one.size())},
            {.ts_usec = 300U, .captured_bytes = response_one, .original_length = static_cast<std::uint32_t>(response_one.size())},
            {.ts_usec = 900U, .captured_bytes = std::vector<std::uint8_t>(request_two.begin(), request_two.begin() + 54), .original_length = static_cast<std::uint32_t>(request_two.size())},
            {.ts_usec = 1200U, .captured_bytes = other_flow, .original_length = static_cast<std::uint32_t>(other_flow.size())},
        })
    );
}

std::filesystem::path build_cli_packet_info_unrecognized_capture_path() {
    const auto recognized_packet = make_ethernet_ipv4_udp_packet(
        ipv4(10, 3, 0, 1),
        ipv4(10, 3, 0, 2),
        53000,
        53
    );
    const auto unrecognized_packet = unrecognized_ethernet_frame();
    return write_temp_pcap(
        "pfl_cli_packet_info_unrecognized_capture.pcap",
        make_classic_pcap(std::vector<std::pair<std::uint32_t, std::vector<std::uint8_t>>> {
            {100U, recognized_packet},
            {200U, unrecognized_packet},
        })
    );
}

std::string expected_packet_hex_dump(const std::filesystem::path& capture_path, const std::uint64_t packet_index) {
    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(capture_path));
    const auto packet = session.find_packet(packet_index);
    PFL_REQUIRE(packet.has_value());
    HexDumpService hex_dump_service {};
    return hex_dump_service.format(session.read_packet_data(*packet));
}

std::uint32_t expected_captured_length(const std::filesystem::path& capture_path, const std::uint64_t packet_index) {
    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(capture_path));
    const auto packet = session.find_packet(packet_index);
    PFL_REQUIRE(packet.has_value());
    return packet->captured_length;
}

void expect_packet_info_help_and_parser_behavior() {
    {
        const std::vector<std::string> args {"packet-info", "-h"};
        const auto result = invoke_cli(args);
        PFL_EXPECT(result.handled);
        PFL_EXPECT(result.exit_code == 0);
        PFL_EXPECT(result.stderr_text.empty());
        PFL_EXPECT(contains_text(result.stdout_text, "PcapFlowLab CLI - packet-info"));
        PFL_EXPECT(contains_text(result.stdout_text, "--packet-in-file <N>"));
        PFL_EXPECT(contains_text(result.stdout_text, "--flow-number <F>"));
        PFL_EXPECT(contains_text(result.stdout_text, "--packet-in-flow <P>"));
        PFL_EXPECT(contains_text(result.stdout_text, "--bytes"));
        PFL_EXPECT(!contains_text(result.stdout_text, "\\--input"));
        PFL_EXPECT(!contains_text(result.stdout_text, "\\<input>"));
        PFL_EXPECT(has_no_tabs_or_trailing_spaces(result.stdout_text));
        PFL_EXPECT(has_no_ansi_escape_sequences(result.stdout_text));
    }

    {
        const std::vector<std::string> args {"packet-info", "--help", "--unknown"};
        const auto result = invoke_cli(args);
        PFL_EXPECT(result.handled);
        PFL_EXPECT(result.exit_code == 0);
        PFL_EXPECT(result.stderr_text.empty());
        PFL_EXPECT(contains_text(result.stdout_text, "PcapFlowLab CLI - packet-info"));
    }

    {
        const std::vector<std::string_view> args {"capture.pcap", "--packet-in-file", "7"};
        const auto parse_result = cli::parse_packet_info_command_arguments(args);
        PFL_REQUIRE(parse_result.ok);
        PFL_REQUIRE(parse_result.options.has_value());
        PFL_EXPECT(parse_result.options->input_path == std::filesystem::path("capture.pcap"));
        PFL_EXPECT(parse_result.options->packet_in_file == 7U);
    }

    {
        const std::vector<std::string_view> args {"--input", "capture.pcap", "--flow-number", "2", "--packet-in-flow", "5"};
        const auto parse_result = cli::parse_packet_info_command_arguments(args);
        PFL_REQUIRE(parse_result.ok);
        PFL_REQUIRE(parse_result.options.has_value());
        PFL_EXPECT(parse_result.options->flow_index == 1U);
        PFL_EXPECT(parse_result.options->packet_in_flow == 5U);
    }

    {
        const std::vector<std::string_view> args {"capture.pcap", "--input", "capture.pcap", "--packet-in-file", "1"};
        const auto parse_result = cli::parse_packet_info_command_arguments(args);
        PFL_EXPECT(!parse_result.ok);
        PFL_EXPECT(contains_text(parse_result.error_text, "mutually exclusive"));
    }

    {
        const std::vector<std::string_view> args {"capture.pcap"};
        const auto parse_result = cli::parse_packet_info_command_arguments(args);
        PFL_EXPECT(!parse_result.ok);
        PFL_EXPECT(contains_text(parse_result.error_text, "requires either --packet-in-file"));
    }

    {
        const std::vector<std::string_view> args {"capture.pcap", "--flow-number", "1"};
        const auto parse_result = cli::parse_packet_info_command_arguments(args);
        PFL_EXPECT(!parse_result.ok);
        PFL_EXPECT(contains_text(parse_result.error_text, "--flow-number and --packet-in-flow"));
    }

    {
        const std::vector<std::string_view> args {"capture.pcap", "--packet-in-flow", "1"};
        const auto parse_result = cli::parse_packet_info_command_arguments(args);
        PFL_EXPECT(!parse_result.ok);
        PFL_EXPECT(contains_text(parse_result.error_text, "--flow-number and --packet-in-flow"));
    }

    {
        const std::vector<std::string_view> args {"capture.pcap", "--flow-number", "1", "--packet-in-file", "2"};
        const auto parse_result = cli::parse_packet_info_command_arguments(args);
        PFL_EXPECT(!parse_result.ok);
        PFL_EXPECT(contains_text(parse_result.error_text, "either flow-scoped selection or --packet-in-file"));
    }

    {
        const std::vector<std::string_view> args {"capture.pcap", "--packet-in-flow", "1", "--packet-in-file", "2"};
        const auto parse_result = cli::parse_packet_info_command_arguments(args);
        PFL_EXPECT(!parse_result.ok);
        PFL_EXPECT(contains_text(parse_result.error_text, "--flow-number and --packet-in-flow"));
    }

    {
        const std::vector<std::string_view> args {"capture.pcap", "--flow-number", "1", "--packet-in-flow", "2", "--packet-in-file", "3"};
        const auto parse_result = cli::parse_packet_info_command_arguments(args);
        PFL_EXPECT(!parse_result.ok);
        PFL_EXPECT(contains_text(parse_result.error_text, "either flow-scoped selection or --packet-in-file"));
    }

    {
        const std::vector<std::string_view> args {"capture.pcap", "--packet-in-file", "0"};
        const auto parse_result = cli::parse_packet_info_command_arguments(args);
        PFL_EXPECT(!parse_result.ok);
        PFL_EXPECT(contains_text(parse_result.error_text, "positive 1-based"));
    }

    {
        const std::vector<std::string_view> args {"capture.pcap", "--packet-in-flow", "0", "--flow-number", "1"};
        const auto parse_result = cli::parse_packet_info_command_arguments(args);
        PFL_EXPECT(!parse_result.ok);
        PFL_EXPECT(contains_text(parse_result.error_text, "positive 1-based"));
    }

    {
        const std::vector<std::string_view> args {"capture.pcap", "--packet-in-file", "abc"};
        const auto parse_result = cli::parse_packet_info_command_arguments(args);
        PFL_EXPECT(!parse_result.ok);
        PFL_EXPECT(contains_text(parse_result.error_text, "positive 1-based"));
    }

    {
        const std::vector<std::string_view> args {"capture.pcap", "--packet-in-file", "184467440737095516160"};
        const auto parse_result = cli::parse_packet_info_command_arguments(args);
        PFL_EXPECT(!parse_result.ok);
        PFL_EXPECT(contains_text(parse_result.error_text, "positive 1-based"));
    }

    {
        const std::vector<std::string_view> args {"capture.pcap", "--packet-in-file", "1", "--packet-in-file", "2"};
        const auto parse_result = cli::parse_packet_info_command_arguments(args);
        PFL_EXPECT(!parse_result.ok);
        PFL_EXPECT(contains_text(parse_result.error_text, "Duplicate --packet-in-file"));
    }

    {
        const std::vector<std::string_view> args {"capture.pcap", "--flow-number", "1", "--flow-number", "2", "--packet-in-flow", "1"};
        const auto parse_result = cli::parse_packet_info_command_arguments(args);
        PFL_EXPECT(!parse_result.ok);
        PFL_EXPECT(contains_text(parse_result.error_text, "Duplicate --flow-number"));
    }

    {
        const std::vector<std::string_view> args {"capture.pcap", "--flow-number", "1", "--packet-in-flow", "1", "--unknown"};
        const auto parse_result = cli::parse_packet_info_command_arguments(args);
        PFL_EXPECT(!parse_result.ok);
        PFL_EXPECT(contains_text(parse_result.error_text, "Unknown packet-info option"));
    }

    {
        const std::vector<std::string_view> args {"capture.pcap", "--packet-number", "1"};
        const auto parse_result = cli::parse_packet_info_command_arguments(args);
        PFL_EXPECT(!parse_result.ok);
        PFL_EXPECT(contains_text(parse_result.error_text, "does not accept --packet-number"));
    }

    {
        const std::vector<std::string_view> args {"capture.pcap", "--packet-in-file", "1", "--byte-view", "frame:0:0"};
        const auto parse_result = cli::parse_packet_info_command_arguments(args);
        PFL_EXPECT(!parse_result.ok);
        PFL_EXPECT(contains_text(parse_result.error_text, "does not accept --byte-view"));
    }

    {
        const std::vector<std::string_view> args {"capture.pcap", "--packet-in-file", "1", "--format", "json"};
        const auto parse_result = cli::parse_packet_info_command_arguments(args);
        PFL_EXPECT(!parse_result.ok);
        PFL_EXPECT(contains_text(parse_result.error_text, "does not accept --format"));
    }

    {
        const std::vector<std::string_view> args {"capture.pcap", "--packet-in-file", "1", "--out", "packet.txt"};
        const auto parse_result = cli::parse_packet_info_command_arguments(args);
        PFL_EXPECT(!parse_result.ok);
        PFL_EXPECT(contains_text(parse_result.error_text, "does not accept --out"));
    }
}

void expect_shared_packet_info_model_behavior() {
    const auto capture_path = build_cli_packet_info_capture_path("pfl_cli_packet_info_shared_capture.pcap");

    FrontendSessionAdapter adapter {};
    PFL_REQUIRE(adapter.open_capture(capture_path).opened);

    const auto flow_scoped = adapter.get_packet_info_by_flow(0U, 2U);
    PFL_EXPECT(flow_scoped.has_capture);
    PFL_EXPECT(flow_scoped.packet_available);
    PFL_EXPECT(flow_scoped.recognized_flow);
    PFL_EXPECT(flow_scoped.flow_index == std::optional<std::size_t> {0U});
    PFL_EXPECT(flow_scoped.packet_in_flow == std::optional<std::uint64_t> {2U});
    PFL_EXPECT(flow_scoped.packet_in_file == 2U);
    PFL_EXPECT(flow_scoped.direction_text == "B -> A");
    PFL_EXPECT(!flow_scoped.endpoint_summary_text.empty());
    PFL_EXPECT(!flow_scoped.summary_layers.empty());

    const auto global_recognized = adapter.get_packet_info_by_file(1U);
    PFL_EXPECT(global_recognized.has_capture);
    PFL_EXPECT(global_recognized.packet_available);
    PFL_EXPECT(global_recognized.recognized_flow);
    PFL_EXPECT(global_recognized.flow_index == std::optional<std::size_t> {0U});
    PFL_EXPECT(global_recognized.packet_in_flow == std::optional<std::uint64_t> {2U});
    PFL_EXPECT(global_recognized.packet_in_file == 2U);
    PFL_EXPECT(global_recognized.direction_text == "B -> A");
    PFL_EXPECT(!global_recognized.endpoint_summary_text.empty());
    PFL_EXPECT(!global_recognized.summary_layers.empty());

    FrontendSessionAdapter unrecognized_adapter {};
    const auto unrecognized_capture_path = build_cli_packet_info_unrecognized_capture_path();
    PFL_REQUIRE(unrecognized_adapter.open_capture(unrecognized_capture_path).opened);
    const auto global_unrecognized = unrecognized_adapter.get_packet_info_by_file(1U);
    PFL_EXPECT(global_unrecognized.has_capture);
    PFL_EXPECT(global_unrecognized.packet_available);
    PFL_EXPECT(!global_unrecognized.recognized_flow);
    PFL_EXPECT(!global_unrecognized.flow_index.has_value());
    PFL_EXPECT(!global_unrecognized.packet_in_flow.has_value());
    PFL_EXPECT(global_unrecognized.endpoint_summary_text.empty());
    PFL_EXPECT(global_unrecognized.direction_text.empty());
}

void expect_packet_info_runtime_and_output_behavior() {
    const auto capture_path = build_cli_packet_info_capture_path("pfl_cli_packet_info_runtime_capture.pcap");

    {
        const std::vector<std::string> args {
            "packet-info",
            capture_path.string(),
            "--flow-number",
            "1",
            "--packet-in-flow",
            "2",
            "--progress",
            "off",
        };
        const auto result = invoke_cli(args);
        PFL_EXPECT(result.handled);
        PFL_EXPECT(result.exit_code == 0);
        PFL_EXPECT(result.stderr_text.empty());
        PFL_EXPECT(contains_text(result.stdout_text, "Flow 1 / Packet 2"));
        PFL_EXPECT(contains_text(result.stdout_text, "\nFlow Context\n"));
        PFL_EXPECT(contains_text(result.stdout_text, "Endpoints: "));
        PFL_EXPECT(contains_text(result.stdout_text, "Direction: B -> A"));
        PFL_EXPECT(!contains_text(result.stdout_text, "\nFlow: "));
        PFL_EXPECT(!contains_text(result.stdout_text, "\nPacket in Flow: "));
        PFL_EXPECT(contains_text(result.stdout_text, "\nPacket\n"));
        PFL_EXPECT(contains_text(result.stdout_text, "Packet in File: 2"));
        PFL_EXPECT(contains_text(result.stdout_text, "Captured Length: "));
        PFL_EXPECT(contains_text(result.stdout_text, "Original Length: "));
        PFL_EXPECT(!contains_text(result.stdout_text, "Payload Length: "));
        PFL_EXPECT(contains_text(result.stdout_text, "\nSummary\n"));
        PFL_EXPECT(contains_text(result.stdout_text, "Ethernet II"));
        PFL_EXPECT(contains_text(result.stdout_text, "IPv4"));
        PFL_EXPECT(contains_text(result.stdout_text, "TCP"));
        PFL_EXPECT(!contains_text(result.stdout_text, "\nBytes\n"));
    }

    {
        const std::vector<std::string> args {
            "packet-info",
            capture_path.string(),
            "--packet-in-file",
            "2",
            "--progress",
            "off",
        };
        const auto result = invoke_cli(args);
        PFL_EXPECT(result.handled);
        PFL_EXPECT(result.exit_code == 0);
        PFL_EXPECT(result.stderr_text.empty());
        PFL_EXPECT(contains_text(result.stdout_text, "Packet 2"));
        PFL_EXPECT(contains_text(result.stdout_text, "\nFlow Context\n"));
        PFL_EXPECT(contains_text(result.stdout_text, "Flow: 1"));
        PFL_EXPECT(contains_text(result.stdout_text, "Packet in Flow: 2"));
        PFL_EXPECT(contains_text(result.stdout_text, "Direction: B -> A"));
        PFL_EXPECT(contains_text(result.stdout_text, "Packet in File: 2"));
        PFL_EXPECT(contains_text(result.stdout_text, "Ethernet II"));
        PFL_EXPECT(contains_text(result.stdout_text, "IPv4"));
        PFL_EXPECT(contains_text(result.stdout_text, "TCP"));
    }

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(capture_path));
        const auto packet = session.find_packet(1U);
        PFL_REQUIRE(packet.has_value());
        HexDumpService hex_dump_service {};
        const auto expected_hex = hex_dump_service.format(session.read_packet_data(*packet));

        const std::vector<std::string> args {
            "packet-info",
            capture_path.string(),
            "--packet-in-file",
            "2",
            "--bytes",
            "--progress",
            "off",
        };
        const auto result = invoke_cli(args);
        PFL_EXPECT(result.handled);
        PFL_EXPECT(result.exit_code == 0);
        PFL_EXPECT(contains_text(result.stdout_text, "\nSummary\n"));
        PFL_EXPECT(contains_text(result.stdout_text, "\nBytes\n"));
        PFL_EXPECT(contains_text(result.stdout_text, "Captured Packet - "));
        PFL_EXPECT(contains_text(result.stdout_text, expected_hex));
        PFL_EXPECT(!contains_text(result.stdout_text, "frame:0:0"));
        PFL_EXPECT(!contains_text(result.stdout_text, "Ethernet II Frame - "));
    }

    {
        const auto vlan_capture_path = fixture_path("parsing/vlan/01_vlan_ipv4_tcp.pcap");
        const auto expected_hex = expected_packet_hex_dump(vlan_capture_path, 0U);
        const auto captured_length = expected_captured_length(vlan_capture_path, 0U);
        const auto expected_length_text = std::string {"Captured Packet - "}
            + std::to_string(captured_length)
            + " bytes";

        const std::vector<std::string> flow_scoped_args {
            std::string {"packet-info"},
            vlan_capture_path.string(),
            std::string {"--flow-number"},
            std::string {"1"},
            std::string {"--packet-in-flow"},
            std::string {"1"},
            std::string {"--bytes"},
            std::string {"--progress"},
            std::string {"off"},
        };
        const auto flow_scoped_result = invoke_cli(flow_scoped_args);
        PFL_EXPECT(flow_scoped_result.handled);
        PFL_EXPECT(flow_scoped_result.exit_code == 0);
        PFL_EXPECT(flow_scoped_result.stderr_text.empty());
        PFL_EXPECT(contains_text(flow_scoped_result.stdout_text, "\nSummary\n"));
        PFL_EXPECT(contains_text(flow_scoped_result.stdout_text, "\nBytes\n"));
        PFL_EXPECT(contains_text(flow_scoped_result.stdout_text, expected_length_text));
        PFL_EXPECT(contains_text(flow_scoped_result.stdout_text, expected_hex));

        const std::vector<std::string> global_args {
            std::string {"packet-info"},
            vlan_capture_path.string(),
            std::string {"--packet-in-file"},
            std::string {"1"},
            std::string {"--bytes"},
            std::string {"--progress"},
            std::string {"off"},
        };
        const auto global_result = invoke_cli(global_args);
        PFL_EXPECT(global_result.handled);
        PFL_EXPECT(global_result.exit_code == 0);
        PFL_EXPECT(global_result.stderr_text.empty());
        PFL_EXPECT(contains_text(global_result.stdout_text, expected_length_text));
        PFL_EXPECT(contains_text(global_result.stdout_text, expected_hex));
        PFL_EXPECT(!contains_text(flow_scoped_result.stderr_text, "requested byte view is unavailable"));
        PFL_EXPECT(!contains_text(global_result.stderr_text, "requested byte view is unavailable"));
    }

    {
        const auto mpls_capture_path = fixture_path("parsing/mpls/13_vlan_mpls_ipv4_tcp.pcap");
        const auto expected_hex = expected_packet_hex_dump(mpls_capture_path, 0U);
        const auto captured_length = expected_captured_length(mpls_capture_path, 0U);
        const auto expected_length_text = std::string {"Captured Packet - "}
            + std::to_string(captured_length)
            + " bytes";

        const std::vector<std::string> args {
            std::string {"packet-info"},
            mpls_capture_path.string(),
            std::string {"--flow-number"},
            std::string {"1"},
            std::string {"--packet-in-flow"},
            std::string {"1"},
            std::string {"--bytes"},
            std::string {"--progress"},
            std::string {"off"},
        };
        const auto result = invoke_cli(args);
        PFL_EXPECT(result.handled);
        PFL_EXPECT(result.exit_code == 0);
        PFL_EXPECT(result.stderr_text.empty());
        PFL_EXPECT(contains_text(result.stdout_text, expected_length_text));
        PFL_EXPECT(contains_text(result.stdout_text, expected_hex));
    }

    {
        const auto unrecognized_capture_path = build_cli_packet_info_unrecognized_capture_path();
        const std::vector<std::string> args {
            "packet-info",
            unrecognized_capture_path.string(),
            "--packet-in-file",
            "2",
            "--progress",
            "off",
        };
        const auto result = invoke_cli(args);
        PFL_EXPECT(result.handled);
        PFL_EXPECT(result.exit_code == 0);
        PFL_EXPECT(result.stderr_text.empty());
        PFL_EXPECT(contains_text(result.stdout_text, "Packet 2"));
        PFL_EXPECT(contains_text(result.stdout_text, "Recognized Flow: No"));
        PFL_EXPECT(!contains_text(result.stdout_text, "\nFlow: "));
        PFL_EXPECT(!contains_text(result.stdout_text, "Endpoints: "));
        PFL_EXPECT(!contains_text(result.stdout_text, "Direction: "));
        PFL_EXPECT(contains_text(result.stdout_text, "\nPacket\n"));
        PFL_EXPECT(contains_text(result.stdout_text, "\nSummary\n"));
        PFL_EXPECT(contains_text(result.stdout_text, "Frame"));
    }

    {
        const std::vector<std::string> args {
            "packet-info",
            capture_path.string(),
            "--packet-in-file",
            "99",
        };
        const auto result = invoke_cli(args);
        PFL_EXPECT(result.handled);
        PFL_EXPECT(result.exit_code == 1);
        PFL_EXPECT(result.stdout_text.empty());
        PFL_EXPECT(contains_text(result.stderr_text, "Packet 99 is out of range"));
        PFL_EXPECT(!contains_text(result.stderr_text, "PcapFlowLab CLI - packet-info"));
    }

    {
        const std::vector<std::string> args {
            "packet-info",
            capture_path.string(),
            "--flow-number",
            "99",
            "--packet-in-flow",
            "1",
        };
        const auto result = invoke_cli(args);
        PFL_EXPECT(result.handled);
        PFL_EXPECT(result.exit_code == 1);
        PFL_EXPECT(result.stdout_text.empty());
        PFL_EXPECT(contains_text(result.stderr_text, "Flow 99 is out of range for this input"));
    }

    {
        const std::vector<std::string> args {
            "packet-info",
            capture_path.string(),
            "--flow-number",
            "1",
            "--packet-in-flow",
            "99",
        };
        const auto result = invoke_cli(args);
        PFL_EXPECT(result.handled);
        PFL_EXPECT(result.exit_code == 1);
        PFL_EXPECT(result.stdout_text.empty());
        PFL_EXPECT(contains_text(result.stderr_text, "Packet 99 is out of range for flow 1"));
    }

    {
        const auto settings_path = write_temp_text_file(
            "pfl_cli_packet_info_settings.json",
            settings_json(false, false, true)
        );
        const std::vector<std::string> args {
            "packet-info",
            capture_path.string(),
            "--packet-in-file",
            "2",
            "--settings",
            settings_path.string(),
            "--progress",
            "off",
        };
        const auto result = invoke_cli(args);
        PFL_EXPECT(result.handled);
        PFL_EXPECT(result.exit_code == 0);
        PFL_EXPECT(contains_text(result.stdout_text, "Packet 2"));
    }

    {
        const std::vector<std::string> args {
            "packet-info",
            capture_path.string(),
            "--packet-in-file",
            "2",
            "--source-capture",
            capture_path.string(),
        };
        const auto result = invoke_cli(args);
        PFL_EXPECT(result.handled);
        PFL_EXPECT(result.exit_code == 1);
        PFL_EXPECT(result.stdout_text.empty());
        PFL_EXPECT(contains_text(result.stderr_text, "--source-capture is valid only for index input"));
    }

    std::filesystem::path index_path = std::filesystem::temp_directory_path() / "pfl_cli_packet_info.idx";
    std::filesystem::remove(index_path);
    {
        FrontendSessionAdapter adapter {};
        PFL_REQUIRE(adapter.open_capture(capture_path).opened);
        PFL_REQUIRE(adapter.save_index(index_path).saved);
    }

    std::string raw_stdout {};
    {
        const std::vector<std::string> args {
            "packet-info",
            capture_path.string(),
            "--packet-in-file",
            "2",
            "--progress",
            "off",
        };
        const auto result = invoke_cli(args);
        PFL_REQUIRE(result.handled);
        PFL_REQUIRE(result.exit_code == 0);
        raw_stdout = result.stdout_text;
    }

    {
        const std::vector<std::string> args {
            "packet-info",
            index_path.string(),
            "--packet-in-file",
            "2",
            "--progress",
            "off",
        };
        const auto result = invoke_cli(args);
        PFL_EXPECT(result.handled);
        PFL_EXPECT(result.exit_code == 0);
        PFL_EXPECT(result.stderr_text.empty());
        PFL_EXPECT(result.stdout_text == raw_stdout);
    }

    std::filesystem::remove(capture_path);

    {
        const std::vector<std::string> args {
            "packet-info",
            index_path.string(),
            "--packet-in-file",
            "2",
            "--progress",
            "off",
        };
        const auto result = invoke_cli(args);
        PFL_EXPECT(result.handled);
        PFL_EXPECT(result.exit_code == 1);
        PFL_EXPECT(result.stdout_text.empty());
        PFL_EXPECT(contains_text(result.stderr_text, "Packet inspection requires source capture data."));
        PFL_EXPECT(contains_text(result.stderr_text, "Use --source-capture <path>"));
        PFL_EXPECT(!contains_text(result.stderr_text, "PcapFlowLab CLI - packet-info"));
    }

    {
        const auto moved_source_path = build_cli_packet_info_capture_path("pfl_cli_packet_info_moved_source.pcap");
        const std::vector<std::string> args {
            "packet-info",
            index_path.string(),
            "--packet-in-file",
            "2",
            "--source-capture",
            moved_source_path.string(),
            "--progress",
            "off",
        };
        const auto result = invoke_cli(args);
        PFL_EXPECT(result.handled);
        PFL_EXPECT(result.exit_code == 0);
        PFL_EXPECT(result.stderr_text.empty());
        PFL_EXPECT(result.stdout_text == raw_stdout);
    }

    {
        const auto index_capture_path = fixture_path("parsing/vlan/01_vlan_ipv4_tcp.pcap");
        const auto expected_hex = expected_packet_hex_dump(index_capture_path, 0U);
        std::filesystem::path fixture_index_path = std::filesystem::temp_directory_path() / "pfl_cli_packet_info_fixture.idx";
        std::filesystem::remove(fixture_index_path);

        FrontendSessionAdapter adapter {};
        PFL_REQUIRE(adapter.open_capture(index_capture_path).opened);
        PFL_REQUIRE(adapter.save_index(fixture_index_path).saved);

        const std::vector<std::string> args {
            std::string {"packet-info"},
            fixture_index_path.string(),
            std::string {"--flow-number"},
            std::string {"1"},
            std::string {"--packet-in-flow"},
            std::string {"1"},
            std::string {"--bytes"},
            std::string {"--source-capture"},
            index_capture_path.string(),
            std::string {"--progress"},
            std::string {"off"},
        };
        const auto result = invoke_cli(args);
        PFL_EXPECT(result.handled);
        PFL_EXPECT(result.exit_code == 0);
        PFL_EXPECT(result.stderr_text.empty());
        PFL_EXPECT(contains_text(result.stdout_text, "\nBytes\n"));
        PFL_EXPECT(contains_text(result.stdout_text, "Captured Packet - "));
        PFL_EXPECT(contains_text(result.stdout_text, expected_hex));
    }

    {
        const auto mismatched_source_path = build_cli_packet_info_unrecognized_capture_path();
        const std::vector<std::string> args {
            "packet-info",
            index_path.string(),
            "--packet-in-file",
            "2",
            "--source-capture",
            mismatched_source_path.string(),
            "--progress",
            "off",
        };
        const auto result = invoke_cli(args);
        PFL_EXPECT(result.handled);
        PFL_EXPECT(result.exit_code == 1);
        PFL_EXPECT(result.stdout_text.empty());
        PFL_EXPECT(contains_text(result.stderr_text, "Selected file does not match the expected source capture"));
        PFL_EXPECT(!contains_text(result.stderr_text, "PcapFlowLab CLI - packet-info"));
    }

    {
        const auto settings_path = write_temp_text_file(
            "pfl_cli_packet_info_index_settings.json",
            settings_json()
        );
        const std::vector<std::string> args {
            "packet-info",
            index_path.string(),
            "--packet-in-file",
            "2",
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

void run_cli_packet_info_tests() {
    expect_packet_info_help_and_parser_behavior();
    expect_shared_packet_info_model_behavior();
    expect_packet_info_runtime_and_output_behavior();
}

}  // namespace pfl::tests
