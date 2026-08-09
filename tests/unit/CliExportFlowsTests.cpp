#include <filesystem>
#include <fstream>
#include <initializer_list>
#include <limits>
#include <chrono>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "PcapTestUtils.h"
#include "TestSupport.h"
#include "app/frontend/FrontendSessionAdapter.h"
#include "cli/ExportFlowsCommand.h"
#include "cli/SummaryCommand.h"
#include "core/io/PcapReader.h"

namespace pfl::tests {

namespace {

std::filesystem::path fixture_path(const std::filesystem::path& relative_path) {
    return std::filesystem::path(__FILE__).parent_path().parent_path() / "data" / relative_path;
}

bool contains_text(const std::string_view haystack, const std::string_view needle) {
    return haystack.find(needle) != std::string_view::npos;
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

std::vector<std::string> read_text_file_lines(const std::filesystem::path& path) {
    std::ifstream stream {path, std::ios::binary};
    PFL_EXPECT(stream.is_open());

    std::vector<std::string> lines {};
    std::string line {};
    while (std::getline(stream, line)) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        lines.push_back(line);
    }
    return lines;
}

std::vector<std::string> split_csv_line(const std::string& line) {
    std::vector<std::string> fields {};
    std::string current {};
    bool in_quotes = false;

    for (std::size_t index = 0U; index < line.size(); ++index) {
        const char ch = line[index];
        if (in_quotes) {
            if (ch == '"') {
                if (index + 1U < line.size() && line[index + 1U] == '"') {
                    current.push_back('"');
                    ++index;
                } else {
                    in_quotes = false;
                }
            } else {
                current.push_back(ch);
            }
            continue;
        }

        if (ch == '"') {
            in_quotes = true;
            continue;
        }

        if (ch == ',') {
            fields.push_back(current);
            current.clear();
            continue;
        }

        current.push_back(ch);
    }

    fields.push_back(current);
    return fields;
}

std::vector<RawPcapPacket> read_all_packets(const std::filesystem::path& path) {
    PcapReader reader {};
    PFL_EXPECT(reader.open(path));

    std::vector<RawPcapPacket> packets {};
    while (const auto packet = reader.read_next()) {
        packets.push_back(*packet);
    }

    return packets;
}

template <typename Progress, typename RenderFn>
std::vector<std::string> collect_emitted_progress_lines(
    const std::vector<std::pair<std::chrono::milliseconds, Progress>>& samples,
    RenderFn&& render
) {
    cli::SmartExportCliProgressRenderState state {};
    std::vector<std::string> lines {};
    const auto base = std::chrono::steady_clock::time_point {};
    for (const auto& [offset, progress] : samples) {
        const auto line = render(progress, state, base + offset);
        if (line.has_value()) {
            lines.push_back(*line);
        }
    }
    return lines;
}

cli::ExportFlowsCommandParseResult parse_export_args(std::initializer_list<std::string_view> args) {
    const std::vector<std::string_view> values(args);
    return cli::parse_export_flows_command_arguments(values);
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
    const bool ignore_gtpu_teids_when_grouping_inner_flows,
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

std::filesystem::path build_export_cli_capture_path() {
    const auto flow_a_packet_1 = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
        ipv4(10, 1, 0, 1),
        ipv4(10, 1, 0, 2),
        41001,
        80,
        std::vector<std::uint8_t> {0xA1},
        0x18
    );
    const auto flow_b_packet_1 = make_ethernet_ipv4_udp_packet_with_bytes_payload(
        ipv4(10, 2, 0, 1),
        ipv4(10, 2, 0, 2),
        42001,
        53,
        std::vector<std::uint8_t> {0xB1}
    );
    const auto flow_a_packet_2 = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
        ipv4(10, 1, 0, 1),
        ipv4(10, 1, 0, 2),
        41001,
        80,
        std::vector<std::uint8_t> {0xA2},
        0x18
    );
    const auto flow_b_packet_2 = make_ethernet_ipv4_udp_packet_with_bytes_payload(
        ipv4(10, 2, 0, 1),
        ipv4(10, 2, 0, 2),
        42001,
        53,
        std::vector<std::uint8_t> {0xB2}
    );
    const auto flow_a_packet_3 = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
        ipv4(10, 1, 0, 1),
        ipv4(10, 1, 0, 2),
        41001,
        80,
        std::vector<std::uint8_t> {0xA3},
        0x18
    );
    const auto flow_b_packet_3 = make_ethernet_ipv4_udp_packet_with_bytes_payload(
        ipv4(10, 2, 0, 1),
        ipv4(10, 2, 0, 2),
        42001,
        53,
        std::vector<std::uint8_t> {0xB3}
    );
    const auto flow_a_packet_4 = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
        ipv4(10, 1, 0, 1),
        ipv4(10, 1, 0, 2),
        41001,
        80,
        std::vector<std::uint8_t> {0xA4},
        0x18
    );
    const auto flow_b_packet_4 = make_ethernet_ipv4_udp_packet_with_bytes_payload(
        ipv4(10, 2, 0, 1),
        ipv4(10, 2, 0, 2),
        42001,
        53,
        std::vector<std::uint8_t> {0xB4}
    );

    return write_temp_pcap(
        "pfl_cli_export_flows_source.pcap",
        make_classic_pcap({
            {100U, flow_a_packet_1},
            {200U, flow_b_packet_1},
            {300U, flow_a_packet_2},
            {400U, flow_b_packet_2},
            {500U, flow_a_packet_3},
            {600U, flow_b_packet_3},
            {700U, flow_a_packet_4},
            {800U, flow_b_packet_4},
        })
    );
}

std::filesystem::path build_original_bytes_capture_path() {
    return write_temp_pcap(
        "pfl_cli_export_flows_original_bytes_source.pcap",
        make_classic_pcap_with_captured_lengths({
            {
                .ts_usec = 100U,
                .captured_bytes = make_ethernet_ipv4_udp_packet_with_bytes_payload(
                    ipv4(10, 30, 0, 1),
                    ipv4(10, 30, 0, 2),
                    43001,
                    43002,
                    std::vector<std::uint8_t> {0x01}
                ),
                .original_length = 100U,
            },
            {
                .ts_usec = 200U,
                .captured_bytes = make_ethernet_ipv4_udp_packet_with_bytes_payload(
                    ipv4(10, 30, 0, 1),
                    ipv4(10, 30, 0, 2),
                    43001,
                    43002,
                    std::vector<std::uint8_t> {0x02}
                ),
                .original_length = 100U,
            },
            {
                .ts_usec = 300U,
                .captured_bytes = make_ethernet_ipv4_udp_packet_with_bytes_payload(
                    ipv4(10, 30, 0, 1),
                    ipv4(10, 30, 0, 2),
                    43001,
                    43002,
                    std::vector<std::uint8_t> {0x03}
                ),
                .original_length = 100U,
            },
            {
                .ts_usec = 400U,
                .captured_bytes = make_ethernet_ipv4_udp_packet_with_bytes_payload(
                    ipv4(10, 30, 0, 1),
                    ipv4(10, 30, 0, 2),
                    43001,
                    43002,
                    std::vector<std::uint8_t> {0x04}
                ),
                .original_length = 100U,
            },
        })
    );
}

std::filesystem::path build_unrecognized_export_cli_capture_path() {
    const auto malformed_packets =
        read_all_packets(fixture_path("parsing/tcp_options/19_tcp_syn_tcp_header_snaplen_truncated.pcap"));
    PFL_REQUIRE(!malformed_packets.empty());
    const auto& malformed_packet = malformed_packets.front();
    const auto recognized_packet_a = make_ethernet_ipv4_udp_packet_with_bytes_payload(
        ipv4(10, 90, 0, 1),
        ipv4(10, 90, 0, 2),
        49001,
        49002,
        std::vector<std::uint8_t> {0xA1}
    );
    const auto recognized_packet_b = make_ethernet_ipv4_udp_packet_with_bytes_payload(
        ipv4(10, 90, 0, 2),
        ipv4(10, 90, 0, 1),
        49002,
        49001,
        std::vector<std::uint8_t> {0xA2}
    );

    const std::vector<ClassicPcapCapturedRecord> packets {
        {.ts_usec = 100U, .captured_bytes = recognized_packet_a, .original_length = static_cast<std::uint32_t>(recognized_packet_a.size())},
        {.ts_usec = 200U, .captured_bytes = malformed_packet.bytes, .original_length = malformed_packet.original_length},
        {.ts_usec = 300U, .captured_bytes = recognized_packet_b, .original_length = static_cast<std::uint32_t>(recognized_packet_b.size())},
        {.ts_usec = 400U, .captured_bytes = malformed_packet.bytes, .original_length = malformed_packet.original_length},
    };

    return write_temp_pcap(
        "pfl_cli_export_unrecognized_source.pcap",
        make_classic_pcap_with_captured_lengths(packets)
    );
}

void expect_parser_and_help_behavior() {
    {
        const std::vector<std::string_view> args {"export-flows", "capture.pcap"};
        const auto decision = cli::classify_cli_invocation(args);
        PFL_EXPECT(decision.kind == cli::SummaryDispatchKind::export_flows);
        PFL_REQUIRE(decision.summary_args.size() == 1U);
        PFL_EXPECT(decision.summary_args[0] == "capture.pcap");
    }

    {
        const std::vector<std::string_view> args {"capture.pcap", "--all-flows", "--out", "selected.pcap"};
        const auto parse_result = cli::parse_export_flows_command_arguments(args);
        PFL_REQUIRE(parse_result.ok);
        PFL_REQUIRE(parse_result.options.has_value());
        PFL_EXPECT(parse_result.options->input_path == std::filesystem::path("capture.pcap"));
        PFL_EXPECT(parse_result.options->all_flows);
        PFL_EXPECT(parse_result.options->base_mode == SmartFlowExportBaseMode::all_packets);
        PFL_REQUIRE(parse_result.options->out_path.has_value());
        PFL_EXPECT(*parse_result.options->out_path == std::filesystem::path("selected.pcap"));
    }

    {
        const std::vector<std::string_view> args {
            "--input", "capture.pcap", "--flow-number", "42", "--out", "selected.pcap"
        };
        const auto parse_result = cli::parse_export_flows_command_arguments(args);
        PFL_REQUIRE(parse_result.ok);
        PFL_REQUIRE(parse_result.options.has_value());
        PFL_REQUIRE(parse_result.options->selected_flow_indices.has_value());
        const std::vector<std::size_t> expected {41U};
        PFL_EXPECT(*parse_result.options->selected_flow_indices == expected);
    }

    {
        const std::vector<std::string_view> args {"capture.pcap", "--input", "capture.pcap", "--all-flows", "--out", "x.pcap"};
        const auto parse_result = cli::parse_export_flows_command_arguments(args);
        PFL_EXPECT(!parse_result.ok);
        PFL_EXPECT(contains_text(parse_result.error_text, "mutually exclusive input forms"));
    }

    {
        const std::vector<std::string_view> args {
            "--input", "capture-a.pcap", "--input", "capture-b.pcap", "--all-flows", "--out", "x.pcap"
        };
        const auto parse_result = cli::parse_export_flows_command_arguments(args);
        PFL_EXPECT(!parse_result.ok);
        PFL_EXPECT(contains_text(parse_result.error_text, "Duplicate --input"));
    }

    {
        const auto parse_result = parse_export_args({
            "capture.pcap", "--all-flows", "--all-flows", "--out", "x.pcap"
        });
        PFL_EXPECT(!parse_result.ok);
        PFL_EXPECT(contains_text(parse_result.error_text, "Duplicate --all-flows"));
    }

    {
        const std::vector<std::string_view> args {"--all-flows", "--out", "x.pcap"};
        const auto parse_result = cli::parse_export_flows_command_arguments(args);
        PFL_EXPECT(!parse_result.ok);
        PFL_EXPECT(contains_text(parse_result.error_text, "requires an input path"));
    }

    {
        const auto help_result = invoke_cli({"export-flows", "--help", "--out", "should_not_exist.pcap"});
        PFL_EXPECT(help_result.handled);
        PFL_EXPECT(help_result.exit_code == 0);
        PFL_EXPECT(help_result.stderr_text.empty());
        PFL_EXPECT(contains_text(help_result.stdout_text, "PcapFlowLab CLI - export-flows"));
        PFL_EXPECT(contains_text(help_result.stdout_text, "--unrecognized-packets"));
        PFL_EXPECT(contains_text(help_result.stdout_text, "--packet-limit <N>"));
        PFL_EXPECT(contains_text(help_result.stdout_text, "--flow-number <N>"));
        PFL_EXPECT(contains_text(help_result.stdout_text, "--out-dir <path>"));
        PFL_EXPECT(!contains_text(help_result.stdout_text, "\\--input"));
        PFL_EXPECT(!contains_text(help_result.stdout_text, "\\<input>"));
        PFL_EXPECT(has_no_ansi_escape_sequences(help_result.stdout_text));
    }

    {
        const auto global_help = invoke_cli({"--help"});
        PFL_EXPECT(global_help.handled);
        PFL_EXPECT(global_help.exit_code == 0);
        PFL_EXPECT(contains_text(global_help.stdout_text, "export-flows"));
    }

    {
        const auto parse_result = parse_export_args({"capture.pcap", "--out", "x.pcap"});
        PFL_EXPECT(!parse_result.ok);
        PFL_EXPECT(contains_text(parse_result.error_text, "requires at least one selector"));
    }

    {
        const auto parse_result = parse_export_args({"capture.pcap", "--all-flows"});
        PFL_EXPECT(!parse_result.ok);
        PFL_EXPECT(contains_text(parse_result.error_text, "Exactly one of --out or --out-dir is required"));
    }

    {
        const auto parse_result = parse_export_args({"capture.pcap", "--all-flows", "--flow-number", "1", "--out", "x.pcap"});
        PFL_EXPECT(!parse_result.ok);
        PFL_EXPECT(contains_text(parse_result.error_text, "mutually exclusive"));
    }

    {
        const auto parse_result = parse_export_args({"capture.pcap", "--all-flows", "--filter", "TLS", "--out", "x.pcap"});
        PFL_EXPECT(!parse_result.ok);
        PFL_EXPECT(contains_text(parse_result.error_text, "mutually exclusive"));
    }

    {
        const auto parse_result = parse_export_args({"capture.pcap", "--flow-number", "2", "--filter", "TLS", "--out", "x.pcap"});
        PFL_REQUIRE(parse_result.ok);
        PFL_REQUIRE(parse_result.options.has_value());
        PFL_EXPECT(parse_result.options->text_filter == "TLS");
        PFL_REQUIRE(parse_result.options->selected_flow_indices.has_value());
        const std::vector<std::size_t> expected {1U};
        PFL_EXPECT(*parse_result.options->selected_flow_indices == expected);
    }

    {
        const auto parse_result = parse_export_args({"capture.pcap", "--all-flows", "--limit", "10", "--out", "x.pcap"});
        PFL_REQUIRE(parse_result.ok);
        PFL_REQUIRE(parse_result.options.has_value());
        PFL_EXPECT(parse_result.options->limit == std::optional<std::size_t> {10U});
    }

    for (const auto invalid_limit : {"0", "-1"}) {
        const auto parse_result = parse_export_args({"capture.pcap", "--all-flows", "--limit", invalid_limit, "--out", "x.pcap"});
        PFL_EXPECT(!parse_result.ok);
        PFL_EXPECT(contains_text(parse_result.error_text, "Invalid --limit"));
    }

    for (const auto unsupported : {"--sort", "--format", "--columns"}) {
        const auto parse_result = parse_export_args({"capture.pcap", "--all-flows", unsupported, "value", "--out", "x.pcap"});
        PFL_EXPECT(!parse_result.ok);
        PFL_EXPECT(contains_text(parse_result.error_text, "not implemented for export-flows"));
    }
}

void expect_packet_retention_and_output_parser_behavior() {
    {
        const auto parse_result = parse_export_args({"capture.pcap", "--all-flows", "--all-packets", "--out", "x.pcap"});
        PFL_REQUIRE(parse_result.ok);
        PFL_REQUIRE(parse_result.options.has_value());
        PFL_EXPECT(parse_result.options->base_mode == SmartFlowExportBaseMode::all_packets);
    }

    {
        const auto parse_result = parse_export_args({"capture.pcap", "--all-flows", "--first-packets", "3", "--include-last-packet", "--out", "x.pcap"});
        PFL_REQUIRE(parse_result.ok);
        PFL_REQUIRE(parse_result.options.has_value());
        PFL_EXPECT(parse_result.options->base_mode == SmartFlowExportBaseMode::first_n_packets);
        PFL_EXPECT(parse_result.options->first_n_packets == 3U);
        PFL_EXPECT(parse_result.options->include_last_packet);
    }

    {
        const auto parse_result = parse_export_args({"capture.pcap", "--all-flows", "--first-original-bytes", "150", "--every-kth-packet", "2", "--out", "x.pcap"});
        PFL_REQUIRE(parse_result.ok);
        PFL_REQUIRE(parse_result.options.has_value());
        PFL_EXPECT(parse_result.options->base_mode == SmartFlowExportBaseMode::first_m_original_bytes);
        PFL_EXPECT(parse_result.options->first_m_original_bytes == 150U);
        PFL_EXPECT(parse_result.options->include_every_kth_packet_after_base);
        PFL_EXPECT(parse_result.options->every_kth_packet == 2U);
    }

    for (const auto invalid_first_packets : {"0", "-1"}) {
        const auto parse_result = parse_export_args({"capture.pcap", "--all-flows", "--first-packets", invalid_first_packets, "--out", "x.pcap"});
        PFL_EXPECT(!parse_result.ok);
        PFL_EXPECT(contains_text(parse_result.error_text, "Invalid --first-packets"));
    }

    for (const auto invalid_first_bytes : {"0", "-1"}) {
        const auto parse_result = parse_export_args({"capture.pcap", "--all-flows", "--first-original-bytes", invalid_first_bytes, "--out", "x.pcap"});
        PFL_EXPECT(!parse_result.ok);
        PFL_EXPECT(contains_text(parse_result.error_text, "Invalid --first-original-bytes"));
    }

    {
        const auto parse_result = parse_export_args({"capture.pcap", "--all-flows", "--first-packets", "1", "--first-original-bytes", "10", "--out", "x.pcap"});
        PFL_EXPECT(!parse_result.ok);
        PFL_EXPECT(contains_text(parse_result.error_text, "mutually exclusive"));
    }

    for (const auto invalid_k : {"0", "-1"}) {
        const auto parse_result = parse_export_args({"capture.pcap", "--all-flows", "--first-packets", "1", "--every-kth-packet", invalid_k, "--out", "x.pcap"});
        PFL_EXPECT(!parse_result.ok);
        PFL_EXPECT(contains_text(parse_result.error_text, "Invalid --every-kth-packet"));
    }

    for (const auto& args : {
        std::vector<std::string_view> {"capture.pcap", "--all-flows", "--all-packets", "--include-last-packet", "--out", "x.pcap"},
        std::vector<std::string_view> {"capture.pcap", "--all-flows", "--all-packets", "--every-kth-packet", "10", "--out", "x.pcap"},
        std::vector<std::string_view> {"capture.pcap", "--all-flows", "--include-last-packet", "--out", "x.pcap"},
        std::vector<std::string_view> {"capture.pcap", "--all-flows", "--every-kth-packet", "10", "--out", "x.pcap"},
    }) {
        const auto parse_result = cli::parse_export_flows_command_arguments(args);
        PFL_EXPECT(!parse_result.ok);
        PFL_EXPECT(contains_text(parse_result.error_text, "require --first-packets or --first-original-bytes"));
    }

    {
        const auto parse_result = parse_export_args({"capture.pcap", "--all-flows", "--out-dir", "exports", "--buffer-memory-mib", "16"});
        PFL_REQUIRE(parse_result.ok);
        PFL_REQUIRE(parse_result.options.has_value());
        PFL_REQUIRE(parse_result.options->out_dir_path.has_value());
        PFL_EXPECT(parse_result.options->buffer_memory_bytes == 16U * 1024U * 1024U);
    }

    {
        const auto parse_result = parse_export_args({"capture.pcap", "--all-flows", "--out", "x.pcap", "--buffer-memory-mib", "16"});
        PFL_EXPECT(!parse_result.ok);
        PFL_EXPECT(contains_text(parse_result.error_text, "valid only with --out-dir"));
    }

    {
        const auto huge_mib = std::to_string(std::numeric_limits<std::size_t>::max());
        const auto parse_result = parse_export_args({"capture.pcap", "--all-flows", "--out-dir", "exports", "--buffer-memory-mib", huge_mib});
        PFL_EXPECT(!parse_result.ok);
        PFL_EXPECT(contains_text(parse_result.error_text, "too large for the current platform"));
    }

    {
        const auto parse_result = parse_export_args({"capture.pcap", "--all-flows", "--out", "x.pcap", "--out-dir", "exports"});
        PFL_EXPECT(!parse_result.ok);
        PFL_EXPECT(contains_text(parse_result.error_text, "Exactly one of --out or --out-dir is required"));
    }

    {
        const auto parse_result = parse_export_args({"capture.pcap", "--unrecognized-packets", "--out", "x.pcap"});
        PFL_REQUIRE(parse_result.ok);
        PFL_REQUIRE(parse_result.options.has_value());
        PFL_EXPECT(parse_result.options->unrecognized_packets);
        PFL_EXPECT(!parse_result.options->packet_limit.has_value());
    }

    {
        const auto parse_result = parse_export_args({
            "capture.pcap", "--unrecognized-packets", "--packet-limit", "3", "--out", "x.pcap"
        });
        PFL_REQUIRE(parse_result.ok);
        PFL_REQUIRE(parse_result.options.has_value());
        PFL_EXPECT(parse_result.options->packet_limit == std::optional<std::size_t> {3U});
    }

    {
        const auto parse_result = parse_export_args({"capture.pcap", "--unrecognized-packets"});
        PFL_EXPECT(!parse_result.ok);
        PFL_EXPECT(contains_text(parse_result.error_text, "Exactly one of --out or --out-dir is required"));
    }

    for (const auto& args : {
        std::vector<std::string_view> {"capture.pcap", "--unrecognized-packets", "--flow-number", "1", "--out", "x.pcap"},
        std::vector<std::string_view> {"capture.pcap", "--unrecognized-packets", "--flow-numbers", "1-2", "--out", "x.pcap"},
        std::vector<std::string_view> {"capture.pcap", "--unrecognized-packets", "--filter", "TLS", "--out", "x.pcap"},
        std::vector<std::string_view> {"capture.pcap", "--unrecognized-packets", "--all-flows", "--out", "x.pcap"},
        std::vector<std::string_view> {"capture.pcap", "--unrecognized-packets", "--limit", "1", "--out", "x.pcap"},
        std::vector<std::string_view> {"capture.pcap", "--unrecognized-packets", "--out-dir", "exports"},
        std::vector<std::string_view> {"capture.pcap", "--unrecognized-packets", "--out", "x.pcap", "--buffer-memory-mib", "16"},
        std::vector<std::string_view> {"capture.pcap", "--unrecognized-packets", "--all-packets", "--out", "x.pcap"},
        std::vector<std::string_view> {"capture.pcap", "--unrecognized-packets", "--first-packets", "1", "--out", "x.pcap"},
        std::vector<std::string_view> {"capture.pcap", "--unrecognized-packets", "--first-original-bytes", "10", "--out", "x.pcap"},
        std::vector<std::string_view> {"capture.pcap", "--unrecognized-packets", "--include-last-packet", "--out", "x.pcap"},
        std::vector<std::string_view> {"capture.pcap", "--unrecognized-packets", "--every-kth-packet", "2", "--out", "x.pcap"},
    }) {
        const auto parse_result = cli::parse_export_flows_command_arguments(args);
        PFL_EXPECT(!parse_result.ok);
        PFL_EXPECT(contains_text(parse_result.error_text, "--unrecognized-packets"));
    }

    {
        const auto parse_result = parse_export_args({"capture.pcap", "--packet-limit", "1", "--out", "x.pcap"});
        PFL_EXPECT(!parse_result.ok);
        PFL_EXPECT(contains_text(parse_result.error_text, "--packet-limit is valid only with --unrecognized-packets"));
    }

    for (const auto invalid_limit : {"0", "-1"}) {
        const auto parse_result = parse_export_args({"capture.pcap", "--unrecognized-packets", "--packet-limit", invalid_limit, "--out", "x.pcap"});
        PFL_EXPECT(!parse_result.ok);
        PFL_EXPECT(contains_text(parse_result.error_text, "Invalid --packet-limit"));
    }

    {
        const auto huge_limit = std::to_string(std::numeric_limits<std::size_t>::max()) + '0';
        const auto parse_result = parse_export_args({"capture.pcap", "--unrecognized-packets", "--packet-limit", huge_limit, "--out", "x.pcap"});
        PFL_EXPECT(!parse_result.ok);
        PFL_EXPECT(contains_text(parse_result.error_text, "Invalid --packet-limit"));
    }

    {
        const auto parse_result = parse_export_args({
            "capture.pcap", "--unrecognized-packets", "--packet-limit", "1", "--packet-limit", "2", "--out", "x.pcap"
        });
        PFL_EXPECT(!parse_result.ok);
        PFL_EXPECT(contains_text(parse_result.error_text, "Duplicate --packet-limit"));
    }
}

void expect_runtime_direct_and_smart_export_behavior() {
    const auto capture_path = build_export_cli_capture_path();

    {
        const auto output_path = std::filesystem::temp_directory_path() / "pfl_cli_export_direct_output.pcap";
        std::filesystem::remove(output_path);

        const auto result = invoke_cli({
            "export-flows",
            capture_path.string(),
            "--flow-numbers",
            "1-2",
            "--out",
            output_path.string(),
            "--progress",
            "off",
        });
        PFL_EXPECT(result.handled);
        PFL_EXPECT(result.exit_code == 0);
        PFL_EXPECT(result.stdout_text.empty());
        PFL_EXPECT(contains_text(result.stderr_text, "Exported 2 flows to:"));
        PFL_EXPECT(!contains_text(result.stderr_text, "Opening "));
        const auto exported_packets = read_all_packets(output_path);
        PFL_REQUIRE(exported_packets.size() == 8U);
        PFL_EXPECT(exported_packets[0].ts_usec == 100U);
        PFL_EXPECT(exported_packets[1].ts_usec == 200U);
        PFL_EXPECT(exported_packets[7].ts_usec == 800U);
    }

    {
        const auto output_path = std::filesystem::temp_directory_path() / "pfl_cli_export_direct_single_flow_output.pcap";
        std::filesystem::remove(output_path);

        const auto result = invoke_cli({
            "export-flows",
            capture_path.string(),
            "--flow-number",
            "1",
            "--out",
            output_path.string(),
            "--progress",
            "off",
        });
        PFL_EXPECT(result.exit_code == 0);
        const auto exported_packets = read_all_packets(output_path);
        PFL_REQUIRE(exported_packets.size() == 4U);
        PFL_EXPECT(exported_packets[0].ts_usec == 100U);
        PFL_EXPECT(exported_packets[3].ts_usec == 700U);
    }

    {
        const auto output_path = std::filesystem::temp_directory_path() / "pfl_cli_export_filtered_output.pcap";
        std::filesystem::remove(output_path);

        const auto result = invoke_cli({
            "export-flows",
            capture_path.string(),
            "--filter",
            "10.1.0.1",
            "--limit",
            "1",
            "--out",
            output_path.string(),
            "--progress",
            "off",
        });
        PFL_EXPECT(result.exit_code == 0);
        const auto exported_packets = read_all_packets(output_path);
        PFL_REQUIRE(exported_packets.size() == 4U);
        PFL_EXPECT(exported_packets[0].ts_usec == 100U);
        PFL_EXPECT(exported_packets[3].ts_usec == 700U);
    }

    {
        const auto output_path = std::filesystem::temp_directory_path() / "pfl_cli_export_first_packets_output.pcap";
        std::filesystem::remove(output_path);

        const auto result = invoke_cli({
            "export-flows",
            capture_path.string(),
            "--flow-number",
            "1",
            "--first-packets",
            "1",
            "--include-last-packet",
            "--out",
            output_path.string(),
            "--progress",
            "off",
        });
        PFL_EXPECT(result.exit_code == 0);
        PFL_EXPECT(!contains_text(result.stderr_text, "Smart export:"));
        const auto exported_packets = read_all_packets(output_path);
        PFL_REQUIRE(exported_packets.size() == 2U);
        PFL_EXPECT(exported_packets[0].ts_usec == 100U);
        PFL_EXPECT(exported_packets[1].ts_usec == 700U);
    }

    {
        const auto output_path = std::filesystem::temp_directory_path() / "pfl_cli_export_original_bytes_output.pcap";
        std::filesystem::remove(output_path);
        const auto original_bytes_capture_path = build_original_bytes_capture_path();

        const auto result = invoke_cli({
            "export-flows",
            original_bytes_capture_path.string(),
            "--all-flows",
            "--first-original-bytes",
            "150",
            "--every-kth-packet",
            "2",
            "--out",
            output_path.string(),
            "--progress",
            "off",
        });
        PFL_EXPECT(result.exit_code == 0);
        const auto exported_packets = read_all_packets(output_path);
        PFL_REQUIRE(exported_packets.size() == 3U);
        PFL_EXPECT(exported_packets[0].ts_usec == 100U);
        PFL_EXPECT(exported_packets[1].ts_usec == 200U);
        PFL_EXPECT(exported_packets[2].ts_usec == 400U);
    }
}

void expect_smart_export_progress_rendering_behavior() {
    using namespace std::chrono_literals;

    {
        const auto lines = collect_emitted_progress_lines<SmartPerFlowExportProgress>(
            {
                {0ms, SmartPerFlowExportProgress {
                    .phase = SmartPerFlowExportPhase::preparing,
                    .packets_processed = 0U,
                    .total_packets_to_scan = 11U,
                    .exported_packets_written = 0U,
                }},
            },
            [](const SmartPerFlowExportProgress& progress, auto& state, const auto now) {
                return cli::render_throttled_smart_per_flow_progress_line(progress, state, now);
            }
        );
        PFL_REQUIRE(lines.size() == 1U);
        PFL_EXPECT(lines[0] == "Preparing per-flow export: prepared 0 / 11 flows.");
    }

    {
        const auto lines = collect_emitted_progress_lines<SmartPerFlowExportProgress>(
            {
                {0ms, SmartPerFlowExportProgress {.phase = SmartPerFlowExportPhase::preparing, .packets_processed = 0U, .total_packets_to_scan = 11U, .exported_packets_written = 0U}},
                {50ms, SmartPerFlowExportProgress {.phase = SmartPerFlowExportPhase::preparing, .packets_processed = 1U, .total_packets_to_scan = 11U, .exported_packets_written = 0U}},
                {100ms, SmartPerFlowExportProgress {.phase = SmartPerFlowExportPhase::preparing, .packets_processed = 2U, .total_packets_to_scan = 11U, .exported_packets_written = 0U}},
                {700ms, SmartPerFlowExportProgress {.phase = SmartPerFlowExportPhase::preparing, .packets_processed = 3U, .total_packets_to_scan = 11U, .exported_packets_written = 0U}},
            },
            [](const SmartPerFlowExportProgress& progress, auto& state, const auto now) {
                return cli::render_throttled_smart_per_flow_progress_line(progress, state, now);
            }
        );
        PFL_REQUIRE(lines.size() == 1U);
        PFL_EXPECT(lines[0] == "Preparing per-flow export: prepared 0 / 11 flows.");
    }

    {
        const auto lines = collect_emitted_progress_lines<SmartPerFlowExportProgress>(
            {
                {0ms, SmartPerFlowExportProgress {.phase = SmartPerFlowExportPhase::preparing, .packets_processed = 0U, .total_packets_to_scan = 11U, .exported_packets_written = 0U}},
                {800ms, SmartPerFlowExportProgress {.phase = SmartPerFlowExportPhase::preparing, .packets_processed = 4U, .total_packets_to_scan = 11U, .exported_packets_written = 0U}},
            },
            [](const SmartPerFlowExportProgress& progress, auto& state, const auto now) {
                return cli::render_throttled_smart_per_flow_progress_line(progress, state, now);
            }
        );
        PFL_REQUIRE(lines.size() == 2U);
        PFL_EXPECT(lines[1] == "Preparing per-flow export: prepared 4 / 11 flows.");
    }

    {
        const auto lines = collect_emitted_progress_lines<SmartPerFlowExportProgress>(
            {
                {0ms, SmartPerFlowExportProgress {.phase = SmartPerFlowExportPhase::preparing, .packets_processed = 4U, .total_packets_to_scan = 11U, .exported_packets_written = 0U}},
                {800ms, SmartPerFlowExportProgress {.phase = SmartPerFlowExportPhase::preparing, .packets_processed = 4U, .total_packets_to_scan = 11U, .exported_packets_written = 0U}},
            },
            [](const SmartPerFlowExportProgress& progress, auto& state, const auto now) {
                return cli::render_throttled_smart_per_flow_progress_line(progress, state, now);
            }
        );
        PFL_REQUIRE(lines.size() == 1U);
    }

    {
        const auto lines = collect_emitted_progress_lines<SmartPerFlowExportProgress>(
            {
                {0ms, SmartPerFlowExportProgress {.phase = SmartPerFlowExportPhase::preparing, .packets_processed = 11U, .total_packets_to_scan = 11U, .exported_packets_written = 0U}},
                {10ms, SmartPerFlowExportProgress {.phase = SmartPerFlowExportPhase::writing, .packets_processed = 0U, .total_packets_to_scan = 200U, .exported_packets_written = 0U}},
            },
            [](const SmartPerFlowExportProgress& progress, auto& state, const auto now) {
                return cli::render_throttled_smart_per_flow_progress_line(progress, state, now);
            }
        );
        PFL_REQUIRE(lines.size() == 2U);
        PFL_EXPECT(lines[0] == "Preparing per-flow export: prepared 11 / 11 flows.");
        PFL_EXPECT(lines[1] == "Writing per-flow export: scanned 0 / 200 packets, wrote 0.");
    }

    {
        const auto lines = collect_emitted_progress_lines<SmartPerFlowExportProgress>(
            {
                {0ms, SmartPerFlowExportProgress {.phase = SmartPerFlowExportPhase::writing, .packets_processed = 10U, .total_packets_to_scan = 200U, .exported_packets_written = 2U}},
                {10ms, SmartPerFlowExportProgress {.phase = SmartPerFlowExportPhase::writing, .packets_processed = 200U, .total_packets_to_scan = 200U, .exported_packets_written = 8U}},
            },
            [](const SmartPerFlowExportProgress& progress, auto& state, const auto now) {
                return cli::render_throttled_smart_per_flow_progress_line(progress, state, now);
            }
        );
        PFL_REQUIRE(lines.size() == 2U);
        PFL_EXPECT(lines[1] == "Writing per-flow export: scanned 200 / 200 packets, wrote 8.");
    }

    {
        const auto lines = collect_emitted_progress_lines<SmartPerFlowExportProgress>(
            {
                {0ms, SmartPerFlowExportProgress {.phase = SmartPerFlowExportPhase::writing, .packets_processed = 200U, .total_packets_to_scan = 200U, .exported_packets_written = 8U}},
                {10ms, SmartPerFlowExportProgress {.phase = SmartPerFlowExportPhase::writing, .packets_processed = 200U, .total_packets_to_scan = 200U, .exported_packets_written = 8U}},
            },
            [](const SmartPerFlowExportProgress& progress, auto& state, const auto now) {
                return cli::render_throttled_smart_per_flow_progress_line(progress, state, now);
            }
        );
        PFL_REQUIRE(lines.size() == 1U);
    }

    {
        const auto lines = collect_emitted_progress_lines<SmartSingleFileExportProgress>(
            {
                {0ms, SmartSingleFileExportProgress {.packets_processed = 0U, .total_packets_to_scan = 184532U, .exported_packets_written = 0U, .total_selected_packets = 12418U}},
                {100ms, SmartSingleFileExportProgress {.packets_processed = 1000U, .total_packets_to_scan = 184532U, .exported_packets_written = 100U, .total_selected_packets = 12418U}},
                {850ms, SmartSingleFileExportProgress {.packets_processed = 2000U, .total_packets_to_scan = 184532U, .exported_packets_written = 200U, .total_selected_packets = 12418U}},
                {900ms, SmartSingleFileExportProgress {.packets_processed = 184532U, .total_packets_to_scan = 184532U, .exported_packets_written = 12418U, .total_selected_packets = 12418U}},
            },
            [](const SmartSingleFileExportProgress& progress, auto& state, const auto now) {
                return cli::render_throttled_smart_single_file_progress_line(progress, state, now);
            }
        );
        PFL_REQUIRE(lines.size() == 3U);
        PFL_EXPECT(lines[0] == "Smart export: scanned 0 / 184 532 packets, wrote 0 of 12 418.");
        PFL_EXPECT(lines[1] == "Smart export: scanned 2 000 / 184 532 packets, wrote 200 of 12 418.");
        PFL_EXPECT(lines[2] == "Smart export: scanned 184 532 / 184 532 packets, wrote 12 418 of 12 418.");
    }
}

void expect_runtime_folder_and_preflight_behavior() {
    const auto capture_path = build_export_cli_capture_path();

    {
        const auto output_directory = std::filesystem::temp_directory_path() / "pfl_cli_export_folder_output";
        std::filesystem::remove_all(output_directory);

        const auto result = invoke_cli({
            "export-flows",
            capture_path.string(),
            "--all-flows",
            "--out-dir",
            output_directory.string(),
            "--buffer-memory-mib",
            "1",
            "--progress",
            "off",
        });
        PFL_EXPECT(result.exit_code == 0);
        PFL_EXPECT(!contains_text(result.stderr_text, "Preparing per-flow export:"));
        PFL_EXPECT(!contains_text(result.stderr_text, "Writing per-flow export:"));
        PFL_EXPECT(std::filesystem::exists(output_directory / "flows_manifest.csv"));
        const auto manifest_lines = read_text_file_lines(output_directory / "flows_manifest.csv");
        PFL_REQUIRE(manifest_lines.size() == 3U);
        const auto header = split_csv_line(manifest_lines[0]);
        const auto first_data = split_csv_line(manifest_lines[1]);
        const auto second_data = split_csv_line(manifest_lines[2]);
        PFL_REQUIRE(header.size() >= 20U);
        PFL_REQUIRE(first_data.size() == header.size());
        PFL_REQUIRE(second_data.size() == header.size());
        PFL_EXPECT(first_data[0] == "1");
        PFL_EXPECT(second_data[0] == "2");
        PFL_EXPECT(first_data[16] == "4");
        PFL_EXPECT(second_data[16] == "4");
    }

    {
        const auto existing_output = write_temp_text_file("pfl_cli_export_existing_output.pcap", "old");
        const auto rejected = invoke_cli({
            "export-flows",
            capture_path.string(),
            "--all-flows",
            "--out",
            existing_output.string(),
            "--progress",
            "off",
        });
        PFL_EXPECT(rejected.exit_code == 1);
        PFL_EXPECT(contains_text(rejected.stderr_text, "--out already exists"));

        const auto forced = invoke_cli({
            "export-flows",
            capture_path.string(),
            "--all-flows",
            "--out",
            existing_output.string(),
            "--force",
            "--progress",
            "off",
        });
        PFL_EXPECT(forced.exit_code == 0);
    }

    {
        const auto result = invoke_cli({
            "export-flows",
            capture_path.string(),
            "--all-flows",
            "--out",
            capture_path.string(),
            "--progress",
            "off",
        });
        PFL_EXPECT(result.exit_code == 1);
        PFL_EXPECT(contains_text(result.stderr_text, "cannot overwrite the input path"));
    }

    {
        const auto missing_parent = std::filesystem::temp_directory_path() / "pfl_cli_export_missing_parent" / "selected.pcap";
        const auto result = invoke_cli({
            "export-flows",
            capture_path.string(),
            "--all-flows",
            "--out",
            missing_parent.string(),
            "--progress",
            "off",
        });
        PFL_EXPECT(result.exit_code == 1);
        PFL_EXPECT(contains_text(result.stderr_text, "parent directory does not exist"));
    }

    {
        const auto directory_target = std::filesystem::temp_directory_path() / "pfl_cli_export_out_directory_target";
        std::filesystem::remove_all(directory_target);
        std::filesystem::create_directories(directory_target);
        const auto result = invoke_cli({
            "export-flows",
            capture_path.string(),
            "--all-flows",
            "--out",
            directory_target.string(),
            "--progress",
            "off",
        });
        PFL_EXPECT(result.exit_code == 1);
        PFL_EXPECT(contains_text(result.stderr_text, "must be a regular file path"));
    }

    {
        const auto output_directory = std::filesystem::temp_directory_path() / "pfl_cli_export_existing_empty_dir";
        std::filesystem::remove_all(output_directory);
        std::filesystem::create_directories(output_directory);
        const auto result = invoke_cli({
            "export-flows",
            capture_path.string(),
            "--all-flows",
            "--out-dir",
            output_directory.string(),
            "--progress",
            "off",
        });
        PFL_EXPECT(result.exit_code == 0);
        PFL_EXPECT(std::filesystem::exists(output_directory / "flows_manifest.csv"));
    }

    {
        const auto output_directory = std::filesystem::temp_directory_path() / "pfl_cli_export_existing_nonempty_dir";
        std::filesystem::remove_all(output_directory);
        std::filesystem::create_directories(output_directory);
        {
            std::ofstream keep_stream(output_directory / "keep.txt", std::ios::binary | std::ios::trunc);
            keep_stream << "keep";
        }

        const auto rejected = invoke_cli({
            "export-flows",
            capture_path.string(),
            "--all-flows",
            "--out-dir",
            output_directory.string(),
            "--progress",
            "off",
        });
        PFL_EXPECT(rejected.exit_code == 1);
        PFL_EXPECT(contains_text(rejected.stderr_text, "is not empty"));

        const auto forced = invoke_cli({
            "export-flows",
            capture_path.string(),
            "--all-flows",
            "--out-dir",
            output_directory.string(),
            "--force",
            "--progress",
            "off",
        });
        PFL_EXPECT(forced.exit_code == 0);
        PFL_EXPECT(std::filesystem::exists(output_directory / "keep.txt"));
        PFL_EXPECT(std::filesystem::exists(output_directory / "flows_manifest.csv"));
    }

    {
        const auto regular_file = write_temp_text_file("pfl_cli_export_out_dir_regular_file.txt", "old");
        const auto result = invoke_cli({
            "export-flows",
            capture_path.string(),
            "--all-flows",
            "--out-dir",
            regular_file.string(),
            "--progress",
            "off",
        });
        PFL_EXPECT(result.exit_code == 1);
        PFL_EXPECT(contains_text(result.stderr_text, "must be a directory path"));
    }
}

void expect_empty_selection_and_source_behavior() {
    const auto capture_path = build_export_cli_capture_path();

    {
        const auto output_path = std::filesystem::temp_directory_path() / "pfl_cli_export_no_match_output.pcap";
        std::filesystem::remove(output_path);
        const auto output_directory = std::filesystem::temp_directory_path() / "pfl_cli_export_no_match_dir";
        std::filesystem::remove_all(output_directory);

        const auto result = invoke_cli({
            "export-flows",
            capture_path.string(),
            "--filter",
            "no-such-flow",
            "--out",
            output_path.string(),
            "--progress",
            "off",
        });
        PFL_EXPECT(result.exit_code == 1);
        PFL_EXPECT(contains_text(result.stderr_text, "No flows matched the export selection"));
        PFL_EXPECT(!std::filesystem::exists(output_path));
        PFL_EXPECT(!std::filesystem::exists(output_directory));
    }

    {
        const auto raw_result = invoke_cli({
            "export-flows",
            capture_path.string(),
            "--all-flows",
            "--source-capture",
            capture_path.string(),
            "--out",
            (std::filesystem::temp_directory_path() / "pfl_cli_export_invalid_raw_source_output.pcap").string(),
            "--progress",
            "off",
        });
        PFL_EXPECT(raw_result.exit_code == 1);
        PFL_EXPECT(contains_text(raw_result.stderr_text, "--source-capture is valid only for index input"));
    }

    {
        const auto settings_path = write_temp_text_file(
            "pfl_cli_export_gtpu_settings.json",
            settings_json(true)
        );
        const auto output_path = std::filesystem::temp_directory_path() / "pfl_cli_export_settings_output.pcap";
        std::filesystem::remove(output_path);
        const auto result = invoke_cli({
            "export-flows",
            fixture_path("parsing/gtpu/21_gtpu_same_inner_tuple_different_teid.pcap").string(),
            "--all-flows",
            "--settings",
            settings_path.string(),
            "--out",
            output_path.string(),
            "--progress",
            "off",
        });
        PFL_EXPECT(result.exit_code == 0);
        PFL_EXPECT(std::filesystem::exists(output_path));
    }

    {
        const auto source_path = write_temp_pcap(
            "pfl_cli_export_index_source.pcap",
            make_classic_pcap({
                {100U, make_ethernet_ipv4_udp_packet(ipv4(10, 60, 0, 1), ipv4(10, 60, 0, 2), 46001, 53)},
                {200U, make_ethernet_ipv4_udp_packet(ipv4(10, 60, 0, 2), ipv4(10, 60, 0, 1), 53, 46001)},
            })
        );
        const auto index_path = std::filesystem::temp_directory_path() / "pfl_cli_export_index_source.idx";
        const auto output_path = std::filesystem::temp_directory_path() / "pfl_cli_export_index_auto_output.pcap";
        std::filesystem::remove(index_path);
        std::filesystem::remove(output_path);

        FrontendSessionAdapter adapter {};
        PFL_REQUIRE(adapter.open_capture(source_path).opened);
        PFL_REQUIRE(adapter.save_index(index_path).saved);

        const auto auto_result = invoke_cli({
            "export-flows",
            index_path.string(),
            "--all-flows",
            "--out",
            output_path.string(),
            "--progress",
            "off",
        });
        PFL_EXPECT(auto_result.exit_code == 0);
        PFL_EXPECT(std::filesystem::exists(output_path));

        const auto explicit_source_reject = invoke_cli({
            "export-flows",
            index_path.string(),
            "--all-flows",
            "--source-capture",
            source_path.string(),
            "--out",
            source_path.string(),
            "--force",
            "--progress",
            "off",
        });
        PFL_EXPECT(explicit_source_reject.exit_code == 1);
        PFL_EXPECT(contains_text(explicit_source_reject.stderr_text, "must not overwrite the source capture"));

        const auto settings_path = write_temp_text_file(
            "pfl_cli_export_index_settings.json",
            settings_json(false)
        );
        const auto settings_reject = invoke_cli({
            "export-flows",
            index_path.string(),
            "--all-flows",
            "--settings",
            settings_path.string(),
            "--out",
            output_path.string(),
            "--progress",
            "off",
        });
        PFL_EXPECT(settings_reject.exit_code == 1);
        PFL_EXPECT(contains_text(settings_reject.stderr_text, "--settings is valid only for raw capture input"));

        const auto moved_source_path = std::filesystem::temp_directory_path() / "pfl_cli_export_index_source_moved.pcap";
        std::filesystem::remove(moved_source_path);
        std::filesystem::rename(source_path, moved_source_path);
        std::filesystem::remove(output_path);

        const auto missing_source_result = invoke_cli({
            "export-flows",
            index_path.string(),
            "--all-flows",
            "--out",
            output_path.string(),
            "--progress",
            "off",
        });
        PFL_EXPECT(missing_source_result.exit_code == 1);
        PFL_EXPECT(contains_text(missing_source_result.stderr_text, "requires a valid source capture"));

        auto mismatched_bytes = make_classic_pcap({
            {100U, make_ethernet_ipv4_udp_packet(ipv4(10, 60, 0, 1), ipv4(10, 60, 0, 2), 46001, 53)},
            {200U, make_ethernet_ipv4_udp_packet(ipv4(10, 60, 0, 2), ipv4(10, 60, 0, 1), 53, 46001)},
        });
        PFL_REQUIRE(!mismatched_bytes.empty());
        mismatched_bytes.back() ^= 0xFFU;
        const auto mismatched_source_path = std::filesystem::temp_directory_path() / "pfl_cli_export_index_source_mismatch.pcap";
        {
            std::ofstream stream(mismatched_source_path, std::ios::binary | std::ios::trunc);
            stream.write(
                reinterpret_cast<const char*>(mismatched_bytes.data()),
                static_cast<std::streamsize>(mismatched_bytes.size())
            );
        }
        std::filesystem::last_write_time(
            mismatched_source_path,
            std::filesystem::last_write_time(moved_source_path)
        );

        const auto mismatched_result = invoke_cli({
            "export-flows",
            index_path.string(),
            "--all-flows",
            "--source-capture",
            mismatched_source_path.string(),
            "--out",
            output_path.string(),
            "--progress",
            "off",
        });
        PFL_EXPECT(mismatched_result.exit_code == 1);
        PFL_EXPECT(contains_text(mismatched_result.stderr_text, "Selected file does not match the expected source capture"));

        std::filesystem::remove(output_path);
        const auto valid_result = invoke_cli({
            "export-flows",
            index_path.string(),
            "--all-flows",
            "--source-capture",
            moved_source_path.string(),
            "--out",
            output_path.string(),
            "--progress",
            "off",
        });
        PFL_EXPECT(valid_result.exit_code == 0);
        PFL_EXPECT(std::filesystem::exists(output_path));
    }
}

void expect_unrecognized_export_behavior() {
    const auto capture_path = build_unrecognized_export_cli_capture_path();

    {
        const auto output_path = std::filesystem::temp_directory_path() / "pfl_cli_export_unrecognized_output.pcap";
        std::filesystem::remove(output_path);

        const auto result = invoke_cli({
            "export-flows",
            capture_path.string(),
            "--unrecognized-packets",
            "--out",
            output_path.string(),
            "--progress",
            "off",
        });
        PFL_EXPECT(result.exit_code == 0);
        PFL_EXPECT(!contains_text(result.stderr_text, "Smart export:"));
        PFL_EXPECT(contains_text(result.stderr_text, "Exported 2 unrecognized packets to:"));

        const auto exported_packets = read_all_packets(output_path);
        PFL_REQUIRE(exported_packets.size() == 2U);
        PFL_EXPECT(exported_packets[0].ts_usec == 200U);
        PFL_EXPECT(exported_packets[1].ts_usec == 400U);
    }

    {
        const auto output_path = std::filesystem::temp_directory_path() / "pfl_cli_export_unrecognized_first_output.pcap";
        std::filesystem::remove(output_path);

        const auto result = invoke_cli({
            "export-flows",
            capture_path.string(),
            "--unrecognized-packets",
            "--packet-limit",
            "1",
            "--out",
            output_path.string(),
            "--progress",
            "off",
        });
        PFL_EXPECT(result.exit_code == 0);
        PFL_EXPECT(contains_text(result.stderr_text, "Exported 1 unrecognized packets to:"));

        const auto exported_packets = read_all_packets(output_path);
        PFL_REQUIRE(exported_packets.size() == 1U);
        PFL_EXPECT(exported_packets[0].ts_usec == 200U);
    }

    {
        const auto output_path = std::filesystem::temp_directory_path() / "pfl_cli_export_unrecognized_all_available_output.pcap";
        std::filesystem::remove(output_path);

        const auto result = invoke_cli({
            "export-flows",
            capture_path.string(),
            "--unrecognized-packets",
            "--packet-limit",
            "100",
            "--out",
            output_path.string(),
            "--progress",
            "off",
        });
        PFL_EXPECT(result.exit_code == 0);
        PFL_EXPECT(contains_text(result.stderr_text, "Exported 2 unrecognized packets to:"));

        const auto exported_packets = read_all_packets(output_path);
        PFL_REQUIRE(exported_packets.size() == 2U);
        PFL_EXPECT(exported_packets[0].ts_usec == 200U);
        PFL_EXPECT(exported_packets[1].ts_usec == 400U);
    }

    {
        const auto output_path = std::filesystem::temp_directory_path() / "pfl_cli_export_unrecognized_empty_output.pcap";
        std::filesystem::remove(output_path);

        const auto result = invoke_cli({
            "export-flows",
            build_export_cli_capture_path().string(),
            "--unrecognized-packets",
            "--out",
            output_path.string(),
            "--progress",
            "off",
        });
        PFL_EXPECT(result.exit_code == 1);
        PFL_EXPECT(contains_text(result.stderr_text, "No unrecognized packets to export"));
        PFL_EXPECT(!std::filesystem::exists(output_path));
    }

    {
        const auto source_path = capture_path;
        const auto index_path = std::filesystem::temp_directory_path() / "pfl_cli_export_unrecognized_source.idx";
        const auto output_path = std::filesystem::temp_directory_path() / "pfl_cli_export_unrecognized_index_output.pcap";
        std::filesystem::remove(index_path);
        std::filesystem::remove(output_path);

        FrontendSessionAdapter adapter {};
        PFL_REQUIRE(adapter.open_capture(source_path).opened);
        PFL_REQUIRE(adapter.save_index(index_path).saved);

        const auto auto_result = invoke_cli({
            "export-flows",
            index_path.string(),
            "--unrecognized-packets",
            "--out",
            output_path.string(),
            "--progress",
            "off",
        });
        PFL_EXPECT(auto_result.exit_code == 0);
        PFL_EXPECT(std::filesystem::exists(output_path));
        PFL_EXPECT(contains_text(auto_result.stderr_text, "Exported 2 unrecognized packets to:"));

        std::filesystem::remove(output_path);
        const auto explicit_result = invoke_cli({
            "export-flows",
            index_path.string(),
            "--unrecognized-packets",
            "--source-capture",
            source_path.string(),
            "--out",
            output_path.string(),
            "--progress",
            "off",
        });
        PFL_EXPECT(explicit_result.exit_code == 0);
        PFL_EXPECT(std::filesystem::exists(output_path));

        const auto moved_source_path = std::filesystem::temp_directory_path() / "pfl_cli_export_unrecognized_source_moved.pcap";
        std::filesystem::remove(moved_source_path);
        std::filesystem::rename(source_path, moved_source_path);
        std::filesystem::remove(output_path);

        const auto missing_source_result = invoke_cli({
            "export-flows",
            index_path.string(),
            "--unrecognized-packets",
            "--out",
            output_path.string(),
            "--progress",
            "off",
        });
        PFL_EXPECT(missing_source_result.exit_code == 1);
        PFL_EXPECT(contains_text(missing_source_result.stderr_text, "requires a valid source capture"));
        PFL_EXPECT(!std::filesystem::exists(output_path));

        const auto explicit_after_move_result = invoke_cli({
            "export-flows",
            index_path.string(),
            "--unrecognized-packets",
            "--source-capture",
            moved_source_path.string(),
            "--out",
            output_path.string(),
            "--progress",
            "off",
        });
        PFL_EXPECT(explicit_after_move_result.exit_code == 0);
        PFL_EXPECT(std::filesystem::exists(output_path));
    }

    {
        const auto output_path = write_temp_text_file("pfl_cli_export_unrecognized_existing_output.pcap", "old");
        const auto rejected = invoke_cli({
            "export-flows",
            capture_path.string(),
            "--unrecognized-packets",
            "--out",
            output_path.string(),
            "--progress",
            "off",
        });
        PFL_EXPECT(rejected.exit_code == 1);
        PFL_EXPECT(contains_text(rejected.stderr_text, "--out already exists"));

        const auto forced = invoke_cli({
            "export-flows",
            capture_path.string(),
            "--unrecognized-packets",
            "--out",
            output_path.string(),
            "--force",
            "--progress",
            "off",
        });
        PFL_EXPECT(forced.exit_code == 0);
    }
}

}  // namespace

void run_cli_export_flows_tests() {
    expect_parser_and_help_behavior();
    expect_packet_retention_and_output_parser_behavior();
    expect_smart_export_progress_rendering_behavior();
    expect_runtime_direct_and_smart_export_behavior();
    expect_runtime_folder_and_preflight_behavior();
    expect_empty_selection_and_source_behavior();
    expect_unrecognized_export_behavior();
}

}  // namespace pfl::tests
