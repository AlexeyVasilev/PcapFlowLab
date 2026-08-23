#include <filesystem>
#include <fstream>
#include <iterator>
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

        if (ch == ',') {
            fields.push_back(current);
            current.clear();
            continue;
        }
        if (ch == '"') {
            in_quotes = true;
            continue;
        }
        current.push_back(ch);
    }

    fields.push_back(current);
    return fields;
}

struct CapturedCliInvocation {
    cli::CliInvocationResult result {};
    std::string progress_text {};
};

CapturedCliInvocation invoke_cli_with_runtime(
    const std::vector<std::string>& args_storage,
    const bool stderr_is_terminal,
    const bool collect_progress = true
) {
    std::vector<std::string_view> args {};
    args.reserve(args_storage.size());
    for (const auto& arg : args_storage) {
        args.push_back(arg);
    }

    CapturedCliInvocation invocation {};
    invocation.result = cli::process_cli_invocation(
        args,
        cli::CliRuntimeEnvironment {
            .stderr_is_terminal = stderr_is_terminal,
            .progress_sink = collect_progress
                ? cli::CliProgressSink {[&invocation](const std::string_view text) {
                    invocation.progress_text.append(text);
                }}
                : cli::CliProgressSink {},
        }
    );
    return invocation;
}

std::string last_progress_line(const std::string_view progress_text) {
    std::string last_line {};
    std::size_t start = 0U;
    while (start < progress_text.size()) {
        const auto end = progress_text.find_first_of("\r\n", start);
        const auto line = progress_text.substr(
            start,
            end == std::string_view::npos ? progress_text.size() - start : end - start
        );
        if (!line.empty()) {
            last_line = std::string {line};
        }
        if (end == std::string_view::npos) {
            break;
        }
        start = end + 1U;
    }
    return last_line;
}

std::size_t count_text_occurrences(const std::string_view haystack, const std::string_view needle) {
    if (needle.empty()) {
        return 0U;
    }

    std::size_t count = 0U;
    std::size_t offset = 0U;
    while ((offset = haystack.find(needle, offset)) != std::string_view::npos) {
        ++count;
        offset += needle.size();
    }
    return count;
}

std::filesystem::path build_cli_progress_capture_path() {
    return write_temp_pcap(
        "pfl_cli_progress_capture.pcap",
        make_classic_pcap({
            {
                100U,
                make_ethernet_ipv4_tcp_packet_with_bytes_payload(
                    ipv4(10, 80, 0, 1),
                    ipv4(10, 80, 0, 2),
                    48000,
                    443,
                    std::vector<std::uint8_t> {'G', 'E', 'T'},
                    0x18
                )
            },
            {
                200U,
                make_ethernet_ipv4_tcp_packet_with_bytes_payload(
                    ipv4(10, 80, 0, 2),
                    ipv4(10, 80, 0, 1),
                    443,
                    48000,
                    std::vector<std::uint8_t> {'O', 'K'},
                    0x18
                )
            },
        })
    );
}

std::filesystem::path build_partial_open_capture_path() {
    auto bytes = make_classic_pcap({
        {
            100U,
            make_ethernet_ipv4_udp_packet(
                ipv4(10, 81, 0, 1),
                ipv4(10, 81, 0, 2),
                48100,
                53
            )
        },
        {
            200U,
            make_ethernet_ipv4_udp_packet(
                ipv4(10, 81, 0, 3),
                ipv4(10, 81, 0, 4),
                48101,
                54
            )
        },
    });
    bytes.resize(bytes.size() - 8U);
    return write_temp_pcap("pfl_cli_progress_partial_open.pcap", bytes);
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

void expect_global_and_summary_help_behavior() {
    std::string global_help_stdout {};

    {
        const std::vector<std::string_view> args {"-h"};
        const auto result = cli::process_cli_invocation(args);
        PFL_EXPECT(result.handled);
        PFL_EXPECT(result.exit_code == 0);
        PFL_EXPECT(result.stderr_text.empty());
        PFL_EXPECT(contains_text(result.stdout_text, "Pcap Flow Lab"));
        PFL_EXPECT(contains_text(result.stdout_text, "0.3.0"));
        PFL_EXPECT(contains_text(result.stdout_text, "pcap-flow-lab <capture-or-index> [summary options]"));
        PFL_EXPECT(contains_text(result.stdout_text, "summary"));
        PFL_EXPECT(contains_text(result.stdout_text, "flows"));
        PFL_EXPECT(contains_text(result.stdout_text, "export-flows"));
        PFL_EXPECT(contains_text(result.stdout_text, "flow-info"));
        PFL_EXPECT(contains_text(result.stdout_text, "packet-info"));
        PFL_EXPECT(!contains_text(result.stdout_text, "Aliases"));
        PFL_EXPECT(!contains_text(result.stdout_text, "export-flow"));
        PFL_EXPECT(!contains_text(result.stdout_text, "flows-info"));
        PFL_EXPECT(!contains_text(result.stdout_text, "packets-info"));
        PFL_EXPECT(!contains_text(result.stdout_text, "inspect-packet"));
        PFL_EXPECT(!contains_text(result.stdout_text, "hex                 Legacy"));
        PFL_EXPECT(!contains_text(result.stdout_text, "save-index"));
        PFL_EXPECT(!contains_text(result.stdout_text, "load-index-summary"));
        PFL_EXPECT(!contains_text(result.stdout_text, "chunked-import"));
        PFL_EXPECT(!contains_text(result.stdout_text, "resume-import"));
        PFL_EXPECT(!contains_text(result.stdout_text, "finalize-import"));
        PFL_EXPECT(contains_text(result.stdout_text, "pcap-flow-lab <command> --help"));
        PFL_EXPECT(!contains_text(result.stdout_text, "\\--input"));
        PFL_EXPECT(!contains_text(result.stdout_text, "\\<input>"));
        PFL_EXPECT(has_no_tabs_or_trailing_spaces(result.stdout_text));
        PFL_EXPECT(has_no_ansi_escape_sequences(result.stdout_text));
        global_help_stdout = result.stdout_text;
    }

    {
        const std::vector<std::string_view> args {"--help"};
        const auto result = cli::process_cli_invocation(args);
        PFL_EXPECT(result.handled);
        PFL_EXPECT(result.exit_code == 0);
        PFL_EXPECT(result.stderr_text.empty());
        PFL_EXPECT(contains_text(result.stdout_text, "Commands"));
        PFL_EXPECT(contains_text(result.stdout_text, "List, filter, sort, and export flow metadata."));
        PFL_EXPECT(result.stdout_text == global_help_stdout);
    }

    {
        const auto output_path = std::filesystem::temp_directory_path() / "pfl_cli_summary_help_should_not_exist.idx";
        const auto output_path_text = output_path.string();
        std::filesystem::remove(output_path);
        const std::vector<std::string_view> args {
            "summary",
            "--help",
            "--unknown",
            "--out-index",
            output_path_text,
        };
        const auto result = cli::process_cli_invocation(args);
        PFL_EXPECT(result.handled);
        PFL_EXPECT(result.exit_code == 0);
        PFL_EXPECT(result.stderr_text.empty());
        PFL_EXPECT(contains_text(result.stdout_text, "PcapFlowLab CLI - summary"));
        PFL_EXPECT(contains_text(result.stdout_text, "pcap-flow-lab summary <input> [options]"));
        PFL_EXPECT(contains_text(result.stdout_text, "--settings <settings.json>"));
        PFL_EXPECT(contains_text(result.stdout_text, "--extended"));
        PFL_EXPECT(contains_text(result.stdout_text, "--protocol-path-tree"));
        PFL_EXPECT(contains_text(result.stdout_text, "kind-overview|identity-tree|terminal-paths"));
        PFL_EXPECT(contains_text(result.stdout_text, "--out-index <path>"));
        PFL_EXPECT(contains_text(result.stdout_text, "--out-flows-list <path>"));
        PFL_EXPECT(contains_text(result.stdout_text, "--out-protocol-path-tree <path>"));
        PFL_EXPECT(contains_text(result.stdout_text, "--progress <auto|on|off>"));
        PFL_EXPECT(contains_text(result.stdout_text, "--force"));
        PFL_EXPECT(contains_text(result.stdout_text, "-h, --help"));
        PFL_EXPECT(contains_text(result.stdout_text, "pcap-flow-lab capture.pcap"));
        PFL_EXPECT(!contains_text(result.stdout_text, "--format"));
        PFL_EXPECT(!contains_text(result.stdout_text, "\\--input"));
        PFL_EXPECT(!contains_text(result.stdout_text, "\\<input>"));
        PFL_EXPECT(!std::filesystem::exists(output_path));
        PFL_EXPECT(has_no_tabs_or_trailing_spaces(result.stdout_text));
        PFL_EXPECT(has_no_ansi_escape_sequences(result.stdout_text));
    }

    {
        const std::vector<std::string_view> args {"summary", "missing_capture_for_help.pcap", "--help"};
        const auto result = cli::process_cli_invocation(args);
        PFL_EXPECT(result.handled);
        PFL_EXPECT(result.exit_code == 0);
        PFL_EXPECT(result.stderr_text.empty());
        PFL_EXPECT(contains_text(result.stdout_text, "PcapFlowLab CLI - summary"));
        PFL_EXPECT(!contains_text(result.stdout_text, "Failed to open"));
    }

    {
        const std::vector<std::string_view> args {};
        const auto result = cli::process_cli_invocation(args);
        PFL_EXPECT(result.handled);
        PFL_EXPECT(result.exit_code == 1);
        PFL_EXPECT(result.stdout_text.empty());
        PFL_EXPECT(contains_text(result.stderr_text, "Pcap Flow Lab"));
        PFL_EXPECT(contains_text(result.stderr_text, "0.3.0"));
        PFL_EXPECT(contains_text(result.stderr_text, "Usage"));
        PFL_EXPECT(!contains_text(result.stderr_text, "PcapFlowLab CLI - summary"));
        PFL_EXPECT(!contains_text(result.stderr_text, "Usage:\n  pcap-flow-lab [summary] <input>\n"));
        PFL_EXPECT(!contains_text(result.stderr_text, "\\--input"));
        PFL_EXPECT(!contains_text(result.stderr_text, "\\<input>"));
        PFL_EXPECT(result.stderr_text == global_help_stdout);
        PFL_EXPECT(has_no_tabs_or_trailing_spaces(result.stderr_text));
        PFL_EXPECT(has_no_ansi_escape_sequences(result.stderr_text));
    }
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
        const std::vector<std::string_view> args {"hex"};
        const auto decision = cli::classify_cli_invocation(args);
        PFL_EXPECT(decision.kind == cli::SummaryDispatchKind::summary);
        PFL_REQUIRE(decision.summary_args.size() == 1U);
        PFL_EXPECT(decision.summary_args[0] == "hex");
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
        PFL_EXPECT(decision.kind == cli::SummaryDispatchKind::flows);
        PFL_REQUIRE(decision.summary_args.size() == 1U);
        PFL_EXPECT(decision.summary_args[0] == "capture.pcap");
    }

    {
        const std::vector<std::string_view> args {"flow", "capture.pcap"};
        const auto decision = cli::classify_cli_invocation(args);
        PFL_EXPECT(decision.kind == cli::SummaryDispatchKind::flows);
        PFL_REQUIRE(decision.summary_args.size() == 1U);
        PFL_EXPECT(decision.summary_args[0] == "capture.pcap");
    }

    {
        const std::vector<std::string_view> args {"export-flow", "capture.pcap"};
        const auto decision = cli::classify_cli_invocation(args);
        PFL_EXPECT(decision.kind == cli::SummaryDispatchKind::export_flows);
        PFL_REQUIRE(decision.summary_args.size() == 1U);
        PFL_EXPECT(decision.summary_args[0] == "capture.pcap");
    }

    {
        const std::vector<std::string_view> args {"flows-info", "capture.pcap"};
        const auto decision = cli::classify_cli_invocation(args);
        PFL_EXPECT(decision.kind == cli::SummaryDispatchKind::flow_info);
        PFL_REQUIRE(decision.summary_args.size() == 1U);
        PFL_EXPECT(decision.summary_args[0] == "capture.pcap");
    }

    {
        const std::vector<std::string_view> args {"packets-info", "capture.pcap"};
        const auto decision = cli::classify_cli_invocation(args);
        PFL_EXPECT(decision.kind == cli::SummaryDispatchKind::packet_info);
        PFL_REQUIRE(decision.summary_args.size() == 1U);
        PFL_EXPECT(decision.summary_args[0] == "capture.pcap");
    }

    {
        const std::vector<std::string_view> args {"summary", "flow"};
        const auto decision = cli::classify_cli_invocation(args);
        PFL_EXPECT(decision.kind == cli::SummaryDispatchKind::summary);
        PFL_REQUIRE(decision.summary_args.size() == 1U);
        PFL_EXPECT(decision.summary_args[0] == "flow");
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
        PFL_REQUIRE(parse_result.ok);
        PFL_REQUIRE(parse_result.options.has_value());
        PFL_REQUIRE(parse_result.options->settings_path.has_value());
        PFL_EXPECT(parse_result.options->settings_path->filename() == "settings.json");
    }

    {
        const std::vector<std::string_view> args {"capture.pcap", "--protocol-path-mode", "identity-tree"};
        const auto parse_result = cli::parse_summary_command_arguments(args);
        PFL_EXPECT(!parse_result.ok);
        PFL_EXPECT(contains_text(parse_result.error_text, "--out-protocol-path-tree"));
    }

    {
        const std::vector<std::string_view> args {
            "capture.pcap",
            "--out-protocol-path-tree",
            "tree.txt",
            "--protocol-path-mode",
            "terminal-paths",
        };
        const auto parse_result = cli::parse_summary_command_arguments(args);
        PFL_REQUIRE(parse_result.ok);
        PFL_REQUIRE(parse_result.options.has_value());
        PFL_REQUIRE(parse_result.options->out_protocol_path_tree_path.has_value());
        PFL_EXPECT(parse_result.options->protocol_path_mode == ProtocolPathStatisticsMode::terminal_paths);
    }

    {
        const std::vector<std::string_view> args {"capture.pcap", "--progress", "on", "--force"};
        const auto parse_result = cli::parse_summary_command_arguments(args);
        PFL_REQUIRE(parse_result.ok);
        PFL_REQUIRE(parse_result.options.has_value());
        PFL_EXPECT(parse_result.options->progress_mode == cli::SummaryCommandProgressMode::on);
        PFL_EXPECT(parse_result.options->force);
    }

    {
        const std::vector<std::string_view> args {"capture.pcap", "--out-flows-list", "flows.csv"};
        const auto parse_result = cli::parse_summary_command_arguments(args);
        PFL_REQUIRE(parse_result.ok);
        PFL_REQUIRE(parse_result.options.has_value());
        PFL_REQUIRE(parse_result.options->out_flows_list_path.has_value());
        PFL_EXPECT(parse_result.options->out_flows_list_path->filename() == "flows.csv");
    }

    {
        const std::vector<std::string_view> args {"capture.pcap", "--out-flows-list"};
        const auto parse_result = cli::parse_summary_command_arguments(args);
        PFL_EXPECT(!parse_result.ok);
        PFL_EXPECT(contains_text(parse_result.error_text, "--out-flows-list requires a path"));
    }

    {
        const std::vector<std::string_view> args {"capture.pcap", "--out-flows-list", "a.csv", "--out-flows-list", "b.csv"};
        const auto parse_result = cli::parse_summary_command_arguments(args);
        PFL_EXPECT(!parse_result.ok);
        PFL_EXPECT(contains_text(parse_result.error_text, "Duplicate --out-flows-list"));
    }

    {
        const std::vector<std::string_view> args {"capture.pcap", "--filter", "TLS"};
        const auto parse_result = cli::parse_summary_command_arguments(args);
        PFL_EXPECT(!parse_result.ok);
        PFL_EXPECT(contains_text(parse_result.error_text, "always whole-capture"));
    }
}

void expect_summary_syntax_error_help_behavior() {
    {
        const std::vector<std::string_view> args {"summary"};
        const auto result = cli::process_cli_invocation(args);
        PFL_EXPECT(result.handled);
        PFL_EXPECT(result.exit_code == 1);
        PFL_EXPECT(result.stdout_text.empty());
        PFL_EXPECT(contains_text(result.stderr_text, "summary requires an input path"));
        PFL_EXPECT(contains_text(result.stderr_text, "PcapFlowLab CLI - summary"));
        PFL_EXPECT(!contains_text(result.stderr_text, "PcapFlowLab CLI\n\nUsage"));
    }

    {
        const std::vector<std::string_view> args {"summary", "capture.pcap", "--input", "capture.pcap"};
        const auto result = cli::process_cli_invocation(args);
        PFL_EXPECT(result.handled);
        PFL_EXPECT(result.exit_code == 1);
        PFL_EXPECT(result.stdout_text.empty());
        PFL_EXPECT(contains_text(result.stderr_text, "mutually exclusive input forms"));
        PFL_EXPECT(contains_text(result.stderr_text, "pcap-flow-lab summary <input> [options]"));
    }

    {
        const std::vector<std::string_view> args {"summary", "capture.pcap", "--unknown"};
        const auto result = cli::process_cli_invocation(args);
        PFL_EXPECT(result.handled);
        PFL_EXPECT(result.exit_code == 1);
        PFL_EXPECT(result.stdout_text.empty());
        PFL_EXPECT(contains_text(result.stderr_text, "Unknown summary option"));
        PFL_EXPECT(contains_text(result.stderr_text, "--protocol-path-mode <kind-overview|identity-tree|terminal-paths>"));
    }

    {
        const std::vector<std::string_view> args {"summary", "capture.pcap", "--protocol-path-mode", "invalid-mode"};
        const auto result = cli::process_cli_invocation(args);
        PFL_EXPECT(result.handled);
        PFL_EXPECT(result.exit_code == 1);
        PFL_EXPECT(result.stdout_text.empty());
        PFL_EXPECT(contains_text(result.stderr_text, "Invalid --protocol-path-mode value"));
        PFL_EXPECT(contains_text(result.stderr_text, "PcapFlowLab CLI - summary"));
    }

    {
        const std::vector<std::string_view> args {"capture.pcap", "--unknown"};
        const auto result = cli::process_cli_invocation(args);
        PFL_EXPECT(result.handled);
        PFL_EXPECT(result.exit_code == 1);
        PFL_EXPECT(result.stdout_text.empty());
        PFL_EXPECT(contains_text(result.stderr_text, "Unknown summary option"));
        PFL_EXPECT(contains_text(result.stderr_text, "pcap-flow-lab <input> [summary options]"));
    }
}

void expect_runtime_errors_do_not_append_help() {
    {
        const std::vector<std::string_view> args {"summary", "missing_capture_for_cli_help_test.pcap"};
        const auto result = cli::process_cli_invocation(args);
        PFL_EXPECT(result.handled);
        PFL_EXPECT(result.exit_code == 1);
        PFL_EXPECT(result.stdout_text.empty());
        PFL_EXPECT(!result.stderr_text.empty());
        PFL_EXPECT(!contains_text(result.stderr_text, "PcapFlowLab CLI - summary"));
        PFL_EXPECT(!contains_text(result.stderr_text, "Usage"));
    }

    {
        const auto malformed_settings_path = write_temp_text_file(
            "pfl_cli_summary_help_runtime_malformed.json",
            "{"
        );
        const auto input_path_text = fixture_path("parsing/packet_byte_views/01_ethernet_ipv4_udp.pcap").string();
        const auto malformed_settings_path_text = malformed_settings_path.string();
        const std::vector<std::string_view> args {
            "summary",
            input_path_text,
            "--settings",
            malformed_settings_path_text,
        };
        const auto result = cli::process_cli_invocation(args);
        PFL_EXPECT(result.handled);
        PFL_EXPECT(result.exit_code == 1);
        PFL_EXPECT(result.stdout_text.empty());
        PFL_EXPECT(contains_text(result.stderr_text, "Invalid settings JSON"));
        PFL_EXPECT(!contains_text(result.stderr_text, "PcapFlowLab CLI - summary"));
    }

    {
        const auto capture_path = fixture_path("parsing/packet_byte_views/01_ethernet_ipv4_udp.pcap");
        const auto existing_target = write_temp_text_file("pfl_cli_summary_help_runtime_existing.txt", "old");
        cli::SummaryCommandOptions options {};
        options.input_path = capture_path;
        options.out_protocol_path_tree_path = existing_target;
        const auto result = cli::execute_summary_command(options);
        PFL_EXPECT(result.exit_code == 1);
        PFL_EXPECT(contains_text(result.stderr_text, "--out-protocol-path-tree already exists"));
        PFL_EXPECT(!contains_text(result.stderr_text, "PcapFlowLab CLI - summary"));
    }
}

void expect_progress_policy_rules() {
    PFL_EXPECT(!cli::should_enable_summary_progress(cli::SummaryCommandProgressMode::off, false));
    PFL_EXPECT(!cli::should_enable_summary_progress(cli::SummaryCommandProgressMode::off, true));
    PFL_EXPECT(cli::should_enable_summary_progress(cli::SummaryCommandProgressMode::on, false));
    PFL_EXPECT(cli::should_enable_summary_progress(cli::SummaryCommandProgressMode::on, true));
    PFL_EXPECT(!cli::should_enable_summary_progress(cli::SummaryCommandProgressMode::auto_mode, false));
    PFL_EXPECT(cli::should_enable_summary_progress(cli::SummaryCommandProgressMode::auto_mode, true));
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

void expect_settings_file_contracts() {
    const auto capture_path = fixture_path("parsing/gtpu/21_gtpu_same_inner_tuple_different_teid.pcap");
    const auto empty_settings_path = write_temp_text_file(
        "pfl_cli_summary_settings_empty.json",
        "{}"
    );
    const auto settings_path = write_temp_text_file(
        "pfl_cli_summary_settings_valid.json",
        settings_json(true)
    );
    const auto checksum_only_settings_path = write_temp_text_file(
        "pfl_cli_summary_settings_checksum_only.json",
        "{\"validate_selected_packet_checksums\":true}"
    );

    FrontendSessionAdapter default_adapter {};
    PFL_REQUIRE(default_adapter.open_capture(capture_path).opened);
    const auto default_overview = default_adapter.get_overview();

    FrontendSessionAdapter grouped_adapter {};
    [[maybe_unused]] const auto grouped_settings = grouped_adapter.update_settings(FrontendSettingsDto {
        .ignore_gtpu_teids_when_grouping_inner_flows = true,
        .show_wireshark_filter_for_selected_flow = true,
    });
    PFL_REQUIRE(grouped_adapter.open_capture(capture_path).opened);
    const auto grouped_overview = grouped_adapter.get_overview();
    PFL_EXPECT(default_overview.summary.flow_count != grouped_overview.summary.flow_count);

    {
        cli::SummaryCommandOptions empty_options {};
        empty_options.input_path = capture_path;
        empty_options.settings_path = empty_settings_path;
        const auto empty_result = cli::execute_summary_command(empty_options);
        PFL_EXPECT(empty_result.exit_code == 0);
        PFL_EXPECT(contains_text(
            empty_result.stdout_text,
            "Flows:   " + session_detail::format_statistics_count_value(default_overview.summary.flow_count)
        ));
    }

    cli::SummaryCommandOptions options {};
    options.input_path = capture_path;
    options.settings_path = settings_path;
    const auto execution_result = cli::execute_summary_command(options);
    PFL_EXPECT(execution_result.exit_code == 0);
    PFL_EXPECT(contains_text(
        execution_result.stdout_text,
        "Flows:   " + session_detail::format_statistics_count_value(grouped_overview.summary.flow_count)
    ));

    {
        cli::SummaryCommandOptions checksum_only_options {};
        checksum_only_options.input_path = capture_path;
        checksum_only_options.settings_path = checksum_only_settings_path;
        const auto checksum_only_result = cli::execute_summary_command(checksum_only_options);
        PFL_EXPECT(checksum_only_result.exit_code == 0);
        PFL_EXPECT(contains_text(
            checksum_only_result.stdout_text,
            "Flows:   " + session_detail::format_statistics_count_value(default_overview.summary.flow_count)
        ));
    }

    {
        cli::SummaryCommandOptions index_settings_options {};
        index_settings_options.input_path = std::filesystem::temp_directory_path() / "capture.idx";
        index_settings_options.settings_path = settings_path;
        const auto result = cli::execute_summary_command(index_settings_options);
        PFL_EXPECT(result.exit_code == 1);
        PFL_EXPECT(contains_text(result.stderr_text, "--settings is valid only for raw capture input"));
    }

    {
        cli::SummaryCommandOptions missing_settings_options {};
        missing_settings_options.input_path = capture_path;
        missing_settings_options.settings_path = std::filesystem::temp_directory_path() / "missing-summary-settings.json";
        const auto result = cli::execute_summary_command(missing_settings_options);
        PFL_EXPECT(result.exit_code == 1);
        PFL_EXPECT(contains_text(result.stderr_text, "Settings file does not exist"));
    }

    {
        const auto malformed_settings_path = write_temp_text_file(
            "pfl_cli_summary_settings_malformed.json",
            "{"
        );
        cli::SummaryCommandOptions malformed_options {};
        malformed_options.input_path = capture_path;
        malformed_options.settings_path = malformed_settings_path;
        const auto result = cli::execute_summary_command(malformed_options);
        PFL_EXPECT(result.exit_code == 1);
        PFL_EXPECT(contains_text(result.stderr_text, "Invalid settings JSON"));
    }

    {
        const auto trailing_comma_settings_path = write_temp_text_file(
            "pfl_cli_summary_settings_trailing_comma.json",
            "{\n  \"validate_selected_packet_checksums\": true,\n}"
        );
        cli::SummaryCommandOptions trailing_comma_options {};
        trailing_comma_options.input_path = capture_path;
        trailing_comma_options.settings_path = trailing_comma_settings_path;
        const auto result = cli::execute_summary_command(trailing_comma_options);
        PFL_EXPECT(result.exit_code == 1);
        PFL_EXPECT(contains_text(result.stderr_text, "Invalid settings JSON"));
    }

    {
        const auto invalid_type_settings_path = write_temp_text_file(
            "pfl_cli_summary_settings_invalid_type.json",
            "{\"ignore_gtpu_teids_when_grouping_inner_flows\":1}"
        );
        cli::SummaryCommandOptions invalid_type_options {};
        invalid_type_options.input_path = capture_path;
        invalid_type_options.settings_path = invalid_type_settings_path;
        const auto result = cli::execute_summary_command(invalid_type_options);
        PFL_EXPECT(result.exit_code == 1);
        PFL_EXPECT(contains_text(result.stderr_text, "expected boolean value"));
    }

    {
        const auto invalid_vlan_type_settings_path = write_temp_text_file(
            "pfl_cli_summary_settings_invalid_vlan_type.json",
            "{\"ignore_vlan_and_mpls_layers_when_grouping_flows\":1}"
        );
        cli::SummaryCommandOptions invalid_vlan_type_options {};
        invalid_vlan_type_options.input_path = capture_path;
        invalid_vlan_type_options.settings_path = invalid_vlan_type_settings_path;
        const auto result = cli::execute_summary_command(invalid_vlan_type_options);
        PFL_EXPECT(result.exit_code == 1);
        PFL_EXPECT(contains_text(result.stderr_text, "expected boolean value"));
    }

    {
        const auto invalid_checksum_type_settings_path = write_temp_text_file(
            "pfl_cli_summary_settings_invalid_checksum_type.json",
            "{\"validate_selected_packet_checksums\":1}"
        );
        cli::SummaryCommandOptions invalid_checksum_type_options {};
        invalid_checksum_type_options.input_path = capture_path;
        invalid_checksum_type_options.settings_path = invalid_checksum_type_settings_path;
        const auto result = cli::execute_summary_command(invalid_checksum_type_options);
        PFL_EXPECT(result.exit_code == 1);
        PFL_EXPECT(contains_text(result.stderr_text, "expected boolean value"));
    }

    {
        const auto removed_http_settings_path = write_temp_text_file(
            "pfl_cli_summary_settings_removed_http.json",
            "{\"http_use_path_as_service_hint\":true}"
        );
        cli::SummaryCommandOptions removed_http_options {};
        removed_http_options.input_path = capture_path;
        removed_http_options.settings_path = removed_http_settings_path;
        const auto result = cli::execute_summary_command(removed_http_options);
        PFL_EXPECT(result.exit_code == 1);
        PFL_EXPECT(contains_text(result.stderr_text, "Unknown settings field"));
    }

    {
        const auto removed_quic_settings_path = write_temp_text_file(
            "pfl_cli_summary_settings_removed_quic.json",
            "{\"use_possible_tls_quic\":true}"
        );
        cli::SummaryCommandOptions removed_quic_options {};
        removed_quic_options.input_path = capture_path;
        removed_quic_options.settings_path = removed_quic_settings_path;
        const auto result = cli::execute_summary_command(removed_quic_options);
        PFL_EXPECT(result.exit_code == 1);
        PFL_EXPECT(contains_text(result.stderr_text, "Unknown settings field"));
    }

    {
        const auto removed_wireshark_settings_path = write_temp_text_file(
            "pfl_cli_summary_settings_removed_wireshark.json",
            "{\"show_wireshark_filter_for_selected_flow\":true}"
        );
        cli::SummaryCommandOptions removed_wireshark_options {};
        removed_wireshark_options.input_path = capture_path;
        removed_wireshark_options.settings_path = removed_wireshark_settings_path;
        const auto result = cli::execute_summary_command(removed_wireshark_options);
        PFL_EXPECT(result.exit_code == 1);
        PFL_EXPECT(contains_text(result.stderr_text, "Unknown settings field"));
    }

    {
        const auto typo_settings_path = write_temp_text_file(
            "pfl_cli_summary_settings_typo.json",
            "{\"ignore_gtpu_teids_when_grouping_inner_flowz\":true}"
        );
        cli::SummaryCommandOptions typo_options {};
        typo_options.input_path = capture_path;
        typo_options.settings_path = typo_settings_path;
        const auto result = cli::execute_summary_command(typo_options);
        PFL_EXPECT(result.exit_code == 1);
        PFL_EXPECT(contains_text(result.stderr_text, "Unknown settings field"));
    }

    {
        const auto all_supported_settings_path = write_temp_text_file(
            "pfl_cli_summary_settings_all_supported.json",
            settings_json(true, false, true)
        );
        cli::SummaryCommandOptions all_supported_options {};
        all_supported_options.input_path = capture_path;
        all_supported_options.settings_path = all_supported_settings_path;
        const auto result = cli::execute_summary_command(all_supported_options);
        PFL_EXPECT(result.exit_code == 0);
        PFL_EXPECT(contains_text(
            result.stdout_text,
            "Flows:   " + session_detail::format_statistics_count_value(grouped_overview.summary.flow_count)
        ));
    }
}

void expect_index_output_contracts() {
    const auto capture_path = fixture_path("parsing/gtpu/21_gtpu_same_inner_tuple_different_teid.pcap");
    const auto settings_path = write_temp_text_file(
        "pfl_cli_summary_settings_for_index.json",
        settings_json(true)
    );
    const auto output_index_path = std::filesystem::temp_directory_path() / "pfl_cli_summary_output.idx";
    const auto protocol_tree_path = std::filesystem::temp_directory_path() / "pfl_cli_summary_output_protocol_tree.txt";
    std::filesystem::remove(output_index_path);
    std::filesystem::remove(protocol_tree_path);

    FrontendSessionAdapter grouped_adapter {};
    [[maybe_unused]] const auto grouped_settings = grouped_adapter.update_settings(FrontendSettingsDto {
        .ignore_gtpu_teids_when_grouping_inner_flows = true,
        .show_wireshark_filter_for_selected_flow = true,
    });
    PFL_REQUIRE(grouped_adapter.open_capture(capture_path).opened);
    const auto grouped_overview = grouped_adapter.get_overview();

    cli::SummaryCommandOptions options {};
    options.input_path = capture_path;
    options.settings_path = settings_path;
    options.out_index_path = output_index_path;
    options.out_protocol_path_tree_path = protocol_tree_path;
    const auto result = cli::execute_summary_command(options);
    PFL_EXPECT(result.exit_code == 0);
    PFL_EXPECT(contains_text(result.stderr_text, "Index written to:"));
    PFL_EXPECT(contains_text(result.stderr_text, "Protocol Path Tree written to:"));

    FrontendSessionAdapter reopened_index {};
    PFL_REQUIRE(reopened_index.open_capture(output_index_path).opened);
    const auto reopened_overview = reopened_index.get_overview();
    PFL_EXPECT(reopened_overview.summary.flow_count == grouped_overview.summary.flow_count);

    std::ifstream protocol_tree_stream {protocol_tree_path, std::ios::binary};
    const std::string protocol_tree_text {
        std::istreambuf_iterator<char>(protocol_tree_stream),
        std::istreambuf_iterator<char>()
    };
    PFL_EXPECT(contains_text(protocol_tree_text, "Protocol Path Tree"));

    {
        cli::SummaryCommandOptions invalid_index_options {};
        invalid_index_options.input_path = output_index_path;
        invalid_index_options.out_index_path = std::filesystem::temp_directory_path() / "copy.idx";
        const auto invalid_result = cli::execute_summary_command(invalid_index_options);
        PFL_EXPECT(invalid_result.exit_code == 1);
        PFL_EXPECT(contains_text(invalid_result.stderr_text, "--out-index is valid only for raw capture input"));
    }

    {
        const auto existing_target = write_temp_text_file("pfl_cli_summary_existing_output.idx", "old");
        cli::SummaryCommandOptions existing_options {};
        existing_options.input_path = capture_path;
        existing_options.out_index_path = existing_target;
        const auto existing_result = cli::execute_summary_command(existing_options);
        PFL_EXPECT(existing_result.exit_code == 1);
        PFL_EXPECT(contains_text(existing_result.stderr_text, "--out-index already exists"));

        cli::SummaryCommandOptions force_options {};
        force_options.input_path = capture_path;
        force_options.out_index_path = existing_target;
        force_options.force = true;
        const auto force_result = cli::execute_summary_command(force_options);
        PFL_EXPECT(force_result.exit_code == 0);
        PFL_EXPECT(contains_text(force_result.stderr_text, "Index written to:"));
    }

    {
        cli::SummaryCommandOptions same_path_options {};
        same_path_options.input_path = capture_path;
        same_path_options.out_index_path = capture_path;
        const auto same_path_result = cli::execute_summary_command(same_path_options);
        PFL_EXPECT(same_path_result.exit_code == 1);
        PFL_EXPECT(contains_text(same_path_result.stderr_text, "cannot overwrite an input or configuration path"));
    }
}

void expect_protocol_path_export_contracts() {
    const auto capture_path = fixture_path("parsing/packet_byte_views/01_ethernet_ipv4_udp.pcap");
    const auto protocol_tree_path = std::filesystem::temp_directory_path() / "pfl_cli_protocol_path_identity.txt";
    std::filesystem::remove(protocol_tree_path);

    cli::SummaryCommandOptions identity_options {};
    identity_options.input_path = capture_path;
    identity_options.protocol_path_mode = ProtocolPathStatisticsMode::identity_tree;
    identity_options.out_protocol_path_tree_path = protocol_tree_path;
    const auto identity_result = cli::execute_summary_command(identity_options);
    PFL_EXPECT(identity_result.exit_code == 0);
    PFL_EXPECT(!contains_text(identity_result.stdout_text, "Protocol Path Tree\nMode: Identity tree"));
    PFL_EXPECT(contains_text(identity_result.stderr_text, "Protocol Path Tree written to:"));

    {
        std::ifstream tree_stream {protocol_tree_path, std::ios::binary};
        const std::string tree_text {
            std::istreambuf_iterator<char>(tree_stream),
            std::istreambuf_iterator<char>()
        };
        PFL_EXPECT(contains_text(tree_text, "Mode: Identity tree"));
    }

    cli::SummaryCommandOptions preview_and_export_options {};
    preview_and_export_options.input_path = capture_path;
    preview_and_export_options.protocol_path_tree = true;
    preview_and_export_options.protocol_path_mode = ProtocolPathStatisticsMode::terminal_paths;
    preview_and_export_options.out_protocol_path_tree_path =
        std::filesystem::temp_directory_path() / "pfl_cli_protocol_path_terminal.txt";
    std::filesystem::remove(*preview_and_export_options.out_protocol_path_tree_path);
    const auto preview_and_export_result = cli::execute_summary_command(preview_and_export_options);
    PFL_EXPECT(preview_and_export_result.exit_code == 0);
    PFL_EXPECT(contains_text(preview_and_export_result.stdout_text, "Mode: Terminal paths"));

    {
        FrontendSessionAdapter raw_adapter {};
        PFL_REQUIRE(raw_adapter.open_capture(capture_path).opened);
        const auto index_path = std::filesystem::temp_directory_path() / "pfl_cli_protocol_path.idx";
        std::filesystem::remove(index_path);
        PFL_REQUIRE(raw_adapter.save_index(index_path).saved);

        cli::SummaryCommandOptions index_export_options {};
        index_export_options.input_path = index_path;
        index_export_options.out_protocol_path_tree_path =
            std::filesystem::temp_directory_path() / "pfl_cli_protocol_path_from_index.txt";
        std::filesystem::remove(*index_export_options.out_protocol_path_tree_path);
        const auto index_export_result = cli::execute_summary_command(index_export_options);
        PFL_EXPECT(index_export_result.exit_code == 0);
        PFL_EXPECT(contains_text(index_export_result.stderr_text, "Protocol Path Tree written to:"));
    }

    {
        const auto existing_target = write_temp_text_file("pfl_cli_protocol_path_existing.txt", "old");
        cli::SummaryCommandOptions existing_options {};
        existing_options.input_path = capture_path;
        existing_options.out_protocol_path_tree_path = existing_target;
        const auto existing_result = cli::execute_summary_command(existing_options);
        PFL_EXPECT(existing_result.exit_code == 1);
        PFL_EXPECT(contains_text(existing_result.stderr_text, "--out-protocol-path-tree already exists"));

        cli::SummaryCommandOptions force_options {};
        force_options.input_path = capture_path;
        force_options.out_protocol_path_tree_path = existing_target;
        force_options.force = true;
        const auto force_result = cli::execute_summary_command(force_options);
        PFL_EXPECT(force_result.exit_code == 0);
        PFL_EXPECT(contains_text(force_result.stderr_text, "Protocol Path Tree written to:"));
    }

    {
        cli::SummaryCommandOptions same_path_options {};
        same_path_options.input_path = capture_path;
        same_path_options.out_protocol_path_tree_path = capture_path;
        const auto same_path_result = cli::execute_summary_command(same_path_options);
        PFL_EXPECT(same_path_result.exit_code == 1);
        PFL_EXPECT(contains_text(same_path_result.stderr_text, "cannot overwrite an input or configuration path"));
    }
}

void expect_flow_list_export_contracts() {
    const auto capture_path = fixture_path("parsing/gtpu/21_gtpu_same_inner_tuple_different_teid.pcap");
    const auto settings_path = write_temp_text_file(
        "pfl_cli_summary_settings_for_flow_list.json",
        settings_json(true)
    );
    const auto flow_list_path = std::filesystem::temp_directory_path() / "pfl_cli_summary_flows.csv";
    std::filesystem::remove(flow_list_path);

    FrontendSessionAdapter default_adapter {};
    PFL_REQUIRE(default_adapter.open_capture(capture_path).opened);
    const auto default_overview = default_adapter.get_overview();

    FrontendSessionAdapter grouped_adapter {};
    [[maybe_unused]] const auto grouped_settings = grouped_adapter.update_settings(FrontendSettingsDto {
        .ignore_gtpu_teids_when_grouping_inner_flows = true,
        .show_wireshark_filter_for_selected_flow = true,
    });
    PFL_REQUIRE(grouped_adapter.open_capture(capture_path).opened);
    const auto grouped_overview = grouped_adapter.get_overview();
    PFL_EXPECT(grouped_overview.summary.flow_count < default_overview.summary.flow_count);

    cli::SummaryCommandOptions options {};
    options.input_path = capture_path;
    options.settings_path = settings_path;
    options.out_flows_list_path = flow_list_path;
    const auto result = cli::execute_summary_command(options);
    PFL_EXPECT(result.exit_code == 0);
    PFL_EXPECT(contains_text(result.stderr_text, "Flow list written to:"));

    const auto csv_lines = read_text_file_lines(flow_list_path);
    PFL_EXPECT(csv_lines.size() == grouped_overview.summary.flow_count + 1U);
    PFL_REQUIRE(csv_lines.size() >= 2U);
    PFL_EXPECT(csv_lines.front() ==
        "flow_id,family,transport,protocol,protocol_hint,src_ip,src_port,dst_ip,dst_port,packet_count,captured_bytes,original_bytes,first_timestamp,last_timestamp,duration_us,protocol_path");
    const auto first_row = split_csv_line(csv_lines[1]);
    PFL_REQUIRE(first_row.size() == 16U);
    PFL_EXPECT(first_row[0] == "1");

    {
        const auto flows_csv_path = std::filesystem::temp_directory_path() / "pfl_cli_summary_flows_parity.csv";
        std::filesystem::remove(flows_csv_path);
        const auto capture_path_text = capture_path.string();
        const auto settings_path_text = settings_path.string();
        const auto flows_csv_path_text = flows_csv_path.string();
        const std::vector<std::string_view> flow_args {
            "flows",
            capture_path_text,
            "--settings",
            settings_path_text,
            "--out-flows-list",
            flows_csv_path_text,
        };
        const auto flows_result = cli::process_cli_invocation(flow_args);
        PFL_EXPECT(flows_result.handled);
        PFL_EXPECT(flows_result.exit_code == 0);

        const auto flow_lines = read_text_file_lines(flows_csv_path);
        PFL_EXPECT(flow_lines == csv_lines);
    }

    {
        FrontendSessionAdapter raw_adapter {};
        PFL_REQUIRE(raw_adapter.open_capture(capture_path).opened);
        const auto index_path = std::filesystem::temp_directory_path() / "pfl_cli_summary_flows.idx";
        std::filesystem::remove(index_path);
        PFL_REQUIRE(raw_adapter.save_index(index_path).saved);

        const auto index_flow_list_path = std::filesystem::temp_directory_path() / "pfl_cli_summary_flows_from_index.csv";
        std::filesystem::remove(index_flow_list_path);

        cli::SummaryCommandOptions index_options {};
        index_options.input_path = index_path;
        index_options.out_flows_list_path = index_flow_list_path;
        const auto index_result = cli::execute_summary_command(index_options);
        PFL_EXPECT(index_result.exit_code == 0);
        PFL_EXPECT(contains_text(index_result.stderr_text, "Flow list written to:"));

        const auto index_lines = read_text_file_lines(index_flow_list_path);
        PFL_EXPECT(index_lines.size() == default_overview.summary.flow_count + 1U);
    }

    {
        const auto existing_target = write_temp_text_file("pfl_cli_summary_existing_flows.csv", "old");
        cli::SummaryCommandOptions existing_options {};
        existing_options.input_path = capture_path;
        existing_options.out_flows_list_path = existing_target;
        const auto existing_result = cli::execute_summary_command(existing_options);
        PFL_EXPECT(existing_result.exit_code == 1);
        PFL_EXPECT(contains_text(existing_result.stderr_text, "--out-flows-list already exists"));

        cli::SummaryCommandOptions force_options {};
        force_options.input_path = capture_path;
        force_options.out_flows_list_path = existing_target;
        force_options.force = true;
        const auto force_result = cli::execute_summary_command(force_options);
        PFL_EXPECT(force_result.exit_code == 0);
        PFL_EXPECT(contains_text(force_result.stderr_text, "Flow list written to:"));
    }

    {
        cli::SummaryCommandOptions same_path_options {};
        same_path_options.input_path = capture_path;
        same_path_options.out_flows_list_path = capture_path;
        const auto same_path_result = cli::execute_summary_command(same_path_options);
        PFL_EXPECT(same_path_result.exit_code == 1);
        PFL_EXPECT(contains_text(same_path_result.stderr_text, "cannot overwrite an input or configuration path"));
    }

    {
        cli::SummaryCommandOptions missing_parent_options {};
        missing_parent_options.input_path = capture_path;
        missing_parent_options.out_flows_list_path =
            std::filesystem::temp_directory_path() / "pfl_cli_missing_dir" / "flows.csv";
        const auto missing_parent_result = cli::execute_summary_command(missing_parent_options);
        PFL_EXPECT(missing_parent_result.exit_code == 1);
        PFL_EXPECT(contains_text(missing_parent_result.stderr_text, "parent directory does not exist"));
    }
}

void expect_combined_side_output_preflight_contracts() {
    const auto capture_path = fixture_path("parsing/packet_byte_views/01_ethernet_ipv4_udp.pcap");
    const auto shared_path = std::filesystem::temp_directory_path() / "pfl_cli_summary_duplicate_output.txt";
    const auto index_path = std::filesystem::temp_directory_path() / "pfl_cli_summary_triplet.idx";
    const auto flow_list_path = std::filesystem::temp_directory_path() / "pfl_cli_summary_triplet.csv";
    const auto protocol_tree_path = std::filesystem::temp_directory_path() / "pfl_cli_summary_triplet.txt";
    std::filesystem::remove(shared_path);
    std::filesystem::remove(index_path);
    std::filesystem::remove(flow_list_path);
    std::filesystem::remove(protocol_tree_path);

    {
        cli::SummaryCommandOptions conflict_options {};
        conflict_options.input_path = capture_path;
        conflict_options.out_index_path = shared_path;
        conflict_options.out_flows_list_path = shared_path;
        const auto result = cli::execute_summary_command(conflict_options);
        PFL_EXPECT(result.exit_code == 1);
        PFL_EXPECT(contains_text(result.stderr_text, "Summary side outputs must target distinct paths."));
    }

    {
        cli::SummaryCommandOptions conflict_options {};
        conflict_options.input_path = capture_path;
        conflict_options.out_flows_list_path = shared_path;
        conflict_options.out_protocol_path_tree_path = shared_path;
        const auto result = cli::execute_summary_command(conflict_options);
        PFL_EXPECT(result.exit_code == 1);
        PFL_EXPECT(contains_text(result.stderr_text, "Summary side outputs must target distinct paths."));
    }

    {
        cli::SummaryCommandOptions all_outputs_options {};
        all_outputs_options.input_path = capture_path;
        all_outputs_options.out_index_path = index_path;
        all_outputs_options.out_flows_list_path = flow_list_path;
        all_outputs_options.out_protocol_path_tree_path = protocol_tree_path;
        const auto result = cli::execute_summary_command(all_outputs_options);
        PFL_EXPECT(result.exit_code == 0);
        PFL_EXPECT(contains_text(result.stderr_text, "Index written to:"));
        PFL_EXPECT(contains_text(result.stderr_text, "Flow list written to:"));
        PFL_EXPECT(contains_text(result.stderr_text, "Protocol Path Tree written to:"));
    }
}

void expect_preflight_fails_before_opening_input() {
    const auto existing_target = write_temp_text_file("pfl_cli_summary_preflight_existing.txt", "old");
    cli::SummaryCommandOptions options {};
    options.input_path = std::filesystem::temp_directory_path() / "missing_summary_input_capture.pcap";
    options.out_protocol_path_tree_path = existing_target;
    const auto result = cli::execute_summary_command(options);
    PFL_EXPECT(result.exit_code == 1);
    PFL_EXPECT(contains_text(result.stderr_text, "--out-protocol-path-tree already exists"));
    PFL_EXPECT(!contains_text(result.stderr_text, "Failed to open input"));
}

void expect_open_progress_helper_behavior() {
    FrontendOpenProgressDto stale_success_progress {
        .in_progress = true,
        .opening_as_index = false,
        .bytes_processed = 980U,
        .total_bytes = 1000U,
        .percent = 0.98,
    };
    FrontendOpenResult success_result {
        .opened = true,
    };
    const auto normalized_success = cli::normalize_successful_open_progress(stale_success_progress, success_result);
    PFL_EXPECT(!normalized_success.in_progress);
    PFL_EXPECT(normalized_success.percent == 1.0);
    PFL_EXPECT(normalized_success.bytes_processed == 1000U);
    PFL_EXPECT(contains_text(cli::render_open_progress_text(normalized_success), "100%"));

    FrontendOpenResult partial_result {
        .opened = true,
        .partial_open = true,
    };
    const auto partial_progress = cli::normalize_successful_open_progress(stale_success_progress, partial_result);
    PFL_EXPECT(partial_progress.in_progress == stale_success_progress.in_progress);
    PFL_EXPECT(partial_progress.percent == stale_success_progress.percent);
    PFL_EXPECT(partial_progress.bytes_processed == stale_success_progress.bytes_processed);

    {
        const auto update = cli::render_interactive_progress_update("Opening capture: 100%", 0U);
        PFL_EXPECT(update == "\rOpening capture: 100%");
    }

    {
        const auto update = cli::render_interactive_progress_update("Opening capture: 100%", 32U);
        const auto expected = std::string {"\r"} + std::string(32U, ' ') + "\rOpening capture: 100%";
        PFL_EXPECT(update == expected);
    }
}

void expect_live_progress_runtime_contracts() {
    const auto capture_path = build_cli_progress_capture_path();
    const auto export_path = std::filesystem::temp_directory_path() / "pfl_cli_progress_export_output.pcap";
    std::filesystem::remove(export_path);

    const std::vector<std::vector<std::string>> command_args {
        {"summary", capture_path.string(), "--progress", "on"},
        {capture_path.string(), "--progress", "on"},
        {"flows", capture_path.string(), "--progress", "on"},
        {"export-flows", capture_path.string(), "--flow-number", "1", "--first-packets", "1", "--out", export_path.string(), "--progress", "on"},
        {"flow-info", capture_path.string(), "--flow-number", "1", "--progress", "on"},
        {"packet-info", capture_path.string(), "--packet-in-file", "1", "--progress", "on"},
    };

    for (const auto& args : command_args) {
        const auto invocation = invoke_cli_with_runtime(args, false);
        PFL_EXPECT(invocation.result.handled);
        PFL_EXPECT(invocation.result.exit_code == 0);
        PFL_EXPECT(!invocation.progress_text.empty());
        PFL_EXPECT(contains_text(invocation.progress_text, "Opening capture: "));
        PFL_EXPECT(!contains_text(invocation.result.stderr_text, "Opening capture: "));
        const auto final_line = last_progress_line(invocation.progress_text);
        PFL_EXPECT(contains_text(final_line, "100%"));
        PFL_EXPECT(count_text_occurrences(invocation.progress_text, final_line) == 1U);
    }

    const auto off_invocation = invoke_cli_with_runtime(
        {"summary", capture_path.string(), "--progress", "off"},
        true
    );
    PFL_EXPECT(off_invocation.result.exit_code == 0);
    PFL_EXPECT(off_invocation.progress_text.empty());

    const auto auto_terminal_invocation = invoke_cli_with_runtime(
        {"summary", capture_path.string(), "--progress", "auto"},
        true
    );
    PFL_EXPECT(auto_terminal_invocation.result.exit_code == 0);
    PFL_EXPECT(contains_text(auto_terminal_invocation.progress_text, "Opening capture: "));

    const auto auto_redirected_invocation = invoke_cli_with_runtime(
        {"summary", capture_path.string(), "--progress", "auto"},
        false
    );
    PFL_EXPECT(auto_redirected_invocation.result.exit_code == 0);
    PFL_EXPECT(auto_redirected_invocation.progress_text.empty());
}

void expect_progress_failure_and_partial_open_contracts() {
    const auto failed_invocation = invoke_cli_with_runtime(
        {"summary", "pfl_cli_progress_missing_input_capture.pcap", "--progress", "on"},
        true
    );
    PFL_EXPECT(failed_invocation.result.handled);
    PFL_EXPECT(failed_invocation.result.exit_code == 1);
    PFL_EXPECT(failed_invocation.progress_text.empty());
    PFL_EXPECT(!failed_invocation.result.stderr_text.empty());
    PFL_EXPECT(!contains_text(failed_invocation.result.stderr_text, "100%"));

    const auto partial_capture_path = build_partial_open_capture_path();
    const auto partial_invocation = invoke_cli_with_runtime(
        {"summary", partial_capture_path.string(), "--progress", "on"},
        true
    );
    PFL_EXPECT(partial_invocation.result.handled);
    PFL_EXPECT(partial_invocation.result.exit_code == 0);
    PFL_EXPECT(!partial_invocation.progress_text.empty());
    PFL_EXPECT(!partial_invocation.result.stderr_text.empty());
    PFL_EXPECT(!contains_text(last_progress_line(partial_invocation.progress_text), "100%"));
    PFL_EXPECT(!contains_text(partial_invocation.result.stderr_text, "Opening capture: "));
    PFL_EXPECT(partial_invocation.progress_text.back() == '\n');
}

}  // namespace

void run_cli_summary_tests() {
    expect_global_and_summary_help_behavior();
    expect_summary_dispatch_and_parse_rules();
    expect_summary_syntax_error_help_behavior();
    expect_runtime_errors_do_not_append_help();
    expect_progress_policy_rules();
    expect_basic_summary_rendering();
    expect_index_summary_rendering_without_source_capture();
    expect_extended_summary_rendering();
    expect_protocol_path_preview_rendering();
    expect_protocol_path_summary_execution();
    expect_settings_file_contracts();
    expect_index_output_contracts();
    expect_protocol_path_export_contracts();
    expect_flow_list_export_contracts();
    expect_combined_side_output_preflight_contracts();
    expect_preflight_fails_before_opening_input();
    expect_open_progress_helper_behavior();
    expect_live_progress_runtime_contracts();
    expect_progress_failure_and_partial_open_contracts();
}

}  // namespace pfl::tests
