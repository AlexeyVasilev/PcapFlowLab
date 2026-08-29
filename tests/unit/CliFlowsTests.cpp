#include <filesystem>
#include <fstream>
#include <numeric>
#include <string>
#include <string_view>
#include <vector>

#include "TestSupport.h"
#include "PcapTestUtils.h"
#include "app/frontend/FrontendSessionAdapter.h"
#include "app/session/AdvancedFlowFilterFormat.h"
#include "app/session/SessionFlowHelpers.h"
#include "cli/CliCommandSupport.h"
#include "cli/FlowsCommand.h"
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
    std::string field {};
    bool in_quotes = false;

    for (std::size_t index = 0U; index < line.size(); ++index) {
        const char ch = line[index];
        if (in_quotes) {
            if (ch == '"') {
                if (index + 1U < line.size() && line[index + 1U] == '"') {
                    field.push_back('"');
                    ++index;
                } else {
                    in_quotes = false;
                }
            } else {
                field.push_back(ch);
            }
            continue;
        }

        if (ch == '"') {
            in_quotes = true;
            continue;
        }

        if (ch == ',') {
            fields.push_back(field);
            field.clear();
            continue;
        }

        field.push_back(ch);
    }

    fields.push_back(field);
    return fields;
}

cli::CliInvocationResult invoke_cli(const std::vector<std::string>& args_storage) {
    std::vector<std::string_view> args {};
    args.reserve(args_storage.size());
    for (const auto& arg : args_storage) {
        args.push_back(arg);
    }
    return cli::process_cli_invocation(args);
}

cli::CliInvocationResult invoke_cli_with_environment(
    const std::vector<std::string>& args_storage,
    const cli::CliRuntimeEnvironment& environment
) {
    std::vector<std::string_view> args {};
    args.reserve(args_storage.size());
    for (const auto& arg : args_storage) {
        args.push_back(arg);
    }
    return cli::process_cli_invocation(args, environment);
}

session_detail::AdvancedFlowFilterSpec require_effective_advanced_filter_spec(const std::string_view text) {
    const auto parsed_filter = session_detail::parse_advanced_flow_filter_text(text);
    PFL_REQUIRE(parsed_filter.status == session_detail::AdvancedFlowFilterTextParseStatus::ok);
    return session_detail::make_effective_advanced_flow_filter_spec(parsed_filter.document);
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

std::vector<std::uint8_t> make_http_request_payload() {
    constexpr char request[] =
        "GET / HTTP/1.1\r\n"
        "Host: cli-flows.example\r\n"
        "User-Agent: PFL\r\n"
        "\r\n";
    return std::vector<std::uint8_t>(request, request + sizeof(request) - 1U);
}

std::vector<std::uint8_t> make_dns_query_payload() {
    std::vector<std::uint8_t> payload {};
    append_be16(payload, 0x1234);
    append_be16(payload, 0x0100);
    append_be16(payload, 1U);
    append_be16(payload, 0U);
    append_be16(payload, 0U);
    append_be16(payload, 0U);
    payload.push_back(3U);
    payload.insert(payload.end(), {'c', 'l', 'i'});
    payload.push_back(5U);
    payload.insert(payload.end(), {'f', 'l', 'o', 'w', 's'});
    payload.push_back(7U);
    payload.insert(payload.end(), {'e', 'x', 'a', 'm', 'p', 'l', 'e'});
    payload.push_back(0U);
    append_be16(payload, 1U);
    append_be16(payload, 1U);
    return payload;
}

std::filesystem::path build_cli_flows_capture_path() {
    std::vector<std::pair<std::uint32_t, std::vector<std::uint8_t>>> packets {};

    for (std::uint32_t packet_number = 0U; packet_number < 10U; ++packet_number) {
        packets.push_back({
            100U + packet_number * 10U,
            make_ethernet_ipv4_tcp_packet(
                ipv4(10, 0, 0, 30),
                ipv4(10, 0, 0, 40),
                43000,
                22
            )
        });
    }

    packets.push_back({
        300U,
        make_ethernet_ipv4_tcp_packet_with_bytes_payload(
            ipv4(10, 0, 0, 10),
            ipv4(10, 0, 0, 20),
            41000,
            80,
            make_http_request_payload(),
            0x18
        )
    });
    packets.push_back({
        400U,
        make_ethernet_ipv4_udp_packet_with_bytes_payload(
            ipv4(10, 0, 0, 11),
            ipv4(10, 0, 0, 21),
            53000,
            53,
            make_dns_query_payload()
        )
    });
    packets.push_back({
        500U,
        make_ethernet_ipv6_udp_with_hop_by_hop_packet(
            ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x31}),
            ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x32}),
            54000,
            54001
        )
    });

    return write_temp_pcap(
        "pfl_cli_flows_capture.pcap",
        make_classic_pcap(packets)
    );
}

std::filesystem::path build_many_flows_capture_path(const std::string& name, const std::size_t flow_count) {
    std::vector<std::pair<std::uint32_t, std::vector<std::uint8_t>>> packets {};
    packets.reserve(flow_count);
    for (std::size_t index = 0U; index < flow_count; ++index) {
        packets.push_back({
            static_cast<std::uint32_t>(100U + index * 10U),
            make_ethernet_ipv4_udp_packet(
                ipv4(10, 250, static_cast<std::uint8_t>(index / 200U), static_cast<std::uint8_t>(index % 200U + 1U)),
                ipv4(10, 251, static_cast<std::uint8_t>(index / 200U), static_cast<std::uint8_t>(index % 200U + 1U)),
                static_cast<std::uint16_t>(40000U + index),
                static_cast<std::uint16_t>(50000U + index)
            )
        });
    }

    return write_temp_pcap(name, make_classic_pcap(packets));
}

std::size_t count_rendered_flow_rows(const std::string_view text) {
    std::size_t count = 0U;
    std::size_t line_start = 0U;
    while (line_start < text.size()) {
        const auto line_end = text.find('\n', line_start);
        auto line = text.substr(
            line_start,
            line_end == std::string_view::npos ? text.size() - line_start : line_end - line_start
        );
        while (!line.empty() && line.front() == ' ') {
            line.remove_prefix(1U);
        }
        if (!line.empty() && line.front() >= '0' && line.front() <= '9') {
            ++count;
        }
        if (line_end == std::string_view::npos) {
            break;
        }
        line_start = line_end + 1U;
    }
    return count;
}

std::vector<std::size_t> extract_rendered_flow_numbers(const std::string_view text) {
    std::vector<std::size_t> numbers {};
    std::size_t line_start = 0U;
    while (line_start < text.size()) {
        const auto line_end = text.find('\n', line_start);
        auto line = text.substr(
            line_start,
            line_end == std::string_view::npos ? text.size() - line_start : line_end - line_start
        );
        while (!line.empty() && line.front() == ' ') {
            line.remove_prefix(1U);
        }

        std::size_t value = 0U;
        std::size_t digits = 0U;
        while (digits < line.size() && line[digits] >= '0' && line[digits] <= '9') {
            value = value * 10U + static_cast<std::size_t>(line[digits] - '0');
            ++digits;
        }
        if (digits > 0U) {
            numbers.push_back(value);
        }

        if (line_end == std::string_view::npos) {
            break;
        }
        line_start = line_end + 1U;
    }
    return numbers;
}

std::vector<std::size_t> one_based_numbers(std::span<const std::size_t> flow_indices) {
    std::vector<std::size_t> values {};
    values.reserve(flow_indices.size());
    for (const auto flow_index : flow_indices) {
        values.push_back(flow_index + 1U);
    }
    return values;
}

std::filesystem::path write_temp_advanced_filter_file(const std::string& filename, const std::string& text) {
    return write_temp_text_file(filename, text);
}

void expect_flows_help_and_parser_behavior() {
    {
        const std::vector<std::string> args {"flows", "-h"};
        const auto result = invoke_cli(args);
        PFL_EXPECT(result.handled);
        PFL_EXPECT(result.exit_code == 0);
        PFL_EXPECT(result.stderr_text.empty());
        PFL_EXPECT(contains_text(result.stdout_text, "PcapFlowLab CLI - flows"));
        PFL_EXPECT(contains_text(result.stdout_text, "pcap-flow-lab flows <input> [options]"));
        PFL_EXPECT(contains_text(result.stdout_text, "--flow-number <N>"));
        PFL_EXPECT(contains_text(result.stdout_text, "--flow-numbers <ranges>"));
        PFL_EXPECT(contains_text(result.stdout_text, "--adv-filter <path>"));
        PFL_EXPECT(contains_text(result.stdout_text, "--sort <number|protocol|service|endpoint-a|endpoint-b|packets|bytes>:<asc|desc>"));
        PFL_EXPECT(contains_text(result.stdout_text, "default preview of 25 rows"));
        PFL_EXPECT(contains_text(result.stdout_text, "--filter and --adv-filter are mutually exclusive"));
        PFL_EXPECT(contains_text(result.stdout_text, "Example range: 1-10,24,31-35"));
        PFL_EXPECT(!contains_text(result.stdout_text, "--source-capture"));
        PFL_EXPECT(!contains_text(result.stdout_text, "--format"));
        PFL_EXPECT(!contains_text(result.stdout_text, "--columns"));
        PFL_EXPECT(!contains_text(result.stdout_text, "\\--input"));
        PFL_EXPECT(!contains_text(result.stdout_text, "\\<input>"));
        PFL_EXPECT(has_no_tabs_or_trailing_spaces(result.stdout_text));
        PFL_EXPECT(has_no_ansi_escape_sequences(result.stdout_text));
    }

    {
        const auto canonical = invoke_cli({"flows", "--help"});
        const auto alias = invoke_cli({"flow", "--help"});
        PFL_EXPECT(canonical.handled);
        PFL_EXPECT(alias.handled);
        PFL_EXPECT(canonical.exit_code == 0);
        PFL_EXPECT(alias.exit_code == 0);
        PFL_EXPECT(alias.stdout_text == canonical.stdout_text);
        PFL_EXPECT(alias.stderr_text == canonical.stderr_text);
        PFL_EXPECT(contains_text(alias.stdout_text, "pcap-flow-lab flows <input> [options]"));
    }

    {
        const auto output_path = std::filesystem::temp_directory_path() / "pfl_cli_flows_help_should_not_exist.csv";
        std::filesystem::remove(output_path);
        const std::vector<std::string> args {
            "flows",
            "--help",
            "--unknown",
            "--out-flows-list",
            output_path.string(),
        };
        const auto result = invoke_cli(args);
        PFL_EXPECT(result.handled);
        PFL_EXPECT(result.exit_code == 0);
        PFL_EXPECT(result.stderr_text.empty());
        PFL_EXPECT(contains_text(result.stdout_text, "PcapFlowLab CLI - flows"));
        PFL_EXPECT(!std::filesystem::exists(output_path));
    }

    {
        const std::vector<std::string_view> args {"capture.pcap"};
        const auto parse_result = cli::parse_flows_command_arguments(args);
        PFL_REQUIRE(parse_result.ok);
        PFL_REQUIRE(parse_result.options.has_value());
        PFL_EXPECT(parse_result.options->input_path == std::filesystem::path("capture.pcap"));
    }

    {
        const std::vector<std::string_view> args {"--input", "capture.pcap"};
        const auto parse_result = cli::parse_flows_command_arguments(args);
        PFL_REQUIRE(parse_result.ok);
        PFL_REQUIRE(parse_result.options.has_value());
        PFL_EXPECT(parse_result.options->input_path == std::filesystem::path("capture.pcap"));
    }

    {
        const std::vector<std::string_view> args {"capture.pcap", "--input", "capture.pcap"};
        const auto parse_result = cli::parse_flows_command_arguments(args);
        PFL_EXPECT(!parse_result.ok);
        PFL_EXPECT(contains_text(parse_result.error_text, "mutually exclusive input forms"));
    }

    {
        const std::vector<std::string_view> args {};
        const auto parse_result = cli::parse_flows_command_arguments(args);
        PFL_EXPECT(!parse_result.ok);
        PFL_EXPECT(contains_text(parse_result.error_text, "requires an input path"));
    }

    {
        const std::vector<std::string_view> args {"capture.pcap", "--unknown"};
        const auto parse_result = cli::parse_flows_command_arguments(args);
        PFL_EXPECT(!parse_result.ok);
        PFL_EXPECT(contains_text(parse_result.error_text, "Unknown flows option"));
    }

    {
        const std::vector<std::string_view> args {"capture.pcap", "--filter", "TLS", "--filter", "HTTP"};
        const auto parse_result = cli::parse_flows_command_arguments(args);
        PFL_EXPECT(!parse_result.ok);
        PFL_EXPECT(contains_text(parse_result.error_text, "Duplicate --filter"));
    }

    {
        const std::vector<std::string_view> args {"capture.pcap", "--adv-filter", "rules.filter"};
        const auto parse_result = cli::parse_flows_command_arguments(args);
        PFL_REQUIRE(parse_result.ok);
        PFL_REQUIRE(parse_result.options.has_value());
        PFL_EXPECT(
            parse_result.options->advanced_filter_path
            == std::optional<std::filesystem::path> {std::filesystem::path {"rules.filter"}}
        );
    }

    {
        const std::vector<std::string_view> args {"capture.pcap", "--adv-filter", "rules.filter", "--filter", "TLS"};
        const auto parse_result = cli::parse_flows_command_arguments(args);
        PFL_EXPECT(!parse_result.ok);
        PFL_EXPECT(contains_text(parse_result.error_text, "mutually exclusive"));
    }

    {
        const std::vector<std::string_view> args {"capture.pcap", "--filter", "TLS", "--adv-filter", "rules.filter"};
        const auto parse_result = cli::parse_flows_command_arguments(args);
        PFL_EXPECT(!parse_result.ok);
        PFL_EXPECT(contains_text(parse_result.error_text, "mutually exclusive"));
    }

    {
        const std::vector<std::string_view> args {"capture.pcap", "--flow-number", "42"};
        const auto parse_result = cli::parse_flows_command_arguments(args);
        PFL_REQUIRE(parse_result.ok);
        PFL_REQUIRE(parse_result.options.has_value());
        PFL_REQUIRE(parse_result.options->selected_flow_number_ranges.has_value());
        const auto expected = std::vector<cli::CliFlowNumberRange> {{.first = 42U, .last = 42U}};
        PFL_EXPECT(*parse_result.options->selected_flow_number_ranges == expected);
    }

    {
        const std::vector<std::string_view> args {"capture.pcap", "--flow-number", "0"};
        const auto parse_result = cli::parse_flows_command_arguments(args);
        PFL_EXPECT(!parse_result.ok);
        PFL_EXPECT(contains_text(parse_result.error_text, "Invalid --flow-number"));
    }

    {
        const std::vector<std::string_view> args {"capture.pcap", "--flow-numbers", "1,1,2-3,2"};
        const auto parse_result = cli::parse_flows_command_arguments(args);
        PFL_REQUIRE(parse_result.ok);
        PFL_REQUIRE(parse_result.options.has_value());
        PFL_REQUIRE(parse_result.options->selected_flow_number_ranges.has_value());
        const auto expected = std::vector<cli::CliFlowNumberRange> {
            {.first = 1U, .last = 1U},
            {.first = 1U, .last = 1U},
            {.first = 2U, .last = 3U},
            {.first = 2U, .last = 2U},
        };
        PFL_EXPECT(*parse_result.options->selected_flow_number_ranges == expected);
    }

    {
        const std::vector<std::string_view> args {"capture.pcap", "--flow-numbers", "10-5"};
        const auto parse_result = cli::parse_flows_command_arguments(args);
        PFL_EXPECT(!parse_result.ok);
        PFL_EXPECT(contains_text(parse_result.error_text, "Invalid --flow-numbers"));
    }

    {
        const std::vector<std::string_view> args {"capture.pcap", "--flow-numbers", "1-2-3"};
        const auto parse_result = cli::parse_flows_command_arguments(args);
        PFL_EXPECT(!parse_result.ok);
        PFL_EXPECT(contains_text(parse_result.error_text, "Invalid --flow-numbers"));
    }

    {
        const std::vector<std::string_view> args {"capture.pcap", "--flow-numbers", "18446744073709551616"};
        const auto parse_result = cli::parse_flows_command_arguments(args);
        PFL_EXPECT(!parse_result.ok);
        PFL_EXPECT(contains_text(parse_result.error_text, "Invalid --flow-numbers"));
    }

    {
        const std::vector<std::string_view> args {"capture.pcap", "--flow-number", "1", "--flow-numbers", "2-3"};
        const auto parse_result = cli::parse_flows_command_arguments(args);
        PFL_EXPECT(!parse_result.ok);
        PFL_EXPECT(contains_text(parse_result.error_text, "mutually exclusive"));
    }

    for (const auto sort_text : {
        "number:asc",
        "protocol:desc",
        "service:asc",
        "endpoint-a:desc",
        "endpoint-b:asc",
        "packets:desc",
        "bytes:asc",
    }) {
        const std::vector<std::string_view> args {"capture.pcap", "--sort", sort_text};
        const auto parse_result = cli::parse_flows_command_arguments(args);
        PFL_REQUIRE(parse_result.ok);
        PFL_REQUIRE(parse_result.options.has_value());
        PFL_EXPECT(parse_result.options->sort.has_value());
    }

    for (const auto invalid_sort_text : {
        "bad:desc",
        "packets",
        "packets:sideways",
    }) {
        const std::vector<std::string_view> args {"capture.pcap", "--sort", invalid_sort_text};
        const auto parse_result = cli::parse_flows_command_arguments(args);
        PFL_EXPECT(!parse_result.ok);
        PFL_EXPECT(contains_text(parse_result.error_text, "Invalid --sort value"));
    }

    {
        const std::vector<std::string_view> args {"capture.pcap", "--limit", "50"};
        const auto parse_result = cli::parse_flows_command_arguments(args);
        PFL_REQUIRE(parse_result.ok);
        PFL_REQUIRE(parse_result.options.has_value());
        PFL_EXPECT(parse_result.options->limit == std::optional<std::size_t> {50U});
    }

    for (const auto invalid_limit_text : {"0", "-1"}) {
        const std::vector<std::string_view> args {"capture.pcap", "--limit", invalid_limit_text};
        const auto parse_result = cli::parse_flows_command_arguments(args);
        PFL_EXPECT(!parse_result.ok);
        PFL_EXPECT(contains_text(parse_result.error_text, "Invalid --limit"));
    }

    {
        const std::vector<std::string_view> args {"capture.pcap", "--progress", "on"};
        const auto parse_result = cli::parse_flows_command_arguments(args);
        PFL_REQUIRE(parse_result.ok);
        PFL_REQUIRE(parse_result.options.has_value());
        PFL_EXPECT(parse_result.options->progress_mode == cli::CliProgressMode::on);
    }

    {
        const std::vector<std::string_view> args {"capture.pcap", "--progress", "auto"};
        const auto parse_result = cli::parse_flows_command_arguments(args);
        PFL_REQUIRE(parse_result.ok);
        PFL_REQUIRE(parse_result.options.has_value());
        PFL_EXPECT(parse_result.options->progress_mode == cli::CliProgressMode::auto_mode);
    }

    {
        const std::vector<std::string_view> args {"capture.pcap", "--progress", "off"};
        const auto parse_result = cli::parse_flows_command_arguments(args);
        PFL_REQUIRE(parse_result.ok);
        PFL_REQUIRE(parse_result.options.has_value());
        PFL_EXPECT(parse_result.options->progress_mode == cli::CliProgressMode::off);
    }

    for (const auto unsupported : {"--source-capture", "--format", "--columns"}) {
        const std::vector<std::string_view> args {"capture.pcap", unsupported, "value"};
        const auto parse_result = cli::parse_flows_command_arguments(args);
        PFL_EXPECT(!parse_result.ok);
        PFL_EXPECT(contains_text(parse_result.error_text, "not implemented for flows"));
    }

    {
        const std::vector<std::string> args {"flows"};
        const auto result = invoke_cli(args);
        PFL_EXPECT(result.handled);
        PFL_EXPECT(result.exit_code == 1);
        PFL_EXPECT(result.stdout_text.empty());
        PFL_EXPECT(contains_text(result.stderr_text, "flows requires an input path"));
        PFL_EXPECT(contains_text(result.stderr_text, "PcapFlowLab CLI - flows"));
    }

    {
        const std::vector<std::string> args {"flows", "capture.pcap", "--unknown"};
        const auto result = invoke_cli(args);
        PFL_EXPECT(result.handled);
        PFL_EXPECT(result.exit_code == 1);
        PFL_EXPECT(result.stdout_text.empty());
        PFL_EXPECT(contains_text(result.stderr_text, "Unknown flows option"));
        PFL_EXPECT(contains_text(result.stderr_text, "PcapFlowLab CLI - flows"));
    }

    {
        const std::vector<std::string> args {"flows", "capture.pcap", "--flow-number", "0"};
        const auto result = invoke_cli(args);
        PFL_EXPECT(result.handled);
        PFL_EXPECT(result.exit_code == 1);
        PFL_EXPECT(result.stdout_text.empty());
        PFL_EXPECT(contains_text(result.stderr_text, "Invalid --flow-number"));
        PFL_EXPECT(contains_text(result.stderr_text, "PcapFlowLab CLI - flows"));
    }
}

void expect_shared_cli_flow_selector_helpers() {
    {
        PFL_EXPECT(cli::parse_cli_positive_size("1") == std::optional<std::size_t> {1U});
        PFL_EXPECT(cli::parse_cli_positive_size("50") == std::optional<std::size_t> {50U});
        PFL_EXPECT(!cli::parse_cli_positive_size("0").has_value());
        PFL_EXPECT(!cli::parse_cli_positive_size("-1").has_value());
        PFL_EXPECT(!cli::parse_cli_positive_size("1.5").has_value());
        PFL_EXPECT(!cli::parse_cli_positive_size("abc").has_value());
        PFL_EXPECT(!cli::parse_cli_positive_size("18446744073709551616").has_value());
    }

    {
        PFL_EXPECT(cli::parse_cli_flow_number("1") == std::optional<std::size_t> {0U});
        PFL_EXPECT(cli::parse_cli_flow_number("42") == std::optional<std::size_t> {41U});
        PFL_EXPECT(!cli::parse_cli_flow_number("0").has_value());
        PFL_EXPECT(!cli::parse_cli_flow_number("-1").has_value());
        PFL_EXPECT(!cli::parse_cli_flow_number("abc").has_value());
    }

    {
        const auto single = cli::parse_cli_flow_numbers("42");
        PFL_REQUIRE(single.has_value());
        const auto expected = std::vector<cli::CliFlowNumberRange> {{.first = 42U, .last = 42U}};
        PFL_EXPECT(*single == expected);

        const auto ranges = cli::parse_cli_flow_numbers("1-3,5,7-8");
        PFL_REQUIRE(ranges.has_value());
        const auto expected_ranges = std::vector<cli::CliFlowNumberRange> {
            {.first = 1U, .last = 3U},
            {.first = 5U, .last = 5U},
            {.first = 7U, .last = 8U},
        };
        PFL_EXPECT(*ranges == expected_ranges);

        const auto deduped = cli::parse_cli_flow_numbers("1,1,2-3,2");
        PFL_REQUIRE(deduped.has_value());
        const auto expected_deduped = std::vector<cli::CliFlowNumberRange> {
            {.first = 1U, .last = 1U},
            {.first = 1U, .last = 1U},
            {.first = 2U, .last = 3U},
            {.first = 2U, .last = 2U},
        };
        PFL_EXPECT(*deduped == expected_deduped);

        const auto resolved_single = cli::resolve_cli_flow_numbers(
            std::span<const cli::CliFlowNumberRange>(single->data(), single->size()),
            100U
        );
        PFL_EXPECT(resolved_single.ok);
        PFL_EXPECT((resolved_single.flow_indices == std::vector<std::size_t> {41U}));

        const auto resolved_ranges = cli::resolve_cli_flow_numbers(
            std::span<const cli::CliFlowNumberRange>(ranges->data(), ranges->size()),
            8U
        );
        PFL_EXPECT(resolved_ranges.ok);
        PFL_EXPECT((resolved_ranges.flow_indices == std::vector<std::size_t> {0U, 1U, 2U, 4U, 6U, 7U}));

        const auto resolved_deduped = cli::resolve_cli_flow_numbers(
            std::span<const cli::CliFlowNumberRange>(deduped->data(), deduped->size()),
            4U
        );
        PFL_EXPECT(resolved_deduped.ok);
        PFL_EXPECT((resolved_deduped.flow_indices == std::vector<std::size_t> {0U, 1U, 2U}));

        const auto huge = cli::parse_cli_flow_numbers("1-1000000000000");
        PFL_REQUIRE(huge.has_value());
        const auto huge_resolved = cli::resolve_cli_flow_numbers(
            std::span<const cli::CliFlowNumberRange>(huge->data(), huge->size()),
            4U
        );
        PFL_EXPECT(!huge_resolved.ok);
        PFL_EXPECT(huge_resolved.invalid_flow_index == std::optional<std::size_t> {4U});

        PFL_EXPECT(!cli::parse_cli_flow_numbers("0").has_value());
        PFL_EXPECT(!cli::parse_cli_flow_numbers("-1").has_value());
        PFL_EXPECT(!cli::parse_cli_flow_numbers("10-5").has_value());
        PFL_EXPECT(!cli::parse_cli_flow_numbers("1-2-3").has_value());
        PFL_EXPECT(!cli::parse_cli_flow_numbers("1,,2").has_value());
        PFL_EXPECT(!cli::parse_cli_flow_numbers("18446744073709551616").has_value());
    }
}

void expect_flows_runtime_behavior() {
    const auto capture_path = build_cli_flows_capture_path();

    {
        const std::vector<std::string> args {
            "flows",
            fixture_path("parsing/mdns/01_mdns_ipv4_ptr_query.pcap").string(),
            "--progress",
            "off",
        };
        const auto result = invoke_cli(args);
        PFL_EXPECT(result.handled);
        PFL_EXPECT(result.exit_code == 0);
        PFL_EXPECT(contains_text(result.stdout_text, "mDNS"));
        PFL_EXPECT(contains_text(result.stdout_text, "_demo-service._tcp.local"));
        PFL_EXPECT(!contains_text(result.stdout_text, "MDNS"));
    }

    FrontendSessionAdapter adapter {};
    PFL_REQUIRE(adapter.open_capture(capture_path).opened);
    const auto baseline_query = adapter.query_flows(session_detail::FlowQuery {});
    PFL_REQUIRE(baseline_query.status == session_detail::FlowQueryStatus::ok);
    PFL_REQUIRE(baseline_query.ordered_flow_indices.size() == 4U);
    PFL_EXPECT(baseline_query.result_count_before_limit == 4U);
    const auto advanced_filter_path = write_temp_advanced_filter_file(
        "pfl_cli_flows_http_adv.filter",
        "format_version = 3\n"
        "flow_protocol.include = tcp\n"
        "port.b.include = 80\n"
    );

    {
        const std::vector<std::string> args {"flows", capture_path.string(), "--flow-numbers", "1-1000000000000"};
        const auto result = invoke_cli(args);
        PFL_EXPECT(result.handled);
        PFL_EXPECT(result.exit_code == 1);
        PFL_EXPECT(result.stdout_text.empty());
        PFL_EXPECT(contains_text(result.stderr_text, "outside the available canonical flow range"));
    }

    {
        const auto canonical = invoke_cli({
            "flows",
            capture_path.string(),
            "--filter",
            "10.0.0.10",
            "--sort",
            "bytes:desc",
            "--limit",
            "1",
            "--progress",
            "off",
        });
        const auto alias = invoke_cli({
            "flow",
            capture_path.string(),
            "--filter",
            "10.0.0.10",
            "--sort",
            "bytes:desc",
            "--limit",
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
        const std::vector<std::string> args {"flows", capture_path.string(), "--progress", "off"};
        const auto result = invoke_cli(args);
        PFL_EXPECT(result.handled);
        PFL_EXPECT(result.exit_code == 0);
        PFL_EXPECT(result.stderr_text.empty());
        PFL_EXPECT(contains_text(result.stdout_text, "Flows"));
        PFL_EXPECT(contains_text(result.stdout_text, "No."));
        PFL_EXPECT(contains_text(result.stdout_text, "Endpoint A"));
        PFL_EXPECT(contains_text(result.stdout_text, "Endpoint B"));
        PFL_EXPECT(contains_text(result.stdout_text, "Protocol"));
        PFL_EXPECT(contains_text(result.stdout_text, "Detected Protocol"));
        PFL_EXPECT(contains_text(result.stdout_text, "Service"));
        PFL_EXPECT(contains_text(result.stdout_text, "Path"));
        PFL_EXPECT(contains_text(result.stdout_text, "Packets"));
        PFL_EXPECT(contains_text(result.stdout_text, "Original Bytes"));
        PFL_EXPECT(!contains_text(result.stdout_text, "Family"));
        PFL_EXPECT(!contains_text(result.stdout_text, "Captured Bytes"));
        PFL_EXPECT(!contains_text(result.stdout_text, "Fragment"));
        PFL_EXPECT(count_rendered_flow_rows(result.stdout_text) == baseline_query.ordered_flow_indices.size());
        PFL_EXPECT(extract_rendered_flow_numbers(result.stdout_text) == one_based_numbers(baseline_query.ordered_flow_indices));
        PFL_EXPECT(has_no_tabs_or_trailing_spaces(result.stdout_text));
        PFL_EXPECT(has_no_ansi_escape_sequences(result.stdout_text));

        bool checked_display_row = false;
        for (const auto flow_index : baseline_query.ordered_flow_indices) {
            const auto row = adapter.flow_row(flow_index);
            PFL_REQUIRE(row.has_value());
            PFL_EXPECT(contains_text(result.stdout_text, row->endpoint_a));
            PFL_EXPECT(contains_text(result.stdout_text, row->endpoint_b));
            PFL_EXPECT(contains_text(result.stdout_text, row->protocol_text));
            PFL_EXPECT(contains_text(result.stdout_text, adapter.protocol_path_compact_text(row->protocol_path_id)));
            if (!row->protocol_hint.empty()) {
                PFL_EXPECT(contains_text(
                    result.stdout_text,
                    session_detail::format_flow_protocol_hint_display(row->protocol_hint)
                ));
                checked_display_row = true;
            }
            if (!row->service_hint.empty()) {
                PFL_EXPECT(contains_text(result.stdout_text, row->service_hint));
                checked_display_row = true;
            }
        }
        PFL_EXPECT(checked_display_row);
    }

    {
        const auto target_row = adapter.flow_row(baseline_query.ordered_flow_indices[1]);
        PFL_REQUIRE(target_row.has_value());
        session_detail::FlowQuery query {};
        query.text_filter = target_row->endpoint_a;
        const auto expected = adapter.query_flows(query);
        PFL_REQUIRE(expected.status == session_detail::FlowQueryStatus::ok);
        PFL_EXPECT(expected.result_count_before_limit == 1U);

        const std::vector<std::string> args {"flows", capture_path.string(), "--filter", target_row->endpoint_a};
        const auto result = invoke_cli(args);
        PFL_EXPECT(result.exit_code == 0);
        PFL_EXPECT(extract_rendered_flow_numbers(result.stdout_text) == one_based_numbers(expected.ordered_flow_indices));
    }

    {
        const auto expected = adapter.query_advanced_flows(
            require_effective_advanced_filter_spec(
                "format_version = 3\n"
                "flow_protocol.include = tcp\n"
                "port.b.include = 80\n"
            ),
            std::nullopt,
            std::nullopt,
            std::nullopt
        );
        PFL_REQUIRE(expected.status == FrontendAdvancedFlowQueryStatus::ok);
        PFL_EXPECT(expected.result_count_before_limit == 1U);

        const std::vector<std::string> args {
            "flows",
            capture_path.string(),
            "--adv-filter",
            advanced_filter_path.string(),
        };
        const auto result = invoke_cli(args);
        PFL_EXPECT(result.exit_code == 0);
        PFL_EXPECT(extract_rendered_flow_numbers(result.stdout_text) == one_based_numbers(expected.ordered_flow_indices));
    }

    {
        const auto disabled_section_filter_path = write_temp_advanced_filter_file(
            "pfl_cli_flows_disabled_protocol_section.filter",
            "format_version = 3\n"
            "section.flow_protocol.enabled = false\n"
            "flow_protocol.include = tcp\n"
            "address_family.include = ipv6\n"
        );
        const auto expected = adapter.query_advanced_flows(
            require_effective_advanced_filter_spec(
                "format_version = 3\n"
                "section.flow_protocol.enabled = false\n"
                "flow_protocol.include = tcp\n"
                "address_family.include = ipv6\n"
            ),
            std::nullopt,
            std::nullopt,
            std::nullopt
        );
        PFL_REQUIRE(expected.status == FrontendAdvancedFlowQueryStatus::ok);
        PFL_EXPECT(expected.result_count_before_limit == 1U);
        PFL_REQUIRE(expected.ordered_flow_indices.size() == 1U);

        const std::vector<std::string> args {
            "flows",
            capture_path.string(),
            "--adv-filter",
            disabled_section_filter_path.string(),
        };
        const auto result = invoke_cli(args);
        PFL_EXPECT(result.exit_code == 0);
        PFL_EXPECT(extract_rendered_flow_numbers(result.stdout_text) == one_based_numbers(expected.ordered_flow_indices));
    }

    {
        const auto address_family_filter_path = write_temp_advanced_filter_file(
            "pfl_cli_flows_address_family.filter",
            "format_version = 3\n"
            "address_family.include = ipv6\n"
        );
        const auto expected = adapter.query_advanced_flows(
            require_effective_advanced_filter_spec(
                "format_version = 3\n"
                "address_family.include = ipv6\n"
            ),
            std::nullopt,
            std::nullopt,
            std::nullopt
        );
        PFL_REQUIRE(expected.status == FrontendAdvancedFlowQueryStatus::ok);
        PFL_EXPECT(expected.result_count_before_limit == 1U);

        const std::vector<std::string> args {
            "flows",
            capture_path.string(),
            "--adv-filter",
            address_family_filter_path.string(),
        };
        const auto result = invoke_cli(args);
        PFL_EXPECT(result.exit_code == 0);
        PFL_EXPECT(extract_rendered_flow_numbers(result.stdout_text) == one_based_numbers(expected.ordered_flow_indices));
    }

    {
        const auto expected = adapter.query_advanced_flows(
            require_effective_advanced_filter_spec(
                "format_version = 3\n"
                "flow_protocol.include = tcp\n"
            ),
            std::optional<std::vector<std::size_t>> {std::vector<std::size_t> {baseline_query.ordered_flow_indices[2]}},
            std::nullopt,
            std::nullopt
        );
        PFL_REQUIRE(expected.status == FrontendAdvancedFlowQueryStatus::ok);
        PFL_EXPECT(expected.result_count_before_limit == 1U);

        const auto scoped_filter_path = write_temp_advanced_filter_file(
            "pfl_cli_flows_scoped_adv.filter",
            "format_version = 3\n"
            "flow_protocol.include = tcp\n"
        );
        const std::vector<std::string> args {
            "flows",
            capture_path.string(),
            "--adv-filter",
            scoped_filter_path.string(),
            "--flow-number",
            std::to_string(baseline_query.ordered_flow_indices[2] + 1U),
        };
        const auto result = invoke_cli(args);
        PFL_EXPECT(result.exit_code == 0);
        PFL_EXPECT(extract_rendered_flow_numbers(result.stdout_text) == one_based_numbers(expected.ordered_flow_indices));
    }

    {
        session_detail::FlowQuery query {};
        query.sort = session_detail::FlowQuerySortSpec {
            .key = session_detail::FlowQuerySortKey::packets,
            .direction = session_detail::FlowQuerySortDirection::descending,
        };
        query.limit = 2U;
        const auto expected = adapter.query_flows(query);
        PFL_REQUIRE(expected.status == session_detail::FlowQueryStatus::ok);
        PFL_EXPECT(expected.result_count_before_limit == 4U);

        const std::vector<std::string> args {
            "flows",
            capture_path.string(),
            "--sort",
            "packets:desc",
            "--limit",
            "2",
        };
        const auto result = invoke_cli(args);
        PFL_EXPECT(result.exit_code == 0);
        PFL_EXPECT(extract_rendered_flow_numbers(result.stdout_text) == one_based_numbers(expected.ordered_flow_indices));
        PFL_EXPECT(contains_text(result.stdout_text, "Showing 2 of 4 flows."));
        PFL_EXPECT(!contains_text(result.stdout_text, "Use --limit <N> to show more rows"));
    }

    {
        const auto selected_flow_number =
            session_detail::format_statistics_count_value(baseline_query.ordered_flow_indices[2] + 1U);
        const std::vector<std::string> args {"flows", capture_path.string(), "--flow-number", std::to_string(baseline_query.ordered_flow_indices[2] + 1U)};
        const auto result = invoke_cli(args);
        PFL_EXPECT(result.exit_code == 0);
        const auto expected = std::vector<std::size_t> {baseline_query.ordered_flow_indices[2] + 1U};
        PFL_EXPECT(extract_rendered_flow_numbers(result.stdout_text) == expected);
        PFL_EXPECT(contains_text(result.stdout_text, selected_flow_number));
    }

    {
        const std::vector<std::string> args {"flows", capture_path.string(), "--flow-numbers", "1-2,2,4"};
        const auto result = invoke_cli(args);
        PFL_EXPECT(result.exit_code == 0);
        const auto expected = std::vector<std::size_t> {1U, 2U, 4U};
        PFL_EXPECT(extract_rendered_flow_numbers(result.stdout_text) == expected);
    }

    {
        const std::vector<std::string> args {"flows", capture_path.string(), "--filter", "no-such-flow"};
        const auto result = invoke_cli(args);
        PFL_EXPECT(result.exit_code == 0);
        PFL_EXPECT(contains_text(result.stdout_text, "No matching flows."));
        PFL_EXPECT(count_rendered_flow_rows(result.stdout_text) == 0U);
        PFL_EXPECT(!contains_text(result.stdout_text, "Showing 0 of 0 flows."));
    }

    {
        const std::vector<std::string> args {"flows", capture_path.string(), "--flow-number", "999999"};
        const auto result = invoke_cli(args);
        PFL_EXPECT(result.handled);
        PFL_EXPECT(result.exit_code == 1);
        PFL_EXPECT(result.stdout_text.empty());
        PFL_EXPECT(contains_text(result.stderr_text, "Requested flow number is outside the available canonical flow range"));
        PFL_EXPECT(!contains_text(result.stderr_text, "PcapFlowLab CLI - flows"));
    }

    {
        const auto invalid_filter_path = write_temp_advanced_filter_file(
            "pfl_cli_flows_invalid_tls_token.filter",
            "format_version = 3\n"
            "tls_version.include = tls9_9\n"
        );
        const std::vector<std::string> args {
            "flows",
            "definitely_missing_capture.pcap",
            "--adv-filter",
            invalid_filter_path.string(),
        };
        const auto result = invoke_cli_with_environment(
            args,
            cli::CliRuntimeEnvironment {
                .stderr_is_terminal = false,
            }
        );
        PFL_EXPECT(result.handled);
        PFL_EXPECT(result.exit_code == 1);
        PFL_EXPECT(result.stdout_text.empty());
        PFL_EXPECT(contains_text(result.stderr_text, "Invalid advanced flow filter file:"));
        PFL_EXPECT(contains_text(result.stderr_text, "Unknown TLS version token"));
        PFL_EXPECT(!contains_text(result.stderr_text, "Failed to open input:"));
    }

    {
        const auto invalid_filter_path = write_temp_advanced_filter_file(
            "pfl_cli_flows_invalid_protocol_token.filter",
            "format_version = 3\n"
            "flow_protocol.include = tcpish\n"
        );
        const std::vector<std::string> args {
            "flows",
            "definitely_missing_capture.pcap",
            "--adv-filter",
            invalid_filter_path.string(),
        };
        const auto result = invoke_cli(args);
        PFL_EXPECT(result.handled);
        PFL_EXPECT(result.exit_code == 1);
        PFL_EXPECT(result.stdout_text.empty());
        PFL_EXPECT(contains_text(result.stderr_text, "Invalid advanced flow filter file:"));
        PFL_EXPECT(contains_text(result.stderr_text, "Unknown flow protocol token"));
        PFL_EXPECT(!contains_text(result.stderr_text, "Failed to open input:"));
    }

    {
        const auto invalid_filter_path = write_temp_advanced_filter_file(
            "pfl_cli_flows_bad_version.filter",
            "format_version = 99\n"
        );
        const std::vector<std::string> args {
            "flows",
            "definitely_missing_capture.pcap",
            "--adv-filter",
            invalid_filter_path.string(),
        };
        const auto result = invoke_cli(args);
        PFL_EXPECT(result.handled);
        PFL_EXPECT(result.exit_code == 1);
        PFL_EXPECT(result.stdout_text.empty());
        PFL_EXPECT(contains_text(result.stderr_text, "Invalid advanced flow filter file:"));
        PFL_EXPECT(contains_text(result.stderr_text, "Only format_version = 3 is currently supported."));
        PFL_EXPECT(!contains_text(result.stderr_text, "Failed to open input:"));
    }

    {
        const auto oversized_filter_path = write_temp_text_file(
            "pfl_cli_flows_oversized.filter",
            std::string(session_detail::kAdvancedFlowFilterMaxFileBytes + 1U, 'a')
        );
        const std::vector<std::string> args {
            "flows",
            "definitely_missing_capture.pcap",
            "--adv-filter",
            oversized_filter_path.string(),
        };
        const auto result = invoke_cli(args);
        PFL_EXPECT(result.handled);
        PFL_EXPECT(result.exit_code == 1);
        PFL_EXPECT(result.stdout_text.empty());
        PFL_EXPECT(contains_text(result.stderr_text, "Advanced filter file is too large:"));
        PFL_EXPECT(contains_text(result.stderr_text, "(maximum 1 MiB)."));
        PFL_EXPECT(!contains_text(result.stderr_text, "Invalid advanced flow filter file:"));
        PFL_EXPECT(!contains_text(result.stderr_text, "Failed to open input:"));
    }

    {
        const auto compile_invalid_filter_path = write_temp_advanced_filter_file(
            "pfl_cli_flows_compile_invalid.filter",
            "format_version = 3\n"
            "service.contains.ci.include = \"\"\n"
        );
        const std::vector<std::string> args {
            "flows",
            "definitely_missing_capture.pcap",
            "--adv-filter",
            compile_invalid_filter_path.string(),
        };
        const auto result = invoke_cli(args);
        PFL_EXPECT(result.handled);
        PFL_EXPECT(result.exit_code == 1);
        PFL_EXPECT(result.stdout_text.empty());
        PFL_EXPECT(contains_text(result.stderr_text, "Failed to open input:"));
        PFL_EXPECT(!contains_text(result.stderr_text, "Advanced flow filter is not valid for this capture or index:"));
    }

    {
        const auto compile_invalid_filter_path = write_temp_advanced_filter_file(
            "pfl_cli_flows_compile_invalid_real_capture.filter",
            "format_version = 3\n"
            "service.contains.ci.include = \"\"\n"
        );
        const std::vector<std::string> args {
            "flows",
            capture_path.string(),
            "--adv-filter",
            compile_invalid_filter_path.string(),
        };
        const auto result = invoke_cli(args);
        PFL_EXPECT(result.handled);
        PFL_EXPECT(result.exit_code == 1);
        PFL_EXPECT(result.stdout_text.empty());
        PFL_EXPECT(contains_text(result.stderr_text, "Advanced flow filter is not valid for this capture or index:"));
        PFL_EXPECT(!contains_text(result.stderr_text, "Invalid advanced flow filter file:"));
    }
}

void expect_preview_and_csv_behavior() {
    const auto preview_capture_path = build_many_flows_capture_path("pfl_cli_flows_preview.pcap", 30U);
    const auto filtered_preview_capture_path = build_many_flows_capture_path("pfl_cli_flows_filtered_preview.pcap", 70U);

    {
        const std::vector<std::string> args {"flows", preview_capture_path.string()};
        const auto result = invoke_cli(args);
        PFL_EXPECT(result.exit_code == 0);
        PFL_EXPECT(count_rendered_flow_rows(result.stdout_text) == 25U);
        PFL_EXPECT(contains_text(result.stdout_text, "Showing 25 of 30 flows."));
        PFL_EXPECT(contains_text(result.stdout_text, "--out-flows-list <path>"));

        std::vector<std::size_t> expected_numbers(25U);
        std::iota(expected_numbers.begin(), expected_numbers.end(), 1U);
        PFL_EXPECT(extract_rendered_flow_numbers(result.stdout_text) == expected_numbers);
    }

    {
        const std::vector<std::string> args {"flows", preview_capture_path.string(), "--limit", "30"};
        const auto result = invoke_cli(args);
        PFL_EXPECT(result.exit_code == 0);
        PFL_EXPECT(count_rendered_flow_rows(result.stdout_text) == 30U);
        PFL_EXPECT(contains_text(result.stdout_text, "Showing 30 of 30 flows."));
        PFL_EXPECT(!contains_text(result.stdout_text, "Use --limit <N> to show more rows"));
    }

    {
        const auto output_path = std::filesystem::temp_directory_path() / "pfl_cli_flows_preview_all.csv";
        std::filesystem::remove(output_path);

        const std::vector<std::string> args {
            "flows",
            preview_capture_path.string(),
            "--out-flows-list",
            output_path.string(),
        };
        const auto result = invoke_cli(args);
        PFL_EXPECT(result.exit_code == 0);
        PFL_EXPECT(count_rendered_flow_rows(result.stdout_text) == 25U);
        PFL_EXPECT(contains_text(result.stdout_text, "Showing 25 of 30 flows."));
        PFL_EXPECT(contains_text(result.stdout_text, "Use --limit <N> to show more rows or --out-flows-list <path> to export the result."));

        const std::vector<std::string> baseline_args {"flows", preview_capture_path.string()};
        const auto baseline_result = invoke_cli(baseline_args);
        PFL_EXPECT(baseline_result.exit_code == 0);
        PFL_EXPECT(baseline_result.stdout_text == result.stdout_text);
        PFL_EXPECT(contains_text(result.stderr_text, "Flows list written to:"));

        const auto csv_lines = read_text_file_lines(output_path);
        PFL_REQUIRE(csv_lines.size() == 31U);
        const auto first_row = split_csv_line(csv_lines[1]);
        const auto last_row = split_csv_line(csv_lines.back());
        PFL_REQUIRE(first_row.size() == 16U);
        PFL_REQUIRE(last_row.size() == 16U);
        PFL_EXPECT(first_row[0] == "1");
        PFL_EXPECT(last_row[0] == "30");
    }

    {
        const auto output_path = std::filesystem::temp_directory_path() / "pfl_cli_flows_sorted_subset.csv";
        std::filesystem::remove(output_path);

        const auto capture_path = build_cli_flows_capture_path();
        FrontendSessionAdapter adapter {};
        PFL_REQUIRE(adapter.open_capture(capture_path).opened);
        session_detail::FlowQuery query {};
        query.sort = session_detail::FlowQuerySortSpec {
            .key = session_detail::FlowQuerySortKey::bytes,
            .direction = session_detail::FlowQuerySortDirection::descending,
        };
        query.limit = 2U;
        const auto expected = adapter.query_flows(query);
        PFL_REQUIRE(expected.status == session_detail::FlowQueryStatus::ok);
        PFL_REQUIRE(expected.ordered_flow_indices.size() == 2U);
        PFL_EXPECT(expected.result_count_before_limit == 4U);

        const std::vector<std::string> args {
            "flows",
            capture_path.string(),
            "--sort",
            "bytes:desc",
            "--limit",
            "2",
            "--out-flows-list",
            output_path.string(),
        };
        const auto result = invoke_cli(args);
        PFL_EXPECT(result.exit_code == 0);
        PFL_EXPECT(contains_text(result.stdout_text, "Showing 2 of 4 flows."));
        PFL_EXPECT(!contains_text(result.stdout_text, "Use --limit <N> to show more rows"));

        const auto csv_lines = read_text_file_lines(output_path);
        PFL_REQUIRE(csv_lines.size() == 3U);
        const auto first_data = split_csv_line(csv_lines[1]);
        const auto second_data = split_csv_line(csv_lines[2]);
        PFL_REQUIRE(first_data.size() == 16U);
        PFL_REQUIRE(second_data.size() == 16U);
        PFL_EXPECT(first_data[0] == std::to_string(expected.ordered_flow_indices[0] + 1U));
        PFL_EXPECT(second_data[0] == std::to_string(expected.ordered_flow_indices[1] + 1U));
    }

    {
        const auto output_path = std::filesystem::temp_directory_path() / "pfl_cli_flows_adv_subset.csv";
        std::filesystem::remove(output_path);

        const auto capture_path = build_cli_flows_capture_path();
        const auto advanced_filter_path = write_temp_advanced_filter_file(
            "pfl_cli_flows_export_adv.filter",
            "format_version = 3\n"
            "flow_protocol.include = tcp\n"
        );
        FrontendSessionAdapter adapter {};
        PFL_REQUIRE(adapter.open_capture(capture_path).opened);
        const auto expected = adapter.query_advanced_flows(
            require_effective_advanced_filter_spec(
                "format_version = 3\n"
                "flow_protocol.include = tcp\n"
            ),
            std::nullopt,
            session_detail::FlowQuerySortSpec {
                .key = session_detail::FlowQuerySortKey::bytes,
                .direction = session_detail::FlowQuerySortDirection::descending,
            },
            2U
        );
        PFL_REQUIRE(expected.status == FrontendAdvancedFlowQueryStatus::ok);
        PFL_REQUIRE(expected.ordered_flow_indices.size() == 2U);

        const std::vector<std::string> args {
            "flows",
            capture_path.string(),
            "--adv-filter",
            advanced_filter_path.string(),
            "--sort",
            "bytes:desc",
            "--limit",
            "2",
            "--out-flows-list",
            output_path.string(),
        };
        const auto result = invoke_cli(args);
        PFL_EXPECT(result.exit_code == 0);
        PFL_EXPECT(contains_text(result.stderr_text, "Flows list written to:"));

        const auto csv_lines = read_text_file_lines(output_path);
        PFL_REQUIRE(csv_lines.size() == 3U);
        const auto first_data = split_csv_line(csv_lines[1]);
        const auto second_data = split_csv_line(csv_lines[2]);
        PFL_REQUIRE(first_data.size() == 16U);
        PFL_REQUIRE(second_data.size() == 16U);
        PFL_EXPECT(first_data[0] == std::to_string(expected.ordered_flow_indices[0] + 1U));
        PFL_EXPECT(second_data[0] == std::to_string(expected.ordered_flow_indices[1] + 1U));
    }

    {
        const auto output_path = std::filesystem::temp_directory_path() / "pfl_cli_flows_preview_limit_30.csv";
        std::filesystem::remove(output_path);

        const std::vector<std::string> baseline_args {"flows", preview_capture_path.string(), "--limit", "30"};
        const auto baseline_result = invoke_cli(baseline_args);
        PFL_EXPECT(baseline_result.exit_code == 0);
        PFL_EXPECT(count_rendered_flow_rows(baseline_result.stdout_text) == 30U);
        PFL_EXPECT(contains_text(baseline_result.stdout_text, "Showing 30 of 30 flows."));

        const std::vector<std::string> args {
            "flows",
            preview_capture_path.string(),
            "--limit",
            "30",
            "--out-flows-list",
            output_path.string(),
        };
        const auto result = invoke_cli(args);
        PFL_EXPECT(result.exit_code == 0);
        PFL_EXPECT(result.stdout_text == baseline_result.stdout_text);
        PFL_EXPECT(count_rendered_flow_rows(result.stdout_text) == 30U);
        PFL_EXPECT(contains_text(result.stderr_text, "Flows list written to:"));

        const auto csv_lines = read_text_file_lines(output_path);
        PFL_REQUIRE(csv_lines.size() == 31U);
    }

    {
        FrontendSessionAdapter adapter {};
        PFL_REQUIRE(adapter.open_capture(filtered_preview_capture_path).opened);
        session_detail::FlowQuery query {};
        query.text_filter = "10.250.";
        const auto expected = adapter.query_flows(query);
        PFL_REQUIRE(expected.status == session_detail::FlowQueryStatus::ok);
        PFL_EXPECT(expected.result_count_before_limit == 70U);
        PFL_EXPECT(expected.ordered_flow_indices.size() == 70U);

        const auto output_path = std::filesystem::temp_directory_path() / "pfl_cli_flows_filtered_preview_all.csv";
        std::filesystem::remove(output_path);

        const std::vector<std::string> baseline_args {
            "flows",
            filtered_preview_capture_path.string(),
            "--filter",
            "10.250.",
        };
        const auto baseline_result = invoke_cli(baseline_args);
        PFL_EXPECT(baseline_result.exit_code == 0);
        PFL_EXPECT(count_rendered_flow_rows(baseline_result.stdout_text) == 25U);
        PFL_EXPECT(contains_text(baseline_result.stdout_text, "Showing 25 of 70 flows."));

        const std::vector<std::string> args {
            "flows",
            filtered_preview_capture_path.string(),
            "--filter",
            "10.250.",
            "--out-flows-list",
            output_path.string(),
        };
        const auto result = invoke_cli(args);
        PFL_EXPECT(result.exit_code == 0);
        PFL_EXPECT(result.stdout_text == baseline_result.stdout_text);
        PFL_EXPECT(count_rendered_flow_rows(result.stdout_text) == 25U);
        PFL_EXPECT(contains_text(result.stdout_text, "Showing 25 of 70 flows."));
        PFL_EXPECT(contains_text(result.stderr_text, "Flows list written to:"));

        const auto csv_lines = read_text_file_lines(output_path);
        PFL_REQUIRE(csv_lines.size() == expected.ordered_flow_indices.size() + 1U);
    }

    {
        const auto output_path = std::filesystem::temp_directory_path() / "pfl_cli_flows_empty.csv";
        std::filesystem::remove(output_path);
        const auto capture_path = build_cli_flows_capture_path();

        const std::vector<std::string> args {
            "flows",
            capture_path.string(),
            "--filter",
            "no-such-flow",
            "--out-flows-list",
            output_path.string(),
        };
        const auto result = invoke_cli(args);
        PFL_EXPECT(result.exit_code == 0);
        PFL_EXPECT(!contains_text(result.stdout_text, "Showing 0 of 0 flows."));

        const auto csv_lines = read_text_file_lines(output_path);
        PFL_REQUIRE(csv_lines.size() == 1U);
        PFL_EXPECT(csv_lines.front() ==
            "flow_id,family,transport,protocol,protocol_hint,src_ip,src_port,dst_ip,dst_port,packet_count,captured_bytes,original_bytes,first_timestamp,last_timestamp,duration_us,protocol_path");
    }

    {
        const auto output_path = write_temp_text_file("pfl_cli_flows_existing.csv", "old");
        const auto capture_path = build_cli_flows_capture_path();

        const std::vector<std::string> args {
            "flows",
            capture_path.string(),
            "--out-flows-list",
            output_path.string(),
        };
        const auto result = invoke_cli(args);
        PFL_EXPECT(result.exit_code == 1);
        PFL_EXPECT(contains_text(result.stderr_text, "--out-flows-list already exists"));

        const std::vector<std::string> force_args {
            "flows",
            capture_path.string(),
            "--out-flows-list",
            output_path.string(),
            "--force",
        };
        const auto force_result = invoke_cli(force_args);
        PFL_EXPECT(force_result.exit_code == 0);
        const auto csv_lines = read_text_file_lines(output_path);
        PFL_EXPECT(csv_lines.size() >= 2U);
    }

    {
        const auto capture_path = build_cli_flows_capture_path();
        const std::vector<std::string> args {
            "flows",
            capture_path.string(),
            "--out-flows-list",
            capture_path.string(),
        };
        const auto result = invoke_cli(args);
        PFL_EXPECT(result.exit_code == 1);
        PFL_EXPECT(contains_text(result.stderr_text, "cannot overwrite an input or configuration path"));
    }

    {
        const auto capture_path = build_cli_flows_capture_path();
        const auto advanced_filter_path = write_temp_advanced_filter_file(
            "pfl_cli_flows_collision_adv.filter",
            "format_version = 3\n"
            "flow_protocol.include = tcp\n"
        );
        const std::vector<std::string> args {
            "flows",
            capture_path.string(),
            "--adv-filter",
            advanced_filter_path.string(),
            "--out-flows-list",
            advanced_filter_path.string(),
        };
        const auto result = invoke_cli(args);
        PFL_EXPECT(result.exit_code == 1);
        PFL_EXPECT(contains_text(result.stderr_text, "cannot overwrite an input or configuration path"));
    }

    {
        const auto capture_path = build_cli_flows_capture_path();
        const auto settings_path = write_temp_text_file(
            "pfl_cli_flows_collision_settings.json",
            settings_json(false, false, false)
        );
        const auto original_settings_lines = read_text_file_lines(settings_path);
        const std::vector<std::string> args {
            "flows",
            capture_path.string(),
            "--settings",
            settings_path.string(),
            "--out-flows-list",
            settings_path.string(),
            "--force",
        };
        const auto result = invoke_cli(args);
        PFL_EXPECT(result.exit_code == 1);
        PFL_EXPECT(contains_text(result.stderr_text, "cannot overwrite an input or configuration path"));
        PFL_EXPECT(read_text_file_lines(settings_path) == original_settings_lines);
    }

    {
        const auto capture_path = build_cli_flows_capture_path();
        const auto settings_path = write_temp_text_file(
            "pfl_cli_flows_distinct_settings.json",
            settings_json(false, false, false)
        );
        const auto advanced_filter_path = write_temp_advanced_filter_file(
            "pfl_cli_flows_distinct_paths.filter",
            "format_version = 3\n"
            "flow_protocol.include = tcp\n"
        );
        const auto output_path = std::filesystem::temp_directory_path() / "pfl_cli_flows_distinct_paths.csv";
        std::filesystem::remove(output_path);

        const std::vector<std::string> args {
            "flows",
            capture_path.string(),
            "--settings",
            settings_path.string(),
            "--adv-filter",
            advanced_filter_path.string(),
            "--out-flows-list",
            output_path.string(),
            "--force",
        };
        const auto result = invoke_cli(args);
        PFL_EXPECT(result.exit_code == 0);
        PFL_EXPECT(std::filesystem::exists(output_path));
    }

    {
        const auto source_path = write_temp_pcap(
            "pfl_cli_flows_index_only_source.pcap",
            make_classic_pcap(std::vector<std::pair<std::uint32_t, std::vector<std::uint8_t>>> {
                {100U, make_ethernet_ipv4_udp_packet(ipv4(10, 120, 0, 1), ipv4(10, 120, 0, 2), 40123, 53)},
                {200U, make_ethernet_ipv4_udp_packet(ipv4(10, 120, 0, 2), ipv4(10, 120, 0, 1), 53, 40123)},
            })
        );
        const auto index_path = std::filesystem::temp_directory_path() / "pfl_cli_flows_index_only.idx";
        const auto output_path = std::filesystem::temp_directory_path() / "pfl_cli_flows_index_only.csv";
        std::filesystem::remove(index_path);
        std::filesystem::remove(output_path);

        FrontendSessionAdapter adapter {};
        PFL_REQUIRE(adapter.open_capture(source_path).opened);
        PFL_REQUIRE(adapter.save_index(index_path).saved);
        std::filesystem::remove(source_path);

        const std::vector<std::string> args {
            "flows",
            index_path.string(),
            "--out-flows-list",
            output_path.string(),
        };
        const auto result = invoke_cli(args);
        PFL_EXPECT(result.exit_code == 0);
        PFL_EXPECT(contains_text(result.stdout_text, "Showing 1 of 1 flows."));

        const auto csv_lines = read_text_file_lines(output_path);
        PFL_REQUIRE(csv_lines.size() == 2U);
        const auto only_row = split_csv_line(csv_lines[1]);
        PFL_REQUIRE(only_row.size() == 16U);
        PFL_EXPECT(only_row[0] == "1");
        PFL_EXPECT(only_row[2] == "UDP");
    }
}

void expect_settings_behavior() {
    const auto capture_path = build_cli_flows_capture_path();
    const auto checksum_settings_path = write_temp_text_file(
        "pfl_cli_flows_checksum_settings.json",
        settings_json(false, false, true)
    );

    {
        const std::vector<std::string> default_args {"flows", capture_path.string(), "--progress", "off"};
        const std::vector<std::string> checksum_args {
            "flows",
            capture_path.string(),
            "--settings",
            checksum_settings_path.string(),
            "--progress",
            "off",
        };
        const auto default_result = invoke_cli(default_args);
        const auto checksum_result = invoke_cli(checksum_args);
        PFL_EXPECT(default_result.exit_code == 0);
        PFL_EXPECT(checksum_result.exit_code == 0);
        PFL_EXPECT(default_result.stdout_text == checksum_result.stdout_text);
    }

    {
        const auto settings_path = write_temp_text_file(
            "pfl_cli_flows_index_settings.json",
            settings_json(false, false, false)
        );
        const std::vector<std::string> args {
            "flows",
            "capture.idx",
            "--settings",
            settings_path.string(),
        };
        const auto result = invoke_cli(args);
        PFL_EXPECT(result.exit_code == 1);
        PFL_EXPECT(contains_text(result.stderr_text, "--settings is valid only for raw capture input"));
    }

    {
        const auto gtpu_fixture = fixture_path("parsing/gtpu/21_gtpu_same_inner_tuple_different_teid.pcap");
        FrontendSessionAdapter default_adapter {};
        PFL_REQUIRE(default_adapter.open_capture(gtpu_fixture).opened);
        const auto default_result = default_adapter.query_flows(session_detail::FlowQuery {});
        PFL_REQUIRE(default_result.status == session_detail::FlowQueryStatus::ok);

        FrontendSessionAdapter grouped_adapter {};
        auto settings = grouped_adapter.get_settings();
        settings.ignore_gtpu_teids_when_grouping_inner_flows = true;
        [[maybe_unused]] const auto updated_settings = grouped_adapter.update_settings(settings);
        PFL_REQUIRE(grouped_adapter.open_capture(gtpu_fixture).opened);
        const auto grouped_result = grouped_adapter.query_flows(session_detail::FlowQuery {});
        PFL_REQUIRE(grouped_result.status == session_detail::FlowQueryStatus::ok);
        PFL_EXPECT(grouped_result.ordered_flow_indices.size() < default_result.ordered_flow_indices.size());
        PFL_EXPECT(grouped_result.result_count_before_limit == grouped_result.ordered_flow_indices.size());

        const auto grouped_settings_path = write_temp_text_file(
            "pfl_cli_flows_gtpu_settings.json",
            settings_json(true, false, false)
        );
        const auto output_path = std::filesystem::temp_directory_path() / "pfl_cli_flows_gtpu_grouped.csv";
        std::filesystem::remove(output_path);

        const std::vector<std::string> args {
            "flows",
            gtpu_fixture.string(),
            "--settings",
            grouped_settings_path.string(),
            "--out-flows-list",
            output_path.string(),
        };
        const auto result = invoke_cli(args);
        PFL_EXPECT(result.exit_code == 0);

        const auto csv_lines = read_text_file_lines(output_path);
        PFL_EXPECT(csv_lines.size() == grouped_result.ordered_flow_indices.size() + 1U);
    }
}

}  // namespace

void run_cli_flows_tests() {
    expect_shared_cli_flow_selector_helpers();
    expect_flows_help_and_parser_behavior();
    expect_flows_runtime_behavior();
    expect_preview_and_csv_behavior();
    expect_settings_behavior();
}

}  // namespace pfl::tests
