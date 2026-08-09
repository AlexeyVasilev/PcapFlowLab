#include "cli/PacketInfoCommand.h"

#include <sstream>
#include <string>
#include <vector>

#include "app/frontend/FrontendSettingsJson.h"
#include "app/session/SessionFlowHelpers.h"
#include "core/index/CaptureIndex.h"

namespace pfl::cli {
namespace {

void append_key_value_line(
    std::ostringstream& out,
    const std::string_view key,
    const std::string_view value
) {
    out << key << ": " << value << '\n';
}

void render_summary_layer(
    std::ostringstream& out,
    const session_detail::PacketSummaryLayer& layer,
    const std::size_t indent_spaces
) {
    out << std::string(indent_spaces, ' ') << layer.title;
    if (!layer.marker_text.empty()) {
        out << " [" << layer.marker_text << ']';
    }
    out << '\n';

    for (const auto& field : layer.fields) {
        out << std::string(indent_spaces + 2U, ' ') << field.label << ": " << field.value << '\n';
    }

    for (std::size_t index = 0U; index < layer.children.size(); ++index) {
        out << '\n';
        render_summary_layer(out, layer.children[index], indent_spaces + 2U);
    }
}

std::string render_summary_section(const std::vector<session_detail::PacketSummaryLayer>& layers) {
    std::ostringstream out {};
    out << "Summary\n\n";
    for (std::size_t index = 0U; index < layers.size(); ++index) {
        if (index > 0U) {
            out << '\n';
        }
        render_summary_layer(out, layers[index], 0U);
    }
    return out.str();
}

std::string render_packet_info_report(
    const FrontendPacketInfoDto& info,
    const bool flow_scoped_selection,
    const bool include_bytes
) {
    std::ostringstream out {};
    if (flow_scoped_selection) {
        out << "Flow " << (*info.flow_index + 1U) << " / Packet " << *info.packet_in_flow << "\n\n";
    } else {
        out << "Packet " << info.packet_in_file << "\n\n";
    }

    out << "Flow Context\n";
    if (!info.recognized_flow) {
        append_key_value_line(out, "Recognized Flow", "No");
    } else {
        if (!flow_scoped_selection) {
            append_key_value_line(out, "Flow", std::to_string(*info.flow_index + 1U));
            append_key_value_line(out, "Packet in Flow", std::to_string(*info.packet_in_flow));
        }
        append_key_value_line(out, "Endpoints", info.endpoint_summary_text);
        append_key_value_line(out, "Direction", info.direction_text);
    }
    out << '\n';

    out << "Packet\n";
    append_key_value_line(out, "Packet in File", session_detail::format_statistics_count_value(info.packet_in_file));
    append_key_value_line(out, "Time", info.timestamp_text);
    append_key_value_line(out, "Captured Length", session_detail::format_statistics_size_value(info.captured_length));
    append_key_value_line(out, "Original Length", session_detail::format_statistics_size_value(info.original_length));
    out << '\n';

    out << render_summary_section(info.summary_layers);

    if (include_bytes) {
        out << "\n\nBytes\n\n";
        out << info.captured_packet_bytes.label << " - " << info.captured_packet_bytes.available_length << " bytes\n\n";
        out << info.captured_packet_bytes.formatted_text;
    }

    return out.str();
}

bool selector_uses_flow_context(const PacketInfoCommandOptions& options) noexcept {
    return options.flow_index.has_value() && options.packet_in_flow.has_value();
}

std::optional<std::uint64_t> parse_cli_positive_uint64(const std::string_view value) noexcept {
    const auto parsed = parse_cli_positive_size(value);
    if (!parsed.has_value()) {
        return std::nullopt;
    }
    return static_cast<std::uint64_t>(*parsed);
}

std::string missing_source_capture_error_text() {
    return "Packet inspection requires source capture data.\n"
           "Use --source-capture <path> to attach the capture used to create this index.\n";
}

}  // namespace

std::string render_packet_info_command_help() {
    std::ostringstream out {};
    out << "PcapFlowLab CLI - packet-info\n\n";
    out << "Inspect exactly one captured packet.\n\n";
    out << "Usage\n";
    out << "  pcap-flow-lab packet-info <input> (--packet-in-file <N> | --flow-number <F> --packet-in-flow <P>) [options]\n";
    out << "  pcap-flow-lab packet-info --input <input> (--packet-in-file <N> | --flow-number <F> --packet-in-flow <P>) [options]\n\n";
    out << "Input and selection\n";
    out << "  --input <path>\n";
    out << "  --packet-in-file <N>\n";
    out << "  --flow-number <F>\n";
    out << "  --packet-in-flow <P>\n";
    out << "  --source-capture <path>\n";
    out << "    Valid only for index input and used when packet inspection needs source capture bytes.\n";
    out << "  --settings <settings.json>\n";
    out << "    Applies to raw capture import and is invalid for index input.\n\n";
    out << "Presentation\n";
    out << "  --bytes\n\n";
    out << "Runtime\n";
    out << "  --progress <auto|on|off>\n\n";
    out << "Help\n";
    out << "  -h, --help\n\n";
    out << "Examples\n";
    out << "  pcap-flow-lab packet-info capture.pcap --packet-in-file 2574112\n";
    out << "  pcap-flow-lab packet-info capture.pcap --flow-number 11724 --packet-in-flow 7 --bytes\n";
    out << "  pcap-flow-lab packet-info capture.idx --packet-in-file 2574112 --source-capture original.pcap\n";
    return out.str();
}

PacketInfoCommandParseResult parse_packet_info_command_arguments(const std::span<const std::string_view> args) {
    PacketInfoCommandOptions options {};
    bool positional_input_seen = false;
    bool explicit_input_seen = false;
    bool settings_seen = false;
    bool source_capture_seen = false;
    bool flow_number_seen = false;
    bool packet_in_flow_seen = false;
    bool packet_in_file_seen = false;
    bool progress_seen = false;

    for (std::size_t index = 0U; index < args.size(); ++index) {
        const auto token = args[index];

        if (token == "--bytes") {
            options.include_bytes = true;
            continue;
        }

        if (token == "--input") {
            if (explicit_input_seen) {
                return {.ok = false, .options = std::nullopt, .error_text = "Duplicate --input is invalid."};
            }
            if (positional_input_seen) {
                return {
                    .ok = false,
                    .options = std::nullopt,
                    .error_text = "Positional input and --input are mutually exclusive input forms. Using both in the same invocation is invalid.",
                };
            }
            if (index + 1U >= args.size()) {
                return {.ok = false, .options = std::nullopt, .error_text = "--input requires a path."};
            }
            explicit_input_seen = true;
            options.input_path = std::filesystem::path {std::string {args[++index]}};
            continue;
        }

        if (token == "--flow-number") {
            if (flow_number_seen) {
                return {.ok = false, .options = std::nullopt, .error_text = "Duplicate --flow-number is invalid."};
            }
            if (index + 1U >= args.size()) {
                return {.ok = false, .options = std::nullopt, .error_text = "--flow-number requires a positive 1-based value."};
            }
            const auto flow_index = parse_cli_flow_number(args[++index]);
            if (!flow_index.has_value()) {
                return {.ok = false, .options = std::nullopt, .error_text = "--flow-number requires a positive 1-based value."};
            }
            flow_number_seen = true;
            options.flow_index = *flow_index;
            continue;
        }

        if (token == "--packet-in-flow") {
            if (packet_in_flow_seen) {
                return {.ok = false, .options = std::nullopt, .error_text = "Duplicate --packet-in-flow is invalid."};
            }
            if (index + 1U >= args.size()) {
                return {.ok = false, .options = std::nullopt, .error_text = "--packet-in-flow requires a positive 1-based value."};
            }
            const auto value = parse_cli_positive_uint64(args[++index]);
            if (!value.has_value()) {
                return {.ok = false, .options = std::nullopt, .error_text = "--packet-in-flow requires a positive 1-based value."};
            }
            packet_in_flow_seen = true;
            options.packet_in_flow = *value;
            continue;
        }

        if (token == "--packet-in-file") {
            if (packet_in_file_seen) {
                return {.ok = false, .options = std::nullopt, .error_text = "Duplicate --packet-in-file is invalid."};
            }
            if (index + 1U >= args.size()) {
                return {.ok = false, .options = std::nullopt, .error_text = "--packet-in-file requires a positive 1-based value."};
            }
            const auto value = parse_cli_positive_uint64(args[++index]);
            if (!value.has_value()) {
                return {.ok = false, .options = std::nullopt, .error_text = "--packet-in-file requires a positive 1-based value."};
            }
            packet_in_file_seen = true;
            options.packet_in_file = *value;
            continue;
        }

        if (token == "--source-capture") {
            if (source_capture_seen) {
                return {.ok = false, .options = std::nullopt, .error_text = "Duplicate --source-capture is invalid."};
            }
            if (index + 1U >= args.size()) {
                return {.ok = false, .options = std::nullopt, .error_text = "--source-capture requires a path."};
            }
            source_capture_seen = true;
            options.source_capture_path = std::filesystem::path {std::string {args[++index]}};
            continue;
        }

        if (token == "--settings") {
            if (settings_seen) {
                return {.ok = false, .options = std::nullopt, .error_text = "Duplicate --settings is invalid."};
            }
            if (index + 1U >= args.size()) {
                return {.ok = false, .options = std::nullopt, .error_text = "--settings requires a path."};
            }
            settings_seen = true;
            options.settings_path = std::filesystem::path {std::string {args[++index]}};
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
            if (token == "--packet-number" || token == "--packet-numbers" || token == "--flow-numbers" ||
                token == "--byte-view" || token == "--list-byte-views" || token == "--bytes-layer" ||
                token == "--format" || token == "--json" || token == "--out" ||
                token == "--filter" || token == "--sort" || token == "--limit") {
                return {.ok = false, .options = std::nullopt, .error_text = "packet-info does not accept " + std::string {token} + '.'};
            }
            return {.ok = false, .options = std::nullopt, .error_text = "Unknown packet-info option: " + std::string {token}};
        }

        if (explicit_input_seen || positional_input_seen) {
            return {.ok = false, .options = std::nullopt, .error_text = "packet-info accepts exactly one input path."};
        }

        positional_input_seen = true;
        options.input_path = std::filesystem::path {std::string {token}};
    }

    if (options.input_path.empty()) {
        return {.ok = false, .options = std::nullopt, .error_text = "packet-info requires an input path."};
    }

    const bool has_flow_selector = options.flow_index.has_value() || options.packet_in_flow.has_value();
    const bool has_complete_flow_selector = options.flow_index.has_value() && options.packet_in_flow.has_value();
    const bool has_global_selector = options.packet_in_file.has_value();

    if (has_complete_flow_selector && has_global_selector) {
        return {.ok = false, .options = std::nullopt, .error_text = "packet-info accepts either flow-scoped selection or --packet-in-file, but not both."};
    }
    if (has_flow_selector && !has_complete_flow_selector) {
        return {.ok = false, .options = std::nullopt, .error_text = "packet-info requires both --flow-number and --packet-in-flow together."};
    }
    if (!has_complete_flow_selector && !has_global_selector) {
        return {.ok = false, .options = std::nullopt, .error_text = "packet-info requires either --packet-in-file or the pair --flow-number and --packet-in-flow."};
    }

    return {.ok = true, .options = options, .error_text = {}};
}

PacketInfoCommandExecutionResult execute_packet_info_command(const PacketInfoCommandOptions& options) {
    return execute_packet_info_command(
        options,
        CliRuntimeEnvironment {
            .stderr_is_terminal = stderr_supports_interactive_updates(),
        }
    );
}

PacketInfoCommandExecutionResult execute_packet_info_command(
    const PacketInfoCommandOptions& options,
    const CliRuntimeEnvironment& environment
) {
    const bool input_looks_like_index = looks_like_index_file(options.input_path);
    if (!input_looks_like_index && options.source_capture_path.has_value()) {
        return {
            .exit_code = 1,
            .stdout_text = {},
            .stderr_text = "--source-capture is valid only for index input.\n",
        };
    }
    if (input_looks_like_index && options.settings_path.has_value()) {
        return {
            .exit_code = 1,
            .stdout_text = {},
            .stderr_text = "--settings is valid only for raw capture input.\n",
        };
    }

    FrontendSettingsDto settings {};
    if (options.settings_path.has_value()) {
        const auto parse_result = parse_frontend_settings_json_file(*options.settings_path);
        if (!parse_result.ok) {
            return {.exit_code = 1, .stdout_text = {}, .stderr_text = parse_result.error_text + '\n'};
        }
        settings = parse_result.settings;
    }

    FrontendSessionAdapter adapter {};
    if (options.settings_path.has_value()) {
        [[maybe_unused]] const auto updated_settings = adapter.update_settings(settings);
    }

    std::string stderr_text {};
    const auto open_result = open_input_with_progress(
        adapter,
        options.input_path,
        options.progress_mode,
        environment,
        stderr_text
    );
    if (!open_result.opened) {
        if (!open_result.error_text.empty()) {
            stderr_text += open_result.error_text;
            if (stderr_text.empty() || stderr_text.back() != '\n') {
                stderr_text.push_back('\n');
            }
        }
        return {.exit_code = 1, .stdout_text = {}, .stderr_text = std::move(stderr_text)};
    }

    if (open_result.partial_open && !open_result.partial_open_warning_text.empty()) {
        if (!stderr_text.empty() && stderr_text.back() != '\n') {
            stderr_text.push_back('\n');
        }
        stderr_text += open_result.partial_open_warning_text;
        if (stderr_text.back() != '\n') {
            stderr_text.push_back('\n');
        }
    }

    if (options.source_capture_path.has_value()) {
        const auto attach_result = adapter.attach_source_capture(*options.source_capture_path);
        if (!attach_result.attached) {
            stderr_text += attach_result.error_text;
            if (stderr_text.empty() || stderr_text.back() != '\n') {
                stderr_text.push_back('\n');
            }
            return {.exit_code = 1, .stdout_text = {}, .stderr_text = std::move(stderr_text)};
        }
    }

    const auto source_availability = adapter.source_availability();
    if (!source_availability.byte_backed_inspection_available) {
        return {
            .exit_code = 1,
            .stdout_text = {},
            .stderr_text = source_availability.opened_from_index
                ? missing_source_capture_error_text()
                : "Packet inspection requires readable source capture data.\n",
        };
    }

    const bool flow_scoped_selection = selector_uses_flow_context(options);
    if (flow_scoped_selection && !adapter.flow_row(*options.flow_index).has_value()) {
        std::ostringstream out {};
        out << "Flow " << (*options.flow_index + 1U) << " is out of range for this input.\n";
        return {.exit_code = 1, .stdout_text = {}, .stderr_text = out.str()};
    }
    const auto info = flow_scoped_selection
        ? adapter.get_packet_info_by_flow(*options.flow_index, *options.packet_in_flow)
        : adapter.get_packet_info_by_file(*options.packet_in_file - 1U);

    if (!info.has_capture) {
        return {
            .exit_code = 1,
            .stdout_text = {},
            .stderr_text = info.error_text.empty() ? "No capture is open.\n" : info.error_text + '\n',
        };
    }
    if (!info.packet_available) {
        std::ostringstream out {};
        if (flow_scoped_selection) {
            out << "Packet " << *options.packet_in_flow
                << " is out of range for flow " << (*options.flow_index + 1U) << ".\n";
        } else {
            out << "Packet " << *options.packet_in_file << " is out of range for this input.\n";
        }
        return {.exit_code = 1, .stdout_text = {}, .stderr_text = out.str()};
    }
    if (!info.details_available) {
        const auto error_text = !info.unavailable_text.empty() ? info.unavailable_text : info.error_text;
        return {
            .exit_code = 1,
            .stdout_text = {},
            .stderr_text = error_text.empty()
                ? "Packet inspection is unavailable for the requested packet.\n"
                : error_text + '\n',
        };
    }
    if (options.include_bytes && !info.captured_packet_bytes.available) {
        const auto error_text = !info.captured_packet_bytes.unavailable_text.empty()
            ? info.captured_packet_bytes.unavailable_text
            : info.unavailable_text;
        return {
            .exit_code = 1,
            .stdout_text = {},
            .stderr_text = error_text.empty()
                ? "Captured packet bytes are unavailable for the requested packet.\n"
                : error_text + '\n',
        };
    }

    return {
        .exit_code = 0,
        .stdout_text = render_packet_info_report(info, flow_scoped_selection, options.include_bytes),
        .stderr_text = std::move(stderr_text),
    };
}

}  // namespace pfl::cli
