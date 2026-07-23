#include "tools/import_validation/ImportValidation.h"

#include <cstdlib>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace {

constexpr int kExitCodeSuccess = 0;
constexpr int kExitCodeMismatch = 1;
constexpr int kExitCodeUsageOrImportFailure = 2;

struct ParsedCommandLine {
    bool valid {true};
    std::string error_text {};
    std::string mode {};
    std::filesystem::path capture_path {};
    pfl::ImportValidationOptions options {};
    std::optional<std::filesystem::path> json_output_path {};
};

void print_usage() {
    std::cout
        << "Usage:\n"
        << "  pcap_flow_lab_import_validation compare <capture> [--max-packets N] [--max-mismatches N] [--no-hints] [--json <output-file>]\n"
        << "  pcap_flow_lab_import_validation diagnose <capture> [--packet-index N] [--max-packets N] [--max-mismatches N] [--no-hints] [--json <output-file>]\n"
        << "  pcap_flow_lab_import_validation legacy <capture> [--max-packets N] [--no-hints] [--json <output-file>]\n"
        << "  pcap_flow_lab_import_validation unified <capture> [--max-packets N] [--no-hints] [--json <output-file>]\n";
}

std::string escape_json(std::string_view text) {
    std::ostringstream builder {};
    for (const char ch : text) {
        switch (ch) {
        case '\\':
            builder << "\\\\";
            break;
        case '"':
            builder << "\\\"";
            break;
        case '\n':
            builder << "\\n";
            break;
        case '\r':
            builder << "\\r";
            break;
        case '\t':
            builder << "\\t";
            break;
        default:
            builder << ch;
            break;
        }
    }
    return builder.str();
}

std::string quote_json_string(std::string_view text) {
    return '"' + escape_json(text) + '"';
}

std::string format_bytes_and_mib(const std::optional<std::uint64_t> bytes) {
    if (!bytes.has_value()) {
        return "unsupported";
    }

    std::ostringstream builder {};
    builder << *bytes << " bytes (" << std::fixed << std::setprecision(2)
            << (static_cast<double>(*bytes) / (1024.0 * 1024.0)) << " MiB)";
    return builder.str();
}

std::string format_metrics_json(const pfl::ImportValidationMetrics& metrics) {
    std::ostringstream builder {};
    builder
        << "{"
        << "\"file_size\":" << metrics.file_size << ','
        << "\"packet_count\":" << metrics.packet_count << ','
        << "\"captured_bytes\":" << metrics.captured_bytes << ','
        << "\"flow_count\":" << metrics.flow_count << ','
        << "\"connection_count\":" << metrics.connection_count << ','
        << "\"unrecognized_count\":" << metrics.unrecognized_count << ','
        << "\"registry_size\":" << metrics.registry_size << ','
        << "\"elapsed_seconds\":" << std::fixed << std::setprecision(6) << metrics.elapsed_seconds << ','
        << "\"packets_per_second\":" << std::fixed << std::setprecision(3) << metrics.packets_per_second << ','
        << "\"mib_per_second\":" << std::fixed << std::setprecision(3) << metrics.mib_per_second << ','
        << "\"peak_memory_bytes\":";
    if (metrics.peak_memory_bytes.has_value()) {
        builder << *metrics.peak_memory_bytes;
    } else {
        builder << "null";
    }
    builder << "}";
    return builder.str();
}

std::string format_protocol_path_or_empty(const pfl::ProtocolPath& path) {
    return path.empty() ? std::string {} : pfl::format_protocol_path(path);
}

std::string format_packet_observation_json(const pfl::ImportValidationPacketObservation& observation) {
    std::ostringstream builder {};
    builder
        << "{"
        << "\"packet_index\":" << observation.packet_index << ','
        << "\"file_offset\":" << observation.file_offset << ','
        << "\"captured_length\":" << observation.captured_length << ','
        << "\"original_length\":" << observation.original_length << ','
        << "\"link_type\":" << observation.link_type << ','
        << "\"classification\":" << quote_json_string(pfl::format_import_validation_packet_classification(observation.classification)) << ','
        << "\"family\":" << quote_json_string(std::to_string(static_cast<int>(observation.family))) << ','
        << "\"protocol\":" << quote_json_string(std::to_string(static_cast<int>(observation.protocol))) << ','
        << "\"has_addresses\":" << (observation.has_addresses ? "true" : "false") << ','
        << "\"src_addr_v4\":" << observation.src_addr_v4 << ','
        << "\"dst_addr_v4\":" << observation.dst_addr_v4 << ','
        << "\"has_ports\":" << (observation.has_ports ? "true" : "false") << ','
        << "\"src_port\":" << observation.src_port << ','
        << "\"dst_port\":" << observation.dst_port << ','
        << "\"has_transport_payload_length\":" << (observation.has_transport_payload_length ? "true" : "false") << ','
        << "\"captured_transport_payload_length\":" << observation.captured_transport_payload_length << ','
        << "\"has_tcp_flags\":" << (observation.has_tcp_flags ? "true" : "false") << ','
        << "\"tcp_flags\":" << static_cast<unsigned int>(observation.tcp_flags) << ','
        << "\"fragmented\":" << (observation.fragmented ? "true" : "false") << ','
        << "\"physical_path\":" << quote_json_string(format_protocol_path_or_empty(observation.physical_path)) << ','
        << "\"parse_status\":" << quote_json_string(std::to_string(static_cast<int>(observation.final_status))) << ','
        << "\"stop_reason\":" << quote_json_string(std::to_string(static_cast<int>(observation.stop_reason))) << ','
        << "\"unrecognized_reason\":";
    if (observation.unrecognized_reason.has_value()) {
        builder << quote_json_string(*observation.unrecognized_reason);
    } else {
        builder << "null";
    }
    builder << "}";
    return builder.str();
}

void print_metrics(std::string_view label, const pfl::ImportValidationMetrics& metrics) {
    std::cout
        << label << ":\n"
        << "  packets: " << metrics.packet_count << '\n'
        << "  flows: " << metrics.flow_count << '\n'
        << "  connections: " << metrics.connection_count << '\n'
        << "  unrecognized: " << metrics.unrecognized_count << '\n'
        << "  registry size: " << metrics.registry_size << '\n'
        << "  file size: " << metrics.file_size << " bytes\n"
        << "  captured bytes: " << metrics.captured_bytes << '\n'
        << "  elapsed: " << std::fixed << std::setprecision(6) << metrics.elapsed_seconds << " s\n"
        << "  packets/s: " << std::fixed << std::setprecision(3) << metrics.packets_per_second << '\n'
        << "  MiB/s: " << std::fixed << std::setprecision(3) << metrics.mib_per_second << '\n'
        << "  peak memory: " << format_bytes_and_mib(metrics.peak_memory_bytes) << '\n';
}

void print_packet_observation(std::string_view label, const pfl::ImportValidationPacketObservation& observation) {
    std::cout
        << label << ":\n"
        << "  packet index: " << observation.packet_index << '\n'
        << "  file offset: " << observation.file_offset << '\n'
        << "  caplen/origlen: " << observation.captured_length << '/' << observation.original_length << '\n'
        << "  link type: " << observation.link_type << '\n'
        << "  classification: " << pfl::format_import_validation_packet_classification(observation.classification) << '\n'
        << "  family: " << static_cast<int>(observation.family) << '\n'
        << "  protocol: " << static_cast<int>(observation.protocol) << '\n'
        << "  addresses present: " << (observation.has_addresses ? "yes" : "no") << '\n'
        << "  ports present: " << (observation.has_ports ? "yes" : "no") << '\n'
        << "  transport payload length: ";
    if (observation.has_transport_payload_length) {
        std::cout << observation.captured_transport_payload_length << '\n';
    } else {
        std::cout << "none\n";
    }
    std::cout
        << "  tcp flags: " << (observation.has_tcp_flags ? std::to_string(static_cast<unsigned int>(observation.tcp_flags)) : std::string {"none"}) << '\n'
        << "  fragmented: " << (observation.fragmented ? "yes" : "no") << '\n'
        << "  physical path: " << format_protocol_path_or_empty(observation.physical_path) << '\n'
        << "  parse status: " << static_cast<int>(observation.final_status) << '\n'
        << "  stop reason: " << static_cast<int>(observation.stop_reason) << '\n';
    if (observation.unrecognized_reason.has_value()) {
        std::cout << "  unrecognized reason: " << *observation.unrecognized_reason << '\n';
    }
}

bool write_json_file(const std::filesystem::path& output_path, std::string_view json_text) {
    std::ofstream stream(output_path, std::ios::binary | std::ios::trunc);
    if (!stream.is_open()) {
        return false;
    }

    stream.write(json_text.data(), static_cast<std::streamsize>(json_text.size()));
    return stream.good();
}

ParsedCommandLine parse_command_line(int argc, char* argv[]) {
    ParsedCommandLine parsed {};

    if (argc < 3) {
        parsed.valid = false;
        parsed.error_text = "mode and capture path are required";
        return parsed;
    }

    parsed.mode = argv[1];
    if (parsed.mode != "compare" && parsed.mode != "diagnose" && parsed.mode != "legacy" && parsed.mode != "unified") {
        parsed.valid = false;
        parsed.error_text = "mode must be one of: compare, diagnose, legacy, unified";
        return parsed;
    }

    parsed.capture_path = argv[2];

    for (int index = 3; index < argc; ++index) {
        const std::string_view option = argv[index];

        if (option == "--no-hints") {
            parsed.options.include_hints = false;
            continue;
        }

        if (option == "--max-packets") {
            if (index + 1 >= argc) {
                parsed.valid = false;
                parsed.error_text = "--max-packets requires a value";
                return parsed;
            }

            try {
                parsed.options.max_packets = static_cast<std::uint64_t>(std::stoull(argv[++index]));
            } catch (const std::exception&) {
                parsed.valid = false;
                parsed.error_text = "--max-packets value is invalid";
                return parsed;
            }
            continue;
        }

        if (option == "--packet-index") {
            if (parsed.mode != "diagnose") {
                parsed.valid = false;
                parsed.error_text = "--packet-index is supported only in diagnose mode";
                return parsed;
            }
            if (index + 1 >= argc) {
                parsed.valid = false;
                parsed.error_text = "--packet-index requires a value";
                return parsed;
            }

            try {
                parsed.options.packet_index = static_cast<std::uint64_t>(std::stoull(argv[++index]));
            } catch (const std::exception&) {
                parsed.valid = false;
                parsed.error_text = "--packet-index value is invalid";
                return parsed;
            }
            continue;
        }

        if (option == "--max-mismatches") {
            if (index + 1 >= argc) {
                parsed.valid = false;
                parsed.error_text = "--max-mismatches requires a value";
                return parsed;
            }

            try {
                parsed.options.max_reported_mismatches = static_cast<std::size_t>(std::stoull(argv[++index]));
            } catch (const std::exception&) {
                parsed.valid = false;
                parsed.error_text = "--max-mismatches value is invalid";
                return parsed;
            }
            continue;
        }

        if (option == "--json") {
            if (index + 1 >= argc) {
                parsed.valid = false;
                parsed.error_text = "--json requires an output file path";
                return parsed;
            }

            parsed.json_output_path = std::filesystem::path {argv[++index]};
            continue;
        }

        parsed.valid = false;
        parsed.error_text = "unknown option: " + std::string {option};
        return parsed;
    }

    return parsed;
}

int run_compare_mode(const ParsedCommandLine& parsed) {
    std::cout
        << "Mode: compare\n"
        << "Capture: " << parsed.capture_path.generic_string() << '\n'
        << "Hint comparison: " << (parsed.options.include_hints ? "enabled" : "disabled") << '\n';

    const auto result = pfl::compare_import_validation(parsed.capture_path, parsed.options);
    if (!result.success) {
        std::cerr << "Import validation failed: " << result.error_text << '\n';
        return kExitCodeUsageOrImportFailure;
    }

    print_metrics("Legacy import", result.legacy_metrics);
    print_metrics("Unified import", result.unified_metrics);
    std::cout
        << "Parity: " << (result.parity ? "exact" : "mismatch") << '\n'
        << "Mismatch count: " << result.mismatch_count << '\n'
        << "Registry structural diff: only-in-legacy=" << result.registry_comparison.only_in_legacy.size()
        << ", only-in-unified=" << result.registry_comparison.only_in_unified.size()
        << ", id-drift=" << result.registry_comparison.id_drift_count << '\n';

    if (!result.mismatches.empty()) {
        std::cout << "First mismatches:\n";
        for (const auto& mismatch : result.mismatches) {
            std::cout
                << "  [" << pfl::format_import_validation_mismatch_category(mismatch.category) << "] "
                << mismatch.entity << " :: " << mismatch.field
                << " | legacy=" << mismatch.legacy_value
                << " | unified=" << mismatch.unified_value << '\n';
        }
    }

    if (parsed.json_output_path.has_value()) {
        std::ostringstream json {};
        json
            << "{"
            << "\"mode\":\"compare\","
            << "\"capture\":" << quote_json_string(parsed.capture_path.generic_string()) << ','
            << "\"parity\":" << (result.parity ? "true" : "false") << ','
            << "\"mismatch_count\":" << result.mismatch_count << ','
            << "\"legacy\":" << format_metrics_json(result.legacy_metrics) << ','
            << "\"unified\":" << format_metrics_json(result.unified_metrics) << ','
            << "\"registry_structural\":{"
            << "\"shared\":" << result.registry_comparison.shared_structural_path_count << ','
            << "\"id_drift_count\":" << result.registry_comparison.id_drift_count << ","
            << "\"only_in_legacy\":[";
        for (std::size_t index = 0U; index < result.registry_comparison.only_in_legacy.size(); ++index) {
            if (index > 0U) {
                json << ',';
            }
            json << quote_json_string(format_protocol_path_or_empty(result.registry_comparison.only_in_legacy[index]));
        }
        json << "],\"only_in_unified\":[";
        for (std::size_t index = 0U; index < result.registry_comparison.only_in_unified.size(); ++index) {
            if (index > 0U) {
                json << ',';
            }
            json << quote_json_string(format_protocol_path_or_empty(result.registry_comparison.only_in_unified[index]));
        }
        json << "]},\"mismatches\":[";
        for (std::size_t index = 0U; index < result.mismatches.size(); ++index) {
            if (index > 0U) {
                json << ',';
            }

            const auto& mismatch = result.mismatches[index];
            json
                << "{"
                << "\"category\":" << quote_json_string(pfl::format_import_validation_mismatch_category(mismatch.category)) << ','
                << "\"entity\":" << quote_json_string(mismatch.entity) << ','
                << "\"field\":" << quote_json_string(mismatch.field) << ','
                << "\"legacy_value\":" << quote_json_string(mismatch.legacy_value) << ','
                << "\"unified_value\":" << quote_json_string(mismatch.unified_value)
                << "}";
        }
        json << "]}";

        if (!write_json_file(*parsed.json_output_path, json.str())) {
            std::cerr << "Failed to write JSON output: " << parsed.json_output_path->generic_string() << '\n';
            return kExitCodeUsageOrImportFailure;
        }
    }

    return result.parity ? kExitCodeSuccess : kExitCodeMismatch;
}

int run_diagnose_mode(const ParsedCommandLine& parsed) {
    std::cout
        << "Mode: diagnose\n"
        << "Capture: " << parsed.capture_path.generic_string() << '\n'
        << "Hint comparison: " << (parsed.options.include_hints ? "enabled" : "disabled") << '\n';
    if (parsed.options.packet_index.has_value()) {
        std::cout << "Packet index: " << *parsed.options.packet_index << '\n';
    }

    const auto result = pfl::diagnose_import_validation(parsed.capture_path, parsed.options);
    if (!result.success) {
        std::cerr << "Import validation failed: " << result.error_text << '\n';
        return kExitCodeUsageOrImportFailure;
    }

    print_metrics("Legacy import", result.legacy_metrics);
    print_metrics("Unified import", result.unified_metrics);
    std::cout
        << "Session parity: " << (result.session_compare.parity ? "exact" : "mismatch") << '\n'
        << "Session mismatch count: " << result.session_compare.mismatch_count << '\n'
        << "Packet-level mismatch count: " << result.packet_compare.mismatch_count << '\n';

    std::cout << "First divergences:\n";
    std::cout << "  any: " << (result.packet_compare.first_divergence.any_packet_index.has_value() ? std::to_string(*result.packet_compare.first_divergence.any_packet_index) : std::string {"none"}) << '\n';
    std::cout << "  classification: " << (result.packet_compare.first_divergence.classification_packet_index.has_value() ? std::to_string(*result.packet_compare.first_divergence.classification_packet_index) : std::string {"none"}) << '\n';
    std::cout << "  physical path: " << (result.packet_compare.first_divergence.physical_path_packet_index.has_value() ? std::to_string(*result.packet_compare.first_divergence.physical_path_packet_index) : std::string {"none"}) << '\n';
    std::cout << "  payload length: " << (result.packet_compare.first_divergence.payload_length_packet_index.has_value() ? std::to_string(*result.packet_compare.first_divergence.payload_length_packet_index) : std::string {"none"}) << '\n';

    if (result.legacy_packet.has_value() && result.unified_packet.has_value()) {
        print_packet_observation("Legacy packet", *result.legacy_packet);
        print_packet_observation("Unified packet", *result.unified_packet);
    } else if (!result.packet_compare.groups.empty()) {
        std::cout << "Grouped packet mismatches:\n";
        for (const auto& group : result.packet_compare.groups) {
            std::cout
                << "  [" << pfl::format_import_validation_packet_mismatch_category(group.category) << "] "
                << "count=" << group.occurrence_count
                << " packets=";
            for (std::size_t index = 0U; index < group.packet_indices.size(); ++index) {
                if (index > 0U) {
                    std::cout << ',';
                }
                std::cout << group.packet_indices[index];
            }
            if (group.numeric_delta.has_value()) {
                std::cout << " delta=" << *group.numeric_delta;
            }
            std::cout
                << " legacy_path=" << format_protocol_path_or_empty(group.legacy_path)
                << " unified_path=" << format_protocol_path_or_empty(group.unified_path)
                << '\n'
                << "    representative: packet=" << group.representative.packet_index
                << " caplen/origlen=" << group.representative.captured_length << '/' << group.representative.original_length
                << " legacy=" << group.representative.legacy_value
                << " unified=" << group.representative.unified_value
                << '\n';
        }
    }

    if (parsed.json_output_path.has_value()) {
        std::ostringstream json {};
        json
            << "{"
            << "\"mode\":\"diagnose\","
            << "\"capture\":" << quote_json_string(parsed.capture_path.generic_string()) << ','
            << "\"legacy\":" << format_metrics_json(result.legacy_metrics) << ','
            << "\"unified\":" << format_metrics_json(result.unified_metrics) << ','
            << "\"session_parity\":" << (result.session_compare.parity ? "true" : "false") << ','
            << "\"session_mismatch_count\":" << result.session_compare.mismatch_count << ','
            << "\"packet_mismatch_count\":" << result.packet_compare.mismatch_count << ','
            << "\"first_divergence\":{"
            << "\"any\":";
        if (result.packet_compare.first_divergence.any_packet_index.has_value()) {
            json << *result.packet_compare.first_divergence.any_packet_index;
        } else {
            json << "null";
        }
        json << ",\"classification\":";
        if (result.packet_compare.first_divergence.classification_packet_index.has_value()) {
            json << *result.packet_compare.first_divergence.classification_packet_index;
        } else {
            json << "null";
        }
        json << ",\"physical_path\":";
        if (result.packet_compare.first_divergence.physical_path_packet_index.has_value()) {
            json << *result.packet_compare.first_divergence.physical_path_packet_index;
        } else {
            json << "null";
        }
        json << ",\"payload_length\":";
        if (result.packet_compare.first_divergence.payload_length_packet_index.has_value()) {
            json << *result.packet_compare.first_divergence.payload_length_packet_index;
        } else {
            json << "null";
        }
        json << "},\"groups\":[";
        for (std::size_t index = 0U; index < result.packet_compare.groups.size(); ++index) {
            if (index > 0U) {
                json << ',';
            }
            const auto& group = result.packet_compare.groups[index];
            json
                << "{"
                << "\"category\":" << quote_json_string(pfl::format_import_validation_packet_mismatch_category(group.category)) << ','
                << "\"occurrence_count\":" << group.occurrence_count << ','
                << "\"legacy_protocol\":" << static_cast<int>(group.legacy_protocol) << ','
                << "\"unified_protocol\":" << static_cast<int>(group.unified_protocol) << ','
                << "\"legacy_path\":" << quote_json_string(format_protocol_path_or_empty(group.legacy_path)) << ','
                << "\"unified_path\":" << quote_json_string(format_protocol_path_or_empty(group.unified_path)) << ','
                << "\"numeric_delta\":";
            if (group.numeric_delta.has_value()) {
                json << *group.numeric_delta;
            } else {
                json << "null";
            }
            json << ",\"packet_indices\":[";
            for (std::size_t packet_idx = 0U; packet_idx < group.packet_indices.size(); ++packet_idx) {
                if (packet_idx > 0U) {
                    json << ',';
                }
                json << group.packet_indices[packet_idx];
            }
            json
                << "],\"representative\":{"
                << "\"packet_index\":" << group.representative.packet_index << ','
                << "\"file_offset\":" << group.representative.file_offset << ','
                << "\"captured_length\":" << group.representative.captured_length << ','
                << "\"original_length\":" << group.representative.original_length << ','
                << "\"legacy_value\":" << quote_json_string(group.representative.legacy_value) << ','
                << "\"unified_value\":" << quote_json_string(group.representative.unified_value) << ','
                << "\"legacy_path\":" << quote_json_string(format_protocol_path_or_empty(group.representative.legacy_path)) << ','
                << "\"unified_path\":" << quote_json_string(format_protocol_path_or_empty(group.representative.unified_path))
                << "}}";
        }
        json << "]";
        if (result.legacy_packet.has_value() && result.unified_packet.has_value()) {
            json
                << ",\"legacy_packet\":" << format_packet_observation_json(*result.legacy_packet)
                << ",\"unified_packet\":" << format_packet_observation_json(*result.unified_packet);
        }
        json << "}";

        if (!write_json_file(*parsed.json_output_path, json.str())) {
            std::cerr << "Failed to write JSON output: " << parsed.json_output_path->generic_string() << '\n';
            return kExitCodeUsageOrImportFailure;
        }
    }

    return result.packet_compare.mismatch_count == 0U && result.session_compare.parity
        ? kExitCodeSuccess
        : kExitCodeMismatch;
}

int run_single_mode(const ParsedCommandLine& parsed, const bool unified_mode) {
    std::cout
        << "Mode: " << parsed.mode << '\n'
        << "Capture: " << parsed.capture_path.generic_string() << '\n'
        << "Hint snapshot comparison setting: " << (parsed.options.include_hints ? "enabled" : "disabled")
        << " (import hint execution remains production-compatible)\n";

    const auto result = unified_mode
        ? pfl::run_unified_import_validation(parsed.capture_path, parsed.options)
        : pfl::run_legacy_import_validation(parsed.capture_path, parsed.options);
    if (!result.success) {
        std::cerr << "Import validation failed: " << result.error_text << '\n';
        return kExitCodeUsageOrImportFailure;
    }

    print_metrics(unified_mode ? "Unified import" : "Legacy import", result.metrics);

    if (parsed.json_output_path.has_value()) {
        std::ostringstream json {};
        json
            << "{"
            << "\"mode\":" << quote_json_string(parsed.mode) << ','
            << "\"capture\":" << quote_json_string(parsed.capture_path.generic_string()) << ','
            << "\"parity\":null,"
            << "\"mismatch_count\":0,"
            << "\"metrics\":" << format_metrics_json(result.metrics)
            << "}";
        if (!write_json_file(*parsed.json_output_path, json.str())) {
            std::cerr << "Failed to write JSON output: " << parsed.json_output_path->generic_string() << '\n';
            return kExitCodeUsageOrImportFailure;
        }
    }

    return kExitCodeSuccess;
}

}  // namespace

int main(int argc, char* argv[]) {
    try {
        const auto parsed = parse_command_line(argc, argv);
        if (!parsed.valid) {
            print_usage();
            std::cerr << "Error: " << parsed.error_text << '\n';
            return kExitCodeUsageOrImportFailure;
        }

        if (parsed.mode == "compare") {
            return run_compare_mode(parsed);
        }
        if (parsed.mode == "diagnose") {
            return run_diagnose_mode(parsed);
        }

        return run_single_mode(parsed, parsed.mode == "unified");
    } catch (const std::exception& exception) {
        std::cerr << "Unhandled exception: " << exception.what() << '\n';
        return kExitCodeUsageOrImportFailure;
    } catch (...) {
        std::cerr << "Unhandled unknown exception\n";
        return kExitCodeUsageOrImportFailure;
    }
}
