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
        << "  pcap_flow_lab_import_validation compare <capture> [--max-packets N] [--no-hints] [--json <output-file>]\n"
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
    if (parsed.mode != "compare" && parsed.mode != "legacy" && parsed.mode != "unified") {
        parsed.valid = false;
        parsed.error_text = "mode must be one of: compare, legacy, unified";
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
        << "Mismatch count: " << result.mismatch_count << '\n';

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
            << "\"mismatches\":[";
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

        return run_single_mode(parsed, parsed.mode == "unified");
    } catch (const std::exception& exception) {
        std::cerr << "Unhandled exception: " << exception.what() << '\n';
        return kExitCodeUsageOrImportFailure;
    } catch (...) {
        std::cerr << "Unhandled unknown exception\n";
        return kExitCodeUsageOrImportFailure;
    }
}
