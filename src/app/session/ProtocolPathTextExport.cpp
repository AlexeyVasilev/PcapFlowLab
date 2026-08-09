#include "app/session/ProtocolPathTextExport.h"

#include <algorithm>
#include <fstream>
#include <sstream>
#include <string_view>
#include <vector>

namespace pfl::session_detail {
namespace {

std::string make_indented_layer_text(const CaptureProtocolPathSummary& summary, const ProtocolPathStatisticsRow& row) {
    const std::string_view base_text = !row.layer_text.empty()
        ? std::string_view {row.layer_text}
        : std::string_view {row.path_text};
    if (summary.mode == ProtocolPathStatisticsMode::terminal_paths) {
        return std::string {base_text};
    }

    return std::string(row.depth * 2U, ' ') + std::string {base_text};
}

std::string pad_right(const std::string_view text, const std::size_t width) {
    if (text.size() >= width) {
        return std::string {text};
    }
    return std::string {text} + std::string(width - text.size(), ' ');
}

std::string pad_left(const std::string_view text, const std::size_t width) {
    if (text.size() >= width) {
        return std::string {text};
    }
    return std::string(width - text.size(), ' ') + std::string {text};
}

}  // namespace

std::string protocol_path_statistics_mode_text(const ProtocolPathStatisticsMode mode) {
    switch (mode) {
    case ProtocolPathStatisticsMode::identity_tree:
        return "Identity tree";
    case ProtocolPathStatisticsMode::terminal_paths:
        return "Terminal paths";
    case ProtocolPathStatisticsMode::kind_overview:
    default:
        return "Kind overview";
    }
}

std::string format_protocol_path_tree_text(const CaptureProtocolPathSummary& summary) {
    constexpr std::string_view layer_header = "Layer";
    constexpr std::string_view flows_header = "Flows";
    constexpr std::string_view packets_header = "Packets";
    constexpr std::string_view original_bytes_header = "Original Bytes";

    std::vector<std::string> layer_cells {};
    layer_cells.reserve(summary.rows.size());

    std::size_t layer_width = layer_header.size();
    std::size_t flows_width = flows_header.size();
    std::size_t packets_width = packets_header.size();
    std::size_t original_bytes_width = original_bytes_header.size();

    for (const auto& row : summary.rows) {
        layer_cells.push_back(make_indented_layer_text(summary, row));
        layer_width = std::max(layer_width, layer_cells.back().size());
        flows_width = std::max(flows_width, row.flow_count_text.size());
        packets_width = std::max(packets_width, row.packet_count_text.size());
        original_bytes_width = std::max(original_bytes_width, row.original_byte_count_text.size());
    }

    std::ostringstream out {};
    out << "Protocol Path Tree\n";
    out << "Mode: " << protocol_path_statistics_mode_text(summary.mode) << "\n\n";
    out << pad_right(layer_header, layer_width) << "  "
        << pad_left(flows_header, flows_width) << "  "
        << pad_left(packets_header, packets_width) << "  "
        << pad_left(original_bytes_header, original_bytes_width) << '\n';

    for (std::size_t index = 0; index < summary.rows.size(); ++index) {
        const auto& row = summary.rows[index];
        out << pad_right(layer_cells[index], layer_width) << "  "
            << pad_left(row.flow_count_text, flows_width) << "  "
            << pad_left(row.packet_count_text, packets_width) << "  "
            << pad_left(row.original_byte_count_text, original_bytes_width) << '\n';
    }

    return out.str();
}

bool export_protocol_path_tree_text(
    const CaptureProtocolPathSummary& summary,
    const std::filesystem::path& output_path,
    const TextExportOverwritePolicy overwrite_policy,
    std::string* out_error_text
) {
    if (output_path.empty()) {
        if (out_error_text != nullptr) {
            *out_error_text = "No output file selected.";
        }
        return false;
    }

    std::error_code exists_error {};
    const bool path_exists = std::filesystem::exists(output_path, exists_error);
    if (exists_error) {
        if (out_error_text != nullptr) {
            *out_error_text = "Failed to inspect Protocol Path Tree export path: " + exists_error.message();
        }
        return false;
    }
    if (path_exists && overwrite_policy == TextExportOverwritePolicy::fail_if_exists) {
        if (out_error_text != nullptr) {
            *out_error_text = "Output file already exists.";
        }
        return false;
    }

    std::ofstream stream {output_path, std::ios::binary | std::ios::trunc};
    if (!stream.is_open()) {
        if (out_error_text != nullptr) {
            *out_error_text = "Failed to create Protocol Path Tree export file.";
        }
        return false;
    }

    const auto text = format_protocol_path_tree_text(summary);
    stream.write(text.data(), static_cast<std::streamsize>(text.size()));
    if (!stream.good()) {
        if (out_error_text != nullptr) {
            *out_error_text = "Failed to write Protocol Path Tree export file.";
        }
        return false;
    }

    return true;
}

}  // namespace pfl::session_detail
