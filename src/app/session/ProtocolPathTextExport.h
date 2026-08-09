#pragma once

#include <cstdint>
#include <filesystem>
#include <string>

#include "app/session/FlowRows.h"

namespace pfl::session_detail {

enum class TextExportOverwritePolicy : std::uint8_t {
    fail_if_exists = 0,
    overwrite_existing = 1,
};

[[nodiscard]] std::string protocol_path_statistics_mode_text(ProtocolPathStatisticsMode mode);

[[nodiscard]] std::string format_protocol_path_tree_text(const CaptureProtocolPathSummary& summary);

[[nodiscard]] bool export_protocol_path_tree_text(
    const CaptureProtocolPathSummary& summary,
    const std::filesystem::path& output_path,
    TextExportOverwritePolicy overwrite_policy,
    std::string* out_error_text = nullptr
);

}  // namespace pfl::session_detail
