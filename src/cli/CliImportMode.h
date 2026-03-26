#pragma once

#include <optional>
#include <string_view>

#include "core/services/CaptureImporter.h"

namespace pfl {

inline constexpr int kCliFastImportModeIndex = 0;
inline constexpr int kCliDeepImportModeIndex = 1;

inline std::optional<ImportMode> parse_import_mode_value(const std::string_view value) {
    if (value == "fast") {
        return ImportMode::fast;
    }

    if (value == "deep") {
        return ImportMode::deep;
    }

    return std::nullopt;
}

inline CaptureImportOptions capture_import_options_for_ui_index(const int mode_index) {
    return CaptureImportOptions {
        .mode = (mode_index == kCliDeepImportModeIndex) ? ImportMode::deep : ImportMode::fast,
    };
}

}  // namespace pfl
