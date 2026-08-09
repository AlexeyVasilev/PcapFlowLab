#pragma once

#include <filesystem>
#include <string>

#include "app/frontend/FrontendDtos.h"

namespace pfl {

struct FrontendSettingsJsonParseResult {
    bool ok {false};
    FrontendSettingsDto settings {};
    std::string error_text {};
};

[[nodiscard]] FrontendSettingsJsonParseResult parse_frontend_settings_json_file(
    const std::filesystem::path& path
);

}  // namespace pfl
