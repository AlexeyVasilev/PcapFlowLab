#pragma once

#include <filesystem>

#include "core/domain/CaptureState.h"

namespace pfl {

class FastCaptureImporter {
public:
    [[nodiscard]] bool import_capture(const std::filesystem::path& path, CaptureState& state) const;
};

}  // namespace pfl
