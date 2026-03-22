#pragma once

#include <filesystem>

#include "core/domain/CaptureState.h"

namespace pfl {

class CaptureImporter {
public:
    bool import_capture(const std::filesystem::path& path, CaptureState& state);
};

}  // namespace pfl
