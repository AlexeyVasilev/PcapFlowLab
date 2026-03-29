#pragma once

#include <filesystem>

#include "core/domain/CaptureState.h"
#include "core/services/CaptureImporter.h"

namespace pfl {

class FastCaptureImporter {
public:
    [[nodiscard]] bool import_capture(const std::filesystem::path& path,
                                      CaptureState& state,
                                      const CaptureImportOptions& options,
                                      OpenContext* ctx = nullptr) const;
};

}  // namespace pfl

