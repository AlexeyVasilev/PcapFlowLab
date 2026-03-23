#pragma once

#include <filesystem>

#include "core/domain/CaptureState.h"

namespace pfl {

class CaptureIndexWriter {
public:
    bool write(const std::filesystem::path& index_path,
               const CaptureState& state,
               const std::filesystem::path& source_capture_path) const;
};

}  // namespace pfl
