#pragma once

#include <filesystem>

#include "core/domain/CaptureState.h"
#include "core/index/CaptureIndex.h"

struct OpenContext;

namespace pfl {

class CaptureIndexReader {
public:
    bool read(const std::filesystem::path& index_path,
              CaptureState& out_state,
              std::filesystem::path& out_source_capture_path,
              CaptureSourceInfo* out_source_info = nullptr,
              OpenContext* ctx = nullptr) const;
};

}  // namespace pfl
