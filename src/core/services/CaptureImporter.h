#pragma once

#include <cstdint>
#include <filesystem>

#include "core/domain/CaptureState.h"
#include "core/services/AnalysisSettings.h"

struct OpenContext;

namespace pfl {

enum class ImportMode : std::uint8_t {
    fast,
    deep,
};

struct CaptureImportOptions {
    ImportMode mode {ImportMode::fast};
    AnalysisSettings settings {};
};

class CaptureImporter {
public:
    bool import_capture(const std::filesystem::path& path, CaptureState& state);
    bool import_capture(const std::filesystem::path& path, CaptureState& state, OpenContext* ctx);
    bool import_capture(const std::filesystem::path& path, CaptureState& state, const CaptureImportOptions& options);
    bool import_capture(const std::filesystem::path& path, CaptureState& state, const CaptureImportOptions& options, OpenContext* ctx);
};

}  // namespace pfl

