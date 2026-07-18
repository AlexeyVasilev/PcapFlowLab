#pragma once

#include <filesystem>

#include "core/domain/CaptureState.h"
#include "core/services/AnalysisSettings.h"

struct OpenContext;

namespace pfl {

enum class CaptureImportResult : std::uint8_t {
    success,
    partial_success_with_warning,
    failure,
};

struct CaptureImportOptions {
    AnalysisSettings settings {};
};

class CaptureImporter {
public:
    bool import_capture(const std::filesystem::path& path, CaptureState& state);
    bool import_capture(const std::filesystem::path& path, CaptureState& state, OpenContext* ctx);
    bool import_capture(const std::filesystem::path& path, CaptureState& state, const CaptureImportOptions& options);
    bool import_capture(const std::filesystem::path& path, CaptureState& state, const CaptureImportOptions& options, OpenContext* ctx);
    CaptureImportResult import_capture_result(const std::filesystem::path& path, CaptureState& state);
    CaptureImportResult import_capture_result(const std::filesystem::path& path, CaptureState& state, OpenContext* ctx);
    CaptureImportResult import_capture_result(const std::filesystem::path& path, CaptureState& state, const CaptureImportOptions& options);
    CaptureImportResult import_capture_result(const std::filesystem::path& path, CaptureState& state, const CaptureImportOptions& options, OpenContext* ctx);
};

}  // namespace pfl
