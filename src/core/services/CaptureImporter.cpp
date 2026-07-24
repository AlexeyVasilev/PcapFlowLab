#include "core/services/CaptureImporter.h"

#include "core/services/CaptureImportProcessor.h"

namespace pfl {

bool CaptureImporter::import_capture(const std::filesystem::path& path, CaptureState& state) {
    return import_capture_result(path, state, CaptureImportOptions {}, nullptr) != CaptureImportResult::failure;
}

bool CaptureImporter::import_capture(const std::filesystem::path& path, CaptureState& state, OpenContext* ctx) {
    return import_capture_result(path, state, CaptureImportOptions {}, ctx) != CaptureImportResult::failure;
}

bool CaptureImporter::import_capture(const std::filesystem::path& path,
                                     CaptureState& state,
                                     const CaptureImportOptions& options) {
    return import_capture_result(path, state, options, nullptr) != CaptureImportResult::failure;
}

bool CaptureImporter::import_capture(const std::filesystem::path& path,
                                     CaptureState& state,
                                     const CaptureImportOptions& options,
                                     OpenContext* ctx) {
    return import_capture_result(path, state, options, ctx) != CaptureImportResult::failure;
}

CaptureImportResult CaptureImporter::import_capture_result(const std::filesystem::path& path, CaptureState& state) {
    return import_capture_result(path, state, CaptureImportOptions {}, nullptr);
}

CaptureImportResult CaptureImporter::import_capture_result(const std::filesystem::path& path, CaptureState& state, OpenContext* ctx) {
    return import_capture_result(path, state, CaptureImportOptions {}, ctx);
}

CaptureImportResult CaptureImporter::import_capture_result(const std::filesystem::path& path,
                                                           CaptureState& state,
                                                           const CaptureImportOptions& options) {
    return import_capture_result(path, state, options, nullptr);
}

CaptureImportResult CaptureImporter::import_capture_result(const std::filesystem::path& path,
                                                           CaptureState& state,
                                                           const CaptureImportOptions& options,
                                                           OpenContext* ctx) {
    state = {};
    CaptureImportProcessor processor {options.settings};
    return import_capture_from_path(path, state, processor, ctx);
}

}  // namespace pfl
