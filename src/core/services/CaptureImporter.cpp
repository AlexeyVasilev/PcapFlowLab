#include "core/services/CaptureImporter.h"

#include "core/services/DeepCaptureImporter.h"
#include "core/services/FastCaptureImporter.h"

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
    switch (options.mode) {
    case ImportMode::fast: {
        FastCaptureImporter importer {};
        return importer.import_capture(path, state, options, ctx);
    }
    case ImportMode::deep: {
        DeepCaptureImporter importer {};
        return importer.import_capture(path, state, options, ctx);
    }
    }

    return CaptureImportResult::failure;
}

}  // namespace pfl
