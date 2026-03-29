#include "core/services/CaptureImporter.h"

#include "core/services/DeepCaptureImporter.h"
#include "core/services/FastCaptureImporter.h"

namespace pfl {

bool CaptureImporter::import_capture(const std::filesystem::path& path, CaptureState& state) {
    return import_capture(path, state, CaptureImportOptions {}, nullptr);
}

bool CaptureImporter::import_capture(const std::filesystem::path& path, CaptureState& state, OpenContext* ctx) {
    return import_capture(path, state, CaptureImportOptions {}, ctx);
}

bool CaptureImporter::import_capture(const std::filesystem::path& path,
                                     CaptureState& state,
                                     const CaptureImportOptions& options) {
    return import_capture(path, state, options, nullptr);
}

bool CaptureImporter::import_capture(const std::filesystem::path& path,
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

    return false;
}

}  // namespace pfl

