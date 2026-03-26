#include "core/services/CaptureImporter.h"

#include "core/services/DeepCaptureImporter.h"
#include "core/services/FastCaptureImporter.h"

namespace pfl {

bool CaptureImporter::import_capture(const std::filesystem::path& path, CaptureState& state) {
    return import_capture(path, state, CaptureImportOptions {});
}

bool CaptureImporter::import_capture(const std::filesystem::path& path,
                                     CaptureState& state,
                                     const CaptureImportOptions& options) {
    switch (options.mode) {
    case ImportMode::fast: {
        FastCaptureImporter importer {};
        return importer.import_capture(path, state);
    }
    case ImportMode::deep: {
        DeepCaptureImporter importer {};
        return importer.import_capture(path, state);
    }
    }

    return false;
}

}  // namespace pfl
