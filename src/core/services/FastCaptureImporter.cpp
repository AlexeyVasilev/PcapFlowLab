#include "core/services/FastCaptureImporter.h"

#include "core/services/CaptureImportProcessor.h"

namespace pfl {

bool FastCaptureImporter::import_capture(const std::filesystem::path& path, CaptureState& state) const {
    state = {};

    CaptureImportProcessor processor {};
    return import_capture_from_path(path, state, processor);
}

}  // namespace pfl
