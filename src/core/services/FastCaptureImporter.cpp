#include "core/services/FastCaptureImporter.h"

#include "core/services/CaptureImportProcessor.h"

namespace pfl {

CaptureImportResult FastCaptureImporter::import_capture(const std::filesystem::path& path,
                                                        CaptureState& state,
                                                        const CaptureImportOptions& options,
                                                        OpenContext* ctx) const {
    state = {};

    CaptureImportProcessor processor {options.settings, false};
    return import_capture_from_path(path, state, processor, ctx);
}

}  // namespace pfl
