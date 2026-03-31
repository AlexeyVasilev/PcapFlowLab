#include "core/services/DeepCaptureImporter.h"

#include "core/services/CaptureImportProcessor.h"

namespace pfl {

CaptureImportResult DeepCaptureImporter::import_capture(const std::filesystem::path& path,
                                                        CaptureState& state,
                                                        const CaptureImportOptions& options,
                                                        OpenContext* ctx) const {
    state = {};

    // Deep import currently reuses the same base decode and aggregation path as fast import.
    // It remains a distinct integration point for future expensive protocol analyzers and reassembly.
    CaptureImportProcessor processor {options.settings};
    return import_capture_from_path(path, state, processor, ctx);
}

}  // namespace pfl
