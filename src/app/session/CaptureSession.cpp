#include "app/session/CaptureSession.h"

#include "core/services/CaptureImporter.h"

namespace pfl {

bool CaptureSession::open_capture(const std::filesystem::path& path) {
    CaptureImporter importer {};
    CaptureState imported_state {};

    if (!importer.import_pcap(path, imported_state)) {
        capture_path_.clear();
        state_ = {};
        return false;
    }

    capture_path_ = path;
    state_ = imported_state;
    return true;
}

bool CaptureSession::has_capture() const noexcept {
    return !capture_path_.empty();
}

const CaptureSummary& CaptureSession::summary() const noexcept {
    return state_.summary;
}

CaptureState& CaptureSession::state() noexcept {
    return state_;
}

const CaptureState& CaptureSession::state() const noexcept {
    return state_;
}

}  // namespace pfl
