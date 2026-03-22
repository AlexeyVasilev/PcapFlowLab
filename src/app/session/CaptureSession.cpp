#include "app/session/CaptureSession.h"

namespace pfl {

bool CaptureSession::open_capture(const std::filesystem::path& path) {
    capture_path_ = path;
    summary_ = {};
    return !capture_path_.empty();
}

bool CaptureSession::has_capture() const noexcept {
    return !capture_path_.empty();
}

const CaptureSummary& CaptureSession::summary() const noexcept {
    return summary_;
}

}  // namespace pfl
