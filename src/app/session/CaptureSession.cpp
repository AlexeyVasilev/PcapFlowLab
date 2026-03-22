#include "app/session/CaptureSession.h"

namespace pfl {

bool CaptureSession::open_capture(const std::filesystem::path& path) {
    capture_path_ = path;
    state_ = {};
    return !capture_path_.empty();
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
