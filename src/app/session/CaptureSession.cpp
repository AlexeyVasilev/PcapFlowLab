#include "app/session/CaptureSession.h"

#include "core/io/CaptureFilePacketReader.h"
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

std::vector<std::uint8_t> CaptureSession::read_packet_data(const PacketRef& packet) const {
    if (!has_capture()) {
        return {};
    }

    CaptureFilePacketReader reader {capture_path_};
    if (!reader.is_open()) {
        return {};
    }

    return reader.read_packet_data(packet);
}

CaptureState& CaptureSession::state() noexcept {
    return state_;
}

const CaptureState& CaptureSession::state() const noexcept {
    return state_;
}

}  // namespace pfl
