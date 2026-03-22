#pragma once

#include <filesystem>
#include <vector>

#include "core/domain/CaptureState.h"

namespace pfl {

class CaptureSession {
public:
    bool open_capture(const std::filesystem::path& path);
    [[nodiscard]] bool has_capture() const noexcept;
    [[nodiscard]] const CaptureSummary& summary() const noexcept;
    [[nodiscard]] std::vector<std::uint8_t> read_packet_data(const PacketRef& packet) const;
    [[nodiscard]] CaptureState& state() noexcept;
    [[nodiscard]] const CaptureState& state() const noexcept;

private:
    std::filesystem::path capture_path_ {};
    CaptureState state_ {};
};

}  // namespace pfl
