#pragma once

#include <filesystem>

#include "core/domain/CaptureSummary.h"

namespace pfl {

class CaptureSession {
public:
    bool open_capture(const std::filesystem::path& path);
    [[nodiscard]] bool has_capture() const noexcept;
    [[nodiscard]] const CaptureSummary& summary() const noexcept;

private:
    std::filesystem::path capture_path_ {};
    CaptureSummary summary_ {};
};

}  // namespace pfl
