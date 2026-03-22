#pragma once

#include <cstdint>

namespace pfl {

struct CaptureSummary {
    std::uint64_t packet_count {0};
    std::uint64_t flow_count {0};
    std::uint64_t total_bytes {0};

    [[nodiscard]] bool empty() const noexcept;
};

}  // namespace pfl
