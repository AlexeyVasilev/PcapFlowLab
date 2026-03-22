#pragma once

#include <cstdint>
#include <vector>

#include "core/domain/FlowKey.h"
#include "core/domain/PacketRef.h"

namespace pfl {

struct FlowV4 {
    FlowKeyV4 key {};
    std::vector<PacketRef> packets {};
    std::uint64_t packet_count {0};
    std::uint64_t total_bytes {0};

    [[nodiscard]] bool empty() const noexcept;
};

struct FlowV6 {
    FlowKeyV6 key {};
    std::vector<PacketRef> packets {};
    std::uint64_t packet_count {0};
    std::uint64_t total_bytes {0};

    [[nodiscard]] bool empty() const noexcept;
};

}  // namespace pfl
