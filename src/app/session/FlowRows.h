#pragma once

#include <cstdint>

#include "core/domain/ConnectionKey.h"

namespace pfl {

struct FlowRowV4 {
    ConnectionKeyV4 key {};
    std::uint64_t packet_count {0};
    std::uint64_t total_bytes {0};
};

struct FlowRowV6 {
    ConnectionKeyV6 key {};
    std::uint64_t packet_count {0};
    std::uint64_t total_bytes {0};
};

}  // namespace pfl
