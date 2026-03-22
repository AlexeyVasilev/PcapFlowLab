#pragma once

#include <cstddef>
#include <cstdint>
#include <variant>

#include "core/domain/ConnectionKey.h"

namespace pfl {

enum class FlowAddressFamily : std::uint8_t {
    ipv4,
    ipv6
};

using FlowConnectionKey = std::variant<ConnectionKeyV4, ConnectionKeyV6>;

struct FlowRow {
    std::size_t index {0};
    FlowAddressFamily family {FlowAddressFamily::ipv4};
    FlowConnectionKey key {ConnectionKeyV4 {}};
    std::uint64_t packet_count {0};
    std::uint64_t total_bytes {0};
};

}  // namespace pfl
