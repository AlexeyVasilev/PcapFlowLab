#pragma once

#include <cstdint>

namespace pfl {

enum class ProtocolId : std::uint8_t {
    unknown = 0,
    tcp = 6,
    udp = 17
};

}  // namespace pfl
