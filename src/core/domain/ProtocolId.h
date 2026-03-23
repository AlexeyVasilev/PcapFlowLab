#pragma once

#include <cstdint>

namespace pfl {

enum class ProtocolId : std::uint8_t {
    unknown = 0,
    icmp = 1,
    tcp = 6,
    udp = 17,
    icmpv6 = 58,
    arp = 253,
};

}  // namespace pfl
