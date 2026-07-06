#pragma once

#include <cstdint>

namespace pfl {

enum class ProtocolId : std::uint8_t {
    unknown = 0,
    icmp = 1,
    igmp = 2,
    tcp = 6,
    udp = 17,
    icmpv6 = 58,
    sctp = 132,
    arp = 253,
};

}  // namespace pfl
