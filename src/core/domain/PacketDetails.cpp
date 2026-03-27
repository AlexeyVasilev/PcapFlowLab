#include "core/domain/PacketDetails.h"

namespace pfl {

bool PacketDetails::empty() const noexcept {
    return !has_ethernet && !has_vlan && !has_linux_cooked && !has_arp && !has_ipv4 && !has_ipv6 && !has_tcp && !has_udp &&
           !has_icmp && !has_icmpv6;
}

}  // namespace pfl
