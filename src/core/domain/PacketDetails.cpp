#include "core/domain/PacketDetails.h"

namespace pfl {

bool PacketDetails::empty() const noexcept {
    return !has_ethernet && !has_vlan && !has_linux_cooked && !has_llc && !has_snap && !has_mpls &&
           !has_pbb && !has_mpls_pseudowire_control_word && !has_inner_ethernet && !has_unknown_inner_ethernet_payload &&
           !has_pppoe && !has_arp && !has_ipv4 && !has_ipv6 &&
           !has_tcp && !has_udp && !has_icmp && !has_icmpv6 && !has_igmp;
}

}  // namespace pfl
