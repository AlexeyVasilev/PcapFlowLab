#pragma once

#include <cstddef>
#include <cstdint>

#include "core/dissection/DissectionRegistry.h"

namespace pfl::dissection {

inline constexpr std::uint32_t kVxlanInnerFrameSelectorValue = 0U;
inline constexpr std::uint32_t kVxlanInnerIeee8023PayloadSelectorValue = 0U;

struct ParsedVxlanHeader {
    ParseStatus status {ParseStatus::opaque};
    std::uint8_t flags {0U};
    std::uint32_t vni {0U};
    std::size_t header_length {0U};
    std::size_t declared_payload_length {0U};
};

[[nodiscard]] ParsedVxlanHeader parse_vxlan_header(const PacketSlice& slice) noexcept;
[[nodiscard]] DissectionStep dissect_vxlan(const PacketSlice& slice);
[[nodiscard]] DissectionStep dissect_vxlan_inner_ethernet(const PacketSlice& slice);
[[nodiscard]] DissectionStep dissect_vxlan_inner_vlan(const PacketSlice& slice);
[[nodiscard]] DissectionStep dissect_vxlan_inner_llc_snap(const PacketSlice& slice);
[[nodiscard]] DissectionStep dissect_vxlan_inner_ipv4(const PacketSlice& slice);
[[nodiscard]] DissectionStep dissect_vxlan_inner_ipv6(const PacketSlice& slice);

}  // namespace pfl::dissection
