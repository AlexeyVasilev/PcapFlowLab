#pragma once

#include <cstddef>
#include <cstdint>

#include "core/dissection/DissectionRegistry.h"

namespace pfl::dissection {

inline constexpr std::uint32_t kEoipInnerFrameSelectorValue = 0U;
inline constexpr std::uint32_t kEoipInnerIeee8023PayloadSelectorValue = 0U;

struct ParsedEoipFrame {
    ParseStatus status {ParseStatus::opaque};
    std::uint16_t gre_flags_and_version {0U};
    std::uint16_t gre_protocol_type {0U};
    std::uint16_t frame_length {0U};
    std::uint16_t tunnel_id {0U};
    std::size_t header_length {0U};
    std::size_t declared_payload_length {0U};
};

[[nodiscard]] ParsedEoipFrame parse_eoip_frame(const PacketSlice& slice) noexcept;
[[nodiscard]] DissectionStep dissect_ipv4_gre_variant(const PacketSlice& slice);
[[nodiscard]] DissectionStep dissect_eoip(const PacketSlice& slice);
[[nodiscard]] DissectionStep dissect_eoip_inner_ethernet(const PacketSlice& slice);
[[nodiscard]] DissectionStep dissect_eoip_inner_vlan(const PacketSlice& slice);
[[nodiscard]] DissectionStep dissect_eoip_inner_llc_snap(const PacketSlice& slice);
[[nodiscard]] DissectionStep dissect_eoip_inner_ipv4(const PacketSlice& slice);
[[nodiscard]] DissectionStep dissect_eoip_inner_ipv6(const PacketSlice& slice);

}  // namespace pfl::dissection
