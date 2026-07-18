#pragma once

#include <cstddef>
#include <cstdint>

#include "core/dissection/DissectionRegistry.h"

namespace pfl::dissection {

struct ParsedEthernetFrame {
    ParseStatus status {ParseStatus::opaque};
    std::uint16_t protocol_type {0U};
    std::size_t header_length {0U};
    std::size_t declared_payload_length {0U};
    bool is_ieee_802_3 {false};
};

struct ParsedVlanTag {
    ParseStatus status {ParseStatus::opaque};
    std::uint16_t tci {0U};
    std::uint16_t encapsulated_ether_type {0U};
    std::size_t header_length {0U};
    std::size_t declared_payload_length {0U};
};

[[nodiscard]] ParsedEthernetFrame parse_ethernet_frame(const PacketSlice& slice) noexcept;
[[nodiscard]] ParsedVlanTag parse_vlan_tag(const PacketSlice& slice) noexcept;

[[nodiscard]] DissectionStep dissect_ethernet(const PacketSlice& slice);
[[nodiscard]] DissectionStep dissect_vlan(const PacketSlice& slice);

}  // namespace pfl::dissection
