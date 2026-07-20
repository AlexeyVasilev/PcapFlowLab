#pragma once

#include <cstddef>
#include <cstdint>

#include "core/dissection/DissectionRegistry.h"

namespace pfl::dissection {

struct ParsedLinuxCookedFrame {
    ParseStatus status {ParseStatus::opaque};
    bool is_sll2 {false};
    std::uint16_t protocol_type {0U};
    std::uint16_t packet_type {0U};
    std::uint16_t hardware_type {0U};
    std::uint16_t address_length {0U};
    std::uint16_t reserved {0U};
    std::uint32_t interface_index {0U};
    std::size_t header_length {0U};
    std::size_t declared_payload_length {0U};
};

[[nodiscard]] ParsedLinuxCookedFrame parse_linux_sll_frame(const PacketSlice& slice) noexcept;
[[nodiscard]] ParsedLinuxCookedFrame parse_linux_sll2_frame(const PacketSlice& slice) noexcept;

[[nodiscard]] DissectionStep dissect_linux_sll(const PacketSlice& slice);
[[nodiscard]] DissectionStep dissect_linux_sll2(const PacketSlice& slice);
[[nodiscard]] DissectionStep dissect_linux_cooked_arp(const PacketSlice& slice);

}  // namespace pfl::dissection
