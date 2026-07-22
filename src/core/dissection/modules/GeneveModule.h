#pragma once

#include <cstddef>
#include <cstdint>

#include "core/dissection/DissectionRegistry.h"

namespace pfl::dissection {

inline constexpr std::uint32_t kGeneveInnerFrameSelectorValue = 0U;
inline constexpr std::uint32_t kGeneveInnerIeee8023PayloadSelectorValue = 0U;

struct ParsedGeneveHeader {
    ParseStatus status {ParseStatus::opaque};
    std::uint8_t version {0U};
    std::uint8_t option_length_words {0U};
    bool oam_flag {false};
    bool critical_flag {false};
    std::uint8_t reserved_control_bits {0U};
    std::uint16_t protocol_type {0U};
    std::uint32_t vni {0U};
    std::uint8_t reserved_trailer_byte {0U};
    std::size_t header_length {0U};
    std::size_t declared_payload_length {0U};
};

[[nodiscard]] ParsedGeneveHeader parse_geneve_header(const PacketSlice& slice) noexcept;
[[nodiscard]] DissectionStep dissect_geneve(const PacketSlice& slice);
[[nodiscard]] DissectionStep dissect_geneve_inner_ethernet(const PacketSlice& slice);
[[nodiscard]] DissectionStep dissect_geneve_inner_vlan(const PacketSlice& slice);
[[nodiscard]] DissectionStep dissect_geneve_inner_llc_snap(const PacketSlice& slice);
[[nodiscard]] DissectionStep dissect_geneve_inner_ipv4(const PacketSlice& slice);
[[nodiscard]] DissectionStep dissect_geneve_inner_ipv6(const PacketSlice& slice);

}  // namespace pfl::dissection
