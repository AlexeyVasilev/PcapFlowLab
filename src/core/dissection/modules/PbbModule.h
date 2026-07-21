#pragma once

#include <cstddef>
#include <cstdint>

#include "core/dissection/DissectionRegistry.h"

namespace pfl::dissection {

inline constexpr std::uint32_t kPbbInnerFrameSelectorValue = 0U;

struct ParsedPbbFrame {
    ParseStatus status {ParseStatus::opaque};
    std::uint8_t pcp {0U};
    bool dei {false};
    bool nca {false};
    std::uint8_t reserved {0U};
    std::uint32_t isid {0U};
    std::size_t header_length {0U};
    std::size_t declared_payload_length {0U};
};

[[nodiscard]] ParsedPbbFrame parse_pbb_frame(const PacketSlice& slice) noexcept;
[[nodiscard]] DissectionStep dissect_pbb(const PacketSlice& slice);
[[nodiscard]] DissectionStep dissect_pbb_inner_ethernet(const PacketSlice& slice);
[[nodiscard]] DissectionStep dissect_pbb_inner_vlan(const PacketSlice& slice);

}  // namespace pfl::dissection
