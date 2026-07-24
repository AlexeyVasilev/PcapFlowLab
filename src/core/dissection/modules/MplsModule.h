#pragma once

#include <cstddef>
#include <cstdint>

#include "core/dissection/DissectionRegistry.h"

namespace pfl::dissection {

inline constexpr std::uint32_t kMplsStackContinueSelectorValue = 0U;

struct ParsedMplsLabel {
    ParseStatus status {ParseStatus::opaque};
    std::uint32_t label {0U};
    std::uint8_t traffic_class {0U};
    bool bottom_of_stack {false};
    std::uint8_t ttl {0U};
    std::size_t header_length {0U};
    std::size_t declared_payload_length {0U};
};

[[nodiscard]] ParsedMplsLabel parse_mpls_label(const PacketSlice& slice) noexcept;
[[nodiscard]] DissectionStep dissect_mpls_label(const PacketSlice& slice);

}  // namespace pfl::dissection
