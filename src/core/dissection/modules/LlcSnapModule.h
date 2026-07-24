#pragma once

#include <cstddef>
#include <cstdint>

#include "core/dissection/DissectionRegistry.h"

namespace pfl::dissection {

inline constexpr std::uint32_t kIeee8023PayloadSelectorValue = 0U;

struct ParsedLlcSnapPayload {
    ParseStatus status {ParseStatus::opaque};
    std::uint8_t dsap {0U};
    std::uint8_t ssap {0U};
    std::uint8_t control {0U};
    bool has_snap {false};
    std::uint32_t oui {0U};
    std::uint16_t pid {0U};
    bool pid_supported {false};
    std::size_t header_length {0U};
};

[[nodiscard]] ParsedLlcSnapPayload parse_llc_snap_payload(const PacketSlice& slice) noexcept;
[[nodiscard]] DissectionStep dissect_llc_snap(const PacketSlice& slice);

}  // namespace pfl::dissection
