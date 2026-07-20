#pragma once

#include <cstddef>
#include <cstdint>

#include "core/dissection/DissectionRegistry.h"

namespace pfl::dissection {

inline constexpr std::uint32_t kPppFrameContinueSelectorValue = 1U;

struct ParsedPppoeFrame {
    ParseStatus status {ParseStatus::opaque};
    std::uint8_t version {0U};
    std::uint8_t type {0U};
    std::uint8_t code {0U};
    std::uint16_t session_id {0U};
    std::uint16_t payload_length {0U};
    bool is_discovery {false};
    bool declared_payload_exceeds_capture {false};
    bool captured_payload_exceeds_declared {false};
    std::size_t header_length {0U};
    std::size_t declared_payload_length {0U};
    std::size_t logical_payload_length {0U};
};

struct ParsedPppFrame {
    ParseStatus status {ParseStatus::opaque};
    std::uint16_t protocol {0U};
    std::size_t header_length {0U};
    std::size_t declared_payload_length {0U};
};

[[nodiscard]] ParsedPppoeFrame parse_pppoe_frame(
    const PacketSlice& slice,
    bool discovery_entry
) noexcept;
[[nodiscard]] ParsedPppFrame parse_ppp_frame(const PacketSlice& slice) noexcept;

[[nodiscard]] DissectionStep dissect_pppoe_discovery(const PacketSlice& slice);
[[nodiscard]] DissectionStep dissect_pppoe_session(const PacketSlice& slice);
[[nodiscard]] DissectionStep dissect_ppp(const PacketSlice& slice);
[[nodiscard]] DissectionStep dissect_ppp_control(const PacketSlice& slice);

}  // namespace pfl::dissection
