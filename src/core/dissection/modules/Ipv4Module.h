#pragma once

#include <cstddef>
#include <cstdint>

#include "core/dissection/DissectionRegistry.h"

namespace pfl::dissection {

struct ParsedIpv4Packet {
    ParseStatus status {ParseStatus::opaque};
    std::uint8_t protocol {0U};
    std::uint16_t total_length {0U};
    std::size_t header_length {0U};
    std::size_t nominal_packet_end {0U};
    std::size_t packet_end {0U};
    std::uint32_t src_addr {0U};
    std::uint32_t dst_addr {0U};
    std::uint16_t flags_fragment {0U};
    bool bounds_from_captured_bytes {false};
    bool is_fragmented {false};
    bool more_fragments {false};
    std::uint16_t fragment_offset_units {0U};
};

[[nodiscard]] ParsedIpv4Packet parse_ipv4_packet(const PacketSlice& slice) noexcept;
[[nodiscard]] DissectionStep dissect_ipv4(const PacketSlice& slice);

}  // namespace pfl::dissection
