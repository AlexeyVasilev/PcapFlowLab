#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "core/dissection/DissectionRegistry.h"

namespace pfl::dissection {

struct ParsedIpv6Packet {
    ParseStatus status {ParseStatus::opaque};
    std::uint8_t next_header {0U};
    std::uint16_t payload_length {0U};
    std::size_t header_length {0U};
    std::size_t nominal_packet_end {0U};
    std::size_t packet_end {0U};
    std::array<std::uint8_t, 16> src_addr {};
    std::array<std::uint8_t, 16> dst_addr {};
};

[[nodiscard]] ParsedIpv6Packet parse_ipv6_packet(const PacketSlice& slice) noexcept;
[[nodiscard]] DissectionStep dissect_ipv6(const PacketSlice& slice);

}  // namespace pfl::dissection
