#pragma once

#include <cstddef>
#include <cstdint>

#include "core/dissection/DissectionRegistry.h"

namespace pfl::dissection {

struct ParsedArpPacket {
    ParseStatus status {ParseStatus::opaque};
    bool fixed_header_truncated {false};
    bool address_section_truncated {false};
    std::uint16_t hardware_type {0U};
    std::uint16_t protocol_type {0U};
    std::uint8_t hardware_size {0U};
    std::uint8_t protocol_size {0U};
    std::size_t declared_length {0U};
    std::uint16_t opcode {0U};
    bool has_sender_ipv4 {false};
    bool has_target_ipv4 {false};
    std::uint32_t sender_ipv4 {0U};
    std::uint32_t target_ipv4 {0U};
};

[[nodiscard]] ParsedArpPacket parse_arp_packet(const PacketSlice& slice) noexcept;
[[nodiscard]] DissectionStep dissect_arp(const PacketSlice& slice);

}  // namespace pfl::dissection
