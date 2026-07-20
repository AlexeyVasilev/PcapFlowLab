#pragma once

#include <cstddef>
#include <cstdint>

#include "core/dissection/DissectionRegistry.h"

namespace pfl::dissection {

struct ParsedGreHeader {
    ParseStatus status {ParseStatus::opaque};
    std::uint16_t flags_and_version {0U};
    std::uint16_t protocol_type {0U};
    bool has_checksum {false};
    std::uint16_t checksum {0U};
    std::uint16_t reserved1 {0U};
    bool has_key {false};
    std::uint32_t key {0U};
    bool has_sequence {false};
    std::uint32_t sequence_number {0U};
    std::size_t header_length {0U};
};

[[nodiscard]] ParsedGreHeader parse_gre_header(const PacketSlice& slice) noexcept;
[[nodiscard]] DissectionStep dissect_gre(const PacketSlice& slice);

}  // namespace pfl::dissection
