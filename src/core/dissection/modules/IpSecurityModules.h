#pragma once

#include <cstddef>
#include <cstdint>

#include "core/dissection/DissectionRegistry.h"

namespace pfl::dissection {

struct ParsedAhHeader {
    ParseStatus status {ParseStatus::opaque};
    std::uint8_t next_header {0U};
    std::uint8_t payload_length_field {0U};
    std::uint16_t reserved {0U};
    std::uint32_t spi {0U};
    std::uint32_t sequence_number {0U};
    std::size_t header_length {0U};
    std::size_t icv_length {0U};
};

struct ParsedEspHeader {
    ParseStatus status {ParseStatus::opaque};
    std::uint32_t spi {0U};
    std::uint32_t sequence_number {0U};
    std::size_t header_length {0U};
};

[[nodiscard]] ParsedAhHeader parse_ah_header(const PacketSlice& slice) noexcept;
[[nodiscard]] ParsedEspHeader parse_esp_header(const PacketSlice& slice) noexcept;

[[nodiscard]] DissectionStep dissect_ipv4_ah(const PacketSlice& slice);
[[nodiscard]] DissectionStep dissect_ipv6_ah(const PacketSlice& slice);
[[nodiscard]] DissectionStep dissect_esp(const PacketSlice& slice);

}  // namespace pfl::dissection
