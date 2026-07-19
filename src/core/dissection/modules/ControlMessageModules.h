#pragma once

#include <cstddef>
#include <cstdint>

#include "core/dissection/DissectionRegistry.h"

namespace pfl::dissection {

struct ParsedIcmpHeader {
    ParseStatus status {ParseStatus::opaque};
    std::uint8_t type {0U};
    std::uint8_t code {0U};
    std::uint16_t checksum {0U};
    std::size_t header_length {0U};
    std::uint32_t captured_payload_length {0U};
};

struct ParsedIcmpv6Header {
    ParseStatus status {ParseStatus::opaque};
    std::uint8_t type {0U};
    std::uint8_t code {0U};
    std::uint16_t checksum {0U};
    std::size_t header_length {0U};
    std::uint32_t captured_payload_length {0U};
};

struct ParsedIgmpHeader {
    ParseStatus status {ParseStatus::opaque};
    std::uint8_t type {0U};
    std::uint8_t code {0U};
    std::uint16_t checksum {0U};
    std::uint32_t group_or_control {0U};
    std::uint32_t effective_destination_v4 {0U};
    bool has_effective_destination_v4 {false};
    std::size_t header_length {0U};
    std::uint32_t captured_payload_length {0U};
};

[[nodiscard]] ParsedIcmpHeader parse_icmp_common_header(const PacketSlice& slice) noexcept;
[[nodiscard]] ParsedIcmpv6Header parse_icmpv6_common_header(const PacketSlice& slice) noexcept;
[[nodiscard]] ParsedIgmpHeader parse_igmp_common_header(const PacketSlice& slice) noexcept;

[[nodiscard]] DissectionStep dissect_icmp(const PacketSlice& slice);
[[nodiscard]] DissectionStep dissect_icmpv6(const PacketSlice& slice);
[[nodiscard]] DissectionStep dissect_igmp(const PacketSlice& slice);

}  // namespace pfl::dissection
