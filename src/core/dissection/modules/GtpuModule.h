#pragma once

#include <cstddef>
#include <cstdint>

#include "core/dissection/DissectionRegistry.h"

namespace pfl::dissection {

struct ParsedGtpuHeader {
    ParseStatus status {ParseStatus::opaque};
    std::uint8_t flags {0U};
    std::uint8_t version {0U};
    std::uint8_t message_type {0U};
    std::uint16_t length {0U};
    std::uint32_t teid {0U};
    bool has_optional_fields {false};
    bool has_sequence_number {false};
    bool has_npdu_number {false};
    bool has_extension_headers {false};
    std::uint16_t sequence_number {0U};
    std::uint8_t npdu_number {0U};
    std::uint8_t first_extension_header_type {0U};
    std::size_t header_length {0U};
    std::size_t packet_length {0U};
    std::size_t inner_payload_offset {0U};
    std::uint16_t inner_payload_type {0U};
};

[[nodiscard]] ParsedGtpuHeader parse_gtpu_header(const PacketSlice& slice) noexcept;
[[nodiscard]] DissectionStep dissect_gtpu(const PacketSlice& slice);
[[nodiscard]] DissectionStep dissect_gtpu_inner_ipv4(const PacketSlice& slice);
[[nodiscard]] DissectionStep dissect_gtpu_inner_ipv6(const PacketSlice& slice);

}  // namespace pfl::dissection
