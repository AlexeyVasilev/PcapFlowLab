#pragma once

#include <cstddef>
#include <cstdint>

#include "core/dissection/DissectionRegistry.h"

namespace pfl::dissection {

struct ParsedMacsecFrame {
    ParseStatus status {ParseStatus::opaque};
    std::uint8_t available_base_bytes {0U};
    std::uint8_t available_sci_bytes {0U};
    std::uint8_t tci_an {0U};
    std::uint8_t version {0U};
    bool end_station {false};
    bool sci_present {false};
    bool single_copy_broadcast {false};
    bool encrypted {false};
    bool changed_text {false};
    std::uint8_t association_number {0U};
    std::uint8_t short_length {0U};
    bool packet_number_present {false};
    std::uint32_t packet_number {0U};
    bool has_sci {false};
    std::uint64_t sci {0U};
    bool has_plain_ether_type {false};
    std::uint16_t plain_ether_type {0U};
    std::size_t header_length {0U};
    std::size_t protected_payload_offset {0U};
    std::size_t protected_payload_length {0U};
    std::size_t icv_offset {0U};
    std::size_t icv_length {0U};
    bool icv_complete {false};
};

[[nodiscard]] ParsedMacsecFrame parse_macsec_frame(const PacketSlice& slice) noexcept;
[[nodiscard]] DissectionStep dissect_macsec(const PacketSlice& slice);

}  // namespace pfl::dissection
