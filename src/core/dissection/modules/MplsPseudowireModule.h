#pragma once

#include <cstddef>
#include <cstdint>

#include "core/dissection/DissectionRegistry.h"

namespace pfl::dissection {

inline constexpr std::uint32_t kMplsBosPayloadSelectorValue = 0U;
inline constexpr std::uint32_t kMplsPseudowireInnerFrameSelectorValue = 0U;

struct ParsedMplsPseudowireControlWord {
    ParseStatus status {ParseStatus::opaque};
    std::uint16_t flags {0U};
    std::uint16_t sequence {0U};
    std::size_t header_length {0U};
    std::size_t declared_payload_length {0U};
};

[[nodiscard]] ParsedMplsPseudowireControlWord parse_mpls_pseudowire_control_word(const PacketSlice& slice) noexcept;
[[nodiscard]] DissectionStep dissect_mpls_bos_payload(const PacketSlice& slice);
[[nodiscard]] DissectionStep dissect_mpls_pseudowire_inner_ethernet(const PacketSlice& slice);
[[nodiscard]] DissectionStep dissect_mpls_pseudowire_inner_vlan(const PacketSlice& slice);

}  // namespace pfl::dissection
