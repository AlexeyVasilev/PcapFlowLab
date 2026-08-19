#pragma once

#include <cstddef>
#include <cstdint>

#include "core/io/LinkType.h"

namespace pfl {

struct PacketRef {
    std::uint64_t packet_index {0};
    // Persistent packet locator/ordering metadata for indexed captures.
    // Decoded packet facts such as transport payload length, TCP flags, and
    // fragmentation state are derived transiently from source bytes or
    // import-time metadata and are not retained here.
    std::uint32_t ts_sec {0};
    std::uint32_t ts_usec {0};
    // File offset of the packet data bytes inside the original capture file.
    std::uint64_t byte_offset {0};
    std::uint32_t data_link_type {kLinkTypeEthernet};
    std::uint32_t captured_length {0};
    std::uint32_t original_length {0};

    [[nodiscard]] friend constexpr bool operator==(const PacketRef&, const PacketRef&) = default;
};

}  // namespace pfl
