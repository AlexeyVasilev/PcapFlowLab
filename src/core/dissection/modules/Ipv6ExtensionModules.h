#pragma once

#include <cstddef>
#include <cstdint>

#include "core/dissection/DissectionRegistry.h"

namespace pfl::dissection {

enum class Ipv6ExtensionHeaderKind : std::uint8_t {
    hop_by_hop = 0,
    routing,
    destination_options,
};

struct ParsedIpv6ExtensionHeader {
    ParseStatus status {ParseStatus::opaque};
    Ipv6ExtensionHeaderKind kind {Ipv6ExtensionHeaderKind::hop_by_hop};
    std::uint8_t next_header {0U};
    std::size_t header_length {0U};
};

struct ParsedIpv6FragmentHeader {
    ParseStatus status {ParseStatus::opaque};
    std::uint8_t next_header {0U};
    std::size_t header_length {0U};
    std::uint16_t fragment_offset_units {0U};
    bool more_fragments {false};
    bool is_atomic_fragment {false};
};

[[nodiscard]] ParsedIpv6ExtensionHeader parse_ipv6_extension_header(
    const PacketSlice& slice,
    Ipv6ExtensionHeaderKind kind
) noexcept;

[[nodiscard]] ParsedIpv6FragmentHeader parse_ipv6_fragment_header(const PacketSlice& slice) noexcept;

[[nodiscard]] DissectionStep dissect_ipv6_hop_by_hop(const PacketSlice& slice);
[[nodiscard]] DissectionStep dissect_ipv6_routing(const PacketSlice& slice);
[[nodiscard]] DissectionStep dissect_ipv6_destination_options(const PacketSlice& slice);
[[nodiscard]] DissectionStep dissect_ipv6_fragment(const PacketSlice& slice);

}  // namespace pfl::dissection
