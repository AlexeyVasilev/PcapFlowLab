#pragma once

#include <cstddef>
#include <cstdint>

#include "core/dissection/DissectionRegistry.h"

namespace pfl::dissection {

struct ParsedTcpSegment {
    ParseStatus status {ParseStatus::opaque};
    std::uint16_t src_port {0U};
    std::uint16_t dst_port {0U};
    std::size_t header_length {0U};
    std::uint32_t captured_payload_length {0U};
    std::uint8_t flags {0U};
};

struct ParsedUdpDatagram {
    ParseStatus status {ParseStatus::opaque};
    std::uint16_t src_port {0U};
    std::uint16_t dst_port {0U};
    std::uint16_t datagram_length {0U};
    std::uint32_t captured_payload_length {0U};
};

struct ParsedSctpCommonHeader {
    ParseStatus status {ParseStatus::opaque};
    std::uint16_t src_port {0U};
    std::uint16_t dst_port {0U};
    std::uint32_t verification_tag {0U};
    std::uint32_t checksum {0U};
    std::size_t header_length {0U};
    std::uint32_t captured_payload_length {0U};
};

[[nodiscard]] ParsedTcpSegment parse_tcp_segment(const PacketSlice& slice) noexcept;
[[nodiscard]] ParsedUdpDatagram parse_udp_datagram(const PacketSlice& slice) noexcept;
[[nodiscard]] ParsedSctpCommonHeader parse_sctp_common_header(const PacketSlice& slice) noexcept;

[[nodiscard]] DissectionStep dissect_tcp(const PacketSlice& slice);
[[nodiscard]] DissectionStep dissect_udp(const PacketSlice& slice);
[[nodiscard]] DissectionStep dissect_sctp(const PacketSlice& slice);

}  // namespace pfl::dissection
