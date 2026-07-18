#pragma once

#include <cstddef>
#include <cstdint>

#include "core/dissection/DissectionRegistry.h"

namespace pfl::dissection {

struct ParsedEthernetFrame {
    ParseStatus status {ParseStatus::opaque};
    std::uint16_t protocol_type {0U};
    std::size_t header_length {0U};
    std::size_t declared_payload_length {0U};
    bool is_ieee_802_3 {false};
};

struct ParsedVlanTag {
    ParseStatus status {ParseStatus::opaque};
    std::uint16_t tci {0U};
    std::uint16_t encapsulated_ether_type {0U};
    std::size_t header_length {0U};
    std::size_t declared_payload_length {0U};
};

struct ParsedIpv4Packet {
    ParseStatus status {ParseStatus::opaque};
    std::uint8_t protocol {0U};
    std::uint16_t total_length {0U};
    std::size_t header_length {0U};
    std::size_t nominal_packet_end {0U};
    std::size_t packet_end {0U};
    std::uint32_t src_addr {0U};
    std::uint32_t dst_addr {0U};
    std::uint16_t flags_fragment {0U};
    bool bounds_from_captured_bytes {false};
    bool is_fragmented {false};
    bool more_fragments {false};
    std::uint16_t fragment_offset_units {0U};
};

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

struct ParsedArpPacket {
    ParseStatus status {ParseStatus::opaque};
    bool fixed_header_truncated {false};
    bool address_section_truncated {false};
    std::uint16_t hardware_type {0U};
    std::uint16_t protocol_type {0U};
    std::uint8_t hardware_size {0U};
    std::uint8_t protocol_size {0U};
    std::uint16_t opcode {0U};
    bool has_sender_ipv4 {false};
    bool has_target_ipv4 {false};
    std::uint32_t sender_ipv4 {0U};
    std::uint32_t target_ipv4 {0U};
};

[[nodiscard]] ParsedEthernetFrame parse_ethernet_frame(const PacketSlice& slice) noexcept;
[[nodiscard]] ParsedVlanTag parse_vlan_tag(const PacketSlice& slice) noexcept;
[[nodiscard]] ParsedIpv4Packet parse_ipv4_packet(const PacketSlice& slice) noexcept;
[[nodiscard]] ParsedTcpSegment parse_tcp_segment(const PacketSlice& slice) noexcept;
[[nodiscard]] ParsedUdpDatagram parse_udp_datagram(const PacketSlice& slice) noexcept;
[[nodiscard]] ParsedArpPacket parse_arp_packet(const PacketSlice& slice) noexcept;

[[nodiscard]] DissectionStep dissect_ethernet(const PacketSlice& slice);
[[nodiscard]] DissectionStep dissect_vlan(const PacketSlice& slice);
[[nodiscard]] DissectionStep dissect_ipv4(const PacketSlice& slice);
[[nodiscard]] DissectionStep dissect_tcp(const PacketSlice& slice);
[[nodiscard]] DissectionStep dissect_udp(const PacketSlice& slice);
[[nodiscard]] DissectionStep dissect_arp(const PacketSlice& slice);

}  // namespace pfl::dissection
