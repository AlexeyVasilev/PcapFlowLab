#pragma once

#include <array>
#include <cstdint>
#include <vector>

namespace pfl {

enum class NetworkAddressFamily : std::uint8_t {
    unknown,
    ipv4,
    ipv6
};

struct EthernetDetails {
    std::uint16_t ether_type {0};
};

struct VlanTagDetails {
    std::uint16_t tci {0};
    std::uint16_t encapsulated_ether_type {0};
};

struct IPv4Details {
    std::uint32_t src_addr {0};
    std::uint32_t dst_addr {0};
    std::uint8_t protocol {0};
    std::uint8_t ttl {0};
    std::uint16_t total_length {0};
};

struct IPv6Details {
    std::array<std::uint8_t, 16> src_addr {};
    std::array<std::uint8_t, 16> dst_addr {};
    std::uint8_t next_header {0};
    std::uint8_t hop_limit {0};
    std::uint16_t payload_length {0};
};

struct TcpDetails {
    std::uint16_t src_port {0};
    std::uint16_t dst_port {0};
    std::uint8_t flags {0};
    std::uint32_t seq_number {0};
    std::uint32_t ack_number {0};
};

struct UdpDetails {
    std::uint16_t src_port {0};
    std::uint16_t dst_port {0};
    std::uint16_t length {0};
};

struct PacketDetails {
    std::uint64_t packet_index {0};
    std::uint32_t captured_length {0};
    std::uint32_t original_length {0};

    bool has_ethernet {false};
    EthernetDetails ethernet {};

    bool has_vlan {false};
    std::vector<VlanTagDetails> vlan_tags {};

    NetworkAddressFamily address_family {NetworkAddressFamily::unknown};

    bool has_ipv4 {false};
    IPv4Details ipv4 {};

    bool has_ipv6 {false};
    IPv6Details ipv6 {};

    bool has_tcp {false};
    TcpDetails tcp {};

    bool has_udp {false};
    UdpDetails udp {};

    [[nodiscard]] bool empty() const noexcept;
};

}  // namespace pfl
