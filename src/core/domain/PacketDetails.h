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
    std::array<std::uint8_t, 6> src_mac {};
    std::array<std::uint8_t, 6> dst_mac {};
    std::uint16_t ether_type {0};
};

struct VlanTagDetails {
    std::uint16_t tpid {0};
    std::uint16_t tci {0};
    std::uint16_t encapsulated_ether_type {0};
};

struct LinuxCookedDetails {
    std::uint32_t link_type {0};
    std::uint16_t protocol_type {0};
    std::uint16_t packet_type {0};
    std::uint16_t hardware_type {0};
};

struct MplsLabelDetails {
    std::uint32_t label {0};
    std::uint8_t traffic_class {0};
    bool bottom_of_stack {false};
    std::uint8_t ttl {0};
};

struct PppoeTagDetails {
    std::uint16_t type {0};
    std::uint16_t declared_length {0};
    std::vector<std::uint8_t> value {};
    bool header_truncated {false};
    bool value_truncated {false};
};

struct PppoeSessionDetails {
    std::uint8_t version {0};
    std::uint8_t type {0};
    std::uint8_t code {0};
    std::uint16_t session_id {0};
    std::uint16_t payload_length {0};
    std::uint16_t ppp_protocol {0};
    bool is_discovery {false};
    bool header_truncated {false};
    bool protocol_field_truncated {false};
    bool payload_length_mismatch {false};
    std::vector<PppoeTagDetails> discovery_tags {};
    bool discovery_tag_header_truncated {false};
    bool discovery_tag_value_truncated {false};
};

struct ArpDetails {
    std::uint16_t hardware_type {0};
    std::uint16_t protocol_type {0};
    std::uint8_t hardware_size {0};
    std::uint8_t protocol_size {0};
    std::uint16_t opcode {0};
    std::vector<std::uint8_t> sender_hardware_address {};
    std::vector<std::uint8_t> sender_protocol_address {};
    std::vector<std::uint8_t> target_hardware_address {};
    std::vector<std::uint8_t> target_protocol_address {};
    std::array<std::uint8_t, 4> sender_ipv4 {};
    std::array<std::uint8_t, 4> target_ipv4 {};
    bool fixed_header_truncated {false};
    bool address_section_truncated {false};
};

struct IPv4Details {
    std::uint32_t src_addr {0};
    std::uint32_t dst_addr {0};
    std::uint8_t header_length_bytes {0};
    std::uint8_t differentiated_services_field {0};
    std::uint8_t protocol {0};
    std::uint8_t ttl {0};
    std::uint16_t identification {0};
    std::uint8_t flags {0};
    std::uint16_t fragment_offset {0};
    std::uint16_t total_length {0};
    std::uint16_t header_checksum {0};
    std::vector<std::uint8_t> options_bytes {};
    bool invalid_header_length {false};
    bool header_truncated {false};
    bool options_truncated {false};
    bool total_length_invalid {false};
};

struct IPv6Details {
    std::array<std::uint8_t, 16> src_addr {};
    std::array<std::uint8_t, 16> dst_addr {};
    std::uint8_t traffic_class {0};
    std::uint8_t next_header {0};
    std::uint8_t hop_limit {0};
    std::uint32_t flow_label {0};
    std::uint16_t payload_length {0};
};

struct TcpDetails {
    std::uint16_t src_port {0};
    std::uint16_t dst_port {0};
    std::uint32_t seq_number {0};
    std::uint32_t ack_number {0};
    std::uint8_t header_length_bytes {0};
    std::uint8_t flags {0};
    std::uint16_t window {0};
    std::uint16_t checksum {0};
    std::uint16_t urgent_pointer {0};
    std::vector<std::uint8_t> options_bytes {};
};

struct UdpDetails {
    std::uint16_t src_port {0};
    std::uint16_t dst_port {0};
    std::uint16_t length {0};
    std::uint16_t checksum {0};
};

struct IcmpDetails {
    std::uint8_t type {0};
    std::uint8_t code {0};
};

struct IcmpV6Details {
    std::uint8_t type {0};
    std::uint8_t code {0};
};

struct IgmpDetails {
    std::uint8_t type {0};
    std::uint8_t max_resp_code {0};
    std::uint16_t checksum {0};
    std::uint32_t group_address {0};
    std::uint16_t group_record_count {0};
    bool has_group_address {false};
    bool is_v3_membership_report {false};
    bool header_truncated {false};
};

struct PacketDetails {
    std::uint64_t packet_index {0};
    std::uint32_t captured_length {0};
    std::uint32_t original_length {0};
    bool ipv4_bounds_from_captured_bytes {false};

    bool has_ethernet {false};
    EthernetDetails ethernet {};

    bool has_vlan {false};
    std::vector<VlanTagDetails> vlan_tags {};
    bool vlan_tag_truncated {false};
    std::uint16_t truncated_vlan_tpid {0};

    bool has_linux_cooked {false};
    LinuxCookedDetails linux_cooked {};

    bool has_mpls {false};
    std::uint16_t mpls_ether_type {0};
    std::vector<MplsLabelDetails> mpls_labels {};

    bool has_pppoe {false};
    PppoeSessionDetails pppoe {};

    bool has_arp {false};
    ArpDetails arp {};

    NetworkAddressFamily address_family {NetworkAddressFamily::unknown};

    bool has_ipv4 {false};
    IPv4Details ipv4 {};

    bool has_ipv6 {false};
    IPv6Details ipv6 {};

    bool has_tcp {false};
    TcpDetails tcp {};

    bool has_udp {false};
    UdpDetails udp {};

    bool has_icmp {false};
    IcmpDetails icmp {};

    bool has_icmpv6 {false};
    IcmpV6Details icmpv6 {};

    bool has_igmp {false};
    IgmpDetails igmp {};

    [[nodiscard]] bool empty() const noexcept;
};

}  // namespace pfl
