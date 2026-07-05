#pragma once

#include <array>
#include <cstdint>
#include <memory>
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
    bool uses_length_field {false};
    std::size_t trailer_length {0};
    std::vector<std::uint8_t> trailer_preview {};
    bool trailer_preview_truncated {false};
};

struct LlcDetails {
    std::uint8_t available_header_bytes {0};
    std::uint8_t dsap {0};
    std::uint8_t ssap {0};
    std::uint8_t control {0};
    std::uint16_t declared_payload_length {0};
    bool header_truncated {false};
    bool payload_length_exceeds_captured {false};
    bool captured_payload_exceeds_declared {false};
    std::size_t payload_length {0};
    std::vector<std::uint8_t> payload_preview {};
    bool payload_preview_truncated {false};
};

struct SnapDetails {
    std::array<std::uint8_t, 3> oui {};
    std::uint16_t pid {0};
    bool header_truncated {false};
    std::size_t payload_length {0};
    std::vector<std::uint8_t> payload_preview {};
    bool payload_preview_truncated {false};
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

struct InnerEthernetDetails {
    std::array<std::uint8_t, 6> src_mac {};
    std::array<std::uint8_t, 6> dst_mac {};
    std::uint16_t ether_type {0};
    bool uses_length_field {false};
    std::uint8_t available_header_bytes {0};
    bool header_truncated {false};
};

struct PbbDetails {
    bool present {false};
    bool itag_truncated {false};
    std::uint8_t available_bytes {0};
    std::uint8_t pcp {0};
    bool dei {false};
    bool nca {false};
    std::uint8_t reserved {0};
    std::uint32_t isid {0};
};

struct MacsecDetails {
    bool present {false};
    bool sectag_truncated {false};
    bool packet_number_truncated {false};
    bool sci_truncated {false};
    bool icv_truncated {false};
    std::uint8_t available_base_bytes {0};
    std::uint8_t version {0};
    bool es {false};
    bool sc {false};
    bool scb {false};
    bool encrypted {false};
    bool changed {false};
    std::uint8_t association_number {0};
    std::uint8_t short_length {0};
    bool packet_number_present {false};
    std::uint32_t packet_number {0};
    std::uint8_t available_sci_bytes {0};
    std::array<std::uint8_t, 6> sci_system_id {};
    std::uint16_t sci_port_id {0};
    std::size_t protected_payload_length {0};
    std::vector<std::uint8_t> protected_payload_preview {};
    bool protected_payload_preview_truncated {false};
    std::size_t icv_length {0};
    std::vector<std::uint8_t> icv_preview {};
    bool icv_preview_truncated {false};
};

struct MplsPseudowireControlWordDetails {
    bool present {false};
    bool truncated {false};
    std::uint8_t available_bytes {0};
    std::uint16_t flags {0};
    std::uint16_t sequence {0};
};

struct MplsPseudowirePayloadDetails {
    std::size_t payload_length {0};
    std::vector<std::uint8_t> payload_preview {};
    bool payload_preview_truncated {false};
};

struct VxlanInnerPacketDetails;
struct GeneveInnerPacketDetails;

struct VxlanDetails {
    bool present {false};
    std::uint8_t flags {0};
    bool i_flag_set {false};
    std::uint8_t available_header_bytes {0};
    bool header_truncated {false};
    bool invalid_header {false};
    bool reserved_bits_non_zero {false};
    std::uint32_t vni {0};
    bool has_inner_ethernet {false};
    bool inner_ethernet_truncated {false};
    bool has_inner_packet {false};
    std::shared_ptr<VxlanInnerPacketDetails> inner_packet {};
};

struct GeneveDetails {
    bool present {false};
    std::uint8_t version {0};
    bool oam_flag {false};
    bool critical_flag {false};
    std::uint8_t reserved_control_bits {0};
    std::uint8_t reserved_trailer_byte {0};
    std::uint8_t available_header_bytes {0};
    bool header_truncated {false};
    bool invalid_version {false};
    bool options_present {false};
    std::uint8_t option_length_words {0};
    std::uint16_t option_length_bytes {0};
    bool options_truncated {false};
    std::uint16_t protocol_type {0};
    bool protocol_type_supported {false};
    std::uint32_t vni {0};
    bool has_inner_ethernet {false};
    bool inner_ethernet_truncated {false};
    bool has_inner_packet {false};
    std::shared_ptr<GeneveInnerPacketDetails> inner_packet {};
};

struct PppoeTagDetails {
    std::uint16_t type {0};
    std::uint16_t declared_length {0};
    std::vector<std::uint8_t> value {};
    bool header_truncated {false};
    bool value_truncated {false};
};

struct PppControlOptionDetails {
    std::uint8_t type {0};
    std::uint8_t declared_length {0};
    std::vector<std::uint8_t> value {};
    bool header_truncated {false};
    bool value_truncated {false};
};

struct PppControlDetails {
    bool present {false};
    std::uint8_t code {0};
    std::uint8_t identifier {0};
    std::uint16_t length {0};
    bool header_truncated {false};
    bool payload_truncated {false};
    bool option_header_truncated {false};
    bool option_value_truncated {false};
    std::vector<PppControlOptionDetails> options {};
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
    bool declared_payload_exceeds_captured {false};
    bool captured_payload_exceeds_declared {false};
    std::size_t captured_payload_length {0};
    std::vector<PppoeTagDetails> discovery_tags {};
    bool discovery_tag_header_truncated {false};
    bool discovery_tag_value_truncated {false};
    PppControlDetails control {};
    std::size_t unknown_ppp_payload_length {0};
    std::vector<std::uint8_t> unknown_ppp_payload_preview {};
    bool unknown_ppp_payload_preview_truncated {false};
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
    std::uint8_t available_header_bytes {0};
    std::uint16_t available_packet_bytes {0};
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
    bool payload_truncated {false};
};

struct VxlanInnerPacketDetails {
    bool has_vlan {false};
    std::vector<VlanTagDetails> vlan_tags {};
    bool has_llc {false};
    LlcDetails llc {};
    bool has_snap {false};
    SnapDetails snap {};
    bool has_ipv4 {false};
    IPv4Details ipv4 {};
    bool has_ipv6 {false};
    IPv6Details ipv6 {};
    bool has_tcp {false};
    TcpDetails tcp {};
    bool has_udp {false};
    UdpDetails udp {};
};

struct GeneveInnerPacketDetails {
    bool has_vlan {false};
    std::vector<VlanTagDetails> vlan_tags {};
    bool has_llc {false};
    LlcDetails llc {};
    bool has_snap {false};
    SnapDetails snap {};
    bool has_ipv4 {false};
    IPv4Details ipv4 {};
    bool has_ipv6 {false};
    IPv6Details ipv6 {};
    bool has_tcp {false};
    TcpDetails tcp {};
    bool has_udp {false};
    UdpDetails udp {};
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
    std::vector<VlanTagDetails> encapsulating_vlan_tags {};
    bool vlan_tag_truncated {false};
    std::uint16_t truncated_vlan_tpid {0};

    bool has_linux_cooked {false};
    LinuxCookedDetails linux_cooked {};

    bool has_llc {false};
    LlcDetails llc {};

    bool has_snap {false};
    SnapDetails snap {};

    bool has_mpls {false};
    std::uint16_t mpls_ether_type {0};
    std::vector<MplsLabelDetails> mpls_labels {};
    bool has_pbb {false};
    PbbDetails pbb {};
    bool has_macsec {false};
    MacsecDetails macsec {};
    bool has_mpls_pseudowire_control_word {false};
    MplsPseudowireControlWordDetails mpls_pseudowire_control_word {};
    bool has_vxlan {false};
    VxlanDetails vxlan {};
    bool has_geneve {false};
    GeneveDetails geneve {};
    bool has_inner_ethernet {false};
    InnerEthernetDetails inner_ethernet {};
    bool has_unknown_inner_ethernet_payload {false};
    MplsPseudowirePayloadDetails unknown_inner_ethernet_payload {};

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
