#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <initializer_list>
#include <optional>
#include <string>
#include <vector>

#include "TestSupport.h"
#include "PcapTestUtils.h"
#include "core/decode/PacketDecodeSupport.h"
#include "core/dissection/CommonDirectDissection.h"
#include "core/dissection/DissectionEngine.h"
#include "core/dissection/PacketSlice.h"
#include "core/domain/ProtocolPath.h"
#include "core/io/LinkType.h"
#include "core/io/PcapReader.h"

namespace pfl::tests::common_direct_test {

using namespace dissection;

struct LegacyDirectFacts {
    bool recognized_flow {false};
    ProtocolId protocol {ProtocolId::unknown};
    DissectionAddressFamily family {DissectionAddressFamily::unknown};
    bool has_addresses {false};
    std::uint32_t src_addr_v4 {0U};
    std::uint32_t dst_addr_v4 {0U};
    std::array<std::uint8_t, 16> src_addr_v6 {};
    std::array<std::uint8_t, 16> dst_addr_v6 {};
    bool has_ports {false};
    std::uint16_t src_port {0U};
    std::uint16_t dst_port {0U};
    bool has_payload_length {false};
    std::uint32_t captured_payload_length {0U};
    bool has_tcp_flags {false};
    std::uint8_t tcp_flags {0U};
    bool is_ip_fragmented {false};
    ProtocolPath path {};
};

struct StepKindRecorder {
    std::vector<DissectionLayerKind> kinds {};
};

void run_common_direct_core_dissection_tests();
void run_common_direct_registry_engine_tests();
void run_common_direct_collector_tests();
void run_common_direct_path_policy_tests();
void run_common_direct_bounds_traversal_tests();
void run_common_direct_link_dissection_tests();
void run_common_direct_network_dissection_tests();
void run_common_direct_encapsulation_dissection_tests();
void run_common_direct_eoip_dissection_tests();
void run_common_direct_mpls_pseudowire_dissection_tests();
void run_common_direct_transport_dissection_tests();
void run_common_direct_vxlan_dissection_tests();
void run_common_direct_geneve_dissection_tests();
void run_common_direct_gtpu_dissection_tests();

RawPcapPacket make_raw_packet(
    const std::vector<std::uint8_t>& captured_bytes,
    std::uint32_t original_length = 0U,
    std::uint32_t data_link_type = kLinkTypeEthernet,
    std::uint64_t packet_index = 0U
);
RawPcapPacket require_raw_fixture_packet(const std::filesystem::path& relative_path);
std::vector<RawPcapPacket> require_raw_fixture_packets(const std::filesystem::path& relative_path);
PacketSlice make_root_slice(const RawPcapPacket& packet);
PacketSlice make_declared_root_slice(const std::vector<std::uint8_t>& bytes, std::size_t declared_length);
PacketSlice require_child_slice(const PacketSlice& parent, std::size_t payload_offset, std::size_t declared_payload_length);
ByteRange require_range(std::size_t begin, std::size_t end);
std::string format_shadow_path(const ImportDissectionFacts& facts);
ProtocolPath shadow_path(const ImportDissectionFacts& facts);
LegacyDirectFacts decode_legacy_direct(const RawPcapPacket& packet);
ImportDissectionFacts run_shadow(const RawPcapPacket& packet, const DissectionRegistry& registry);
std::vector<DissectionStep> collect_shadow_steps(const RawPcapPacket& packet, const DissectionRegistry& registry);
std::vector<DissectionLayerKind> collect_step_kinds(const std::vector<DissectionStep>& steps);
const PppoeFacts* find_pppoe_facts(const std::vector<DissectionStep>& steps);
const PbbFacts* find_pbb_facts(const std::vector<DissectionStep>& steps);
const MacsecFacts* find_macsec_facts(const std::vector<DissectionStep>& steps);
void expect_shadow_matches_legacy_flow(
    const DissectionRegistry& registry,
    const RawPcapPacket& packet,
    const std::string& expected_path,
    StopReason expected_stop_reason
);
void expect_shadow_matches_legacy_portless_terminal_flow(
    const DissectionRegistry& registry,
    const RawPcapPacket& packet,
    const std::string& expected_path,
    StopReason expected_stop_reason
);
void expect_shadow_matches_legacy_recognized_non_flow(
    const DissectionRegistry& registry,
    const RawPcapPacket& packet,
    const std::string& expected_shadow_path,
    const std::string& expected_legacy_path,
    StopReason expected_stop_reason
);
void record_step_kind(void* context, const DissectionStep& step);

std::vector<std::uint8_t> add_ipv4_options(
    const std::vector<std::uint8_t>& ethernet_packet,
    const std::vector<std::uint8_t>& options
);
void set_ipv4_total_length(std::vector<std::uint8_t>& packet, std::uint16_t total_length);
void set_udp_length(std::vector<std::uint8_t>& packet, std::uint16_t datagram_length);
std::vector<std::uint8_t> make_ethernet_ieee8023_frame(std::uint16_t payload_length);
std::vector<std::uint8_t> make_ethernet_frame_with_payload(
    std::uint16_t ether_type,
    const std::vector<std::uint8_t>& payload
);
std::vector<std::uint8_t> make_macsec_bytes(
    std::uint8_t tci_an,
    std::uint8_t short_length,
    std::uint32_t packet_number,
    const std::vector<std::uint8_t>& protected_payload = {},
    bool has_sci = false,
    std::uint64_t sci = 0x0200000071010001ULL,
    bool include_full_icv = true,
    const std::vector<std::uint8_t>& icv_override = {}
);
void append_mpls_label(
    std::vector<std::uint8_t>& bytes,
    std::uint32_t label,
    bool bottom_of_stack,
    std::uint8_t traffic_class = 0U,
    std::uint8_t ttl = 64U
);
std::vector<std::uint8_t> make_mpls_payload_with_labels(
    const std::initializer_list<std::uint32_t> labels,
    const std::vector<std::uint8_t>& payload,
    std::uint8_t traffic_class = 0U,
    std::uint8_t ttl = 64U
);
std::vector<std::uint8_t> make_ipv4_header_only_packet(std::uint8_t protocol);
std::vector<std::uint8_t> make_sctp_segment(
    std::uint16_t src_port,
    std::uint16_t dst_port,
    std::uint32_t verification_tag,
    std::uint32_t checksum,
    std::uint16_t payload_length = 0U
);
std::vector<std::uint8_t> make_ethernet_ipv4_sctp_packet(
    std::uint32_t src_addr,
    std::uint32_t dst_addr,
    std::uint16_t src_port,
    std::uint16_t dst_port,
    std::uint32_t verification_tag,
    std::uint32_t checksum,
    std::uint16_t payload_length = 0U
);
std::vector<std::uint8_t> make_gre_header(
    std::uint16_t protocol_type,
    const std::vector<std::uint8_t>& payload = {},
    bool has_checksum = false,
    bool has_key = false,
    bool has_sequence = false,
    std::uint16_t extra_flags = 0U,
    std::uint16_t checksum = 0x1234U,
    std::uint16_t reserved1 = 0x5678U,
    std::uint32_t key = 0x11111111U,
    std::uint32_t sequence_number = 0x01020304U
);
std::vector<std::uint8_t> make_ethernet_ipv4_gre_packet(
    std::uint32_t src_addr,
    std::uint32_t dst_addr,
    const std::vector<std::uint8_t>& gre_payload,
    std::uint16_t flags_fragment = 0U,
    std::uint8_t ttl = 64U
);
std::vector<std::uint8_t> make_ethernet_ipv6_gre_packet(
    const std::array<std::uint8_t, 16>& src_addr,
    const std::array<std::uint8_t, 16>& dst_addr,
    const std::vector<std::uint8_t>& gre_payload
);
std::vector<std::uint8_t> make_ah_header(
    std::uint8_t next_header,
    std::uint32_t spi,
    std::uint32_t sequence_number,
    const std::vector<std::uint8_t>& icv = {},
    std::uint16_t reserved = 0U,
    const std::optional<std::uint8_t>& payload_length_field_override = std::nullopt
);
std::vector<std::uint8_t> make_esp_header(
    std::uint32_t spi,
    std::uint32_t sequence_number,
    const std::vector<std::uint8_t>& opaque_payload = {}
);
std::vector<std::uint8_t> make_ethernet_ipv4_ah_packet(
    std::uint32_t src_addr,
    std::uint32_t dst_addr,
    std::uint8_t next_header,
    const std::vector<std::uint8_t>& inner_payload = {},
    std::uint32_t spi = 0x11111111U,
    std::uint32_t sequence_number = 0x01020304U,
    const std::vector<std::uint8_t>& icv = {},
    std::uint16_t flags_fragment = 0U
);
std::vector<std::uint8_t> make_ethernet_ipv6_ah_packet(
    const std::array<std::uint8_t, 16>& src_addr,
    const std::array<std::uint8_t, 16>& dst_addr,
    std::uint8_t next_header,
    const std::vector<std::uint8_t>& inner_payload = {},
    std::uint32_t spi = 0x11111111U,
    std::uint32_t sequence_number = 0x01020304U,
    const std::vector<std::uint8_t>& icv = {}
);
std::vector<std::uint8_t> make_ethernet_ipv4_esp_packet(
    std::uint32_t src_addr,
    std::uint32_t dst_addr,
    std::uint32_t spi,
    std::uint32_t sequence_number,
    const std::vector<std::uint8_t>& opaque_payload = {},
    std::uint16_t flags_fragment = 0U
);
std::vector<std::uint8_t> make_ethernet_ipv6_esp_packet(
    const std::array<std::uint8_t, 16>& src_addr,
    const std::array<std::uint8_t, 16>& dst_addr,
    std::uint32_t spi,
    std::uint32_t sequence_number,
    const std::vector<std::uint8_t>& opaque_payload = {}
);
std::vector<std::uint8_t> make_ipv4_payload_packet(
    std::uint32_t src_addr,
    std::uint32_t dst_addr,
    std::uint8_t protocol,
    const std::vector<std::uint8_t>& payload,
    std::uint16_t flags_fragment = 0U,
    std::uint8_t ttl = 64U
);
std::vector<std::uint8_t> make_ipv6_payload_packet(
    const std::array<std::uint8_t, 16>& src_addr,
    const std::array<std::uint8_t, 16>& dst_addr,
    std::uint8_t next_header,
    const std::vector<std::uint8_t>& payload
);
std::vector<std::uint8_t> make_igmp_message(
    std::uint8_t type,
    std::uint8_t code,
    std::uint16_t checksum,
    std::uint32_t group_or_control,
    const std::vector<std::uint8_t>& body = {}
);
std::vector<std::uint8_t> make_ethernet_ipv4_igmp_packet(
    std::uint32_t src_addr,
    std::uint32_t dst_addr,
    std::uint8_t type,
    std::uint8_t code,
    std::uint16_t checksum,
    std::uint32_t group_or_control,
    const std::vector<std::uint8_t>& body = {}
);
std::vector<std::uint8_t> make_ipv6_tcp_segment(
    std::uint16_t src_port,
    std::uint16_t dst_port,
    std::uint16_t payload_length = 0U,
    std::uint8_t flags = 0x10U
);
std::vector<std::uint8_t> make_ipv4_tcp_segment(
    std::uint16_t src_port,
    std::uint16_t dst_port,
    std::uint16_t payload_length = 0U,
    std::uint8_t flags = 0x10U
);
std::vector<std::uint8_t> make_ipv4_udp_segment(
    std::uint16_t src_port,
    std::uint16_t dst_port,
    std::uint16_t payload_length = 0U
);
std::vector<std::uint8_t> make_ipv6_routing_extension(
    std::uint8_t next_header,
    const std::vector<std::uint8_t>& payload
);
std::vector<std::uint8_t> make_ipv6_destination_options_extension(
    std::uint8_t next_header,
    const std::vector<std::uint8_t>& payload
);

}  // namespace pfl::tests::common_direct_test

namespace pfl::tests {

void run_common_direct_dissection_tests();

}  // namespace pfl::tests
