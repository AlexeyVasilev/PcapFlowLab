#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <variant>
#include <vector>

#include "TestSupport.h"
#include "PcapTestUtils.h"
#include "core/decode/PacketDecodeSupport.h"
#include "core/decode/PacketDecoder.h"
#include "core/dissection/CommonDirectDissection.h"
#include "core/dissection/PacketSlice.h"
#include "core/dissection/modules/CommonDirectModules.h"
#include "core/domain/ProtocolPath.h"
#include "core/io/LinkType.h"

namespace pfl::tests {

namespace {

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

RawPcapPacket make_raw_packet(
    const std::vector<std::uint8_t>& captured_bytes,
    const std::uint32_t original_length = 0U,
    const std::uint32_t data_link_type = kLinkTypeEthernet,
    const std::uint64_t packet_index = 0U
) {
    return RawPcapPacket {
        .packet_index = packet_index,
        .ts_sec = 1U,
        .ts_usec = 1U,
        .captured_length = static_cast<std::uint32_t>(captured_bytes.size()),
        .original_length = original_length == 0U ? static_cast<std::uint32_t>(captured_bytes.size()) : original_length,
        .data_offset = 64U,
        .data_link_type = data_link_type,
        .bytes = captured_bytes,
    };
}

PacketSlice make_root_slice(const RawPcapPacket& packet) {
    return make_root_packet_slice(
        ByteSourceId::captured_frame(static_cast<std::uint32_t>(packet.packet_index)),
        packet.bytes,
        packet.captured_length,
        packet.original_length
    );
}

PacketSlice require_child_slice(
    const PacketSlice& parent,
    const std::size_t payload_offset,
    const std::size_t declared_payload_length
) {
    const auto child = make_child_slice(parent, payload_offset, declared_payload_length);
    PFL_REQUIRE(child.has_slice());
    return *child.slice;
}

ByteRange require_range(const std::size_t begin, const std::size_t end) {
    const auto range = ByteRange::from_begin_end(begin, end);
    PFL_REQUIRE(range.has_value());
    return *range;
}

std::string format_builder_path(const ProtocolPathBuilder& builder) {
    PFL_EXPECT(!builder.overflowed());
    return format_protocol_path(builder.to_path());
}

std::string format_shadow_path(const ImportDissectionFacts& facts) {
    return format_builder_path(facts.physical_path);
}

ProtocolPath shadow_path(const ImportDissectionFacts& facts) {
    PFL_EXPECT(!facts.physical_path.overflowed());
    return facts.physical_path.to_path();
}

LegacyDirectFacts decode_legacy_direct(const RawPcapPacket& packet) {
    PacketDecoder decoder {};
    const auto decoded = decoder.decode(packet);

    LegacyDirectFacts facts {};
    if (!decoded.has_value()) {
        return facts;
    }

    facts.recognized_flow = true;
    facts.path = decoded.protocol_path_builder.to_path();

    if (decoded.ipv4.has_value()) {
        facts.family = DissectionAddressFamily::ipv4;
        facts.protocol = decoded.ipv4->flow_key.protocol;
        facts.has_addresses = true;
        facts.src_addr_v4 = decoded.ipv4->flow_key.src_addr;
        facts.dst_addr_v4 = decoded.ipv4->flow_key.dst_addr;
        facts.is_ip_fragmented = decoded.ipv4->packet_ref.is_ip_fragmented;
        facts.has_ports = !facts.is_ip_fragmented;
        facts.src_port = decoded.ipv4->flow_key.src_port;
        facts.dst_port = decoded.ipv4->flow_key.dst_port;
        facts.has_payload_length = !facts.is_ip_fragmented || decoded.ipv4->packet_ref.payload_length != 0U;
        facts.captured_payload_length = decoded.ipv4->packet_ref.payload_length;
        facts.has_tcp_flags = facts.protocol == ProtocolId::tcp && !facts.is_ip_fragmented;
        facts.tcp_flags = decoded.ipv4->packet_ref.tcp_flags;
    } else if (decoded.ipv6.has_value()) {
        facts.family = DissectionAddressFamily::ipv6;
        facts.protocol = decoded.ipv6->flow_key.protocol;
        facts.has_addresses = true;
        facts.src_addr_v6 = decoded.ipv6->flow_key.src_addr;
        facts.dst_addr_v6 = decoded.ipv6->flow_key.dst_addr;
        facts.is_ip_fragmented = decoded.ipv6->packet_ref.is_ip_fragmented;
        facts.has_ports = !facts.is_ip_fragmented;
        facts.src_port = decoded.ipv6->flow_key.src_port;
        facts.dst_port = decoded.ipv6->flow_key.dst_port;
        facts.has_payload_length = !facts.is_ip_fragmented || decoded.ipv6->packet_ref.payload_length != 0U;
        facts.captured_payload_length = decoded.ipv6->packet_ref.payload_length;
        facts.has_tcp_flags = facts.protocol == ProtocolId::tcp && !facts.is_ip_fragmented;
        facts.tcp_flags = decoded.ipv6->packet_ref.tcp_flags;
    }

    return facts;
}

ImportDissectionFacts run_shadow(const RawPcapPacket& packet, const DissectionRegistry& registry) {
    ImportDissectionCollector collector {};
    const DissectionEngine engine {};
    const auto result = engine.run(
        registry,
        make_link_type_selector(packet.data_link_type),
        make_root_slice(packet),
        collector.consumer()
    );
    collector.finish(result);
    return collector.facts();
}

void expect_shadow_matches_legacy_flow(
    const DissectionRegistry& registry,
    const RawPcapPacket& packet,
    const std::string& expected_path,
    const StopReason expected_stop_reason
) {
    const auto legacy = decode_legacy_direct(packet);
    const auto shadow = run_shadow(packet, registry);

    PFL_REQUIRE(legacy.recognized_flow);
    PFL_EXPECT(shadow.outcome == ImportDissectionOutcome::recognized_flow);
    PFL_EXPECT(shadow.stop_reason == expected_stop_reason);
    PFL_EXPECT(shadow_path(shadow) == legacy.path);
    PFL_EXPECT(format_shadow_path(shadow) == expected_path);
    PFL_EXPECT(format_protocol_path(legacy.path) == expected_path);
    PFL_EXPECT(shadow.terminal_protocol == legacy.protocol);
    PFL_EXPECT(shadow.family == legacy.family);
    PFL_EXPECT(shadow.has_flow_addresses == legacy.has_addresses);
    if (legacy.family == DissectionAddressFamily::ipv4) {
        PFL_EXPECT(shadow.src_addr_v4 == legacy.src_addr_v4);
        PFL_EXPECT(shadow.dst_addr_v4 == legacy.dst_addr_v4);
        PFL_EXPECT(shadow.has_ipv4_fragmentation);
        PFL_EXPECT(shadow.ipv4_fragmentation.is_fragmented == legacy.is_ip_fragmented);
    } else if (legacy.family == DissectionAddressFamily::ipv6) {
        PFL_EXPECT(shadow.src_addr_v6 == legacy.src_addr_v6);
        PFL_EXPECT(shadow.dst_addr_v6 == legacy.dst_addr_v6);
        PFL_EXPECT(shadow.has_ipv6_fragmentation);
        PFL_EXPECT(shadow.ipv6_fragmentation.has_fragment_header == legacy.is_ip_fragmented);
    }
    PFL_EXPECT(shadow.has_ports == legacy.has_ports);
    PFL_EXPECT(shadow.src_port == legacy.src_port);
    PFL_EXPECT(shadow.dst_port == legacy.dst_port);
    PFL_EXPECT(shadow.has_transport_payload_length == legacy.has_payload_length);
    PFL_EXPECT(shadow.captured_transport_payload_length == legacy.captured_payload_length);
    PFL_EXPECT(shadow.has_tcp_flags == legacy.has_tcp_flags);
    PFL_EXPECT(shadow.tcp_flags == legacy.tcp_flags);
}

std::vector<std::uint8_t> add_ipv4_options(
    const std::vector<std::uint8_t>& ethernet_packet,
    const std::vector<std::uint8_t>& options
) {
    PFL_REQUIRE((options.size() % 4U) == 0U);
    auto bytes = ethernet_packet;
    constexpr std::size_t ip_offset = 14U;
    const auto old_header_length = static_cast<std::size_t>((bytes[ip_offset] & 0x0FU) * 4U);
    const auto transport_offset = ip_offset + old_header_length;
    bytes.insert(
        bytes.begin() + static_cast<std::ptrdiff_t>(transport_offset),
        options.begin(),
        options.end()
    );

    bytes[ip_offset] = static_cast<std::uint8_t>((bytes[ip_offset] & 0xF0U) | ((old_header_length + options.size()) / 4U));
    const auto total_length = static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(bytes[ip_offset + 2U]) << 8U) |
        static_cast<std::uint16_t>(bytes[ip_offset + 3U])
    );
    const auto new_total_length = static_cast<std::uint16_t>(total_length + options.size());
    bytes[ip_offset + 2U] = static_cast<std::uint8_t>((new_total_length >> 8U) & 0xFFU);
    bytes[ip_offset + 3U] = static_cast<std::uint8_t>(new_total_length & 0xFFU);
    return bytes;
}

void set_ipv4_total_length(std::vector<std::uint8_t>& packet, const std::uint16_t total_length) {
    constexpr std::size_t ip_offset = 14U;
    packet[ip_offset + 2U] = static_cast<std::uint8_t>((total_length >> 8U) & 0xFFU);
    packet[ip_offset + 3U] = static_cast<std::uint8_t>(total_length & 0xFFU);
}

void set_udp_length(std::vector<std::uint8_t>& packet, const std::uint16_t datagram_length) {
    constexpr std::size_t udp_offset = 14U + 20U;
    packet[udp_offset + 4U] = static_cast<std::uint8_t>((datagram_length >> 8U) & 0xFFU);
    packet[udp_offset + 5U] = static_cast<std::uint8_t>(datagram_length & 0xFFU);
}

std::vector<std::uint8_t> make_ethernet_ieee8023_frame(const std::uint16_t payload_length) {
    std::vector<std::uint8_t> bytes {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
        static_cast<std::uint8_t>((payload_length >> 8U) & 0xFFU),
        static_cast<std::uint8_t>(payload_length & 0xFFU),
    };
    for (std::uint16_t index = 0U; index < payload_length; ++index) {
        bytes.push_back(static_cast<std::uint8_t>(index & 0xFFU));
    }
    return bytes;
}

std::vector<std::uint8_t> make_ipv4_header_only_packet(const std::uint8_t protocol) {
    std::vector<std::uint8_t> bytes {
        0xde, 0xad, 0xbe, 0xef, 0x00, 0x01,
        0xca, 0xfe, 0xba, 0xbe, 0x00, 0x02,
        0x08, 0x00,
        0x45, 0x00,
    };
    append_be16(bytes, 20U);
    append_be16(bytes, 0U);
    append_be16(bytes, 0U);
    bytes.push_back(64U);
    bytes.push_back(protocol);
    append_be16(bytes, 0U);
    append_be32(bytes, ipv4(10, 0, 0, 1));
    append_be32(bytes, ipv4(10, 0, 0, 2));
    return bytes;
}

std::vector<std::uint8_t> make_sctp_segment(
    const std::uint16_t src_port,
    const std::uint16_t dst_port,
    const std::uint32_t verification_tag,
    const std::uint32_t checksum,
    const std::uint16_t payload_length = 0U
) {
    std::vector<std::uint8_t> bytes {};
    append_be16(bytes, src_port);
    append_be16(bytes, dst_port);
    append_be32(bytes, verification_tag);
    append_be32(bytes, checksum);
    for (std::uint16_t index = 0U; index < payload_length; ++index) {
        bytes.push_back(static_cast<std::uint8_t>(0x30U + (index % 10U)));
    }
    return bytes;
}

std::vector<std::uint8_t> make_ethernet_ipv4_sctp_packet(
    const std::uint32_t src_addr,
    const std::uint32_t dst_addr,
    const std::uint16_t src_port,
    const std::uint16_t dst_port,
    const std::uint32_t verification_tag,
    const std::uint32_t checksum,
    const std::uint16_t payload_length = 0U
) {
    return make_ethernet_ipv4_fragment_packet(
        src_addr,
        dst_addr,
        detail::kIpProtocolSctp,
        0U,
        make_sctp_segment(src_port, dst_port, verification_tag, checksum, payload_length)
    );
}

std::vector<std::uint8_t> make_ipv6_tcp_segment(
    const std::uint16_t src_port,
    const std::uint16_t dst_port,
    const std::uint16_t payload_length = 0U,
    const std::uint8_t tcp_flags = 0x18U
) {
    std::vector<std::uint8_t> bytes {};
    append_be16(bytes, src_port);
    append_be16(bytes, dst_port);
    append_be32(bytes, 0U);
    append_be32(bytes, 0U);
    bytes.push_back(0x50U);
    bytes.push_back(tcp_flags);
    append_be16(bytes, 0U);
    append_be16(bytes, 0U);
    append_be16(bytes, 0U);
    for (std::uint16_t index = 0U; index < payload_length; ++index) {
        bytes.push_back(static_cast<std::uint8_t>(0x41U + (index % 26U)));
    }
    return bytes;
}

std::vector<std::uint8_t> make_ipv6_routing_extension(
    const std::uint8_t next_header,
    const std::vector<std::uint8_t>& payload
) {
    std::vector<std::uint8_t> bytes {
        next_header,
        0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    bytes.insert(bytes.end(), payload.begin(), payload.end());
    return bytes;
}

std::vector<std::uint8_t> make_ipv6_destination_options_extension(
    const std::uint8_t next_header,
    const std::vector<std::uint8_t>& payload
) {
    std::vector<std::uint8_t> bytes {
        next_header,
        0x00,
        0x01, 0x04, 0x00, 0x00, 0x00, 0x00,
    };
    bytes.insert(bytes.end(), payload.begin(), payload.end());
    return bytes;
}

struct StepKindRecorder {
    std::vector<DissectionLayerKind> kinds {};
};

void record_step_kind(void* context, const DissectionStep& step) {
    auto* recorder = static_cast<StepKindRecorder*>(context);
    recorder->kinds.push_back(step.layer);
}

void expect_common_direct_registry_and_root_selector() {
    const auto built = make_common_direct_registry();
    PFL_REQUIRE(built.ok());
    PFL_EXPECT(built.registry->entry_count() == 17U);

    const auto root_selector = make_link_type_selector(kLinkTypeEthernet);
    PFL_EXPECT(root_selector.domain == SelectorDomain::link_type);
    PFL_EXPECT(root_selector.value == kLinkTypeEthernet);
}

void expect_ethernet_and_vlan_canonical_parsers() {
    const auto plain_tcp = make_raw_packet(make_ethernet_ipv4_tcp_packet(ipv4(10, 0, 0, 1), ipv4(10, 0, 0, 2), 1111U, 2222U));
    const auto plain_root = make_root_slice(plain_tcp);
    const auto ethernet = parse_ethernet_frame(plain_root);
    PFL_EXPECT(ethernet.status == ParseStatus::complete);
    PFL_EXPECT(ethernet.protocol_type == 0x0800U);
    PFL_EXPECT(ethernet.header_length == 14U);
    PFL_EXPECT(ethernet.declared_payload_length == 40U);
    PFL_EXPECT(!ethernet.is_ieee_802_3);

    const auto single_tagged = make_raw_packet(make_single_tagged_ethernet_ipv4_tcp_packet(
        ipv4(192, 168, 1, 10), ipv4(192, 168, 1, 20), 12345U, 443U, 100U));
    const auto single_root = make_root_slice(single_tagged);
    const auto single_ethernet = parse_ethernet_frame(single_root);
    PFL_REQUIRE(single_ethernet.status == ParseStatus::complete);
    const auto single_vlan_slice = require_child_slice(
        single_root,
        single_ethernet.header_length,
        single_ethernet.declared_payload_length
    );
    const auto single_vlan = parse_vlan_tag(single_vlan_slice);
    PFL_EXPECT(single_vlan.status == ParseStatus::complete);
    PFL_EXPECT(single_vlan.tci == 100U);
    PFL_EXPECT(single_vlan.encapsulated_ether_type == 0x0800U);
    PFL_EXPECT(single_vlan.header_length == 4U);

    const auto double_tagged = make_raw_packet(make_double_tagged_ethernet_ipv4_udp_packet(
        ipv4(172, 16, 0, 1), ipv4(172, 16, 0, 2), 5353U, 53U, 200U, 300U));
    const auto double_root = make_root_slice(double_tagged);
    const auto double_ethernet = parse_ethernet_frame(double_root);
    PFL_REQUIRE(double_ethernet.status == ParseStatus::complete);
    const auto outer_vlan_slice = require_child_slice(
        double_root,
        double_ethernet.header_length,
        double_ethernet.declared_payload_length
    );
    const auto outer_vlan = parse_vlan_tag(outer_vlan_slice);
    PFL_EXPECT(outer_vlan.status == ParseStatus::complete);
    PFL_EXPECT((outer_vlan.tci & 0x0FFFU) == 200U);
    PFL_EXPECT(outer_vlan.encapsulated_ether_type == 0x8100U);

    const auto inner_vlan_slice = require_child_slice(
        outer_vlan_slice,
        outer_vlan.header_length,
        outer_vlan.declared_payload_length
    );
    const auto inner_vlan = parse_vlan_tag(inner_vlan_slice);
    PFL_EXPECT(inner_vlan.status == ParseStatus::complete);
    PFL_EXPECT((inner_vlan.tci & 0x0FFFU) == 300U);
    PFL_EXPECT(inner_vlan.encapsulated_ether_type == 0x0800U);

    const auto vid_zero = make_raw_packet(make_single_tagged_ethernet_ipv4_tcp_packet(
        ipv4(10, 10, 10, 1), ipv4(10, 10, 10, 2), 2222U, 80U, 0U));
    const auto vid_zero_ethernet = parse_ethernet_frame(make_root_slice(vid_zero));
    PFL_REQUIRE(vid_zero_ethernet.status == ParseStatus::complete);
    const auto vid_zero_vlan = parse_vlan_tag(require_child_slice(
        make_root_slice(vid_zero),
        vid_zero_ethernet.header_length,
        vid_zero_ethernet.declared_payload_length
    ));
    PFL_EXPECT(vid_zero_vlan.status == ParseStatus::complete);
    PFL_EXPECT((vid_zero_vlan.tci & 0x0FFFU) == 0U);

    const auto truncated_ethernet = make_raw_packet(std::vector<std::uint8_t> {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x66, 0x77, 0x88, 0x99,
    });
    PFL_EXPECT(parse_ethernet_frame(make_root_slice(truncated_ethernet)).status == ParseStatus::truncated);

    const auto truncated_vlan = make_raw_packet(std::vector<std::uint8_t> {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
        0x81, 0x00,
        0x00, 0x64,
    }, 18U);
    const auto truncated_vlan_ethernet = parse_ethernet_frame(make_root_slice(truncated_vlan));
    PFL_REQUIRE(truncated_vlan_ethernet.status == ParseStatus::complete);
    PFL_EXPECT(parse_vlan_tag(require_child_slice(
        make_root_slice(truncated_vlan),
        truncated_vlan_ethernet.header_length,
        truncated_vlan_ethernet.declared_payload_length
    )).status == ParseStatus::truncated);

    const auto ieee8023 = make_raw_packet(make_ethernet_ieee8023_frame(16U));
    const auto parsed_ieee8023 = parse_ethernet_frame(make_root_slice(ieee8023));
    PFL_EXPECT(parsed_ieee8023.status == ParseStatus::complete);
    PFL_EXPECT(parsed_ieee8023.is_ieee_802_3);
    PFL_EXPECT(parsed_ieee8023.protocol_type == 16U);
}

void expect_ipv4_tcp_udp_and_arp_canonical_parsers() {
    const auto registry = make_common_direct_registry();
    PFL_REQUIRE(registry.ok());

    const auto tcp_packet_bytes = make_ethernet_ipv4_tcp_packet_with_payload(
        ipv4(10, 0, 0, 3), ipv4(10, 0, 0, 4), 12345U, 443U, 6U, 0x1BU);
    const auto tcp_packet = make_raw_packet(tcp_packet_bytes);
    const auto tcp_root = make_root_slice(tcp_packet);
    const auto tcp_ethernet = parse_ethernet_frame(tcp_root);
    const auto tcp_ipv4 = parse_ipv4_packet(require_child_slice(tcp_root, tcp_ethernet.header_length, tcp_ethernet.declared_payload_length));
    PFL_EXPECT(tcp_ipv4.status == ParseStatus::complete);
    PFL_EXPECT(tcp_ipv4.protocol == 6U);
    PFL_EXPECT(tcp_ipv4.header_length == 20U);
    PFL_EXPECT(tcp_ipv4.total_length == 46U);
    PFL_EXPECT(!tcp_ipv4.is_fragmented);

    const auto tcp_transport = parse_tcp_segment(require_child_slice(
        require_child_slice(tcp_root, tcp_ethernet.header_length, tcp_ethernet.declared_payload_length),
        tcp_ipv4.header_length,
        tcp_ipv4.nominal_packet_end - tcp_ipv4.header_length
    ));
    PFL_EXPECT(tcp_transport.status == ParseStatus::complete);
    PFL_EXPECT(tcp_transport.src_port == 12345U);
    PFL_EXPECT(tcp_transport.dst_port == 443U);
    PFL_EXPECT(tcp_transport.captured_payload_length == 6U);
    PFL_EXPECT(tcp_transport.flags == 0x1BU);

    auto ipv4_options_bytes = add_ipv4_options(
        make_ethernet_ipv4_tcp_packet(ipv4(10, 0, 0, 5), ipv4(10, 0, 0, 6), 4444U, 5555U),
        {0x01, 0x01, 0x00, 0x00}
    );
    const auto ipv4_options_packet = make_raw_packet(ipv4_options_bytes);
    const auto ipv4_options_root = make_root_slice(ipv4_options_packet);
    const auto ipv4_options_ethernet = parse_ethernet_frame(ipv4_options_root);
    const auto ipv4_options_ipv4_slice = require_child_slice(
        ipv4_options_root,
        ipv4_options_ethernet.header_length,
        ipv4_options_ethernet.declared_payload_length
    );
    const auto ipv4_options_ipv4 = parse_ipv4_packet(ipv4_options_ipv4_slice);
    PFL_EXPECT(ipv4_options_ipv4.status == ParseStatus::complete);
    PFL_EXPECT(ipv4_options_ipv4.header_length == 24U);
    const auto ipv4_options_transport = parse_tcp_segment(require_child_slice(
        ipv4_options_ipv4_slice,
        ipv4_options_ipv4.header_length,
        ipv4_options_ipv4.nominal_packet_end - ipv4_options_ipv4.header_length
    ));
    PFL_EXPECT(ipv4_options_transport.status == ParseStatus::complete);
    PFL_EXPECT(ipv4_options_transport.header_length == 20U);

    auto tcp_options_bytes = make_ethernet_ipv4_tcp_packet(ipv4(10, 0, 0, 7), ipv4(10, 0, 0, 8), 6666U, 7777U);
    tcp_options_bytes.insert(tcp_options_bytes.end(), {0x01, 0x01, 0x00, 0x00});
    set_ipv4_total_length(tcp_options_bytes, 44U);
    tcp_options_bytes[46] = 0x60U;
    const auto tcp_options_packet = make_raw_packet(tcp_options_bytes);
    const auto tcp_options_root = make_root_slice(tcp_options_packet);
    const auto tcp_options_ethernet = parse_ethernet_frame(tcp_options_root);
    const auto tcp_options_ipv4_slice = require_child_slice(
        tcp_options_root,
        tcp_options_ethernet.header_length,
        tcp_options_ethernet.declared_payload_length
    );
    const auto tcp_options_ipv4 = parse_ipv4_packet(tcp_options_ipv4_slice);
    PFL_EXPECT(tcp_options_ipv4.status == ParseStatus::complete);
    PFL_EXPECT(tcp_options_ipv4.header_length == 20U);
    const auto tcp_options_transport = parse_tcp_segment(require_child_slice(
        tcp_options_ipv4_slice,
        tcp_options_ipv4.header_length,
        tcp_options_ipv4.nominal_packet_end - tcp_options_ipv4.header_length
    ));
    PFL_EXPECT(tcp_options_transport.status == ParseStatus::complete);
    PFL_EXPECT(tcp_options_transport.header_length == 24U);

    const auto udp_packet = make_raw_packet(make_ethernet_ipv4_udp_packet_with_bytes_payload(
        ipv4(192, 0, 2, 1), ipv4(192, 0, 2, 2), 5300U, 53U, {0x61, 0x62, 0x63, 0x64}));
    const auto udp_root = make_root_slice(udp_packet);
    const auto udp_ethernet = parse_ethernet_frame(udp_root);
    const auto udp_ipv4_slice = require_child_slice(udp_root, udp_ethernet.header_length, udp_ethernet.declared_payload_length);
    const auto udp_ipv4 = parse_ipv4_packet(udp_ipv4_slice);
    PFL_EXPECT(udp_ipv4.status == ParseStatus::complete);
    PFL_EXPECT(udp_ipv4.protocol == 17U);
    const auto udp_transport = parse_udp_datagram(require_child_slice(
        udp_ipv4_slice,
        udp_ipv4.header_length,
        udp_ipv4.nominal_packet_end - udp_ipv4.header_length
    ));
    PFL_EXPECT(udp_transport.status == ParseStatus::complete);
    PFL_EXPECT(udp_transport.src_port == 5300U);
    PFL_EXPECT(udp_transport.dst_port == 53U);
    PFL_EXPECT(udp_transport.datagram_length == 12U);
    PFL_EXPECT(udp_transport.captured_payload_length == 4U);

    const auto udp_zero_payload = make_raw_packet(make_ethernet_ipv4_udp_packet(
        ipv4(203, 0, 113, 1), ipv4(203, 0, 113, 2), 1000U, 2000U));
    const auto udp_zero_root = make_root_slice(udp_zero_payload);
    const auto udp_zero_ethernet = parse_ethernet_frame(udp_zero_root);
    const auto udp_zero_ipv4 = parse_ipv4_packet(require_child_slice(
        udp_zero_root,
        udp_zero_ethernet.header_length,
        udp_zero_ethernet.declared_payload_length
    ));
    const auto udp_zero_transport = parse_udp_datagram(require_child_slice(
        require_child_slice(udp_zero_root, udp_zero_ethernet.header_length, udp_zero_ethernet.declared_payload_length),
        udp_zero_ipv4.header_length,
        udp_zero_ipv4.nominal_packet_end - udp_zero_ipv4.header_length
    ));
    PFL_EXPECT(udp_zero_transport.status == ParseStatus::complete);
    PFL_EXPECT(udp_zero_transport.captured_payload_length == 0U);

    auto udp_extra_tail = make_ethernet_ipv4_udp_packet(ipv4(203, 0, 113, 10), ipv4(203, 0, 113, 11), 1200U, 2200U);
    udp_extra_tail.push_back(0xAAU);
    udp_extra_tail.push_back(0xBBU);
    udp_extra_tail.push_back(0xCCU);
    const auto udp_extra_tail_packet = make_raw_packet(udp_extra_tail);
    const auto udp_extra_tail_shadow = run_shadow(udp_extra_tail_packet, *registry.registry);
    PFL_EXPECT(udp_extra_tail_shadow.has_transport_payload_length);
    PFL_EXPECT(udp_extra_tail_shadow.captured_transport_payload_length == 0U);

    auto truncated_udp_payload = make_ethernet_ipv4_udp_packet_with_bytes_payload(
        ipv4(203, 0, 113, 20), ipv4(203, 0, 113, 21), 1300U, 2300U, {0x10, 0x20, 0x30, 0x40});
    truncated_udp_payload.resize(truncated_udp_payload.size() - 2U);
    const auto truncated_udp_packet = make_raw_packet(truncated_udp_payload, 46U);
    const auto truncated_udp_shadow = run_shadow(truncated_udp_packet, *registry.registry);
    PFL_EXPECT(truncated_udp_shadow.outcome == ImportDissectionOutcome::recognized_flow);
    PFL_EXPECT(truncated_udp_shadow.captured_transport_payload_length == 2U);

    auto malformed_udp = make_ethernet_ipv4_udp_packet(ipv4(10, 1, 1, 1), ipv4(10, 1, 1, 2), 3000U, 4000U);
    set_udp_length(malformed_udp, 7U);
    const auto malformed_udp_raw = make_raw_packet(malformed_udp);
    const auto malformed_udp_root = make_root_slice(malformed_udp_raw);
    PFL_EXPECT(parse_udp_datagram(require_child_slice(
        require_child_slice(
            malformed_udp_root,
            14U,
            malformed_udp.size() - 14U
        ),
        20U,
        8U
    )).status == ParseStatus::malformed);

    auto invalid_ihl = make_ethernet_ipv4_tcp_packet(ipv4(10, 1, 2, 1), ipv4(10, 1, 2, 2), 100U, 200U);
    invalid_ihl[14] = 0x44U;
    const auto invalid_ihl_raw = make_raw_packet(invalid_ihl);
    const auto invalid_ihl_root = make_root_slice(invalid_ihl_raw);
    PFL_EXPECT(parse_ipv4_packet(require_child_slice(
        invalid_ihl_root,
        14U,
        invalid_ihl.size() - 14U
    )).status == ParseStatus::malformed);

    auto short_total_length = make_ethernet_ipv4_tcp_packet(ipv4(10, 1, 3, 1), ipv4(10, 1, 3, 2), 100U, 200U);
    set_ipv4_total_length(short_total_length, 16U);
    const auto short_total_length_raw = make_raw_packet(short_total_length);
    const auto short_total_length_root = make_root_slice(short_total_length_raw);
    PFL_EXPECT(parse_ipv4_packet(require_child_slice(
        short_total_length_root,
        14U,
        short_total_length.size() - 14U
    )).status == ParseStatus::malformed);

    const auto header_only_ipv4 = make_raw_packet(make_ipv4_header_only_packet(6U));
    const auto header_only_shadow = run_shadow(header_only_ipv4, *registry.registry);
    PFL_EXPECT(header_only_shadow.stop_reason == StopReason::malformed);
    PFL_EXPECT(format_shadow_path(header_only_shadow) == "EthernetII -> IPv4");

    const auto first_fragment_packet = make_raw_packet(make_ethernet_ipv4_fragment_packet(
        ipv4(10, 2, 0, 1), ipv4(10, 2, 0, 2), 6U, 0x2000U, {0x16, 0x03, 0x03, 0x00, 0x10}));
    const auto first_fragment_ipv4 = parse_ipv4_packet(require_child_slice(
        make_root_slice(first_fragment_packet),
        14U,
        first_fragment_packet.bytes.size() - 14U
    ));
    PFL_EXPECT(first_fragment_ipv4.status == ParseStatus::complete);
    PFL_EXPECT(first_fragment_ipv4.is_fragmented);
    PFL_EXPECT(first_fragment_ipv4.more_fragments);
    PFL_EXPECT(first_fragment_ipv4.fragment_offset_units == 0U);

    const auto noninitial_fragment_packet = make_raw_packet(make_ethernet_ipv4_fragment_packet(
        ipv4(10, 2, 0, 3), ipv4(10, 2, 0, 4), 17U, 0x0001U, {0xde, 0xad, 0xbe, 0xef}));
    const auto noninitial_fragment_ipv4 = parse_ipv4_packet(require_child_slice(
        make_root_slice(noninitial_fragment_packet),
        14U,
        noninitial_fragment_packet.bytes.size() - 14U
    ));
    PFL_EXPECT(noninitial_fragment_ipv4.status == ParseStatus::complete);
    PFL_EXPECT(noninitial_fragment_ipv4.is_fragmented);
    PFL_EXPECT(!noninitial_fragment_ipv4.more_fragments);
    PFL_EXPECT(noninitial_fragment_ipv4.fragment_offset_units == 1U);

    const auto arp_bytes = make_ethernet_arp_packet(ipv4(10, 10, 12, 2), ipv4(10, 10, 12, 1));
    const auto arp_packet = make_raw_packet(arp_bytes);
    const auto arp_root = make_root_slice(arp_packet);
    const auto arp_ethernet = parse_ethernet_frame(arp_root);
    const auto arp = parse_arp_packet(require_child_slice(
        arp_root,
        arp_ethernet.header_length,
        arp_ethernet.declared_payload_length
    ));
    PFL_EXPECT(arp.status == ParseStatus::complete);
    PFL_EXPECT(arp.declared_length == 28U);
    PFL_EXPECT(arp.has_sender_ipv4);
    PFL_EXPECT(arp.has_target_ipv4);
    PFL_EXPECT(arp.sender_ipv4 == ipv4(10, 10, 12, 2));
    PFL_EXPECT(arp.target_ipv4 == ipv4(10, 10, 12, 1));

    auto truncated_arp_bytes = arp_bytes;
    truncated_arp_bytes.resize(18U);
    const auto truncated_arp_packet = make_raw_packet(
        truncated_arp_bytes,
        static_cast<std::uint32_t>(arp_bytes.size())
    );
    const auto truncated_arp_root = make_root_slice(truncated_arp_packet);
    const auto truncated_arp = parse_arp_packet(require_child_slice(
        truncated_arp_root,
        14U,
        arp_bytes.size() - 14U
    ));
    PFL_EXPECT(truncated_arp.status == ParseStatus::truncated);
    PFL_EXPECT(truncated_arp.fixed_header_truncated);
    PFL_EXPECT(!truncated_arp.address_section_truncated);

    auto truncated_arp_address_bytes = arp_bytes;
    truncated_arp_address_bytes.resize(30U);
    const auto truncated_arp_address_packet = make_raw_packet(
        truncated_arp_address_bytes,
        static_cast<std::uint32_t>(arp_bytes.size())
    );
    const auto truncated_arp_address_root = make_root_slice(truncated_arp_address_packet);
    const auto truncated_arp_address = parse_arp_packet(require_child_slice(
        truncated_arp_address_root,
        14U,
        arp_bytes.size() - 14U
    ));
    PFL_EXPECT(truncated_arp_address.status == ParseStatus::truncated);
    PFL_EXPECT(!truncated_arp_address.fixed_header_truncated);
    PFL_EXPECT(truncated_arp_address.address_section_truncated);
    PFL_EXPECT(truncated_arp_address.declared_length == 28U);

    auto impossible_arp_bytes = arp_bytes;
    impossible_arp_bytes[18] = 6U;
    impossible_arp_bytes[19] = 16U;
    const auto impossible_arp_packet = make_raw_packet(impossible_arp_bytes);
    const auto impossible_arp_root = make_root_slice(impossible_arp_packet);
    const auto impossible_arp_ethernet = parse_ethernet_frame(impossible_arp_root);
    PFL_REQUIRE(impossible_arp_ethernet.status == ParseStatus::complete);
    const auto impossible_arp = parse_arp_packet(require_child_slice(
        impossible_arp_root,
        impossible_arp_ethernet.header_length,
        impossible_arp_ethernet.declared_payload_length
    ));
    PFL_EXPECT(impossible_arp.status == ParseStatus::malformed);
    PFL_EXPECT(!impossible_arp.fixed_header_truncated);
    PFL_EXPECT(!impossible_arp.address_section_truncated);
    PFL_EXPECT(impossible_arp.declared_length == 52U);
}

void expect_common_direct_steps_report_handoffs_bounds_and_facts() {
    const auto tcp_packet = make_raw_packet(make_ethernet_ipv4_tcp_packet_with_payload(
        ipv4(10, 0, 0, 3), ipv4(10, 0, 0, 4), 12345U, 443U, 6U, 0x1BU));
    const auto tcp_root = make_root_slice(tcp_packet);
    const auto ethernet_step = dissect_ethernet(tcp_root);
    PFL_EXPECT(ethernet_step.layer == DissectionLayerKind::ethernet_ii);
    PFL_REQUIRE(ethernet_step.path_contribution.has_value());
    PFL_EXPECT(*ethernet_step.path_contribution == LayerKey::ethernet_ii());
    PFL_REQUIRE(ethernet_step.handoff.has_value());
    PFL_REQUIRE(ethernet_step.handoff->child.has_value());
    const ProtocolSelector expected_ethernet_selector {
        .domain = SelectorDomain::ether_type,
        .value = 0x0800U,
    };
    PFL_EXPECT(ethernet_step.handoff->selector == expected_ethernet_selector);
    PFL_EXPECT(std::holds_alternative<EthernetFacts>(ethernet_step.facts));
    PFL_EXPECT(ethernet_step.bounds.full.declared == require_range(0U, tcp_packet.bytes.size()));
    PFL_EXPECT(ethernet_step.bounds.full.captured == require_range(0U, tcp_packet.bytes.size()));
    PFL_REQUIRE(ethernet_step.bounds.payload.has_value());
    PFL_EXPECT(ethernet_step.bounds.payload->declared == require_range(14U, tcp_packet.bytes.size()));

    const auto ipv4_step = dissect_ipv4(*ethernet_step.handoff->child);
    PFL_EXPECT(ipv4_step.layer == DissectionLayerKind::ipv4);
    PFL_REQUIRE(ipv4_step.path_contribution.has_value());
    PFL_EXPECT(*ipv4_step.path_contribution == LayerKey::ipv4());
    PFL_REQUIRE(ipv4_step.handoff.has_value());
    PFL_REQUIRE(ipv4_step.handoff->child.has_value());
    const ProtocolSelector expected_ipv4_selector {
        .domain = SelectorDomain::ip_protocol,
        .value = 6U,
    };
    PFL_EXPECT(ipv4_step.handoff->selector == expected_ipv4_selector);
    PFL_EXPECT(std::holds_alternative<Ipv4Facts>(ipv4_step.facts));
    const auto* ipv4_facts = std::get_if<Ipv4Facts>(&ipv4_step.facts);
    PFL_REQUIRE(ipv4_facts != nullptr);
    PFL_EXPECT(ipv4_facts->protocol == 6U);
    PFL_EXPECT(ipv4_facts->src_addr_v4 == ipv4(10, 0, 0, 3));
    PFL_EXPECT(ipv4_facts->dst_addr_v4 == ipv4(10, 0, 0, 4));

    const auto tcp_step = dissect_tcp(*ipv4_step.handoff->child);
    PFL_EXPECT(tcp_step.layer == DissectionLayerKind::tcp);
    PFL_REQUIRE(tcp_step.path_contribution.has_value());
    PFL_EXPECT(*tcp_step.path_contribution == LayerKey::tcp());
    PFL_EXPECT(tcp_step.terminal_disposition == TerminalDisposition::flow_candidate);
    PFL_EXPECT(std::holds_alternative<TcpFacts>(tcp_step.facts));
    const auto* tcp_facts = std::get_if<TcpFacts>(&tcp_step.facts);
    PFL_REQUIRE(tcp_facts != nullptr);
    PFL_EXPECT(tcp_facts->src_port == 12345U);
    PFL_EXPECT(tcp_facts->dst_port == 443U);
    PFL_EXPECT(tcp_facts->flags == 0x1BU);
    PFL_REQUIRE(tcp_step.bounds.payload.has_value());
    PFL_EXPECT(tcp_step.bounds.payload->captured.length() == 6U);

    auto udp_extra_tail = make_ethernet_ipv4_udp_packet(ipv4(203, 0, 113, 10), ipv4(203, 0, 113, 11), 1200U, 2200U);
    udp_extra_tail.push_back(0xAAU);
    udp_extra_tail.push_back(0xBBU);
    udp_extra_tail.push_back(0xCCU);
    set_ipv4_total_length(udp_extra_tail, 31U);
    const auto udp_packet = make_raw_packet(udp_extra_tail);
    const auto udp_root = make_root_slice(udp_packet);
    const auto udp_ethernet = parse_ethernet_frame(udp_root);
    PFL_REQUIRE(udp_ethernet.status == ParseStatus::complete);
    const auto udp_ipv4_slice = require_child_slice(udp_root, udp_ethernet.header_length, udp_ethernet.declared_payload_length);
    const auto udp_ipv4 = parse_ipv4_packet(udp_ipv4_slice);
    PFL_REQUIRE(udp_ipv4.status == ParseStatus::complete);
    const auto udp_transport_slice = require_child_slice(
        udp_ipv4_slice,
        udp_ipv4.header_length,
        udp_ipv4.nominal_packet_end - udp_ipv4.header_length
    );
    PFL_EXPECT(udp_transport_slice.declared_end() - udp_transport_slice.source_offset() == 11U);
    const auto udp_step = dissect_udp(udp_transport_slice);
    PFL_EXPECT(udp_step.layer == DissectionLayerKind::udp);
    PFL_REQUIRE(udp_step.path_contribution.has_value());
    PFL_EXPECT(*udp_step.path_contribution == LayerKey::udp());
    PFL_EXPECT(udp_step.terminal_disposition == TerminalDisposition::flow_candidate);
    PFL_EXPECT(std::holds_alternative<UdpFacts>(udp_step.facts));
    const auto* udp_facts = std::get_if<UdpFacts>(&udp_step.facts);
    PFL_REQUIRE(udp_facts != nullptr);
    PFL_EXPECT(udp_facts->datagram_length == 8U);
    PFL_EXPECT(udp_step.bounds.full.declared.length() == 8U);
    PFL_EXPECT(udp_step.bounds.full.captured.length() == 8U);
    PFL_REQUIRE(udp_step.bounds.payload.has_value());
    PFL_EXPECT(udp_step.bounds.payload->declared.length() == 0U);
    PFL_EXPECT(udp_step.bounds.payload->captured.length() == 0U);

    const auto ipv6_udp_packet = make_raw_packet(make_ethernet_ipv6_udp_with_hop_by_hop_packet(
        ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5}),
        ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6}),
        53000U,
        53001U
    ));
    const auto ipv6_udp_root = make_root_slice(ipv6_udp_packet);
    const auto ipv6_udp_ethernet = dissect_ethernet(ipv6_udp_root);
    PFL_REQUIRE(ipv6_udp_ethernet.handoff.has_value());
    PFL_REQUIRE(ipv6_udp_ethernet.handoff->child.has_value());
    const auto ipv6_step = dissect_ipv6(*ipv6_udp_ethernet.handoff->child);
    PFL_EXPECT(ipv6_step.layer == DissectionLayerKind::ipv6);
    PFL_REQUIRE(ipv6_step.path_contribution.has_value());
    PFL_EXPECT(*ipv6_step.path_contribution == LayerKey::ipv6());
    PFL_REQUIRE(ipv6_step.handoff.has_value());
    PFL_REQUIRE(ipv6_step.handoff->child.has_value());
    const ProtocolSelector expected_ipv6_selector {
        .domain = SelectorDomain::ipv6_next_header,
        .value = detail::kIpProtocolHopByHop,
    };
    PFL_EXPECT(ipv6_step.handoff->selector == expected_ipv6_selector);
    PFL_EXPECT(std::holds_alternative<Ipv6Facts>(ipv6_step.facts));
    const auto* ipv6_facts = std::get_if<Ipv6Facts>(&ipv6_step.facts);
    PFL_REQUIRE(ipv6_facts != nullptr);
    PFL_EXPECT(ipv6_facts->next_header == detail::kIpProtocolHopByHop);
    PFL_EXPECT(!ipv6_facts->has_fragment_header);
    PFL_REQUIRE(ipv6_step.bounds.payload.has_value());
    PFL_EXPECT(ipv6_step.bounds.payload->declared.length() == 16U);

    const auto hop_by_hop_step = dissect_ipv6_hop_by_hop(*ipv6_step.handoff->child);
    PFL_EXPECT(hop_by_hop_step.layer == DissectionLayerKind::ipv6_hop_by_hop);
    PFL_EXPECT(!hop_by_hop_step.path_contribution.has_value());
    PFL_REQUIRE(hop_by_hop_step.handoff.has_value());
    PFL_REQUIRE(hop_by_hop_step.handoff->child.has_value());
    const ProtocolSelector expected_hop_selector {
        .domain = SelectorDomain::ipv6_next_header,
        .value = detail::kIpProtocolUdp,
    };
    PFL_EXPECT(hop_by_hop_step.handoff->selector == expected_hop_selector);
    PFL_EXPECT(std::holds_alternative<Ipv6ExtensionFacts>(hop_by_hop_step.facts));
    const auto* hop_by_hop_facts = std::get_if<Ipv6ExtensionFacts>(&hop_by_hop_step.facts);
    PFL_REQUIRE(hop_by_hop_facts != nullptr);
    PFL_EXPECT(hop_by_hop_facts->kind == DissectionLayerKind::ipv6_hop_by_hop);
    PFL_EXPECT(hop_by_hop_facts->next_header == detail::kIpProtocolUdp);
    PFL_EXPECT(hop_by_hop_step.bounds.source_id == ipv6_step.bounds.source_id);
    PFL_EXPECT(hop_by_hop_step.bounds.full.declared.length() == 8U);
    PFL_EXPECT(hop_by_hop_step.bounds.header.declared.length() == 8U);
    PFL_EXPECT(!hop_by_hop_step.bounds.payload.has_value());

    const auto ipv6_udp_step = dissect_udp(*hop_by_hop_step.handoff->child);
    PFL_EXPECT(ipv6_udp_step.layer == DissectionLayerKind::udp);
    PFL_EXPECT(ipv6_udp_step.terminal_disposition == TerminalDisposition::flow_candidate);
    PFL_REQUIRE(ipv6_udp_step.bounds.payload.has_value());
    PFL_EXPECT(ipv6_udp_step.bounds.payload->declared.length() == 0U);
}

void expect_failed_layers_do_not_contribute_path_and_exact_arp_bounds() {
    const auto truncated_vlan_packet = make_raw_packet(std::vector<std::uint8_t> {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
        0x81, 0x00,
        0x00, 0x64,
    }, 18U);
    const auto truncated_vlan_root = make_root_slice(truncated_vlan_packet);
    const auto truncated_vlan_ethernet = parse_ethernet_frame(truncated_vlan_root);
    PFL_REQUIRE(truncated_vlan_ethernet.status == ParseStatus::complete);
    const auto truncated_vlan_step = dissect_vlan(require_child_slice(
        truncated_vlan_root,
        truncated_vlan_ethernet.header_length,
        truncated_vlan_ethernet.declared_payload_length
    ));
    PFL_EXPECT(truncated_vlan_step.layer == DissectionLayerKind::vlan);
    PFL_EXPECT(truncated_vlan_step.status == ParseStatus::truncated);
    PFL_EXPECT(!truncated_vlan_step.path_contribution.has_value());

    auto invalid_ihl_packet = make_ethernet_ipv4_tcp_packet(ipv4(10, 8, 0, 1), ipv4(10, 8, 0, 2), 1U, 2U);
    invalid_ihl_packet[14] = 0x44U;
    const auto invalid_ihl_raw_packet = make_raw_packet(invalid_ihl_packet);
    const auto invalid_ihl_root = make_root_slice(invalid_ihl_raw_packet);
    const auto invalid_ihl_ethernet = parse_ethernet_frame(invalid_ihl_root);
    PFL_REQUIRE(invalid_ihl_ethernet.status == ParseStatus::complete);
    const auto invalid_ipv4_step = dissect_ipv4(require_child_slice(
        invalid_ihl_root,
        invalid_ihl_ethernet.header_length,
        invalid_ihl_ethernet.declared_payload_length
    ));
    PFL_EXPECT(invalid_ipv4_step.status == ParseStatus::malformed);
    PFL_EXPECT(!invalid_ipv4_step.path_contribution.has_value());

    const auto header_only_tcp_packet = make_raw_packet(make_ipv4_header_only_packet(6U));
    const auto header_only_tcp_root = make_root_slice(header_only_tcp_packet);
    const auto header_only_tcp_ethernet = parse_ethernet_frame(header_only_tcp_root);
    PFL_REQUIRE(header_only_tcp_ethernet.status == ParseStatus::complete);
    const auto header_only_tcp_ipv4_slice = require_child_slice(
        header_only_tcp_root,
        header_only_tcp_ethernet.header_length,
        header_only_tcp_ethernet.declared_payload_length
    );
    const auto header_only_tcp_ipv4 = parse_ipv4_packet(header_only_tcp_ipv4_slice);
    PFL_REQUIRE(header_only_tcp_ipv4.status == ParseStatus::complete);
    const auto header_only_tcp_step = dissect_tcp(require_child_slice(
        header_only_tcp_ipv4_slice,
        header_only_tcp_ipv4.header_length,
        header_only_tcp_ipv4.nominal_packet_end - header_only_tcp_ipv4.header_length
    ));
    PFL_EXPECT(header_only_tcp_step.status == ParseStatus::malformed);
    PFL_EXPECT(!header_only_tcp_step.path_contribution.has_value());

    auto malformed_udp_packet = make_ethernet_ipv4_udp_packet(ipv4(10, 1, 1, 1), ipv4(10, 1, 1, 2), 3000U, 4000U);
    set_udp_length(malformed_udp_packet, 7U);
    const auto malformed_udp_raw_packet = make_raw_packet(malformed_udp_packet);
    const auto malformed_udp_root = make_root_slice(malformed_udp_raw_packet);
    const auto malformed_udp_ethernet = parse_ethernet_frame(malformed_udp_root);
    PFL_REQUIRE(malformed_udp_ethernet.status == ParseStatus::complete);
    const auto malformed_udp_ipv4_slice = require_child_slice(
        malformed_udp_root,
        malformed_udp_ethernet.header_length,
        malformed_udp_ethernet.declared_payload_length
    );
    const auto malformed_udp_ipv4 = parse_ipv4_packet(malformed_udp_ipv4_slice);
    PFL_REQUIRE(malformed_udp_ipv4.status == ParseStatus::complete);
    const auto malformed_udp_step = dissect_udp(require_child_slice(
        malformed_udp_ipv4_slice,
        malformed_udp_ipv4.header_length,
        malformed_udp_ipv4.nominal_packet_end - malformed_udp_ipv4.header_length
    ));
    PFL_EXPECT(malformed_udp_step.status == ParseStatus::malformed);
    PFL_EXPECT(!malformed_udp_step.path_contribution.has_value());

    const auto truncated_ipv6_extension_packet = make_raw_packet(make_truncated_ethernet_ipv6_extension_packet(
        ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7}),
        ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8})
    ));
    const auto truncated_ipv6_extension_root = make_root_slice(truncated_ipv6_extension_packet);
    const auto truncated_ipv6_extension_ethernet = parse_ethernet_frame(truncated_ipv6_extension_root);
    PFL_REQUIRE(truncated_ipv6_extension_ethernet.status == ParseStatus::complete);
    const auto truncated_ipv6_step = dissect_ipv6(require_child_slice(
        truncated_ipv6_extension_root,
        truncated_ipv6_extension_ethernet.header_length,
        truncated_ipv6_extension_ethernet.declared_payload_length
    ));
    PFL_EXPECT(truncated_ipv6_step.status == ParseStatus::complete);
    PFL_REQUIRE(truncated_ipv6_step.path_contribution.has_value());
    PFL_EXPECT(*truncated_ipv6_step.path_contribution == LayerKey::ipv6());
    PFL_REQUIRE(truncated_ipv6_step.handoff.has_value());
    PFL_REQUIRE(truncated_ipv6_step.handoff->child.has_value());
    const auto truncated_hop_by_hop_step = dissect_ipv6_hop_by_hop(*truncated_ipv6_step.handoff->child);
    PFL_EXPECT(truncated_hop_by_hop_step.status == ParseStatus::malformed);
    PFL_EXPECT(!truncated_hop_by_hop_step.path_contribution.has_value());

    const auto arp_bytes = make_ethernet_arp_packet(ipv4(10, 10, 12, 2), ipv4(10, 10, 12, 1));
    auto padded_arp_bytes = arp_bytes;
    padded_arp_bytes.insert(padded_arp_bytes.end(), {0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
    const auto padded_arp_packet = make_raw_packet(padded_arp_bytes);
    const auto padded_arp_root = make_root_slice(padded_arp_packet);
    const auto padded_arp_ethernet = parse_ethernet_frame(padded_arp_root);
    PFL_REQUIRE(padded_arp_ethernet.status == ParseStatus::complete);
    const auto padded_arp_step = dissect_arp(require_child_slice(
        padded_arp_root,
        padded_arp_ethernet.header_length,
        padded_arp_ethernet.declared_payload_length
    ));
    PFL_EXPECT(padded_arp_step.status == ParseStatus::complete);
    PFL_REQUIRE(padded_arp_step.path_contribution.has_value());
    PFL_EXPECT(*padded_arp_step.path_contribution == LayerKey::arp());
    PFL_EXPECT(padded_arp_step.bounds.full.declared.length() == 28U);
    PFL_EXPECT(padded_arp_step.bounds.full.captured.length() == 28U);
    PFL_EXPECT(padded_arp_step.bounds.header.declared.length() == 8U);
    PFL_EXPECT(padded_arp_step.bounds.header.captured.length() == 8U);
    PFL_REQUIRE(padded_arp_step.bounds.payload.has_value());
    PFL_EXPECT(padded_arp_step.bounds.payload->declared.length() == 20U);
    PFL_EXPECT(padded_arp_step.bounds.payload->captured.length() == 20U);
    PFL_EXPECT(padded_arp_step.terminal_disposition == TerminalDisposition::recognized_non_flow);

    auto truncated_arp_fixed_header_bytes = arp_bytes;
    truncated_arp_fixed_header_bytes.resize(18U);
    const auto truncated_arp_fixed_header_packet = make_raw_packet(
        truncated_arp_fixed_header_bytes,
        static_cast<std::uint32_t>(arp_bytes.size())
    );
    const auto truncated_arp_fixed_header_root = make_root_slice(truncated_arp_fixed_header_packet);
    const auto truncated_arp_fixed_header_ethernet = parse_ethernet_frame(truncated_arp_fixed_header_root);
    PFL_REQUIRE(truncated_arp_fixed_header_ethernet.status == ParseStatus::complete);
    const auto truncated_arp_fixed_header_step = dissect_arp(require_child_slice(
        truncated_arp_fixed_header_root,
        truncated_arp_fixed_header_ethernet.header_length,
        truncated_arp_fixed_header_ethernet.declared_payload_length
    ));
    PFL_EXPECT(truncated_arp_fixed_header_step.status == ParseStatus::truncated);
    PFL_EXPECT(!truncated_arp_fixed_header_step.path_contribution.has_value());
    PFL_EXPECT(!truncated_arp_fixed_header_step.bounds.payload.has_value());

    auto truncated_arp_address_bytes = arp_bytes;
    truncated_arp_address_bytes.resize(30U);
    const auto truncated_arp_address_packet = make_raw_packet(
        truncated_arp_address_bytes,
        static_cast<std::uint32_t>(arp_bytes.size())
    );
    const auto truncated_arp_address_root = make_root_slice(truncated_arp_address_packet);
    const auto truncated_arp_address_ethernet = parse_ethernet_frame(truncated_arp_address_root);
    PFL_REQUIRE(truncated_arp_address_ethernet.status == ParseStatus::complete);
    const auto truncated_arp_address_step = dissect_arp(require_child_slice(
        truncated_arp_address_root,
        truncated_arp_address_ethernet.header_length,
        truncated_arp_address_ethernet.declared_payload_length
    ));
    PFL_EXPECT(truncated_arp_address_step.status == ParseStatus::truncated);
    PFL_EXPECT(!truncated_arp_address_step.path_contribution.has_value());
    PFL_EXPECT(truncated_arp_address_step.bounds.full.declared.length() == 28U);
    PFL_EXPECT(truncated_arp_address_step.bounds.full.captured.length() == 16U);
    PFL_EXPECT(truncated_arp_address_step.bounds.header.declared.length() == 8U);
    PFL_EXPECT(truncated_arp_address_step.bounds.header.captured.length() == 8U);
    PFL_REQUIRE(truncated_arp_address_step.bounds.payload.has_value());
    PFL_EXPECT(truncated_arp_address_step.bounds.payload->declared.length() == 20U);
    PFL_EXPECT(truncated_arp_address_step.bounds.payload->captured.length() == 8U);

    auto impossible_arp_bytes = arp_bytes;
    impossible_arp_bytes[18] = 6U;
    impossible_arp_bytes[19] = 16U;
    const auto impossible_arp_packet = make_raw_packet(impossible_arp_bytes);
    const auto impossible_arp_root = make_root_slice(impossible_arp_packet);
    const auto impossible_arp_ethernet = parse_ethernet_frame(impossible_arp_root);
    PFL_REQUIRE(impossible_arp_ethernet.status == ParseStatus::complete);
    const auto impossible_arp_step = dissect_arp(require_child_slice(
        impossible_arp_root,
        impossible_arp_ethernet.header_length,
        impossible_arp_ethernet.declared_payload_length
    ));
    PFL_EXPECT(impossible_arp_step.status == ParseStatus::malformed);
    PFL_EXPECT(impossible_arp_step.stop_reason == StopReason::malformed);
    PFL_EXPECT(!impossible_arp_step.path_contribution.has_value());
    PFL_EXPECT(impossible_arp_step.terminal_disposition == TerminalDisposition::none);
    PFL_EXPECT(impossible_arp_step.bounds.full.declared.length() == 28U);
    PFL_EXPECT(impossible_arp_step.bounds.full.captured.length() == 28U);
    PFL_EXPECT(impossible_arp_step.bounds.header.declared.length() == 8U);
    PFL_EXPECT(impossible_arp_step.bounds.header.captured.length() == 8U);
    PFL_REQUIRE(impossible_arp_step.bounds.payload.has_value());
    PFL_EXPECT(impossible_arp_step.bounds.payload->declared.length() == 20U);
    PFL_EXPECT(impossible_arp_step.bounds.payload->captured.length() == 20U);
}

void expect_ipv6_and_extension_canonical_parsers() {
    const auto built = make_common_direct_registry();
    PFL_REQUIRE(built.ok());
    const auto& registry = *built.registry;
    const auto src_addr = ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1});
    const auto dst_addr = ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2});

    const auto direct_udp_packet = make_raw_packet(make_ethernet_ipv6_packet(
        src_addr,
        dst_addr,
        detail::kIpProtocolUdp,
        make_ipv6_udp_segment(5300U, 53U, 4U)
    ));
    const auto direct_udp_root = make_root_slice(direct_udp_packet);
    const auto direct_udp_ethernet = parse_ethernet_frame(direct_udp_root);
    PFL_REQUIRE(direct_udp_ethernet.status == ParseStatus::complete);
    const auto direct_udp_ipv6_slice = require_child_slice(
        direct_udp_root,
        direct_udp_ethernet.header_length,
        direct_udp_ethernet.declared_payload_length
    );
    const auto direct_udp_ipv6 = parse_ipv6_packet(direct_udp_ipv6_slice);
    PFL_EXPECT(direct_udp_ipv6.status == ParseStatus::complete);
    PFL_EXPECT(direct_udp_ipv6.next_header == detail::kIpProtocolUdp);
    PFL_EXPECT(direct_udp_ipv6.payload_length == 12U);
    PFL_EXPECT(direct_udp_ipv6.header_length == detail::kIpv6HeaderSize);
    PFL_EXPECT(direct_udp_ipv6.nominal_packet_end == 52U);

    const auto direct_udp_payload_slice = require_child_slice(
        direct_udp_ipv6_slice,
        direct_udp_ipv6.header_length,
        direct_udp_ipv6.payload_length
    );
    const auto direct_udp_transport = parse_udp_datagram(direct_udp_payload_slice);
    PFL_EXPECT(direct_udp_transport.status == ParseStatus::complete);
    PFL_EXPECT(direct_udp_transport.src_port == 5300U);
    PFL_EXPECT(direct_udp_transport.dst_port == 53U);
    PFL_EXPECT(direct_udp_transport.captured_payload_length == 4U);

    const auto hop_by_hop_packet = make_raw_packet(make_ethernet_ipv6_udp_with_hop_by_hop_packet(
        src_addr,
        dst_addr,
        61000U,
        443U
    ));
    const auto hop_by_hop_root = make_root_slice(hop_by_hop_packet);
    const auto hop_by_hop_ethernet = parse_ethernet_frame(hop_by_hop_root);
    PFL_REQUIRE(hop_by_hop_ethernet.status == ParseStatus::complete);
    const auto hop_by_hop_ipv6_slice = require_child_slice(
        hop_by_hop_root,
        hop_by_hop_ethernet.header_length,
        hop_by_hop_ethernet.declared_payload_length
    );
    const auto hop_by_hop_ipv6 = parse_ipv6_packet(hop_by_hop_ipv6_slice);
    PFL_REQUIRE(hop_by_hop_ipv6.status == ParseStatus::complete);
    const auto hop_by_hop_payload_slice = require_child_slice(
        hop_by_hop_ipv6_slice,
        hop_by_hop_ipv6.header_length,
        hop_by_hop_ipv6.payload_length
    );
    const auto hop_extension = parse_ipv6_extension_header(
        hop_by_hop_payload_slice,
        Ipv6ExtensionHeaderKind::hop_by_hop
    );
    PFL_EXPECT(hop_extension.status == ParseStatus::complete);
    PFL_EXPECT(hop_extension.next_header == detail::kIpProtocolUdp);
    PFL_EXPECT(hop_extension.header_length == 8U);
    const auto hop_by_hop_step = dissect_ipv6_hop_by_hop(hop_by_hop_payload_slice);
    PFL_EXPECT(hop_by_hop_step.status == ParseStatus::complete);
    PFL_EXPECT(hop_by_hop_step.layer == DissectionLayerKind::ipv6_hop_by_hop);
    PFL_EXPECT(!hop_by_hop_step.path_contribution.has_value());
    PFL_REQUIRE(hop_by_hop_step.handoff.has_value());
    PFL_REQUIRE(hop_by_hop_step.handoff->child.has_value());
    const ProtocolSelector expected_hop_by_hop_selector {
        .domain = SelectorDomain::ipv6_next_header,
        .value = detail::kIpProtocolUdp,
    };
    PFL_EXPECT(hop_by_hop_step.handoff->selector == expected_hop_by_hop_selector);
    StepKindRecorder hop_recorder {};
    const DissectionEngine engine {};
    const auto hop_engine_result = engine.run(
        registry,
        make_link_type_selector(hop_by_hop_packet.data_link_type),
        hop_by_hop_root,
        DissectionConsumer {.on_step = record_step_kind, .context = &hop_recorder}
    );
    const std::vector<DissectionLayerKind> expected_hop_kinds {
        DissectionLayerKind::ethernet_ii,
        DissectionLayerKind::ipv6,
        DissectionLayerKind::ipv6_hop_by_hop,
        DissectionLayerKind::udp,
    };
    PFL_EXPECT(hop_engine_result.stop_reason == StopReason::terminal_protocol);
    PFL_EXPECT(hop_recorder.kinds == expected_hop_kinds);

    const auto routing_packet = make_raw_packet(make_ethernet_ipv6_packet(
        src_addr,
        dst_addr,
        detail::kIpProtocolRouting,
        make_ipv6_routing_extension(detail::kIpProtocolUdp, make_ipv6_udp_segment(1200U, 2200U))
    ));
    const auto routing_root = make_root_slice(routing_packet);
    const auto routing_ethernet = parse_ethernet_frame(routing_root);
    PFL_REQUIRE(routing_ethernet.status == ParseStatus::complete);
    const auto routing_ipv6_slice = require_child_slice(
        routing_root,
        routing_ethernet.header_length,
        routing_ethernet.declared_payload_length
    );
    const auto routing_ipv6 = parse_ipv6_packet(routing_ipv6_slice);
    PFL_REQUIRE(routing_ipv6.status == ParseStatus::complete);
    const auto routing_payload_slice = require_child_slice(
        routing_ipv6_slice,
        routing_ipv6.header_length,
        routing_ipv6.payload_length
    );
    const auto routing_extension = parse_ipv6_extension_header(
        routing_payload_slice,
        Ipv6ExtensionHeaderKind::routing
    );
    PFL_EXPECT(routing_extension.status == ParseStatus::complete);
    PFL_EXPECT(routing_extension.next_header == detail::kIpProtocolUdp);
    const auto routing_step = dissect_ipv6_routing(routing_payload_slice);
    PFL_EXPECT(routing_step.status == ParseStatus::complete);
    PFL_EXPECT(routing_step.layer == DissectionLayerKind::ipv6_routing);
    PFL_EXPECT(!routing_step.path_contribution.has_value());
    PFL_REQUIRE(routing_step.handoff.has_value());
    PFL_REQUIRE(routing_step.handoff->child.has_value());
    const ProtocolSelector expected_routing_selector {
        .domain = SelectorDomain::ipv6_next_header,
        .value = detail::kIpProtocolUdp,
    };
    PFL_EXPECT(routing_step.handoff->selector == expected_routing_selector);

    const auto destination_tcp_packet = make_raw_packet(make_ethernet_ipv6_packet(
        src_addr,
        dst_addr,
        detail::kIpProtocolDestinationOptions,
        make_ipv6_destination_options_extension(detail::kIpProtocolTcp, make_ipv6_tcp_segment(32000U, 443U, 3U, 0x19U))
    ));
    const auto destination_tcp_root = make_root_slice(destination_tcp_packet);
    const auto destination_tcp_ethernet = parse_ethernet_frame(destination_tcp_root);
    PFL_REQUIRE(destination_tcp_ethernet.status == ParseStatus::complete);
    const auto destination_tcp_ipv6_slice = require_child_slice(
        destination_tcp_root,
        destination_tcp_ethernet.header_length,
        destination_tcp_ethernet.declared_payload_length
    );
    const auto destination_tcp_ipv6 = parse_ipv6_packet(destination_tcp_ipv6_slice);
    PFL_REQUIRE(destination_tcp_ipv6.status == ParseStatus::complete);
    const auto destination_payload_slice = require_child_slice(
        destination_tcp_ipv6_slice,
        destination_tcp_ipv6.header_length,
        destination_tcp_ipv6.payload_length
    );
    const auto destination_extension = parse_ipv6_extension_header(
        destination_payload_slice,
        Ipv6ExtensionHeaderKind::destination_options
    );
    PFL_EXPECT(destination_extension.status == ParseStatus::complete);
    PFL_EXPECT(destination_extension.next_header == detail::kIpProtocolTcp);
    const auto destination_step = dissect_ipv6_destination_options(destination_payload_slice);
    PFL_EXPECT(destination_step.status == ParseStatus::complete);
    PFL_EXPECT(destination_step.layer == DissectionLayerKind::ipv6_destination_options);
    PFL_EXPECT(!destination_step.path_contribution.has_value());
    PFL_REQUIRE(destination_step.handoff.has_value());
    PFL_REQUIRE(destination_step.handoff->child.has_value());
    const ProtocolSelector expected_destination_selector {
        .domain = SelectorDomain::ipv6_next_header,
        .value = detail::kIpProtocolTcp,
    };
    PFL_EXPECT(destination_step.handoff->selector == expected_destination_selector);

    const auto fragment_packet = make_raw_packet(make_ethernet_ipv6_fragment_packet(
        src_addr,
        dst_addr,
        detail::kIpProtocolUdp,
        make_ipv6_udp_segment(45000U, 45001U, 2U)
    ));
    const auto fragment_root = make_root_slice(fragment_packet);
    const auto fragment_ethernet = parse_ethernet_frame(fragment_root);
    PFL_REQUIRE(fragment_ethernet.status == ParseStatus::complete);
    const auto fragment_ipv6_slice = require_child_slice(
        fragment_root,
        fragment_ethernet.header_length,
        fragment_ethernet.declared_payload_length
    );
    const auto fragment_ipv6 = parse_ipv6_packet(fragment_ipv6_slice);
    PFL_REQUIRE(fragment_ipv6.status == ParseStatus::complete);
    const auto fragment_payload_slice = require_child_slice(
        fragment_ipv6_slice,
        fragment_ipv6.header_length,
        fragment_ipv6.payload_length
    );
    const auto fragment_header = parse_ipv6_fragment_header(fragment_payload_slice);
    PFL_EXPECT(fragment_header.status == ParseStatus::complete);
    PFL_EXPECT(fragment_header.next_header == detail::kIpProtocolUdp);
    PFL_EXPECT(fragment_header.fragment_offset_units == 0U);
    PFL_EXPECT(!fragment_header.more_fragments);
    PFL_EXPECT(fragment_header.is_atomic_fragment);
    const auto fragment_step = dissect_ipv6_fragment(fragment_payload_slice);
    PFL_EXPECT(fragment_step.status == ParseStatus::complete);
    PFL_EXPECT(fragment_step.layer == DissectionLayerKind::ipv6_fragment);
    PFL_EXPECT(!fragment_step.path_contribution.has_value());
    PFL_REQUIRE(fragment_step.handoff.has_value());
    const ProtocolSelector expected_fragment_selector {
        .domain = SelectorDomain::ipv6_next_header,
        .value = detail::kIpProtocolUdp,
    };
    PFL_EXPECT(fragment_step.handoff->selector == expected_fragment_selector);
    PFL_EXPECT(!fragment_step.handoff->child.has_value());
    PFL_EXPECT(fragment_step.stop_reason == StopReason::needs_reassembly);
    PFL_EXPECT(std::holds_alternative<Ipv6FragmentFacts>(fragment_step.facts));
    const auto* fragment_facts = std::get_if<Ipv6FragmentFacts>(&fragment_step.facts);
    PFL_REQUIRE(fragment_facts != nullptr);
    PFL_EXPECT(fragment_facts->fragment_offset_units == 0U);
    PFL_EXPECT(!fragment_facts->more_fragments);
    PFL_EXPECT(fragment_facts->is_atomic_fragment);

    const auto truncated_extension_packet = make_raw_packet(make_truncated_ethernet_ipv6_extension_packet(src_addr, dst_addr));
    const auto truncated_extension_root = make_root_slice(truncated_extension_packet);
    const auto truncated_extension_ethernet = parse_ethernet_frame(truncated_extension_root);
    PFL_REQUIRE(truncated_extension_ethernet.status == ParseStatus::complete);
    const auto truncated_extension_ipv6_slice = require_child_slice(
        truncated_extension_root,
        truncated_extension_ethernet.header_length,
        truncated_extension_ethernet.declared_payload_length
    );
    const auto truncated_extension_ipv6 = parse_ipv6_packet(truncated_extension_ipv6_slice);
    PFL_REQUIRE(truncated_extension_ipv6.status == ParseStatus::complete);
    const auto truncated_extension_payload_slice = require_child_slice(
        truncated_extension_ipv6_slice,
        truncated_extension_ipv6.header_length,
        truncated_extension_ipv6.payload_length
    );
    const auto truncated_extension = parse_ipv6_extension_header(
        truncated_extension_payload_slice,
        Ipv6ExtensionHeaderKind::hop_by_hop
    );
    PFL_EXPECT(truncated_extension.status == ParseStatus::malformed);
}

void expect_sctp_canonical_parsers_and_bounds() {
    const auto built = make_common_direct_registry();
    PFL_REQUIRE(built.ok());
    const auto& registry = *built.registry;

    const auto exact_header_bytes = make_sctp_segment(49152U, 36412U, 0x10213243U, 0x89ABCDEFU);
    const auto exact_header_packet = make_raw_packet(exact_header_bytes, detail::kSctpCommonHeaderSize);
    const auto exact_header_root = make_root_slice(exact_header_packet);
    const auto exact_header = parse_sctp_common_header(exact_header_root);
    PFL_EXPECT(exact_header.status == ParseStatus::complete);
    PFL_EXPECT(exact_header.src_port == 49152U);
    PFL_EXPECT(exact_header.dst_port == 36412U);
    PFL_EXPECT(exact_header.verification_tag == 0x10213243U);
    PFL_EXPECT(exact_header.checksum == 0x89ABCDEFU);
    PFL_EXPECT(exact_header.header_length == detail::kSctpCommonHeaderSize);
    PFL_EXPECT(exact_header.captured_payload_length == 0U);

    const auto exact_header_step = dissect_sctp(exact_header_root);
    PFL_EXPECT(exact_header_step.layer == DissectionLayerKind::sctp);
    PFL_REQUIRE(exact_header_step.path_contribution.has_value());
    PFL_EXPECT(*exact_header_step.path_contribution == LayerKey::sctp());
    PFL_EXPECT(exact_header_step.terminal_disposition == TerminalDisposition::flow_candidate);
    PFL_EXPECT(exact_header_step.bounds.source_id == exact_header_root.source_id());
    PFL_EXPECT(exact_header_step.bounds.full.declared.length() == detail::kSctpCommonHeaderSize);
    PFL_EXPECT(exact_header_step.bounds.full.captured.length() == detail::kSctpCommonHeaderSize);
    PFL_EXPECT(exact_header_step.bounds.header.declared.length() == detail::kSctpCommonHeaderSize);
    PFL_EXPECT(exact_header_step.bounds.header.captured.length() == detail::kSctpCommonHeaderSize);
    PFL_REQUIRE(exact_header_step.bounds.payload.has_value());
    PFL_EXPECT(exact_header_step.bounds.payload->declared.length() == 0U);
    PFL_EXPECT(exact_header_step.bounds.payload->captured.length() == 0U);
    PFL_EXPECT(std::holds_alternative<SctpFacts>(exact_header_step.facts));
    const auto* exact_header_facts = std::get_if<SctpFacts>(&exact_header_step.facts);
    PFL_REQUIRE(exact_header_facts != nullptr);
    PFL_EXPECT(exact_header_facts->src_port == 49152U);
    PFL_EXPECT(exact_header_facts->dst_port == 36412U);
    PFL_EXPECT(exact_header_facts->verification_tag == 0x10213243U);
    PFL_EXPECT(exact_header_facts->checksum == 0x89ABCDEFU);

    const auto payload_bytes = make_sctp_segment(5000U, 5001U, 0x01020304U, 0xA0B0C0D0U, 5U);
    const auto payload_packet = make_raw_packet(payload_bytes);
    const auto payload_header = parse_sctp_common_header(make_root_slice(payload_packet));
    PFL_EXPECT(payload_header.status == ParseStatus::complete);
    PFL_EXPECT(payload_header.captured_payload_length == 5U);

    auto truncated_header_bytes = exact_header_bytes;
    truncated_header_bytes.resize(detail::kSctpCommonHeaderSize - 2U);
    const auto truncated_header_packet = make_raw_packet(
        truncated_header_bytes,
        detail::kSctpCommonHeaderSize
    );
    const auto truncated_header_root = make_root_slice(truncated_header_packet);
    const auto truncated_header = parse_sctp_common_header(truncated_header_root);
    PFL_EXPECT(truncated_header.status == ParseStatus::truncated);
    const auto truncated_header_step = dissect_sctp(truncated_header_root);
    PFL_EXPECT(truncated_header_step.layer == DissectionLayerKind::sctp);
    PFL_EXPECT(truncated_header_step.status == ParseStatus::truncated);
    PFL_EXPECT(!truncated_header_step.path_contribution.has_value());
    PFL_EXPECT(truncated_header_step.terminal_disposition == TerminalDisposition::none);

    const auto impossible_declared_packet = make_raw_packet(exact_header_bytes, detail::kSctpCommonHeaderSize - 1U);
    const auto impossible_declared_step = dissect_sctp(make_root_slice(impossible_declared_packet));
    PFL_EXPECT(impossible_declared_step.status == ParseStatus::malformed);
    PFL_EXPECT(!impossible_declared_step.path_contribution.has_value());
    PFL_EXPECT(impossible_declared_step.bounds.full.declared.length() == detail::kSctpCommonHeaderSize - 1U);
    PFL_EXPECT(impossible_declared_step.bounds.full.captured.length() == detail::kSctpCommonHeaderSize - 1U);
    PFL_EXPECT(impossible_declared_step.bounds.header.declared.length() == detail::kSctpCommonHeaderSize - 1U);
    PFL_EXPECT(impossible_declared_step.bounds.header.captured.length() == detail::kSctpCommonHeaderSize - 1U);

    auto truncated_payload_bytes = payload_bytes;
    truncated_payload_bytes.resize(detail::kSctpCommonHeaderSize + 2U);
    const auto truncated_payload_packet = make_raw_packet(
        truncated_payload_bytes,
        static_cast<std::uint32_t>(payload_bytes.size())
    );
    const auto truncated_payload_root = make_root_slice(truncated_payload_packet);
    const auto truncated_payload = parse_sctp_common_header(truncated_payload_root);
    PFL_EXPECT(truncated_payload.status == ParseStatus::complete);
    PFL_EXPECT(truncated_payload.captured_payload_length == 2U);
    const auto truncated_payload_step = dissect_sctp(truncated_payload_root);
    PFL_EXPECT(truncated_payload_step.status == ParseStatus::complete);
    PFL_REQUIRE(truncated_payload_step.bounds.payload.has_value());
    PFL_EXPECT(truncated_payload_step.bounds.payload->declared.length() == 5U);
    PFL_EXPECT(truncated_payload_step.bounds.payload->captured.length() == 2U);

    const auto ipv4_sctp_packet = make_raw_packet(make_ethernet_ipv4_sctp_packet(
        ipv4(10, 20, 30, 40),
        ipv4(10, 20, 30, 41),
        49152U,
        36412U,
        0x10213243U,
        0x89ABCDEFU,
        3U
    ));
    const auto ipv4_sctp_root = make_root_slice(ipv4_sctp_packet);
    const auto ipv4_sctp_ethernet = parse_ethernet_frame(ipv4_sctp_root);
    PFL_REQUIRE(ipv4_sctp_ethernet.status == ParseStatus::complete);
    const auto ipv4_sctp_ipv4_slice = require_child_slice(
        ipv4_sctp_root,
        ipv4_sctp_ethernet.header_length,
        ipv4_sctp_ethernet.declared_payload_length
    );
    const auto ipv4_sctp_ipv4 = parse_ipv4_packet(ipv4_sctp_ipv4_slice);
    PFL_REQUIRE(ipv4_sctp_ipv4.status == ParseStatus::complete);
    const auto ipv4_sctp_transport_slice = require_child_slice(
        ipv4_sctp_ipv4_slice,
        ipv4_sctp_ipv4.header_length,
        ipv4_sctp_ipv4.nominal_packet_end - ipv4_sctp_ipv4.header_length
    );
    const auto ipv4_sctp_step = dissect_sctp(ipv4_sctp_transport_slice);
    PFL_EXPECT(ipv4_sctp_step.status == ParseStatus::complete);
    PFL_EXPECT(ipv4_sctp_step.stop_reason == StopReason::terminal_protocol);

    const auto truncated_sctp_shadow = run_shadow(
        make_raw_packet(
            []() {
                auto packet = make_ethernet_ipv4_sctp_packet(
                    ipv4(10, 30, 0, 1),
                    ipv4(10, 30, 0, 2),
                    4096U,
                    4097U,
                    0x11223344U,
                    0x55667788U
                );
                packet.resize(packet.size() - 3U);
                return packet;
            }(),
            14U + 20U + detail::kSctpCommonHeaderSize
        ),
        registry
    );
    PFL_EXPECT(truncated_sctp_shadow.outcome == ImportDissectionOutcome::unrecognized);
    PFL_EXPECT(truncated_sctp_shadow.stop_reason == StopReason::truncated);
    PFL_EXPECT(truncated_sctp_shadow.terminal_protocol == ProtocolId::sctp);
    PFL_EXPECT(!truncated_sctp_shadow.has_ports);
    PFL_EXPECT(!truncated_sctp_shadow.has_transport_payload_length);
    PFL_EXPECT(format_shadow_path(truncated_sctp_shadow) == "EthernetII -> IPv4");
}

void expect_fragmented_ipv4_preserves_selector_only_handoff() {
    const auto built = make_common_direct_registry();
    PFL_REQUIRE(built.ok());
    const auto& registry = *built.registry;

    const auto first_fragment_packet = make_raw_packet(make_ethernet_ipv4_fragment_packet(
        ipv4(10, 0, 3, 1), ipv4(10, 0, 3, 2), 6U, 0x2000U, {0x16, 0x03, 0x03, 0x00, 0x10}));
    const auto first_fragment_root = make_root_slice(first_fragment_packet);
    const auto first_fragment_ethernet = dissect_ethernet(first_fragment_root);
    PFL_REQUIRE(first_fragment_ethernet.handoff.has_value());
    PFL_REQUIRE(first_fragment_ethernet.handoff->child.has_value());

    const auto first_fragment_ipv4 = dissect_ipv4(*first_fragment_ethernet.handoff->child);
    PFL_EXPECT(first_fragment_ipv4.status == ParseStatus::complete);
    PFL_EXPECT(first_fragment_ipv4.stop_reason == StopReason::needs_reassembly);
    PFL_REQUIRE(first_fragment_ipv4.path_contribution.has_value());
    PFL_EXPECT(*first_fragment_ipv4.path_contribution == LayerKey::ipv4());
    PFL_REQUIRE(first_fragment_ipv4.handoff.has_value());
    const ProtocolSelector expected_fragment_selector {
        .domain = SelectorDomain::ip_protocol,
        .value = 6U,
    };
    PFL_EXPECT(first_fragment_ipv4.handoff->selector == expected_fragment_selector);
    PFL_EXPECT(!first_fragment_ipv4.handoff->child.has_value());

    StepKindRecorder recorder {};
    const DissectionEngine engine {};
    const auto engine_result = engine.run(
        registry,
        make_link_type_selector(first_fragment_packet.data_link_type),
        first_fragment_root,
        DissectionConsumer {.on_step = record_step_kind, .context = &recorder}
    );
    PFL_EXPECT(engine_result.stop_reason == StopReason::needs_reassembly);
    PFL_EXPECT(engine_result.step_count == 2U);
    PFL_EXPECT(engine_result.traversed_depth == 2U);
    const std::vector<DissectionLayerKind> expected_kinds {
        DissectionLayerKind::ethernet_ii,
        DissectionLayerKind::ipv4,
    };
    PFL_EXPECT(recorder.kinds == expected_kinds);
}

void expect_sctp_fragmentation_preserves_selector_only_handoff() {
    const auto built = make_common_direct_registry();
    PFL_REQUIRE(built.ok());
    const auto& registry = *built.registry;

    const auto ipv4_fragment_packet = make_raw_packet(make_ethernet_ipv4_fragment_packet(
        ipv4(10, 44, 0, 1),
        ipv4(10, 44, 0, 2),
        detail::kIpProtocolSctp,
        0x2000U,
        {0xde, 0xad, 0xbe, 0xef}
    ));
    const auto ipv4_fragment_root = make_root_slice(ipv4_fragment_packet);
    const auto ipv4_fragment_ethernet = dissect_ethernet(ipv4_fragment_root);
    PFL_REQUIRE(ipv4_fragment_ethernet.handoff.has_value());
    PFL_REQUIRE(ipv4_fragment_ethernet.handoff->child.has_value());
    const auto ipv4_fragment_step = dissect_ipv4(*ipv4_fragment_ethernet.handoff->child);
    PFL_EXPECT(ipv4_fragment_step.status == ParseStatus::complete);
    PFL_EXPECT(ipv4_fragment_step.stop_reason == StopReason::needs_reassembly);
    PFL_REQUIRE(ipv4_fragment_step.handoff.has_value());
    PFL_EXPECT(ipv4_fragment_step.handoff->selector.domain == SelectorDomain::ip_protocol);
    PFL_EXPECT(ipv4_fragment_step.handoff->selector.value == detail::kIpProtocolSctp);
    PFL_EXPECT(!ipv4_fragment_step.handoff->child.has_value());

    const auto ipv4_fragment_shadow = run_shadow(ipv4_fragment_packet, registry);
    PFL_EXPECT(ipv4_fragment_shadow.outcome == ImportDissectionOutcome::recognized_flow);
    PFL_EXPECT(ipv4_fragment_shadow.stop_reason == StopReason::needs_reassembly);
    PFL_EXPECT(ipv4_fragment_shadow.terminal_protocol == ProtocolId::sctp);
    PFL_EXPECT(!ipv4_fragment_shadow.has_ports);
    PFL_EXPECT(format_shadow_path(ipv4_fragment_shadow) == "EthernetII -> IPv4");

    const auto src_addr = ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x51});
    const auto dst_addr = ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x52});
    const auto ipv6_fragment_packet = make_raw_packet(make_ethernet_ipv6_fragment_packet(
        src_addr,
        dst_addr,
        detail::kIpProtocolSctp,
        {0xca, 0xfe, 0xba, 0xbe}
    ));
    const auto ipv6_fragment_root = make_root_slice(ipv6_fragment_packet);
    const auto ipv6_fragment_ethernet = dissect_ethernet(ipv6_fragment_root);
    PFL_REQUIRE(ipv6_fragment_ethernet.handoff.has_value());
    PFL_REQUIRE(ipv6_fragment_ethernet.handoff->child.has_value());
    const auto ipv6_step = dissect_ipv6(*ipv6_fragment_ethernet.handoff->child);
    PFL_REQUIRE(ipv6_step.handoff.has_value());
    PFL_REQUIRE(ipv6_step.handoff->child.has_value());
    const auto fragment_step = dissect_ipv6_fragment(*ipv6_step.handoff->child);
    PFL_EXPECT(fragment_step.status == ParseStatus::complete);
    PFL_EXPECT(fragment_step.stop_reason == StopReason::needs_reassembly);
    PFL_REQUIRE(fragment_step.handoff.has_value());
    PFL_EXPECT(fragment_step.handoff->selector.domain == SelectorDomain::ipv6_next_header);
    PFL_EXPECT(fragment_step.handoff->selector.value == detail::kIpProtocolSctp);
    PFL_EXPECT(!fragment_step.handoff->child.has_value());

    const auto ipv6_fragment_shadow = run_shadow(ipv6_fragment_packet, registry);
    PFL_EXPECT(ipv6_fragment_shadow.outcome == ImportDissectionOutcome::recognized_flow);
    PFL_EXPECT(ipv6_fragment_shadow.stop_reason == StopReason::needs_reassembly);
    PFL_EXPECT(ipv6_fragment_shadow.terminal_protocol == ProtocolId::sctp);
    PFL_EXPECT(!ipv6_fragment_shadow.has_ports);
    PFL_EXPECT(format_shadow_path(ipv6_fragment_shadow) == "EthernetII -> IPv6");
}

void expect_common_direct_supports_triple_vlan_and_depth_limits() {
    const auto built = make_common_direct_registry();
    PFL_REQUIRE(built.ok());
    const auto& registry = *built.registry;

    const auto triple_tagged_packet = make_raw_packet(add_vlan_tags(
        make_ethernet_ipv4_udp_packet(ipv4(192, 0, 2, 10), ipv4(192, 0, 2, 11), 9000U, 53U),
        {
            {0x8100U, 10U},
            {0x8100U, 20U},
            {0x8100U, 30U},
        }
    ));
    const auto triple_shadow = run_shadow(triple_tagged_packet, registry);
    PFL_EXPECT(triple_shadow.outcome == ImportDissectionOutcome::recognized_flow);
    PFL_EXPECT(format_shadow_path(triple_shadow) == "EthernetII -> VLAN(vid=10) -> VLAN(vid=20) -> VLAN(vid=30) -> IPv4 -> UDP");

    StepKindRecorder recorder {};
    const DissectionEngine engine {};
    const auto limited_result = engine.run(
        registry,
        make_link_type_selector(triple_tagged_packet.data_link_type),
        make_root_slice(triple_tagged_packet),
        DissectionConsumer {.on_step = record_step_kind, .context = &recorder},
        4U
    );
    PFL_EXPECT(limited_result.stop_reason == StopReason::depth_limit);
    PFL_EXPECT(limited_result.step_count == 4U);
    PFL_EXPECT(limited_result.traversed_depth == 4U);
    const std::vector<DissectionLayerKind> expected_kinds {
        DissectionLayerKind::ethernet_ii,
        DissectionLayerKind::vlan,
        DissectionLayerKind::vlan,
        DissectionLayerKind::vlan,
    };
    PFL_EXPECT(recorder.kinds == expected_kinds);
}

void expect_shadow_parity_for_common_direct_subset() {
    const auto built = make_common_direct_registry();
    PFL_REQUIRE(built.ok());
    const auto& registry = *built.registry;
    const auto ipv6_src_addr = ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x11});
    const auto ipv6_dst_addr = ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x22});

    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(make_ethernet_ipv4_tcp_packet_with_payload(
            ipv4(10, 0, 1, 1), ipv4(10, 0, 1, 2), 12345U, 443U, 5U, 0x18U)),
        "EthernetII -> IPv4 -> TCP",
        StopReason::terminal_protocol
    );

    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(make_ethernet_ipv4_udp_packet_with_bytes_payload(
            ipv4(10, 0, 2, 1), ipv4(10, 0, 2, 2), 5353U, 53U, {0x01, 0x02, 0x03})),
        "EthernetII -> IPv4 -> UDP",
        StopReason::terminal_protocol
    );

    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(make_ethernet_ipv4_sctp_packet(
            ipv4(10, 0, 2, 11), ipv4(10, 0, 2, 12), 49132U, 36412U, 0x10213243U, 0x00000000U, 4U)),
        "EthernetII -> IPv4 -> SCTP",
        StopReason::terminal_protocol
    );

    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(make_single_tagged_ethernet_ipv4_tcp_packet(
            ipv4(192, 168, 1, 10), ipv4(192, 168, 1, 20), 12345U, 443U, 100U)),
        "EthernetII -> VLAN(vid=100) -> IPv4 -> TCP",
        StopReason::terminal_protocol
    );

    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(add_vlan_tags(
            make_ethernet_ipv4_sctp_packet(
                ipv4(192, 168, 1, 30), ipv4(192, 168, 1, 31), 2905U, 2906U, 0x01020304U, 0xAABBCCDDU, 2U),
            {{0x8100U, 101U}}
        )),
        "EthernetII -> VLAN(vid=101) -> IPv4 -> SCTP",
        StopReason::terminal_protocol
    );

    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(make_double_tagged_ethernet_ipv4_udp_packet(
            ipv4(172, 16, 0, 1), ipv4(172, 16, 0, 2), 5353U, 53U, 200U, 300U)),
        "EthernetII -> VLAN(vid=200) -> VLAN(vid=300) -> IPv4 -> UDP",
        StopReason::terminal_protocol
    );

    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(make_single_tagged_ethernet_ipv4_tcp_packet(
            ipv4(10, 10, 10, 1), ipv4(10, 10, 10, 2), 2222U, 80U, 0U)),
        "EthernetII -> VLAN(vid=0) -> IPv4 -> TCP",
        StopReason::terminal_protocol
    );

    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(make_ethernet_ipv4_fragment_packet(
            ipv4(10, 0, 3, 1), ipv4(10, 0, 3, 2), 6U, 0x2000U, {0x16, 0x03, 0x03, 0x00, 0x10})),
        "EthernetII -> IPv4",
        StopReason::needs_reassembly
    );

    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(make_ethernet_ipv4_fragment_packet(
            ipv4(10, 0, 4, 1), ipv4(10, 0, 4, 2), 17U, 0x0001U, {0xde, 0xad, 0xbe, 0xef})),
        "EthernetII -> IPv4",
        StopReason::needs_reassembly
    );

    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(make_ethernet_ipv4_fragment_packet(
            ipv4(10, 0, 4, 11), ipv4(10, 0, 4, 12), detail::kIpProtocolSctp, 0x0001U, {0xde, 0xad, 0xbe, 0xef})),
        "EthernetII -> IPv4",
        StopReason::needs_reassembly
    );

    auto udp_options_packet = add_ipv4_options(
        make_ethernet_ipv4_udp_packet(ipv4(198, 51, 100, 1), ipv4(198, 51, 100, 2), 9000U, 9001U),
        {0x01, 0x01, 0x01, 0x01}
    );
    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(udp_options_packet),
        "EthernetII -> IPv4 -> UDP",
        StopReason::terminal_protocol
    );

    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(make_ethernet_ipv6_packet(
            ipv6_src_addr,
            ipv6_dst_addr,
            detail::kIpProtocolTcp,
            make_ipv6_tcp_segment(12345U, 443U, 5U, 0x18U)
        )),
        "EthernetII -> IPv6 -> TCP",
        StopReason::terminal_protocol
    );

    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(make_ethernet_ipv6_packet(
            ipv6_src_addr,
            ipv6_dst_addr,
            detail::kIpProtocolUdp,
            make_ipv6_udp_segment(5353U, 53U, 3U)
        )),
        "EthernetII -> IPv6 -> UDP",
        StopReason::terminal_protocol
    );

    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(make_ethernet_ipv6_packet(
            ipv6_src_addr,
            ipv6_dst_addr,
            detail::kIpProtocolSctp,
            make_sctp_segment(49132U, 36412U, 0x10213243U, 0x00000000U, 4U)
        )),
        "EthernetII -> IPv6 -> SCTP",
        StopReason::terminal_protocol
    );

    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(add_vlan_tags(
            make_ethernet_ipv6_packet(
                ipv6_src_addr,
                ipv6_dst_addr,
                detail::kIpProtocolUdp,
                make_ipv6_udp_segment(9000U, 9001U)
            ),
            {{0x8100U, 400U}}
        )),
        "EthernetII -> VLAN(vid=400) -> IPv6 -> UDP",
        StopReason::terminal_protocol
    );

    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(add_vlan_tags(
            make_ethernet_ipv6_packet(
                ipv6_src_addr,
                ipv6_dst_addr,
                detail::kIpProtocolSctp,
                make_sctp_segment(2905U, 2906U, 0x01020304U, 0xAABBCCDDU, 1U)
            ),
            {{0x8100U, 401U}}
        )),
        "EthernetII -> VLAN(vid=401) -> IPv6 -> SCTP",
        StopReason::terminal_protocol
    );

    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(make_ethernet_ipv6_udp_with_hop_by_hop_packet(
            ipv6_src_addr,
            ipv6_dst_addr,
            61000U,
            53U
        )),
        "EthernetII -> IPv6 -> UDP",
        StopReason::terminal_protocol
    );

    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(make_ethernet_ipv6_packet(
            ipv6_src_addr,
            ipv6_dst_addr,
            detail::kIpProtocolHopByHop,
            make_ipv6_hop_by_hop_extension(
                detail::kIpProtocolSctp,
                make_sctp_segment(49132U, 36412U, 0x10213243U, 0x00000000U, 3U)
            )
        )),
        "EthernetII -> IPv6 -> SCTP",
        StopReason::terminal_protocol
    );

    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(make_ethernet_ipv6_packet(
            ipv6_src_addr,
            ipv6_dst_addr,
            detail::kIpProtocolRouting,
            make_ipv6_routing_extension(detail::kIpProtocolUdp, make_ipv6_udp_segment(1200U, 2200U))
        )),
        "EthernetII -> IPv6 -> UDP",
        StopReason::terminal_protocol
    );

    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(make_ethernet_ipv6_packet(
            ipv6_src_addr,
            ipv6_dst_addr,
            detail::kIpProtocolDestinationOptions,
            make_ipv6_destination_options_extension(detail::kIpProtocolTcp, make_ipv6_tcp_segment(32000U, 443U, 2U, 0x19U))
        )),
        "EthernetII -> IPv6 -> TCP",
        StopReason::terminal_protocol
    );

    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(make_ethernet_ipv6_fragment_packet(
            ipv6_src_addr,
            ipv6_dst_addr,
            detail::kIpProtocolUdp,
            make_ipv6_udp_segment(20000U, 20001U, 2U)
        )),
        "EthernetII -> IPv6",
        StopReason::needs_reassembly
    );

    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(make_ethernet_ipv6_fragment_packet(
            ipv6_src_addr,
            ipv6_dst_addr,
            detail::kIpProtocolSctp,
            make_sctp_segment(49132U, 36412U, 0x10213243U, 0x00000000U, 2U)
        )),
        "EthernetII -> IPv6",
        StopReason::needs_reassembly
    );

    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(make_ethernet_ipv6_fragment_packet(
            ipv6_src_addr,
            ipv6_dst_addr,
            detail::kIpProtocolTcp,
            make_ipv6_tcp_segment(20002U, 20003U, 4U, 0x10U),
            0U,
            true
        )),
        "EthernetII -> IPv6",
        StopReason::needs_reassembly
    );
}

void expect_shadow_conservative_stops_and_arp_behavior() {
    const auto built = make_common_direct_registry();
    PFL_REQUIRE(built.ok());
    const auto& registry = *built.registry;
    const auto ipv6_src_addr = ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x31});
    const auto ipv6_dst_addr = ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x32});

    const auto ieee8023_shadow = run_shadow(make_raw_packet(make_ethernet_ieee8023_frame(16U)), registry);
    PFL_EXPECT(ieee8023_shadow.outcome == ImportDissectionOutcome::unrecognized);
    PFL_EXPECT(ieee8023_shadow.stop_reason == StopReason::unrecognized_payload);
    PFL_EXPECT(format_shadow_path(ieee8023_shadow) == "IEEE 802.3");

    const auto unsupported_ip_shadow = run_shadow(
        make_raw_packet(make_ethernet_ipv4_icmp_packet(ipv4(10, 9, 0, 1), ipv4(10, 9, 0, 2), 8U, 0U)),
        registry
    );
    PFL_EXPECT(unsupported_ip_shadow.outcome == ImportDissectionOutcome::unrecognized);
    PFL_EXPECT(unsupported_ip_shadow.stop_reason == StopReason::unknown_next_protocol);
    PFL_EXPECT(format_shadow_path(unsupported_ip_shadow) == "EthernetII -> IPv4");

    const auto unsupported_ipv6_shadow = run_shadow(
        make_raw_packet(make_ethernet_ipv6_packet(
            ipv6_src_addr,
            ipv6_dst_addr,
            0xFD,
            {0xde, 0xad, 0xbe, 0xef}
        )),
        registry
    );
    PFL_EXPECT(unsupported_ipv6_shadow.outcome == ImportDissectionOutcome::unrecognized);
    PFL_EXPECT(unsupported_ipv6_shadow.stop_reason == StopReason::unknown_next_protocol);
    PFL_EXPECT(format_shadow_path(unsupported_ipv6_shadow) == "EthernetII -> IPv6");

    const auto zero_payload_ipv6_shadow = run_shadow(
        make_raw_packet(make_ethernet_ipv6_packet(
            ipv6_src_addr,
            ipv6_dst_addr,
            detail::kIpProtocolUdp,
            {}
        )),
        registry
    );
    PFL_EXPECT(zero_payload_ipv6_shadow.outcome == ImportDissectionOutcome::unrecognized);
    PFL_EXPECT(zero_payload_ipv6_shadow.stop_reason == StopReason::malformed);
    PFL_EXPECT(format_shadow_path(zero_payload_ipv6_shadow) == "EthernetII -> IPv6");

    const auto truncated_ipv6_extension_shadow = run_shadow(
        make_raw_packet(make_truncated_ethernet_ipv6_extension_packet(ipv6_src_addr, ipv6_dst_addr)),
        registry
    );
    PFL_EXPECT(truncated_ipv6_extension_shadow.outcome == ImportDissectionOutcome::unrecognized);
    PFL_EXPECT(truncated_ipv6_extension_shadow.stop_reason == StopReason::malformed);
    PFL_EXPECT(format_shadow_path(truncated_ipv6_extension_shadow) == "EthernetII -> IPv6");

    auto repeated_extensions_payload = make_ipv6_udp_segment(7000U, 8000U, 1U);
    repeated_extensions_payload = make_ipv6_hop_by_hop_extension(detail::kIpProtocolUdp, repeated_extensions_payload);
    for (std::size_t index = 0U; index < detail::kMaxIpv6ExtensionHeaders; ++index) {
        repeated_extensions_payload = make_ipv6_hop_by_hop_extension(detail::kIpProtocolHopByHop, repeated_extensions_payload);
    }
    const auto repeated_extensions_packet = make_raw_packet(make_ethernet_ipv6_packet(
        ipv6_src_addr,
        ipv6_dst_addr,
        detail::kIpProtocolHopByHop,
        repeated_extensions_payload
    ));
    StepKindRecorder repeated_extensions_recorder {};
    const DissectionEngine engine {};
    const auto repeated_extensions_result = engine.run(
        registry,
        make_link_type_selector(repeated_extensions_packet.data_link_type),
        make_root_slice(repeated_extensions_packet),
        DissectionConsumer {.on_step = record_step_kind, .context = &repeated_extensions_recorder},
        6U
    );
    const std::vector<DissectionLayerKind> expected_repeated_extension_kinds {
        DissectionLayerKind::ethernet_ii,
        DissectionLayerKind::ipv6,
        DissectionLayerKind::ipv6_hop_by_hop,
        DissectionLayerKind::ipv6_hop_by_hop,
        DissectionLayerKind::ipv6_hop_by_hop,
        DissectionLayerKind::ipv6_hop_by_hop,
    };
    PFL_EXPECT(repeated_extensions_result.stop_reason == StopReason::depth_limit);
    PFL_EXPECT(repeated_extensions_result.step_count == 6U);
    PFL_EXPECT(repeated_extensions_result.traversed_depth == 6U);
    PFL_EXPECT(repeated_extensions_recorder.kinds == expected_repeated_extension_kinds);

    const auto unknown_ethertype_shadow = run_shadow(
        make_raw_packet(std::vector<std::uint8_t> {
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
            0x12, 0x34,
            0xde, 0xad, 0xbe, 0xef,
        }),
        registry
    );
    PFL_EXPECT(unknown_ethertype_shadow.outcome == ImportDissectionOutcome::unrecognized);
    PFL_EXPECT(unknown_ethertype_shadow.stop_reason == StopReason::unknown_next_protocol);
    PFL_EXPECT(format_shadow_path(unknown_ethertype_shadow) == "EthernetII");

    const auto truncated_vlan_shadow = run_shadow(
        make_raw_packet(std::vector<std::uint8_t> {
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
            0x81, 0x00,
            0x00, 0x64,
        }, 18U),
        registry
    );
    PFL_EXPECT(truncated_vlan_shadow.outcome == ImportDissectionOutcome::unrecognized);
    PFL_EXPECT(truncated_vlan_shadow.stop_reason == StopReason::truncated);
    PFL_EXPECT(format_shadow_path(truncated_vlan_shadow) == "EthernetII");

    const auto arp_bytes = make_ethernet_arp_packet(ipv4(10, 10, 12, 2), ipv4(10, 10, 12, 1));
    const auto arp_shadow = run_shadow(make_raw_packet(arp_bytes), registry);
    PFL_EXPECT(arp_shadow.outcome == ImportDissectionOutcome::recognized_non_flow);
    PFL_EXPECT(arp_shadow.stop_reason == StopReason::terminal_protocol);
    PFL_EXPECT(arp_shadow.terminal_protocol == ProtocolId::arp);
    PFL_EXPECT(arp_shadow.has_arp_addresses);
    PFL_EXPECT(arp_shadow.arp_addresses.has_sender_ipv4);
    PFL_EXPECT(arp_shadow.arp_addresses.has_target_ipv4);
    PFL_EXPECT(arp_shadow.arp_addresses.sender_ipv4 == ipv4(10, 10, 12, 2));
    PFL_EXPECT(arp_shadow.arp_addresses.target_ipv4 == ipv4(10, 10, 12, 1));
    PFL_EXPECT(format_shadow_path(arp_shadow) == "EthernetII -> ARP");

    auto truncated_arp_packet = arp_bytes;
    truncated_arp_packet.resize(18U);
    const auto truncated_arp_shadow = run_shadow(
        make_raw_packet(truncated_arp_packet, static_cast<std::uint32_t>(arp_bytes.size())),
        registry
    );
    PFL_EXPECT(truncated_arp_shadow.outcome == ImportDissectionOutcome::unrecognized);
    PFL_EXPECT(truncated_arp_shadow.stop_reason == StopReason::truncated);
    PFL_EXPECT(format_shadow_path(truncated_arp_shadow) == "EthernetII");

    auto impossible_arp_packet = arp_bytes;
    impossible_arp_packet[18] = 6U;
    impossible_arp_packet[19] = 16U;
    const auto impossible_arp_shadow = run_shadow(make_raw_packet(impossible_arp_packet), registry);
    PFL_EXPECT(impossible_arp_shadow.outcome == ImportDissectionOutcome::unrecognized);
    PFL_EXPECT(impossible_arp_shadow.stop_reason == StopReason::malformed);
    PFL_EXPECT(impossible_arp_shadow.terminal_protocol == ProtocolId::unknown);
    PFL_EXPECT(format_shadow_path(impossible_arp_shadow) == "EthernetII");

    const auto truncated_ethernet_shadow = run_shadow(
        make_raw_packet(std::vector<std::uint8_t> {
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            0x66, 0x77, 0x88, 0x99,
        }),
        registry
    );
    PFL_EXPECT(truncated_ethernet_shadow.outcome == ImportDissectionOutcome::unrecognized);
    PFL_EXPECT(truncated_ethernet_shadow.stop_reason == StopReason::truncated);

    auto invalid_ihl_packet = make_ethernet_ipv4_tcp_packet(ipv4(10, 8, 0, 1), ipv4(10, 8, 0, 2), 1U, 2U);
    invalid_ihl_packet[14] = 0x44U;
    const auto invalid_ihl_shadow = run_shadow(make_raw_packet(invalid_ihl_packet), registry);
    PFL_EXPECT(invalid_ihl_shadow.outcome == ImportDissectionOutcome::unrecognized);
    PFL_EXPECT(invalid_ihl_shadow.stop_reason == StopReason::malformed);
    PFL_EXPECT(format_shadow_path(invalid_ihl_shadow) == "EthernetII");
}

}  // namespace

void run_common_direct_dissection_tests() {
    expect_common_direct_registry_and_root_selector();
    expect_ethernet_and_vlan_canonical_parsers();
    expect_ipv4_tcp_udp_and_arp_canonical_parsers();
    expect_ipv6_and_extension_canonical_parsers();
    expect_sctp_canonical_parsers_and_bounds();
    expect_common_direct_steps_report_handoffs_bounds_and_facts();
    expect_failed_layers_do_not_contribute_path_and_exact_arp_bounds();
    expect_fragmented_ipv4_preserves_selector_only_handoff();
    expect_sctp_fragmentation_preserves_selector_only_handoff();
    expect_common_direct_supports_triple_vlan_and_depth_limits();
    expect_shadow_parity_for_common_direct_subset();
    expect_shadow_conservative_stops_and_arp_behavior();
}

}  // namespace pfl::tests
