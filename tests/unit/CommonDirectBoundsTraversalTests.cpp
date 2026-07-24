#include "CommonDirectDissectionTestSupport.h"

#include "core/dissection/modules/ArpModule.h"
#include "core/dissection/modules/EthernetVlanModules.h"
#include "core/dissection/modules/Ipv4Module.h"
#include "core/dissection/modules/Ipv6ExtensionModules.h"
#include "core/dissection/modules/Ipv6Module.h"
#include "core/dissection/modules/TransportModules.h"

namespace pfl::tests::common_direct_test {

using namespace dissection;

namespace {

void expect_ipv4_tcp_steps_report_handoffs_bounds_and_facts() {
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
        .domain = SelectorDomain::native_ether_type,
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
}

void expect_udp_bounds_respect_declared_lengths() {
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
}

void expect_ipv6_extension_steps_report_handoffs_and_bounds() {
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

void expect_failed_link_and_transport_layers_do_not_contribute_path() {
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
}

void expect_failed_ipv6_extension_layer_does_not_contribute_path() {
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
}

void expect_arp_bounds_exclude_padding_for_complete_and_truncated_cases() {
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
    PFL_EXPECT(!padded_arp_step.path_contribution.has_value());
    PFL_EXPECT(padded_arp_step.bounds.full.declared.length() == 28U);
    PFL_EXPECT(padded_arp_step.bounds.full.captured.length() == 28U);
    PFL_EXPECT(padded_arp_step.bounds.header.declared.length() == 8U);
    PFL_EXPECT(padded_arp_step.bounds.header.captured.length() == 8U);
    PFL_REQUIRE(padded_arp_step.bounds.payload.has_value());
    PFL_EXPECT(padded_arp_step.bounds.payload->declared.length() == 20U);
    PFL_EXPECT(padded_arp_step.bounds.payload->captured.length() == 20U);
    PFL_EXPECT(padded_arp_step.terminal_disposition == TerminalDisposition::flow_candidate);

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
}

void expect_structurally_impossible_arp_is_malformed_without_path() {
    const auto arp_bytes = make_ethernet_arp_packet(ipv4(10, 10, 12, 2), ipv4(10, 10, 12, 1));
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

}  // namespace

void run_common_direct_bounds_traversal_tests() {
    expect_ipv4_tcp_steps_report_handoffs_bounds_and_facts();
    expect_udp_bounds_respect_declared_lengths();
    expect_ipv6_extension_steps_report_handoffs_and_bounds();
    expect_failed_link_and_transport_layers_do_not_contribute_path();
    expect_failed_ipv6_extension_layer_does_not_contribute_path();
    expect_arp_bounds_exclude_padding_for_complete_and_truncated_cases();
    expect_structurally_impossible_arp_is_malformed_without_path();
}

}  // namespace pfl::tests::common_direct_test
