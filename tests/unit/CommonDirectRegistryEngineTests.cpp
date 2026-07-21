#include "CommonDirectDissectionTestSupport.h"
#include "core/dissection/modules/CommonDirectModules.h"

namespace pfl::tests::common_direct_test {

using namespace dissection;

namespace {

void expect_link_type_and_linux_cooked_registry_mappings(const DissectionRegistry& registry) {
    PFL_EXPECT(registry.entry_count() == 98U);
    PFL_EXPECT(registry.find(make_link_type_selector(kLinkTypeEthernet)) == dissect_ethernet);
    PFL_EXPECT(registry.find(make_link_type_selector(kLinkTypeLinuxSll)) == dissect_linux_sll);
    PFL_EXPECT(registry.find(make_link_type_selector(kLinkTypeLinuxSll2)) == dissect_linux_sll2);

    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::linux_cooked_protocol,
        .value = detail::kEtherTypeIpv4,
    }) == dissect_ipv4);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::linux_cooked_protocol,
        .value = detail::kEtherTypeIpv6,
    }) == dissect_ipv6);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::linux_cooked_protocol,
        .value = detail::kEtherTypeArp,
    }) == dissect_linux_cooked_arp);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::linux_cooked_protocol,
        .value = detail::kEtherTypeVlan,
    }) == nullptr);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::linux_cooked_protocol,
        .value = detail::kEtherTypeQinq,
    }) == nullptr);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::linux_cooked_protocol,
        .value = detail::kEtherTypeLegacyVlan,
    }) == nullptr);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::linux_cooked_protocol,
        .value = detail::kEtherTypeMacsec,
    }) == nullptr);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::native_ieee8023_payload,
        .value = kIeee8023PayloadSelectorValue,
    }) == dissect_llc_snap);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::ieee8023_payload,
        .value = kIeee8023PayloadSelectorValue,
    }) == dissect_llc_snap);
}

void expect_ip_protocol_and_control_registry_mappings(const DissectionRegistry& registry) {
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::ip_protocol,
        .value = detail::kIpProtocolIcmp,
    }) == dissect_icmp);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::ip_protocol,
        .value = detail::kIpProtocolIgmp,
    }) == dissect_igmp);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::ip_protocol,
        .value = detail::kIpProtocolIpv4Encapsulation,
    }) == dissect_ipv4);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::ip_protocol,
        .value = detail::kIpProtocolIpv6Encapsulation,
    }) == dissect_ipv6);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::ip_protocol,
        .value = detail::kIpProtocolGre,
    }) == dissect_ipv4_gre_variant);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::ip_protocol,
        .value = detail::kIpProtocolAh,
    }) == dissect_ipv4_ah);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::ip_protocol,
        .value = detail::kIpProtocolEsp,
    }) == dissect_esp);

    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::ipv6_next_header,
        .value = detail::kIpProtocolIcmpV6,
    }) == dissect_icmpv6);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::ipv6_next_header,
        .value = detail::kIpProtocolIpv4Encapsulation,
    }) == dissect_ipv4);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::ipv6_next_header,
        .value = detail::kIpProtocolIpv6Encapsulation,
    }) == dissect_ipv6);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::ipv6_next_header,
        .value = detail::kIpProtocolGre,
    }) == dissect_gre);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::ipv6_next_header,
        .value = detail::kIpProtocolAh,
    }) == dissect_ipv6_ah);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::ipv6_next_header,
        .value = detail::kIpProtocolEsp,
    }) == dissect_esp);

    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::llc_snap_pid,
        .value = detail::kEtherTypeIpv4,
    }) == dissect_ipv4);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::llc_snap_pid,
        .value = detail::kEtherTypeIpv6,
    }) == dissect_ipv6);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::llc_snap_pid,
        .value = detail::kEtherTypeArp,
    }) == dissect_arp);
}

void expect_ether_and_embedded_frame_registry_mappings(const DissectionRegistry& registry) {
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::pbb_inner_frame,
        .value = kPbbInnerFrameSelectorValue,
    }) == dissect_pbb_inner_ethernet);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::pbb_inner_ether_type,
        .value = detail::kEtherTypeIpv4,
    }) == dissect_ipv4);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::pbb_inner_ether_type,
        .value = detail::kEtherTypeIpv6,
    }) == dissect_ipv6);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::pbb_inner_ether_type,
        .value = detail::kEtherTypeArp,
    }) == dissect_arp);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::pbb_inner_ether_type,
        .value = detail::kEtherTypeVlan,
    }) == dissect_pbb_inner_vlan);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::pbb_inner_ether_type,
        .value = detail::kEtherTypeQinq,
    }) == dissect_pbb_inner_vlan);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::pbb_inner_ether_type,
        .value = detail::kEtherTypeLegacyVlan,
    }) == dissect_pbb_inner_vlan);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::pbb_inner_ether_type,
        .value = detail::kEtherTypeMacsec,
    }) == nullptr);

    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::native_ether_type,
        .value = detail::kEtherTypeIpv4,
    }) == dissect_ipv4);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::native_ether_type,
        .value = detail::kEtherTypeIpv6,
    }) == dissect_ipv6);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::native_ether_type,
        .value = detail::kEtherTypeArp,
    }) == dissect_arp);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::native_ether_type,
        .value = detail::kEtherTypePbb,
    }) == dissect_pbb);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::native_ether_type,
        .value = detail::kEtherTypePppoeDiscovery,
    }) == dissect_pppoe_discovery);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::native_ether_type,
        .value = detail::kEtherTypePppoeSession,
    }) == dissect_pppoe_session);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::native_ether_type,
        .value = detail::kEtherTypeMacsec,
    }) == dissect_macsec);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::native_ether_type,
        .value = detail::kEtherTypeVlan,
    }) == dissect_vlan);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::native_ether_type,
        .value = detail::kEtherTypeQinq,
    }) == dissect_vlan);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::native_ether_type,
        .value = detail::kEtherTypeLegacyVlan,
    }) == dissect_vlan);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::native_ether_type,
        .value = detail::kEtherTypeMplsUnicast,
    }) == dissect_mpls_label);

    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::ether_type,
        .value = detail::kEtherTypePbb,
    }) == dissect_pbb);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::ether_type,
        .value = detail::kEtherTypePppoeDiscovery,
    }) == dissect_pppoe_discovery);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::ether_type,
        .value = detail::kEtherTypePppoeSession,
    }) == dissect_pppoe_session);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::ether_type,
        .value = detail::kEtherTypeMacsec,
    }) == nullptr);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::ether_type,
        .value = detail::kEtherTypeVlan,
    }) == dissect_embedded_vlan);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::ether_type,
        .value = detail::kEtherTypeQinq,
    }) == dissect_embedded_vlan);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::ether_type,
        .value = detail::kEtherTypeLegacyVlan,
    }) == dissect_embedded_vlan);
}

void expect_ppp_gre_and_mpls_registry_mappings(const DissectionRegistry& registry) {
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::ppp_frame,
        .value = kPppFrameContinueSelectorValue,
    }) == dissect_ppp);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::ppp_protocol,
        .value = detail::kPppProtocolIpv4,
    }) == dissect_ipv4);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::ppp_protocol,
        .value = detail::kPppProtocolIpv6,
    }) == dissect_ipv6);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::ppp_protocol,
        .value = 0xC021U,
    }) == dissect_ppp_control);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::ppp_protocol,
        .value = 0x8021U,
    }) == dissect_ppp_control);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::ppp_protocol,
        .value = 0x8057U,
    }) == dissect_ppp_control);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::ppp_protocol,
        .value = 0x1235U,
    }) == nullptr);

    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::gre_protocol_type,
        .value = detail::kEtherTypeIpv4,
    }) == dissect_ipv4);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::gre_protocol_type,
        .value = detail::kEtherTypeIpv6,
    }) == dissect_ipv6);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::gre_protocol_type,
        .value = detail::kGreProtocolTypeTransparentEthernetBridging,
    }) == dissect_embedded_ethernet);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::gre_protocol_type,
        .value = detail::kEtherTypeMacsec,
    }) == nullptr);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::gre_protocol_type,
        .value = detail::kEtherTypeMplsUnicast,
    }) == dissect_mpls_label);

    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::eoip_inner_frame,
        .value = kEoipInnerFrameSelectorValue,
    }) == dissect_eoip_inner_ethernet);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::eoip_inner_ether_type,
        .value = detail::kEtherTypeIpv4,
    }) == dissect_eoip_inner_ipv4);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::eoip_inner_ether_type,
        .value = detail::kEtherTypeIpv6,
    }) == dissect_eoip_inner_ipv6);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::eoip_inner_ether_type,
        .value = detail::kEtherTypeArp,
    }) == dissect_arp);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::eoip_inner_ether_type,
        .value = detail::kEtherTypeVlan,
    }) == dissect_eoip_inner_vlan);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::eoip_inner_ether_type,
        .value = detail::kEtherTypeQinq,
    }) == dissect_eoip_inner_vlan);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::eoip_inner_ether_type,
        .value = detail::kEtherTypeLegacyVlan,
    }) == dissect_eoip_inner_vlan);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::eoip_inner_ether_type,
        .value = detail::kEtherTypePppoeSession,
    }) == nullptr);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::eoip_inner_ether_type,
        .value = detail::kEtherTypePbb,
    }) == nullptr);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::eoip_inner_ether_type,
        .value = detail::kEtherTypeMacsec,
    }) == nullptr);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::eoip_inner_ieee8023_payload,
        .value = kEoipInnerIeee8023PayloadSelectorValue,
    }) == dissect_eoip_inner_llc_snap);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::eoip_inner_llc_snap_pid,
        .value = detail::kEtherTypeIpv4,
    }) == dissect_eoip_inner_ipv4);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::eoip_inner_llc_snap_pid,
        .value = detail::kEtherTypeIpv6,
    }) == dissect_eoip_inner_ipv6);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::eoip_inner_llc_snap_pid,
        .value = detail::kEtherTypeArp,
    }) == dissect_arp);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::eoip_inner_ip_protocol,
        .value = detail::kIpProtocolTcp,
    }) == dissect_tcp);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::eoip_inner_ip_protocol,
        .value = detail::kIpProtocolUdp,
    }) == dissect_udp);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::eoip_inner_ip_protocol,
        .value = detail::kIpProtocolGre,
    }) == nullptr);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::eoip_inner_ipv6_next_header,
        .value = detail::kIpProtocolTcp,
    }) == dissect_tcp);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::eoip_inner_ipv6_next_header,
        .value = detail::kIpProtocolUdp,
    }) == dissect_udp);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::eoip_inner_ipv6_next_header,
        .value = detail::kIpProtocolGre,
    }) == nullptr);

    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::ether_type,
        .value = detail::kEtherTypeMplsUnicast,
    }) == dissect_mpls_label);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::mpls_stack,
        .value = kMplsStackContinueSelectorValue,
    }) == dissect_mpls_label);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::mpls_payload,
        .value = detail::kEtherTypeIpv4,
    }) == dissect_ipv4);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::mpls_payload,
        .value = detail::kEtherTypeIpv6,
    }) == dissect_ipv6);
}

void expect_link_type_selector_helpers() {
    const auto root_selector = make_link_type_selector(kLinkTypeEthernet);
    PFL_EXPECT(root_selector.domain == SelectorDomain::link_type);
    PFL_EXPECT(root_selector.value == kLinkTypeEthernet);

    const auto sll_root_selector = make_link_type_selector(kLinkTypeLinuxSll);
    PFL_EXPECT(sll_root_selector.domain == SelectorDomain::link_type);
    PFL_EXPECT(sll_root_selector.value == kLinkTypeLinuxSll);

    const auto sll2_root_selector = make_link_type_selector(kLinkTypeLinuxSll2);
    PFL_EXPECT(sll2_root_selector.domain == SelectorDomain::link_type);
    PFL_EXPECT(sll2_root_selector.value == kLinkTypeLinuxSll2);
}

void expect_shadow_parity_for_ipv4_and_vlan_flows(const DissectionRegistry& registry) {
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

    expect_shadow_matches_legacy_portless_flow(
        registry,
        make_raw_packet(make_ethernet_ipv4_icmp_packet(
            ipv4(10, 9, 0, 1),
            ipv4(10, 9, 0, 2),
            8U,
            0U
        )),
        "EthernetII -> IPv4 -> ICMP",
        "EthernetII -> IPv4",
        StopReason::terminal_protocol
    );
    expect_shadow_matches_legacy_portless_flow(
        registry,
        make_raw_packet(add_vlan_tags(
            make_ethernet_ipv4_icmp_packet(
                ipv4(10, 9, 0, 3),
                ipv4(10, 9, 0, 4),
                0U,
                0U
            ),
            {{0x8100U, 405U}}
        )),
        "EthernetII -> VLAN(vid=405) -> IPv4 -> ICMP",
        "EthernetII -> VLAN(vid=405) -> IPv4",
        StopReason::terminal_protocol
    );
}

void expect_shadow_parity_for_ipv6_flows_and_extensions(const DissectionRegistry& registry) {
    const auto ipv6_src_addr = ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x11});
    const auto ipv6_dst_addr = ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x22});

    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(make_ethernet_ipv6_packet(
            ipv6_src_addr, ipv6_dst_addr, detail::kIpProtocolTcp, make_ipv6_tcp_segment(12345U, 443U, 5U, 0x18U))),
        "EthernetII -> IPv6 -> TCP",
        StopReason::terminal_protocol
    );
    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(make_ethernet_ipv6_packet(
            ipv6_src_addr, ipv6_dst_addr, detail::kIpProtocolUdp, make_ipv6_udp_segment(5353U, 53U, 3U))),
        "EthernetII -> IPv6 -> UDP",
        StopReason::terminal_protocol
    );
    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(make_ethernet_ipv6_packet(
            ipv6_src_addr, ipv6_dst_addr, detail::kIpProtocolSctp, make_sctp_segment(49132U, 36412U, 0x10213243U, 0x00000000U, 4U))),
        "EthernetII -> IPv6 -> SCTP",
        StopReason::terminal_protocol
    );
    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(add_vlan_tags(
            make_ethernet_ipv6_packet(
                ipv6_src_addr, ipv6_dst_addr, detail::kIpProtocolUdp, make_ipv6_udp_segment(9000U, 9001U)),
            {{0x8100U, 400U}}
        )),
        "EthernetII -> VLAN(vid=400) -> IPv6 -> UDP",
        StopReason::terminal_protocol
    );
    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(add_vlan_tags(
            make_ethernet_ipv6_packet(
                ipv6_src_addr, ipv6_dst_addr, detail::kIpProtocolSctp, make_sctp_segment(2905U, 2906U, 0x01020304U, 0xAABBCCDDU, 1U)),
            {{0x8100U, 401U}}
        )),
        "EthernetII -> VLAN(vid=401) -> IPv6 -> SCTP",
        StopReason::terminal_protocol
    );
    expect_shadow_matches_legacy_portless_flow(
        registry,
        make_raw_packet(make_ethernet_ipv6_packet(
            ipv6_src_addr, ipv6_dst_addr, detail::kIpProtocolIcmpV6, make_ipv6_icmpv6_message(128U, 0U))),
        "EthernetII -> IPv6 -> ICMPv6",
        "EthernetII -> IPv6",
        StopReason::terminal_protocol
    );
    expect_shadow_matches_legacy_portless_flow(
        registry,
        make_raw_packet(add_vlan_tags(
            make_ethernet_ipv6_packet(
                ipv6_src_addr, ipv6_dst_addr, detail::kIpProtocolIcmpV6, make_ipv6_icmpv6_message(129U, 1U)),
            {{0x8100U, 406U}}
        )),
        "EthernetII -> VLAN(vid=406) -> IPv6 -> ICMPv6",
        "EthernetII -> VLAN(vid=406) -> IPv6",
        StopReason::terminal_protocol
    );
    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(make_ethernet_ipv6_udp_with_hop_by_hop_packet(
            ipv6_src_addr, ipv6_dst_addr, 61000U, 53U)),
        "EthernetII -> IPv6 -> UDP",
        StopReason::terminal_protocol
    );
    expect_shadow_matches_legacy_portless_flow(
        registry,
        make_raw_packet(make_ethernet_ipv6_icmpv6_with_hop_by_hop_packet(
            ipv6_src_addr, ipv6_dst_addr, 128U, 0U)),
        "EthernetII -> IPv6 -> ICMPv6",
        "EthernetII -> IPv6",
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
            ipv6_src_addr, ipv6_dst_addr, detail::kIpProtocolUdp, make_ipv6_udp_segment(20000U, 20001U, 2U))),
        "EthernetII -> IPv6",
        StopReason::needs_reassembly
    );
    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(make_ethernet_ipv6_fragment_packet(
            ipv6_src_addr, ipv6_dst_addr, detail::kIpProtocolSctp, make_sctp_segment(49132U, 36412U, 0x10213243U, 0x00000000U, 2U))),
        "EthernetII -> IPv6",
        StopReason::needs_reassembly
    );
    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(make_ethernet_ipv6_fragment_packet(
            ipv6_src_addr, ipv6_dst_addr, detail::kIpProtocolTcp, make_ipv6_tcp_segment(20002U, 20003U, 4U, 0x10U), 0U, true)),
        "EthernetII -> IPv6",
        StopReason::needs_reassembly
    );
}

void expect_shadow_parity_for_nested_ip_encapsulation(const DissectionRegistry& registry) {
    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(make_ethernet_ipv4_fragment_packet(
            ipv4(198, 18, 0, 1),
            ipv4(198, 18, 0, 2),
            detail::kIpProtocolIpv4Encapsulation,
            0U,
            make_ipv4_payload_packet(
                ipv4(10, 50, 0, 1),
                ipv4(10, 50, 0, 2),
                detail::kIpProtocolTcp,
                make_ipv6_tcp_segment(32000U, 443U, 4U, 0x18U)
            )
        )),
        "EthernetII -> IPv4 -> IPv4 -> TCP",
        StopReason::terminal_protocol
    );
    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(make_ethernet_ipv4_fragment_packet(
            ipv4(198, 18, 0, 3),
            ipv4(198, 18, 0, 4),
            detail::kIpProtocolIpv6Encapsulation,
            0U,
            make_ipv6_payload_packet(
                ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0x81}),
                ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0x82}),
                detail::kIpProtocolUdp,
                make_ipv6_udp_segment(5300U, 53U, 5U)
            )
        )),
        "EthernetII -> IPv4 -> IPv6 -> UDP",
        StopReason::terminal_protocol
    );
    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(make_ethernet_ipv6_packet(
            ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0, 0x91}),
            ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0, 0x92}),
            detail::kIpProtocolIpv4Encapsulation,
            make_ipv4_payload_packet(
                ipv4(10, 60, 0, 1),
                ipv4(10, 60, 0, 2),
                detail::kIpProtocolUdp,
                make_ipv6_udp_segment(1200U, 2200U, 2U)
            )
        )),
        "EthernetII -> IPv6 -> IPv4 -> UDP",
        StopReason::terminal_protocol
    );
    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(make_ethernet_ipv6_packet(
            ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0xa1}),
            ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0xa2}),
            detail::kIpProtocolIpv6Encapsulation,
            make_ipv6_payload_packet(
                ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 11, 0, 0, 0, 0, 0, 0, 0, 0xb1}),
                ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 11, 0, 0, 0, 0, 0, 0, 0, 0xb2}),
                detail::kIpProtocolTcp,
                make_ipv6_tcp_segment(22000U, 8443U, 3U, 0x18U)
            )
        )),
        "EthernetII -> IPv6 -> IPv6 -> TCP",
        StopReason::terminal_protocol
    );
    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(make_ethernet_ipv6_packet(
            ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 12, 0, 0, 0, 0, 0, 0, 0, 0xc1}),
            ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 12, 0, 0, 0, 0, 0, 0, 0, 0xc2}),
            detail::kIpProtocolHopByHop,
            make_ipv6_hop_by_hop_extension(
                detail::kIpProtocolIpv4Encapsulation,
                make_ipv4_payload_packet(
                    ipv4(10, 70, 0, 1),
                    ipv4(10, 70, 0, 2),
                    detail::kIpProtocolUdp,
                    make_ipv6_udp_segment(9000U, 9001U, 1U)
                )
            )
        )),
        "EthernetII -> IPv6 -> IPv4 -> UDP",
        StopReason::terminal_protocol
    );
    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(make_ethernet_ipv4_fragment_packet(
            ipv4(198, 18, 0, 5),
            ipv4(198, 18, 0, 6),
            detail::kIpProtocolIpv6Encapsulation,
            0U,
            make_ipv6_payload_packet(
                ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 13, 0, 0, 0, 0, 0, 0, 0, 0xd1}),
                ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 13, 0, 0, 0, 0, 0, 0, 0, 0xd2}),
                detail::kIpProtocolRouting,
                make_ipv6_routing_extension(detail::kIpProtocolUdp, make_ipv6_udp_segment(3333U, 4444U, 2U))
            )
        )),
        "EthernetII -> IPv4 -> IPv6 -> UDP",
        StopReason::terminal_protocol
    );
}

void expect_shadow_reports_unrecognized_and_malformed_stops(const DissectionRegistry& registry) {
    const auto ipv6_src_addr = ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x31});
    const auto ipv6_dst_addr = ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x32});

    const auto ieee8023_shadow = run_shadow(make_raw_packet(make_ethernet_ieee8023_frame(16U)), registry);
    PFL_EXPECT(ieee8023_shadow.outcome == ImportDissectionOutcome::unrecognized);
    PFL_EXPECT(ieee8023_shadow.stop_reason == StopReason::unrecognized_payload);
    PFL_EXPECT(format_shadow_path(ieee8023_shadow) == "IEEE 802.3");

    const auto unsupported_ip_shadow = run_shadow(
        make_raw_packet(make_ethernet_ipv4_fragment_packet(
            ipv4(10, 9, 0, 1), ipv4(10, 9, 0, 2), 0xFDU, 0U, {0xdeU, 0xadU, 0xbeU, 0xefU})),
        registry
    );
    PFL_EXPECT(unsupported_ip_shadow.outcome == ImportDissectionOutcome::unrecognized);
    PFL_EXPECT(unsupported_ip_shadow.stop_reason == StopReason::unknown_next_protocol);
    PFL_EXPECT(format_shadow_path(unsupported_ip_shadow) == "EthernetII -> IPv4");

    const auto unsupported_ipv6_shadow = run_shadow(
        make_raw_packet(make_ethernet_ipv6_packet(
            ipv6_src_addr, ipv6_dst_addr, 0xFD, {0xde, 0xad, 0xbe, 0xef})),
        registry
    );
    PFL_EXPECT(unsupported_ipv6_shadow.outcome == ImportDissectionOutcome::unrecognized);
    PFL_EXPECT(unsupported_ipv6_shadow.stop_reason == StopReason::unknown_next_protocol);
    PFL_EXPECT(format_shadow_path(unsupported_ipv6_shadow) == "EthernetII -> IPv6");

    const auto zero_payload_ipv6_shadow = run_shadow(
        make_raw_packet(make_ethernet_ipv6_packet(
            ipv6_src_addr, ipv6_dst_addr, detail::kIpProtocolUdp, {})),
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

    auto invalid_ihl_packet = make_ethernet_ipv4_tcp_packet(ipv4(10, 8, 0, 1), ipv4(10, 8, 0, 2), 1U, 2U);
    invalid_ihl_packet[14] = 0x44U;
    const auto invalid_ihl_shadow = run_shadow(make_raw_packet(invalid_ihl_packet), registry);
    PFL_EXPECT(invalid_ihl_shadow.outcome == ImportDissectionOutcome::unrecognized);
    PFL_EXPECT(invalid_ihl_shadow.stop_reason == StopReason::malformed);
    PFL_EXPECT(format_shadow_path(invalid_ihl_shadow) == "EthernetII");

    const auto truncated_ethernet_shadow = run_shadow(
        make_raw_packet(std::vector<std::uint8_t> {
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            0x66, 0x77, 0x88, 0x99,
        }),
        registry
    );
    PFL_EXPECT(truncated_ethernet_shadow.outcome == ImportDissectionOutcome::unrecognized);
    PFL_EXPECT(truncated_ethernet_shadow.stop_reason == StopReason::truncated);
}

void expect_shadow_depth_limit_reports_partial_step_sequence(const DissectionRegistry& registry) {
    const auto ipv6_src_addr = ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x31});
    const auto ipv6_dst_addr = ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x32});

    auto repeated_extensions_payload = make_ipv6_udp_segment(7000U, 8000U, 1U);
    repeated_extensions_payload = make_ipv6_hop_by_hop_extension(detail::kIpProtocolUdp, repeated_extensions_payload);
    for (std::size_t index = 0U; index < detail::kMaxIpv6ExtensionHeaders; ++index) {
        repeated_extensions_payload = make_ipv6_hop_by_hop_extension(detail::kIpProtocolHopByHop, repeated_extensions_payload);
    }

    const auto repeated_extensions_packet = make_raw_packet(make_ethernet_ipv6_packet(
        ipv6_src_addr, ipv6_dst_addr, detail::kIpProtocolHopByHop, repeated_extensions_payload));
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
}

void expect_shadow_arp_terminal_and_failure_behavior(const DissectionRegistry& registry) {
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
}

}  // namespace

void run_common_direct_registry_engine_tests() {
    const auto built = make_common_direct_registry();
    PFL_REQUIRE(built.ok());
    const auto& registry = *built.registry;

    expect_link_type_and_linux_cooked_registry_mappings(registry);
    expect_ip_protocol_and_control_registry_mappings(registry);
    expect_ether_and_embedded_frame_registry_mappings(registry);
    expect_ppp_gre_and_mpls_registry_mappings(registry);
    expect_link_type_selector_helpers();

    expect_shadow_parity_for_ipv4_and_vlan_flows(registry);
    expect_shadow_parity_for_ipv6_flows_and_extensions(registry);
    expect_shadow_parity_for_nested_ip_encapsulation(registry);

    expect_shadow_reports_unrecognized_and_malformed_stops(registry);
    expect_shadow_depth_limit_reports_partial_step_sequence(registry);
    expect_shadow_arp_terminal_and_failure_behavior(registry);
}

}  // namespace pfl::tests::common_direct_test
