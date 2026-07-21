#include "CommonDirectDissectionTestSupport.h"
#include "core/dissection/modules/CommonDirectModules.h"

namespace pfl::tests::common_direct_test {

using namespace dissection;


void expect_import_dissection_collector_uses_explicit_path_commit_policies() {
    const auto make_result = [](const StopReason stop_reason, const std::size_t step_count) {
        return DissectionEngineResult {
            .stop_reason = stop_reason,
            .step_count = step_count,
            .traversed_depth = step_count,
        };
    };
    const std::array all_policies {
        PathCommitPolicy::immediate,
        PathCommitPolicy::recognized_flow,
        PathCommitPolicy::recognized_flow_or_recognized_non_flow,
    };

    for (const auto lhs : all_policies) {
        for (const auto rhs : all_policies) {
            const auto combined = combine_path_commit_policies(lhs, rhs);
            PFL_EXPECT(combined == combine_path_commit_policies(rhs, lhs));
            PFL_EXPECT(path_commit_policy_strength(combined) >= path_commit_policy_strength(lhs));
            PFL_EXPECT(path_commit_policy_strength(combined) >= path_commit_policy_strength(rhs));
        }
        PFL_EXPECT(combine_path_commit_policies(lhs, lhs) == lhs);
    }

    for (const auto lhs : all_policies) {
        for (const auto middle : all_policies) {
            for (const auto rhs : all_policies) {
                PFL_EXPECT(
                    combine_path_commit_policies(
                        combine_path_commit_policies(lhs, middle),
                        rhs)
                    == combine_path_commit_policies(
                        lhs,
                        combine_path_commit_policies(middle, rhs))
                );
            }
        }
    }

    {
        ImportDissectionCollector collector {};
        collector.consume(DissectionStep {
            .layer = DissectionLayerKind::ethernet_ii,
            .path_contribution = LayerKey::ethernet_ii(),
            .status = ParseStatus::complete,
            .stop_reason = StopReason::none,
        });
        collector.finish(make_result(StopReason::unknown_next_protocol, 1U));

        PFL_EXPECT(collector.facts().outcome == ImportDissectionOutcome::unrecognized);
        PFL_EXPECT(format_shadow_path(collector.facts()) == "EthernetII");
    }

    {
        ImportDissectionCollector collector {};
        collector.consume(DissectionStep {
            .layer = DissectionLayerKind::ethernet_ii,
            .path_contribution = LayerKey::ethernet_ii(),
            .status = ParseStatus::complete,
            .stop_reason = StopReason::none,
        });
        collector.consume(DissectionStep {
            .layer = DissectionLayerKind::pppoe,
            .path_contribution = LayerKey::pppoe(),
            .path_commit_policy = PathCommitPolicy::recognized_flow,
            .status = ParseStatus::complete,
            .stop_reason = StopReason::none,
        });
        collector.finish(make_result(StopReason::unsupported_variant, 2U));

        PFL_EXPECT(collector.facts().outcome == ImportDissectionOutcome::unrecognized);
        PFL_EXPECT(format_shadow_path(collector.facts()) == "EthernetII");
    }

    {
        ImportDissectionCollector collector {};
        collector.consume(DissectionStep {
            .layer = DissectionLayerKind::ieee8023,
            .path_contribution = LayerKey::ieee8023(),
            .path_contribution_deferrable_by_child = true,
            .status = ParseStatus::complete,
            .stop_reason = StopReason::none,
        });
        collector.consume(DissectionStep {
            .layer = DissectionLayerKind::llc_snap,
            .path_contribution = LayerKey::llc_snap(),
            .path_commit_policy = PathCommitPolicy::recognized_flow_or_recognized_non_flow,
            .defer_last_deferrable_path_contribution = true,
            .status = ParseStatus::complete,
            .stop_reason = StopReason::none,
        });
        collector.finish(make_result(StopReason::truncated, 2U));

        PFL_EXPECT(collector.facts().outcome == ImportDissectionOutcome::unrecognized);
        PFL_EXPECT(format_shadow_path(collector.facts()).empty());
    }

    {
        ImportDissectionCollector collector {};
        collector.consume(DissectionStep {
            .layer = DissectionLayerKind::ieee8023,
            .path_contribution = LayerKey::ieee8023(),
            .path_contribution_deferrable_by_child = true,
            .status = ParseStatus::complete,
            .stop_reason = StopReason::none,
        });
        collector.consume(DissectionStep {
            .layer = DissectionLayerKind::llc_snap,
            .path_contribution = LayerKey::llc_snap(),
            .path_commit_policy = PathCommitPolicy::recognized_flow_or_recognized_non_flow,
            .defer_last_deferrable_path_contribution = true,
            .status = ParseStatus::complete,
            .stop_reason = StopReason::none,
        });
        collector.consume(DissectionStep {
            .layer = DissectionLayerKind::arp,
            .facts = ArpFacts {
                .has_sender_ipv4 = true,
                .has_target_ipv4 = true,
                .sender_ipv4 = ipv4(192, 0, 2, 10),
                .target_ipv4 = ipv4(192, 0, 2, 1),
            },
            .terminal_disposition = TerminalDisposition::recognized_non_flow,
            .status = ParseStatus::complete,
            .stop_reason = StopReason::terminal_protocol,
        });
        collector.finish(make_result(StopReason::terminal_protocol, 3U));

        PFL_EXPECT(collector.facts().outcome == ImportDissectionOutcome::recognized_non_flow);
        PFL_EXPECT(format_shadow_path(collector.facts()) == "IEEE 802.3 -> LLC/SNAP");
    }

    {
        ImportDissectionCollector collector {};
        collector.consume(DissectionStep {
            .layer = DissectionLayerKind::ethernet_ii,
            .path_contribution = LayerKey::ethernet_ii(),
            .status = ParseStatus::complete,
            .stop_reason = StopReason::none,
        });
        collector.consume(DissectionStep {
            .layer = DissectionLayerKind::pppoe,
            .path_contribution = LayerKey::pppoe(),
            .path_commit_policy = PathCommitPolicy::recognized_flow,
            .status = ParseStatus::complete,
            .stop_reason = StopReason::none,
        });
        collector.consume(DissectionStep {
            .layer = DissectionLayerKind::ppp,
            .path_contribution = LayerKey::ppp(),
            .path_commit_policy = PathCommitPolicy::recognized_flow,
            .status = ParseStatus::complete,
            .stop_reason = StopReason::none,
        });
        collector.consume(DissectionStep {
            .layer = DissectionLayerKind::ipv4,
            .path_contribution = LayerKey::ipv4(),
            .facts = Ipv4Facts {
                .protocol = detail::kIpProtocolUdp,
                .src_addr_v4 = ipv4(192, 0, 2, 30),
                .dst_addr_v4 = ipv4(198, 51, 100, 30),
            },
            .status = ParseStatus::complete,
            .stop_reason = StopReason::none,
        });
        collector.consume(DissectionStep {
            .layer = DissectionLayerKind::udp,
            .path_contribution = LayerKey::udp(),
            .facts = UdpFacts {
                .src_port = 53540U,
                .dst_port = 443U,
            },
            .terminal_disposition = TerminalDisposition::flow_candidate,
            .status = ParseStatus::complete,
            .stop_reason = StopReason::terminal_protocol,
        });
        collector.finish(make_result(StopReason::terminal_protocol, 5U));

        PFL_EXPECT(collector.facts().outcome == ImportDissectionOutcome::recognized_flow);
        PFL_EXPECT(format_shadow_path(collector.facts()) == "EthernetII -> PPPoE -> PPP -> IPv4 -> UDP");
    }

    {
        ImportDissectionCollector collector {};
        collector.consume(DissectionStep {
            .layer = DissectionLayerKind::ethernet_ii,
            .path_contribution = LayerKey::ethernet_ii(),
            .status = ParseStatus::complete,
            .stop_reason = StopReason::none,
        });
        collector.consume(DissectionStep {
            .layer = DissectionLayerKind::pppoe,
            .path_contribution = LayerKey::pppoe(),
            .path_commit_policy = PathCommitPolicy::recognized_flow,
            .descendant_path_commit_policy = PathCommitPolicy::recognized_flow,
            .status = ParseStatus::complete,
            .stop_reason = StopReason::none,
        });
        collector.consume(DissectionStep {
            .layer = DissectionLayerKind::ppp,
            .path_contribution = LayerKey::ppp(),
            .path_commit_policy = PathCommitPolicy::recognized_flow_or_recognized_non_flow,
            .descendant_path_commit_policy = PathCommitPolicy::recognized_flow_or_recognized_non_flow,
            .status = ParseStatus::complete,
            .stop_reason = StopReason::none,
        });
        collector.consume(DissectionStep {
            .layer = DissectionLayerKind::arp,
            .path_contribution = LayerKey::arp(),
            .facts = ArpFacts {
                .has_sender_ipv4 = true,
                .has_target_ipv4 = true,
                .sender_ipv4 = ipv4(198, 51, 100, 10),
                .target_ipv4 = ipv4(198, 51, 100, 1),
            },
            .terminal_disposition = TerminalDisposition::recognized_non_flow,
            .status = ParseStatus::complete,
            .stop_reason = StopReason::terminal_protocol,
        });
        collector.finish(make_result(StopReason::terminal_protocol, 4U));

        PFL_EXPECT(collector.facts().outcome == ImportDissectionOutcome::recognized_non_flow);
        PFL_EXPECT(format_shadow_path(collector.facts()) == "EthernetII");
    }

    {
        ImportDissectionCollector collector {};
        collector.consume(DissectionStep {
            .layer = DissectionLayerKind::ethernet_ii,
            .path_contribution = LayerKey::ethernet_ii(),
            .status = ParseStatus::complete,
            .stop_reason = StopReason::none,
        });
        collector.consume(DissectionStep {
            .layer = DissectionLayerKind::linux_sll,
            .path_contribution = LayerKey::linux_sll(),
            .path_commit_policy = PathCommitPolicy::recognized_flow_or_recognized_non_flow,
            .descendant_path_commit_policy = PathCommitPolicy::recognized_flow_or_recognized_non_flow,
            .status = ParseStatus::complete,
            .stop_reason = StopReason::none,
        });
        collector.consume(DissectionStep {
            .layer = DissectionLayerKind::pppoe,
            .path_contribution = LayerKey::pppoe(),
            .path_commit_policy = PathCommitPolicy::recognized_flow,
            .descendant_path_commit_policy = PathCommitPolicy::recognized_flow,
            .status = ParseStatus::complete,
            .stop_reason = StopReason::none,
        });
        collector.consume(DissectionStep {
            .layer = DissectionLayerKind::arp,
            .path_contribution = LayerKey::arp(),
            .facts = ArpFacts {
                .has_sender_ipv4 = true,
                .has_target_ipv4 = true,
                .sender_ipv4 = ipv4(198, 51, 100, 20),
                .target_ipv4 = ipv4(198, 51, 100, 1),
            },
            .terminal_disposition = TerminalDisposition::recognized_non_flow,
            .status = ParseStatus::complete,
            .stop_reason = StopReason::terminal_protocol,
        });
        collector.finish(make_result(StopReason::terminal_protocol, 4U));

        PFL_EXPECT(collector.facts().outcome == ImportDissectionOutcome::recognized_non_flow);
        PFL_EXPECT(format_shadow_path(collector.facts()) == "EthernetII -> LinuxSll");
    }

    {
        ImportDissectionCollector collector {};
        collector.consume(DissectionStep {
            .layer = DissectionLayerKind::ethernet_ii,
            .path_contribution = LayerKey::ethernet_ii(),
            .status = ParseStatus::complete,
            .stop_reason = StopReason::none,
        });
        collector.consume(DissectionStep {
            .layer = DissectionLayerKind::pppoe,
            .path_contribution = LayerKey::pppoe(),
            .path_commit_policy = PathCommitPolicy::recognized_flow_or_recognized_non_flow,
            .descendant_path_commit_policy = PathCommitPolicy::recognized_flow_or_recognized_non_flow,
            .status = ParseStatus::complete,
            .stop_reason = StopReason::none,
        });
        collector.consume(DissectionStep {
            .layer = DissectionLayerKind::ppp,
            .path_contribution = LayerKey::ppp(),
            .path_commit_policy = PathCommitPolicy::recognized_flow,
            .descendant_path_commit_policy = PathCommitPolicy::recognized_flow,
            .status = ParseStatus::complete,
            .stop_reason = StopReason::none,
        });
        collector.consume(DissectionStep {
            .layer = DissectionLayerKind::arp,
            .path_contribution = LayerKey::arp(),
            .facts = ArpFacts {
                .has_sender_ipv4 = true,
                .has_target_ipv4 = true,
                .sender_ipv4 = ipv4(203, 0, 113, 10),
                .target_ipv4 = ipv4(203, 0, 113, 1),
            },
            .terminal_disposition = TerminalDisposition::recognized_non_flow,
            .status = ParseStatus::complete,
            .stop_reason = StopReason::terminal_protocol,
        });
        collector.finish(make_result(StopReason::terminal_protocol, 4U));

        PFL_EXPECT(collector.facts().outcome == ImportDissectionOutcome::recognized_non_flow);
        PFL_EXPECT(format_shadow_path(collector.facts()) == "EthernetII -> PPPoE");
    }

    {
        ImportDissectionCollector collector {};
        collector.consume(DissectionStep {
            .layer = DissectionLayerKind::ethernet_ii,
            .path_contribution = LayerKey::ethernet_ii(),
            .status = ParseStatus::complete,
            .stop_reason = StopReason::none,
        });
        collector.consume(DissectionStep {
            .layer = DissectionLayerKind::pppoe,
            .path_contribution = LayerKey::pppoe(),
            .descendant_path_commit_policy = PathCommitPolicy::recognized_flow,
            .status = ParseStatus::complete,
            .stop_reason = StopReason::none,
        });
        collector.consume(DissectionStep {
            .layer = DissectionLayerKind::ipv4,
            .path_contribution = LayerKey::ipv4(),
            .status = ParseStatus::complete,
            .stop_reason = StopReason::none,
        });
        collector.consume(DissectionStep {
            .layer = DissectionLayerKind::arp,
            .path_contribution = LayerKey::arp(),
            .facts = ArpFacts {
                .has_sender_ipv4 = true,
                .has_target_ipv4 = true,
                .sender_ipv4 = ipv4(203, 0, 113, 30),
                .target_ipv4 = ipv4(203, 0, 113, 1),
            },
            .terminal_disposition = TerminalDisposition::recognized_non_flow,
            .status = ParseStatus::complete,
            .stop_reason = StopReason::terminal_protocol,
        });
        collector.finish(make_result(StopReason::terminal_protocol, 4U));

        PFL_EXPECT(collector.facts().outcome == ImportDissectionOutcome::recognized_non_flow);
        PFL_EXPECT(format_shadow_path(collector.facts()) == "EthernetII");
    }

    {
        ImportDissectionCollector collector {};
        collector.consume(DissectionStep {
            .layer = DissectionLayerKind::ieee8023,
            .path_contribution = LayerKey::ieee8023(),
            .path_commit_policy = PathCommitPolicy::recognized_flow,
            .path_contribution_deferrable_by_child = true,
            .status = ParseStatus::complete,
            .stop_reason = StopReason::none,
        });
        collector.consume(DissectionStep {
            .layer = DissectionLayerKind::llc_snap,
            .path_contribution = LayerKey::llc_snap(),
            .path_commit_policy = PathCommitPolicy::recognized_flow_or_recognized_non_flow,
            .defer_last_deferrable_path_contribution = true,
            .status = ParseStatus::complete,
            .stop_reason = StopReason::none,
        });
        collector.finish(make_result(StopReason::truncated, 2U));

        PFL_EXPECT(collector.facts().outcome == ImportDissectionOutcome::unrecognized);
        PFL_EXPECT(format_shadow_path(collector.facts()).empty());
    }

    {
        ImportDissectionCollector collector {};
        collector.consume(DissectionStep {
            .layer = DissectionLayerKind::ieee8023,
            .path_contribution = LayerKey::ieee8023(),
            .path_contribution_deferrable_by_child = true,
            .status = ParseStatus::complete,
            .stop_reason = StopReason::none,
        });
        collector.consume(DissectionStep {
            .layer = DissectionLayerKind::llc_snap,
            .path_contribution = LayerKey::llc_snap(),
            .path_commit_policy = PathCommitPolicy::recognized_flow,
            .defer_last_deferrable_path_contribution = true,
            .status = ParseStatus::complete,
            .stop_reason = StopReason::none,
        });
        collector.consume(DissectionStep {
            .layer = DissectionLayerKind::ipv4,
            .path_contribution = LayerKey::ipv4(),
            .path_commit_policy = PathCommitPolicy::recognized_flow_or_recognized_non_flow,
            .facts = Ipv4Facts {
                .protocol = detail::kIpProtocolUdp,
                .src_addr_v4 = ipv4(192, 0, 2, 40),
                .dst_addr_v4 = ipv4(198, 51, 100, 40),
            },
            .status = ParseStatus::complete,
            .stop_reason = StopReason::none,
        });
        collector.consume(DissectionStep {
            .layer = DissectionLayerKind::udp,
            .path_contribution = LayerKey::udp(),
            .path_commit_policy = PathCommitPolicy::recognized_flow_or_recognized_non_flow,
            .facts = UdpFacts {
                .src_port = 1234U,
                .dst_port = 5678U,
            },
            .terminal_disposition = TerminalDisposition::flow_candidate,
            .status = ParseStatus::complete,
            .stop_reason = StopReason::terminal_protocol,
        });
        collector.finish(make_result(StopReason::terminal_protocol, 4U));

        PFL_EXPECT(collector.facts().outcome == ImportDissectionOutcome::recognized_flow);
        PFL_EXPECT(format_shadow_path(collector.facts()) == "IEEE 802.3 -> LLC/SNAP -> IPv4 -> UDP");
    }
}


void expect_common_direct_registry_and_root_selector() {
    const auto built = make_common_direct_registry();
    PFL_REQUIRE(built.ok());
    PFL_EXPECT(built.registry->entry_count() == 75U);
    PFL_EXPECT(built.registry->find(make_link_type_selector(kLinkTypeEthernet)) == dissect_ethernet);
    PFL_EXPECT(built.registry->find(make_link_type_selector(kLinkTypeLinuxSll)) == dissect_linux_sll);
    PFL_EXPECT(built.registry->find(make_link_type_selector(kLinkTypeLinuxSll2)) == dissect_linux_sll2);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::linux_cooked_protocol,
        .value = detail::kEtherTypeIpv4,
    }) == dissect_ipv4);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::linux_cooked_protocol,
        .value = detail::kEtherTypeIpv6,
    }) == dissect_ipv6);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::linux_cooked_protocol,
        .value = detail::kEtherTypeArp,
    }) == dissect_linux_cooked_arp);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::linux_cooked_protocol,
        .value = detail::kEtherTypeVlan,
    }) == nullptr);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::linux_cooked_protocol,
        .value = detail::kEtherTypeQinq,
    }) == nullptr);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::linux_cooked_protocol,
        .value = detail::kEtherTypeLegacyVlan,
    }) == nullptr);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::linux_cooked_protocol,
        .value = detail::kEtherTypeMacsec,
    }) == nullptr);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::native_ieee8023_payload,
        .value = kIeee8023PayloadSelectorValue,
    }) == dissect_llc_snap);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::ieee8023_payload,
        .value = kIeee8023PayloadSelectorValue,
    }) == dissect_llc_snap);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::ip_protocol,
        .value = detail::kIpProtocolIcmp,
    }) == dissect_icmp);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::ip_protocol,
        .value = detail::kIpProtocolIgmp,
    }) == dissect_igmp);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::ip_protocol,
        .value = detail::kIpProtocolIpv4Encapsulation,
    }) == dissect_ipv4);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::ip_protocol,
        .value = detail::kIpProtocolIpv6Encapsulation,
    }) == dissect_ipv6);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::ip_protocol,
        .value = detail::kIpProtocolGre,
    }) == dissect_gre);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::ip_protocol,
        .value = detail::kIpProtocolAh,
    }) == dissect_ipv4_ah);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::ip_protocol,
        .value = detail::kIpProtocolEsp,
    }) == dissect_esp);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::ipv6_next_header,
        .value = detail::kIpProtocolIcmpV6,
    }) == dissect_icmpv6);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::ipv6_next_header,
        .value = detail::kIpProtocolIpv4Encapsulation,
    }) == dissect_ipv4);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::ipv6_next_header,
        .value = detail::kIpProtocolIpv6Encapsulation,
    }) == dissect_ipv6);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::ipv6_next_header,
        .value = detail::kIpProtocolGre,
    }) == dissect_gre);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::ipv6_next_header,
        .value = detail::kIpProtocolAh,
    }) == dissect_ipv6_ah);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::ipv6_next_header,
        .value = detail::kIpProtocolEsp,
    }) == dissect_esp);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::llc_snap_pid,
        .value = detail::kEtherTypeIpv4,
    }) == dissect_ipv4);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::llc_snap_pid,
        .value = detail::kEtherTypeIpv6,
    }) == dissect_ipv6);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::llc_snap_pid,
        .value = detail::kEtherTypeArp,
    }) == dissect_arp);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::pbb_inner_frame,
        .value = kPbbInnerFrameSelectorValue,
    }) == dissect_pbb_inner_ethernet);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::pbb_inner_ether_type,
        .value = detail::kEtherTypeIpv4,
    }) == dissect_ipv4);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::pbb_inner_ether_type,
        .value = detail::kEtherTypeIpv6,
    }) == dissect_ipv6);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::pbb_inner_ether_type,
        .value = detail::kEtherTypeArp,
    }) == dissect_arp);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::pbb_inner_ether_type,
        .value = detail::kEtherTypeVlan,
    }) == dissect_pbb_inner_vlan);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::pbb_inner_ether_type,
        .value = detail::kEtherTypeQinq,
    }) == dissect_pbb_inner_vlan);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::pbb_inner_ether_type,
        .value = detail::kEtherTypeLegacyVlan,
    }) == dissect_pbb_inner_vlan);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::pbb_inner_ether_type,
        .value = detail::kEtherTypeMacsec,
    }) == nullptr);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::native_ether_type,
        .value = detail::kEtherTypeIpv4,
    }) == dissect_ipv4);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::native_ether_type,
        .value = detail::kEtherTypeIpv6,
    }) == dissect_ipv6);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::native_ether_type,
        .value = detail::kEtherTypeArp,
    }) == dissect_arp);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::native_ether_type,
        .value = detail::kEtherTypePbb,
    }) == dissect_pbb);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::native_ether_type,
        .value = detail::kEtherTypePppoeDiscovery,
    }) == dissect_pppoe_discovery);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::native_ether_type,
        .value = detail::kEtherTypePppoeSession,
    }) == dissect_pppoe_session);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::native_ether_type,
        .value = detail::kEtherTypeMacsec,
    }) == dissect_macsec);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::native_ether_type,
        .value = detail::kEtherTypeVlan,
    }) == dissect_vlan);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::native_ether_type,
        .value = detail::kEtherTypeQinq,
    }) == dissect_vlan);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::native_ether_type,
        .value = detail::kEtherTypeLegacyVlan,
    }) == dissect_vlan);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::native_ether_type,
        .value = detail::kEtherTypeMplsUnicast,
    }) == dissect_mpls_label);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::ether_type,
        .value = detail::kEtherTypePbb,
    }) == dissect_pbb);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::ether_type,
        .value = detail::kEtherTypePppoeDiscovery,
    }) == dissect_pppoe_discovery);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::ether_type,
        .value = detail::kEtherTypePppoeSession,
    }) == dissect_pppoe_session);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::ether_type,
        .value = detail::kEtherTypeMacsec,
    }) == nullptr);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::ether_type,
        .value = detail::kEtherTypeVlan,
    }) == dissect_embedded_vlan);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::ether_type,
        .value = detail::kEtherTypeQinq,
    }) == dissect_embedded_vlan);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::ether_type,
        .value = detail::kEtherTypeLegacyVlan,
    }) == dissect_embedded_vlan);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::ppp_frame,
        .value = kPppFrameContinueSelectorValue,
    }) == dissect_ppp);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::ppp_protocol,
        .value = detail::kPppProtocolIpv4,
    }) == dissect_ipv4);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::ppp_protocol,
        .value = detail::kPppProtocolIpv6,
    }) == dissect_ipv6);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::ppp_protocol,
        .value = 0xC021U,
    }) == dissect_ppp_control);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::ppp_protocol,
        .value = 0x8021U,
    }) == dissect_ppp_control);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::ppp_protocol,
        .value = 0x8057U,
    }) == dissect_ppp_control);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::ppp_protocol,
        .value = 0x1235U,
    }) == nullptr);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::gre_protocol_type,
        .value = detail::kEtherTypeIpv4,
    }) == dissect_ipv4);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::gre_protocol_type,
        .value = detail::kEtherTypeIpv6,
    }) == dissect_ipv6);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::gre_protocol_type,
        .value = detail::kGreProtocolTypeTransparentEthernetBridging,
    }) == dissect_embedded_ethernet);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::gre_protocol_type,
        .value = detail::kEtherTypeMacsec,
    }) == nullptr);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::gre_protocol_type,
        .value = detail::kEtherTypeMplsUnicast,
    }) == dissect_mpls_label);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::ether_type,
        .value = detail::kEtherTypeMplsUnicast,
    }) == dissect_mpls_label);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::mpls_stack,
        .value = kMplsStackContinueSelectorValue,
    }) == dissect_mpls_label);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::mpls_payload,
        .value = detail::kEtherTypeIpv4,
    }) == dissect_ipv4);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::mpls_payload,
        .value = detail::kEtherTypeIpv6,
    }) == dissect_ipv6);

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

    expect_shadow_matches_legacy_portless_flow(
        registry,
        make_raw_packet(make_ethernet_ipv6_packet(
            ipv6_src_addr,
            ipv6_dst_addr,
            detail::kIpProtocolIcmpV6,
            make_ipv6_icmpv6_message(128U, 0U)
        )),
        "EthernetII -> IPv6 -> ICMPv6",
        "EthernetII -> IPv6",
        StopReason::terminal_protocol
    );

    expect_shadow_matches_legacy_portless_flow(
        registry,
        make_raw_packet(add_vlan_tags(
            make_ethernet_ipv6_packet(
                ipv6_src_addr,
                ipv6_dst_addr,
                detail::kIpProtocolIcmpV6,
                make_ipv6_icmpv6_message(129U, 1U)
            ),
            {{0x8100U, 406U}}
        )),
        "EthernetII -> VLAN(vid=406) -> IPv6 -> ICMPv6",
        "EthernetII -> VLAN(vid=406) -> IPv6",
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

    expect_shadow_matches_legacy_portless_flow(
        registry,
        make_raw_packet(make_ethernet_ipv6_icmpv6_with_hop_by_hop_packet(
            ipv6_src_addr,
            ipv6_dst_addr,
            128U,
            0U
        )),
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
        make_raw_packet(make_ethernet_ipv4_fragment_packet(
            ipv4(10, 9, 0, 1),
            ipv4(10, 9, 0, 2),
            0xFDU,
            0U,
            {0xdeU, 0xadU, 0xbeU, 0xefU}
        )),
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


void run_common_direct_core_dissection_tests() {
    expect_import_dissection_collector_uses_explicit_path_commit_policies();
    expect_common_direct_registry_and_root_selector();
    expect_common_direct_steps_report_handoffs_bounds_and_facts();
    expect_failed_layers_do_not_contribute_path_and_exact_arp_bounds();
    expect_shadow_parity_for_common_direct_subset();
    expect_shadow_conservative_stops_and_arp_behavior();
}

}  // namespace pfl::tests::common_direct_test
