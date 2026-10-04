#include "CommonDirectDissectionTestSupport.h"

namespace pfl::tests::common_direct_test {

using namespace dissection;

namespace {

DissectionEngineResult make_test_result(const StopReason stop_reason, const std::size_t step_count) {
    return DissectionEngineResult {
        .stop_reason = stop_reason,
        .step_count = step_count,
        .traversed_depth = step_count,
    };
}

DissectionStep make_path_step(
    const DissectionLayerKind layer,
    const LayerKey path_contribution,
    const PathCommitPolicy path_commit_policy = PathCommitPolicy::immediate,
    const std::optional<PathCommitPolicy>& descendant_path_commit_policy = std::nullopt,
    const bool path_contribution_deferrable_by_child = false,
    const bool defer_last_deferrable_path_contribution = false
) {
    return DissectionStep {
        .layer = layer,
        .path_contribution = path_contribution,
        .path_commit_policy = path_commit_policy,
        .descendant_path_commit_policy = descendant_path_commit_policy,
        .path_contribution_deferrable_by_child = path_contribution_deferrable_by_child,
        .defer_last_deferrable_path_contribution = defer_last_deferrable_path_contribution,
        .status = ParseStatus::complete,
        .stop_reason = StopReason::none,
    };
}

DissectionStep make_ipv4_flow_step(
    const std::uint8_t protocol,
    const std::uint32_t src_addr,
    const std::uint32_t dst_addr
) {
    return DissectionStep {
        .layer = DissectionLayerKind::ipv4,
        .path_contribution = LayerKey::ipv4(),
        .facts = Ipv4Facts {
            .protocol = protocol,
            .src_addr_v4 = src_addr,
            .dst_addr_v4 = dst_addr,
        },
        .status = ParseStatus::complete,
        .stop_reason = StopReason::none,
    };
}

DissectionStep make_ipv6_flow_step(
    const std::uint8_t next_header,
    const std::array<std::uint8_t, 16>& src_addr,
    const std::array<std::uint8_t, 16>& dst_addr
) {
    return DissectionStep {
        .layer = DissectionLayerKind::ipv6,
        .path_contribution = LayerKey::ipv6(),
        .facts = Ipv6Facts {
            .next_header = next_header,
            .src_addr_v6 = src_addr,
            .dst_addr_v6 = dst_addr,
        },
        .status = ParseStatus::complete,
        .stop_reason = StopReason::none,
    };
}

DissectionStep make_udp_terminal_step(const std::uint16_t src_port, const std::uint16_t dst_port) {
    return DissectionStep {
        .layer = DissectionLayerKind::udp,
        .path_contribution = LayerKey::udp(),
        .facts = UdpFacts {
            .src_port = src_port,
            .dst_port = dst_port,
        },
        .terminal_disposition = TerminalDisposition::flow_candidate,
        .status = ParseStatus::complete,
        .stop_reason = StopReason::terminal_protocol,
    };
}

DissectionStep make_arp_terminal_step(const std::uint32_t sender_ipv4, const std::uint32_t target_ipv4) {
    return DissectionStep {
        .layer = DissectionLayerKind::arp,
        .facts = ArpFacts {
            .has_sender_ipv4 = true,
            .has_target_ipv4 = true,
            .sender_ipv4 = sender_ipv4,
            .target_ipv4 = target_ipv4,
        },
        .terminal_disposition = TerminalDisposition::flow_candidate,
        .status = ParseStatus::complete,
        .stop_reason = StopReason::terminal_protocol,
    };
}

void expect_non_terminal_level(
    const NonTerminalIpContextBuilder& builder,
    const std::size_t index,
    const NonTerminalIpLevel& expected
) {
    PFL_REQUIRE(index < builder.size());
    PFL_EXPECT(builder[index] == expected);
}

void expect_collector_immediate_path_contribution_survives_unrecognized_stops() {
    {
        ImportDissectionCollector collector {};
        collector.consume(make_path_step(
            DissectionLayerKind::ethernet_ii,
            LayerKey::ethernet_ii()
        ));
        collector.finish(make_test_result(StopReason::unknown_next_protocol, 1U));

        PFL_EXPECT(collector.facts().outcome == ImportDissectionOutcome::unrecognized);
        PFL_EXPECT(format_shadow_path(collector.facts()) == "EthernetII");
    }

    {
        ImportDissectionCollector collector {};
        collector.consume(make_path_step(
            DissectionLayerKind::ethernet_ii,
            LayerKey::ethernet_ii()
        ));
        collector.consume(make_path_step(
            DissectionLayerKind::pppoe,
            LayerKey::pppoe(),
            PathCommitPolicy::recognized_flow
        ));
        collector.finish(make_test_result(StopReason::unsupported_variant, 2U));

        PFL_EXPECT(collector.facts().outcome == ImportDissectionOutcome::unrecognized);
        PFL_EXPECT(format_shadow_path(collector.facts()) == "EthernetII");
    }
}

void expect_collector_arp_flow_finalization_preserves_committed_path() {
    ImportDissectionCollector collector {};
    collector.consume(make_path_step(
        DissectionLayerKind::ieee8023,
        LayerKey::ieee8023(),
        PathCommitPolicy::immediate,
        std::nullopt,
        true
    ));
    collector.consume(make_path_step(
        DissectionLayerKind::llc_snap,
        LayerKey::llc_snap(),
        PathCommitPolicy::recognized_flow_or_recognized_non_flow,
        std::nullopt,
        false,
        true
    ));
    collector.consume(make_arp_terminal_step(
        ipv4(192, 0, 2, 10),
        ipv4(192, 0, 2, 1)
    ));
    collector.finish(make_test_result(StopReason::terminal_protocol, 3U));

    PFL_EXPECT(collector.facts().outcome == ImportDissectionOutcome::recognized_flow);
    PFL_EXPECT(format_shadow_path(collector.facts()) == "IEEE 802.3 -> LLC/SNAP");
    PFL_EXPECT(collector.facts().terminal_protocol == ProtocolId::arp);
    PFL_EXPECT(collector.facts().family == DissectionAddressFamily::ipv4);
    PFL_EXPECT(collector.facts().has_arp_addresses);
    PFL_EXPECT(collector.facts().has_flow_addresses);
    PFL_EXPECT(collector.facts().src_addr_v4 == ipv4(192, 0, 2, 10));
    PFL_EXPECT(collector.facts().dst_addr_v4 == ipv4(192, 0, 2, 1));
    PFL_EXPECT(collector.facts().arp_addresses.sender_ipv4 == ipv4(192, 0, 2, 10));
    PFL_EXPECT(collector.facts().arp_addresses.target_ipv4 == ipv4(192, 0, 2, 1));
    PFL_EXPECT(!collector.facts().has_ports);
    PFL_EXPECT(!collector.facts().has_transport_payload_length);
    PFL_EXPECT(!collector.facts().has_tcp_flags);
    PFL_EXPECT(!collector.facts().has_tcp_sequence_number);
}

void expect_collector_recognized_flow_finalization_populates_terminal_metadata() {
    ImportDissectionCollector collector {};
    collector.consume(make_path_step(
        DissectionLayerKind::ethernet_ii,
        LayerKey::ethernet_ii()
    ));
    collector.consume(make_path_step(
        DissectionLayerKind::pppoe,
        LayerKey::pppoe(),
        PathCommitPolicy::recognized_flow
    ));
    collector.consume(make_path_step(
        DissectionLayerKind::ppp,
        LayerKey::ppp(),
        PathCommitPolicy::recognized_flow
    ));
    collector.consume(make_ipv4_flow_step(
        detail::kIpProtocolUdp,
        ipv4(192, 0, 2, 30),
        ipv4(198, 51, 100, 30)
    ));
    collector.consume(make_udp_terminal_step(53540U, 443U));
    collector.finish(make_test_result(StopReason::terminal_protocol, 5U));

    PFL_EXPECT(collector.facts().outcome == ImportDissectionOutcome::recognized_flow);
    PFL_EXPECT(format_shadow_path(collector.facts()) == "EthernetII -> PPPoE -> PPP -> IPv4 -> UDP");
    PFL_EXPECT(collector.facts().terminal_protocol == ProtocolId::udp);
    PFL_EXPECT(collector.facts().family == DissectionAddressFamily::ipv4);
    PFL_EXPECT(collector.facts().has_flow_addresses);
    PFL_EXPECT(collector.facts().src_addr_v4 == ipv4(192, 0, 2, 30));
    PFL_EXPECT(collector.facts().dst_addr_v4 == ipv4(198, 51, 100, 30));
    PFL_EXPECT(collector.facts().has_ports);
    PFL_EXPECT(collector.facts().src_port == 53540U);
    PFL_EXPECT(collector.facts().dst_port == 443U);
    PFL_EXPECT(!collector.facts().has_transport_payload_length);
    PFL_EXPECT(!collector.facts().has_tcp_flags);
    PFL_EXPECT(!collector.facts().has_tcp_sequence_number);
}

void expect_collector_direct_ipv4_has_empty_non_terminal_context() {
    ImportDissectionCollector collector {};
    collector.consume(make_ipv4_flow_step(
        detail::kIpProtocolUdp,
        ipv4(192, 0, 2, 10),
        ipv4(198, 51, 100, 10)
    ));
    collector.consume(make_udp_terminal_step(12345U, 443U));
    collector.finish(make_test_result(StopReason::terminal_protocol, 2U));

    PFL_EXPECT(collector.facts().outcome == ImportDissectionOutcome::recognized_flow);
    PFL_EXPECT(collector.facts().family == DissectionAddressFamily::ipv4);
    PFL_EXPECT(collector.facts().src_addr_v4 == ipv4(192, 0, 2, 10));
    PFL_EXPECT(collector.facts().dst_addr_v4 == ipv4(198, 51, 100, 10));
    PFL_EXPECT(collector.facts().non_terminal_ip_context_builder.empty());
    PFL_EXPECT(!collector.facts().non_terminal_ip_context_builder.overflowed());
}

void expect_collector_direct_ipv6_has_empty_non_terminal_context() {
    const auto src = ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0x10});
    const auto dst = ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0x20});

    ImportDissectionCollector collector {};
    collector.consume(make_ipv6_flow_step(detail::kIpProtocolUdp, src, dst));
    collector.consume(make_udp_terminal_step(12345U, 443U));
    collector.finish(make_test_result(StopReason::terminal_protocol, 2U));

    PFL_EXPECT(collector.facts().outcome == ImportDissectionOutcome::recognized_flow);
    PFL_EXPECT(collector.facts().family == DissectionAddressFamily::ipv6);
    PFL_EXPECT(collector.facts().src_addr_v6 == src);
    PFL_EXPECT(collector.facts().dst_addr_v6 == dst);
    PFL_EXPECT(collector.facts().non_terminal_ip_context_builder.empty());
    PFL_EXPECT(!collector.facts().non_terminal_ip_context_builder.overflowed());
}

void expect_collector_ipv4_to_ipv4_promotes_outer_only() {
    ImportDissectionCollector collector {};
    collector.consume(make_ipv4_flow_step(
        detail::kIpProtocolIpv4Encapsulation,
        ipv4(192, 0, 2, 1),
        ipv4(192, 0, 2, 2)
    ));
    collector.consume(make_ipv4_flow_step(
        detail::kIpProtocolUdp,
        ipv4(198, 51, 100, 1),
        ipv4(198, 51, 100, 2)
    ));
    collector.consume(make_udp_terminal_step(12345U, 443U));
    collector.finish(make_test_result(StopReason::terminal_protocol, 3U));

    PFL_EXPECT(collector.facts().family == DissectionAddressFamily::ipv4);
    PFL_EXPECT(collector.facts().src_addr_v4 == ipv4(198, 51, 100, 1));
    PFL_EXPECT(collector.facts().dst_addr_v4 == ipv4(198, 51, 100, 2));
    PFL_EXPECT(collector.facts().non_terminal_ip_context_builder.size() == 1U);
    expect_non_terminal_level(
        collector.facts().non_terminal_ip_context_builder,
        0U,
        NonTerminalIpLevel::ipv4(ipv4(192, 0, 2, 1), ipv4(192, 0, 2, 2))
    );
    PFL_EXPECT(!collector.facts().non_terminal_ip_context_builder.overflowed());
}

void expect_collector_ipv4_to_ipv6_promotes_ipv4_outer() {
    const auto inner_src = ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0x10});
    const auto inner_dst = ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0x20});

    ImportDissectionCollector collector {};
    collector.consume(make_ipv4_flow_step(
        detail::kIpProtocolIpv6Encapsulation,
        ipv4(192, 0, 2, 11),
        ipv4(192, 0, 2, 12)
    ));
    collector.consume(make_ipv6_flow_step(detail::kIpProtocolUdp, inner_src, inner_dst));
    collector.consume(make_udp_terminal_step(12345U, 443U));
    collector.finish(make_test_result(StopReason::terminal_protocol, 3U));

    PFL_EXPECT(collector.facts().family == DissectionAddressFamily::ipv6);
    PFL_EXPECT(collector.facts().src_addr_v6 == inner_src);
    PFL_EXPECT(collector.facts().dst_addr_v6 == inner_dst);
    PFL_EXPECT(collector.facts().non_terminal_ip_context_builder.size() == 1U);
    expect_non_terminal_level(
        collector.facts().non_terminal_ip_context_builder,
        0U,
        NonTerminalIpLevel::ipv4(ipv4(192, 0, 2, 11), ipv4(192, 0, 2, 12))
    );
}

void expect_collector_ipv6_to_ipv4_promotes_ipv6_outer() {
    const auto outer_src = ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0x10});
    const auto outer_dst = ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0x20});

    ImportDissectionCollector collector {};
    collector.consume(make_ipv6_flow_step(detail::kIpProtocolIpv4Encapsulation, outer_src, outer_dst));
    collector.consume(make_ipv4_flow_step(
        detail::kIpProtocolUdp,
        ipv4(198, 51, 100, 11),
        ipv4(198, 51, 100, 12)
    ));
    collector.consume(make_udp_terminal_step(12345U, 443U));
    collector.finish(make_test_result(StopReason::terminal_protocol, 3U));

    PFL_EXPECT(collector.facts().family == DissectionAddressFamily::ipv4);
    PFL_EXPECT(collector.facts().src_addr_v4 == ipv4(198, 51, 100, 11));
    PFL_EXPECT(collector.facts().dst_addr_v4 == ipv4(198, 51, 100, 12));
    PFL_EXPECT(collector.facts().non_terminal_ip_context_builder.size() == 1U);
    expect_non_terminal_level(
        collector.facts().non_terminal_ip_context_builder,
        0U,
        NonTerminalIpLevel::ipv6(outer_src, outer_dst)
    );
}

void expect_collector_ipv6_to_ipv6_promotes_outer_only() {
    const auto outer_src = ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0x10});
    const auto outer_dst = ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0x20});
    const auto inner_src = ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0x10});
    const auto inner_dst = ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0x20});

    ImportDissectionCollector collector {};
    collector.consume(make_ipv6_flow_step(detail::kIpProtocolIpv6Encapsulation, outer_src, outer_dst));
    collector.consume(make_ipv6_flow_step(detail::kIpProtocolUdp, inner_src, inner_dst));
    collector.consume(make_udp_terminal_step(12345U, 443U));
    collector.finish(make_test_result(StopReason::terminal_protocol, 3U));

    PFL_EXPECT(collector.facts().family == DissectionAddressFamily::ipv6);
    PFL_EXPECT(collector.facts().src_addr_v6 == inner_src);
    PFL_EXPECT(collector.facts().dst_addr_v6 == inner_dst);
    PFL_EXPECT(collector.facts().non_terminal_ip_context_builder.size() == 1U);
    expect_non_terminal_level(
        collector.facts().non_terminal_ip_context_builder,
        0U,
        NonTerminalIpLevel::ipv6(outer_src, outer_dst)
    );
}

void expect_collector_three_ipv4_levels_preserve_outer_to_inner_order() {
    ImportDissectionCollector collector {};
    collector.consume(make_ipv4_flow_step(
        detail::kIpProtocolIpv4Encapsulation,
        ipv4(10, 0, 0, 1),
        ipv4(10, 0, 0, 2)
    ));
    collector.consume(make_ipv4_flow_step(
        detail::kIpProtocolIpv4Encapsulation,
        ipv4(10, 1, 0, 1),
        ipv4(10, 1, 0, 2)
    ));
    collector.consume(make_ipv4_flow_step(
        detail::kIpProtocolUdp,
        ipv4(10, 2, 0, 1),
        ipv4(10, 2, 0, 2)
    ));
    collector.consume(make_udp_terminal_step(12345U, 443U));
    collector.finish(make_test_result(StopReason::terminal_protocol, 4U));

    PFL_EXPECT(collector.facts().src_addr_v4 == ipv4(10, 2, 0, 1));
    PFL_EXPECT(collector.facts().dst_addr_v4 == ipv4(10, 2, 0, 2));
    PFL_EXPECT(collector.facts().non_terminal_ip_context_builder.size() == 2U);
    expect_non_terminal_level(
        collector.facts().non_terminal_ip_context_builder,
        0U,
        NonTerminalIpLevel::ipv4(ipv4(10, 0, 0, 1), ipv4(10, 0, 0, 2))
    );
    expect_non_terminal_level(
        collector.facts().non_terminal_ip_context_builder,
        1U,
        NonTerminalIpLevel::ipv4(ipv4(10, 1, 0, 1), ipv4(10, 1, 0, 2))
    );
}

void expect_collector_mixed_three_levels_preserve_family_and_order() {
    const auto middle_src = ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 0x10});
    const auto middle_dst = ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 0x20});

    ImportDissectionCollector collector {};
    collector.consume(make_ipv4_flow_step(
        detail::kIpProtocolIpv6Encapsulation,
        ipv4(203, 0, 113, 1),
        ipv4(203, 0, 113, 2)
    ));
    collector.consume(make_ipv6_flow_step(detail::kIpProtocolIpv4Encapsulation, middle_src, middle_dst));
    collector.consume(make_ipv4_flow_step(
        detail::kIpProtocolUdp,
        ipv4(198, 51, 100, 21),
        ipv4(198, 51, 100, 22)
    ));
    collector.consume(make_udp_terminal_step(12345U, 443U));
    collector.finish(make_test_result(StopReason::terminal_protocol, 4U));

    PFL_EXPECT(collector.facts().family == DissectionAddressFamily::ipv4);
    PFL_EXPECT(collector.facts().src_addr_v4 == ipv4(198, 51, 100, 21));
    PFL_EXPECT(collector.facts().dst_addr_v4 == ipv4(198, 51, 100, 22));
    PFL_EXPECT(collector.facts().non_terminal_ip_context_builder.size() == 2U);
    expect_non_terminal_level(
        collector.facts().non_terminal_ip_context_builder,
        0U,
        NonTerminalIpLevel::ipv4(ipv4(203, 0, 113, 1), ipv4(203, 0, 113, 2))
    );
    expect_non_terminal_level(
        collector.facts().non_terminal_ip_context_builder,
        1U,
        NonTerminalIpLevel::ipv6(middle_src, middle_dst)
    );
}

void expect_collector_does_not_guess_inner_ip_when_no_inner_ip_fact_is_emitted() {
    ImportDissectionCollector collector {};
    collector.consume(make_ipv4_flow_step(
        detail::kIpProtocolGre,
        ipv4(192, 0, 2, 31),
        ipv4(192, 0, 2, 32)
    ));
    collector.finish(make_test_result(StopReason::unsupported_variant, 1U));

    PFL_EXPECT(collector.facts().family == DissectionAddressFamily::ipv4);
    PFL_EXPECT(collector.facts().src_addr_v4 == ipv4(192, 0, 2, 31));
    PFL_EXPECT(collector.facts().dst_addr_v4 == ipv4(192, 0, 2, 32));
    PFL_EXPECT(collector.facts().non_terminal_ip_context_builder.empty());
    PFL_EXPECT(!collector.facts().non_terminal_ip_context_builder.overflowed());
}

void expect_collector_non_terminal_context_overflow_is_recorded_but_dormant() {
    ImportDissectionCollector collector {};
    for (std::size_t index = 0U; index < kMaxNonTerminalIpContextLevels + 2U; ++index) {
        collector.consume(make_ipv4_flow_step(
            detail::kIpProtocolIpv4Encapsulation,
            ipv4(10, static_cast<std::uint8_t>(index & 0xffU), 0, 1),
            ipv4(10, static_cast<std::uint8_t>(index & 0xffU), 0, 2)
        ));
    }
    collector.consume(make_udp_terminal_step(12345U, 443U));
    collector.finish(make_test_result(StopReason::terminal_protocol, kMaxNonTerminalIpContextLevels + 3U));

    PFL_EXPECT(collector.facts().outcome == ImportDissectionOutcome::recognized_flow);
    PFL_EXPECT(collector.facts().family == DissectionAddressFamily::ipv4);
    PFL_EXPECT(collector.facts().src_addr_v4 == ipv4(10, static_cast<std::uint8_t>((kMaxNonTerminalIpContextLevels + 1U) & 0xffU), 0, 1));
    PFL_EXPECT(collector.facts().dst_addr_v4 == ipv4(10, static_cast<std::uint8_t>((kMaxNonTerminalIpContextLevels + 1U) & 0xffU), 0, 2));
    PFL_EXPECT(collector.facts().non_terminal_ip_context_builder.overflowed());
    PFL_EXPECT(collector.facts().non_terminal_ip_context_builder.size() == kMaxNonTerminalIpContextLevels);
}

}  // namespace

void run_common_direct_collector_tests() {
    expect_collector_immediate_path_contribution_survives_unrecognized_stops();
    expect_collector_arp_flow_finalization_preserves_committed_path();
    expect_collector_recognized_flow_finalization_populates_terminal_metadata();
    expect_collector_direct_ipv4_has_empty_non_terminal_context();
    expect_collector_direct_ipv6_has_empty_non_terminal_context();
    expect_collector_ipv4_to_ipv4_promotes_outer_only();
    expect_collector_ipv4_to_ipv6_promotes_ipv4_outer();
    expect_collector_ipv6_to_ipv4_promotes_ipv6_outer();
    expect_collector_ipv6_to_ipv6_promotes_outer_only();
    expect_collector_three_ipv4_levels_preserve_outer_to_inner_order();
    expect_collector_mixed_three_levels_preserve_family_and_order();
    expect_collector_does_not_guess_inner_ip_when_no_inner_ip_fact_is_emitted();
    expect_collector_non_terminal_context_overflow_is_recorded_but_dormant();
}

}  // namespace pfl::tests::common_direct_test
