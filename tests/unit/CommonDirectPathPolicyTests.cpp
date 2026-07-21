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

DissectionStep make_ipv4_step(
    const std::uint8_t protocol,
    const std::uint32_t src_addr,
    const std::uint32_t dst_addr,
    const PathCommitPolicy path_commit_policy = PathCommitPolicy::immediate
) {
    return DissectionStep {
        .layer = DissectionLayerKind::ipv4,
        .path_contribution = LayerKey::ipv4(),
        .path_commit_policy = path_commit_policy,
        .facts = Ipv4Facts {
            .protocol = protocol,
            .src_addr_v4 = src_addr,
            .dst_addr_v4 = dst_addr,
        },
        .status = ParseStatus::complete,
        .stop_reason = StopReason::none,
    };
}

DissectionStep make_udp_terminal_step(
    const std::uint16_t src_port,
    const std::uint16_t dst_port,
    const PathCommitPolicy path_commit_policy = PathCommitPolicy::immediate
) {
    return DissectionStep {
        .layer = DissectionLayerKind::udp,
        .path_contribution = LayerKey::udp(),
        .path_commit_policy = path_commit_policy,
        .facts = UdpFacts {
            .src_port = src_port,
            .dst_port = dst_port,
        },
        .terminal_disposition = TerminalDisposition::flow_candidate,
        .status = ParseStatus::complete,
        .stop_reason = StopReason::terminal_protocol,
    };
}

DissectionStep make_arp_terminal_step(
    const std::uint32_t sender_ipv4,
    const std::uint32_t target_ipv4,
    const std::optional<LayerKey>& path_contribution = std::nullopt
) {
    return DissectionStep {
        .layer = DissectionLayerKind::arp,
        .path_contribution = path_contribution,
        .facts = ArpFacts {
            .has_sender_ipv4 = true,
            .has_target_ipv4 = true,
            .sender_ipv4 = sender_ipv4,
            .target_ipv4 = target_ipv4,
        },
        .terminal_disposition = TerminalDisposition::recognized_non_flow,
        .status = ParseStatus::complete,
        .stop_reason = StopReason::terminal_protocol,
    };
}

void expect_path_policy_combination_algebra() {
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
}

void expect_deferrable_paths_remain_uncommitted_on_truncation() {
    {
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
        collector.finish(make_test_result(StopReason::truncated, 2U));

        PFL_EXPECT(collector.facts().outcome == ImportDissectionOutcome::unrecognized);
        PFL_EXPECT(format_shadow_path(collector.facts()).empty());
    }

    {
        ImportDissectionCollector collector {};
        collector.consume(make_path_step(
            DissectionLayerKind::ieee8023,
            LayerKey::ieee8023(),
            PathCommitPolicy::recognized_flow,
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
        collector.finish(make_test_result(StopReason::truncated, 2U));

        PFL_EXPECT(collector.facts().outcome == ImportDissectionOutcome::unrecognized);
        PFL_EXPECT(format_shadow_path(collector.facts()).empty());
    }
}

void expect_descendant_policy_cannot_weaken_parent_non_flow_commit() {
    ImportDissectionCollector collector {};
    collector.consume(make_path_step(
        DissectionLayerKind::ethernet_ii,
        LayerKey::ethernet_ii()
    ));
    collector.consume(make_path_step(
        DissectionLayerKind::pppoe,
        LayerKey::pppoe(),
        PathCommitPolicy::recognized_flow,
        PathCommitPolicy::recognized_flow
    ));
    collector.consume(make_path_step(
        DissectionLayerKind::ppp,
        LayerKey::ppp(),
        PathCommitPolicy::recognized_flow_or_recognized_non_flow,
        PathCommitPolicy::recognized_flow_or_recognized_non_flow
    ));
    collector.consume(make_arp_terminal_step(
        ipv4(198, 51, 100, 10),
        ipv4(198, 51, 100, 1),
        LayerKey::arp()
    ));
    collector.finish(make_test_result(StopReason::terminal_protocol, 4U));

    PFL_EXPECT(collector.facts().outcome == ImportDissectionOutcome::recognized_non_flow);
    PFL_EXPECT(format_shadow_path(collector.facts()) == "EthernetII");
}

void expect_intermediate_non_flow_policy_can_commit_nested_path() {
    {
        ImportDissectionCollector collector {};
        collector.consume(make_path_step(
            DissectionLayerKind::ethernet_ii,
            LayerKey::ethernet_ii()
        ));
        collector.consume(make_path_step(
            DissectionLayerKind::linux_sll,
            LayerKey::linux_sll(),
            PathCommitPolicy::recognized_flow_or_recognized_non_flow,
            PathCommitPolicy::recognized_flow_or_recognized_non_flow
        ));
        collector.consume(make_path_step(
            DissectionLayerKind::pppoe,
            LayerKey::pppoe(),
            PathCommitPolicy::recognized_flow,
            PathCommitPolicy::recognized_flow
        ));
        collector.consume(make_arp_terminal_step(
            ipv4(198, 51, 100, 20),
            ipv4(198, 51, 100, 1),
            LayerKey::arp()
        ));
        collector.finish(make_test_result(StopReason::terminal_protocol, 4U));

        PFL_EXPECT(collector.facts().outcome == ImportDissectionOutcome::recognized_non_flow);
        PFL_EXPECT(format_shadow_path(collector.facts()) == "EthernetII -> LinuxSll");
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
            PathCommitPolicy::recognized_flow_or_recognized_non_flow,
            PathCommitPolicy::recognized_flow_or_recognized_non_flow
        ));
        collector.consume(make_path_step(
            DissectionLayerKind::ppp,
            LayerKey::ppp(),
            PathCommitPolicy::recognized_flow,
            PathCommitPolicy::recognized_flow
        ));
        collector.consume(make_arp_terminal_step(
            ipv4(203, 0, 113, 10),
            ipv4(203, 0, 113, 1),
            LayerKey::arp()
        ));
        collector.finish(make_test_result(StopReason::terminal_protocol, 4U));

        PFL_EXPECT(collector.facts().outcome == ImportDissectionOutcome::recognized_non_flow);
        PFL_EXPECT(format_shadow_path(collector.facts()) == "EthernetII -> PPPoE");
    }
}

void expect_descendant_flow_policy_alone_does_not_commit_non_flow_parent_path() {
    ImportDissectionCollector collector {};
    collector.consume(make_path_step(
        DissectionLayerKind::ethernet_ii,
        LayerKey::ethernet_ii()
    ));
    collector.consume(make_path_step(
        DissectionLayerKind::pppoe,
        LayerKey::pppoe(),
        PathCommitPolicy::immediate,
        PathCommitPolicy::recognized_flow
    ));
    collector.consume(make_path_step(
        DissectionLayerKind::ipv4,
        LayerKey::ipv4()
    ));
    collector.consume(make_arp_terminal_step(
        ipv4(203, 0, 113, 30),
        ipv4(203, 0, 113, 1),
        LayerKey::arp()
    ));
    collector.finish(make_test_result(StopReason::terminal_protocol, 4U));

    PFL_EXPECT(collector.facts().outcome == ImportDissectionOutcome::recognized_non_flow);
    PFL_EXPECT(format_shadow_path(collector.facts()) == "EthernetII");
}

void expect_recognized_flow_commits_deferred_parent_path() {
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
        PathCommitPolicy::recognized_flow,
        std::nullopt,
        false,
        true
    ));
    collector.consume(make_ipv4_step(
        detail::kIpProtocolUdp,
        ipv4(192, 0, 2, 40),
        ipv4(198, 51, 100, 40),
        PathCommitPolicy::recognized_flow_or_recognized_non_flow
    ));
    collector.consume(make_udp_terminal_step(
        1234U,
        5678U,
        PathCommitPolicy::recognized_flow_or_recognized_non_flow
    ));
    collector.finish(make_test_result(StopReason::terminal_protocol, 4U));

    PFL_EXPECT(collector.facts().outcome == ImportDissectionOutcome::recognized_flow);
    PFL_EXPECT(format_shadow_path(collector.facts()) == "IEEE 802.3 -> LLC/SNAP -> IPv4 -> UDP");
}

}  // namespace

void run_common_direct_path_policy_tests() {
    expect_path_policy_combination_algebra();
    expect_deferrable_paths_remain_uncommitted_on_truncation();
    expect_descendant_policy_cannot_weaken_parent_non_flow_commit();
    expect_intermediate_non_flow_policy_can_commit_nested_path();
    expect_descendant_flow_policy_alone_does_not_commit_non_flow_parent_path();
    expect_recognized_flow_commits_deferred_parent_path();
}

}  // namespace pfl::tests::common_direct_test
