#include "CommonDirectDissectionTestSupport.h"
#include "core/dissection/modules/CommonDirectModules.h"

namespace pfl::tests::common_direct_test {

using namespace dissection;


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


void expect_linux_cooked_shadow_root_parsers_and_fixture_parity() {
    const auto built = make_common_direct_registry();
    PFL_REQUIRE(built.ok());
    const auto& registry = *built.registry;

    {
        const auto root = make_declared_root_slice(
            {
                0x12U, 0x34U,
                0x34U, 0x56U,
                0x00U, 0x06U,
                0x10U, 0x20U, 0x30U, 0x40U, 0x50U, 0x60U, 0x70U, 0x80U,
                0x08U, 0x00U,
            },
            detail::kLinuxSllHeaderSize
        );
        const auto parsed = parse_linux_sll_frame(root);
        PFL_EXPECT(parsed.status == ParseStatus::complete);
        PFL_EXPECT(!parsed.is_sll2);
        PFL_EXPECT(parsed.protocol_type == detail::kEtherTypeIpv4);
        PFL_EXPECT(parsed.packet_type == 0x1234U);
        PFL_EXPECT(parsed.hardware_type == 0x3456U);
        PFL_EXPECT(parsed.address_length == 6U);
        PFL_EXPECT(parsed.header_length == detail::kLinuxSllHeaderSize);
        PFL_EXPECT(parsed.declared_payload_length == 0U);

        const auto step = dissect_linux_sll(root);
        PFL_EXPECT(step.layer == DissectionLayerKind::linux_sll);
        PFL_REQUIRE(step.path_contribution.has_value());
        PFL_EXPECT(*step.path_contribution == LayerKey::linux_sll());
        PFL_EXPECT(step.path_commit_policy == PathCommitPolicy::recognized_flow_or_recognized_non_flow);
        PFL_REQUIRE(step.handoff.has_value());
        PFL_REQUIRE(step.handoff->child.has_value());
        PFL_EXPECT(step.handoff->selector.domain == SelectorDomain::linux_cooked_protocol);
        PFL_EXPECT(step.handoff->selector.value == detail::kEtherTypeIpv4);
        PFL_EXPECT(step.status == ParseStatus::complete);
        PFL_EXPECT(step.stop_reason == StopReason::none);
        PFL_EXPECT(step.bounds.full.declared.length() == detail::kLinuxSllHeaderSize);
        PFL_EXPECT(step.bounds.header.declared.length() == detail::kLinuxSllHeaderSize);
        PFL_REQUIRE(step.bounds.payload.has_value());
        PFL_EXPECT(step.bounds.payload->declared.length() == 0U);
        PFL_EXPECT(step.bounds.payload->captured.length() == 0U);
        PFL_EXPECT(std::holds_alternative<LinuxCookedFacts>(step.facts));
        const auto* facts = std::get_if<LinuxCookedFacts>(&step.facts);
        PFL_REQUIRE(facts != nullptr);
        PFL_EXPECT(!facts->is_sll2);
        PFL_EXPECT(facts->protocol_type == detail::kEtherTypeIpv4);
        PFL_EXPECT(facts->packet_type == 0x1234U);
        PFL_EXPECT(facts->hardware_type == 0x3456U);
        PFL_EXPECT(facts->address_length == 6U);
    }

    {
        const auto root = make_declared_root_slice(
            {
                0x86U, 0xddU,
                0x00U, 0x00U,
                0x10U, 0x20U, 0x30U, 0x40U,
                0x12U, 0x34U,
                0x11U,
                0x08U,
                0x31U, 0x32U, 0x33U, 0x34U, 0x35U, 0x36U, 0x37U, 0x38U,
            },
            detail::kLinuxSll2HeaderSize
        );
        const auto parsed = parse_linux_sll2_frame(root);
        PFL_EXPECT(parsed.status == ParseStatus::complete);
        PFL_EXPECT(parsed.is_sll2);
        PFL_EXPECT(parsed.protocol_type == detail::kEtherTypeIpv6);
        PFL_EXPECT(parsed.packet_type == 0x11U);
        PFL_EXPECT(parsed.hardware_type == 0x1234U);
        PFL_EXPECT(parsed.address_length == 8U);
        PFL_EXPECT(parsed.reserved == 0U);
        PFL_EXPECT(parsed.interface_index == 0x10203040U);
        PFL_EXPECT(parsed.header_length == detail::kLinuxSll2HeaderSize);
        PFL_EXPECT(parsed.declared_payload_length == 0U);

        const auto step = dissect_linux_sll2(root);
        PFL_EXPECT(step.layer == DissectionLayerKind::linux_sll2);
        PFL_REQUIRE(step.path_contribution.has_value());
        PFL_EXPECT(*step.path_contribution == LayerKey::linux_sll2());
        PFL_EXPECT(step.path_commit_policy == PathCommitPolicy::recognized_flow_or_recognized_non_flow);
        PFL_REQUIRE(step.handoff.has_value());
        PFL_REQUIRE(step.handoff->child.has_value());
        PFL_EXPECT(step.handoff->selector.domain == SelectorDomain::linux_cooked_protocol);
        PFL_EXPECT(step.handoff->selector.value == detail::kEtherTypeIpv6);
        PFL_EXPECT(std::holds_alternative<LinuxCookedFacts>(step.facts));
        const auto* facts = std::get_if<LinuxCookedFacts>(&step.facts);
        PFL_REQUIRE(facts != nullptr);
        PFL_EXPECT(facts->is_sll2);
        PFL_EXPECT(facts->interface_index == 0x10203040U);
        PFL_EXPECT(facts->reserved == 0U);
        PFL_EXPECT(facts->packet_type == 0x11U);
        PFL_EXPECT(facts->address_length == 8U);
    }

    {
        const auto truncated_root = make_declared_root_slice(
            {0x12U, 0x34U, 0x34U, 0x56U, 0x00U, 0x06U, 0x10U, 0x20U},
            8U
        );
        const auto parsed = parse_linux_sll_frame(truncated_root);
        PFL_EXPECT(parsed.status == ParseStatus::truncated);
        const auto step = dissect_linux_sll(truncated_root);
        PFL_EXPECT(step.layer == DissectionLayerKind::linux_sll);
        PFL_EXPECT(step.status == ParseStatus::truncated);
        PFL_EXPECT(step.stop_reason == StopReason::truncated);
        PFL_EXPECT(!step.path_contribution.has_value());
        PFL_EXPECT(!step.handoff.has_value());
        PFL_EXPECT(step.bounds.full.declared.length() == 8U);
        PFL_EXPECT(step.bounds.header.declared.length() == 8U);
    }

    {
        const auto arp_slice = make_declared_root_slice(
            {
                0x00U, 0x01U, 0x08U, 0x00U, 0x06U, 0x04U, 0x00U, 0x01U,
                0x00U, 0x11U, 0x22U, 0x33U, 0x44U, 0x55U,
                0xc0U, 0x00U, 0x02U, 0x0aU,
                0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
                0xc0U, 0x00U, 0x02U, 0x01U,
            },
            28U
        );
        const auto step = dissect_linux_cooked_arp(arp_slice);
        PFL_EXPECT(step.layer == DissectionLayerKind::arp);
        PFL_EXPECT(step.status == ParseStatus::complete);
        PFL_EXPECT(step.stop_reason == StopReason::terminal_protocol);
        PFL_EXPECT(!step.path_contribution.has_value());
        PFL_EXPECT(!step.handoff.has_value());
        PFL_EXPECT(step.terminal_disposition == TerminalDisposition::flow_candidate);
        PFL_EXPECT(std::holds_alternative<ArpFacts>(step.facts));
    }

    const std::vector<std::pair<const char*, const char*>> supported_flow_expectations {
        {"parsing/linux_cooked/01_sll_ipv4_tcp.pcap", "LinuxSll -> IPv4 -> TCP"},
        {"parsing/linux_cooked/02_sll_ipv6_udp.pcap", "LinuxSll -> IPv6 -> UDP"},
        {"parsing/linux_cooked/05_sll2_ipv4_tcp.pcap", "LinuxSll2 -> IPv4 -> TCP"},
        {"parsing/linux_cooked/06_sll2_ipv6_udp.pcap", "LinuxSll2 -> IPv6 -> UDP"},
        {"parsing/linux_cooked/15_sll_addrlen_8_ipv4_udp.pcap", "LinuxSll -> IPv4 -> UDP"},
        {"parsing/linux_cooked/16_sll_addrlen_12_ipv4_tcp.pcap", "LinuxSll -> IPv4 -> TCP"},
        {"parsing/linux_cooked/17_sll2_addrlen_8_ipv4_udp.pcap", "LinuxSll2 -> IPv4 -> UDP"},
        {"parsing/linux_cooked/18_sll2_addrlen_12_ipv6_udp.pcap", "LinuxSll2 -> IPv6 -> UDP"},
    };

    for (const auto& expectation : supported_flow_expectations) {
        expect_shadow_matches_legacy_flow(
            registry,
            require_raw_fixture_packet(expectation.first),
            expectation.second,
            StopReason::terminal_protocol
        );
    }

    expect_shadow_matches_legacy_arp_flow(
        registry,
        require_raw_fixture_packet("parsing/linux_cooked/03_sll_arp.pcap"),
        "LinuxSll",
        StopReason::terminal_protocol
    );
    expect_shadow_matches_legacy_arp_flow(
        registry,
        require_raw_fixture_packet("parsing/linux_cooked/07_sll2_arp.pcap"),
        "LinuxSll2",
        StopReason::terminal_protocol
    );

    struct UnsupportedExpectation {
        const char* relative_path;
        StopReason expected_stop_reason;
    };

    const std::vector<UnsupportedExpectation> unsupported_expectations {
        {"parsing/linux_cooked/04_sll_vlan_ipv4_udp_unsupported.pcap", StopReason::unknown_next_protocol},
        {"parsing/linux_cooked/08_sll2_vlan_ipv6_tcp_unsupported.pcap", StopReason::unknown_next_protocol},
        {"parsing/linux_cooked/09_sll_truncated_header.pcap", StopReason::truncated},
        {"parsing/linux_cooked/10_sll2_truncated_header.pcap", StopReason::truncated},
        {"parsing/linux_cooked/11_sll_unknown_protocol.pcap", StopReason::unknown_next_protocol},
        {"parsing/linux_cooked/12_sll2_unknown_protocol.pcap", StopReason::unknown_next_protocol},
        {"parsing/linux_cooked/13_sll_truncated_inner_ipv4.pcap", StopReason::truncated},
        {"parsing/linux_cooked/14_sll2_truncated_inner_ipv6.pcap", StopReason::truncated},
    };

    for (const auto& expectation : unsupported_expectations) {
        const auto packet = require_raw_fixture_packet(expectation.relative_path);
        const auto legacy = decode_legacy_direct(packet);
        const auto shadow = run_shadow(packet, registry);
        PFL_EXPECT(!legacy.recognized_flow);
        PFL_EXPECT(shadow.outcome == ImportDissectionOutcome::unrecognized);
        PFL_EXPECT(shadow.stop_reason == expectation.expected_stop_reason);
        PFL_EXPECT(format_shadow_path(shadow).empty());
        PFL_EXPECT(!shadow.has_ports);
        PFL_EXPECT(!shadow.has_transport_payload_length);
        PFL_EXPECT(!shadow.has_tcp_flags);
    }
}

void expect_llc_snap_shadow_parsers_bounds_and_fixture_parity() {
    const auto built = make_common_direct_registry();
    PFL_REQUIRE(built.ok());
    const auto& registry = *built.registry;

    {
        const auto exact_header_slice = make_declared_root_slice(
            {0xaaU, 0xaaU, 0x03U, 0x00U, 0x00U, 0x00U, 0x08U, 0x00U},
            8U
        );
        const auto parsed = parse_llc_snap_payload(exact_header_slice);
        PFL_EXPECT(parsed.status == ParseStatus::complete);
        PFL_EXPECT(parsed.dsap == 0xaaU);
        PFL_EXPECT(parsed.ssap == 0xaaU);
        PFL_EXPECT(parsed.control == 0x03U);
        PFL_EXPECT(parsed.has_snap);
        PFL_EXPECT(parsed.oui == 0U);
        PFL_EXPECT(parsed.pid == detail::kEtherTypeIpv4);
        PFL_EXPECT(parsed.pid_supported);
        PFL_EXPECT(parsed.header_length == detail::kLlcSnapHeaderSize);

        const auto step = dissect_llc_snap(exact_header_slice);
        PFL_EXPECT(step.layer == DissectionLayerKind::llc_snap);
        PFL_REQUIRE(step.path_contribution.has_value());
        PFL_EXPECT(*step.path_contribution == LayerKey::llc_snap());
        PFL_EXPECT(step.path_commit_policy == PathCommitPolicy::recognized_flow_or_recognized_non_flow);
        PFL_REQUIRE(step.descendant_path_commit_policy.has_value());
        PFL_EXPECT(*step.descendant_path_commit_policy == PathCommitPolicy::recognized_flow_or_recognized_non_flow);
        PFL_EXPECT(step.defer_last_deferrable_path_contribution);
        PFL_REQUIRE(step.handoff.has_value());
        PFL_REQUIRE(step.handoff->child.has_value());
        PFL_EXPECT(step.handoff->selector.domain == SelectorDomain::llc_snap_pid);
        PFL_EXPECT(step.handoff->selector.value == detail::kEtherTypeIpv4);
        PFL_EXPECT(step.status == ParseStatus::complete);
        PFL_EXPECT(step.stop_reason == StopReason::none);
        PFL_EXPECT(step.bounds.full.declared.length() == 8U);
        PFL_EXPECT(step.bounds.full.captured.length() == 8U);
        PFL_EXPECT(step.bounds.header.declared.length() == 8U);
        PFL_EXPECT(step.bounds.header.captured.length() == 8U);
        PFL_REQUIRE(step.bounds.payload.has_value());
        PFL_EXPECT(step.bounds.payload->declared.length() == 0U);
        PFL_EXPECT(step.bounds.payload->captured.length() == 0U);
        PFL_EXPECT(std::holds_alternative<LlcSnapFacts>(step.facts));
        const auto* facts = std::get_if<LlcSnapFacts>(&step.facts);
        PFL_REQUIRE(facts != nullptr);
        PFL_EXPECT(facts->dsap == 0xaaU);
        PFL_EXPECT(facts->ssap == 0xaaU);
        PFL_EXPECT(facts->control == 0x03U);
        PFL_EXPECT(facts->has_snap);
        PFL_EXPECT(facts->oui == 0U);
        PFL_EXPECT(facts->pid == detail::kEtherTypeIpv4);
    }

    {
        const auto nonzero_oui_slice = make_declared_root_slice(
            {0xaaU, 0xaaU, 0x03U, 0x00U, 0x00U, 0xf8U, 0x08U, 0x00U},
            8U
        );
        const auto parsed = parse_llc_snap_payload(nonzero_oui_slice);
        PFL_EXPECT(parsed.status == ParseStatus::complete);
        PFL_EXPECT(parsed.has_snap);
        PFL_EXPECT(parsed.oui == 0x0000f8U);
        PFL_EXPECT(parsed.pid == detail::kEtherTypeIpv4);
        PFL_EXPECT(parsed.pid_supported);
    }

    {
        const auto unknown_pid_slice = make_declared_root_slice(
            {0xaaU, 0xaaU, 0x03U, 0x00U, 0x00U, 0x00U, 0x12U, 0x34U},
            8U
        );
        const auto parsed = parse_llc_snap_payload(unknown_pid_slice);
        PFL_EXPECT(parsed.status == ParseStatus::complete);
        PFL_EXPECT(parsed.has_snap);
        PFL_EXPECT(parsed.pid == 0x1234U);
        PFL_EXPECT(!parsed.pid_supported);

        const auto step = dissect_llc_snap(unknown_pid_slice);
        PFL_EXPECT(step.status == ParseStatus::complete);
        PFL_EXPECT(step.stop_reason == StopReason::unrecognized_payload);
        PFL_EXPECT(!step.path_contribution.has_value());
        PFL_EXPECT(!step.handoff.has_value());
    }

    {
        const auto dsap_only_slice = make_declared_root_slice({0xaaU}, 1U);
        const auto parsed = parse_llc_snap_payload(dsap_only_slice);
        PFL_EXPECT(parsed.status == ParseStatus::truncated);
        PFL_EXPECT(parsed.dsap == 0xaaU);
        PFL_EXPECT(parsed.header_length == 1U);
        const auto step = dissect_llc_snap(dsap_only_slice);
        PFL_EXPECT(step.status == ParseStatus::truncated);
        PFL_EXPECT(step.stop_reason == StopReason::truncated);
        PFL_EXPECT(!step.path_contribution.has_value());
    }

    {
        const auto dsap_ssap_slice = make_declared_root_slice({0xaaU, 0xaaU}, 2U);
        const auto parsed = parse_llc_snap_payload(dsap_ssap_slice);
        PFL_EXPECT(parsed.status == ParseStatus::truncated);
        PFL_EXPECT(parsed.dsap == 0xaaU);
        PFL_EXPECT(parsed.ssap == 0xaaU);
        PFL_EXPECT(parsed.header_length == 2U);
    }

    {
        const auto nonsnap_slice = make_declared_root_slice(
            {0xaaU, 0xaaU, 0x00U, 0x00U, 0x00U, 0x00U, 0x08U, 0x00U},
            8U
        );
        const auto parsed = parse_llc_snap_payload(nonsnap_slice);
        PFL_EXPECT(parsed.status == ParseStatus::complete);
        PFL_EXPECT(!parsed.has_snap);
        PFL_EXPECT(parsed.header_length == detail::kLlcHeaderSize);
        const auto step = dissect_llc_snap(nonsnap_slice);
        PFL_EXPECT(step.status == ParseStatus::complete);
        PFL_EXPECT(step.stop_reason == StopReason::unrecognized_payload);
        PFL_EXPECT(!step.path_contribution.has_value());
        PFL_EXPECT(step.bounds.full.declared.length() == detail::kLlcHeaderSize);
        PFL_EXPECT(step.bounds.header.declared.length() == detail::kLlcHeaderSize);
    }

    {
        const auto truncated_oui_slice = make_declared_root_slice({0xaaU, 0xaaU, 0x03U, 0x00U}, 4U);
        const auto parsed = parse_llc_snap_payload(truncated_oui_slice);
        PFL_EXPECT(parsed.status == ParseStatus::truncated);
        PFL_EXPECT(parsed.header_length == 4U);
        const auto truncated_pid_slice = make_declared_root_slice(
            {0xaaU, 0xaaU, 0x03U, 0x00U, 0x00U, 0x00U, 0x08U},
            7U
        );
        const auto truncated_pid = parse_llc_snap_payload(truncated_pid_slice);
        PFL_EXPECT(truncated_pid.status == ParseStatus::truncated);
        PFL_EXPECT(truncated_pid.header_length == 7U);
    }

    struct SupportedFlowExpectation {
        const char* relative_path;
        const char* expected_path;
        StopReason expected_stop_reason;
        bool is_arp_flow;
    };

    const std::vector<SupportedFlowExpectation> supported_expectations {
        {"parsing/llc_snap/01_llc_snap_ipv4_tcp.pcap", "IEEE 802.3 -> LLC/SNAP -> IPv4 -> TCP", StopReason::terminal_protocol, false},
        {"parsing/llc_snap/02_llc_snap_ipv4_udp.pcap", "IEEE 802.3 -> LLC/SNAP -> IPv4 -> UDP", StopReason::terminal_protocol, false},
        {"parsing/llc_snap/03_llc_snap_ipv6_tcp.pcap", "IEEE 802.3 -> LLC/SNAP -> IPv6 -> TCP", StopReason::terminal_protocol, false},
        {"parsing/llc_snap/04_llc_snap_ipv6_udp.pcap", "IEEE 802.3 -> LLC/SNAP -> IPv6 -> UDP", StopReason::terminal_protocol, false},
        {"parsing/llc_snap/05_llc_snap_arp.pcap", "IEEE 802.3 -> LLC/SNAP", StopReason::terminal_protocol, true},
        {"parsing/llc_snap/06_vlan_llc_snap_ipv4_tcp.pcap", "EthernetII -> VLAN(vid=100) -> LLC/SNAP -> IPv4 -> TCP", StopReason::terminal_protocol, false},
        {"parsing/llc_snap/07_qinq_llc_snap_ipv4_udp.pcap", "EthernetII -> VLAN(vid=200) -> VLAN(vid=300) -> LLC/SNAP -> IPv4 -> UDP", StopReason::terminal_protocol, false},
        {"parsing/llc_snap/09_llc_snap_nonzero_oui_ipv4_pid.pcap", "IEEE 802.3 -> LLC/SNAP -> IPv4 -> UDP", StopReason::terminal_protocol, false},
        {"parsing/llc_snap/14_llc_snap_length_short_payload.pcap", "IEEE 802.3 -> LLC/SNAP -> IPv4 -> UDP", StopReason::terminal_protocol, false},
        {"parsing/llc_snap/20_llc_snap_padding_after_declared_payload.pcap", "IEEE 802.3 -> LLC/SNAP -> IPv4 -> UDP", StopReason::terminal_protocol, false},
        {"parsing/llc_snap/23_vlan_9100_llc_snap_ipv4_udp.pcap", "EthernetII -> VLAN(vid=413) -> LLC/SNAP -> IPv4 -> UDP", StopReason::terminal_protocol, false},
    };

    for (const auto& expectation : supported_expectations) {
        const auto packet = require_raw_fixture_packet(expectation.relative_path);
        if (expectation.is_arp_flow) {
            expect_shadow_matches_legacy_arp_flow(
                registry,
                packet,
                expectation.expected_path,
                expectation.expected_stop_reason
            );
        } else {
            expect_shadow_matches_legacy_flow(
                registry,
                packet,
                expectation.expected_path,
                expectation.expected_stop_reason
            );
        }
    }

    {
        const auto packet = require_raw_fixture_packet("parsing/llc_snap/20_llc_snap_padding_after_declared_payload.pcap");
        const auto root = make_root_slice(packet);
        const auto ethernet_step = dissect_ethernet(root);
        PFL_REQUIRE(ethernet_step.handoff.has_value());
        PFL_REQUIRE(ethernet_step.handoff->child.has_value());
        const auto& ieee8023_child = *ethernet_step.handoff->child;
        PFL_EXPECT(ieee8023_child.declared_end() < root.captured_end());
        const auto llc_snap_step = dissect_llc_snap(ieee8023_child);
        PFL_REQUIRE(llc_snap_step.bounds.payload.has_value());
        PFL_EXPECT(llc_snap_step.bounds.payload->declared.end() == ieee8023_child.declared_end());
        PFL_EXPECT(llc_snap_step.bounds.payload->captured.end() == ieee8023_child.captured_end());
    }

    struct UnsupportedFixtureExpectation {
        const char* relative_path;
        const char* expected_shadow_path;
        StopReason expected_stop_reason;
    };

    const std::vector<UnsupportedFixtureExpectation> unsupported_expectations {
        {"parsing/llc_snap/08_llc_snap_unknown_pid.pcap", "IEEE 802.3", StopReason::unrecognized_payload},
        {"parsing/llc_snap/10_llc_non_snap_ipx_like.pcap", "IEEE 802.3", StopReason::unrecognized_payload},
        {"parsing/llc_snap/11_llc_snap_truncated_llc_header.pcap", "", StopReason::malformed},
        {"parsing/llc_snap/12_llc_snap_truncated_snap_header.pcap", "", StopReason::malformed},
        {"parsing/llc_snap/13_llc_snap_truncated_inner_ipv4.pcap", "", StopReason::truncated},
        {"parsing/llc_snap/15_llc_snap_length_extra_payload.pcap", "", StopReason::malformed},
        {"parsing/llc_snap/16_llc_truncated_dsap_only.pcap", "IEEE 802.3", StopReason::truncated},
        {"parsing/llc_snap/17_llc_truncated_dsap_ssap.pcap", "IEEE 802.3", StopReason::truncated},
        {"parsing/llc_snap/18_llc_non_snap_control.pcap", "IEEE 802.3", StopReason::unrecognized_payload},
        {"parsing/llc_snap/19_llc_snap_declared_short_with_captured_tail.pcap", "IEEE 802.3", StopReason::truncated},
        {"parsing/llc_snap/21_llc_snap_truncated_inner_ipv6.pcap", "", StopReason::malformed},
        {"parsing/llc_snap/22_llc_snap_truncated_inner_arp.pcap", "", StopReason::truncated},
    };

    for (const auto& expectation : unsupported_expectations) {
        const auto packet = require_raw_fixture_packet(expectation.relative_path);
        const auto legacy = decode_legacy_direct(packet);
        const auto shadow = run_shadow(packet, registry);
        PFL_EXPECT(!legacy.recognized_flow);
        PFL_EXPECT(shadow.outcome == ImportDissectionOutcome::unrecognized);
        PFL_EXPECT(shadow.stop_reason == expectation.expected_stop_reason);
        PFL_EXPECT(format_shadow_path(shadow) == expectation.expected_shadow_path);
        PFL_EXPECT(!shadow.has_ports);
        PFL_EXPECT(!shadow.has_transport_payload_length);
        PFL_EXPECT(!shadow.has_tcp_flags);
    }
}

void expect_pppoe_ppp_shadow_parsers_bounds_and_fixture_parity() {
    const auto built = make_common_direct_registry();
    PFL_REQUIRE(built.ok());
    const auto& registry = *built.registry;

    {
        const auto supported_session_slice = make_declared_root_slice(
            {
                0x11U, 0x00U, 0x12U, 0x34U, 0x00U, 0x04U,
                0x00U, 0x21U, 0xaaU, 0xbbU,
            },
            10U
        );
        const auto parsed = parse_pppoe_frame(supported_session_slice, false);
        PFL_EXPECT(parsed.status == ParseStatus::complete);
        PFL_EXPECT(parsed.version == 1U);
        PFL_EXPECT(parsed.type == 1U);
        PFL_EXPECT(parsed.code == 0U);
        PFL_EXPECT(parsed.session_id == 0x1234U);
        PFL_EXPECT(parsed.payload_length == 4U);
        PFL_EXPECT(parsed.header_length == detail::kPppoeHeaderSize);
        PFL_EXPECT(parsed.declared_payload_length == 4U);
        PFL_EXPECT(parsed.logical_payload_length == 4U);
        PFL_EXPECT(!parsed.declared_payload_exceeds_capture);
        PFL_EXPECT(!parsed.captured_payload_exceeds_declared);

        const auto step = dissect_pppoe_session(supported_session_slice);
        PFL_EXPECT(step.layer == DissectionLayerKind::pppoe);
        PFL_REQUIRE(step.path_contribution.has_value());
        PFL_EXPECT(*step.path_contribution == LayerKey::pppoe());
        PFL_EXPECT(step.path_commit_policy == PathCommitPolicy::recognized_flow);
        PFL_REQUIRE(step.descendant_path_commit_policy.has_value());
        PFL_EXPECT(*step.descendant_path_commit_policy == PathCommitPolicy::recognized_flow);
        PFL_REQUIRE(step.handoff.has_value());
        PFL_REQUIRE(step.handoff->child.has_value());
        PFL_EXPECT(step.handoff->selector.domain == SelectorDomain::ppp_frame);
        PFL_EXPECT(step.handoff->selector.value == kPppFrameContinueSelectorValue);
        PFL_EXPECT(step.status == ParseStatus::complete);
        PFL_EXPECT(step.stop_reason == StopReason::none);
        PFL_EXPECT(step.bounds.full.declared.length() == 10U);
        PFL_EXPECT(step.bounds.header.declared.length() == 6U);
        PFL_REQUIRE(step.bounds.payload.has_value());
        PFL_EXPECT(step.bounds.payload->declared.length() == 4U);
        PFL_EXPECT(step.bounds.payload->captured.length() == 4U);
        const auto* facts = std::get_if<PppoeFacts>(&step.facts);
        PFL_REQUIRE(facts != nullptr);
        PFL_EXPECT(facts->version == 1U);
        PFL_EXPECT(facts->type == 1U);
        PFL_EXPECT(facts->code == 0U);
        PFL_EXPECT(facts->session_id == 0x1234U);
        PFL_EXPECT(facts->payload_length == 4U);
        PFL_EXPECT(!facts->is_discovery);
    }

    {
        const auto discovery_slice = make_declared_root_slice(
            {
                0x11U, 0x09U, 0x00U, 0x00U, 0x00U, 0x03U,
                0x01U, 0x02U, 0x03U,
            },
            9U
        );
        const auto parsed = parse_pppoe_frame(discovery_slice, true);
        PFL_EXPECT(parsed.status == ParseStatus::complete);
        PFL_EXPECT(parsed.is_discovery);
        PFL_EXPECT(parsed.code == 0x09U);
        const auto step = dissect_pppoe_discovery(discovery_slice);
        PFL_EXPECT(step.layer == DissectionLayerKind::pppoe);
        PFL_EXPECT(!step.path_contribution.has_value());
        PFL_EXPECT(!step.handoff.has_value());
        PFL_EXPECT(step.status == ParseStatus::complete);
        PFL_EXPECT(step.stop_reason == StopReason::terminal_protocol);
        const auto* facts = std::get_if<PppoeFacts>(&step.facts);
        PFL_REQUIRE(facts != nullptr);
        PFL_EXPECT(facts->is_discovery);
        PFL_EXPECT(facts->payload_length == 3U);
    }

    {
        const auto unsupported_version_slice = make_declared_root_slice(
            {
                0x21U, 0x00U, 0x12U, 0x34U, 0x00U, 0x04U,
                0x00U, 0x21U, 0xaaU, 0xbbU,
            },
            10U
        );
        const auto step = dissect_pppoe_session(unsupported_version_slice);
        PFL_EXPECT(step.layer == DissectionLayerKind::pppoe);
        PFL_EXPECT(!step.path_contribution.has_value());
        PFL_EXPECT(!step.handoff.has_value());
        PFL_EXPECT(step.status == ParseStatus::unsupported_variant);
        PFL_EXPECT(step.stop_reason == StopReason::unsupported_variant);
    }

    {
        const auto declared_shorter_slice = make_declared_root_slice(
            {
                0x11U, 0x00U, 0x00U, 0x00U, 0x00U, 0x04U,
                0x00U, 0x57U, 0xaaU, 0xbbU, 0xccU, 0xddU,
            },
            12U
        );
        const auto parsed = parse_pppoe_frame(declared_shorter_slice, false);
        PFL_EXPECT(parsed.status == ParseStatus::complete);
        PFL_EXPECT(parsed.logical_payload_length == 4U);
        PFL_EXPECT(parsed.captured_payload_exceeds_declared);
        PFL_EXPECT(!parsed.declared_payload_exceeds_capture);

        const auto step = dissect_pppoe_session(declared_shorter_slice);
        PFL_REQUIRE(step.bounds.payload.has_value());
        PFL_EXPECT(step.bounds.full.declared.length() == 10U);
        PFL_EXPECT(step.bounds.full.captured.length() == 10U);
        PFL_EXPECT(step.bounds.payload->declared.length() == 4U);
        PFL_EXPECT(step.bounds.payload->captured.length() == 4U);
    }

    {
        const auto declared_longer_slice = make_declared_root_slice(
            {
                0x11U, 0x00U, 0x12U, 0x34U, 0x00U, 0x08U,
                0x00U, 0x21U, 0xaaU,
            },
            14U
        );
        const auto parsed = parse_pppoe_frame(declared_longer_slice, false);
        PFL_EXPECT(parsed.status == ParseStatus::complete);
        PFL_EXPECT(parsed.logical_payload_length == 3U);
        PFL_EXPECT(parsed.declared_payload_exceeds_capture);
        PFL_EXPECT(!parsed.captured_payload_exceeds_declared);

        const auto step = dissect_pppoe_session(declared_longer_slice);
        PFL_REQUIRE(step.bounds.payload.has_value());
        PFL_EXPECT(step.bounds.full.declared.length() == 14U);
        PFL_EXPECT(step.bounds.full.captured.length() == 9U);
        PFL_EXPECT(step.bounds.payload->declared.length() == 8U);
        PFL_EXPECT(step.bounds.payload->captured.length() == 3U);
    }

    {
        const auto zero_session_slice = make_declared_root_slice(
            {
                0x11U, 0x00U, 0x00U, 0x00U, 0x00U, 0x02U,
                0x00U, 0x21U,
            },
            8U
        );
        const auto parsed = parse_pppoe_frame(zero_session_slice, false);
        PFL_EXPECT(parsed.status == ParseStatus::complete);
        PFL_EXPECT(parsed.session_id == 0U);
    }

    {
        const auto ppp_ipv6_slice = make_declared_root_slice(
            {0x00U, 0x57U, 0xaaU, 0xbbU},
            4U
        );
        const auto parsed = parse_ppp_frame(ppp_ipv6_slice);
        PFL_EXPECT(parsed.status == ParseStatus::complete);
        PFL_EXPECT(parsed.protocol == detail::kPppProtocolIpv6);
        PFL_EXPECT(parsed.header_length == detail::kPppProtocolFieldSize);
        PFL_EXPECT(parsed.declared_payload_length == 2U);

        const auto step = dissect_ppp(ppp_ipv6_slice);
        PFL_EXPECT(step.layer == DissectionLayerKind::ppp);
        PFL_REQUIRE(step.path_contribution.has_value());
        PFL_EXPECT(*step.path_contribution == LayerKey::ppp());
        PFL_EXPECT(step.path_commit_policy == PathCommitPolicy::recognized_flow);
        PFL_REQUIRE(step.descendant_path_commit_policy.has_value());
        PFL_EXPECT(*step.descendant_path_commit_policy == PathCommitPolicy::recognized_flow);
        PFL_REQUIRE(step.handoff.has_value());
        PFL_EXPECT(step.handoff->selector.domain == SelectorDomain::ppp_protocol);
        PFL_EXPECT(step.handoff->selector.value == detail::kPppProtocolIpv6);
        PFL_REQUIRE(step.bounds.payload.has_value());
        PFL_EXPECT(step.bounds.payload->declared.length() == 2U);
        PFL_EXPECT(step.bounds.payload->captured.length() == 2U);
        const auto* facts = std::get_if<PppFacts>(&step.facts);
        PFL_REQUIRE(facts != nullptr);
        PFL_EXPECT(facts->protocol == detail::kPppProtocolIpv6);
    }

    {
        const auto ppp_short_slice = make_declared_root_slice({0x00U}, 1U);
        const auto parsed = parse_ppp_frame(ppp_short_slice);
        PFL_EXPECT(parsed.status == ParseStatus::truncated);
        const auto step = dissect_ppp(ppp_short_slice);
        PFL_EXPECT(step.layer == DissectionLayerKind::ppp);
        PFL_EXPECT(step.status == ParseStatus::truncated);
        PFL_EXPECT(step.stop_reason == StopReason::truncated);
        PFL_EXPECT(!step.path_contribution.has_value());
        PFL_EXPECT(!step.handoff.has_value());
    }

    {
        const auto control_slice = make_declared_root_slice({0x01U, 0x02U, 0x03U}, 3U);
        const auto step = dissect_ppp_control(control_slice);
        PFL_EXPECT(step.layer == DissectionLayerKind::ppp_control);
        PFL_EXPECT(step.status == ParseStatus::complete);
        PFL_EXPECT(step.stop_reason == StopReason::terminal_protocol);
        PFL_REQUIRE(step.bounds.payload.has_value());
        PFL_EXPECT(step.bounds.payload->declared.length() == 3U);
    }

    struct SupportedFlowExpectation {
        const char* relative_path;
        const char* expected_shadow_path;
    };

    const std::vector<SupportedFlowExpectation> supported_expectations {
        {"parsing/pppoe/01_pppoe_session_ipv4_tcp.pcap", "EthernetII -> PPPoE -> PPP -> IPv4 -> TCP"},
        {"parsing/pppoe/02_pppoe_session_ipv4_udp.pcap", "EthernetII -> PPPoE -> PPP -> IPv4 -> UDP"},
        {"parsing/pppoe/03_pppoe_session_ipv6_tcp.pcap", "EthernetII -> PPPoE -> PPP -> IPv6 -> TCP"},
        {"parsing/pppoe/04_pppoe_session_ipv6_udp.pcap", "EthernetII -> PPPoE -> PPP -> IPv6 -> UDP"},
        {"parsing/pppoe/13_vlan_pppoe_session_ipv4_tcp.pcap", "EthernetII -> VLAN(vid=130) -> PPPoE -> PPP -> IPv4 -> TCP"},
        {"parsing/pppoe/14_qinq_pppoe_session_ipv4_udp.pcap", "EthernetII -> VLAN(vid=230) -> VLAN(vid=231) -> PPPoE -> PPP -> IPv4 -> UDP"},
        {"parsing/pppoe/19_pppoe_bad_length_short_payload.pcap", "EthernetII -> PPPoE -> PPP -> IPv4 -> UDP"},
        {"parsing/pppoe/23_pppoe_session_zero_session_id_ipv4_udp.pcap", "EthernetII -> PPPoE -> PPP -> IPv4 -> UDP"},
        {"parsing/pppoe/24_qinq_pppoe_session_ipv6_tcp.pcap", "EthernetII -> VLAN(vid=232) -> VLAN(vid=233) -> PPPoE -> PPP -> IPv6 -> TCP"},
        {"parsing/pppoe/25_legacy_9100_vlan_pppoe_session_ipv4_udp.pcap", "EthernetII -> VLAN(vid=330) -> PPPoE -> PPP -> IPv4 -> UDP"},
    };

    for (const auto& expectation : supported_expectations) {
        const ScopedTestContext fixture_context {"fixture=" + std::string {expectation.relative_path}};
        expect_shadow_matches_legacy_flow(
            registry,
            require_raw_fixture_packet(expectation.relative_path),
            expectation.expected_shadow_path,
            StopReason::terminal_protocol
        );
    }

    struct NoFlowExpectation {
        const char* relative_path;
        const char* expected_shadow_path;
        StopReason expected_stop_reason;
        std::vector<DissectionLayerKind> expected_kinds;
    };

    const std::vector<NoFlowExpectation> control_expectations {
        {"parsing/pppoe/05_pppoe_session_lcp_config_request.pcap", "EthernetII", StopReason::terminal_protocol, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::pppoe, DissectionLayerKind::ppp, DissectionLayerKind::ppp_control}},
        {"parsing/pppoe/06_pppoe_session_ipcp_config_request.pcap", "EthernetII", StopReason::terminal_protocol, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::pppoe, DissectionLayerKind::ppp, DissectionLayerKind::ppp_control}},
        {"parsing/pppoe/07_pppoe_session_ipv6cp_config_request.pcap", "EthernetII", StopReason::terminal_protocol, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::pppoe, DissectionLayerKind::ppp, DissectionLayerKind::ppp_control}},
        {"parsing/pppoe/08_pppoe_discovery_padi.pcap", "EthernetII", StopReason::terminal_protocol, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::pppoe}},
        {"parsing/pppoe/09_pppoe_discovery_pado.pcap", "EthernetII", StopReason::terminal_protocol, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::pppoe}},
        {"parsing/pppoe/10_pppoe_discovery_padr.pcap", "EthernetII", StopReason::terminal_protocol, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::pppoe}},
        {"parsing/pppoe/11_pppoe_discovery_pads.pcap", "EthernetII", StopReason::terminal_protocol, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::pppoe}},
        {"parsing/pppoe/12_pppoe_discovery_padt.pcap", "EthernetII", StopReason::terminal_protocol, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::pppoe}},
    };

    for (const auto& expectation : control_expectations) {
        const ScopedTestContext fixture_context {"fixture=" + std::string {expectation.relative_path}};
        const auto packet = require_raw_fixture_packet(expectation.relative_path);
        const auto legacy = decode_legacy_direct(packet);
        const auto shadow = run_shadow(packet, registry);
        const auto steps = collect_shadow_steps(packet, registry);
        std::vector<DissectionLayerKind> kinds {};
        for (const auto& step : steps) {
            kinds.push_back(step.layer);
        }

        PFL_EXPECT(!legacy.recognized_flow);
        PFL_EXPECT(shadow.outcome == ImportDissectionOutcome::unrecognized);
        PFL_EXPECT(shadow.stop_reason == expectation.expected_stop_reason);
        PFL_EXPECT(format_shadow_path(shadow) == expectation.expected_shadow_path);
        PFL_EXPECT((kinds == expectation.expected_kinds));

        const auto* pppoe_facts = find_pppoe_facts(steps);
        PFL_REQUIRE(pppoe_facts != nullptr);
        if (expectation.expected_kinds.size() == 2U) {
            PFL_EXPECT(pppoe_facts->is_discovery);
        } else {
            PFL_EXPECT(!pppoe_facts->is_discovery);
        }
    }

    struct UnsupportedExpectation {
        const char* relative_path;
        const char* expected_shadow_path;
        StopReason expected_stop_reason;
        std::vector<DissectionLayerKind> expected_kinds;
    };

    const std::vector<UnsupportedExpectation> unsupported_expectations {
        {"parsing/pppoe/15_pppoe_session_unknown_ppp_protocol.pcap", "EthernetII", StopReason::unknown_next_protocol, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::pppoe, DissectionLayerKind::ppp}},
        {"parsing/pppoe/16_pppoe_truncated_header.pcap", "EthernetII", StopReason::truncated, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::pppoe}},
        {"parsing/pppoe/17_pppoe_truncated_ppp_protocol.pcap", "EthernetII", StopReason::truncated, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::pppoe, DissectionLayerKind::ppp}},
        {"parsing/pppoe/18_pppoe_truncated_inner_ipv4.pcap", "EthernetII", StopReason::truncated, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::pppoe, DissectionLayerKind::ppp, DissectionLayerKind::ipv4}},
        {"parsing/pppoe/26_pppoe_session_declared_too_short_for_ppp_protocol_with_valid_trailer.pcap", "EthernetII", StopReason::truncated, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::pppoe, DissectionLayerKind::ppp}},
        {"parsing/pppoe/27_pppoe_session_capture_truncated_ipv4_udp_caplen_lt_origlen.pcap", "EthernetII", StopReason::truncated, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::pppoe, DissectionLayerKind::ppp, DissectionLayerKind::ipv4, DissectionLayerKind::udp}},
        {"parsing/pppoe/28_pppoe_session_unsupported_version_with_ipv4_trailer.pcap", "EthernetII", StopReason::unsupported_variant, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::pppoe}},
        {"parsing/pppoe/29_pppoe_session_unsupported_type_with_ipv4_trailer.pcap", "EthernetII", StopReason::unsupported_variant, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::pppoe}},
        {"parsing/pppoe/30_pppoe_session_unsupported_code_with_ipv4_trailer.pcap", "EthernetII", StopReason::unsupported_variant, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::pppoe}},
        {"parsing/pppoe/31_pppoe_session_zero_length_payload.pcap", "EthernetII", StopReason::truncated, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::pppoe, DissectionLayerKind::ppp}},
        {"parsing/pppoe/32_pppoe_session_truncated_inner_ipv6.pcap", "EthernetII", StopReason::malformed, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::pppoe, DissectionLayerKind::ppp, DissectionLayerKind::ipv6}},
    };

    for (const auto& expectation : unsupported_expectations) {
        const ScopedTestContext fixture_context {"fixture=" + std::string {expectation.relative_path}};
        const auto packet = require_raw_fixture_packet(expectation.relative_path);
        const auto legacy = decode_legacy_direct(packet);
        const auto shadow = run_shadow(packet, registry);
        const auto steps = collect_shadow_steps(packet, registry);
        std::vector<DissectionLayerKind> kinds {};
        for (const auto& step : steps) {
            kinds.push_back(step.layer);
        }

        PFL_EXPECT(!legacy.recognized_flow);
        PFL_EXPECT(shadow.outcome == ImportDissectionOutcome::unrecognized);
        PFL_EXPECT(shadow.stop_reason == expectation.expected_stop_reason);
        PFL_EXPECT(format_shadow_path(shadow) == expectation.expected_shadow_path);
        PFL_EXPECT((kinds == expectation.expected_kinds));
    }

    {
        const ScopedTestContext fixture_context {"fixture=parsing/pppoe/20_pppoe_bad_length_extra_payload.pcap"};
        const auto packet = require_raw_fixture_packet("parsing/pppoe/20_pppoe_bad_length_extra_payload.pcap");
        const auto legacy = decode_legacy_direct(packet);
        const auto shadow = run_shadow(packet, registry);
        const auto steps = collect_shadow_steps(packet, registry);
        std::vector<DissectionLayerKind> kinds {};
        for (const auto& step : steps) {
            kinds.push_back(step.layer);
        }

        // PPPoE declared payload length is 33 bytes while the inner IPv4 Total
        // Length field is 37 bytes. Legacy import now matches the strict
        // declared-boundary policy already enforced by the shadow PacketSlice
        // model, so neither path recovers a UDP flow from bytes beyond the
        // bounded PPPoE payload.
        PFL_EXPECT(!legacy.recognized_flow);
        PFL_EXPECT(legacy.protocol == ProtocolId::unknown);
        PFL_EXPECT(legacy.family == DissectionAddressFamily::unknown);
        PFL_EXPECT(!legacy.has_addresses);
        PFL_EXPECT(!legacy.has_ports);
        PFL_EXPECT(!legacy.has_payload_length);
        PFL_EXPECT(legacy.path.empty());

        PFL_EXPECT(shadow.outcome == ImportDissectionOutcome::unrecognized);
        PFL_EXPECT(shadow.stop_reason == StopReason::malformed);
        PFL_EXPECT(format_shadow_path(shadow) == "EthernetII");
        PFL_EXPECT((kinds == std::vector<DissectionLayerKind> {
            DissectionLayerKind::ethernet_ii,
            DissectionLayerKind::pppoe,
            DissectionLayerKind::ppp,
            DissectionLayerKind::ipv4,
        }));
    }

    {
        const ScopedTestContext fixture_context {"fixture=parsing/pppoe/21_pppoe_session_same_tuple_same_session_id.pcap"};
        const auto packets = require_raw_fixture_packets("parsing/pppoe/21_pppoe_session_same_tuple_same_session_id.pcap");
        PFL_EXPECT(packets.size() == 2U);
        for (const auto& packet : packets) {
            expect_shadow_matches_legacy_flow(
                registry,
                packet,
                "EthernetII -> PPPoE -> PPP -> IPv4 -> UDP",
                StopReason::terminal_protocol
            );
            const auto steps = collect_shadow_steps(packet, registry);
            const auto* pppoe_facts = find_pppoe_facts(steps);
            PFL_REQUIRE(pppoe_facts != nullptr);
            PFL_EXPECT(pppoe_facts->session_id == 0x3333U);
        }
    }

    {
        const ScopedTestContext fixture_context {"fixture=parsing/pppoe/22_pppoe_session_same_tuple_different_session_id.pcap"};
        const auto packets = require_raw_fixture_packets("parsing/pppoe/22_pppoe_session_same_tuple_different_session_id.pcap");
        PFL_EXPECT(packets.size() == 2U);
        const std::vector<std::uint16_t> expected_session_ids {0x3333U, 0x4444U};
        for (std::size_t index = 0U; index < packets.size(); ++index) {
            expect_shadow_matches_legacy_flow(
                registry,
                packets[index],
                "EthernetII -> PPPoE -> PPP -> IPv4 -> UDP",
                StopReason::terminal_protocol
            );
            const auto steps = collect_shadow_steps(packets[index], registry);
            const auto* pppoe_facts = find_pppoe_facts(steps);
            PFL_REQUIRE(pppoe_facts != nullptr);
            PFL_EXPECT(pppoe_facts->session_id == expected_session_ids[index]);
        }
    }

    {
        const ScopedTestContext fixture_context {"fixture=parsing/pppoe/33_pppoe_same_session_id_supported_and_unsupported_code.pcap"};
        const auto packets = require_raw_fixture_packets("parsing/pppoe/33_pppoe_same_session_id_supported_and_unsupported_code.pcap");
        PFL_EXPECT(packets.size() == 2U);

        expect_shadow_matches_legacy_flow(
            registry,
            packets[0],
            "EthernetII -> PPPoE -> PPP -> IPv4 -> UDP",
            StopReason::terminal_protocol
        );

        {
            const auto legacy = decode_legacy_direct(packets[1]);
            const auto shadow = run_shadow(packets[1], registry);
            const auto steps = collect_shadow_steps(packets[1], registry);
            std::vector<DissectionLayerKind> kinds {};
            for (const auto& step : steps) {
                kinds.push_back(step.layer);
            }

            PFL_EXPECT(!legacy.recognized_flow);
            PFL_EXPECT(shadow.outcome == ImportDissectionOutcome::unrecognized);
            PFL_EXPECT(shadow.stop_reason == StopReason::unsupported_variant);
            PFL_EXPECT(format_shadow_path(shadow) == "EthernetII");
            PFL_EXPECT((kinds == std::vector<DissectionLayerKind> {DissectionLayerKind::ethernet_ii, DissectionLayerKind::pppoe}));

            const auto* pppoe_facts = find_pppoe_facts(steps);
            PFL_REQUIRE(pppoe_facts != nullptr);
            PFL_EXPECT(pppoe_facts->session_id == 0x5555U);
            PFL_EXPECT(pppoe_facts->code == 0x01U);
        }
    }
}

void expect_pbb_shadow_parsers_bounds_and_fixture_parity() {
    const auto built = make_common_direct_registry();
    PFL_REQUIRE(built.ok());
    const auto& registry = *built.registry;

    {
        const auto exact_header_slice = make_declared_root_slice(
            {0xABU, 0x12U, 0x34U, 0x56U},
            4U
        );
        const auto parsed = parse_pbb_frame(exact_header_slice);
        PFL_EXPECT(parsed.status == ParseStatus::complete);
        PFL_EXPECT(parsed.pcp == 5U);
        PFL_EXPECT(!parsed.dei);
        PFL_EXPECT(parsed.nca);
        PFL_EXPECT(parsed.reserved == 3U);
        PFL_EXPECT(parsed.isid == 0x123456U);
        PFL_EXPECT(parsed.header_length == detail::kPbbITagSize);
        PFL_EXPECT(parsed.declared_payload_length == 0U);

        const auto step = dissect_pbb(exact_header_slice);
        PFL_EXPECT(step.layer == DissectionLayerKind::pbb);
        PFL_REQUIRE(step.path_contribution.has_value());
        PFL_EXPECT(*step.path_contribution == LayerKey::pbb(0x123456U));
        PFL_EXPECT(step.path_commit_policy == PathCommitPolicy::recognized_flow_or_recognized_non_flow);
        PFL_REQUIRE(step.descendant_path_commit_policy.has_value());
        PFL_EXPECT(*step.descendant_path_commit_policy == PathCommitPolicy::recognized_flow_or_recognized_non_flow);
        PFL_EXPECT(step.status == ParseStatus::complete);
        PFL_EXPECT(step.stop_reason == StopReason::truncated);
        PFL_EXPECT(!step.handoff.has_value());
        PFL_REQUIRE(step.bounds.payload.has_value());
        PFL_EXPECT(step.bounds.payload->declared.length() == 0U);
        PFL_EXPECT(step.bounds.payload->captured.length() == 0U);
        const auto* facts = std::get_if<PbbFacts>(&step.facts);
        PFL_REQUIRE(facts != nullptr);
        PFL_EXPECT(facts->pcp == 5U);
        PFL_EXPECT(!facts->dei);
        PFL_EXPECT(facts->nca);
        PFL_EXPECT(facts->reserved == 3U);
        PFL_EXPECT(facts->isid == 0x123456U);
    }

    {
        const auto truncated_slice = make_declared_root_slice({0x10U, 0x20U}, 4U);
        const auto parsed = parse_pbb_frame(truncated_slice);
        PFL_EXPECT(parsed.status == ParseStatus::truncated);
        const auto step = dissect_pbb(truncated_slice);
        PFL_EXPECT(step.layer == DissectionLayerKind::pbb);
        PFL_EXPECT(step.status == ParseStatus::truncated);
        PFL_EXPECT(step.stop_reason == StopReason::truncated);
        PFL_EXPECT(!step.path_contribution.has_value());
        PFL_EXPECT(!step.handoff.has_value());
    }

    {
        const auto inner_ipv4_slice = make_declared_root_slice(
            {
                0x20U, 0x12U, 0x34U, 0x56U,
                0x02U, 0x00U, 0x00U, 0x00U, 0x61U, 0x02U,
                0x02U, 0x00U, 0x00U, 0x00U, 0x61U, 0x01U,
                0x08U, 0x00U,
            },
            18U
        );
        const auto pbb_step = dissect_pbb(inner_ipv4_slice);
        PFL_REQUIRE(pbb_step.handoff.has_value());
        PFL_REQUIRE(pbb_step.handoff->child.has_value());
        const auto inner_step = dissect_pbb_inner_ethernet(*pbb_step.handoff->child);
        PFL_EXPECT(inner_step.layer == DissectionLayerKind::ethernet_ii);
        PFL_REQUIRE(inner_step.path_contribution.has_value());
        PFL_EXPECT(*inner_step.path_contribution == LayerKey::ethernet_ii());
        PFL_REQUIRE(inner_step.handoff.has_value());
        PFL_EXPECT(inner_step.handoff->selector.domain == SelectorDomain::pbb_inner_ether_type);
        PFL_EXPECT(inner_step.handoff->selector.value == detail::kEtherTypeIpv4);
    }

    {
        const auto inner_vlan_slice = make_declared_root_slice(
            {
                0x02U, 0x00U, 0x00U, 0x00U, 0x61U, 0x02U,
                0x02U, 0x00U, 0x00U, 0x00U, 0x61U, 0x01U,
                0x81U, 0x00U, 0x02U, 0x62U, 0x08U, 0x00U,
            },
            18U
        );
        const auto ethernet_step = dissect_pbb_inner_ethernet(inner_vlan_slice);
        PFL_REQUIRE(ethernet_step.handoff.has_value());
        PFL_REQUIRE(ethernet_step.handoff->child.has_value());
        const auto vlan_step = dissect_pbb_inner_vlan(*ethernet_step.handoff->child);
        PFL_EXPECT(vlan_step.layer == DissectionLayerKind::vlan);
        PFL_REQUIRE(vlan_step.path_contribution.has_value());
        PFL_EXPECT(*vlan_step.path_contribution == LayerKey::vlan(610U));
        PFL_REQUIRE(vlan_step.handoff.has_value());
        PFL_EXPECT(vlan_step.handoff->selector.domain == SelectorDomain::pbb_inner_ether_type);
        PFL_EXPECT(vlan_step.handoff->selector.value == detail::kEtherTypeIpv4);
    }

    struct SupportedFlowExpectation {
        const char* relative_path;
        const char* expected_shadow_path;
    };

    const std::vector<SupportedFlowExpectation> supported_expectations {
        {"parsing/pbb/01_pbb_ipv4_tcp.pcap", "EthernetII -> PBB(isid=0x123456) -> EthernetII -> IPv4 -> TCP"},
        {"parsing/pbb/02_pbb_ipv4_udp.pcap", "EthernetII -> PBB(isid=0x123456) -> EthernetII -> IPv4 -> UDP"},
        {"parsing/pbb/03_pbb_ipv6_tcp.pcap", "EthernetII -> PBB(isid=0x123456) -> EthernetII -> IPv6 -> TCP"},
        {"parsing/pbb/04_pbb_ipv6_udp.pcap", "EthernetII -> PBB(isid=0x123456) -> EthernetII -> IPv6 -> UDP"},
        {"parsing/pbb/06_pbb_inner_vlan_ipv4_tcp.pcap", "EthernetII -> PBB(isid=0x123456) -> EthernetII -> VLAN(vid=610) -> IPv4 -> TCP"},
        {"parsing/pbb/07_pbb_inner_qinq_ipv4_udp.pcap", "EthernetII -> PBB(isid=0x123456) -> EthernetII -> VLAN(vid=620) -> VLAN(vid=610) -> IPv4 -> UDP"},
        {"parsing/pbb/08_pbb_inner_llc_snap_ipv4_udp.pcap", "EthernetII -> PBB(isid=0x123456) -> IEEE 802.3 -> LLC/SNAP -> IPv4 -> UDP"},
        {"parsing/pbb/09_pbb_outer_btag_ipv4_udp.pcap", "EthernetII -> VLAN(vid=600) -> PBB(isid=0x123456) -> EthernetII -> IPv4 -> UDP"},
        {"parsing/pbb/10_pbb_outer_btag_inner_vlan_ipv4_tcp.pcap", "EthernetII -> VLAN(vid=600) -> PBB(isid=0x123456) -> EthernetII -> VLAN(vid=610) -> IPv4 -> TCP"},
        {"parsing/pbb/15_pbb_metadata_nondefault_itag.pcap", "EthernetII -> PBB(isid=0x654321) -> EthernetII -> IPv4 -> UDP"},
        {"parsing/pbb/18_pbb_zero_isid_ipv4_udp.pcap", "EthernetII -> PBB(isid=0x000000) -> EthernetII -> IPv4 -> UDP"},
        {"parsing/pbb/19_pbb_max_isid_ipv4_udp.pcap", "EthernetII -> PBB(isid=0xffffff) -> EthernetII -> IPv4 -> UDP"},
        {"parsing/pbb/20_pbb_outer_qinq_ipv6_udp.pcap", "EthernetII -> VLAN(vid=701) -> VLAN(vid=702) -> PBB(isid=0x123456) -> EthernetII -> IPv6 -> UDP"},
        {"parsing/pbb/21_pbb_outer_legacy_vlan_ipv4_udp.pcap", "EthernetII -> VLAN(vid=703) -> PBB(isid=0x123456) -> EthernetII -> IPv4 -> UDP"},
        {"parsing/pbb/27_pbb_extra_captured_tail_ipv4_udp.pcap", "EthernetII -> PBB(isid=0x123456) -> EthernetII -> IPv4 -> UDP"},
    };

    for (const auto& expectation : supported_expectations) {
        const ScopedTestContext fixture_context {"fixture=" + std::string {expectation.relative_path}};
        const auto packet = require_raw_fixture_packet(expectation.relative_path);
        expect_shadow_matches_legacy_flow(
            registry,
            packet,
            expectation.expected_shadow_path,
            StopReason::terminal_protocol
        );

        const auto steps = collect_shadow_steps(packet, registry);
        const auto* pbb = find_pbb_facts(steps);
        PFL_REQUIRE(pbb != nullptr);
        const auto expects_zero_isid = std::string {expectation.relative_path}.find("18_") != std::string::npos;
        PFL_EXPECT(pbb->isid != 0U || expects_zero_isid);
    }

    {
        const ScopedTestContext fixture_context {"fixture=parsing/pbb/05_pbb_arp.pcap"};
        const auto packet = require_raw_fixture_packet("parsing/pbb/05_pbb_arp.pcap");
        expect_shadow_matches_legacy_arp_flow(
            registry,
            packet,
            "EthernetII -> PBB(isid=0x123456) -> EthernetII",
            StopReason::terminal_protocol
        );
    }

    {
        const ScopedTestContext fixture_context {"fixture=parsing/pbb/16_pbb_same_isid_same_inner_tuple_metadata_variation.pcap"};
        const auto packets = require_raw_fixture_packets("parsing/pbb/16_pbb_same_isid_same_inner_tuple_metadata_variation.pcap");
        PFL_EXPECT(packets.size() == 2U);
        for (const auto& packet : packets) {
            expect_shadow_matches_legacy_flow(
                registry,
                packet,
                "EthernetII -> PBB(isid=0x123456) -> EthernetII -> IPv4 -> UDP",
                StopReason::terminal_protocol
            );
        }
    }

    {
        const ScopedTestContext fixture_context {"fixture=parsing/pbb/17_pbb_different_isid_same_inner_tuple.pcap"};
        const auto packets = require_raw_fixture_packets("parsing/pbb/17_pbb_different_isid_same_inner_tuple.pcap");
        PFL_EXPECT(packets.size() == 2U);
        const std::vector<std::string> expected_paths {
            "EthernetII -> PBB(isid=0x123456) -> EthernetII -> IPv4 -> UDP",
            "EthernetII -> PBB(isid=0x123457) -> EthernetII -> IPv4 -> UDP",
        };
        for (std::size_t index = 0U; index < packets.size(); ++index) {
            expect_shadow_matches_legacy_flow(
                registry,
                packets[index],
                expected_paths[index],
                StopReason::terminal_protocol
            );
        }
    }

    struct UnsupportedExpectation {
        const char* relative_path;
        StopReason expected_stop_reason;
        std::vector<DissectionLayerKind> expected_kinds;
    };

    const std::vector<UnsupportedExpectation> unsupported_expectations {
        {"parsing/pbb/11_pbb_unknown_inner_ethertype.pcap", StopReason::unknown_next_protocol, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::pbb, DissectionLayerKind::ethernet_ii}},
        {"parsing/pbb/12_pbb_truncated_itag.pcap", StopReason::malformed, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::pbb}},
        {"parsing/pbb/13_pbb_truncated_inner_ethernet.pcap", StopReason::truncated, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::pbb, DissectionLayerKind::ethernet_ii}},
        {"parsing/pbb/14_pbb_truncated_inner_ipv4.pcap", StopReason::truncated, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::pbb, DissectionLayerKind::ethernet_ii, DissectionLayerKind::ipv4}},
        {"parsing/pbb/22_pbb_capture_truncated_inner_ipv4_caplen_lt_origlen.pcap", StopReason::truncated, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::pbb, DissectionLayerKind::ethernet_ii, DissectionLayerKind::ipv4}},
        {"parsing/pbb/23_pbb_complete_itag_no_inner_ethernet.pcap", StopReason::truncated, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::pbb}},
        {"parsing/pbb/24_pbb_truncated_inner_ipv6.pcap", StopReason::malformed, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::pbb, DissectionLayerKind::ethernet_ii, DissectionLayerKind::ipv6}},
        {"parsing/pbb/26_pbb_inner_pppoe_session_unsupported.pcap", StopReason::unknown_next_protocol, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::pbb, DissectionLayerKind::ethernet_ii}},
    };

    for (const auto& expectation : unsupported_expectations) {
        const ScopedTestContext fixture_context {"fixture=" + std::string {expectation.relative_path}};
        const auto packet = require_raw_fixture_packet(expectation.relative_path);
        const auto legacy = decode_legacy_direct(packet);
        const auto shadow = run_shadow(packet, registry);
        const auto steps = collect_shadow_steps(packet, registry);
        const auto kinds = collect_step_kinds(steps);

        PFL_EXPECT(!legacy.recognized_flow);
        PFL_EXPECT(shadow.outcome == ImportDissectionOutcome::unrecognized);
        PFL_EXPECT(shadow.stop_reason == expectation.expected_stop_reason);
        PFL_EXPECT(format_shadow_path(shadow) == "EthernetII");
        PFL_EXPECT((kinds == expectation.expected_kinds));
    }

    {
        const ScopedTestContext fixture_context {"fixture=parsing/pbb/25_pbb_truncated_inner_arp.pcap"};
        const auto packet = require_raw_fixture_packet("parsing/pbb/25_pbb_truncated_inner_arp.pcap");
        const auto shadow = run_shadow(packet, registry);
        const auto steps = collect_shadow_steps(packet, registry);
        const auto kinds = collect_step_kinds(steps);

        PFL_EXPECT(shadow.outcome != ImportDissectionOutcome::recognized_flow);
        PFL_EXPECT(!shadow.has_ports);
        PFL_EXPECT((kinds == std::vector<DissectionLayerKind> {
            DissectionLayerKind::ethernet_ii,
            DissectionLayerKind::pbb,
            DissectionLayerKind::ethernet_ii,
            DissectionLayerKind::arp,
        }));
    }
}

void expect_macsec_shadow_parsers_bounds_and_fixture_parity() {
    const auto built = make_common_direct_registry();
    PFL_REQUIRE(built.ok());
    const auto& registry = *built.registry;

    {
        const auto macsec_bytes = make_macsec_bytes(
            0xFDU,
            7U,
            0xA1B2C3D4U,
            {},
            true,
            0x0123456789ABCDEFULL
        );
        const auto slice = make_declared_root_slice(macsec_bytes, macsec_bytes.size());
        const auto parsed = parse_macsec_frame(slice);
        PFL_EXPECT(parsed.status == ParseStatus::complete);
        PFL_EXPECT(parsed.available_base_bytes == 6U);
        PFL_EXPECT(parsed.available_sci_bytes == 8U);
        PFL_EXPECT(parsed.tci_an == 0xFDU);
        PFL_EXPECT(parsed.version == 1U);
        PFL_EXPECT(parsed.end_station);
        PFL_EXPECT(parsed.sci_present);
        PFL_EXPECT(parsed.single_copy_broadcast);
        PFL_EXPECT(parsed.encrypted);
        PFL_EXPECT(parsed.changed_text);
        PFL_EXPECT(parsed.association_number == 1U);
        PFL_EXPECT(parsed.short_length == 7U);
        PFL_EXPECT(parsed.packet_number_present);
        PFL_EXPECT(parsed.packet_number == 0xA1B2C3D4U);
        PFL_EXPECT(parsed.has_sci);
        PFL_EXPECT(parsed.sci == 0x0123456789ABCDEFULL);
        PFL_EXPECT(!parsed.has_plain_ether_type);
        PFL_EXPECT(parsed.header_length == 14U);
        PFL_EXPECT(parsed.protected_payload_offset == 14U);
        PFL_EXPECT(parsed.protected_payload_length == 0U);
        PFL_EXPECT(parsed.icv_offset == 14U);
        PFL_EXPECT(parsed.icv_length == 16U);
        PFL_EXPECT(parsed.icv_complete);

        const auto step = dissect_macsec(slice);
        PFL_EXPECT(step.layer == DissectionLayerKind::macsec);
        PFL_EXPECT(!step.path_contribution.has_value());
        PFL_EXPECT(!step.handoff.has_value());
        PFL_EXPECT(step.terminal_disposition == TerminalDisposition::none);
        PFL_EXPECT(step.status == ParseStatus::complete);
        PFL_EXPECT(step.stop_reason == StopReason::encrypted_payload);
        PFL_EXPECT(step.bounds.full.declared.length() == macsec_bytes.size());
        PFL_EXPECT(step.bounds.header.declared.length() == 14U);
        PFL_REQUIRE(step.bounds.payload.has_value());
        PFL_EXPECT(step.bounds.payload->declared.length() == 0U);
        const auto* facts = std::get_if<MacsecFacts>(&step.facts);
        PFL_REQUIRE(facts != nullptr);
        PFL_EXPECT(facts->sci == 0x0123456789ABCDEFULL);
        PFL_EXPECT(facts->icv_complete);
    }

    for (std::uint8_t association_number = 0U; association_number < 4U; ++association_number) {
        const auto parsed = parse_macsec_frame(make_declared_root_slice(
            make_macsec_bytes(
                static_cast<std::uint8_t>(0x80U | association_number),
                0U,
                0xFFFFFFFFU
            ),
            22U
        ));
        PFL_EXPECT(parsed.status == ParseStatus::complete);
        PFL_EXPECT(parsed.version == 1U);
        PFL_EXPECT(parsed.association_number == association_number);
        PFL_EXPECT(parsed.packet_number == 0xFFFFFFFFU);
    }

    for (std::size_t length = 0U; length <= 5U; ++length) {
        std::vector<std::uint8_t> bytes {};
        for (std::size_t index = 0U; index < length; ++index) {
            bytes.push_back(static_cast<std::uint8_t>(0x10U + index));
        }
        const auto parsed = parse_macsec_frame(make_declared_root_slice(bytes, length));
        PFL_EXPECT(parsed.status == ParseStatus::truncated);
        PFL_EXPECT(parsed.available_base_bytes == length);
        PFL_EXPECT(!parsed.packet_number_present);
        if (length < 2U) {
            PFL_EXPECT(parsed.header_length == 2U);
        } else {
            PFL_EXPECT(parsed.header_length == 6U);
        }
    }

    {
        auto truncated_sci = make_macsec_bytes(0x20U, 0U, 0x01020304U, {}, true, 0x0102030405060708ULL, false);
        truncated_sci.resize(13U);
        const auto parsed = parse_macsec_frame(make_declared_root_slice(truncated_sci, truncated_sci.size()));
        PFL_EXPECT(parsed.status == ParseStatus::truncated);
        PFL_EXPECT(parsed.sci_present);
        PFL_EXPECT(parsed.available_sci_bytes == 7U);
        PFL_EXPECT(!parsed.has_sci);
        PFL_EXPECT(parsed.header_length == 14U);
    }

    for (std::size_t remaining = 1U; remaining < 16U; ++remaining) {
        std::vector<std::uint8_t> protected_payload {};
        for (std::size_t index = 0U; index < remaining; ++index) {
            protected_payload.push_back(static_cast<std::uint8_t>(0x30U + index));
        }
        const auto parsed = parse_macsec_frame(make_declared_root_slice(
            make_macsec_bytes(0x0CU, 0U, 0x01020304U, protected_payload, false, 0U, false),
            6U + remaining
        ));
        PFL_EXPECT(parsed.status == ParseStatus::truncated);
        PFL_EXPECT(parsed.protected_payload_length == remaining);
        PFL_EXPECT(parsed.icv_length == 0U);
        PFL_EXPECT(!parsed.icv_complete);
    }

    {
        const auto exact_icv = parse_macsec_frame(make_declared_root_slice(
            make_macsec_bytes(0x0CU, 0U, 0x01020304U),
            22U
        ));
        PFL_EXPECT(exact_icv.status == ParseStatus::complete);
        PFL_EXPECT(exact_icv.protected_payload_length == 0U);
        PFL_EXPECT(exact_icv.icv_length == 16U);
        PFL_EXPECT(exact_icv.icv_complete);

        const auto one_payload = parse_macsec_frame(make_declared_root_slice(
            make_macsec_bytes(0x0CU, 0U, 0x01020304U, {0x45U}),
            23U
        ));
        PFL_EXPECT(one_payload.status == ParseStatus::complete);
        PFL_EXPECT(one_payload.protected_payload_length == 1U);
        PFL_EXPECT(!one_payload.has_plain_ether_type);
    }

    {
        const auto plain = parse_macsec_frame(make_declared_root_slice(
            make_macsec_bytes(
                0x00U,
                4U,
                0x01020304U,
                {0x08U, 0x00U, 0xdeU, 0xadU, 0xbeU, 0xefU, 0xcaU, 0xfeU, 0xbaU, 0xbeU, 0x11U, 0x22U}
            ),
            34U
        ));
        PFL_EXPECT(plain.status == ParseStatus::complete);
        PFL_EXPECT(plain.short_length == 4U);
        PFL_EXPECT(plain.protected_payload_length == 12U);
        PFL_EXPECT(plain.has_plain_ether_type);
        PFL_EXPECT(plain.plain_ether_type == detail::kEtherTypeIpv4);

        const auto encrypted = parse_macsec_frame(make_declared_root_slice(
            make_macsec_bytes(0x08U, 0U, 0x01020304U, {0x08U, 0x00U}),
            24U
        ));
        PFL_EXPECT(!encrypted.has_plain_ether_type);

        const auto changed = parse_macsec_frame(make_declared_root_slice(
            make_macsec_bytes(0x04U, 0U, 0x01020304U, {0x08U, 0x00U}),
            24U
        ));
        PFL_EXPECT(!changed.has_plain_ether_type);
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
            .layer = DissectionLayerKind::macsec,
            .facts = MacsecFacts {
                .version = 1U,
                .association_number = 3U,
                .packet_number_present = true,
                .packet_number = 0xFFFFFFFFU,
                .protected_payload_offset = 6U,
                .protected_payload_length = 12U,
            },
            .status = ParseStatus::complete,
            .stop_reason = StopReason::encrypted_payload,
        });
        collector.finish(DissectionEngineResult {
            .stop_reason = StopReason::encrypted_payload,
            .step_count = 2U,
            .traversed_depth = 2U,
        });
        PFL_EXPECT(collector.facts().outcome == ImportDissectionOutcome::unrecognized);
        PFL_EXPECT(collector.facts().terminal_protocol == ProtocolId::unknown);
        PFL_EXPECT(!collector.facts().has_flow_addresses);
        PFL_EXPECT(!collector.facts().has_ports);
        PFL_EXPECT(!collector.facts().has_transport_payload_length);
        PFL_EXPECT(format_shadow_path(collector.facts()) == "EthernetII");
    }

    {
        const auto direct_packet = make_raw_packet(make_ethernet_frame_with_payload(
            detail::kEtherTypeMacsec,
            make_macsec_bytes(0x0CU, 0U, 0x01020304U, {0xdeU, 0xadU}, false, 0U, false)
        ));
        const auto shadow = run_shadow(direct_packet, registry);
        const auto steps = collect_shadow_steps(direct_packet, registry);
        PFL_EXPECT(shadow.outcome == ImportDissectionOutcome::unrecognized);
        PFL_EXPECT((collect_step_kinds(steps) == std::vector<DissectionLayerKind> {
            DissectionLayerKind::ethernet_ii,
            DissectionLayerKind::macsec,
        }));
        PFL_EXPECT(format_shadow_path(shadow) == "EthernetII");
    }

    {
        const auto nested_packet = make_raw_packet(make_ethernet_frame_with_payload(
            detail::kEtherTypeMacsec,
            make_macsec_bytes(
                0x00U,
                0U,
                0x01020304U,
                {0x88U, 0xe5U, 0x01U, 0x02U},
                false,
                0U,
                true
            )
        ));
        const auto steps = collect_shadow_steps(nested_packet, registry);
        PFL_EXPECT((collect_step_kinds(steps) == std::vector<DissectionLayerKind> {
            DissectionLayerKind::ethernet_ii,
            DissectionLayerKind::macsec,
        }));
    }

    {
        const auto gre_teb_macsec = make_raw_packet(make_ethernet_ipv4_gre_packet(
            ipv4(10, 92, 0, 1),
            ipv4(10, 92, 0, 2),
            make_gre_header(
                detail::kGreProtocolTypeTransparentEthernetBridging,
                make_ethernet_frame_with_payload(
                    detail::kEtherTypeMacsec,
                    make_macsec_bytes(0x0CU, 0U, 0x01020304U, {0xdeU, 0xadU}, false, 0U, false)
                )
            )
        ));
        const auto shadow = run_shadow(gre_teb_macsec, registry);
        const auto steps = collect_shadow_steps(gre_teb_macsec, registry);
        PFL_EXPECT(shadow.outcome == ImportDissectionOutcome::unrecognized);
        PFL_EXPECT(shadow.stop_reason == StopReason::unknown_next_protocol);
        PFL_EXPECT(format_shadow_path(shadow) == "EthernetII -> IPv4 -> GRE -> EthernetII");
        PFL_EXPECT((collect_step_kinds(steps) == std::vector<DissectionLayerKind> {
            DissectionLayerKind::ethernet_ii,
            DissectionLayerKind::ipv4,
            DissectionLayerKind::gre,
            DissectionLayerKind::ethernet_ii,
        }));
    }

    {
        const auto gre_teb_vlan_macsec = make_raw_packet(make_ethernet_ipv4_gre_packet(
            ipv4(10, 92, 1, 1),
            ipv4(10, 92, 1, 2),
            make_gre_header(
                detail::kGreProtocolTypeTransparentEthernetBridging,
                add_vlan_tags(
                    make_ethernet_frame_with_payload(
                        detail::kEtherTypeMacsec,
                        make_macsec_bytes(0x0CU, 0U, 0x01020304U, {0xdeU, 0xadU}, false, 0U, false)
                    ),
                    {{0x8100U, 131U}}
                )
            )
        ));
        const auto shadow = run_shadow(gre_teb_vlan_macsec, registry);
        const auto steps = collect_shadow_steps(gre_teb_vlan_macsec, registry);
        PFL_EXPECT(shadow.outcome == ImportDissectionOutcome::unrecognized);
        PFL_EXPECT(shadow.stop_reason == StopReason::unknown_next_protocol);
        PFL_EXPECT(format_shadow_path(shadow) == "EthernetII -> IPv4 -> GRE -> EthernetII -> VLAN(vid=131)");
        PFL_EXPECT((collect_step_kinds(steps) == std::vector<DissectionLayerKind> {
            DissectionLayerKind::ethernet_ii,
            DissectionLayerKind::ipv4,
            DissectionLayerKind::gre,
            DissectionLayerKind::ethernet_ii,
            DissectionLayerKind::vlan,
        }));
    }

    {
        const auto pbb_inner_macsec = make_raw_packet(make_ethernet_frame_with_payload(
            detail::kEtherTypePbb,
            [] {
                std::vector<std::uint8_t> payload {0x20U, 0x12U, 0x34U, 0x56U};
                const auto inner_frame = make_ethernet_frame_with_payload(
                    detail::kEtherTypeMacsec,
                    make_macsec_bytes(0x0CU, 0U, 0x01020304U, {0xdeU, 0xadU}, false, 0U, false)
                );
                payload.insert(payload.end(), inner_frame.begin(), inner_frame.end());
                return payload;
            }()
        ));
        const auto shadow = run_shadow(pbb_inner_macsec, registry);
        const auto steps = collect_shadow_steps(pbb_inner_macsec, registry);
        PFL_EXPECT(shadow.outcome == ImportDissectionOutcome::unrecognized);
        PFL_EXPECT(shadow.stop_reason == StopReason::unknown_next_protocol);
        PFL_EXPECT(format_shadow_path(shadow) == "EthernetII");
        PFL_EXPECT((collect_step_kinds(steps) == std::vector<DissectionLayerKind> {
            DissectionLayerKind::ethernet_ii,
            DissectionLayerKind::pbb,
            DissectionLayerKind::ethernet_ii,
        }));
        PFL_EXPECT(find_macsec_facts(steps) == nullptr);
    }

    {
        const auto linux_cooked_macsec = make_raw_packet(
            {
                0x12U, 0x34U,
                0x34U, 0x56U,
                0x00U, 0x06U,
                0x10U, 0x20U, 0x30U, 0x40U, 0x50U, 0x60U, 0x70U, 0x80U,
                0x88U, 0xe5U,
            },
            16U,
            kLinkTypeLinuxSll
        );
        const auto shadow = run_shadow(linux_cooked_macsec, registry);
        const auto steps = collect_shadow_steps(linux_cooked_macsec, registry);
        PFL_EXPECT(shadow.outcome == ImportDissectionOutcome::unrecognized);
        PFL_EXPECT(shadow.stop_reason == StopReason::unknown_next_protocol);
        PFL_EXPECT(format_shadow_path(shadow).empty());
        PFL_EXPECT((collect_step_kinds(steps) == std::vector<DissectionLayerKind> {
            DissectionLayerKind::linux_sll,
        }));
        PFL_EXPECT(find_macsec_facts(steps) == nullptr);
    }

    struct MacsecFixtureExpectation {
        const char* relative_path;
        const char* expected_shadow_path;
        StopReason expected_stop_reason;
        std::vector<DissectionLayerKind> expected_kinds;
        bool expect_plain_ether_type;
        std::uint32_t expected_packet_number;
        std::uint32_t expected_payload_length;
        std::uint32_t expected_icv_length;
        bool expect_icv_complete;
    };

    const std::vector<MacsecFixtureExpectation> expectations {
        {"parsing/macsec/01_macsec_basic_no_sci.pcap", "EthernetII", StopReason::encrypted_payload, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::macsec}, false, 0x01020304U, 24U, 16U, true},
        {"parsing/macsec/02_macsec_sci_present.pcap", "EthernetII", StopReason::encrypted_payload, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::macsec}, false, 0x01020304U, 24U, 16U, true},
        {"parsing/macsec/03_macsec_an2_nonzero_pn_sci.pcap", "EthernetII", StopReason::encrypted_payload, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::macsec}, false, 0x0A0B0C0DU, 24U, 16U, true},
        {"parsing/macsec/04_macsec_integrity_only_cleartext_like_payload.pcap", "EthernetII", StopReason::unrecognized_payload, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::macsec}, true, 0x01020304U, 35U, 16U, true},
        {"parsing/macsec/05_macsec_short_length_nonzero.pcap", "EthernetII", StopReason::encrypted_payload, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::macsec}, false, 0x01020304U, 32U, 16U, true},
        {"parsing/macsec/06_vlan_macsec_sci.pcap", "EthernetII -> VLAN(vid=700)", StopReason::encrypted_payload, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::vlan, DissectionLayerKind::macsec}, false, 0x01020304U, 24U, 16U, true},
        {"parsing/macsec/07_qinq_macsec_basic.pcap", "EthernetII -> VLAN(vid=710) -> VLAN(vid=720)", StopReason::encrypted_payload, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::vlan, DissectionLayerKind::vlan, DissectionLayerKind::macsec}, false, 0x01020304U, 24U, 16U, true},
        {"parsing/macsec/08_macsec_scb_flag.pcap", "EthernetII", StopReason::encrypted_payload, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::macsec}, false, 0x01020304U, 24U, 16U, true},
        {"parsing/macsec/09_macsec_es_flag.pcap", "EthernetII", StopReason::encrypted_payload, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::macsec}, false, 0x01020304U, 24U, 16U, true},
        {"parsing/macsec/10_macsec_truncated_base_sectag.pcap", "EthernetII", StopReason::truncated, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::macsec}, false, 0U, 0U, 0U, false},
        {"parsing/macsec/11_macsec_truncated_packet_number.pcap", "EthernetII", StopReason::truncated, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::macsec}, false, 0U, 0U, 0U, false},
        {"parsing/macsec/12_macsec_truncated_sci.pcap", "EthernetII", StopReason::truncated, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::macsec}, false, 0x01020304U, 0U, 0U, false},
        {"parsing/macsec/13_macsec_missing_icv_or_short_payload.pcap", "EthernetII", StopReason::truncated, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::macsec}, false, 0x01020304U, 15U, 0U, false},
        {"parsing/macsec/14_macsec_zero_packet_number.pcap", "EthernetII", StopReason::encrypted_payload, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::macsec}, false, 0x00000000U, 24U, 16U, true},
        {"parsing/macsec/15_macsec_protected_payload_ipv4_like_no_decode.pcap", "EthernetII", StopReason::encrypted_payload, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::macsec}, false, 0x01020304U, 38U, 16U, true},
        {"parsing/macsec/16_macsec_legacy_vlan_9100.pcap", "EthernetII -> VLAN(vid=730)", StopReason::encrypted_payload, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::vlan, DissectionLayerKind::macsec}, false, 0x01020304U, 24U, 16U, true},
        {"parsing/macsec/17_macsec_version1_max_packet_number.pcap", "EthernetII", StopReason::encrypted_payload, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::macsec}, false, 0xFFFFFFFFU, 24U, 16U, true},
        {"parsing/macsec/18_macsec_short_length_ignored_for_bounds.pcap", "EthernetII", StopReason::encrypted_payload, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::macsec}, false, 0x01020304U, 12U, 16U, true},
        {"parsing/macsec/19_macsec_caplen_lt_origlen_partial_icv.pcap", "EthernetII", StopReason::truncated, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::macsec}, false, 0x01020304U, 12U, 0U, false},
        {"parsing/macsec/20_macsec_plain_ether_type_one_byte_only.pcap", "EthernetII", StopReason::unrecognized_payload, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::macsec}, false, 0x01020304U, 1U, 16U, true},
    };

    ProtocolPathRegistry shadow_path_registry {};
    for (const auto& expectation : expectations) {
        const ScopedTestContext fixture_context {"fixture=" + std::string {expectation.relative_path}};
        const auto packet = require_raw_fixture_packet(expectation.relative_path);
        const auto legacy = decode_legacy_direct(packet);
        const auto shadow = run_shadow(packet, registry);
        const auto steps = collect_shadow_steps(packet, registry);
        const auto kinds = collect_step_kinds(steps);
        const auto* macsec = find_macsec_facts(steps);

        PFL_EXPECT(!legacy.recognized_flow);
        PFL_EXPECT(shadow.outcome == ImportDissectionOutcome::unrecognized);
        PFL_EXPECT(shadow.stop_reason == expectation.expected_stop_reason);
        PFL_EXPECT(shadow.terminal_protocol == ProtocolId::unknown);
        PFL_EXPECT(!shadow.has_flow_addresses);
        PFL_EXPECT(!shadow.has_ports);
        PFL_EXPECT(!shadow.has_transport_payload_length);
        PFL_EXPECT(format_shadow_path(shadow) == expectation.expected_shadow_path);
        PFL_EXPECT(format_shadow_path(shadow).find("MACsec") == std::string::npos);
        PFL_EXPECT((kinds == expectation.expected_kinds));
        PFL_REQUIRE(macsec != nullptr);
        PFL_EXPECT(macsec->has_plain_ether_type == expectation.expect_plain_ether_type);
        PFL_EXPECT(macsec->packet_number == expectation.expected_packet_number);
        PFL_EXPECT(macsec->protected_payload_length == expectation.expected_payload_length);
        PFL_EXPECT(macsec->icv_length == expectation.expected_icv_length);
        PFL_EXPECT(macsec->icv_complete == expectation.expect_icv_complete);
        PFL_EXPECT(shadow_path_registry.intern(shadow_path(shadow)) != kInvalidProtocolPathId);
    }

    {
        const auto fixture_01 = run_shadow(require_raw_fixture_packet("parsing/macsec/01_macsec_basic_no_sci.pcap"), registry);
        const auto fixture_04 = run_shadow(
            require_raw_fixture_packet("parsing/macsec/04_macsec_integrity_only_cleartext_like_payload.pcap"),
            registry
        );
        const auto fixture_17 = run_shadow(
            require_raw_fixture_packet("parsing/macsec/17_macsec_version1_max_packet_number.pcap"),
            registry
        );

        ProtocolPathRegistry direct_registry {};
        const auto id_01 = direct_registry.intern(shadow_path(fixture_01));
        const auto id_04 = direct_registry.intern(shadow_path(fixture_04));
        const auto id_17 = direct_registry.intern(shadow_path(fixture_17));
        PFL_EXPECT(id_01 != kInvalidProtocolPathId);
        PFL_EXPECT(id_01 == id_04);
        PFL_EXPECT(id_01 == id_17);
        PFL_EXPECT(direct_registry.size() == 1U);
    }
}


void run_common_direct_link_dissection_tests() {
    expect_ethernet_and_vlan_canonical_parsers();
    expect_common_direct_supports_triple_vlan_and_depth_limits();
    expect_linux_cooked_shadow_root_parsers_and_fixture_parity();
    expect_llc_snap_shadow_parsers_bounds_and_fixture_parity();
    expect_pppoe_ppp_shadow_parsers_bounds_and_fixture_parity();
    expect_pbb_shadow_parsers_bounds_and_fixture_parity();
    expect_macsec_shadow_parsers_bounds_and_fixture_parity();
}

}  // namespace pfl::tests::common_direct_test
