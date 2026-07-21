#include "CommonDirectDissectionTestSupport.h"
#include "core/dissection/modules/CommonDirectModules.h"

namespace pfl::tests::common_direct_test {

using namespace dissection;


void expect_ah_and_esp_shadow_parsers_bounds_and_traversal() {
    const auto built = make_common_direct_registry();
    PFL_REQUIRE(built.ok());
    const auto& registry = *built.registry;
    const DissectionEngine engine {};

    const auto ipv6_src_addr = ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 21, 0, 0, 0, 0, 0, 0, 0, 0x11});
    const auto ipv6_dst_addr = ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 21, 0, 0, 0, 0, 0, 0, 0, 0x12});

    {
        const auto exact_ah_packet = make_raw_packet(make_ah_header(
            detail::kIpProtocolTcp,
            0x01020304U,
            0x05060708U,
            {}
        ), 12U);
        const auto exact_ah_root = make_root_slice(exact_ah_packet);
        const auto exact_ah = parse_ah_header(exact_ah_root);
        PFL_EXPECT(exact_ah.status == ParseStatus::complete);
        PFL_EXPECT(exact_ah.next_header == detail::kIpProtocolTcp);
        PFL_EXPECT(exact_ah.payload_length_field == 1U);
        PFL_EXPECT(exact_ah.reserved == 0U);
        PFL_EXPECT(exact_ah.spi == 0x01020304U);
        PFL_EXPECT(exact_ah.sequence_number == 0x05060708U);
        PFL_EXPECT(exact_ah.header_length == 12U);
        PFL_EXPECT(exact_ah.icv_length == 0U);

        const auto exact_ah_step = dissect_ipv4_ah(exact_ah_root);
        PFL_EXPECT(exact_ah_step.layer == DissectionLayerKind::ah);
        PFL_REQUIRE(exact_ah_step.path_contribution.has_value());
        PFL_EXPECT(*exact_ah_step.path_contribution == LayerKey::ah(0x01020304U));
        PFL_EXPECT(exact_ah_step.terminal_disposition == TerminalDisposition::none);
        PFL_REQUIRE(exact_ah_step.handoff.has_value());
        PFL_REQUIRE(exact_ah_step.handoff->child.has_value());
        const ProtocolSelector expected_ipv4_ah_selector {
            .domain = SelectorDomain::ip_protocol,
            .value = detail::kIpProtocolTcp,
        };
        PFL_EXPECT(exact_ah_step.handoff->selector == expected_ipv4_ah_selector);
        PFL_EXPECT(exact_ah_step.bounds.full.declared.length() == 12U);
        PFL_EXPECT(exact_ah_step.bounds.full.captured.length() == 12U);
        PFL_EXPECT(exact_ah_step.bounds.header.declared.length() == 12U);
        PFL_EXPECT(exact_ah_step.bounds.header.captured.length() == 12U);
        PFL_REQUIRE(exact_ah_step.bounds.payload.has_value());
        PFL_EXPECT(exact_ah_step.bounds.payload->declared.length() == 0U);
        PFL_EXPECT(exact_ah_step.bounds.payload->captured.length() == 0U);
        PFL_EXPECT(std::holds_alternative<AhFacts>(exact_ah_step.facts));
        const auto* exact_ah_facts = std::get_if<AhFacts>(&exact_ah_step.facts);
        PFL_REQUIRE(exact_ah_facts != nullptr);
        PFL_EXPECT(exact_ah_facts->next_header == detail::kIpProtocolTcp);
        PFL_EXPECT(exact_ah_facts->payload_length_field == 1U);
        PFL_EXPECT(exact_ah_facts->reserved == 0U);
        PFL_EXPECT(exact_ah_facts->spi == 0x01020304U);
        PFL_EXPECT(exact_ah_facts->sequence_number == 0x05060708U);
        PFL_EXPECT(exact_ah_facts->header_length == 12U);
        PFL_EXPECT(exact_ah_facts->icv_length == 0U);
    }

    {
        const auto icv_ah_packet = make_raw_packet(make_ah_header(
            detail::kIpProtocolUdp,
            0x11121314U,
            0x15161718U,
            {0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7},
            0x1234U
        ), 20U);
        const auto icv_ah = parse_ah_header(make_root_slice(icv_ah_packet));
        PFL_EXPECT(icv_ah.status == ParseStatus::complete);
        PFL_EXPECT(icv_ah.payload_length_field == 3U);
        PFL_EXPECT(icv_ah.reserved == 0x1234U);
        PFL_EXPECT(icv_ah.header_length == 20U);
        PFL_EXPECT(icv_ah.icv_length == 8U);
    }

    {
        auto truncated_fixed_ah = make_ah_header(detail::kIpProtocolTcp, 0x01020304U, 0x05060708U);
        truncated_fixed_ah.resize(10U);
        const auto parsed = parse_ah_header(make_root_slice(make_raw_packet(truncated_fixed_ah, 12U)));
        PFL_EXPECT(parsed.status == ParseStatus::truncated);
    }

    {
        const auto malformed_short_length = parse_ah_header(make_root_slice(make_raw_packet(
            make_ah_header(detail::kIpProtocolTcp, 0x01020304U, 0x05060708U, {}, 0U, 0U),
            12U
        )));
        PFL_EXPECT(malformed_short_length.status == ParseStatus::malformed);
    }

    {
        const auto malformed_beyond_declared = parse_ah_header(make_root_slice(make_raw_packet(
            make_ah_header(detail::kIpProtocolTcp, 0x01020304U, 0x05060708U, {0xaa, 0xbb, 0xcc, 0xdd}),
            12U
        )));
        PFL_EXPECT(malformed_beyond_declared.status == ParseStatus::malformed);
    }

    {
        auto truncated_icv_ah = make_ah_header(
            detail::kIpProtocolTcp,
            0x01020304U,
            0x05060708U,
            {0xa0, 0xa1, 0xa2, 0xa3}
        );
        truncated_icv_ah.resize(14U);
        const auto parsed = parse_ah_header(make_root_slice(make_raw_packet(truncated_icv_ah, 16U)));
        PFL_EXPECT(parsed.status == ParseStatus::truncated);
    }

    {
        const auto exact_esp_packet = make_raw_packet(make_esp_header(
            0x21222324U,
            0x31323334U,
            {}
        ), detail::kEspBaseHeaderSize);
        const auto exact_esp_root = make_root_slice(exact_esp_packet);
        const auto exact_esp = parse_esp_header(exact_esp_root);
        PFL_EXPECT(exact_esp.status == ParseStatus::complete);
        PFL_EXPECT(exact_esp.spi == 0x21222324U);
        PFL_EXPECT(exact_esp.sequence_number == 0x31323334U);
        PFL_EXPECT(exact_esp.header_length == detail::kEspBaseHeaderSize);

        const auto exact_esp_step = dissect_esp(exact_esp_root);
        PFL_EXPECT(exact_esp_step.layer == DissectionLayerKind::esp);
        PFL_REQUIRE(exact_esp_step.path_contribution.has_value());
        PFL_EXPECT(*exact_esp_step.path_contribution == LayerKey::esp(0x21222324U));
        PFL_EXPECT(exact_esp_step.terminal_disposition == TerminalDisposition::flow_candidate);
        PFL_EXPECT(exact_esp_step.stop_reason == StopReason::terminal_protocol);
        PFL_EXPECT(exact_esp_step.bounds.full.declared.length() == detail::kEspBaseHeaderSize);
        PFL_EXPECT(exact_esp_step.bounds.header.declared.length() == detail::kEspBaseHeaderSize);
        PFL_REQUIRE(exact_esp_step.bounds.payload.has_value());
        PFL_EXPECT(exact_esp_step.bounds.payload->declared.length() == 0U);
        PFL_EXPECT(exact_esp_step.bounds.payload->captured.length() == 0U);
        PFL_EXPECT(std::holds_alternative<EspFacts>(exact_esp_step.facts));
        const auto* exact_esp_facts = std::get_if<EspFacts>(&exact_esp_step.facts);
        PFL_REQUIRE(exact_esp_facts != nullptr);
        PFL_EXPECT(exact_esp_facts->spi == 0x21222324U);
        PFL_EXPECT(exact_esp_facts->sequence_number == 0x31323334U);
    }

    {
        const auto payload_esp_packet = make_raw_packet(make_esp_header(
            0x01020304U,
            0x0a0b0c0dU,
            {0xde, 0xad, 0xbe, 0xef, 0x10}
        ));
        const auto payload_esp_step = dissect_esp(make_root_slice(payload_esp_packet));
        PFL_EXPECT(payload_esp_step.status == ParseStatus::complete);
        PFL_REQUIRE(payload_esp_step.bounds.payload.has_value());
        PFL_EXPECT(payload_esp_step.bounds.payload->declared.length() == 5U);
        PFL_EXPECT(payload_esp_step.bounds.payload->captured.length() == 5U);
    }

    {
        auto truncated_esp_bytes = make_esp_header(0x01020304U, 0x0a0b0c0dU);
        truncated_esp_bytes.resize(detail::kEspBaseHeaderSize - 2U);
        const auto parsed = parse_esp_header(make_root_slice(make_raw_packet(
            truncated_esp_bytes,
            detail::kEspBaseHeaderSize
        )));
        PFL_EXPECT(parsed.status == ParseStatus::truncated);

        const auto step = dissect_esp(make_root_slice(make_raw_packet(
            truncated_esp_bytes,
            detail::kEspBaseHeaderSize
        )));
        PFL_EXPECT(step.status == ParseStatus::truncated);
        PFL_EXPECT(!step.path_contribution.has_value());
        PFL_EXPECT(step.terminal_disposition == TerminalDisposition::none);
    }

    {
        const auto malformed_esp_step = dissect_esp(make_root_slice(make_raw_packet(
            make_esp_header(0x01020304U, 0x0a0b0c0dU),
            detail::kEspBaseHeaderSize - 1U
        )));
        PFL_EXPECT(malformed_esp_step.status == ParseStatus::malformed);
        PFL_EXPECT(!malformed_esp_step.path_contribution.has_value());
    }

    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(make_ethernet_ipv4_ah_packet(
            ipv4(10, 50, 0, 1), ipv4(10, 50, 0, 2), detail::kIpProtocolTcp,
            make_ipv4_tcp_segment(12345U, 443U, 3U, 0x18U)
        )),
        "EthernetII -> IPv4 -> AH(spi=0x11111111) -> TCP",
        StopReason::terminal_protocol
    );
    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(make_ethernet_ipv4_ah_packet(
            ipv4(10, 50, 1, 1), ipv4(10, 50, 1, 2), detail::kIpProtocolUdp,
            make_ipv4_udp_segment(5300U, 53U, 4U)
        )),
        "EthernetII -> IPv4 -> AH(spi=0x11111111) -> UDP",
        StopReason::terminal_protocol
    );
    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(make_ethernet_ipv6_ah_packet(
            ipv6_src_addr, ipv6_dst_addr, detail::kIpProtocolTcp,
            make_ipv6_tcp_segment(23456U, 443U, 2U, 0x18U)
        )),
        "EthernetII -> IPv6 -> AH(spi=0x11111111) -> TCP",
        StopReason::terminal_protocol
    );
    expect_shadow_matches_legacy_flow(
        registry,
        [&]() {
            auto ah_udp_payload = make_ah_header(
                detail::kIpProtocolUdp,
                0x11111111U,
                0x01020304U,
                {}
            );
            const auto udp_segment = make_ipv6_udp_segment(5301U, 5302U, 0U);
            ah_udp_payload.insert(ah_udp_payload.end(), udp_segment.begin(), udp_segment.end());
            return make_raw_packet(make_ethernet_ipv6_packet(
                ipv6_src_addr,
                ipv6_dst_addr,
                detail::kIpProtocolHopByHop,
                make_ipv6_hop_by_hop_extension(detail::kIpProtocolAh, ah_udp_payload)
            ));
        }(),
        "EthernetII -> IPv6 -> AH(spi=0x11111111) -> UDP",
        StopReason::terminal_protocol
    );

    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(make_ethernet_ipv4_esp_packet(
            ipv4(10, 60, 0, 1), ipv4(10, 60, 0, 2), 0x01020304U, 0x11121314U, {0xde, 0xad, 0xbe}
        )),
        "EthernetII -> IPv4 -> ESP(spi=0x01020304)",
        StopReason::terminal_protocol
    );
    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(make_ethernet_ipv6_esp_packet(
            ipv6_src_addr, ipv6_dst_addr, 0x01020304U, 0x11121314U, {0xde, 0xad}
        )),
        "EthernetII -> IPv6 -> ESP(spi=0x01020304)",
        StopReason::terminal_protocol
    );

    {
        const auto ah_inner_ipv6_packet = make_raw_packet(make_ethernet_ipv4_ah_packet(
            ipv4(10, 70, 0, 1),
            ipv4(10, 70, 0, 2),
            detail::kIpProtocolIpv6Encapsulation,
            strip_ethernet_header(make_ethernet_ipv6_packet(
                ipv6_src_addr,
                ipv6_dst_addr,
                detail::kIpProtocolTcp,
                make_ipv6_tcp_segment(30000U, 443U, 1U, 0x18U)
            ))
        ));
        expect_shadow_matches_legacy_flow(
            registry,
            ah_inner_ipv6_packet,
            "EthernetII -> IPv4 -> AH(spi=0x11111111) -> IPv6 -> TCP",
            StopReason::terminal_protocol
        );
    }

    {
        const auto ah_inner_ipv4_packet = make_raw_packet(make_ethernet_ipv6_ah_packet(
            ipv6_src_addr,
            ipv6_dst_addr,
            detail::kIpProtocolIpv4Encapsulation,
            strip_ethernet_header(make_ethernet_ipv4_udp_packet(
                ipv4(172, 16, 0, 1),
                ipv4(172, 16, 0, 2),
                40000U,
                53U
            ))
        ));
        expect_shadow_matches_legacy_flow(
            registry,
            ah_inner_ipv4_packet,
            "EthernetII -> IPv6 -> AH(spi=0x11111111) -> IPv4 -> UDP",
            StopReason::terminal_protocol
        );
    }

    {
        const auto ah_sctp_shadow = run_shadow(make_raw_packet(make_ethernet_ipv4_ah_packet(
            ipv4(10, 80, 0, 1),
            ipv4(10, 80, 0, 2),
            detail::kIpProtocolSctp,
            make_sctp_segment(49152U, 36412U, 0x01020304U, 0x89ABCDEFU, 2U)
        )), registry);
        PFL_EXPECT(ah_sctp_shadow.outcome == ImportDissectionOutcome::recognized_flow);
        PFL_EXPECT(ah_sctp_shadow.terminal_protocol == ProtocolId::sctp);
        PFL_EXPECT(ah_sctp_shadow.has_ports);
        PFL_EXPECT(ah_sctp_shadow.src_port == 49152U);
        PFL_EXPECT(ah_sctp_shadow.dst_port == 36412U);
        PFL_EXPECT(format_shadow_path(ah_sctp_shadow) == "EthernetII -> IPv4 -> AH(spi=0x11111111) -> SCTP");
    }

    {
        const auto ah_icmp_shadow = run_shadow(make_raw_packet(make_ethernet_ipv4_ah_packet(
            ipv4(10, 81, 0, 1),
            ipv4(10, 81, 0, 2),
            detail::kIpProtocolIcmp,
            {8U, 0U, 0x12U, 0x34U}
        )), registry);
        PFL_EXPECT(ah_icmp_shadow.outcome == ImportDissectionOutcome::recognized_flow);
        PFL_EXPECT(ah_icmp_shadow.terminal_protocol == ProtocolId::icmp);
        PFL_EXPECT(!ah_icmp_shadow.has_ports);
        PFL_EXPECT(format_shadow_path(ah_icmp_shadow) == "EthernetII -> IPv4 -> AH(spi=0x11111111) -> ICMP");
    }

    {
        const auto ah_icmpv6_shadow = run_shadow(make_raw_packet(make_ethernet_ipv6_ah_packet(
            ipv6_src_addr,
            ipv6_dst_addr,
            detail::kIpProtocolIcmpV6,
            {128U, 0U, 0x12U, 0x34U}
        )), registry);
        PFL_EXPECT(ah_icmpv6_shadow.outcome == ImportDissectionOutcome::recognized_flow);
        PFL_EXPECT(ah_icmpv6_shadow.terminal_protocol == ProtocolId::icmpv6);
        PFL_EXPECT(!ah_icmpv6_shadow.has_ports);
        PFL_EXPECT(format_shadow_path(ah_icmpv6_shadow) == "EthernetII -> IPv6 -> AH(spi=0x11111111) -> ICMPv6");
    }

    {
        const auto ah_igmp_shadow = run_shadow(make_raw_packet(make_ethernet_ipv4_ah_packet(
            ipv4(192, 0, 2, 200),
            ipv4(224, 0, 0, 1),
            detail::kIpProtocolIgmp,
            make_igmp_message(0x16U, 0U, 0x1234U, ipv4(239, 1, 1, 1))
        )), registry);
        PFL_EXPECT(ah_igmp_shadow.outcome == ImportDissectionOutcome::recognized_flow);
        PFL_EXPECT(ah_igmp_shadow.terminal_protocol == ProtocolId::igmp);
        PFL_EXPECT(ah_igmp_shadow.family == DissectionAddressFamily::ipv4);
        PFL_EXPECT(ah_igmp_shadow.dst_addr_v4 == ipv4(239, 1, 1, 1));
        PFL_EXPECT(format_shadow_path(ah_igmp_shadow) == "EthernetII -> IPv4 -> AH(spi=0x11111111)");
    }

    {
        const auto ah_esp_shadow = run_shadow(make_raw_packet(make_ethernet_ipv4_ah_packet(
            ipv4(10, 82, 0, 1),
            ipv4(10, 82, 0, 2),
            detail::kIpProtocolEsp,
            make_esp_header(0x21222324U, 0x31323334U, {0xde, 0xad, 0xbe, 0xef})
        )), registry);
        PFL_EXPECT(ah_esp_shadow.outcome == ImportDissectionOutcome::recognized_flow);
        PFL_EXPECT(ah_esp_shadow.terminal_protocol == ProtocolId::esp);
        PFL_EXPECT(!ah_esp_shadow.has_ports);
        PFL_EXPECT(ah_esp_shadow.has_transport_payload_length);
        PFL_EXPECT(ah_esp_shadow.captured_transport_payload_length == 4U);
        PFL_EXPECT(format_shadow_path(ah_esp_shadow) == "EthernetII -> IPv4 -> AH(spi=0x11111111) -> ESP(spi=0x21222324)");
    }

    {
        const auto unknown_ah_shadow = run_shadow(make_raw_packet(make_ethernet_ipv4_ah_packet(
            ipv4(10, 83, 0, 1),
            ipv4(10, 83, 0, 2),
            0xFDU,
            {0xde, 0xad, 0xbe, 0xef}
        )), registry);
        PFL_EXPECT(unknown_ah_shadow.outcome == ImportDissectionOutcome::unrecognized);
        PFL_EXPECT(unknown_ah_shadow.stop_reason == StopReason::unknown_next_protocol);
        PFL_EXPECT(unknown_ah_shadow.terminal_protocol == ProtocolId::unknown);
        PFL_EXPECT(format_shadow_path(unknown_ah_shadow) == "EthernetII -> IPv4 -> AH(spi=0x11111111)");
    }

    {
        auto nested_ah_payload = make_ipv6_tcp_segment(1234U, 4321U, 1U, 0x18U);
        auto ah3 = make_ah_header(detail::kIpProtocolTcp, 0x33333333U, 3U);
        ah3.insert(ah3.end(), nested_ah_payload.begin(), nested_ah_payload.end());
        auto ah2 = make_ah_header(detail::kIpProtocolAh, 0x22222222U, 2U);
        ah2.insert(ah2.end(), ah3.begin(), ah3.end());
        auto ah1 = make_ah_header(detail::kIpProtocolAh, 0x11111111U, 1U);
        ah1.insert(ah1.end(), ah2.begin(), ah2.end());
        const auto repeated_ah_packet = make_raw_packet(make_ethernet_ipv6_packet(
            ipv6_src_addr,
            ipv6_dst_addr,
            detail::kIpProtocolAh,
            ah1
        ));

        StepKindRecorder repeated_ah_recorder {};
        const auto repeated_ah_result = engine.run(
            registry,
            make_link_type_selector(repeated_ah_packet.data_link_type),
            make_root_slice(repeated_ah_packet),
            DissectionConsumer {.on_step = record_step_kind, .context = &repeated_ah_recorder},
            5U
        );
        const std::vector<DissectionLayerKind> expected_repeated_ah_kinds {
            DissectionLayerKind::ethernet_ii,
            DissectionLayerKind::ipv6,
            DissectionLayerKind::ah,
            DissectionLayerKind::ah,
            DissectionLayerKind::ah,
        };
        PFL_EXPECT(repeated_ah_result.stop_reason == StopReason::depth_limit);
        PFL_EXPECT(repeated_ah_result.step_count == 5U);
        PFL_EXPECT(repeated_ah_result.traversed_depth == 5U);
        PFL_EXPECT(repeated_ah_recorder.kinds == expected_repeated_ah_kinds);

        const auto repeated_ah_shadow = run_shadow(repeated_ah_packet, registry);
        PFL_EXPECT(repeated_ah_shadow.outcome == ImportDissectionOutcome::recognized_flow);
        PFL_EXPECT(repeated_ah_shadow.terminal_protocol == ProtocolId::tcp);
        PFL_EXPECT(format_shadow_path(repeated_ah_shadow) ==
            "EthernetII -> IPv6 -> AH(spi=0x11111111) -> AH(spi=0x22222222) -> AH(spi=0x33333333) -> TCP");
    }

    {
        const auto outer_ipv4_ah_fragment_shadow = run_shadow(make_raw_packet(make_ethernet_ipv4_ah_packet(
            ipv4(10, 84, 0, 1),
            ipv4(10, 84, 0, 2),
            detail::kIpProtocolTcp,
            make_ipv4_tcp_segment(80U, 12345U),
            0x11111111U,
            1U,
            {},
            0x2000U
        )), registry);
        PFL_EXPECT(outer_ipv4_ah_fragment_shadow.outcome == ImportDissectionOutcome::unrecognized);
        PFL_EXPECT(outer_ipv4_ah_fragment_shadow.stop_reason == StopReason::needs_reassembly);
        PFL_EXPECT(format_shadow_path(outer_ipv4_ah_fragment_shadow) == "EthernetII -> IPv4");
    }

    {
        const auto outer_ipv4_esp_fragment_shadow = run_shadow(make_raw_packet(make_ethernet_ipv4_esp_packet(
            ipv4(10, 85, 0, 1),
            ipv4(10, 85, 0, 2),
            0x01020304U,
            1U,
            {0xde, 0xad, 0xbe, 0xef},
            0x2000U
        )), registry);
        PFL_EXPECT(outer_ipv4_esp_fragment_shadow.outcome == ImportDissectionOutcome::unrecognized);
        PFL_EXPECT(outer_ipv4_esp_fragment_shadow.stop_reason == StopReason::needs_reassembly);
        PFL_EXPECT(format_shadow_path(outer_ipv4_esp_fragment_shadow) == "EthernetII -> IPv4");
    }

    {
        const auto outer_ipv6_ah_fragment_shadow = run_shadow(make_raw_packet(make_ethernet_ipv6_fragment_packet(
            ipv6_src_addr,
            ipv6_dst_addr,
            detail::kIpProtocolAh,
            make_ah_header(detail::kIpProtocolTcp, 0x11111111U, 1U),
            0x0000U,
            true
        )), registry);
        PFL_EXPECT(outer_ipv6_ah_fragment_shadow.outcome == ImportDissectionOutcome::unrecognized);
        PFL_EXPECT(outer_ipv6_ah_fragment_shadow.stop_reason == StopReason::needs_reassembly);
        PFL_EXPECT(format_shadow_path(outer_ipv6_ah_fragment_shadow) == "EthernetII -> IPv6");
    }

    {
        const auto outer_ipv6_esp_fragment_shadow = run_shadow(make_raw_packet(make_ethernet_ipv6_fragment_packet(
            ipv6_src_addr,
            ipv6_dst_addr,
            detail::kIpProtocolEsp,
            make_esp_header(0x01020304U, 1U),
            0x0000U,
            true
        )), registry);
        PFL_EXPECT(outer_ipv6_esp_fragment_shadow.outcome == ImportDissectionOutcome::unrecognized);
        PFL_EXPECT(outer_ipv6_esp_fragment_shadow.stop_reason == StopReason::needs_reassembly);
        PFL_EXPECT(format_shadow_path(outer_ipv6_esp_fragment_shadow) == "EthernetII -> IPv6");
    }
}

void expect_mpls_shadow_parsers_bounds_and_traversal() {
    const auto built = make_common_direct_registry();
    PFL_REQUIRE(built.ok());
    const auto& registry = *built.registry;
    const DissectionEngine engine {};

    {
        const auto exact_label_packet = make_raw_packet(
            make_mpls_payload_with_labels(
                {16030U},
                make_ipv4_payload_packet(
                    ipv4(10, 130, 0, 1),
                    ipv4(10, 130, 0, 2),
                    detail::kIpProtocolUdp,
                    make_ipv4_udp_segment(5300U, 53U, 2U)
                )
            )
        );
        const auto exact_label_root = make_root_slice(exact_label_packet);
        const auto exact_label = parse_mpls_label(exact_label_root);
        PFL_EXPECT(exact_label.status == ParseStatus::complete);
        PFL_EXPECT(exact_label.label == 16030U);
        PFL_EXPECT(exact_label.traffic_class == 0U);
        PFL_EXPECT(exact_label.bottom_of_stack);
        PFL_EXPECT(exact_label.ttl == 64U);
        PFL_EXPECT(exact_label.header_length == detail::kMplsLabelSize);
        PFL_EXPECT(exact_label.declared_payload_length == exact_label_packet.bytes.size() - detail::kMplsLabelSize);

        const auto exact_label_step = dissect_mpls_label(exact_label_root);
        PFL_EXPECT(exact_label_step.layer == DissectionLayerKind::mpls);
        PFL_EXPECT(exact_label_step.status == ParseStatus::complete);
        PFL_EXPECT(exact_label_step.stop_reason == StopReason::none);
        PFL_REQUIRE(exact_label_step.path_contribution.has_value());
        PFL_EXPECT(*exact_label_step.path_contribution == LayerKey::mpls(16030U));
        PFL_REQUIRE(exact_label_step.handoff.has_value());
        PFL_REQUIRE(exact_label_step.handoff->child.has_value());
        const ProtocolSelector expected_payload_selector {
            .domain = SelectorDomain::mpls_bos_payload,
            .value = kMplsBosPayloadSelectorValue,
        };
        PFL_EXPECT(exact_label_step.handoff->selector == expected_payload_selector);
        PFL_EXPECT(exact_label_step.bounds.full.declared.length() == exact_label_packet.bytes.size());
        PFL_EXPECT(exact_label_step.bounds.full.captured.length() == exact_label_packet.bytes.size());
        PFL_EXPECT(exact_label_step.bounds.header.declared.length() == detail::kMplsLabelSize);
        PFL_EXPECT(exact_label_step.bounds.header.captured.length() == detail::kMplsLabelSize);
        PFL_REQUIRE(exact_label_step.bounds.payload.has_value());
        PFL_EXPECT(exact_label_step.bounds.payload->declared.length() == exact_label_packet.bytes.size() - detail::kMplsLabelSize);
        PFL_EXPECT(exact_label_step.bounds.payload->captured.length() == exact_label_packet.bytes.size() - detail::kMplsLabelSize);
        const auto* exact_label_facts = std::get_if<MplsFacts>(&exact_label_step.facts);
        PFL_REQUIRE(exact_label_facts != nullptr);
        PFL_EXPECT(exact_label_facts->label == 16030U);
        PFL_EXPECT(exact_label_facts->bottom_of_stack);
    }

    {
        const auto stacked_label_packet = make_raw_packet(
            make_mpls_payload_with_labels(
                {16030U, 16031U},
                make_ipv4_payload_packet(
                    ipv4(10, 130, 1, 1),
                    ipv4(10, 130, 1, 2),
                    detail::kIpProtocolTcp,
                    make_ipv4_tcp_segment(12345U, 443U, 2U, 0x18U)
                )
            )
        );
        const auto stacked_label_step = dissect_mpls_label(make_root_slice(stacked_label_packet));
        PFL_EXPECT(stacked_label_step.status == ParseStatus::complete);
        PFL_REQUIRE(stacked_label_step.handoff.has_value());
        const ProtocolSelector expected_stack_selector {
            .domain = SelectorDomain::mpls_stack,
            .value = kMplsStackContinueSelectorValue,
        };
        PFL_EXPECT(stacked_label_step.handoff->selector == expected_stack_selector);
    }

    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(make_ethernet_frame_with_payload(
            detail::kEtherTypeMplsUnicast,
            make_mpls_payload_with_labels(
                {16030U},
                make_ipv4_payload_packet(
                    ipv4(10, 131, 0, 1),
                    ipv4(10, 131, 0, 2),
                    detail::kIpProtocolUdp,
                    make_ipv4_udp_segment(5301U, 53U, 3U)
                )
            )
        )),
        "EthernetII -> MPLS(label=16030) -> IPv4 -> UDP",
        StopReason::terminal_protocol
    );

    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(add_vlan_tags(
            make_ethernet_frame_with_payload(
                detail::kEtherTypeMplsUnicast,
                make_mpls_payload_with_labels(
                    {16040U},
                    make_ipv4_payload_packet(
                        ipv4(10, 131, 1, 1),
                        ipv4(10, 131, 1, 2),
                        detail::kIpProtocolTcp,
                        make_ipv4_tcp_segment(5302U, 443U, 1U, 0x18U)
                    )
                )
            ),
            {{0x8100U, 410U}}
        )),
        "EthernetII -> VLAN(vid=410) -> MPLS(label=16040) -> IPv4 -> TCP",
        StopReason::terminal_protocol
    );

    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(add_vlan_tags(
            make_ethernet_frame_with_payload(
                detail::kEtherTypeMplsUnicast,
                make_mpls_payload_with_labels(
                    {16050U},
                    make_ipv6_payload_packet(
                        ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 50, 0, 0, 0, 0, 0, 0, 0, 0x11}),
                        ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 50, 0, 0, 0, 0, 0, 0, 0, 0x12}),
                        detail::kIpProtocolUdp,
                        make_ipv6_udp_segment(6300U, 6301U, 2U)
                    )
                )
            ),
            {{0x88A8U, 411U}, {0x8100U, 412U}}
        )),
        "EthernetII -> VLAN(vid=411) -> VLAN(vid=412) -> MPLS(label=16050) -> IPv6 -> UDP",
        StopReason::terminal_protocol
    );

    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(make_ethernet_ipv4_gre_packet(
            ipv4(10, 132, 0, 1),
            ipv4(10, 132, 0, 2),
            make_gre_header(
                detail::kEtherTypeMplsUnicast,
                make_mpls_payload_with_labels(
                    {16030U},
                    make_ipv4_payload_packet(
                        ipv4(10, 132, 1, 1),
                        ipv4(10, 132, 1, 2),
                        detail::kIpProtocolUdp,
                        make_ipv4_udp_segment(6302U, 53U, 1U)
                    )
                )
            )
        )),
        "EthernetII -> IPv4 -> GRE -> MPLS(label=16030) -> IPv4 -> UDP",
        StopReason::terminal_protocol
    );

    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(make_ethernet_frame_with_payload(
            detail::kEtherTypeMplsUnicast,
            make_mpls_payload_with_labels(
                {100U, 200U, 300U},
                make_ipv4_payload_packet(
                    ipv4(10, 133, 0, 1),
                    ipv4(10, 133, 0, 2),
                    detail::kIpProtocolUdp,
                    make_ipv4_udp_segment(7000U, 7001U, 1U)
                )
            )
        )),
        "EthernetII -> MPLS(label=100) -> MPLS(label=200) -> MPLS(label=300) -> IPv4 -> UDP",
        StopReason::terminal_protocol
    );

    {
        const auto deep_stack_packet = make_raw_packet(make_ethernet_frame_with_payload(
            detail::kEtherTypeMplsUnicast,
            make_mpls_payload_with_labels(
                {100U, 200U, 300U},
                make_ipv4_payload_packet(
                    ipv4(10, 133, 1, 1),
                    ipv4(10, 133, 1, 2),
                    detail::kIpProtocolUdp,
                    make_ipv4_udp_segment(7002U, 7003U, 1U)
                )
            )
        ));
        StepKindRecorder recorder {};
        const auto result = engine.run(
            registry,
            make_link_type_selector(deep_stack_packet.data_link_type),
            make_root_slice(deep_stack_packet),
            DissectionConsumer {.on_step = record_step_kind, .context = &recorder}
        );
        const std::vector<DissectionLayerKind> expected_kinds {
            DissectionLayerKind::ethernet_ii,
            DissectionLayerKind::mpls,
            DissectionLayerKind::mpls,
            DissectionLayerKind::mpls,
            DissectionLayerKind::ipv4,
            DissectionLayerKind::udp,
        };
        PFL_EXPECT(result.stop_reason == StopReason::terminal_protocol);
        PFL_EXPECT(recorder.kinds == expected_kinds);

        StepKindRecorder limited_recorder {};
        const auto limited_result = engine.run(
            registry,
            make_link_type_selector(deep_stack_packet.data_link_type),
            make_root_slice(deep_stack_packet),
            DissectionConsumer {.on_step = record_step_kind, .context = &limited_recorder},
            4U
        );
        const std::vector<DissectionLayerKind> expected_limited_kinds {
            DissectionLayerKind::ethernet_ii,
            DissectionLayerKind::mpls,
            DissectionLayerKind::mpls,
            DissectionLayerKind::mpls,
        };
        PFL_EXPECT(limited_result.stop_reason == StopReason::depth_limit);
        PFL_EXPECT(limited_recorder.kinds == expected_limited_kinds);
    }

    {
        const auto unknown_payload_shadow = run_shadow(make_raw_packet(make_ethernet_frame_with_payload(
            detail::kEtherTypeMplsUnicast,
            make_mpls_payload_with_labels({16060U}, {0x12U, 0x34U, 0x56U, 0x78U})
        )), registry);
        PFL_EXPECT(unknown_payload_shadow.outcome == ImportDissectionOutcome::unrecognized);
        PFL_EXPECT(unknown_payload_shadow.stop_reason == StopReason::truncated);
        PFL_EXPECT(format_shadow_path(unknown_payload_shadow) == "EthernetII -> MPLS(label=16060)");
    }

    {
        const auto missing_payload_shadow = run_shadow(make_raw_packet(make_ethernet_frame_with_payload(
            detail::kEtherTypeMplsUnicast,
            make_mpls_payload_with_labels({16061U}, {})
        )), registry);
        PFL_EXPECT(missing_payload_shadow.outcome == ImportDissectionOutcome::unrecognized);
        PFL_EXPECT(missing_payload_shadow.stop_reason == StopReason::no_payload);
        PFL_EXPECT(format_shadow_path(missing_payload_shadow) == "EthernetII -> MPLS(label=16061)");
    }

    {
        auto truncated_inner_ipv4 = make_ipv4_payload_packet(
            ipv4(10, 134, 0, 1),
            ipv4(10, 134, 0, 2),
            detail::kIpProtocolUdp,
            make_ipv4_udp_segment(7400U, 7401U, 1U)
        );
        truncated_inner_ipv4.resize(10U);
        const auto truncated_inner_shadow = run_shadow(
            make_raw_packet(
                make_ethernet_frame_with_payload(
                    detail::kEtherTypeMplsUnicast,
                    make_mpls_payload_with_labels({16062U}, truncated_inner_ipv4)
                ),
                14U + 4U + 20U
            ),
            registry
        );
        PFL_EXPECT(truncated_inner_shadow.outcome == ImportDissectionOutcome::unrecognized);
        PFL_EXPECT(truncated_inner_shadow.stop_reason == StopReason::truncated);
        PFL_EXPECT(format_shadow_path(truncated_inner_shadow) == "EthernetII -> MPLS(label=16062)");
    }

    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(make_ethernet_frame_with_payload(
            detail::kEtherTypeMplsUnicast,
            make_mpls_payload_with_labels(
                {16063U},
                strip_ethernet_header(make_ethernet_ipv4_fragment_packet(
                    ipv4(10, 134, 1, 1),
                    ipv4(10, 134, 1, 2),
                    detail::kIpProtocolUdp,
                    0x2000U,
                    {0xdeU, 0xadU, 0xbeU, 0xefU}
                ))
            )
        )),
        "EthernetII -> MPLS(label=16063) -> IPv4",
        StopReason::needs_reassembly
    );

    {
        const auto base_payload = make_ethernet_frame_with_payload(
            detail::kEtherTypeMplsUnicast,
            make_mpls_payload_with_labels(
                {17000U},
                make_ipv4_payload_packet(
                    ipv4(10, 135, 0, 1),
                    ipv4(10, 135, 0, 2),
                    detail::kIpProtocolUdp,
                    make_ipv4_udp_segment(7500U, 7501U, 1U)
                ),
                0U,
                64U
            )
        );
        const auto tc_ttl_variant = make_ethernet_frame_with_payload(
            detail::kEtherTypeMplsUnicast,
            make_mpls_payload_with_labels(
                {17000U},
                make_ipv4_payload_packet(
                    ipv4(10, 135, 0, 1),
                    ipv4(10, 135, 0, 2),
                    detail::kIpProtocolUdp,
                    make_ipv4_udp_segment(7500U, 7501U, 1U)
                ),
                5U,
                1U
            )
        );
        const auto different_label = make_ethernet_frame_with_payload(
            detail::kEtherTypeMplsUnicast,
            make_mpls_payload_with_labels(
                {17001U},
                make_ipv4_payload_packet(
                    ipv4(10, 135, 0, 1),
                    ipv4(10, 135, 0, 2),
                    detail::kIpProtocolUdp,
                    make_ipv4_udp_segment(7500U, 7501U, 1U)
                )
            )
        );
        const auto different_order = make_ethernet_frame_with_payload(
            detail::kEtherTypeMplsUnicast,
            make_mpls_payload_with_labels(
                {17002U, 17003U},
                make_ipv4_payload_packet(
                    ipv4(10, 135, 1, 1),
                    ipv4(10, 135, 1, 2),
                    detail::kIpProtocolUdp,
                    make_ipv4_udp_segment(7502U, 7503U, 1U)
                )
            )
        );
        const auto reversed_order = make_ethernet_frame_with_payload(
            detail::kEtherTypeMplsUnicast,
            make_mpls_payload_with_labels(
                {17003U, 17002U},
                make_ipv4_payload_packet(
                    ipv4(10, 135, 1, 1),
                    ipv4(10, 135, 1, 2),
                    detail::kIpProtocolUdp,
                    make_ipv4_udp_segment(7502U, 7503U, 1U)
                )
            )
        );

        const auto base_shadow = run_shadow(make_raw_packet(base_payload), registry);
        const auto tc_ttl_shadow = run_shadow(make_raw_packet(tc_ttl_variant), registry);
        const auto different_label_shadow = run_shadow(make_raw_packet(different_label), registry);
        const auto different_order_shadow = run_shadow(make_raw_packet(different_order), registry);
        const auto reversed_order_shadow = run_shadow(make_raw_packet(reversed_order), registry);

        PFL_EXPECT(shadow_path(base_shadow) == shadow_path(tc_ttl_shadow));
        PFL_EXPECT(format_shadow_path(base_shadow) == format_shadow_path(tc_ttl_shadow));
        PFL_EXPECT(shadow_path(base_shadow) != shadow_path(different_label_shadow));
        PFL_EXPECT(shadow_path(different_order_shadow) != shadow_path(reversed_order_shadow));
        PFL_EXPECT(format_shadow_path(different_order_shadow) == "EthernetII -> MPLS(label=17002) -> MPLS(label=17003) -> IPv4 -> UDP");
        PFL_EXPECT(format_shadow_path(reversed_order_shadow) == "EthernetII -> MPLS(label=17003) -> MPLS(label=17002) -> IPv4 -> UDP");
    }
}

void expect_gre_shadow_parsers_bounds_and_traversal() {
    const auto built = make_common_direct_registry();
    PFL_REQUIRE(built.ok());
    const auto& registry = *built.registry;
    const DissectionEngine engine {};

    const auto outer_ipv6_src = ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 31, 0, 0, 0, 0, 0, 0, 0, 0x11});
    const auto outer_ipv6_dst = ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 31, 0, 0, 0, 0, 0, 0, 0, 0x12});
    const auto inner_ipv6_src = ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 41, 0, 0, 0, 0, 0, 0, 0, 0x21});
    const auto inner_ipv6_dst = ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 41, 0, 0, 0, 0, 0, 0, 0, 0x22});

    {
        const auto exact_header_packet = make_raw_packet(make_gre_header(detail::kEtherTypeIpv4), detail::kGreBaseHeaderSize);
        const auto exact_header_root = make_root_slice(exact_header_packet);
        const auto exact_header = parse_gre_header(exact_header_root);
        PFL_EXPECT(exact_header.status == ParseStatus::complete);
        PFL_EXPECT(exact_header.flags_and_version == 0U);
        PFL_EXPECT(exact_header.protocol_type == detail::kEtherTypeIpv4);
        PFL_EXPECT(!exact_header.has_checksum);
        PFL_EXPECT(!exact_header.has_key);
        PFL_EXPECT(!exact_header.has_sequence);
        PFL_EXPECT(exact_header.header_length == detail::kGreBaseHeaderSize);

        const auto exact_header_step = dissect_gre(exact_header_root);
        PFL_EXPECT(exact_header_step.layer == DissectionLayerKind::gre);
        PFL_EXPECT(exact_header_step.status == ParseStatus::complete);
        PFL_EXPECT(exact_header_step.stop_reason == StopReason::none);
        PFL_REQUIRE(exact_header_step.path_contribution.has_value());
        PFL_EXPECT(*exact_header_step.path_contribution == LayerKey::gre());
        PFL_REQUIRE(exact_header_step.handoff.has_value());
        PFL_REQUIRE(exact_header_step.handoff->child.has_value());
        const ProtocolSelector expected_selector {
            .domain = SelectorDomain::gre_protocol_type,
            .value = detail::kEtherTypeIpv4,
        };
        PFL_EXPECT(exact_header_step.handoff->selector == expected_selector);
        PFL_EXPECT(exact_header_step.bounds.full.declared.length() == detail::kGreBaseHeaderSize);
        PFL_EXPECT(exact_header_step.bounds.full.captured.length() == detail::kGreBaseHeaderSize);
        PFL_EXPECT(exact_header_step.bounds.header.declared.length() == detail::kGreBaseHeaderSize);
        PFL_EXPECT(exact_header_step.bounds.header.captured.length() == detail::kGreBaseHeaderSize);
        PFL_REQUIRE(exact_header_step.bounds.payload.has_value());
        PFL_EXPECT(exact_header_step.bounds.payload->declared.length() == 0U);
        PFL_EXPECT(exact_header_step.bounds.payload->captured.length() == 0U);
        PFL_EXPECT(std::holds_alternative<GreFacts>(exact_header_step.facts));
        const auto* exact_header_facts = std::get_if<GreFacts>(&exact_header_step.facts);
        PFL_REQUIRE(exact_header_facts != nullptr);
        PFL_EXPECT(exact_header_facts->protocol_type == detail::kEtherTypeIpv4);
        PFL_EXPECT(exact_header_facts->header_length == detail::kGreBaseHeaderSize);
    }

    {
        const auto checksum_only = parse_gre_header(make_root_slice(make_raw_packet(
            make_gre_header(detail::kEtherTypeIpv4, {}, true, false, false),
            detail::kGreBaseHeaderSize + detail::kGreOptionalFieldSize
        )));
        PFL_EXPECT(checksum_only.status == ParseStatus::complete);
        PFL_EXPECT(checksum_only.has_checksum);
        PFL_EXPECT(checksum_only.checksum == 0x1234U);
        PFL_EXPECT(checksum_only.reserved1 == 0x5678U);
        PFL_EXPECT(checksum_only.header_length == detail::kGreBaseHeaderSize + detail::kGreOptionalFieldSize);
    }

    {
        const auto key_only_step = dissect_gre(make_root_slice(make_raw_packet(
            make_gre_header(detail::kEtherTypeIpv4, {}, false, true, false),
            detail::kGreBaseHeaderSize + detail::kGreOptionalFieldSize
        )));
        PFL_EXPECT(key_only_step.status == ParseStatus::complete);
        PFL_REQUIRE(key_only_step.path_contribution.has_value());
        PFL_EXPECT(*key_only_step.path_contribution == LayerKey::gre(0x11111111U));
        const auto* key_only_facts = std::get_if<GreFacts>(&key_only_step.facts);
        PFL_REQUIRE(key_only_facts != nullptr);
        PFL_EXPECT(key_only_facts->has_key);
        PFL_EXPECT(key_only_facts->key == 0x11111111U);
        PFL_EXPECT(key_only_facts->header_length == detail::kGreBaseHeaderSize + detail::kGreOptionalFieldSize);
    }

    {
        const auto sequence_only = parse_gre_header(make_root_slice(make_raw_packet(
            make_gre_header(detail::kEtherTypeIpv4, {}, false, false, true),
            detail::kGreBaseHeaderSize + detail::kGreOptionalFieldSize
        )));
        PFL_EXPECT(sequence_only.status == ParseStatus::complete);
        PFL_EXPECT(sequence_only.has_sequence);
        PFL_EXPECT(sequence_only.sequence_number == 0x01020304U);
        PFL_EXPECT(sequence_only.header_length == detail::kGreBaseHeaderSize + detail::kGreOptionalFieldSize);
    }

    {
        const auto full_optional_step = dissect_gre(make_root_slice(make_raw_packet(
            make_gre_header(detail::kEtherTypeIpv6, {}, true, true, true),
            detail::kGreBaseHeaderSize + (3U * detail::kGreOptionalFieldSize)
        )));
        PFL_EXPECT(full_optional_step.status == ParseStatus::complete);
        PFL_REQUIRE(full_optional_step.path_contribution.has_value());
        PFL_EXPECT(*full_optional_step.path_contribution == LayerKey::gre(0x11111111U));
        const auto* full_optional_facts = std::get_if<GreFacts>(&full_optional_step.facts);
        PFL_REQUIRE(full_optional_facts != nullptr);
        PFL_EXPECT(full_optional_facts->has_checksum);
        PFL_EXPECT(full_optional_facts->has_key);
        PFL_EXPECT(full_optional_facts->has_sequence);
        PFL_EXPECT(full_optional_facts->checksum == 0x1234U);
        PFL_EXPECT(full_optional_facts->reserved1 == 0x5678U);
        PFL_EXPECT(full_optional_facts->key == 0x11111111U);
        PFL_EXPECT(full_optional_facts->sequence_number == 0x01020304U);
        PFL_EXPECT(full_optional_facts->header_length == detail::kGreBaseHeaderSize + (3U * detail::kGreOptionalFieldSize));
    }

    {
        const auto zero_key_step = dissect_gre(make_root_slice(make_raw_packet(
            make_gre_header(detail::kEtherTypeIpv4, {}, false, true, false, 0U, 0x1234U, 0x5678U, 0U),
            detail::kGreBaseHeaderSize + detail::kGreOptionalFieldSize
        )));
        PFL_EXPECT(zero_key_step.status == ParseStatus::complete);
        PFL_REQUIRE(zero_key_step.path_contribution.has_value());
        PFL_EXPECT(*zero_key_step.path_contribution == LayerKey::gre(0U));
    }

    {
        const auto unsupported_version_step = dissect_gre(make_root_slice(make_raw_packet(
            make_gre_header(detail::kEtherTypeIpv4, {}, false, false, false, 0x0001U),
            detail::kGreBaseHeaderSize
        )));
        PFL_EXPECT(unsupported_version_step.status == ParseStatus::unsupported_variant);
        PFL_EXPECT(unsupported_version_step.stop_reason == StopReason::unsupported_variant);
        PFL_EXPECT(!unsupported_version_step.path_contribution.has_value());
        PFL_EXPECT(!unsupported_version_step.handoff.has_value());
    }

    {
        const auto unsupported_routing_step = dissect_gre(make_root_slice(make_raw_packet(
            make_gre_header(detail::kEtherTypeIpv4, {}, false, false, false, 0x4000U),
            detail::kGreBaseHeaderSize
        )));
        PFL_EXPECT(unsupported_routing_step.status == ParseStatus::unsupported_variant);
        PFL_EXPECT(unsupported_routing_step.stop_reason == StopReason::unsupported_variant);
        PFL_EXPECT(!unsupported_routing_step.path_contribution.has_value());
        PFL_EXPECT(!unsupported_routing_step.handoff.has_value());
    }

    {
        const auto malformed_short_step = dissect_gre(make_root_slice(make_raw_packet(
            {0x00, 0x00, 0x08},
            3U
        )));
        PFL_EXPECT(malformed_short_step.status == ParseStatus::malformed);
        PFL_EXPECT(!malformed_short_step.path_contribution.has_value());
        PFL_EXPECT(!malformed_short_step.handoff.has_value());
    }

    {
        auto truncated_base_bytes = make_gre_header(detail::kEtherTypeIpv4);
        truncated_base_bytes.resize(detail::kGreBaseHeaderSize - 1U);
        const auto truncated_base_step = dissect_gre(make_root_slice(make_raw_packet(
            truncated_base_bytes,
            detail::kGreBaseHeaderSize
        )));
        PFL_EXPECT(truncated_base_step.status == ParseStatus::truncated);
        PFL_EXPECT(!truncated_base_step.path_contribution.has_value());
        PFL_EXPECT(!truncated_base_step.handoff.has_value());
    }

    {
        const auto malformed_key_step = dissect_gre(make_root_slice(make_raw_packet(
            make_gre_header(detail::kEtherTypeIpv4, {}, false, true, false),
            detail::kGreBaseHeaderSize + 2U
        )));
        PFL_EXPECT(malformed_key_step.status == ParseStatus::malformed);
        PFL_EXPECT(!malformed_key_step.path_contribution.has_value());
    }

    {
        auto truncated_key_bytes = make_gre_header(detail::kEtherTypeIpv4, {}, false, true, false);
        truncated_key_bytes.resize(detail::kGreBaseHeaderSize + 2U);
        const auto truncated_key_step = dissect_gre(make_root_slice(make_raw_packet(
            truncated_key_bytes,
            detail::kGreBaseHeaderSize + detail::kGreOptionalFieldSize
        )));
        PFL_EXPECT(truncated_key_step.status == ParseStatus::truncated);
        PFL_EXPECT(!truncated_key_step.path_contribution.has_value());
    }

    {
        const auto malformed_sequence_step = dissect_gre(make_root_slice(make_raw_packet(
            make_gre_header(detail::kEtherTypeIpv4, {}, false, false, true),
            detail::kGreBaseHeaderSize + 2U
        )));
        PFL_EXPECT(malformed_sequence_step.status == ParseStatus::malformed);
        PFL_EXPECT(!malformed_sequence_step.path_contribution.has_value());
    }

    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(make_ethernet_ipv4_gre_packet(
            ipv4(10, 90, 0, 1),
            ipv4(10, 90, 0, 2),
            make_gre_header(
                detail::kEtherTypeIpv4,
                make_ipv4_payload_packet(
                    ipv4(172, 20, 0, 1),
                    ipv4(172, 20, 0, 2),
                    detail::kIpProtocolTcp,
                    make_ipv4_tcp_segment(12345U, 443U, 3U, 0x18U)
                )
            )
        )),
        "EthernetII -> IPv4 -> GRE -> IPv4 -> TCP",
        StopReason::terminal_protocol
    );
    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(make_ethernet_ipv4_gre_packet(
            ipv4(10, 90, 1, 1),
            ipv4(10, 90, 1, 2),
            make_gre_header(
                detail::kEtherTypeIpv4,
                make_ipv4_payload_packet(
                    ipv4(172, 20, 1, 1),
                    ipv4(172, 20, 1, 2),
                    detail::kIpProtocolUdp,
                    make_ipv4_udp_segment(5300U, 53U, 4U)
                )
            )
        )),
        "EthernetII -> IPv4 -> GRE -> IPv4 -> UDP",
        StopReason::terminal_protocol
    );
    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(make_ethernet_ipv4_gre_packet(
            ipv4(10, 90, 2, 1),
            ipv4(10, 90, 2, 2),
            make_gre_header(
                detail::kEtherTypeIpv6,
                make_ipv6_payload_packet(
                    inner_ipv6_src,
                    inner_ipv6_dst,
                    detail::kIpProtocolTcp,
                    make_ipv6_tcp_segment(23456U, 443U, 2U, 0x18U)
                )
            )
        )),
        "EthernetII -> IPv4 -> GRE -> IPv6 -> TCP",
        StopReason::terminal_protocol
    );
    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(make_ethernet_ipv4_gre_packet(
            ipv4(10, 90, 3, 1),
            ipv4(10, 90, 3, 2),
            make_gre_header(
                detail::kEtherTypeIpv6,
                make_ipv6_payload_packet(
                    inner_ipv6_src,
                    inner_ipv6_dst,
                    detail::kIpProtocolUdp,
                    make_ipv6_udp_segment(5301U, 5302U, 3U)
                )
            )
        )),
        "EthernetII -> IPv4 -> GRE -> IPv6 -> UDP",
        StopReason::terminal_protocol
    );
    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(make_ethernet_ipv6_gre_packet(
            outer_ipv6_src,
            outer_ipv6_dst,
            make_gre_header(
                detail::kEtherTypeIpv4,
                make_ipv4_payload_packet(
                    ipv4(172, 20, 4, 1),
                    ipv4(172, 20, 4, 2),
                    detail::kIpProtocolTcp,
                    make_ipv4_tcp_segment(34567U, 8443U, 1U, 0x18U)
                )
            )
        )),
        "EthernetII -> IPv6 -> GRE -> IPv4 -> TCP",
        StopReason::terminal_protocol
    );
    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(make_ethernet_ipv6_gre_packet(
            outer_ipv6_src,
            outer_ipv6_dst,
            make_gre_header(
                detail::kEtherTypeIpv6,
                make_ipv6_payload_packet(
                    inner_ipv6_src,
                    inner_ipv6_dst,
                    detail::kIpProtocolUdp,
                    make_ipv6_udp_segment(6300U, 6301U, 2U)
                )
            )
        )),
        "EthernetII -> IPv6 -> GRE -> IPv6 -> UDP",
        StopReason::terminal_protocol
    );
    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(make_ethernet_ipv4_gre_packet(
            ipv4(10, 90, 5, 1),
            ipv4(10, 90, 5, 2),
            make_gre_header(
                detail::kEtherTypeIpv4,
                make_ipv4_payload_packet(
                    ipv4(172, 20, 5, 1),
                    ipv4(172, 20, 5, 2),
                    detail::kIpProtocolSctp,
                    make_sctp_segment(49152U, 36412U, 0x01020304U, 0x89ABCDEFU, 2U)
                )
            )
        )),
        "EthernetII -> IPv4 -> GRE -> IPv4 -> SCTP",
        StopReason::terminal_protocol
    );

    {
        const auto outer_hbh_gre_udp = make_raw_packet(make_ethernet_ipv6_packet(
            outer_ipv6_src,
            outer_ipv6_dst,
            detail::kIpProtocolHopByHop,
            make_ipv6_hop_by_hop_extension(
                detail::kIpProtocolGre,
                make_gre_header(
                    detail::kEtherTypeIpv4,
                    make_ipv4_payload_packet(
                        ipv4(172, 20, 6, 1),
                        ipv4(172, 20, 6, 2),
                        detail::kIpProtocolUdp,
                        make_ipv4_udp_segment(7000U, 7001U, 2U)
                    )
                )
            )
        ));
        expect_shadow_matches_legacy_flow(
            registry,
            outer_hbh_gre_udp,
            "EthernetII -> IPv6 -> GRE -> IPv4 -> UDP",
            StopReason::terminal_protocol
        );
    }

    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(add_vlan_tags(
            make_ethernet_ipv4_gre_packet(
                ipv4(10, 90, 7, 1),
                ipv4(10, 90, 7, 2),
                make_gre_header(
                    detail::kEtherTypeIpv4,
                    make_ipv4_payload_packet(
                        ipv4(172, 20, 7, 1),
                        ipv4(172, 20, 7, 2),
                        detail::kIpProtocolUdp,
                        make_ipv4_udp_segment(7100U, 7101U, 1U)
                    )
                )
            ),
            {{0x8100U, 330U}}
        )),
        "EthernetII -> VLAN(vid=330) -> IPv4 -> GRE -> IPv4 -> UDP",
        StopReason::terminal_protocol
    );
    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(add_vlan_tags(
            make_ethernet_ipv4_gre_packet(
                ipv4(10, 90, 8, 1),
                ipv4(10, 90, 8, 2),
                make_gre_header(
                    detail::kEtherTypeIpv4,
                    make_ipv4_payload_packet(
                        ipv4(172, 20, 8, 1),
                        ipv4(172, 20, 8, 2),
                        detail::kIpProtocolTcp,
                        make_ipv4_tcp_segment(7200U, 7201U, 1U, 0x18U)
                    )
                )
            ),
            {{0x88A8U, 331U}, {0x8100U, 330U}}
        )),
        "EthernetII -> VLAN(vid=331) -> VLAN(vid=330) -> IPv4 -> GRE -> IPv4 -> TCP",
        StopReason::terminal_protocol
    );
    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(make_ethernet_ipv4_gre_packet(
            ipv4(10, 90, 9, 1),
            ipv4(10, 90, 9, 2),
            make_gre_header(
                detail::kGreProtocolTypeTransparentEthernetBridging,
                make_ethernet_ipv4_tcp_packet(ipv4(192, 0, 2, 1), ipv4(192, 0, 2, 2), 7300U, 7301U)
            )
        )),
        "EthernetII -> IPv4 -> GRE -> EthernetII -> IPv4 -> TCP",
        StopReason::terminal_protocol
    );
    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(make_ethernet_ipv4_gre_packet(
            ipv4(10, 90, 10, 1),
            ipv4(10, 90, 10, 2),
            make_gre_header(
                detail::kGreProtocolTypeTransparentEthernetBridging,
                add_vlan_tags(
                    make_ethernet_ipv4_udp_packet(ipv4(192, 0, 2, 11), ipv4(192, 0, 2, 12), 7400U, 7401U),
                    {{0x8100U, 130U}}
                )
            )
        )),
        "EthernetII -> IPv4 -> GRE -> EthernetII -> VLAN(vid=130) -> IPv4 -> UDP",
        StopReason::terminal_protocol
    );

    {
        const auto gre_icmp_shadow = run_shadow(make_raw_packet(make_ethernet_ipv4_gre_packet(
            ipv4(10, 91, 0, 1),
            ipv4(10, 91, 0, 2),
            make_gre_header(
                detail::kEtherTypeIpv4,
                strip_ethernet_header(make_ethernet_ipv4_icmp_packet(
                    ipv4(172, 21, 0, 1),
                    ipv4(172, 21, 0, 2),
                    8U,
                    0U
                ))
            )
        )), registry);
        PFL_EXPECT(gre_icmp_shadow.outcome == ImportDissectionOutcome::recognized_flow);
        PFL_EXPECT(gre_icmp_shadow.stop_reason == StopReason::terminal_protocol);
        PFL_EXPECT(gre_icmp_shadow.terminal_protocol == ProtocolId::icmp);
        PFL_EXPECT(!gre_icmp_shadow.has_ports);
        PFL_EXPECT(format_shadow_path(gre_icmp_shadow) == "EthernetII -> IPv4 -> GRE -> IPv4 -> ICMP");
    }

    {
        const auto gre_icmpv6_shadow = run_shadow(make_raw_packet(make_ethernet_ipv4_gre_packet(
            ipv4(10, 91, 1, 1),
            ipv4(10, 91, 1, 2),
            make_gre_header(
                detail::kEtherTypeIpv6,
                make_ipv6_payload_packet(
                    inner_ipv6_src,
                    inner_ipv6_dst,
                    detail::kIpProtocolIcmpV6,
                    make_ipv6_icmpv6_message(128U, 0U)
                )
            )
        )), registry);
        PFL_EXPECT(gre_icmpv6_shadow.outcome == ImportDissectionOutcome::recognized_flow);
        PFL_EXPECT(gre_icmpv6_shadow.stop_reason == StopReason::terminal_protocol);
        PFL_EXPECT(gre_icmpv6_shadow.terminal_protocol == ProtocolId::icmpv6);
        PFL_EXPECT(!gre_icmpv6_shadow.has_ports);
        PFL_EXPECT(format_shadow_path(gre_icmpv6_shadow) == "EthernetII -> IPv4 -> GRE -> IPv6 -> ICMPv6");
    }

    {
        const auto gre_igmp_shadow = run_shadow(make_raw_packet(make_ethernet_ipv4_gre_packet(
            ipv4(10, 91, 2, 1),
            ipv4(10, 91, 2, 2),
            make_gre_header(
                detail::kEtherTypeIpv4,
                strip_ethernet_header(make_ethernet_ipv4_igmp_packet(
                    ipv4(172, 21, 2, 1),
                    ipv4(239, 1, 1, 1),
                    detail::kIgmpTypeV2MembershipReport,
                    0U,
                    0x1234U,
                    ipv4(239, 1, 1, 1)
                ))
            )
        )), registry);
        PFL_EXPECT(gre_igmp_shadow.outcome == ImportDissectionOutcome::recognized_flow);
        PFL_EXPECT(gre_igmp_shadow.stop_reason == StopReason::terminal_protocol);
        PFL_EXPECT(gre_igmp_shadow.terminal_protocol == ProtocolId::igmp);
        PFL_EXPECT(!gre_igmp_shadow.has_ports);
        PFL_EXPECT(gre_igmp_shadow.has_flow_addresses);
        PFL_EXPECT(gre_igmp_shadow.dst_addr_v4 == ipv4(239, 1, 1, 1));
        PFL_EXPECT(format_shadow_path(gre_igmp_shadow) == "EthernetII -> IPv4 -> GRE -> IPv4");
    }

    {
        const auto gre_esp_shadow = run_shadow(make_raw_packet(make_ethernet_ipv4_gre_packet(
            ipv4(10, 91, 3, 1),
            ipv4(10, 91, 3, 2),
            make_gre_header(
                detail::kEtherTypeIpv4,
                make_ipv4_payload_packet(
                    ipv4(172, 21, 3, 1),
                    ipv4(172, 21, 3, 2),
                    detail::kIpProtocolEsp,
                    make_esp_header(0x01020304U, 0x11121314U, {0xde, 0xad})
                )
            )
        )), registry);
        PFL_EXPECT(gre_esp_shadow.outcome == ImportDissectionOutcome::recognized_flow);
        PFL_EXPECT(gre_esp_shadow.stop_reason == StopReason::terminal_protocol);
        PFL_EXPECT(gre_esp_shadow.terminal_protocol == ProtocolId::esp);
        PFL_EXPECT(!gre_esp_shadow.has_ports);
        PFL_EXPECT(format_shadow_path(gre_esp_shadow) == "EthernetII -> IPv4 -> GRE -> IPv4 -> ESP(spi=0x01020304)");
    }

    {
        const auto unknown_inner_shadow = run_shadow(make_raw_packet(make_ethernet_ipv4_gre_packet(
            ipv4(10, 92, 0, 1),
            ipv4(10, 92, 0, 2),
            make_gre_header(0x1234U, {0xde, 0xad, 0xbe, 0xef})
        )), registry);
        PFL_EXPECT(unknown_inner_shadow.outcome == ImportDissectionOutcome::unrecognized);
        PFL_EXPECT(unknown_inner_shadow.stop_reason == StopReason::unknown_next_protocol);
        PFL_EXPECT(unknown_inner_shadow.terminal_protocol == ProtocolId::unknown);
        PFL_EXPECT(format_shadow_path(unknown_inner_shadow) == "EthernetII -> IPv4 -> GRE");
    }

    {
        const auto gre_mpls_shadow = run_shadow(make_raw_packet(make_ethernet_ipv4_gre_packet(
            ipv4(10, 92, 1, 1),
            ipv4(10, 92, 1, 2),
            make_gre_header(
                detail::kEtherTypeMplsUnicast,
                make_mpls_payload_with_labels(
                    {16030U},
                    make_ipv4_payload_packet(
                        ipv4(172, 21, 4, 1),
                        ipv4(172, 21, 4, 2),
                        detail::kIpProtocolUdp,
                        make_ipv4_udp_segment(7600U, 7601U, 1U)
                    )
                )
            )
        )), registry);
        PFL_EXPECT(gre_mpls_shadow.outcome == ImportDissectionOutcome::recognized_flow);
        PFL_EXPECT(gre_mpls_shadow.stop_reason == StopReason::terminal_protocol);
        PFL_EXPECT(gre_mpls_shadow.terminal_protocol == ProtocolId::udp);
        PFL_EXPECT(gre_mpls_shadow.has_ports);
        PFL_EXPECT(gre_mpls_shadow.src_port == 7600U);
        PFL_EXPECT(gre_mpls_shadow.dst_port == 7601U);
        PFL_EXPECT(format_shadow_path(gre_mpls_shadow) == "EthernetII -> IPv4 -> GRE -> MPLS(label=16030) -> IPv4 -> UDP");
    }

    {
        auto truncated_inner_ipv4 = make_ipv4_payload_packet(
            ipv4(172, 22, 0, 1),
            ipv4(172, 22, 0, 2),
            detail::kIpProtocolUdp,
            make_ipv4_udp_segment(7500U, 7501U, 1U)
        );
        truncated_inner_ipv4.resize(10U);
        const auto truncated_inner_shadow = run_shadow(make_raw_packet(make_ethernet_ipv4_gre_packet(
            ipv4(10, 92, 2, 1),
            ipv4(10, 92, 2, 2),
            make_gre_header(detail::kEtherTypeIpv4, truncated_inner_ipv4)
        ), 14U + 20U + detail::kGreBaseHeaderSize + 20U), registry);
        PFL_EXPECT(truncated_inner_shadow.outcome == ImportDissectionOutcome::unrecognized);
        PFL_EXPECT(truncated_inner_shadow.stop_reason == StopReason::truncated);
        PFL_EXPECT(format_shadow_path(truncated_inner_shadow) == "EthernetII -> IPv4 -> GRE");
        PFL_EXPECT(!truncated_inner_shadow.has_ports);
    }

    {
        const auto outer_ipv4_fragment_shadow = run_shadow(make_raw_packet(make_ethernet_ipv4_gre_packet(
            ipv4(10, 92, 3, 1),
            ipv4(10, 92, 3, 2),
            make_gre_header(detail::kEtherTypeIpv4, {0xde, 0xad, 0xbe, 0xef}),
            0x2000U
        )), registry);
        PFL_EXPECT(outer_ipv4_fragment_shadow.outcome == ImportDissectionOutcome::unrecognized);
        PFL_EXPECT(outer_ipv4_fragment_shadow.stop_reason == StopReason::needs_reassembly);
        PFL_EXPECT(format_shadow_path(outer_ipv4_fragment_shadow) == "EthernetII -> IPv4");
    }

    {
        const auto outer_ipv6_fragment_shadow = run_shadow(make_raw_packet(make_ethernet_ipv6_fragment_packet(
            outer_ipv6_src,
            outer_ipv6_dst,
            detail::kIpProtocolGre,
            make_gre_header(detail::kEtherTypeIpv4, {0xde, 0xad, 0xbe, 0xef})
        )), registry);
        PFL_EXPECT(outer_ipv6_fragment_shadow.outcome == ImportDissectionOutcome::unrecognized);
        PFL_EXPECT(outer_ipv6_fragment_shadow.stop_reason == StopReason::needs_reassembly);
        PFL_EXPECT(format_shadow_path(outer_ipv6_fragment_shadow) == "EthernetII -> IPv6");
    }

    {
        const auto inner_fragment_shadow = run_shadow(make_raw_packet(make_ethernet_ipv4_gre_packet(
            ipv4(10, 92, 4, 1),
            ipv4(10, 92, 4, 2),
            make_gre_header(
                detail::kEtherTypeIpv4,
                make_ipv4_payload_packet(
                    ipv4(172, 22, 4, 1),
                    ipv4(172, 22, 4, 2),
                    detail::kIpProtocolUdp,
                    make_ipv4_udp_segment(7600U, 7601U, 2U),
                    0x2000U
                )
            )
        )), registry);
        PFL_EXPECT(inner_fragment_shadow.outcome == ImportDissectionOutcome::recognized_flow);
        PFL_EXPECT(inner_fragment_shadow.stop_reason == StopReason::needs_reassembly);
        PFL_EXPECT(inner_fragment_shadow.terminal_protocol == ProtocolId::udp);
        PFL_EXPECT(format_shadow_path(inner_fragment_shadow) == "EthernetII -> IPv4 -> GRE -> IPv4");
        PFL_EXPECT(!inner_fragment_shadow.has_ports);
    }

    {
        auto nested_gre_payload = make_gre_header(
            detail::kEtherTypeIpv6,
            make_ipv6_payload_packet(
                inner_ipv6_src,
                inner_ipv6_dst,
                detail::kIpProtocolUdp,
                make_ipv6_udp_segment(7700U, 7701U, 1U)
            )
        );
        nested_gre_payload = make_gre_header(
            detail::kEtherTypeIpv4,
            make_ipv4_payload_packet(
                ipv4(172, 22, 5, 1),
                ipv4(172, 22, 5, 2),
                detail::kIpProtocolGre,
                nested_gre_payload
            )
        );
        const auto nested_gre_packet = make_raw_packet(make_ethernet_ipv4_gre_packet(
            ipv4(10, 92, 5, 1),
            ipv4(10, 92, 5, 2),
            nested_gre_payload
        ));
        const auto nested_gre_shadow = run_shadow(nested_gre_packet, registry);
        PFL_EXPECT(nested_gre_shadow.outcome == ImportDissectionOutcome::recognized_flow);
        PFL_EXPECT(nested_gre_shadow.stop_reason == StopReason::terminal_protocol);
        PFL_EXPECT(format_shadow_path(nested_gre_shadow) == "EthernetII -> IPv4 -> GRE -> IPv4 -> GRE -> IPv6 -> UDP");

        StepKindRecorder nested_gre_recorder {};
        const auto nested_gre_depth_result = engine.run(
            registry,
            make_link_type_selector(nested_gre_packet.data_link_type),
            make_root_slice(nested_gre_packet),
            DissectionConsumer {.on_step = record_step_kind, .context = &nested_gre_recorder},
            5U
        );
        const std::vector<DissectionLayerKind> expected_nested_gre_kinds {
            DissectionLayerKind::ethernet_ii,
            DissectionLayerKind::ipv4,
            DissectionLayerKind::gre,
            DissectionLayerKind::ipv4,
            DissectionLayerKind::gre,
        };
        PFL_EXPECT(nested_gre_depth_result.stop_reason == StopReason::depth_limit);
        PFL_EXPECT(nested_gre_recorder.kinds == expected_nested_gre_kinds);
    }

    {
        const auto first_key_shadow = run_shadow(make_raw_packet(make_ethernet_ipv4_gre_packet(
            ipv4(10, 93, 0, 1),
            ipv4(10, 93, 0, 2),
            make_gre_header(
                detail::kEtherTypeIpv4,
                make_ipv4_payload_packet(
                    ipv4(172, 23, 0, 1),
                    ipv4(172, 23, 0, 2),
                    detail::kIpProtocolUdp,
                    make_ipv4_udp_segment(7800U, 7801U, 1U)
                ),
                false,
                true,
                false,
                0U,
                0x1234U,
                0x5678U,
                0x11111111U
            )
        )), registry);
        const auto second_key_shadow = run_shadow(make_raw_packet(make_ethernet_ipv4_gre_packet(
            ipv4(10, 93, 0, 1),
            ipv4(10, 93, 0, 2),
            make_gre_header(
                detail::kEtherTypeIpv4,
                make_ipv4_payload_packet(
                    ipv4(172, 23, 0, 1),
                    ipv4(172, 23, 0, 2),
                    detail::kIpProtocolUdp,
                    make_ipv4_udp_segment(7800U, 7801U, 1U)
                ),
                false,
                true,
                false,
                0U,
                0x1234U,
                0x5678U,
                0x22222222U
            )
        )), registry);
        const auto repeated_first_key_shadow = run_shadow(make_raw_packet(make_ethernet_ipv4_gre_packet(
            ipv4(10, 93, 0, 1),
            ipv4(10, 93, 0, 2),
            make_gre_header(
                detail::kEtherTypeIpv4,
                make_ipv4_payload_packet(
                    ipv4(172, 23, 0, 1),
                    ipv4(172, 23, 0, 2),
                    detail::kIpProtocolUdp,
                    make_ipv4_udp_segment(7800U, 7801U, 1U)
                ),
                false,
                true,
                false,
                0U,
                0x1234U,
                0x5678U,
                0x11111111U
            )
        )), registry);

        const auto first_key_path = shadow_path(first_key_shadow);
        const auto second_key_path = shadow_path(second_key_shadow);
        const auto repeated_first_key_path = shadow_path(repeated_first_key_shadow);
        PFL_EXPECT(format_protocol_path(first_key_path) == "EthernetII -> IPv4 -> GRE(key=0x11111111) -> IPv4 -> UDP");
        PFL_EXPECT(format_protocol_path(second_key_path) == "EthernetII -> IPv4 -> GRE(key=0x22222222) -> IPv4 -> UDP");
        PFL_EXPECT(first_key_path == repeated_first_key_path);
        PFL_EXPECT(!(first_key_path == second_key_path));

        ProtocolPathRegistry registry_ids {};
        const auto first_key_id = registry_ids.intern(first_key_path);
        const auto second_key_id = registry_ids.intern(second_key_path);
        const auto repeated_first_key_id = registry_ids.intern(repeated_first_key_path);
        PFL_EXPECT(first_key_id != kInvalidProtocolPathId);
        PFL_EXPECT(second_key_id != kInvalidProtocolPathId);
        PFL_EXPECT(first_key_id != second_key_id);
        PFL_EXPECT(first_key_id == repeated_first_key_id);
    }
}


void expect_plain_ip_encapsulation_is_registry_driven() {
    const auto built = make_common_direct_registry();
    PFL_REQUIRE(built.ok());
    const auto& registry = *built.registry;
    const auto outer_ipv6_src = ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0x11});
    const auto outer_ipv6_dst = ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0x22});
    const auto inner_ipv6_src = ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0x33});
    const auto inner_ipv6_dst = ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0x44});

    const auto deepest_udp_inner_ipv4 = make_ipv4_payload_packet(
        ipv4(198, 51, 100, 10),
        ipv4(198, 51, 100, 11),
        detail::kIpProtocolUdp,
        make_ipv6_udp_segment(41000U, 53U, 3U)
    );
    const auto middle_ipv6_with_inner_ipv4 = make_ipv6_payload_packet(
        inner_ipv6_src,
        inner_ipv6_dst,
        detail::kIpProtocolIpv4Encapsulation,
        deepest_udp_inner_ipv4
    );
    const auto multi_nested_packet = make_raw_packet(make_ethernet_ipv4_fragment_packet(
        ipv4(203, 0, 113, 1),
        ipv4(203, 0, 113, 2),
        detail::kIpProtocolIpv6Encapsulation,
        0U,
        middle_ipv6_with_inner_ipv4
    ));
    const auto multi_nested_root = make_root_slice(multi_nested_packet);
    const auto multi_nested_ethernet = dissect_ethernet(multi_nested_root);
    PFL_REQUIRE(multi_nested_ethernet.handoff.has_value());
    PFL_REQUIRE(multi_nested_ethernet.handoff->child.has_value());
    PFL_EXPECT(multi_nested_ethernet.handoff->child->source_id() == multi_nested_root.source_id());
    PFL_EXPECT(multi_nested_ethernet.handoff->child->source_offset() == 14U);

    const auto multi_nested_outer_ipv4 = dissect_ipv4(*multi_nested_ethernet.handoff->child);
    PFL_REQUIRE(multi_nested_outer_ipv4.handoff.has_value());
    PFL_REQUIRE(multi_nested_outer_ipv4.handoff->child.has_value());
    PFL_EXPECT(multi_nested_outer_ipv4.handoff->selector.domain == SelectorDomain::ip_protocol);
    PFL_EXPECT(multi_nested_outer_ipv4.handoff->selector.value == detail::kIpProtocolIpv6Encapsulation);
    PFL_EXPECT(multi_nested_outer_ipv4.handoff->child->source_id() == multi_nested_root.source_id());
    PFL_EXPECT(multi_nested_outer_ipv4.handoff->child->source_offset() == 34U);
    PFL_EXPECT(multi_nested_outer_ipv4.handoff->child->captured_end() == multi_nested_outer_ipv4.handoff->child->declared_end());
    PFL_EXPECT(multi_nested_outer_ipv4.handoff->child->declared_end() <= multi_nested_ethernet.handoff->child->declared_end());
    PFL_EXPECT(multi_nested_outer_ipv4.handoff->child->captured_end() <= multi_nested_ethernet.handoff->child->captured_end());

    const auto multi_nested_inner_ipv6 = dissect_ipv6(*multi_nested_outer_ipv4.handoff->child);
    PFL_REQUIRE(multi_nested_inner_ipv6.handoff.has_value());
    PFL_REQUIRE(multi_nested_inner_ipv6.handoff->child.has_value());
    PFL_EXPECT(multi_nested_inner_ipv6.handoff->selector.domain == SelectorDomain::ipv6_next_header);
    PFL_EXPECT(multi_nested_inner_ipv6.handoff->selector.value == detail::kIpProtocolIpv4Encapsulation);
    PFL_EXPECT(multi_nested_inner_ipv6.handoff->child->source_id() == multi_nested_root.source_id());
    PFL_EXPECT(multi_nested_inner_ipv6.handoff->child->source_offset() == 74U);
    PFL_EXPECT(multi_nested_inner_ipv6.handoff->child->captured_end() == multi_nested_inner_ipv6.handoff->child->declared_end());
    PFL_EXPECT(multi_nested_inner_ipv6.handoff->child->declared_end() <= multi_nested_outer_ipv4.handoff->child->declared_end());
    PFL_EXPECT(multi_nested_inner_ipv6.handoff->child->captured_end() <= multi_nested_outer_ipv4.handoff->child->captured_end());

    const auto multi_nested_inner_ipv4 = dissect_ipv4(*multi_nested_inner_ipv6.handoff->child);
    PFL_REQUIRE(multi_nested_inner_ipv4.handoff.has_value());
    PFL_REQUIRE(multi_nested_inner_ipv4.handoff->child.has_value());
    PFL_EXPECT(multi_nested_inner_ipv4.handoff->selector.domain == SelectorDomain::ip_protocol);
    PFL_EXPECT(multi_nested_inner_ipv4.handoff->selector.value == detail::kIpProtocolUdp);
    PFL_EXPECT(multi_nested_inner_ipv4.handoff->child->source_id() == multi_nested_root.source_id());
    PFL_EXPECT(multi_nested_inner_ipv4.handoff->child->source_offset() == 94U);
    PFL_EXPECT(multi_nested_inner_ipv4.handoff->child->declared_end() <= multi_nested_inner_ipv6.handoff->child->declared_end());

    const auto multi_nested_udp = dissect_udp(*multi_nested_inner_ipv4.handoff->child);
    PFL_EXPECT(multi_nested_udp.status == ParseStatus::complete);
    PFL_REQUIRE(multi_nested_udp.bounds.payload.has_value());
    PFL_EXPECT(multi_nested_udp.bounds.source_id == multi_nested_root.source_id());
    PFL_EXPECT(multi_nested_udp.bounds.payload->captured.length() == 3U);

    StepKindRecorder multi_nested_recorder {};
    const DissectionEngine engine {};
    const auto multi_nested_result = engine.run(
        registry,
        make_link_type_selector(multi_nested_packet.data_link_type),
        multi_nested_root,
        DissectionConsumer {.on_step = record_step_kind, .context = &multi_nested_recorder}
    );
    PFL_EXPECT(multi_nested_result.stop_reason == StopReason::terminal_protocol);
    const std::vector<DissectionLayerKind> expected_multi_nested_kinds {
        DissectionLayerKind::ethernet_ii,
        DissectionLayerKind::ipv4,
        DissectionLayerKind::ipv6,
        DissectionLayerKind::ipv4,
        DissectionLayerKind::udp,
    };
    PFL_EXPECT(multi_nested_recorder.kinds == expected_multi_nested_kinds);

    const auto multi_nested_shadow = run_shadow(multi_nested_packet, registry);
    PFL_EXPECT(multi_nested_shadow.outcome == ImportDissectionOutcome::recognized_flow);
    PFL_EXPECT(multi_nested_shadow.stop_reason == StopReason::terminal_protocol);
    PFL_EXPECT(multi_nested_shadow.family == DissectionAddressFamily::ipv4);
    PFL_EXPECT(multi_nested_shadow.terminal_protocol == ProtocolId::udp);
    PFL_EXPECT(multi_nested_shadow.src_addr_v4 == ipv4(198, 51, 100, 10));
    PFL_EXPECT(multi_nested_shadow.dst_addr_v4 == ipv4(198, 51, 100, 11));
    PFL_EXPECT(multi_nested_shadow.has_ports);
    PFL_EXPECT(multi_nested_shadow.src_port == 41000U);
    PFL_EXPECT(multi_nested_shadow.dst_port == 53U);
    PFL_EXPECT(multi_nested_shadow.has_transport_payload_length);
    PFL_EXPECT(multi_nested_shadow.captured_transport_payload_length == 3U);
    PFL_EXPECT(format_shadow_path(multi_nested_shadow) == "EthernetII -> IPv4 -> IPv6 -> IPv4 -> UDP");

    const auto extension_inner_sctp_packet = make_raw_packet(make_ethernet_ipv6_packet(
        outer_ipv6_src,
        outer_ipv6_dst,
        detail::kIpProtocolHopByHop,
        make_ipv6_hop_by_hop_extension(
            detail::kIpProtocolIpv4Encapsulation,
            make_ipv4_payload_packet(
                ipv4(10, 77, 0, 1),
                ipv4(10, 77, 0, 2),
                detail::kIpProtocolSctp,
                make_sctp_segment(2905U, 2906U, 0x11223344U, 0x55667788U, 2U)
            )
        )
    ));
    StepKindRecorder extension_sctp_recorder {};
    const auto extension_sctp_result = engine.run(
        registry,
        make_link_type_selector(extension_inner_sctp_packet.data_link_type),
        make_root_slice(extension_inner_sctp_packet),
        DissectionConsumer {.on_step = record_step_kind, .context = &extension_sctp_recorder}
    );
    PFL_EXPECT(extension_sctp_result.stop_reason == StopReason::terminal_protocol);
    const std::vector<DissectionLayerKind> expected_extension_sctp_kinds {
        DissectionLayerKind::ethernet_ii,
        DissectionLayerKind::ipv6,
        DissectionLayerKind::ipv6_hop_by_hop,
        DissectionLayerKind::ipv4,
        DissectionLayerKind::sctp,
    };
    PFL_EXPECT(extension_sctp_recorder.kinds == expected_extension_sctp_kinds);
    const auto extension_sctp_shadow = run_shadow(extension_inner_sctp_packet, registry);
    PFL_EXPECT(extension_sctp_shadow.outcome == ImportDissectionOutcome::recognized_flow);
    PFL_EXPECT(extension_sctp_shadow.family == DissectionAddressFamily::ipv4);
    PFL_EXPECT(extension_sctp_shadow.terminal_protocol == ProtocolId::sctp);
    PFL_EXPECT(extension_sctp_shadow.src_addr_v4 == ipv4(10, 77, 0, 1));
    PFL_EXPECT(extension_sctp_shadow.dst_addr_v4 == ipv4(10, 77, 0, 2));
    PFL_EXPECT(extension_sctp_shadow.has_ports);
    PFL_EXPECT(extension_sctp_shadow.src_port == 2905U);
    PFL_EXPECT(extension_sctp_shadow.dst_port == 2906U);
    PFL_EXPECT(extension_sctp_shadow.has_transport_payload_length);
    PFL_EXPECT(extension_sctp_shadow.captured_transport_payload_length == 2U);
    PFL_EXPECT(format_shadow_path(extension_sctp_shadow) == "EthernetII -> IPv6 -> IPv4 -> SCTP");

    expect_shadow_matches_legacy_portless_flow(
        registry,
        make_raw_packet(make_ethernet_ipv4_fragment_packet(
            ipv4(203, 0, 113, 70),
            ipv4(203, 0, 113, 71),
            detail::kIpProtocolIpv4Encapsulation,
            0U,
            make_ipv4_payload_packet(
                ipv4(10, 78, 0, 1),
                ipv4(10, 78, 0, 2),
                detail::kIpProtocolIcmp,
                {8U, 0U, 0x12U, 0x34U, 0xAAU, 0xBBU, 0xCCU, 0xDDU}
            )
        )),
        "EthernetII -> IPv4 -> IPv4 -> ICMP",
        "EthernetII -> IPv4 -> IPv4",
        StopReason::terminal_protocol
    );

    expect_shadow_matches_legacy_portless_flow(
        registry,
        make_raw_packet(make_ethernet_ipv4_fragment_packet(
            ipv4(203, 0, 113, 72),
            ipv4(203, 0, 113, 73),
            detail::kIpProtocolIpv6Encapsulation,
            0U,
            make_ipv6_payload_packet(
                inner_ipv6_src,
                inner_ipv6_dst,
                detail::kIpProtocolIcmpV6,
                make_ipv6_icmpv6_message(128U, 0U)
            )
        )),
        "EthernetII -> IPv4 -> IPv6 -> ICMPv6",
        "EthernetII -> IPv4 -> IPv6",
        StopReason::terminal_protocol
    );

    expect_shadow_matches_legacy_portless_flow(
        registry,
        make_raw_packet(make_ethernet_ipv4_fragment_packet(
            ipv4(203, 0, 113, 74),
            ipv4(203, 0, 113, 75),
            detail::kIpProtocolIpv6Encapsulation,
            0U,
            make_ipv6_payload_packet(
                inner_ipv6_src,
                inner_ipv6_dst,
                detail::kIpProtocolHopByHop,
                make_ipv6_hop_by_hop_extension(detail::kIpProtocolIcmpV6, make_ipv6_icmpv6_message(129U, 1U))
            )
        )),
        "EthernetII -> IPv4 -> IPv6 -> ICMPv6",
        "EthernetII -> IPv4 -> IPv6",
        StopReason::terminal_protocol
    );

    const auto inner_ipv6_routing_packet = make_raw_packet(make_ethernet_ipv4_fragment_packet(
        ipv4(203, 0, 113, 12),
        ipv4(203, 0, 113, 13),
        detail::kIpProtocolIpv6Encapsulation,
        0U,
        make_ipv6_payload_packet(
            inner_ipv6_src,
            inner_ipv6_dst,
            detail::kIpProtocolRouting,
            make_ipv6_routing_extension(detail::kIpProtocolUdp, make_ipv6_udp_segment(3333U, 4444U, 2U))
        )
    ));
    StepKindRecorder inner_ipv6_routing_recorder {};
    const auto inner_ipv6_routing_result = engine.run(
        registry,
        make_link_type_selector(inner_ipv6_routing_packet.data_link_type),
        make_root_slice(inner_ipv6_routing_packet),
        DissectionConsumer {.on_step = record_step_kind, .context = &inner_ipv6_routing_recorder}
    );
    PFL_EXPECT(inner_ipv6_routing_result.stop_reason == StopReason::terminal_protocol);
    const std::vector<DissectionLayerKind> expected_inner_ipv6_routing_kinds {
        DissectionLayerKind::ethernet_ii,
        DissectionLayerKind::ipv4,
        DissectionLayerKind::ipv6,
        DissectionLayerKind::ipv6_routing,
        DissectionLayerKind::udp,
    };
    PFL_EXPECT(inner_ipv6_routing_recorder.kinds == expected_inner_ipv6_routing_kinds);
    const auto inner_ipv6_routing_shadow = run_shadow(inner_ipv6_routing_packet, registry);
    PFL_EXPECT(inner_ipv6_routing_shadow.outcome == ImportDissectionOutcome::recognized_flow);
    PFL_EXPECT(inner_ipv6_routing_shadow.family == DissectionAddressFamily::ipv6);
    PFL_EXPECT(inner_ipv6_routing_shadow.terminal_protocol == ProtocolId::udp);
    PFL_EXPECT(inner_ipv6_routing_shadow.has_ports);
    PFL_EXPECT(inner_ipv6_routing_shadow.src_port == 3333U);
    PFL_EXPECT(inner_ipv6_routing_shadow.dst_port == 4444U);
    PFL_EXPECT(format_shadow_path(inner_ipv6_routing_shadow) == "EthernetII -> IPv4 -> IPv6 -> UDP");

    auto outer_extra_tail_packet = make_ethernet_ipv4_fragment_packet(
        ipv4(203, 0, 113, 10),
        ipv4(203, 0, 113, 11),
        detail::kIpProtocolIpv4Encapsulation,
        0U,
        make_ipv4_payload_packet(
            ipv4(10, 1, 0, 1),
            ipv4(10, 1, 0, 2),
            detail::kIpProtocolUdp,
            make_ipv6_udp_segment(5000U, 5001U)
        )
    );
    outer_extra_tail_packet.push_back(0xAAU);
    outer_extra_tail_packet.push_back(0xBBU);
    outer_extra_tail_packet.push_back(0xCCU);
    const auto outer_extra_tail_shadow = run_shadow(make_raw_packet(outer_extra_tail_packet), registry);
    PFL_EXPECT(outer_extra_tail_shadow.outcome == ImportDissectionOutcome::recognized_flow);
    PFL_EXPECT(outer_extra_tail_shadow.has_transport_payload_length);
    PFL_EXPECT(outer_extra_tail_shadow.captured_transport_payload_length == 0U);
    PFL_EXPECT(format_shadow_path(outer_extra_tail_shadow) == "EthernetII -> IPv4 -> IPv4 -> UDP");

    auto truncated_inner_transport_packet = make_ethernet_ipv4_fragment_packet(
        ipv4(203, 0, 113, 20),
        ipv4(203, 0, 113, 21),
        detail::kIpProtocolIpv4Encapsulation,
        0U,
        make_ipv4_payload_packet(
            ipv4(10, 2, 0, 1),
            ipv4(10, 2, 0, 2),
            detail::kIpProtocolTcp,
            make_ipv6_tcp_segment(61000U, 443U)
        )
    );
    const auto truncated_inner_transport_reported_length = static_cast<std::uint32_t>(truncated_inner_transport_packet.size());
    truncated_inner_transport_packet.resize(truncated_inner_transport_packet.size() - 2U);
    const auto truncated_inner_transport_shadow = run_shadow(
        make_raw_packet(truncated_inner_transport_packet, truncated_inner_transport_reported_length),
        registry
    );
    PFL_EXPECT(truncated_inner_transport_shadow.outcome == ImportDissectionOutcome::unrecognized);
    PFL_EXPECT(truncated_inner_transport_shadow.stop_reason == StopReason::truncated);
    PFL_EXPECT(truncated_inner_transport_shadow.family == DissectionAddressFamily::ipv4);
    PFL_EXPECT(truncated_inner_transport_shadow.terminal_protocol == ProtocolId::tcp);
    PFL_EXPECT(!truncated_inner_transport_shadow.has_ports);
    PFL_EXPECT(format_shadow_path(truncated_inner_transport_shadow) == "EthernetII -> IPv4 -> IPv4");

    StepKindRecorder truncated_inner_transport_recorder {};
    const auto truncated_inner_transport_raw =
        make_raw_packet(truncated_inner_transport_packet, truncated_inner_transport_reported_length);
    const auto truncated_inner_transport_result = engine.run(
        registry,
        make_link_type_selector(kLinkTypeEthernet),
        make_root_slice(truncated_inner_transport_raw),
        DissectionConsumer {.on_step = record_step_kind, .context = &truncated_inner_transport_recorder}
    );
    PFL_EXPECT(truncated_inner_transport_result.stop_reason == StopReason::truncated);
    const std::vector<DissectionLayerKind> expected_truncated_inner_transport_kinds {
        DissectionLayerKind::ethernet_ii,
        DissectionLayerKind::ipv4,
        DissectionLayerKind::ipv4,
        DissectionLayerKind::tcp,
    };
    PFL_EXPECT(truncated_inner_transport_recorder.kinds == expected_truncated_inner_transport_kinds);

    const auto short_inner_header_packet = make_raw_packet(make_ethernet_ipv4_fragment_packet(
        ipv4(203, 0, 113, 30),
        ipv4(203, 0, 113, 31),
        detail::kIpProtocolIpv4Encapsulation,
        0U,
        std::vector<std::uint8_t>(10U, 0x00U)
    ));
    StepKindRecorder short_inner_header_recorder {};
    const auto short_inner_header_result = engine.run(
        registry,
        make_link_type_selector(short_inner_header_packet.data_link_type),
        make_root_slice(short_inner_header_packet),
        DissectionConsumer {.on_step = record_step_kind, .context = &short_inner_header_recorder}
    );
    PFL_EXPECT(short_inner_header_result.stop_reason == StopReason::truncated);
    const std::vector<DissectionLayerKind> expected_short_inner_header_kinds {
        DissectionLayerKind::ethernet_ii,
        DissectionLayerKind::ipv4,
        DissectionLayerKind::ipv4,
    };
    PFL_EXPECT(short_inner_header_recorder.kinds == expected_short_inner_header_kinds);
    const auto short_inner_header_shadow = run_shadow(short_inner_header_packet, registry);
    PFL_EXPECT(short_inner_header_shadow.outcome == ImportDissectionOutcome::unrecognized);
    PFL_EXPECT(short_inner_header_shadow.stop_reason == StopReason::truncated);
    PFL_EXPECT(format_shadow_path(short_inner_header_shadow) == "EthernetII -> IPv4");

    const auto unknown_deepest_packet = make_raw_packet(make_ethernet_ipv4_fragment_packet(
        ipv4(203, 0, 113, 40),
        ipv4(203, 0, 113, 41),
        detail::kIpProtocolIpv6Encapsulation,
        0U,
        make_ipv6_payload_packet(inner_ipv6_src, inner_ipv6_dst, 0xFDU, {0xde, 0xad, 0xbe, 0xef})
    ));
    const auto unknown_deepest_shadow = run_shadow(unknown_deepest_packet, registry);
    PFL_EXPECT(unknown_deepest_shadow.outcome == ImportDissectionOutcome::unrecognized);
    PFL_EXPECT(unknown_deepest_shadow.stop_reason == StopReason::unknown_next_protocol);
    PFL_EXPECT(unknown_deepest_shadow.family == DissectionAddressFamily::ipv6);
    PFL_EXPECT(unknown_deepest_shadow.terminal_protocol == ProtocolId::unknown);
    PFL_EXPECT(format_shadow_path(unknown_deepest_shadow) == "EthernetII -> IPv4 -> IPv6");

    const auto outer_ipv4_fragment_packet = make_raw_packet(make_ethernet_ipv4_fragment_packet(
        ipv4(203, 0, 113, 50),
        ipv4(203, 0, 113, 51),
        detail::kIpProtocolIpv4Encapsulation,
        0x2000U,
        {0x45, 0x00, 0x00, 0x14, 0x00}
    ));
    StepKindRecorder outer_ipv4_fragment_recorder {};
    const auto outer_ipv4_fragment_result = engine.run(
        registry,
        make_link_type_selector(outer_ipv4_fragment_packet.data_link_type),
        make_root_slice(outer_ipv4_fragment_packet),
        DissectionConsumer {.on_step = record_step_kind, .context = &outer_ipv4_fragment_recorder}
    );
    PFL_EXPECT(outer_ipv4_fragment_result.stop_reason == StopReason::needs_reassembly);
    const std::vector<DissectionLayerKind> expected_outer_ipv4_fragment_kinds {
        DissectionLayerKind::ethernet_ii,
        DissectionLayerKind::ipv4,
    };
    PFL_EXPECT(outer_ipv4_fragment_recorder.kinds == expected_outer_ipv4_fragment_kinds);
    const auto outer_ipv4_fragment_shadow = run_shadow(outer_ipv4_fragment_packet, registry);
    PFL_EXPECT(outer_ipv4_fragment_shadow.outcome == ImportDissectionOutcome::unrecognized);
    PFL_EXPECT(outer_ipv4_fragment_shadow.stop_reason == StopReason::needs_reassembly);
    PFL_EXPECT(format_shadow_path(outer_ipv4_fragment_shadow) == "EthernetII -> IPv4");

    const auto outer_ipv6_fragment_packet = make_raw_packet(make_ethernet_ipv6_fragment_packet(
        outer_ipv6_src,
        outer_ipv6_dst,
        detail::kIpProtocolIpv6Encapsulation,
        {0x60, 0x00, 0x00, 0x00}
    ));
    StepKindRecorder outer_ipv6_fragment_recorder {};
    const auto outer_ipv6_fragment_result = engine.run(
        registry,
        make_link_type_selector(outer_ipv6_fragment_packet.data_link_type),
        make_root_slice(outer_ipv6_fragment_packet),
        DissectionConsumer {.on_step = record_step_kind, .context = &outer_ipv6_fragment_recorder}
    );
    PFL_EXPECT(outer_ipv6_fragment_result.stop_reason == StopReason::needs_reassembly);
    const std::vector<DissectionLayerKind> expected_outer_ipv6_fragment_kinds {
        DissectionLayerKind::ethernet_ii,
        DissectionLayerKind::ipv6,
        DissectionLayerKind::ipv6_fragment,
    };
    PFL_EXPECT(outer_ipv6_fragment_recorder.kinds == expected_outer_ipv6_fragment_kinds);
    const auto outer_ipv6_fragment_shadow = run_shadow(outer_ipv6_fragment_packet, registry);
    PFL_EXPECT(outer_ipv6_fragment_shadow.outcome == ImportDissectionOutcome::unrecognized);
    PFL_EXPECT(outer_ipv6_fragment_shadow.stop_reason == StopReason::needs_reassembly);
    PFL_EXPECT(format_shadow_path(outer_ipv6_fragment_shadow) == "EthernetII -> IPv6");

    const auto inner_fragmented_shadow = run_shadow(
        make_raw_packet(make_ethernet_ipv6_packet(
            outer_ipv6_src,
            outer_ipv6_dst,
            detail::kIpProtocolIpv4Encapsulation,
            make_ipv4_payload_packet(
                ipv4(10, 88, 0, 1),
                ipv4(10, 88, 0, 2),
                detail::kIpProtocolUdp,
                {0xde, 0xad, 0xbe, 0xef},
                0x2000U
            )
        )),
        registry
    );
    PFL_EXPECT(inner_fragmented_shadow.outcome == ImportDissectionOutcome::recognized_flow);
    PFL_EXPECT(inner_fragmented_shadow.stop_reason == StopReason::needs_reassembly);
    PFL_EXPECT(inner_fragmented_shadow.family == DissectionAddressFamily::ipv4);
    PFL_EXPECT(inner_fragmented_shadow.terminal_protocol == ProtocolId::udp);
    PFL_EXPECT(!inner_fragmented_shadow.has_ports);
    PFL_EXPECT(format_shadow_path(inner_fragmented_shadow) == "EthernetII -> IPv6 -> IPv4");

    const auto outer_ipv6_inner_ipv4_icmp_packet = make_raw_packet(make_ethernet_ipv6_packet(
        outer_ipv6_src,
        outer_ipv6_dst,
        detail::kIpProtocolIpv4Encapsulation,
        make_ipv4_payload_packet(
            ipv4(10, 89, 0, 1),
            ipv4(10, 89, 0, 2),
            detail::kIpProtocolIcmp,
            {8U, 0U, 0x22U, 0x22U, 0x01U, 0x02U, 0x03U, 0x04U}
        )
    ));
    StepKindRecorder outer_ipv6_inner_ipv4_icmp_recorder {};
    const auto outer_ipv6_inner_ipv4_icmp_result = engine.run(
        registry,
        make_link_type_selector(outer_ipv6_inner_ipv4_icmp_packet.data_link_type),
        make_root_slice(outer_ipv6_inner_ipv4_icmp_packet),
        DissectionConsumer {.on_step = record_step_kind, .context = &outer_ipv6_inner_ipv4_icmp_recorder}
    );
    PFL_EXPECT(outer_ipv6_inner_ipv4_icmp_result.stop_reason == StopReason::terminal_protocol);
    const std::vector<DissectionLayerKind> expected_outer_ipv6_inner_ipv4_icmp_kinds {
        DissectionLayerKind::ethernet_ii,
        DissectionLayerKind::ipv6,
        DissectionLayerKind::ipv4,
        DissectionLayerKind::icmp,
    };
    PFL_EXPECT(outer_ipv6_inner_ipv4_icmp_recorder.kinds == expected_outer_ipv6_inner_ipv4_icmp_kinds);
    const auto outer_ipv6_inner_ipv4_icmp_shadow = run_shadow(outer_ipv6_inner_ipv4_icmp_packet, registry);
    PFL_EXPECT(outer_ipv6_inner_ipv4_icmp_shadow.outcome == ImportDissectionOutcome::recognized_flow);
    PFL_EXPECT(outer_ipv6_inner_ipv4_icmp_shadow.family == DissectionAddressFamily::ipv4);
    PFL_EXPECT(outer_ipv6_inner_ipv4_icmp_shadow.terminal_protocol == ProtocolId::icmp);
    PFL_EXPECT(outer_ipv6_inner_ipv4_icmp_shadow.src_addr_v4 == ipv4(10, 89, 0, 1));
    PFL_EXPECT(outer_ipv6_inner_ipv4_icmp_shadow.dst_addr_v4 == ipv4(10, 89, 0, 2));
    PFL_EXPECT(!outer_ipv6_inner_ipv4_icmp_shadow.has_ports);
    PFL_EXPECT(!outer_ipv6_inner_ipv4_icmp_shadow.has_transport_payload_length);
    PFL_EXPECT(format_shadow_path(outer_ipv6_inner_ipv4_icmp_shadow) == "EthernetII -> IPv6 -> IPv4 -> ICMP");

    const auto outer_ipv6_inner_ipv6_icmpv6_packet = make_raw_packet(make_ethernet_ipv6_packet(
        outer_ipv6_src,
        outer_ipv6_dst,
        detail::kIpProtocolIpv6Encapsulation,
        make_ipv6_payload_packet(
            inner_ipv6_src,
            inner_ipv6_dst,
            detail::kIpProtocolIcmpV6,
            make_ipv6_icmpv6_message(128U, 0U)
        )
    ));
    const auto outer_ipv6_inner_ipv6_icmpv6_shadow = run_shadow(outer_ipv6_inner_ipv6_icmpv6_packet, registry);
    PFL_EXPECT(outer_ipv6_inner_ipv6_icmpv6_shadow.outcome == ImportDissectionOutcome::recognized_flow);
    PFL_EXPECT(outer_ipv6_inner_ipv6_icmpv6_shadow.stop_reason == StopReason::terminal_protocol);
    PFL_EXPECT(outer_ipv6_inner_ipv6_icmpv6_shadow.family == DissectionAddressFamily::ipv6);
    PFL_EXPECT(outer_ipv6_inner_ipv6_icmpv6_shadow.terminal_protocol == ProtocolId::icmpv6);
    PFL_EXPECT(outer_ipv6_inner_ipv6_icmpv6_shadow.src_addr_v6 == inner_ipv6_src);
    PFL_EXPECT(outer_ipv6_inner_ipv6_icmpv6_shadow.dst_addr_v6 == inner_ipv6_dst);
    PFL_EXPECT(!outer_ipv6_inner_ipv6_icmpv6_shadow.has_ports);
    PFL_EXPECT(!outer_ipv6_inner_ipv6_icmpv6_shadow.has_transport_payload_length);
    PFL_EXPECT(format_shadow_path(outer_ipv6_inner_ipv6_icmpv6_shadow) == "EthernetII -> IPv6 -> IPv6 -> ICMPv6");

    const auto outer_ipv6_hbh_inner_ipv4_icmp_packet = make_raw_packet(make_ethernet_ipv6_packet(
        outer_ipv6_src,
        outer_ipv6_dst,
        detail::kIpProtocolHopByHop,
        make_ipv6_hop_by_hop_extension(
            detail::kIpProtocolIpv4Encapsulation,
            make_ipv4_payload_packet(
                ipv4(10, 90, 0, 1),
                ipv4(10, 90, 0, 2),
                detail::kIpProtocolIcmp,
                {0U, 0U, 0x11U, 0x22U, 0x55U, 0x66U, 0x77U, 0x88U}
            )
        )
    ));
    StepKindRecorder outer_ipv6_hbh_inner_ipv4_icmp_recorder {};
    const auto outer_ipv6_hbh_inner_ipv4_icmp_result = engine.run(
        registry,
        make_link_type_selector(outer_ipv6_hbh_inner_ipv4_icmp_packet.data_link_type),
        make_root_slice(outer_ipv6_hbh_inner_ipv4_icmp_packet),
        DissectionConsumer {.on_step = record_step_kind, .context = &outer_ipv6_hbh_inner_ipv4_icmp_recorder}
    );
    PFL_EXPECT(outer_ipv6_hbh_inner_ipv4_icmp_result.stop_reason == StopReason::terminal_protocol);
    const std::vector<DissectionLayerKind> expected_outer_ipv6_hbh_inner_ipv4_icmp_kinds {
        DissectionLayerKind::ethernet_ii,
        DissectionLayerKind::ipv6,
        DissectionLayerKind::ipv6_hop_by_hop,
        DissectionLayerKind::ipv4,
        DissectionLayerKind::icmp,
    };
    PFL_EXPECT(outer_ipv6_hbh_inner_ipv4_icmp_recorder.kinds == expected_outer_ipv6_hbh_inner_ipv4_icmp_kinds);
    const auto outer_ipv6_hbh_inner_ipv4_icmp_shadow = run_shadow(outer_ipv6_hbh_inner_ipv4_icmp_packet, registry);
    PFL_EXPECT(outer_ipv6_hbh_inner_ipv4_icmp_shadow.outcome == ImportDissectionOutcome::recognized_flow);
    PFL_EXPECT(outer_ipv6_hbh_inner_ipv4_icmp_shadow.family == DissectionAddressFamily::ipv4);
    PFL_EXPECT(outer_ipv6_hbh_inner_ipv4_icmp_shadow.terminal_protocol == ProtocolId::icmp);
    PFL_EXPECT(!outer_ipv6_hbh_inner_ipv4_icmp_shadow.has_ports);
    PFL_EXPECT(format_shadow_path(outer_ipv6_hbh_inner_ipv4_icmp_shadow) == "EthernetII -> IPv6 -> IPv4 -> ICMP");

    const auto deep_depth_packet = make_raw_packet(make_ethernet_ipv4_fragment_packet(
        ipv4(203, 0, 113, 60),
        ipv4(203, 0, 113, 61),
        detail::kIpProtocolIpv6Encapsulation,
        0U,
        make_ipv6_payload_packet(
            inner_ipv6_src,
            inner_ipv6_dst,
            detail::kIpProtocolIpv4Encapsulation,
            make_ipv4_payload_packet(
                ipv4(10, 99, 0, 1),
                ipv4(10, 99, 0, 2),
                detail::kIpProtocolIpv6Encapsulation,
                make_ipv6_payload_packet(
                    ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0x55}),
                    ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 0x66}),
                    detail::kIpProtocolUdp,
                    make_ipv6_udp_segment(62000U, 62001U, 1U)
                )
            )
        )
    ));
    StepKindRecorder deep_depth_recorder {};
    const auto deep_depth_result = engine.run(
        registry,
        make_link_type_selector(deep_depth_packet.data_link_type),
        make_root_slice(deep_depth_packet),
        DissectionConsumer {.on_step = record_step_kind, .context = &deep_depth_recorder},
        5U
    );
    PFL_EXPECT(deep_depth_result.stop_reason == StopReason::depth_limit);
    PFL_EXPECT(deep_depth_result.step_count == 5U);
    PFL_EXPECT(deep_depth_result.traversed_depth == 5U);
    const std::vector<DissectionLayerKind> expected_deep_depth_kinds {
        DissectionLayerKind::ethernet_ii,
        DissectionLayerKind::ipv4,
        DissectionLayerKind::ipv6,
        DissectionLayerKind::ipv4,
        DissectionLayerKind::ipv6,
    };
    PFL_EXPECT(deep_depth_recorder.kinds == expected_deep_depth_kinds);
}


void run_common_direct_encapsulation_dissection_tests() {
    expect_ah_and_esp_shadow_parsers_bounds_and_traversal();
    expect_mpls_shadow_parsers_bounds_and_traversal();
    expect_gre_shadow_parsers_bounds_and_traversal();
    expect_plain_ip_encapsulation_is_registry_driven();
}

}  // namespace pfl::tests::common_direct_test
