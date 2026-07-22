#include "CommonDirectDissectionTestSupport.h"
#include "core/dissection/modules/CommonDirectModules.h"

namespace pfl::tests::common_direct_test {

using namespace dissection;

namespace {

void expect_shadow_matches_legacy_igmp_flow(
    const DissectionRegistry& registry,
    const RawPcapPacket& packet,
    const std::string& expected_shadow_path,
    const std::string& expected_legacy_path,
    const StopReason expected_stop_reason,
    const std::uint32_t expected_source,
    const std::uint32_t expected_destination
) {
    const auto legacy = decode_legacy_direct(packet);
    const auto shadow = run_shadow(packet, registry);

    PFL_REQUIRE(legacy.recognized_flow);
    PFL_EXPECT(legacy.protocol == ProtocolId::igmp);
    PFL_EXPECT(legacy.family == DissectionAddressFamily::ipv4);
    PFL_EXPECT(legacy.src_addr_v4 == expected_source);
    PFL_EXPECT(legacy.dst_addr_v4 == expected_destination);
    PFL_EXPECT(format_protocol_path(legacy.path) == expected_legacy_path);
    PFL_EXPECT(legacy.src_port == 0U);
    PFL_EXPECT(legacy.dst_port == 0U);

    PFL_EXPECT(shadow.outcome == ImportDissectionOutcome::recognized_flow);
    PFL_EXPECT(shadow.stop_reason == expected_stop_reason);
    PFL_EXPECT(shadow.terminal_protocol == ProtocolId::igmp);
    PFL_EXPECT(shadow.family == DissectionAddressFamily::ipv4);
    PFL_EXPECT(shadow.has_flow_addresses);
    PFL_EXPECT(shadow.src_addr_v4 == expected_source);
    PFL_EXPECT(shadow.dst_addr_v4 == expected_destination);
    PFL_EXPECT(format_shadow_path(shadow) == expected_shadow_path);
    PFL_EXPECT(!shadow.has_ports);
    PFL_EXPECT(shadow.src_port == 0U);
    PFL_EXPECT(shadow.dst_port == 0U);
    PFL_EXPECT(!shadow.has_transport_payload_length);
    PFL_EXPECT(shadow.captured_transport_payload_length == 0U);
    PFL_EXPECT(!shadow.has_tcp_flags);
    PFL_EXPECT(shadow.tcp_flags == 0U);
}

void expect_shadow_only_nested_igmp_flow(
    const DissectionRegistry& registry,
    const RawPcapPacket& packet,
    const std::string& expected_shadow_path,
    const StopReason expected_stop_reason,
    const std::uint32_t expected_source,
    const std::uint32_t expected_destination
) {
    const auto legacy = decode_legacy_direct(packet);
    const auto shadow = run_shadow(packet, registry);

    PFL_EXPECT(!legacy.recognized_flow);

    PFL_EXPECT(shadow.outcome == ImportDissectionOutcome::recognized_flow);
    PFL_EXPECT(shadow.stop_reason == expected_stop_reason);
    PFL_EXPECT(shadow.terminal_protocol == ProtocolId::igmp);
    PFL_EXPECT(shadow.family == DissectionAddressFamily::ipv4);
    PFL_EXPECT(shadow.has_flow_addresses);
    PFL_EXPECT(shadow.src_addr_v4 == expected_source);
    PFL_EXPECT(shadow.dst_addr_v4 == expected_destination);
    PFL_EXPECT(format_shadow_path(shadow) == expected_shadow_path);
    PFL_EXPECT(!shadow.has_ports);
    PFL_EXPECT(shadow.src_port == 0U);
    PFL_EXPECT(shadow.dst_port == 0U);
    PFL_EXPECT(!shadow.has_transport_payload_length);
    PFL_EXPECT(shadow.captured_transport_payload_length == 0U);
    PFL_EXPECT(!shadow.has_tcp_flags);
    PFL_EXPECT(shadow.tcp_flags == 0U);
}

}  // namespace

void expect_ipv4_options_shadow_parsing_and_declared_boundary_semantics() {
    const auto registry = make_common_direct_registry();
    PFL_REQUIRE(registry.ok());

    {
        const auto plain_packet = make_raw_packet(make_ethernet_ipv4_tcp_packet(
            ipv4(10, 20, 0, 1), ipv4(10, 20, 0, 2), 1111U, 2222U));
        const auto plain_root = make_root_slice(plain_packet);
        const auto plain_ethernet = parse_ethernet_frame(plain_root);
        PFL_REQUIRE(plain_ethernet.status == ParseStatus::complete);
        const auto plain_ipv4_step = dissect_ipv4(require_child_slice(
            plain_root,
            plain_ethernet.header_length,
            plain_ethernet.declared_payload_length
        ));
        const auto* plain_facts = std::get_if<Ipv4Facts>(&plain_ipv4_step.facts);
        PFL_REQUIRE(plain_facts != nullptr);
        PFL_EXPECT(plain_facts->options.status == Ipv4OptionsParseStatus::not_present);
        PFL_EXPECT(plain_facts->options.options_length == 0U);
    }

    {
        const auto options_packet = make_raw_packet(add_ipv4_options(
            make_ethernet_ipv4_udp_packet(ipv4(10, 20, 1, 1), ipv4(10, 20, 1, 2), 3000U, 4000U),
            {0x01, 0x94, 0x04, 0x00, 0x00, 0x94, 0x04, 0x12, 0x34, 0x00, 0x00, 0x00}
        ));
        const auto options_root = make_root_slice(options_packet);
        const auto options_ethernet = parse_ethernet_frame(options_root);
        PFL_REQUIRE(options_ethernet.status == ParseStatus::complete);
        const auto options_ipv4_step = dissect_ipv4(require_child_slice(
            options_root,
            options_ethernet.header_length,
            options_ethernet.declared_payload_length
        ));
        PFL_EXPECT(options_ipv4_step.layer == DissectionLayerKind::ipv4);
        PFL_REQUIRE(options_ipv4_step.path_contribution.has_value());
        PFL_EXPECT(*options_ipv4_step.path_contribution == LayerKey::ipv4());
        PFL_REQUIRE(options_ipv4_step.handoff.has_value());
        PFL_REQUIRE(options_ipv4_step.handoff->child.has_value());
        const ProtocolSelector expected_udp_selector {
            .domain = SelectorDomain::ip_protocol,
            .value = detail::kIpProtocolUdp,
        };
        PFL_EXPECT(options_ipv4_step.handoff->selector == expected_udp_selector);
        const auto* options_facts = std::get_if<Ipv4Facts>(&options_ipv4_step.facts);
        PFL_REQUIRE(options_facts != nullptr);
        PFL_EXPECT(options_facts->header_length == 32U);
        PFL_EXPECT(options_facts->options.status == Ipv4OptionsParseStatus::well_formed);
        PFL_EXPECT(options_facts->options.options_length == 12U);
        PFL_EXPECT(options_facts->options.parsed_option_count == 4U);
        PFL_EXPECT(options_facts->options.nop_count == 1U);
        PFL_EXPECT(options_facts->options.has_end_of_list);
        PFL_EXPECT(!options_facts->options.has_nonzero_padding);
        PFL_EXPECT(options_facts->options.has_router_alert);
        PFL_EXPECT(options_facts->options.router_alert_value == 0x1234U);
        PFL_EXPECT(!options_facts->options.has_malformed_offset);
        expect_shadow_matches_legacy_flow(
            *registry.registry,
            options_packet,
            "EthernetII -> IPv4 -> UDP",
            StopReason::terminal_protocol
        );
    }

    {
        const auto malformed_router_alert_packet = make_raw_packet(add_ipv4_options(
            make_ethernet_ipv4_udp_packet(ipv4(10, 20, 2, 1), ipv4(10, 20, 2, 2), 5000U, 5001U),
            {0x94, 0x03, 0x00, 0x00}
        ));
        const auto malformed_root = make_root_slice(malformed_router_alert_packet);
        const auto malformed_ethernet = parse_ethernet_frame(malformed_root);
        PFL_REQUIRE(malformed_ethernet.status == ParseStatus::complete);
        const auto malformed_step = dissect_ipv4(require_child_slice(
            malformed_root,
            malformed_ethernet.header_length,
            malformed_ethernet.declared_payload_length
        ));
        PFL_EXPECT(malformed_step.status == ParseStatus::complete);
        PFL_REQUIRE(malformed_step.path_contribution.has_value());
        PFL_REQUIRE(malformed_step.handoff.has_value());
        const auto* malformed_facts = std::get_if<Ipv4Facts>(&malformed_step.facts);
        PFL_REQUIRE(malformed_facts != nullptr);
        PFL_EXPECT(malformed_facts->options.status == Ipv4OptionsParseStatus::malformed);
        PFL_EXPECT(malformed_facts->options.parsed_option_count == 1U);
        PFL_EXPECT(malformed_facts->options.has_router_alert == false);
        PFL_EXPECT(malformed_facts->options.has_malformed_offset);
        PFL_EXPECT(malformed_facts->options.malformed_offset == 0U);
        expect_shadow_matches_legacy_flow(
            *registry.registry,
            malformed_router_alert_packet,
            "EthernetII -> IPv4 -> UDP",
            StopReason::terminal_protocol
        );
    }

    {
        const auto malformed_missing_length_packet = make_raw_packet(add_ipv4_options(
            make_ethernet_ipv4_tcp_packet(ipv4(10, 20, 3, 1), ipv4(10, 20, 3, 2), 6000U, 6001U),
            {0x01, 0x01, 0x01, 0x44}
        ));
        const auto malformed_root = make_root_slice(malformed_missing_length_packet);
        const auto malformed_ethernet = parse_ethernet_frame(malformed_root);
        PFL_REQUIRE(malformed_ethernet.status == ParseStatus::complete);
        const auto malformed_step = dissect_ipv4(require_child_slice(
            malformed_root,
            malformed_ethernet.header_length,
            malformed_ethernet.declared_payload_length
        ));
        const auto* malformed_facts = std::get_if<Ipv4Facts>(&malformed_step.facts);
        PFL_REQUIRE(malformed_facts != nullptr);
        PFL_EXPECT(malformed_facts->options.status == Ipv4OptionsParseStatus::malformed);
        PFL_EXPECT(malformed_facts->options.nop_count == 3U);
        PFL_EXPECT(malformed_facts->options.parsed_option_count == 3U);
        PFL_EXPECT(malformed_facts->options.has_malformed_offset);
        PFL_EXPECT(malformed_facts->options.malformed_offset == 3U);
        expect_shadow_matches_legacy_flow(
            *registry.registry,
            malformed_missing_length_packet,
            "EthernetII -> IPv4 -> TCP",
            StopReason::terminal_protocol
        );
    }

    {
        const auto malformed_short_length_packet = make_raw_packet(add_ipv4_options(
            make_ethernet_ipv4_udp_packet(ipv4(10, 20, 3, 11), ipv4(10, 20, 3, 12), 6100U, 6101U),
            {0x44, 0x01, 0x00, 0x00}
        ));
        const auto malformed_root = make_root_slice(malformed_short_length_packet);
        const auto malformed_ethernet = parse_ethernet_frame(malformed_root);
        PFL_REQUIRE(malformed_ethernet.status == ParseStatus::complete);
        const auto malformed_step = dissect_ipv4(require_child_slice(
            malformed_root,
            malformed_ethernet.header_length,
            malformed_ethernet.declared_payload_length
        ));
        const auto* malformed_facts = std::get_if<Ipv4Facts>(&malformed_step.facts);
        PFL_REQUIRE(malformed_facts != nullptr);
        PFL_EXPECT(malformed_facts->options.status == Ipv4OptionsParseStatus::malformed);
        PFL_EXPECT(malformed_facts->options.parsed_option_count == 0U);
        PFL_EXPECT(malformed_facts->options.has_malformed_offset);
        PFL_EXPECT(malformed_facts->options.malformed_offset == 0U);
        expect_shadow_matches_legacy_flow(
            *registry.registry,
            malformed_short_length_packet,
            "EthernetII -> IPv4 -> UDP",
            StopReason::terminal_protocol
        );
    }

    {
        const auto malformed_past_end_packet = make_raw_packet(add_ipv4_options(
            make_ethernet_ipv4_udp_packet(ipv4(10, 20, 3, 21), ipv4(10, 20, 3, 22), 6200U, 6201U),
            {0x44, 0x05, 0x00, 0x00}
        ));
        const auto malformed_root = make_root_slice(malformed_past_end_packet);
        const auto malformed_ethernet = parse_ethernet_frame(malformed_root);
        PFL_REQUIRE(malformed_ethernet.status == ParseStatus::complete);
        const auto malformed_step = dissect_ipv4(require_child_slice(
            malformed_root,
            malformed_ethernet.header_length,
            malformed_ethernet.declared_payload_length
        ));
        const auto* malformed_facts = std::get_if<Ipv4Facts>(&malformed_step.facts);
        PFL_REQUIRE(malformed_facts != nullptr);
        PFL_EXPECT(malformed_facts->options.status == Ipv4OptionsParseStatus::malformed);
        PFL_EXPECT(malformed_facts->options.parsed_option_count == 0U);
        PFL_EXPECT(malformed_facts->options.has_malformed_offset);
        PFL_EXPECT(malformed_facts->options.malformed_offset == 0U);
        expect_shadow_matches_legacy_flow(
            *registry.registry,
            malformed_past_end_packet,
            "EthernetII -> IPv4 -> UDP",
            StopReason::terminal_protocol
        );
    }

    {
        const auto malformed_padding_packet = make_raw_packet(add_ipv4_options(
            make_ethernet_ipv4_udp_packet(ipv4(10, 20, 4, 1), ipv4(10, 20, 4, 2), 7000U, 7001U),
            {0x00, 0x01, 0x00, 0x00}
        ));
        const auto malformed_root = make_root_slice(malformed_padding_packet);
        const auto malformed_ethernet = parse_ethernet_frame(malformed_root);
        PFL_REQUIRE(malformed_ethernet.status == ParseStatus::complete);
        const auto malformed_step = dissect_ipv4(require_child_slice(
            malformed_root,
            malformed_ethernet.header_length,
            malformed_ethernet.declared_payload_length
        ));
        const auto* malformed_facts = std::get_if<Ipv4Facts>(&malformed_step.facts);
        PFL_REQUIRE(malformed_facts != nullptr);
        PFL_EXPECT(malformed_facts->options.status == Ipv4OptionsParseStatus::malformed);
        PFL_EXPECT(malformed_facts->options.has_end_of_list);
        PFL_EXPECT(malformed_facts->options.has_nonzero_padding);
        PFL_EXPECT(malformed_facts->options.has_malformed_offset);
        PFL_EXPECT(malformed_facts->options.malformed_offset == 1U);
        expect_shadow_matches_legacy_flow(
            *registry.registry,
            malformed_padding_packet,
            "EthernetII -> IPv4 -> UDP",
            StopReason::terminal_protocol
        );
    }

    {
        const auto fragmented_packet = make_raw_packet(add_ipv4_options(
            make_ethernet_ipv4_fragment_packet(
                ipv4(10, 20, 5, 1),
                ipv4(10, 20, 5, 2),
                detail::kIpProtocolUdp,
                0x2000U,
                {0xde, 0xad, 0xbe, 0xef}
            ),
            {0x94, 0x04, 0x00, 0x00}
        ));
        const auto fragmented_root = make_root_slice(fragmented_packet);
        const auto fragmented_ethernet = parse_ethernet_frame(fragmented_root);
        PFL_REQUIRE(fragmented_ethernet.status == ParseStatus::complete);
        const auto fragmented_step = dissect_ipv4(require_child_slice(
            fragmented_root,
            fragmented_ethernet.header_length,
            fragmented_ethernet.declared_payload_length
        ));
        const auto* fragmented_facts = std::get_if<Ipv4Facts>(&fragmented_step.facts);
        PFL_REQUIRE(fragmented_facts != nullptr);
        PFL_EXPECT(fragmented_step.stop_reason == StopReason::needs_reassembly);
        PFL_EXPECT(fragmented_facts->is_fragmented);
        PFL_EXPECT(fragmented_facts->options.status == Ipv4OptionsParseStatus::well_formed);
        PFL_EXPECT(fragmented_facts->options.has_router_alert);
    }

    {
        const auto nested_inner_ipv4 = strip_ethernet_header(add_ipv4_options(
            make_ethernet_ipv4_udp_packet(ipv4(10, 20, 6, 1), ipv4(10, 20, 6, 2), 8000U, 8001U),
            {0x01, 0x94, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00}
        ));
        const auto nested_ipv6_packet = make_raw_packet(make_ethernet_ipv6_packet(
            ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x31}),
            ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x32}),
            detail::kIpProtocolIpv4Encapsulation,
            nested_inner_ipv4
        ));
        expect_shadow_matches_legacy_flow(
            *registry.registry,
            nested_ipv6_packet,
            "EthernetII -> IPv6 -> IPv4 -> UDP",
            StopReason::terminal_protocol
        );
    }

    {
        const auto nested_inner_ipv4 = strip_ethernet_header(add_ipv4_options(
            make_ethernet_ipv4_tcp_packet(ipv4(10, 20, 6, 11), ipv4(10, 20, 6, 12), 8100U, 8101U),
            {0x01, 0x01, 0x00, 0x00}
        ));
        const auto nested_ipv4_packet = make_raw_packet(make_ethernet_ipv4_fragment_packet(
            ipv4(192, 0, 2, 50),
            ipv4(192, 0, 2, 60),
            detail::kIpProtocolIpv4Encapsulation,
            0U,
            nested_inner_ipv4
        ));
        expect_shadow_matches_legacy_flow(
            *registry.registry,
            nested_ipv4_packet,
            "EthernetII -> IPv4 -> IPv4 -> TCP",
            StopReason::terminal_protocol
        );
    }

    {
        const auto declared_short_ipv4 = strip_ethernet_header(add_ipv4_options(
            make_ethernet_ipv4_udp_packet(ipv4(10, 20, 7, 1), ipv4(10, 20, 7, 2), 9000U, 9001U),
            {0x01, 0x01, 0x00, 0x00}
        ));
        const auto declared_short_slice = make_root_packet_slice(
            ByteSourceId::captured_frame(99U),
            declared_short_ipv4,
            static_cast<std::uint32_t>(declared_short_ipv4.size()),
            22U
        );
        const auto declared_short_parsed = parse_ipv4_packet(declared_short_slice);
        PFL_EXPECT(declared_short_parsed.status == ParseStatus::malformed);
        const auto declared_short_step = dissect_ipv4(declared_short_slice);
        PFL_EXPECT(declared_short_step.status == ParseStatus::malformed);
        PFL_EXPECT(!declared_short_step.path_contribution.has_value());
        PFL_EXPECT(!declared_short_step.handoff.has_value());
    }

    {
        const auto captured_short_ipv4 = strip_ethernet_header(add_ipv4_options(
            make_ethernet_ipv4_udp_packet(ipv4(10, 20, 8, 1), ipv4(10, 20, 8, 2), 9100U, 9101U),
            {0x01, 0x01, 0x00, 0x00}
        ));
        const auto captured_short_slice = make_root_packet_slice(
            ByteSourceId::captured_frame(100U),
            captured_short_ipv4,
            22U,
            static_cast<std::uint32_t>(captured_short_ipv4.size())
        );
        const auto captured_short_parsed = parse_ipv4_packet(captured_short_slice);
        PFL_EXPECT(captured_short_parsed.status == ParseStatus::truncated);
        const auto captured_short_step = dissect_ipv4(captured_short_slice);
        PFL_EXPECT(captured_short_step.status == ParseStatus::truncated);
        PFL_EXPECT(!captured_short_step.path_contribution.has_value());
        PFL_EXPECT(!captured_short_step.handoff.has_value());
    }
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


void expect_icmp_canonical_parsers_and_bounds() {
    const auto exact_icmp_packet = make_raw_packet(std::vector<std::uint8_t> {
        8U, 0U, 0x12U, 0x34U,
    });
    const auto exact_icmp_root = make_root_slice(exact_icmp_packet);
    const auto exact_icmp = parse_icmp_common_header(exact_icmp_root);
    PFL_EXPECT(exact_icmp.status == ParseStatus::complete);
    PFL_EXPECT(exact_icmp.type == 8U);
    PFL_EXPECT(exact_icmp.code == 0U);
    PFL_EXPECT(exact_icmp.checksum == 0x1234U);
    PFL_EXPECT(exact_icmp.header_length == 4U);
    PFL_EXPECT(exact_icmp.captured_payload_length == 0U);

    const auto exact_icmp_step = dissect_icmp(exact_icmp_root);
    PFL_EXPECT(exact_icmp_step.layer == DissectionLayerKind::icmp);
    PFL_EXPECT(!exact_icmp_step.path_contribution.has_value());
    PFL_EXPECT(exact_icmp_step.terminal_disposition == TerminalDisposition::flow_candidate);
    PFL_REQUIRE(exact_icmp_step.bounds.payload.has_value());
    PFL_EXPECT(exact_icmp_step.bounds.full.declared.length() == 4U);
    PFL_EXPECT(exact_icmp_step.bounds.full.captured.length() == 4U);
    PFL_EXPECT(exact_icmp_step.bounds.header.declared.length() == 4U);
    PFL_EXPECT(exact_icmp_step.bounds.header.captured.length() == 4U);
    PFL_EXPECT(exact_icmp_step.bounds.payload->declared.length() == 0U);
    PFL_EXPECT(exact_icmp_step.bounds.payload->captured.length() == 0U);
    PFL_EXPECT(std::holds_alternative<IcmpFacts>(exact_icmp_step.facts));
    const auto* exact_icmp_facts = std::get_if<IcmpFacts>(&exact_icmp_step.facts);
    PFL_REQUIRE(exact_icmp_facts != nullptr);
    PFL_EXPECT(exact_icmp_facts->type == 8U);
    PFL_EXPECT(exact_icmp_facts->code == 0U);
    PFL_EXPECT(exact_icmp_facts->checksum == 0x1234U);

    const auto full_icmp_packet = make_raw_packet(std::vector<std::uint8_t> {
        3U, 7U, 0xAAU, 0x55U, 0xDEU, 0xADU, 0xBEU, 0xEFU,
    });
    const auto full_icmp = parse_icmp_common_header(make_root_slice(full_icmp_packet));
    PFL_EXPECT(full_icmp.status == ParseStatus::complete);
    PFL_EXPECT(full_icmp.captured_payload_length == 4U);

    const auto truncated_body_icmp_packet = make_raw_packet(
        std::vector<std::uint8_t> {3U, 7U, 0xAAU, 0x55U, 0xDEU},
        8U
    );
    const auto truncated_body_icmp_step = dissect_icmp(make_root_slice(truncated_body_icmp_packet));
    PFL_EXPECT(truncated_body_icmp_step.status == ParseStatus::complete);
    PFL_REQUIRE(truncated_body_icmp_step.bounds.payload.has_value());
    PFL_EXPECT(truncated_body_icmp_step.bounds.payload->declared.length() == 4U);
    PFL_EXPECT(truncated_body_icmp_step.bounds.payload->captured.length() == 1U);

    const auto extra_tail_icmp_packet = make_raw_packet(
        std::vector<std::uint8_t> {11U, 9U, 0xBEU, 0xEFU, 0xAAU, 0xBBU, 0xCCU, 0xDDU},
        6U
    );
    const auto extra_tail_icmp_step = dissect_icmp(make_root_slice(extra_tail_icmp_packet));
    PFL_EXPECT(extra_tail_icmp_step.status == ParseStatus::complete);
    PFL_REQUIRE(extra_tail_icmp_step.bounds.payload.has_value());
    PFL_EXPECT(extra_tail_icmp_step.bounds.full.declared.length() == 6U);
    PFL_EXPECT(extra_tail_icmp_step.bounds.full.captured.length() == 6U);
    PFL_EXPECT(extra_tail_icmp_step.bounds.payload->declared.length() == 2U);
    PFL_EXPECT(extra_tail_icmp_step.bounds.payload->captured.length() == 2U);

    const auto truncated_icmp_packet = make_raw_packet(
        std::vector<std::uint8_t> {8U, 0U, 0x12U},
        4U
    );
    const auto truncated_icmp_root = make_root_slice(truncated_icmp_packet);
    const auto truncated_icmp = parse_icmp_common_header(truncated_icmp_root);
    PFL_EXPECT(truncated_icmp.status == ParseStatus::truncated);
    const auto truncated_icmp_step = dissect_icmp(truncated_icmp_root);
    PFL_EXPECT(truncated_icmp_step.status == ParseStatus::truncated);
    PFL_EXPECT(!truncated_icmp_step.path_contribution.has_value());
    PFL_EXPECT(truncated_icmp_step.terminal_disposition == TerminalDisposition::none);

    const auto impossible_icmp_packet = make_raw_packet(
        std::vector<std::uint8_t> {8U, 0U, 0x12U, 0x34U},
        3U
    );
    const auto impossible_icmp_step = dissect_icmp(make_root_slice(impossible_icmp_packet));
    PFL_EXPECT(impossible_icmp_step.status == ParseStatus::malformed);
    PFL_EXPECT(!impossible_icmp_step.path_contribution.has_value());
    PFL_EXPECT(impossible_icmp_step.bounds.full.declared.length() == 3U);
    PFL_EXPECT(impossible_icmp_step.bounds.full.captured.length() == 3U);

    const auto exact_icmpv6_packet = make_raw_packet(std::vector<std::uint8_t> {
        128U, 0U, 0xABU, 0xCDU,
    });
    const auto exact_icmpv6_root = make_root_slice(exact_icmpv6_packet);
    const auto exact_icmpv6 = parse_icmpv6_common_header(exact_icmpv6_root);
    PFL_EXPECT(exact_icmpv6.status == ParseStatus::complete);
    PFL_EXPECT(exact_icmpv6.type == 128U);
    PFL_EXPECT(exact_icmpv6.code == 0U);
    PFL_EXPECT(exact_icmpv6.checksum == 0xABCDU);

    const auto exact_icmpv6_step = dissect_icmpv6(exact_icmpv6_root);
    PFL_EXPECT(exact_icmpv6_step.layer == DissectionLayerKind::icmpv6);
    PFL_EXPECT(!exact_icmpv6_step.path_contribution.has_value());
    PFL_EXPECT(std::holds_alternative<Icmpv6Facts>(exact_icmpv6_step.facts));
    const auto* exact_icmpv6_facts = std::get_if<Icmpv6Facts>(&exact_icmpv6_step.facts);
    PFL_REQUIRE(exact_icmpv6_facts != nullptr);
    PFL_EXPECT(exact_icmpv6_facts->type == 128U);
    PFL_EXPECT(exact_icmpv6_facts->code == 0U);
    PFL_EXPECT(exact_icmpv6_facts->checksum == 0xABCDU);

    const auto unknown_icmpv6_packet = make_raw_packet(std::vector<std::uint8_t> {
        0xFEU, 0x7FU, 0x00U, 0x01U, 0x99U,
    });
    const auto unknown_icmpv6 = parse_icmpv6_common_header(make_root_slice(unknown_icmpv6_packet));
    PFL_EXPECT(unknown_icmpv6.status == ParseStatus::complete);
    PFL_EXPECT(unknown_icmpv6.type == 0xFEU);
    PFL_EXPECT(unknown_icmpv6.code == 0x7FU);

    const auto truncated_icmpv6_packet = make_raw_packet(
        std::vector<std::uint8_t> {128U, 0U},
        4U
    );
    PFL_EXPECT(parse_icmpv6_common_header(make_root_slice(truncated_icmpv6_packet)).status == ParseStatus::truncated);

    const auto built = make_common_direct_registry();
    PFL_REQUIRE(built.ok());
    const auto truncated_icmp_shadow = run_shadow(
        make_raw_packet(
            []() {
                auto packet = make_ethernet_ipv4_icmp_packet(
                    ipv4(10, 91, 0, 1),
                    ipv4(10, 91, 0, 2),
                    8U,
                    0U
                );
                packet.resize(14U + 20U + 3U);
                return packet;
            }(),
            14U + 20U + 8U
        ),
        *built.registry
    );
    PFL_EXPECT(truncated_icmp_shadow.outcome == ImportDissectionOutcome::unrecognized);
    PFL_EXPECT(truncated_icmp_shadow.stop_reason == StopReason::truncated);
    PFL_EXPECT(truncated_icmp_shadow.terminal_protocol == ProtocolId::icmp);
    PFL_EXPECT(!truncated_icmp_shadow.has_ports);
    PFL_EXPECT(format_shadow_path(truncated_icmp_shadow) == "EthernetII -> IPv4");
}

void expect_igmp_canonical_parsers_and_bounds() {
    const auto exact_igmp_packet = make_raw_packet(std::vector<std::uint8_t> {
        detail::kIgmpTypeMembershipQuery,
        0x7FU,
        0x12U, 0x34U,
        0xE0U, 0x00U, 0x00U, 0x01U,
    });
    const auto exact_igmp_root = make_root_slice(exact_igmp_packet);
    const auto exact_igmp = parse_igmp_common_header(exact_igmp_root);
    PFL_EXPECT(exact_igmp.status == ParseStatus::complete);
    PFL_EXPECT(exact_igmp.type == detail::kIgmpTypeMembershipQuery);
    PFL_EXPECT(exact_igmp.code == 0x7FU);
    PFL_EXPECT(exact_igmp.checksum == 0x1234U);
    PFL_EXPECT(exact_igmp.group_or_control == 0xE0000001U);
    PFL_EXPECT(exact_igmp.header_length == detail::kIgmpMinimumHeaderSize);
    PFL_EXPECT(exact_igmp.captured_payload_length == 0U);

    const auto exact_igmp_step = dissect_igmp(exact_igmp_root);
    PFL_EXPECT(exact_igmp_step.layer == DissectionLayerKind::igmp);
    PFL_EXPECT(!exact_igmp_step.path_contribution.has_value());
    PFL_EXPECT(exact_igmp_step.terminal_disposition == TerminalDisposition::flow_candidate);
    PFL_REQUIRE(exact_igmp_step.bounds.payload.has_value());
    PFL_EXPECT(exact_igmp_step.bounds.full.declared.length() == detail::kIgmpMinimumHeaderSize);
    PFL_EXPECT(exact_igmp_step.bounds.full.captured.length() == detail::kIgmpMinimumHeaderSize);
    PFL_EXPECT(exact_igmp_step.bounds.header.declared.length() == detail::kIgmpMinimumHeaderSize);
    PFL_EXPECT(exact_igmp_step.bounds.header.captured.length() == detail::kIgmpMinimumHeaderSize);
    PFL_EXPECT(exact_igmp_step.bounds.payload->declared.length() == 0U);
    PFL_EXPECT(exact_igmp_step.bounds.payload->captured.length() == 0U);
    PFL_EXPECT(std::holds_alternative<IgmpFacts>(exact_igmp_step.facts));
    const auto* exact_igmp_facts = std::get_if<IgmpFacts>(&exact_igmp_step.facts);
    PFL_REQUIRE(exact_igmp_facts != nullptr);
    PFL_EXPECT(exact_igmp_facts->type == detail::kIgmpTypeMembershipQuery);
    PFL_EXPECT(exact_igmp_facts->code == 0x7FU);
    PFL_EXPECT(exact_igmp_facts->checksum == 0x1234U);
    PFL_EXPECT(exact_igmp_facts->group_or_control == 0xE0000001U);
    PFL_EXPECT(exact_igmp_facts->has_effective_destination_v4);
    PFL_EXPECT(exact_igmp_facts->effective_destination_v4 == 0xE0000001U);

    struct IgmpTypeCase {
        std::uint8_t type {0U};
        std::uint8_t code {0U};
        std::uint16_t checksum {0U};
        std::uint32_t group_or_control {0U};
        bool expected_has_effective_destination {false};
        std::uint32_t expected_effective_destination {0U};
    };

    const std::array igmp_type_cases {
        IgmpTypeCase {
            .type = detail::kIgmpTypeMembershipQuery,
            .code = 0x7EU,
            .checksum = 0x1111U,
            .group_or_control = 0xE00000FBU,
            .expected_has_effective_destination = true,
            .expected_effective_destination = 0xE00000FBU,
        },
        IgmpTypeCase {
            .type = detail::kIgmpTypeMembershipQuery,
            .code = 0x70U,
            .checksum = 0x1717U,
            .group_or_control = 0x00000000U,
        },
        IgmpTypeCase {
            .type = detail::kIgmpTypeV1MembershipReport,
            .code = 0x01U,
            .checksum = 0x2222U,
            .group_or_control = 0xE0000016U,
            .expected_has_effective_destination = true,
            .expected_effective_destination = 0xE0000016U,
        },
        IgmpTypeCase {
            .type = detail::kIgmpTypeV2MembershipReport,
            .code = 0x02U,
            .checksum = 0x3333U,
            .group_or_control = 0xE0000017U,
            .expected_has_effective_destination = true,
            .expected_effective_destination = 0xE0000017U,
        },
        IgmpTypeCase {
            .type = detail::kIgmpTypeLeaveGroup,
            .code = 0x03U,
            .checksum = 0x4444U,
            .group_or_control = 0xEFFFFFFAU,
            .expected_has_effective_destination = true,
            .expected_effective_destination = 0xEFFFFFFAU,
        },
        IgmpTypeCase {
            .type = detail::kIgmpTypeV3MembershipReport,
            .code = 0x04U,
            .checksum = 0x5555U,
            .group_or_control = 0xA1B2C3D4U,
        },
        IgmpTypeCase {
            .type = 0x99U,
            .code = 0x05U,
            .checksum = 0x6666U,
            .group_or_control = 0x01020304U,
            .expected_has_effective_destination = true,
            .expected_effective_destination = 0x01020304U,
        },
    };

    for (const auto& test_case : igmp_type_cases) {
        const auto parsed = parse_igmp_common_header(make_root_slice(make_raw_packet(make_igmp_message(
            test_case.type,
            test_case.code,
            test_case.checksum,
            test_case.group_or_control
        ))));
        PFL_EXPECT(parsed.status == ParseStatus::complete);
        PFL_EXPECT(parsed.type == test_case.type);
        PFL_EXPECT(parsed.code == test_case.code);
        PFL_EXPECT(parsed.checksum == test_case.checksum);
        PFL_EXPECT(parsed.group_or_control == test_case.group_or_control);
        PFL_EXPECT(parsed.has_effective_destination_v4 == test_case.expected_has_effective_destination);
        PFL_EXPECT(parsed.effective_destination_v4 == test_case.expected_effective_destination);
    }

    const auto body_igmp_packet = make_raw_packet(make_igmp_message(
        detail::kIgmpTypeV2MembershipReport,
        0x11U,
        0xABCDU,
        0xE00000FBU,
        {0x01U, 0x02U, 0x03U, 0x04U}
    ));
    const auto body_igmp = parse_igmp_common_header(make_root_slice(body_igmp_packet));
    PFL_EXPECT(body_igmp.status == ParseStatus::complete);
    PFL_EXPECT(body_igmp.captured_payload_length == 4U);

    const auto truncated_body_igmp_packet = make_raw_packet(
        make_igmp_message(
            detail::kIgmpTypeV3MembershipReport,
            0x22U,
            0xBEEFU,
            0x00112233U,
            {0x10U, 0x20U, 0x30U, 0x40U}
        ),
        12U
    );
    const auto truncated_body_igmp_step = dissect_igmp(make_root_slice(truncated_body_igmp_packet));
    PFL_EXPECT(truncated_body_igmp_step.status == ParseStatus::complete);
    PFL_REQUIRE(truncated_body_igmp_step.bounds.payload.has_value());
    PFL_EXPECT(truncated_body_igmp_step.bounds.payload->declared.length() == 4U);
    PFL_EXPECT(truncated_body_igmp_step.bounds.payload->captured.length() == 4U);

    const auto capture_truncated_body_igmp_packet = make_raw_packet(
        std::vector<std::uint8_t> {0x22U, 0x33U, 0x44U, 0x55U, 0x66U, 0x77U, 0x88U, 0x99U, 0xAAU, 0xBBU},
        12U
    );
    const auto capture_truncated_body_igmp_step = dissect_igmp(make_root_slice(capture_truncated_body_igmp_packet));
    PFL_EXPECT(capture_truncated_body_igmp_step.status == ParseStatus::complete);
    PFL_REQUIRE(capture_truncated_body_igmp_step.bounds.payload.has_value());
    PFL_EXPECT(capture_truncated_body_igmp_step.bounds.payload->declared.length() == 4U);
    PFL_EXPECT(capture_truncated_body_igmp_step.bounds.payload->captured.length() == 2U);

    const auto extra_tail_igmp_packet = make_raw_packet(
        std::vector<std::uint8_t> {0x16U, 0x40U, 0xABU, 0xCDU, 0xE0U, 0x00U, 0x00U, 0xFBU, 0xDEU, 0xADU},
        8U
    );
    const auto extra_tail_igmp_step = dissect_igmp(make_root_slice(extra_tail_igmp_packet));
    PFL_EXPECT(extra_tail_igmp_step.status == ParseStatus::complete);
    PFL_REQUIRE(extra_tail_igmp_step.bounds.payload.has_value());
    PFL_EXPECT(extra_tail_igmp_step.bounds.full.declared.length() == 8U);
    PFL_EXPECT(extra_tail_igmp_step.bounds.full.captured.length() == 8U);
    PFL_EXPECT(extra_tail_igmp_step.bounds.payload->declared.length() == 0U);
    PFL_EXPECT(extra_tail_igmp_step.bounds.payload->captured.length() == 0U);

    const auto truncated_igmp_packet = make_raw_packet(
        std::vector<std::uint8_t> {0x11U, 0x7FU, 0x12U, 0x34U, 0xE0U, 0x00U, 0x00U},
        8U
    );
    const auto truncated_igmp_root = make_root_slice(truncated_igmp_packet);
    const auto truncated_igmp = parse_igmp_common_header(truncated_igmp_root);
    PFL_EXPECT(truncated_igmp.status == ParseStatus::truncated);
    const auto truncated_igmp_step = dissect_igmp(truncated_igmp_root);
    PFL_EXPECT(truncated_igmp_step.status == ParseStatus::truncated);
    PFL_EXPECT(!truncated_igmp_step.path_contribution.has_value());
    PFL_EXPECT(truncated_igmp_step.terminal_disposition == TerminalDisposition::none);

    const auto impossible_igmp_packet = make_raw_packet(
        std::vector<std::uint8_t> {0x11U, 0x7FU, 0x12U, 0x34U, 0xE0U, 0x00U, 0x00U},
        7U
    );
    const auto impossible_igmp_step = dissect_igmp(make_root_slice(impossible_igmp_packet));
    PFL_EXPECT(impossible_igmp_step.status == ParseStatus::malformed);
    PFL_EXPECT(!impossible_igmp_step.path_contribution.has_value());
    PFL_EXPECT(impossible_igmp_step.bounds.full.declared.length() == 7U);
    PFL_EXPECT(impossible_igmp_step.bounds.full.captured.length() == 7U);
    PFL_EXPECT(impossible_igmp_step.bounds.header.declared.length() == 7U);
    PFL_EXPECT(impossible_igmp_step.bounds.header.captured.length() == 7U);
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


void expect_icmp_fragmentation_preserves_selector_only_handoff() {
    const auto built = make_common_direct_registry();
    PFL_REQUIRE(built.ok());
    const auto& registry = *built.registry;

    const auto ipv4_fragment_packet = make_raw_packet(make_ethernet_ipv4_fragment_packet(
        ipv4(10, 45, 0, 1),
        ipv4(10, 45, 0, 2),
        detail::kIpProtocolIcmp,
        0x2000U,
        {8U, 0U, 0U, 0U}
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
    PFL_EXPECT(ipv4_fragment_step.handoff->selector.value == detail::kIpProtocolIcmp);
    PFL_EXPECT(!ipv4_fragment_step.handoff->child.has_value());

    const auto ipv4_fragment_shadow = run_shadow(ipv4_fragment_packet, registry);
    PFL_EXPECT(ipv4_fragment_shadow.outcome == ImportDissectionOutcome::recognized_flow);
    PFL_EXPECT(ipv4_fragment_shadow.stop_reason == StopReason::needs_reassembly);
    PFL_EXPECT(ipv4_fragment_shadow.terminal_protocol == ProtocolId::icmp);
    PFL_EXPECT(!ipv4_fragment_shadow.has_ports);
    PFL_EXPECT(format_shadow_path(ipv4_fragment_shadow) == "EthernetII -> IPv4");

    const auto src_addr = ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x61});
    const auto dst_addr = ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x62});
    const auto ipv6_fragment_packet = make_raw_packet(make_ethernet_ipv6_fragment_packet(
        src_addr,
        dst_addr,
        detail::kIpProtocolIcmpV6,
        {128U, 0U, 0U, 0U}
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
    PFL_EXPECT(fragment_step.handoff->selector.value == detail::kIpProtocolIcmpV6);
    PFL_EXPECT(!fragment_step.handoff->child.has_value());

    const auto ipv6_fragment_shadow = run_shadow(ipv6_fragment_packet, registry);
    PFL_EXPECT(ipv6_fragment_shadow.outcome == ImportDissectionOutcome::recognized_flow);
    PFL_EXPECT(ipv6_fragment_shadow.stop_reason == StopReason::needs_reassembly);
    PFL_EXPECT(ipv6_fragment_shadow.terminal_protocol == ProtocolId::icmpv6);
    PFL_EXPECT(!ipv6_fragment_shadow.has_ports);
    PFL_EXPECT(format_shadow_path(ipv6_fragment_shadow) == "EthernetII -> IPv6");
}

void expect_igmp_fragmentation_preserves_selector_only_handoff() {
    const auto built = make_common_direct_registry();
    PFL_REQUIRE(built.ok());
    const auto& registry = *built.registry;

    const auto ipv4_fragment_packet = make_raw_packet(make_ethernet_ipv4_fragment_packet(
        ipv4(10, 46, 0, 1),
        ipv4(224, 0, 0, 1),
        detail::kIpProtocolIgmp,
        0x2000U,
        {detail::kIgmpTypeMembershipQuery, 0x00U, 0x00U, 0x00U, 0xE0U, 0x00U, 0x00U, 0x01U}
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
    PFL_EXPECT(ipv4_fragment_step.handoff->selector.value == detail::kIpProtocolIgmp);
    PFL_EXPECT(!ipv4_fragment_step.handoff->child.has_value());

    StepKindRecorder recorder {};
    const DissectionEngine engine {};
    const auto engine_result = engine.run(
        registry,
        make_link_type_selector(ipv4_fragment_packet.data_link_type),
        ipv4_fragment_root,
        DissectionConsumer {.on_step = record_step_kind, .context = &recorder}
    );
    PFL_EXPECT(engine_result.stop_reason == StopReason::needs_reassembly);
    const std::vector<DissectionLayerKind> expected_kinds {
        DissectionLayerKind::ethernet_ii,
        DissectionLayerKind::ipv4,
    };
    PFL_EXPECT(recorder.kinds == expected_kinds);

    expect_shadow_matches_legacy_igmp_flow(
        registry,
        ipv4_fragment_packet,
        "EthernetII -> IPv4",
        "EthernetII -> IPv4",
        StopReason::needs_reassembly,
        ipv4(10, 46, 0, 1),
        ipv4(224, 0, 0, 1)
    );
}

void expect_igmp_shadow_only_flow_behavior() {
    const auto built = make_common_direct_registry();
    PFL_REQUIRE(built.ok());
    const auto& registry = *built.registry;

    const auto direct_packet = make_raw_packet(make_ethernet_ipv4_igmp_packet(
        ipv4(192, 0, 2, 10),
        ipv4(224, 0, 0, 1),
        detail::kIgmpTypeMembershipQuery,
        0x10U,
        0x1111U,
        0x00000000U,
        {0xDEU, 0xADU}
    ));
    StepKindRecorder direct_recorder {};
    const DissectionEngine engine {};
    const auto direct_result = engine.run(
        registry,
        make_link_type_selector(direct_packet.data_link_type),
        make_root_slice(direct_packet),
        DissectionConsumer {.on_step = record_step_kind, .context = &direct_recorder}
    );
    PFL_EXPECT(direct_result.stop_reason == StopReason::terminal_protocol);
    const std::vector<DissectionLayerKind> expected_direct_kinds {
        DissectionLayerKind::ethernet_ii,
        DissectionLayerKind::ipv4,
        DissectionLayerKind::igmp,
    };
    PFL_EXPECT(direct_recorder.kinds == expected_direct_kinds);
    expect_shadow_matches_legacy_igmp_flow(
        registry,
        direct_packet,
        "EthernetII -> IPv4",
        "EthernetII -> IPv4",
        StopReason::terminal_protocol,
        ipv4(192, 0, 2, 10),
        ipv4(224, 0, 0, 1)
    );

    const auto group_specific_query_packet = make_raw_packet(make_ethernet_ipv4_igmp_packet(
        ipv4(192, 0, 2, 13),
        ipv4(224, 0, 0, 1),
        detail::kIgmpTypeMembershipQuery,
        0x19U,
        0x1919U,
        0xEF090909U
    ));
    expect_shadow_matches_legacy_igmp_flow(
        registry,
        group_specific_query_packet,
        "EthernetII -> IPv4",
        "EthernetII -> IPv4",
        StopReason::terminal_protocol,
        ipv4(192, 0, 2, 13),
        ipv4(239, 9, 9, 9)
    );

    const auto v1_report_packet = make_raw_packet(make_ethernet_ipv4_igmp_packet(
        ipv4(192, 0, 2, 14),
        ipv4(224, 0, 0, 22),
        detail::kIgmpTypeV1MembershipReport,
        0x21U,
        0x2121U,
        0xEF010101U
    ));
    expect_shadow_matches_legacy_igmp_flow(
        registry,
        v1_report_packet,
        "EthernetII -> IPv4",
        "EthernetII -> IPv4",
        StopReason::terminal_protocol,
        ipv4(192, 0, 2, 14),
        ipv4(239, 1, 1, 1)
    );

    const auto vlan_packet = make_raw_packet(add_vlan_tags(
        make_ethernet_ipv4_igmp_packet(
            ipv4(192, 0, 2, 11),
            ipv4(224, 0, 0, 22),
            detail::kIgmpTypeV2MembershipReport,
            0x22U,
            0x2222U,
            0xEF010203U
        ),
        {{0x8100U, 405U}}
    ));
    expect_shadow_matches_legacy_igmp_flow(
        registry,
        vlan_packet,
        "EthernetII -> VLAN(vid=405) -> IPv4",
        "EthernetII -> VLAN(vid=405) -> IPv4",
        StopReason::terminal_protocol,
        ipv4(192, 0, 2, 11),
        ipv4(239, 1, 2, 3)
    );

    const auto nested_ipv4_packet = make_raw_packet(make_ethernet_ipv4_fragment_packet(
        ipv4(198, 18, 0, 1),
        ipv4(198, 18, 0, 2),
        detail::kIpProtocolIpv4Encapsulation,
        0U,
        make_ipv4_payload_packet(
            ipv4(10, 50, 0, 1),
            ipv4(224, 0, 0, 1),
            detail::kIpProtocolIgmp,
            make_igmp_message(detail::kIgmpTypeV2MembershipReport, 0x33U, 0x3333U, 0xE0000016U)
        )
    ));
    expect_shadow_only_nested_igmp_flow(
        registry,
        nested_ipv4_packet,
        "EthernetII -> IPv4 -> IPv4",
        StopReason::terminal_protocol,
        ipv4(10, 50, 0, 1),
        ipv4(224, 0, 0, 22)
    );

    const auto nested_ipv6_packet = make_raw_packet(make_ethernet_ipv6_packet(
        ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 20, 0, 0, 0, 0, 0, 0, 0, 1}),
        ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 20, 0, 0, 0, 0, 0, 0, 0, 2}),
        detail::kIpProtocolIpv4Encapsulation,
        make_ipv4_payload_packet(
            ipv4(10, 60, 0, 1),
            ipv4(224, 0, 0, 2),
            detail::kIpProtocolIgmp,
            make_igmp_message(detail::kIgmpTypeLeaveGroup, 0x44U, 0x4444U, 0xEF0A0A0AU)
        )
    ));
    expect_shadow_only_nested_igmp_flow(
        registry,
        nested_ipv6_packet,
        "EthernetII -> IPv6 -> IPv4",
        StopReason::terminal_protocol,
        ipv4(10, 60, 0, 1),
        ipv4(239, 10, 10, 10)
    );

    const auto nested_ipv4_ipv6_ipv4_packet = make_raw_packet(make_ethernet_ipv4_fragment_packet(
        ipv4(198, 18, 0, 3),
        ipv4(198, 18, 0, 4),
        detail::kIpProtocolIpv6Encapsulation,
        0U,
        make_ipv6_payload_packet(
            ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 21, 0, 0, 0, 0, 0, 0, 0, 1}),
            ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 21, 0, 0, 0, 0, 0, 0, 0, 2}),
            detail::kIpProtocolIpv4Encapsulation,
            make_ipv4_payload_packet(
                ipv4(10, 70, 0, 1),
                ipv4(239, 20, 20, 20),
                detail::kIpProtocolIgmp,
                make_igmp_message(detail::kIgmpTypeV3MembershipReport, 0x55U, 0x5555U, 0x01020304U)
            )
        )
    ));
    expect_shadow_only_nested_igmp_flow(
        registry,
        nested_ipv4_ipv6_ipv4_packet,
        "EthernetII -> IPv4 -> IPv6 -> IPv4",
        StopReason::terminal_protocol,
        ipv4(10, 70, 0, 1),
        ipv4(239, 20, 20, 20)
    );

    const auto outer_ipv6_hbh_inner_ipv4_packet = make_raw_packet(make_ethernet_ipv6_packet(
        ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 22, 0, 0, 0, 0, 0, 0, 0, 1}),
        ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 22, 0, 0, 0, 0, 0, 0, 0, 2}),
        detail::kIpProtocolHopByHop,
        make_ipv6_hop_by_hop_extension(
            detail::kIpProtocolIpv4Encapsulation,
            make_ipv4_payload_packet(
                ipv4(10, 80, 0, 1),
                ipv4(239, 30, 30, 30),
                detail::kIpProtocolIgmp,
                make_igmp_message(detail::kIgmpTypeMembershipQuery, 0x66U, 0x6666U, 0x00000000U)
            )
        )
    ));
    StepKindRecorder outer_ipv6_hbh_inner_ipv4_recorder {};
    const auto outer_ipv6_hbh_inner_ipv4_result = engine.run(
        registry,
        make_link_type_selector(outer_ipv6_hbh_inner_ipv4_packet.data_link_type),
        make_root_slice(outer_ipv6_hbh_inner_ipv4_packet),
        DissectionConsumer {.on_step = record_step_kind, .context = &outer_ipv6_hbh_inner_ipv4_recorder}
    );
    PFL_EXPECT(outer_ipv6_hbh_inner_ipv4_result.stop_reason == StopReason::terminal_protocol);
    const std::vector<DissectionLayerKind> expected_outer_ipv6_hbh_inner_ipv4_kinds {
        DissectionLayerKind::ethernet_ii,
        DissectionLayerKind::ipv6,
        DissectionLayerKind::ipv6_hop_by_hop,
        DissectionLayerKind::ipv4,
        DissectionLayerKind::igmp,
    };
    PFL_EXPECT(outer_ipv6_hbh_inner_ipv4_recorder.kinds == expected_outer_ipv6_hbh_inner_ipv4_kinds);
    expect_shadow_only_nested_igmp_flow(
        registry,
        outer_ipv6_hbh_inner_ipv4_packet,
        "EthernetII -> IPv6 -> IPv4",
        StopReason::terminal_protocol,
        ipv4(10, 80, 0, 1),
        ipv4(239, 30, 30, 30)
    );

    const auto unknown_type_packet = make_raw_packet(make_ethernet_ipv4_igmp_packet(
        ipv4(192, 0, 2, 12),
        ipv4(224, 0, 0, 250),
        0x99U,
        0x77U,
        0x9999U,
        0xEF010204U
    ));
    expect_shadow_matches_legacy_igmp_flow(
        registry,
        unknown_type_packet,
        "EthernetII -> IPv4",
        "EthernetII -> IPv4",
        StopReason::terminal_protocol,
        ipv4(192, 0, 2, 12),
        ipv4(239, 1, 2, 4)
    );

    const auto direct_ipv6_igmp_shadow = run_shadow(
        make_raw_packet(make_ethernet_ipv6_packet(
            ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 23, 0, 0, 0, 0, 0, 0, 0, 1}),
            ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 23, 0, 0, 0, 0, 0, 0, 0, 2}),
            detail::kIpProtocolIgmp,
            make_igmp_message(detail::kIgmpTypeMembershipQuery, 0x77U, 0x7777U, 0x00000000U)
        )),
        registry
    );
    PFL_EXPECT(direct_ipv6_igmp_shadow.outcome == ImportDissectionOutcome::unrecognized);
    PFL_EXPECT(direct_ipv6_igmp_shadow.stop_reason == StopReason::unknown_next_protocol);
    PFL_EXPECT(direct_ipv6_igmp_shadow.terminal_protocol == ProtocolId::unknown);
    PFL_EXPECT(format_shadow_path(direct_ipv6_igmp_shadow) == "EthernetII -> IPv6");
}

void expect_igmp_failures_remain_visible_without_path_contribution() {
    const auto built = make_common_direct_registry();
    PFL_REQUIRE(built.ok());
    const auto& registry = *built.registry;

    const auto truncated_igmp_packet = make_raw_packet(
        []() {
            auto packet = make_ethernet_ipv4_igmp_packet(
                ipv4(10, 90, 0, 1),
                ipv4(224, 0, 0, 1),
                detail::kIgmpTypeMembershipQuery,
                0x10U,
                0x1111U,
                0x00000000U
            );
            packet.resize(packet.size() - 1U);
            return packet;
        }(),
        14U + 20U + detail::kIgmpMinimumHeaderSize
    );
    StepKindRecorder truncated_recorder {};
    const DissectionEngine engine {};
    const auto truncated_result = engine.run(
        registry,
        make_link_type_selector(truncated_igmp_packet.data_link_type),
        make_root_slice(truncated_igmp_packet),
        DissectionConsumer {.on_step = record_step_kind, .context = &truncated_recorder}
    );
    PFL_EXPECT(truncated_result.stop_reason == StopReason::truncated);
    const std::vector<DissectionLayerKind> expected_truncated_kinds {
        DissectionLayerKind::ethernet_ii,
        DissectionLayerKind::ipv4,
        DissectionLayerKind::igmp,
    };
    PFL_EXPECT(truncated_recorder.kinds == expected_truncated_kinds);
    const auto truncated_shadow = run_shadow(truncated_igmp_packet, registry);
    PFL_EXPECT(truncated_shadow.outcome == ImportDissectionOutcome::unrecognized);
    PFL_EXPECT(truncated_shadow.stop_reason == StopReason::truncated);
    PFL_EXPECT(truncated_shadow.terminal_protocol == ProtocolId::igmp);
    PFL_EXPECT(format_shadow_path(truncated_shadow) == "EthernetII -> IPv4");

    const auto malformed_igmp_packet = make_raw_packet(make_ethernet_ipv4_fragment_packet(
        ipv4(10, 91, 0, 1),
        ipv4(224, 0, 0, 2),
        detail::kIpProtocolIgmp,
        0U,
        {detail::kIgmpTypeV2MembershipReport, 0x20U, 0x12U, 0x34U, 0xE0U, 0x00U, 0x00U}
    ));
    StepKindRecorder malformed_recorder {};
    const auto malformed_result = engine.run(
        registry,
        make_link_type_selector(malformed_igmp_packet.data_link_type),
        make_root_slice(malformed_igmp_packet),
        DissectionConsumer {.on_step = record_step_kind, .context = &malformed_recorder}
    );
    PFL_EXPECT(malformed_result.stop_reason == StopReason::malformed);
    const std::vector<DissectionLayerKind> expected_malformed_kinds {
        DissectionLayerKind::ethernet_ii,
        DissectionLayerKind::ipv4,
        DissectionLayerKind::igmp,
    };
    PFL_EXPECT(malformed_recorder.kinds == expected_malformed_kinds);
    const auto malformed_shadow = run_shadow(malformed_igmp_packet, registry);
    PFL_EXPECT(malformed_shadow.outcome == ImportDissectionOutcome::unrecognized);
    PFL_EXPECT(malformed_shadow.stop_reason == StopReason::malformed);
    PFL_EXPECT(malformed_shadow.terminal_protocol == ProtocolId::igmp);
    PFL_EXPECT(format_shadow_path(malformed_shadow) == "EthernetII -> IPv4");
}


void run_common_direct_network_dissection_tests() {
    expect_ipv4_options_shadow_parsing_and_declared_boundary_semantics();
    expect_ipv6_and_extension_canonical_parsers();
    expect_icmp_canonical_parsers_and_bounds();
    expect_igmp_canonical_parsers_and_bounds();
    expect_fragmented_ipv4_preserves_selector_only_handoff();
    expect_icmp_fragmentation_preserves_selector_only_handoff();
    expect_igmp_fragmentation_preserves_selector_only_handoff();
    expect_igmp_shadow_only_flow_behavior();
    expect_igmp_failures_remain_visible_without_path_contribution();
}

}  // namespace pfl::tests::common_direct_test
