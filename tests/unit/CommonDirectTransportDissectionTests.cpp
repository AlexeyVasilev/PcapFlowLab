#include "CommonDirectDissectionTestSupport.h"
#include "core/dissection/modules/CommonDirectModules.h"

namespace pfl::tests::common_direct_test {

using namespace dissection;


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


void run_common_direct_transport_dissection_tests() {
    expect_ipv4_tcp_udp_and_arp_canonical_parsers();
    expect_sctp_canonical_parsers_and_bounds();
    expect_sctp_fragmentation_preserves_selector_only_handoff();
}

}  // namespace pfl::tests::common_direct_test
