#include "CommonDirectDissectionTestSupport.h"

#include <filesystem>
#include <initializer_list>
#include <string>
#include <vector>

#include "core/decode/PacketDecoder.h"
#include "core/services/DissectionImportAdapter.h"

namespace pfl::tests {

using namespace common_direct_test;
using namespace dissection;

namespace {

const DissectionRegistry& require_common_direct_registry() {
    static const auto built = make_common_direct_registry();
    PFL_REQUIRE(built.ok());
    return *built.registry;
}

ProtocolPathBuilder make_path_builder(std::initializer_list<LayerKey> layers) {
    ProtocolPathBuilder builder {};
    for (const auto& layer : layers) {
        PFL_EXPECT(builder.push(layer));
    }
    return builder;
}

DissectionImportDecision adapt_fixture_packet(
    const std::filesystem::path& relative_path,
    const std::size_t packet_index = 0U
) {
    const auto packets = require_raw_fixture_packets(relative_path);
    PFL_REQUIRE(packet_index < packets.size());
    const auto facts = run_shadow(packets[packet_index], require_common_direct_registry());
    return adapt_dissection_import_facts(facts);
}

DecodedPacket decode_legacy_fixture_packet(
    const std::filesystem::path& relative_path,
    const std::size_t packet_index = 0U
) {
    PacketDecoder decoder {};
    const auto packets = require_raw_fixture_packets(relative_path);
    PFL_REQUIRE(packet_index < packets.size());
    return decoder.decode(packets[packet_index]);
}

void expect_packet_ref_context_unset(const PacketRef& packet_ref) {
    PFL_EXPECT(packet_ref.packet_index == 0U);
    PFL_EXPECT(packet_ref.byte_offset == 0U);
    PFL_EXPECT(packet_ref.captured_length == 0U);
    PFL_EXPECT(packet_ref.original_length == 0U);
    PFL_EXPECT(packet_ref.ts_sec == 0U);
    PFL_EXPECT(packet_ref.ts_usec == 0U);
}

void expect_adapted_packet_matches_legacy_semantics(
    const std::filesystem::path& relative_path,
    const std::size_t packet_index = 0U
) {
    const ScopedTestContext fixture_context {
        "fixture=" + relative_path.generic_string() + " | packet=" + std::to_string(packet_index + 1U)
    };
    const auto adapted = adapt_fixture_packet(relative_path, packet_index);
    const auto legacy = decode_legacy_fixture_packet(relative_path, packet_index);

    PFL_REQUIRE(legacy.has_value());
    PFL_EXPECT(adapted.outcome == ImportDissectionOutcome::recognized_flow);
    PFL_REQUIRE(adapted.has_decoded_packet());

    PFL_EXPECT(adapted.decoded_packet->protocol_path_builder.to_path() == legacy.protocol_path_builder.to_path());
    PFL_EXPECT(adapted.family == (legacy.ipv4.has_value() ? DissectionAddressFamily::ipv4 : DissectionAddressFamily::ipv6));
    PFL_EXPECT(adapted.terminal_protocol ==
        (legacy.ipv4.has_value() ? legacy.ipv4->flow_key.protocol : legacy.ipv6->flow_key.protocol));
    PFL_EXPECT(!adapted.path_overflowed);

    if (legacy.ipv4.has_value()) {
        PFL_REQUIRE(adapted.decoded_packet->ipv4.has_value());
        PFL_EXPECT(!adapted.decoded_packet->ipv6.has_value());
        PFL_EXPECT(adapted.decoded_packet->ipv4->flow_key == legacy.ipv4->flow_key);
        PFL_EXPECT(adapted.decoded_packet->ipv4->packet_ref.payload_length == legacy.ipv4->packet_ref.payload_length);
        PFL_EXPECT(adapted.decoded_packet->ipv4->packet_ref.tcp_flags == legacy.ipv4->packet_ref.tcp_flags);
        PFL_EXPECT(adapted.decoded_packet->ipv4->packet_ref.is_ip_fragmented == legacy.ipv4->packet_ref.is_ip_fragmented);
        expect_packet_ref_context_unset(adapted.decoded_packet->ipv4->packet_ref);
        return;
    }

    PFL_REQUIRE(legacy.ipv6.has_value());
    PFL_REQUIRE(adapted.decoded_packet->ipv6.has_value());
    PFL_EXPECT(!adapted.decoded_packet->ipv4.has_value());
    PFL_EXPECT(adapted.decoded_packet->ipv6->flow_key == legacy.ipv6->flow_key);
    PFL_EXPECT(adapted.decoded_packet->ipv6->packet_ref.payload_length == legacy.ipv6->packet_ref.payload_length);
    PFL_EXPECT(adapted.decoded_packet->ipv6->packet_ref.tcp_flags == legacy.ipv6->packet_ref.tcp_flags);
    PFL_EXPECT(adapted.decoded_packet->ipv6->packet_ref.is_ip_fragmented == legacy.ipv6->packet_ref.is_ip_fragmented);
    expect_packet_ref_context_unset(adapted.decoded_packet->ipv6->packet_ref);
}

void expect_adapter_matches_legacy_for_direct_transport_fixtures() {
    expect_adapted_packet_matches_legacy_semantics("parsing/tcp/ipv4_tcp_valid_checksum_1.pcap");
    expect_adapted_packet_matches_legacy_semantics("parsing/tcp/tcp_generic_payload_7.pcap");
    expect_adapted_packet_matches_legacy_semantics("parsing/udp/ipv6_udp_bad_checksum_1.pcap");
    expect_adapted_packet_matches_legacy_semantics("parsing/sctp/01_sctp_ipv4_data_s1ap.pcap");
}

void expect_adapter_matches_legacy_for_portless_protocol_fixtures() {
    expect_adapted_packet_matches_legacy_semantics("parsing/arp/01_arp_request_ipv4.pcap");
    expect_adapted_packet_matches_legacy_semantics("parsing/igmp/01_igmpv1_membership_report_mdns_group.pcap");
    expect_adapted_packet_matches_legacy_semantics("parsing/ip_encapsulation/15_ipv4_in_ipv4_inner_icmp.pcap");
    expect_adapted_packet_matches_legacy_semantics("parsing/ip_encapsulation/16_ipv6_in_ipv4_inner_icmpv6.pcap");
    expect_adapted_packet_matches_legacy_semantics("parsing/esp/01_ipv4_esp_basic.pcap");
}

void expect_adapter_matches_legacy_for_overlay_and_carrier_fixtures() {
    expect_adapted_packet_matches_legacy_semantics("parsing/gre/07_gre_key_ipv4_udp.pcap");
    expect_adapted_packet_matches_legacy_semantics("parsing/vxlan/01_vxlan_inner_ipv4_tcp.pcap");
    expect_adapted_packet_matches_legacy_semantics("parsing/geneve/01_geneve_inner_ipv4_tcp.pcap");
    expect_adapted_packet_matches_legacy_semantics("parsing/gtpu/01_gtpu_inner_ipv4_tcp.pcap");
    expect_adapted_packet_matches_legacy_semantics("parsing/pppoe/04_pppoe_session_ipv6_udp.pcap");
}

void expect_adapter_matches_legacy_for_fragment_shell_fixtures() {
    expect_adapted_packet_matches_legacy_semantics("parsing/vxlan/24_vxlan_outer_ipv4_fragmentation.pcap");
    expect_adapted_packet_matches_legacy_semantics("parsing/vxlan/25_vxlan_outer_ipv6_fragmentation.pcap");
}

void expect_adapter_maps_synthetic_portless_and_payload_edge_cases() {
    {
        const ScopedTestContext context {"synthetic=icmp_portless_ipv4"};
        const auto facts = ImportDissectionFacts {
            .physical_path = make_path_builder({LayerKey::ethernet_ii(), LayerKey::ipv4()}),
            .outcome = ImportDissectionOutcome::recognized_flow,
            .family = DissectionAddressFamily::ipv4,
            .terminal_protocol = ProtocolId::icmp,
            .has_flow_addresses = true,
            .src_addr_v4 = 0x0A000001U,
            .dst_addr_v4 = 0x0A000002U,
            .final_status = ParseStatus::complete,
            .stop_reason = StopReason::terminal_protocol,
        };
        const auto decision = adapt_dissection_import_facts(facts);
        PFL_REQUIRE(decision.has_decoded_packet());
        PFL_REQUIRE(decision.decoded_packet->ipv4.has_value());
        PFL_EXPECT(decision.decoded_packet->ipv4->flow_key.src_port == 0U);
        PFL_EXPECT(decision.decoded_packet->ipv4->flow_key.dst_port == 0U);
        PFL_EXPECT(decision.decoded_packet->ipv4->flow_key.protocol == ProtocolId::icmp);
        PFL_EXPECT(decision.decoded_packet->ipv4->packet_ref.payload_length == 0U);
        PFL_EXPECT(decision.decoded_packet->ipv4->packet_ref.tcp_flags == 0U);
        PFL_EXPECT(!decision.decoded_packet->ipv4->packet_ref.is_ip_fragmented);
    }

    {
        const ScopedTestContext context {"synthetic=icmpv6_portless_ipv6"};
        ImportDissectionFacts facts {};
        facts.physical_path = make_path_builder({LayerKey::ethernet_ii(), LayerKey::ipv6()});
        facts.outcome = ImportDissectionOutcome::recognized_flow;
        facts.family = DissectionAddressFamily::ipv6;
        facts.terminal_protocol = ProtocolId::icmpv6;
        facts.has_flow_addresses = true;
        facts.src_addr_v6[15] = 1U;
        facts.dst_addr_v6[15] = 2U;
        facts.final_status = ParseStatus::complete;
        facts.stop_reason = StopReason::terminal_protocol;
        const auto decision = adapt_dissection_import_facts(facts);
        PFL_REQUIRE(decision.has_decoded_packet());
        PFL_REQUIRE(decision.decoded_packet->ipv6.has_value());
        PFL_EXPECT(decision.decoded_packet->ipv6->flow_key.src_port == 0U);
        PFL_EXPECT(decision.decoded_packet->ipv6->flow_key.dst_port == 0U);
        PFL_EXPECT(decision.decoded_packet->ipv6->flow_key.protocol == ProtocolId::icmpv6);
        PFL_EXPECT(decision.decoded_packet->ipv6->packet_ref.payload_length == 0U);
        PFL_EXPECT(decision.decoded_packet->ipv6->packet_ref.tcp_flags == 0U);
        PFL_EXPECT(!decision.decoded_packet->ipv6->packet_ref.is_ip_fragmented);
    }

    {
        const ScopedTestContext context {"synthetic=tcp_no_payload_ipv4"};
        const auto facts = ImportDissectionFacts {
            .physical_path = make_path_builder({LayerKey::ethernet_ii(), LayerKey::ipv4()}),
            .outcome = ImportDissectionOutcome::recognized_flow,
            .family = DissectionAddressFamily::ipv4,
            .terminal_protocol = ProtocolId::tcp,
            .has_flow_addresses = true,
            .src_addr_v4 = 0xC0000201U,
            .dst_addr_v4 = 0xC6336401U,
            .src_port = 443U,
            .dst_port = 51515U,
            .has_ports = true,
            .has_tcp_flags = true,
            .tcp_flags = 0x12U,
            .final_status = ParseStatus::complete,
            .stop_reason = StopReason::terminal_protocol,
        };
        const auto decision = adapt_dissection_import_facts(facts);
        PFL_REQUIRE(decision.has_decoded_packet());
        PFL_REQUIRE(decision.decoded_packet->ipv4.has_value());
        PFL_EXPECT(decision.decoded_packet->ipv4->flow_key.src_port == 443U);
        PFL_EXPECT(decision.decoded_packet->ipv4->flow_key.dst_port == 51515U);
        PFL_EXPECT(decision.decoded_packet->ipv4->packet_ref.payload_length == 0U);
        PFL_EXPECT(decision.decoded_packet->ipv4->packet_ref.tcp_flags == 0x12U);
        PFL_EXPECT(!decision.decoded_packet->ipv4->packet_ref.is_ip_fragmented);
        expect_packet_ref_context_unset(decision.decoded_packet->ipv4->packet_ref);
    }

    {
        const ScopedTestContext context {"synthetic=ipv4_fragment_shell"};
        const auto facts = ImportDissectionFacts {
            .physical_path = make_path_builder({LayerKey::ethernet_ii(), LayerKey::ipv4()}),
            .outcome = ImportDissectionOutcome::recognized_flow,
            .family = DissectionAddressFamily::ipv4,
            .terminal_protocol = ProtocolId::udp,
            .has_flow_addresses = true,
            .src_addr_v4 = 0xC0000201U,
            .dst_addr_v4 = 0xC6336401U,
            .has_ipv4_fragmentation = true,
            .ipv4_fragmentation = ImportIpv4Fragmentation {
                .is_fragmented = true,
                .more_fragments = true,
                .fragment_offset_units = 0U,
            },
            .final_status = ParseStatus::complete,
            .stop_reason = StopReason::needs_reassembly,
        };
        const auto decision = adapt_dissection_import_facts(facts);
        PFL_REQUIRE(decision.has_decoded_packet());
        PFL_REQUIRE(decision.decoded_packet->ipv4.has_value());
        PFL_EXPECT(decision.decoded_packet->ipv4->flow_key.src_port == 0U);
        PFL_EXPECT(decision.decoded_packet->ipv4->flow_key.dst_port == 0U);
        PFL_EXPECT(decision.decoded_packet->ipv4->packet_ref.payload_length == 0U);
        PFL_EXPECT(decision.decoded_packet->ipv4->packet_ref.tcp_flags == 0U);
        PFL_EXPECT(decision.decoded_packet->ipv4->packet_ref.is_ip_fragmented);
        expect_packet_ref_context_unset(decision.decoded_packet->ipv4->packet_ref);
    }
}

void expect_adapter_preserves_unrecognized_and_non_flow_classification() {
    {
        const ScopedTestContext context {"fixture=parsing/geneve/28_geneve_udp_declared_bounds_matrix.pcap | packet=2"};
        const auto decision = adapt_fixture_packet("parsing/geneve/28_geneve_udp_declared_bounds_matrix.pcap", 2U);
        PFL_EXPECT(decision.outcome == ImportDissectionOutcome::unrecognized);
        PFL_EXPECT(!decision.has_decoded_packet());
        PFL_EXPECT(decision.stop_reason == StopReason::malformed);
        PFL_EXPECT(decision.terminal_protocol == ProtocolId::udp);
        PFL_EXPECT(format_protocol_path(decision.physical_path.to_path()) == "EthernetII -> IPv4");
        PFL_EXPECT(!decision.path_overflowed);

        ProtocolPathRegistry registry {};
        PFL_EXPECT(registry.size() == 0U);
        if (decision.has_decoded_packet()) {
            static_cast<void>(registry.intern(decision.decoded_packet->protocol_path_builder.to_path()));
        }
        PFL_EXPECT(registry.size() == 0U);
    }

    {
        const ScopedTestContext context {"synthetic=recognized_non_flow"};
        const auto facts = ImportDissectionFacts {
            .physical_path = make_path_builder({LayerKey::ethernet_ii(), LayerKey::pppoe()}),
            .outcome = ImportDissectionOutcome::recognized_non_flow,
            .family = DissectionAddressFamily::unknown,
            .terminal_protocol = ProtocolId::unknown,
            .final_status = ParseStatus::complete,
            .stop_reason = StopReason::terminal_protocol,
        };
        const auto decision = adapt_dissection_import_facts(facts);
        PFL_EXPECT(decision.outcome == ImportDissectionOutcome::recognized_non_flow);
        PFL_EXPECT(!decision.has_decoded_packet());
        PFL_EXPECT(format_protocol_path(decision.physical_path.to_path()) == "EthernetII -> PPPoE");
    }

    {
        const ScopedTestContext context {"synthetic=path_overflow"};
        const auto facts = ImportDissectionFacts {
            .physical_path = make_path_builder({LayerKey::ethernet_ii(), LayerKey::ipv4()}),
            .outcome = ImportDissectionOutcome::recognized_flow,
            .family = DissectionAddressFamily::ipv4,
            .terminal_protocol = ProtocolId::tcp,
            .has_flow_addresses = true,
            .src_addr_v4 = 0x0A000001U,
            .dst_addr_v4 = 0x0A000002U,
            .src_port = 1234U,
            .dst_port = 443U,
            .has_ports = true,
            .has_transport_payload_length = true,
            .captured_transport_payload_length = 5U,
            .has_tcp_flags = true,
            .tcp_flags = 0x18U,
            .final_status = ParseStatus::complete,
            .stop_reason = StopReason::terminal_protocol,
            .path_overflowed = true,
        };
        const auto decision = adapt_dissection_import_facts(facts);
        PFL_EXPECT(decision.outcome == ImportDissectionOutcome::recognized_flow);
        PFL_EXPECT(!decision.has_decoded_packet());
        PFL_EXPECT(decision.path_overflowed);
        PFL_EXPECT(format_protocol_path(decision.physical_path.to_path()) == "EthernetII -> IPv4");
    }
}

}  // namespace

void run_dissection_import_adapter_tests() {
    expect_adapter_matches_legacy_for_direct_transport_fixtures();
    expect_adapter_matches_legacy_for_portless_protocol_fixtures();
    expect_adapter_matches_legacy_for_overlay_and_carrier_fixtures();
    expect_adapter_matches_legacy_for_fragment_shell_fixtures();
    expect_adapter_maps_synthetic_portless_and_payload_edge_cases();
    expect_adapter_preserves_unrecognized_and_non_flow_classification();
}

}  // namespace pfl::tests
