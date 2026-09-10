#include "CommonDirectDissectionTestSupport.h"

#include <filesystem>
#include <initializer_list>
#include <string>

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

void expect_packet_ref_context_unset(const PacketRef& packet_ref) {
    PFL_EXPECT(packet_ref.packet_index == 0U);
    PFL_EXPECT(packet_ref.byte_offset == 0U);
    PFL_EXPECT(packet_ref.captured_length == 0U);
    PFL_EXPECT(packet_ref.original_length == 0U);
    PFL_EXPECT(packet_ref.ts_sec == 0U);
    PFL_EXPECT(packet_ref.ts_usec == 0U);
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
        PFL_EXPECT(!decision.decoded_packet->ipv4->import_metadata.transport_payload_length.has_value());
        PFL_EXPECT(!decision.decoded_packet->ipv4->import_metadata.tcp_flags.has_value());
        PFL_EXPECT(!decision.decoded_packet->ipv4->import_metadata.is_ip_fragmented);
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
        PFL_EXPECT(!decision.decoded_packet->ipv6->import_metadata.transport_payload_length.has_value());
        PFL_EXPECT(!decision.decoded_packet->ipv6->import_metadata.tcp_flags.has_value());
        PFL_EXPECT(!decision.decoded_packet->ipv6->import_metadata.is_ip_fragmented);
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
        PFL_EXPECT(!decision.decoded_packet->ipv4->import_metadata.transport_payload_length.has_value());
        PFL_EXPECT(decision.decoded_packet->ipv4->import_metadata.tcp_flags == 0x12U);
        PFL_EXPECT(!decision.decoded_packet->ipv4->import_metadata.is_ip_fragmented);
        PFL_EXPECT(!decision.decoded_packet->terminal_transport_payload_bounds.has_value());
        expect_packet_ref_context_unset(decision.decoded_packet->ipv4->packet_ref);
    }

    {
        const ScopedTestContext context {"synthetic=udp_payload_ipv6"};
        ImportDissectionFacts facts {};
        facts.physical_path = make_path_builder({LayerKey::ethernet_ii(), LayerKey::ipv6(), LayerKey::udp()});
        facts.outcome = ImportDissectionOutcome::recognized_flow;
        facts.family = DissectionAddressFamily::ipv6;
        facts.terminal_protocol = ProtocolId::udp;
        facts.has_flow_addresses = true;
        facts.src_addr_v6[15] = 1U;
        facts.dst_addr_v6[15] = 2U;
        facts.src_port = 53000U;
        facts.dst_port = 53U;
        facts.has_ports = true;
        facts.has_transport_payload_length = true;
        facts.captured_transport_payload_length = 9U;
        facts.terminal_transport_payload_bounds = TerminalTransportPayloadBounds {
            .payload_offset = 62U,
            .declared_end_offset = 71U,
        };
        facts.final_status = ParseStatus::complete;
        facts.stop_reason = StopReason::terminal_protocol;
        const auto decision = adapt_dissection_import_facts(facts);
        PFL_REQUIRE(decision.has_decoded_packet());
        PFL_REQUIRE(decision.decoded_packet->ipv6.has_value());
        PFL_EXPECT(decision.decoded_packet->ipv6->flow_key.src_port == 53000U);
        PFL_EXPECT(decision.decoded_packet->ipv6->flow_key.dst_port == 53U);
        PFL_EXPECT(decision.decoded_packet->ipv6->flow_key.protocol == ProtocolId::udp);
        PFL_EXPECT(decision.decoded_packet->ipv6->import_metadata.transport_payload_length == 9U);
        PFL_EXPECT(!decision.decoded_packet->ipv6->import_metadata.tcp_flags.has_value());
        PFL_EXPECT(!decision.decoded_packet->ipv6->import_metadata.is_ip_fragmented);
        PFL_EXPECT(decision.decoded_packet->terminal_transport_payload_bounds == facts.terminal_transport_payload_bounds);
        expect_packet_ref_context_unset(decision.decoded_packet->ipv6->packet_ref);
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
        PFL_EXPECT(!decision.decoded_packet->ipv4->import_metadata.transport_payload_length.has_value());
        PFL_EXPECT(!decision.decoded_packet->ipv4->import_metadata.tcp_flags.has_value());
        PFL_EXPECT(decision.decoded_packet->ipv4->import_metadata.is_ip_fragmented);
        PFL_EXPECT(!decision.decoded_packet->terminal_transport_payload_bounds.has_value());
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
    expect_adapter_maps_synthetic_portless_and_payload_edge_cases();
    expect_adapter_preserves_unrecognized_and_non_flow_classification();
}

}  // namespace pfl::tests
