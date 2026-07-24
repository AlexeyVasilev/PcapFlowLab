#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include "CommonDirectDissectionTestSupport.h"
#include "core/dissection/modules/CommonDirectModules.h"

namespace pfl::tests::common_direct_test {

using namespace dissection;

namespace {

std::vector<std::uint8_t> make_strict_eoip_bytes(
    const std::uint16_t frame_length,
    const std::uint16_t tunnel_id,
    const std::vector<std::uint8_t>& inner_frame
) {
    std::vector<std::uint8_t> bytes {};
    bytes.push_back(0x20U);
    bytes.push_back(0x01U);
    bytes.push_back(0x64U);
    bytes.push_back(0x00U);
    bytes.push_back(static_cast<std::uint8_t>((frame_length >> 8U) & 0xFFU));
    bytes.push_back(static_cast<std::uint8_t>(frame_length & 0xFFU));
    bytes.push_back(static_cast<std::uint8_t>(tunnel_id & 0xFFU));
    bytes.push_back(static_cast<std::uint8_t>((tunnel_id >> 8U) & 0xFFU));
    bytes.insert(bytes.end(), inner_frame.begin(), inner_frame.end());
    return bytes;
}

const EoipFacts* find_eoip_facts(const std::vector<DissectionStep>& steps) {
    for (const auto& step : steps) {
        if (step.layer != DissectionLayerKind::eoip) {
            continue;
        }

        if (const auto* facts = std::get_if<EoipFacts>(&step.facts); facts != nullptr) {
            return facts;
        }
    }

    return nullptr;
}

void expect_step_kinds(
    const std::vector<DissectionStep>& steps,
    const std::initializer_list<DissectionLayerKind> expected
) {
    const auto actual = collect_step_kinds(steps);
    PFL_REQUIRE(actual.size() == expected.size());

    std::size_t index = 0U;
    for (const auto kind : expected) {
        PFL_EXPECT(actual[index] == kind);
        ++index;
    }
}

std::string shadow_flow_identity_text(const ImportDissectionFacts& facts) {
    std::ostringstream builder {};
    builder << static_cast<int>(facts.family) << '|'
            << static_cast<int>(facts.terminal_protocol) << '|'
            << format_shadow_path(facts) << '|';
    if (facts.family == DissectionAddressFamily::ipv4) {
        builder << facts.src_addr_v4 << '|' << facts.dst_addr_v4;
    } else {
        for (const auto byte : facts.src_addr_v6) {
            builder << static_cast<int>(byte) << '.';
        }
        builder << '|';
        for (const auto byte : facts.dst_addr_v6) {
            builder << static_cast<int>(byte) << '.';
        }
    }
    builder << '|' << facts.src_port << '|' << facts.dst_port;
    return builder.str();
}

std::string legacy_flow_identity_text(const LegacyDirectFacts& facts) {
    std::ostringstream builder {};
    builder << static_cast<int>(facts.family) << '|'
            << static_cast<int>(facts.protocol) << '|'
            << format_protocol_path(facts.path) << '|';
    if (facts.family == DissectionAddressFamily::ipv4) {
        builder << facts.src_addr_v4 << '|' << facts.dst_addr_v4;
    } else {
        for (const auto byte : facts.src_addr_v6) {
            builder << static_cast<int>(byte) << '.';
        }
        builder << '|';
        for (const auto byte : facts.dst_addr_v6) {
            builder << static_cast<int>(byte) << '.';
        }
    }
    builder << '|' << facts.src_port << '|' << facts.dst_port;
    return builder.str();
}

void expect_direct_eoip_parser_and_variant_dispatch() {
    const auto inner_ipv4_udp = make_ethernet_frame_with_payload(
        detail::kEtherTypeIpv4,
        make_ipv4_payload_packet(
            ipv4(10, 80, 0, 10),
            ipv4(10, 80, 0, 20),
            detail::kIpProtocolUdp,
            make_ipv4_udp_segment(53800U, 443U, 4U)
        )
    );
    const auto eoip_bytes = make_strict_eoip_bytes(
        static_cast<std::uint16_t>(inner_ipv4_udp.size()),
        6400U,
        inner_ipv4_udp
    );

    {
        const auto step = dissect_eoip(make_declared_root_slice(eoip_bytes, eoip_bytes.size()));
        PFL_EXPECT(step.layer == DissectionLayerKind::eoip);
        PFL_EXPECT(step.status == ParseStatus::complete);
        PFL_EXPECT(step.stop_reason == StopReason::none);
        PFL_REQUIRE(step.path_contribution.has_value());
        PFL_EXPECT(*step.path_contribution == LayerKey::gre(6400U));
        PFL_REQUIRE(step.handoff.has_value());
        PFL_EXPECT(step.handoff->selector.domain == SelectorDomain::eoip_inner_frame);
        PFL_EXPECT(step.handoff->selector.value == kEoipInnerFrameSelectorValue);

        const auto* facts = std::get_if<EoipFacts>(&step.facts);
        PFL_REQUIRE(facts != nullptr);
        PFL_EXPECT(facts->frame_length == inner_ipv4_udp.size());
        PFL_EXPECT(facts->tunnel_id == 6400U);
        PFL_EXPECT(facts->header_length == 8U);
        PFL_EXPECT(step.bounds.header.declared.length() == 8U);
        PFL_EXPECT(step.bounds.payload.has_value());
        PFL_EXPECT(step.bounds.payload->declared.length() == inner_ipv4_udp.size());
    }

    {
        const auto strict_variant = dissect_ipv4_gre_variant(make_declared_root_slice(eoip_bytes, eoip_bytes.size()));
        PFL_EXPECT(strict_variant.layer == DissectionLayerKind::eoip);
    }

    {
        const auto ordinary_gre = make_gre_header(
            detail::kEtherTypeIpv4,
            make_ipv4_payload_packet(
                ipv4(10, 80, 0, 10),
                ipv4(10, 80, 0, 20),
                detail::kIpProtocolUdp,
                make_ipv4_udp_segment(53800U, 443U, 4U)
            )
        );
        const auto ordinary_variant =
            dissect_ipv4_gre_variant(make_declared_root_slice(ordinary_gre, ordinary_gre.size()));
        PFL_EXPECT(ordinary_variant.layer == DissectionLayerKind::gre);
    }

    {
        auto malformed_bytes = make_strict_eoip_bytes(
            static_cast<std::uint16_t>(inner_ipv4_udp.size() + 20U),
            6400U,
            inner_ipv4_udp
        );
        const auto malformed_step =
            dissect_eoip(make_declared_root_slice(malformed_bytes, malformed_bytes.size()));
        PFL_EXPECT(malformed_step.layer == DissectionLayerKind::eoip);
        PFL_EXPECT(malformed_step.status == ParseStatus::malformed);
        PFL_EXPECT(malformed_step.stop_reason == StopReason::malformed);
        PFL_EXPECT(!malformed_step.handoff.has_value());
    }
}

void expect_direct_eoip_header_boundary_classification() {
    {
        auto partial_eoip_word = make_strict_eoip_bytes(0U, 6400U, {});
        partial_eoip_word.resize(6U);

        const auto step = dissect_ipv4_gre_variant(make_declared_root_slice(partial_eoip_word, 8U));
        PFL_EXPECT(step.layer == DissectionLayerKind::eoip);
        PFL_EXPECT(step.status == ParseStatus::truncated);
        PFL_EXPECT(step.stop_reason == StopReason::truncated);
        PFL_EXPECT(!step.handoff.has_value());
    }

    {
        const auto full_eoip_word = make_strict_eoip_bytes(0U, 6400U, {});

        const auto step = dissect_ipv4_gre_variant(make_declared_root_slice(full_eoip_word, 6U));
        PFL_EXPECT(step.layer == DissectionLayerKind::eoip);
        PFL_EXPECT(step.status == ParseStatus::malformed);
        PFL_EXPECT(step.stop_reason == StopReason::malformed);
        PFL_EXPECT(!step.handoff.has_value());
    }

    {
        const auto short_inner_payload = make_strict_eoip_bytes(12U, 6400U, {0x01U, 0x02U, 0x03U, 0x04U});

        const auto step = dissect_eoip(make_declared_root_slice(short_inner_payload, 20U));
        PFL_EXPECT(step.layer == DissectionLayerKind::eoip);
        PFL_EXPECT(step.status == ParseStatus::truncated);
        PFL_EXPECT(step.stop_reason == StopReason::truncated);
        PFL_EXPECT(!step.handoff.has_value());
    }
}

void expect_direct_eoip_inner_boundary_classification() {
    {
        const auto short_inner_ethernet = make_strict_eoip_bytes(
            10U,
            6400U,
            {0x02U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x81U, 0x02U, 0x02U, 0x00U}
        );

        const auto eoip_step = dissect_eoip(make_declared_root_slice(short_inner_ethernet, short_inner_ethernet.size()));
        PFL_REQUIRE(eoip_step.handoff.has_value());
        PFL_REQUIRE(eoip_step.handoff->child.has_value());

        const auto inner_ethernet_step = dissect_eoip_inner_ethernet(*eoip_step.handoff->child);
        PFL_EXPECT(inner_ethernet_step.layer == DissectionLayerKind::ethernet_ii);
        PFL_EXPECT(inner_ethernet_step.status == ParseStatus::truncated);
        PFL_EXPECT(inner_ethernet_step.stop_reason == StopReason::truncated);
    }

    {
        const std::vector<std::uint8_t> partial_vlan_frame {
            0x02U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x81U, 0x02U, 0x02U, 0x00U, 0x00U, 0x00U,
            0x81U, 0x00U,
            0x07U, 0x0EU,
        };
        const auto eoip_step =
            dissect_eoip(make_declared_root_slice(make_strict_eoip_bytes(16U, 6400U, partial_vlan_frame), 24U));
        PFL_REQUIRE(eoip_step.handoff.has_value());
        PFL_REQUIRE(eoip_step.handoff->child.has_value());

        const auto inner_ethernet_step = dissect_eoip_inner_ethernet(*eoip_step.handoff->child);
        PFL_REQUIRE(inner_ethernet_step.handoff.has_value());
        PFL_REQUIRE(inner_ethernet_step.handoff->child.has_value());
        const auto& inner_vlan_child = *inner_ethernet_step.handoff->child;
        PFL_EXPECT(inner_vlan_child.declared_end() - inner_vlan_child.source_offset() == 2U);
        PFL_EXPECT(inner_vlan_child.captured_end() - inner_vlan_child.source_offset() == 2U);

        const auto inner_vlan_step = dissect_eoip_inner_vlan(inner_vlan_child);
        PFL_EXPECT(inner_vlan_step.layer == DissectionLayerKind::vlan);
        PFL_EXPECT(inner_vlan_step.status == ParseStatus::malformed);
        PFL_EXPECT(inner_vlan_step.stop_reason == StopReason::malformed);
    }

    {
        const std::vector<std::uint8_t> partial_vlan_frame {
            0x02U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
            0x81U, 0x02U, 0x02U, 0x00U, 0x00U, 0x00U,
            0x81U, 0x00U,
            0x07U, 0x0EU,
        };
        const auto inner_ethernet_step = dissect_eoip_inner_ethernet(make_declared_root_slice(partial_vlan_frame, 18U));
        PFL_REQUIRE(inner_ethernet_step.handoff.has_value());
        PFL_REQUIRE(inner_ethernet_step.handoff->child.has_value());
        const auto& inner_vlan_child = *inner_ethernet_step.handoff->child;
        PFL_EXPECT(inner_vlan_child.declared_end() - inner_vlan_child.source_offset() == 4U);
        PFL_EXPECT(inner_vlan_child.captured_end() - inner_vlan_child.source_offset() == 2U);

        const auto inner_vlan_step = dissect_eoip_inner_vlan(inner_vlan_child);
        PFL_EXPECT(inner_vlan_step.layer == DissectionLayerKind::vlan);
        PFL_EXPECT(inner_vlan_step.status == ParseStatus::truncated);
        PFL_EXPECT(inner_vlan_step.stop_reason == StopReason::truncated);
    }
}

void expect_supported_eoip_fixtures_match_legacy_paths(const DissectionRegistry& registry) {
    struct PositiveFixtureExpectation {
        const char* file_name;
        const char* expected_path;
    };

    constexpr PositiveFixtureExpectation cases[] {
        {"parsing/eoip/01_ipv4_eoip_inner_ipv4_udp.pcap",
         "EthernetII -> IPv4 -> GRE(key=0x00001900) -> EthernetII -> IPv4 -> UDP"},
        {"parsing/eoip/02_ipv4_eoip_inner_ipv4_tcp.pcap",
         "EthernetII -> IPv4 -> GRE(key=0x00001900) -> EthernetII -> IPv4 -> TCP"},
        {"parsing/eoip/03_ipv4_eoip_inner_ipv6_udp.pcap",
         "EthernetII -> IPv4 -> GRE(key=0x00001900) -> EthernetII -> IPv6 -> UDP"},
        {"parsing/eoip/04_ipv4_eoip_inner_vlan_ipv4_udp.pcap",
         "EthernetII -> IPv4 -> GRE(key=0x00001900) -> EthernetII -> VLAN(vid=1806) -> IPv4 -> UDP"},
        {"parsing/eoip/05_ipv4_eoip_inner_qinq_ipv6_tcp.pcap",
         "EthernetII -> IPv4 -> GRE(key=0x00001900) -> EthernetII -> VLAN(vid=1807) -> VLAN(vid=1808) -> IPv6 -> TCP"},
        {"parsing/eoip/06_outer_vlan_ipv4_eoip_inner_ipv4_udp.pcap",
         "EthernetII -> VLAN(vid=806) -> IPv4 -> GRE(key=0x00001900) -> EthernetII -> IPv4 -> UDP"},
        {"parsing/eoip/07_outer_vlan_mpls2_ipv4_eoip_inner_vlan_ipv4_udp.pcap",
         "EthernetII -> VLAN(vid=406) -> MPLS(label=56474) -> MPLS(label=477436) -> IPv4 -> GRE(key=0x00000019) -> EthernetII -> VLAN(vid=3918) -> IPv4 -> UDP"},
        {"parsing/eoip/19_ipv4_eoip_inner_llc_snap_ipv4_udp.pcap",
         "EthernetII -> IPv4 -> GRE(key=0x00001900) -> IEEE 802.3 -> LLC/SNAP -> IPv4 -> UDP"},
    };

    for (const auto& test_case : cases) {
        const ScopedTestContext fixture_context {
            std::string {"fixture="} + std::string {test_case.file_name}
        };
        const auto packet = require_raw_fixture_packet(test_case.file_name);
        expect_shadow_matches_legacy_flow(
            registry,
            packet,
            std::string {test_case.expected_path},
            StopReason::terminal_protocol
        );

        const auto steps = collect_shadow_steps(packet, registry);
        PFL_REQUIRE(find_eoip_facts(steps) != nullptr);
    }
}

void expect_eoip_identity_grouping_contract(const DissectionRegistry& registry) {
    struct GroupingExpectation {
        const char* file_name;
        std::size_t expected_unique_flow_count;
    };

    constexpr GroupingExpectation cases[] {
        {"parsing/eoip/08_same_inner_tuple_different_tunnel_ids.pcap", 2U},
        {"parsing/eoip/09_same_tunnel_id_different_inner_payload_lengths.pcap", 1U},
        {"parsing/eoip/10_same_tunnel_id_two_packets.pcap", 1U},
        {"parsing/eoip/11_max_tunnel_id.pcap", 1U},
        {"parsing/eoip/26_same_tunnel_same_inner_tuple_different_outer_ipv4_endpoints.pcap", 1U},
        {"parsing/eoip/27_same_tunnel_same_inner_tuple_different_outer_vlan_metadata.pcap", 2U},
        {"parsing/eoip/32_same_tunnel_same_inner_frame_different_frame_length.pcap", 1U},
    };

    for (const auto& test_case : cases) {
        const ScopedTestContext fixture_context {
            std::string {"fixture="} + std::string {test_case.file_name}
        };
        const auto packets = require_raw_fixture_packets(test_case.file_name);

        std::set<std::string> shadow_identities {};
        std::set<std::string> legacy_identities {};
        for (const auto& packet : packets) {
            const auto shadow = run_shadow(packet, registry);
            const auto legacy = decode_legacy_direct(packet);

            PFL_REQUIRE(legacy.recognized_flow);
            PFL_EXPECT(shadow.outcome == ImportDissectionOutcome::recognized_flow);
            PFL_EXPECT(format_shadow_path(shadow) == format_protocol_path(legacy.path));

            shadow_identities.insert(shadow_flow_identity_text(shadow));
            legacy_identities.insert(legacy_flow_identity_text(legacy));
        }

        PFL_EXPECT(shadow_identities.size() == test_case.expected_unique_flow_count);
        PFL_EXPECT(legacy_identities.size() == test_case.expected_unique_flow_count);
        PFL_EXPECT(shadow_identities == legacy_identities);
    }
}

void expect_gre_eoip_ambiguity_contract(const DissectionRegistry& registry) {
    expect_shadow_matches_legacy_flow(
        registry,
        require_raw_fixture_packet("parsing/eoip/21_ipv4_gre_v0_inner_ipv4_udp_not_eoip.pcap"),
        "EthernetII -> IPv4 -> GRE -> IPv4 -> UDP",
        StopReason::terminal_protocol
    );
    expect_shadow_matches_legacy_flow(
        registry,
        require_raw_fixture_packet("parsing/eoip/22_ipv4_gre_v0_teb_inner_ipv4_udp_not_eoip.pcap"),
        "EthernetII -> IPv4 -> GRE -> EthernetII -> IPv4 -> UDP",
        StopReason::terminal_protocol
    );
    expect_shadow_matches_legacy_flow(
        registry,
        require_raw_fixture_packet("parsing/eoip/23_ipv4_gre_v0_key_looks_like_eoip_word_inner_ipv4_udp.pcap"),
        "EthernetII -> IPv4 -> GRE(key=0x002e0019) -> IPv4 -> UDP",
        StopReason::terminal_protocol
    );

    struct NoFlowExpectation {
        const char* file_name;
        const char* expected_shadow_path;
        StopReason expected_stop_reason;
    };

    constexpr NoFlowExpectation no_flow_cases[] {
        {"parsing/eoip/15_eoip_missing_key_bit.pcap", "EthernetII -> IPv4", StopReason::unsupported_variant},
        {"parsing/eoip/16_gre_v1_unsupported_protocol_type.pcap", "EthernetII -> IPv4", StopReason::unsupported_variant},
        {"parsing/eoip/20_ipv6_gre_v1_k_6400_inner_ipv4_udp_not_eoip.pcap", "EthernetII -> IPv6", StopReason::unsupported_variant},
        {"parsing/eoip/24_ipv4_gre_v0_6400_wrong_version_key.pcap", "EthernetII -> IPv4 -> GRE(key=0xdeadbeef)", StopReason::unknown_next_protocol},
        {"parsing/eoip/25_ipv4_gre_v1_checksum_key_6400_not_eoip.pcap", "EthernetII -> IPv4", StopReason::unsupported_variant},
    };

    for (const auto& test_case : no_flow_cases) {
        const ScopedTestContext fixture_context {
            std::string {"fixture="} + std::string {test_case.file_name}
        };
        const auto packet = require_raw_fixture_packet(test_case.file_name);
        const auto shadow = run_shadow(packet, registry);
        const auto steps = collect_shadow_steps(packet, registry);

        PFL_EXPECT(shadow.outcome == ImportDissectionOutcome::unrecognized);
        PFL_EXPECT(shadow.stop_reason == test_case.expected_stop_reason);
        PFL_EXPECT(format_shadow_path(shadow) == test_case.expected_shadow_path);
        PFL_EXPECT(find_eoip_facts(steps) == nullptr);
    }
}

void expect_strict_eoip_no_flow_contract(const DissectionRegistry& registry) {
    {
        const auto packet = require_raw_fixture_packet("parsing/eoip/12_truncated_eoip_key_word.pcap");
        const auto shadow = run_shadow(packet, registry);
        const auto steps = collect_shadow_steps(packet, registry);

        PFL_EXPECT(shadow.outcome == ImportDissectionOutcome::unrecognized);
        PFL_EXPECT(shadow.stop_reason == StopReason::malformed);
        PFL_EXPECT(format_shadow_path(shadow) == "EthernetII -> IPv4");
        expect_step_kinds(steps, {
            DissectionLayerKind::ethernet_ii,
            DissectionLayerKind::ipv4,
            DissectionLayerKind::eoip,
        });
    }

    {
        const auto packet = require_raw_fixture_packet("parsing/eoip/13_eoip_payload_length_exceeds_available.pcap");
        const auto shadow = run_shadow(packet, registry);
        const auto steps = collect_shadow_steps(packet, registry);

        PFL_EXPECT(shadow.outcome == ImportDissectionOutcome::unrecognized);
        PFL_EXPECT(shadow.stop_reason == StopReason::malformed);
        PFL_EXPECT(format_shadow_path(shadow) == "EthernetII -> IPv4");
        expect_step_kinds(steps, {
            DissectionLayerKind::ethernet_ii,
            DissectionLayerKind::ipv4,
            DissectionLayerKind::eoip,
        });
    }

    {
        const auto packet = require_raw_fixture_packet("parsing/eoip/14_eoip_payload_length_smaller_than_inner_frame.pcap");
        const auto shadow = run_shadow(packet, registry);
        const auto steps = collect_shadow_steps(packet, registry);

        PFL_EXPECT(shadow.outcome == ImportDissectionOutcome::unrecognized);
        PFL_EXPECT(shadow.stop_reason == StopReason::truncated);
        PFL_EXPECT(format_shadow_path(shadow) == "EthernetII -> IPv4");
        expect_step_kinds(steps, {
            DissectionLayerKind::ethernet_ii,
            DissectionLayerKind::ipv4,
            DissectionLayerKind::eoip,
            DissectionLayerKind::ethernet_ii,
        });
    }

    {
        const auto packet = require_raw_fixture_packet("parsing/eoip/17_eoip_truncated_inner_ethernet.pcap");
        const auto shadow = run_shadow(packet, registry);
        const auto steps = collect_shadow_steps(packet, registry);

        PFL_EXPECT(shadow.outcome == ImportDissectionOutcome::unrecognized);
        PFL_EXPECT(shadow.stop_reason == StopReason::truncated);
        PFL_EXPECT(format_shadow_path(shadow) == "EthernetII -> IPv4");
        expect_step_kinds(steps, {
            DissectionLayerKind::ethernet_ii,
            DissectionLayerKind::ipv4,
            DissectionLayerKind::eoip,
            DissectionLayerKind::ethernet_ii,
        });
    }

    {
        const auto packet = require_raw_fixture_packet("parsing/eoip/18_eoip_truncated_inner_vlan.pcap");
        const auto shadow = run_shadow(packet, registry);
        const auto steps = collect_shadow_steps(packet, registry);

        PFL_EXPECT(shadow.outcome == ImportDissectionOutcome::unrecognized);
        PFL_EXPECT(shadow.stop_reason == StopReason::malformed);
        PFL_EXPECT(format_shadow_path(shadow) == "EthernetII -> IPv4");
        expect_step_kinds(steps, {
            DissectionLayerKind::ethernet_ii,
            DissectionLayerKind::ipv4,
            DissectionLayerKind::eoip,
            DissectionLayerKind::ethernet_ii,
            DissectionLayerKind::vlan,
        });
    }
}

void expect_fragmented_unsupported_and_nested_eoip_cases(const DissectionRegistry& registry) {
    for (const auto& packet : require_raw_fixture_packets("parsing/eoip/28_ipv4_eoip_first_fragment_mf_complete_inner.pcap")) {
        const auto shadow = run_shadow(packet, registry);
        const auto steps = collect_shadow_steps(packet, registry);
        PFL_EXPECT(shadow.outcome == ImportDissectionOutcome::unrecognized);
        PFL_EXPECT(shadow.stop_reason == StopReason::needs_reassembly);
        PFL_EXPECT(format_shadow_path(shadow) == "EthernetII -> IPv4");
        expect_step_kinds(steps, {
            DissectionLayerKind::ethernet_ii,
            DissectionLayerKind::ipv4,
        });
    }

    for (const auto& packet : require_raw_fixture_packets("parsing/eoip/29_ipv4_eoip_nonfirst_fragment_valid_looking_bytes_captrunc.pcap")) {
        const auto shadow = run_shadow(packet, registry);
        const auto steps = collect_shadow_steps(packet, registry);
        PFL_EXPECT(shadow.outcome == ImportDissectionOutcome::unrecognized);
        PFL_EXPECT(shadow.stop_reason == StopReason::needs_reassembly);
        PFL_EXPECT(format_shadow_path(shadow) == "EthernetII -> IPv4");
        expect_step_kinds(steps, {
            DissectionLayerKind::ethernet_ii,
            DissectionLayerKind::ipv4,
        });
    }

    {
        const auto packets = require_raw_fixture_packets("parsing/eoip/30_ipv4_eoip_inner_unsupported_ethernet_payloads.pcap");
        PFL_REQUIRE(packets.size() == 5U);

        for (const auto& packet : packets) {
            const auto shadow = run_shadow(packet, registry);
            const auto steps = collect_shadow_steps(packet, registry);
            const auto* eoip = find_eoip_facts(steps);

            PFL_EXPECT(shadow.outcome == ImportDissectionOutcome::unrecognized);
            PFL_EXPECT(shadow.stop_reason == StopReason::unknown_next_protocol);
            PFL_EXPECT(format_shadow_path(shadow) == "EthernetII -> IPv4");
            PFL_REQUIRE(eoip != nullptr);
            PFL_EXPECT(eoip->tunnel_id == 6400U);
            expect_step_kinds(steps, {
                DissectionLayerKind::ethernet_ii,
                DissectionLayerKind::ipv4,
                DissectionLayerKind::eoip,
                DissectionLayerKind::ethernet_ii,
            });
        }
    }

    {
        const auto packet = require_raw_fixture_packet("parsing/eoip/31_ipv4_eoip_nested_eoip_not_continued.pcap");
        const auto shadow = run_shadow(packet, registry);
        const auto steps = collect_shadow_steps(packet, registry);

        PFL_EXPECT(shadow.outcome == ImportDissectionOutcome::unrecognized);
        PFL_EXPECT(shadow.stop_reason == StopReason::unknown_next_protocol);
        PFL_EXPECT(format_shadow_path(shadow) == "EthernetII -> IPv4");
        expect_step_kinds(steps, {
            DissectionLayerKind::ethernet_ii,
            DissectionLayerKind::ipv4,
            DissectionLayerKind::eoip,
            DissectionLayerKind::ethernet_ii,
            DissectionLayerKind::ipv4,
        });

        std::size_t eoip_layer_count = 0U;
        for (const auto kind : collect_step_kinds(steps)) {
            if (kind == DissectionLayerKind::eoip) {
                ++eoip_layer_count;
            }
        }
        PFL_EXPECT(eoip_layer_count == 1U);
    }
}

}  // namespace

void run_common_direct_eoip_dissection_tests() {
    const auto built = make_common_direct_registry();
    PFL_REQUIRE(built.ok());
    const auto& registry = *built.registry;

    expect_direct_eoip_parser_and_variant_dispatch();
    expect_direct_eoip_header_boundary_classification();
    expect_direct_eoip_inner_boundary_classification();
    expect_supported_eoip_fixtures_match_legacy_paths(registry);
    expect_eoip_identity_grouping_contract(registry);
    expect_gre_eoip_ambiguity_contract(registry);
    expect_strict_eoip_no_flow_contract(registry);
    expect_fragmented_unsupported_and_nested_eoip_cases(registry);
}

}  // namespace pfl::tests::common_direct_test
