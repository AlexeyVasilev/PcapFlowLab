#include <algorithm>
#include <array>
#include <filesystem>
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

struct FixturePacketExpectation {
    std::string_view fixture {};
    std::size_t packet_index {0U};
    std::optional<std::string_view> expected_path {};
    std::optional<StopReason> expected_stop_reason {};
};

constexpr std::array<std::string_view, 34> kGeneveFixtures {{
    "parsing/geneve/01_geneve_inner_ipv4_tcp.pcap",
    "parsing/geneve/02_geneve_inner_ipv4_udp.pcap",
    "parsing/geneve/03_geneve_inner_ipv6_tcp.pcap",
    "parsing/geneve/04_geneve_inner_ipv6_udp.pcap",
    "parsing/geneve/05_geneve_truncated_base_header.pcap",
    "parsing/geneve/06_geneve_invalid_version.pcap",
    "parsing/geneve/07_geneve_options_length_truncated.pcap",
    "parsing/geneve/08_geneve_truncated_inner_ethernet.pcap",
    "parsing/geneve/09_geneve_truncated_inner_ipv4.pcap",
    "parsing/geneve/10_geneve_unsupported_protocol_type.pcap",
    "parsing/geneve/11_geneve_inner_ipv4_tcp_bidirectional.pcap",
    "parsing/geneve/12_geneve_same_outer_tuple_different_inner_flows.pcap",
    "parsing/geneve/13_geneve_inner_vlan_ipv4_tcp.pcap",
    "parsing/geneve/14_geneve_outer_ipv6_inner_ipv4_tcp.pcap",
    "parsing/geneve/15_geneve_wrong_udp_port_valid_geneve_payload.pcap",
    "parsing/geneve/16_geneve_vni_boundary_values.pcap",
    "parsing/geneve/17_geneve_with_options_inner_ipv4_tcp.pcap",
    "parsing/geneve/18_geneve_udp_port_direction_matrix.pcap",
    "parsing/geneve/19_geneve_same_inner_tuple_different_vni.pcap",
    "parsing/geneve/20_geneve_outer_tagged_contexts.pcap",
    "parsing/geneve/21_geneve_identity_outer_carrier_variation_same_flow.pcap",
    "parsing/geneve/22_geneve_identity_outer_and_inner_vlan_splits.pcap",
    "parsing/geneve/23_geneve_outer_ipv4_fragmentation.pcap",
    "parsing/geneve/24_geneve_outer_ipv6_fragmentation.pcap",
    "parsing/geneve/25_geneve_option_and_flag_tolerance_matrix.pcap",
    "parsing/geneve/26_geneve_inner_supported_and_visible_matrix.pcap",
    "parsing/geneve/27_geneve_unsupported_and_nested_matrix.pcap",
    "parsing/geneve/28_geneve_udp_declared_bounds_matrix.pcap",
    "parsing/geneve/29_geneve_capture_truncation_matrix.pcap",
    "parsing/geneve/30_geneve_vni_byte_order_distinct_values.pcap",
    "parsing/geneve/31_geneve_linux_cooked_contexts.pcap",
    "parsing/geneve/32_geneve_linux_cooked_v2_contexts.pcap",
    "parsing/geneve/33_geneve_inner_unsupported_ethernet_payloads.pcap",
    "parsing/geneve/34_geneve_nested_gtpu_no_recursion.pcap",
}};

std::vector<std::uint8_t> make_geneve_bytes(
    const std::uint32_t vni,
    const std::vector<std::uint8_t>& inner_frame,
    const std::vector<std::uint8_t>& options = {},
    const std::uint8_t version = 0U,
    const bool oam_flag = false,
    const bool critical_flag = false,
    const std::uint8_t reserved_control_bits = 0U,
    const std::uint16_t protocol_type = detail::kGeneveProtocolTypeEthernet,
    const std::uint8_t reserved_trailer_byte = 0U
) {
    PFL_REQUIRE((options.size() % 4U) == 0U);
    const auto option_length_words = static_cast<std::uint8_t>(options.size() / 4U);
    std::vector<std::uint8_t> bytes {
        static_cast<std::uint8_t>((version << 6U) | option_length_words),
        static_cast<std::uint8_t>((oam_flag ? 0x80U : 0U) |
                                  (critical_flag ? 0x40U : 0U) |
                                  (reserved_control_bits & 0x3FU)),
    };
    append_be16(bytes, protocol_type);
    bytes.push_back(static_cast<std::uint8_t>((vni >> 16U) & 0xFFU));
    bytes.push_back(static_cast<std::uint8_t>((vni >> 8U) & 0xFFU));
    bytes.push_back(static_cast<std::uint8_t>(vni & 0xFFU));
    bytes.push_back(reserved_trailer_byte);
    bytes.insert(bytes.end(), options.begin(), options.end());
    bytes.insert(bytes.end(), inner_frame.begin(), inner_frame.end());
    return bytes;
}

const GeneveFacts* find_geneve_facts(const std::vector<DissectionStep>& steps) {
    for (const auto& step : steps) {
        if (step.layer != DissectionLayerKind::geneve) {
            continue;
        }

        if (const auto* facts = std::get_if<GeneveFacts>(&step.facts); facts != nullptr) {
            return facts;
        }
    }

    return nullptr;
}

void expect_step_kinds(
    const std::vector<DissectionStep>& steps,
    const std::initializer_list<DissectionLayerKind> expected_kinds
) {
    const auto actual = collect_step_kinds(steps);
    const std::vector<DissectionLayerKind> expected {expected_kinds};
    PFL_EXPECT(actual == expected);
}

std::string shadow_flow_identity_text(const ImportDissectionFacts& facts) {
    auto canonicalize_endpoints = [](std::string first, std::string second) {
        if (second < first) {
            std::swap(first, second);
        }
        return std::pair {std::move(first), std::move(second)};
    };

    std::ostringstream builder {};
    builder << static_cast<int>(facts.family) << '|'
            << static_cast<int>(facts.terminal_protocol) << '|'
            << format_shadow_path(facts) << '|';

    std::string first_endpoint {};
    std::string second_endpoint {};
    if (facts.family == DissectionAddressFamily::ipv4) {
        first_endpoint = std::to_string(facts.src_addr_v4) + ":" + std::to_string(facts.src_port);
        second_endpoint = std::to_string(facts.dst_addr_v4) + ":" + std::to_string(facts.dst_port);
    } else {
        std::ostringstream first_builder {};
        for (const auto byte : facts.src_addr_v6) {
            first_builder << static_cast<int>(byte) << '.';
        }
        first_builder << ':' << facts.src_port;

        std::ostringstream second_builder {};
        for (const auto byte : facts.dst_addr_v6) {
            second_builder << static_cast<int>(byte) << '.';
        }
        second_builder << ':' << facts.dst_port;

        first_endpoint = std::move(first_builder).str();
        second_endpoint = std::move(second_builder).str();
    }

    const auto [canonical_first, canonical_second] =
        canonicalize_endpoints(std::move(first_endpoint), std::move(second_endpoint));
    builder << canonical_first << '|' << canonical_second;
    return builder.str();
}

std::string legacy_flow_identity_text(const LegacyDirectFacts& facts) {
    auto canonicalize_endpoints = [](std::string first, std::string second) {
        if (second < first) {
            std::swap(first, second);
        }
        return std::pair {std::move(first), std::move(second)};
    };

    std::ostringstream builder {};
    builder << static_cast<int>(facts.family) << '|'
            << static_cast<int>(facts.protocol) << '|'
            << format_protocol_path(facts.path) << '|';

    std::string first_endpoint {};
    std::string second_endpoint {};
    if (facts.family == DissectionAddressFamily::ipv4) {
        first_endpoint = std::to_string(facts.src_addr_v4) + ":" + std::to_string(facts.src_port);
        second_endpoint = std::to_string(facts.dst_addr_v4) + ":" + std::to_string(facts.dst_port);
    } else {
        std::ostringstream first_builder {};
        for (const auto byte : facts.src_addr_v6) {
            first_builder << static_cast<int>(byte) << '.';
        }
        first_builder << ':' << facts.src_port;

        std::ostringstream second_builder {};
        for (const auto byte : facts.dst_addr_v6) {
            second_builder << static_cast<int>(byte) << '.';
        }
        second_builder << ':' << facts.dst_port;

        first_endpoint = std::move(first_builder).str();
        second_endpoint = std::move(second_builder).str();
    }

    const auto [canonical_first, canonical_second] =
        canonicalize_endpoints(std::move(first_endpoint), std::move(second_endpoint));
    builder << canonical_first << '|' << canonical_second;
    return builder.str();
}

void expect_packet_shadow_matches_legacy(
    const DissectionRegistry& registry,
    const FixturePacketExpectation& expectation
) {
    const auto context_text =
        "fixture=" + std::string(expectation.fixture) + " | packet=" + std::to_string(expectation.packet_index);
    const ScopedTestContext fixture_context {context_text.c_str()};

    const auto packets = require_raw_fixture_packets(std::filesystem::path {std::string(expectation.fixture)});
    PFL_REQUIRE(expectation.packet_index < packets.size());
    const auto& packet = packets[expectation.packet_index];

    const auto legacy = decode_legacy_direct(packet);
    const auto shadow = run_shadow(packet, registry);

    if (!legacy.recognized_flow) {
        PFL_EXPECT(shadow.outcome == ImportDissectionOutcome::unrecognized);
        if (expectation.expected_path.has_value()) {
            PFL_EXPECT(format_shadow_path(shadow) == *expectation.expected_path);
        }
        if (expectation.expected_stop_reason.has_value()) {
            PFL_EXPECT(shadow.stop_reason == *expectation.expected_stop_reason);
        }
        return;
    }

    const auto expected_path = expectation.expected_path.has_value()
        ? std::string(*expectation.expected_path)
        : format_protocol_path(legacy.path);
    const auto expected_stop_reason = expectation.expected_stop_reason.value_or(
        legacy.is_ip_fragmented ? StopReason::needs_reassembly : StopReason::terminal_protocol
    );

    PFL_EXPECT(shadow.outcome == ImportDissectionOutcome::recognized_flow);
    PFL_EXPECT(shadow.stop_reason == expected_stop_reason);
    PFL_EXPECT(shadow_path(shadow) == legacy.path);
    PFL_EXPECT(format_shadow_path(shadow) == expected_path);
    PFL_EXPECT(format_protocol_path(legacy.path) == expected_path);
    PFL_EXPECT(shadow.terminal_protocol == legacy.protocol);
    PFL_EXPECT(shadow.family == legacy.family);
    PFL_EXPECT(shadow.has_flow_addresses == legacy.has_addresses);
    if (legacy.family == DissectionAddressFamily::ipv4) {
        PFL_EXPECT(shadow.src_addr_v4 == legacy.src_addr_v4);
        PFL_EXPECT(shadow.dst_addr_v4 == legacy.dst_addr_v4);
        PFL_EXPECT(shadow.has_ipv4_fragmentation);
        PFL_EXPECT(shadow.ipv4_fragmentation.is_fragmented == legacy.is_ip_fragmented);
    } else if (legacy.family == DissectionAddressFamily::ipv6) {
        PFL_EXPECT(shadow.src_addr_v6 == legacy.src_addr_v6);
        PFL_EXPECT(shadow.dst_addr_v6 == legacy.dst_addr_v6);
        PFL_EXPECT(shadow.has_ipv6_fragmentation);
        PFL_EXPECT(shadow.ipv6_fragmentation.has_fragment_header == legacy.is_ip_fragmented);
    }
    PFL_EXPECT(shadow.has_ports == legacy.has_ports);
    PFL_EXPECT(shadow.src_port == legacy.src_port);
    PFL_EXPECT(shadow.dst_port == legacy.dst_port);
    PFL_EXPECT(shadow.has_transport_payload_length == legacy.has_payload_length);
    PFL_EXPECT(shadow.captured_transport_payload_length == legacy.captured_payload_length);
    PFL_EXPECT(shadow.has_tcp_flags == legacy.has_tcp_flags);
    PFL_EXPECT(shadow.tcp_flags == legacy.tcp_flags);
}

void expect_geneve_direct_parser_and_udp_dispatch() {
    const auto inner_ipv4_tcp = make_ethernet_frame_with_payload(
        detail::kEtherTypeIpv4,
        make_ipv4_payload_packet(
            ipv4(10, 50, 0, 10),
            ipv4(10, 50, 0, 20),
            detail::kIpProtocolTcp,
            make_ipv4_tcp_segment(49550U, 443U, 4U, 0x18U)
        )
    );
    const auto options = std::vector<std::uint8_t> {0x11U, 0x22U, 0x33U, 0x44U};

    {
        const auto geneve_bytes = make_geneve_bytes(0x010203U, inner_ipv4_tcp, options, 0U, true, true, 0x15U, detail::kGeneveProtocolTypeEthernet, 0x5AU);
        const auto parsed = parse_geneve_header(make_declared_root_slice(geneve_bytes, geneve_bytes.size()));
        PFL_EXPECT(parsed.status == ParseStatus::complete);
        PFL_EXPECT(parsed.version == 0U);
        PFL_EXPECT(parsed.option_length_words == 1U);
        PFL_EXPECT(parsed.oam_flag);
        PFL_EXPECT(parsed.critical_flag);
        PFL_EXPECT(parsed.reserved_control_bits == 0x15U);
        PFL_EXPECT(parsed.protocol_type == detail::kGeneveProtocolTypeEthernet);
        PFL_EXPECT(parsed.vni == 0x010203U);
        PFL_EXPECT(parsed.reserved_trailer_byte == 0x5AU);
        PFL_EXPECT(parsed.header_length == detail::kGeneveHeaderSize + options.size());
        PFL_EXPECT(parsed.declared_payload_length == inner_ipv4_tcp.size());
    }

    {
        auto truncated_header = make_geneve_bytes(100U, inner_ipv4_tcp);
        truncated_header.resize(detail::kGeneveHeaderSize - 1U);
        const auto parsed = parse_geneve_header(make_declared_root_slice(truncated_header, detail::kGeneveHeaderSize));
        PFL_EXPECT(parsed.status == ParseStatus::truncated);
    }

    {
        const auto parsed = parse_geneve_header(make_declared_root_slice(
            make_geneve_bytes(100U, inner_ipv4_tcp),
            detail::kGeneveHeaderSize - 1U
        ));
        PFL_EXPECT(parsed.status == ParseStatus::malformed);
    }

    {
        const auto unsupported_version = parse_geneve_header(make_declared_root_slice(
            make_geneve_bytes(100U, inner_ipv4_tcp, {}, 1U),
            detail::kGeneveHeaderSize + inner_ipv4_tcp.size()
        ));
        PFL_EXPECT(unsupported_version.status == ParseStatus::unsupported_variant);
        PFL_EXPECT(unsupported_version.version == 1U);
    }

    {
        const auto malformed_options = parse_geneve_header(make_declared_root_slice(
            make_geneve_bytes(100U, inner_ipv4_tcp, options),
            detail::kGeneveHeaderSize + options.size() - 1U
        ));
        PFL_EXPECT(malformed_options.status == ParseStatus::malformed);
    }

    {
        auto truncated_options = make_geneve_bytes(100U, inner_ipv4_tcp, options);
        truncated_options.resize(detail::kGeneveHeaderSize + options.size() - 1U);
        const auto parsed = parse_geneve_header(make_declared_root_slice(
            truncated_options,
            detail::kGeneveHeaderSize + options.size()
        ));
        PFL_EXPECT(parsed.status == ParseStatus::truncated);
    }

    {
        const auto wrong_protocol_type = parse_geneve_header(make_declared_root_slice(
            make_geneve_bytes(100U, inner_ipv4_tcp, {}, 0U, false, false, 0U, 0x1234U),
            detail::kGeneveHeaderSize + inner_ipv4_tcp.size()
        ));
        PFL_EXPECT(wrong_protocol_type.status == ParseStatus::complete);
        PFL_EXPECT(wrong_protocol_type.protocol_type == 0x1234U);
    }

    {
        const auto outer_udp_packet = make_raw_packet(make_ethernet_ipv4_udp_packet_with_bytes_payload(
            ipv4(203, 0, 113, 40),
            ipv4(203, 0, 113, 41),
            54000U,
            detail::kUdpPortGeneve,
            make_geneve_bytes(100U, inner_ipv4_tcp)
        ));
        const auto udp_slice = require_child_slice(
            require_child_slice(
                make_root_slice(outer_udp_packet),
                detail::kEthernetHeaderSize,
                outer_udp_packet.bytes.size() - detail::kEthernetHeaderSize
            ),
            detail::kIpv4MinimumHeaderSize,
            outer_udp_packet.bytes.size() - detail::kEthernetHeaderSize - detail::kIpv4MinimumHeaderSize
        );
        const auto udp_step = dissect_udp(udp_slice);
        PFL_EXPECT(udp_step.layer == DissectionLayerKind::udp);
        PFL_EXPECT(udp_step.status == ParseStatus::complete);
        PFL_EXPECT(udp_step.stop_reason == StopReason::none);
        PFL_REQUIRE(udp_step.handoff.has_value());
        PFL_EXPECT(udp_step.handoff->selector.domain == SelectorDomain::udp_destination_port_candidate);
        PFL_EXPECT(udp_step.handoff->selector.value == detail::kUdpPortGeneve);
    }

    {
        const auto wrong_port_packet = make_raw_packet(make_ethernet_ipv4_udp_packet_with_bytes_payload(
            ipv4(203, 0, 113, 40),
            ipv4(203, 0, 113, 41),
            54001U,
            6082U,
            make_geneve_bytes(100U, inner_ipv4_tcp)
        ));
        const auto udp_slice = require_child_slice(
            require_child_slice(
                make_root_slice(wrong_port_packet),
                detail::kEthernetHeaderSize,
                wrong_port_packet.bytes.size() - detail::kEthernetHeaderSize
            ),
            detail::kIpv4MinimumHeaderSize,
            wrong_port_packet.bytes.size() - detail::kEthernetHeaderSize - detail::kIpv4MinimumHeaderSize
        );
        const auto udp_step = dissect_udp(udp_slice);
        PFL_EXPECT(udp_step.status == ParseStatus::complete);
        PFL_EXPECT(udp_step.stop_reason == StopReason::terminal_protocol);
        PFL_EXPECT(!udp_step.handoff.has_value());
    }
}

void expect_geneve_registry_mappings() {
    const auto built = make_common_direct_registry();
    PFL_REQUIRE(built.ok());
    const auto& registry = *built.registry;

    PFL_EXPECT(registry.entry_count() == 130U);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::udp_destination_port_candidate,
        .value = detail::kUdpPortVxlan,
    }) == dissect_vxlan);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::udp_destination_port_candidate,
        .value = detail::kUdpPortGeneve,
    }) == dissect_geneve);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::udp_destination_port_candidate,
        .value = 6082U,
    }) == nullptr);

    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::geneve_inner_frame,
        .value = kGeneveInnerFrameSelectorValue,
    }) == dissect_geneve_inner_ethernet);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::geneve_inner_ieee8023_payload,
        .value = kGeneveInnerIeee8023PayloadSelectorValue,
    }) == dissect_geneve_inner_llc_snap);

    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::geneve_inner_ether_type,
        .value = detail::kEtherTypeIpv4,
    }) == dissect_geneve_inner_ipv4);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::geneve_inner_ether_type,
        .value = detail::kEtherTypeIpv6,
    }) == dissect_geneve_inner_ipv6);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::geneve_inner_ether_type,
        .value = detail::kEtherTypeVlan,
    }) == dissect_geneve_inner_vlan);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::geneve_inner_ether_type,
        .value = detail::kEtherTypeQinq,
    }) == dissect_geneve_inner_vlan);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::geneve_inner_ether_type,
        .value = detail::kEtherTypeLegacyVlan,
    }) == dissect_geneve_inner_vlan);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::geneve_inner_ether_type,
        .value = detail::kEtherTypeArp,
    }) == nullptr);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::geneve_inner_ether_type,
        .value = detail::kEtherTypePppoeSession,
    }) == nullptr);

    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::geneve_inner_llc_snap_pid,
        .value = detail::kEtherTypeIpv4,
    }) == dissect_geneve_inner_ipv4);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::geneve_inner_llc_snap_pid,
        .value = detail::kEtherTypeIpv6,
    }) == dissect_geneve_inner_ipv6);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::geneve_inner_llc_snap_pid,
        .value = detail::kEtherTypeArp,
    }) == nullptr);

    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::geneve_inner_ip_protocol,
        .value = detail::kIpProtocolTcp,
    }) == dissect_tcp);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::geneve_inner_ip_protocol,
        .value = detail::kIpProtocolUdp,
    }) == dissect_udp_terminal);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::geneve_inner_ip_protocol,
        .value = detail::kIpProtocolSctp,
    }) == dissect_sctp);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::geneve_inner_ip_protocol,
        .value = detail::kIpProtocolGre,
    }) == nullptr);

    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::geneve_inner_ipv6_next_header,
        .value = detail::kIpProtocolTcp,
    }) == dissect_tcp);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::geneve_inner_ipv6_next_header,
        .value = detail::kIpProtocolUdp,
    }) == dissect_udp_terminal);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::geneve_inner_ipv6_next_header,
        .value = detail::kIpProtocolSctp,
    }) == dissect_sctp);
}

void expect_geneve_fixture_packet_parity() {
    const auto built = make_common_direct_registry();
    PFL_REQUIRE(built.ok());
    const auto& registry = *built.registry;

    for (const auto fixture : kGeneveFixtures) {
        const auto packets = require_raw_fixture_packets(std::filesystem::path {std::string(fixture)});
        for (std::size_t packet_index = 0U; packet_index < packets.size(); ++packet_index) {
            expect_packet_shadow_matches_legacy(registry, FixturePacketExpectation {
                .fixture = fixture,
                .packet_index = packet_index,
            });
        }
    }
}

void expect_geneve_selected_step_sequences_and_facts() {
    const auto built = make_common_direct_registry();
    PFL_REQUIRE(built.ok());
    const auto& registry = *built.registry;

    {
        const ScopedTestContext fixture_context {"fixture=parsing/geneve/01_geneve_inner_ipv4_tcp.pcap"};
        const auto steps = collect_shadow_steps(
            require_raw_fixture_packet("parsing/geneve/01_geneve_inner_ipv4_tcp.pcap"),
            registry
        );
        expect_step_kinds(steps, {
            DissectionLayerKind::ethernet_ii,
            DissectionLayerKind::ipv4,
            DissectionLayerKind::udp,
            DissectionLayerKind::geneve,
            DissectionLayerKind::ethernet_ii,
            DissectionLayerKind::ipv4,
            DissectionLayerKind::tcp,
        });
        const auto* facts = find_geneve_facts(steps);
        PFL_REQUIRE(facts != nullptr);
        PFL_EXPECT(facts->version == 0U);
        PFL_EXPECT(facts->option_length_words == 0U);
        PFL_EXPECT(facts->protocol_type == detail::kGeneveProtocolTypeEthernet);
        PFL_EXPECT(facts->vni == 100U);
    }

    {
        const ScopedTestContext fixture_context {"fixture=parsing/geneve/13_geneve_inner_vlan_ipv4_tcp.pcap"};
        const auto steps = collect_shadow_steps(
            require_raw_fixture_packet("parsing/geneve/13_geneve_inner_vlan_ipv4_tcp.pcap"),
            registry
        );
        expect_step_kinds(steps, {
            DissectionLayerKind::ethernet_ii,
            DissectionLayerKind::ipv4,
            DissectionLayerKind::udp,
            DissectionLayerKind::geneve,
            DissectionLayerKind::ethernet_ii,
            DissectionLayerKind::vlan,
            DissectionLayerKind::ipv4,
            DissectionLayerKind::tcp,
        });
    }

    {
        const ScopedTestContext fixture_context {"fixture=parsing/geneve/17_geneve_with_options_inner_ipv4_tcp.pcap"};
        const auto steps = collect_shadow_steps(
            require_raw_fixture_packet("parsing/geneve/17_geneve_with_options_inner_ipv4_tcp.pcap"),
            registry
        );
        expect_step_kinds(steps, {
            DissectionLayerKind::ethernet_ii,
            DissectionLayerKind::ipv4,
            DissectionLayerKind::udp,
            DissectionLayerKind::geneve,
            DissectionLayerKind::ethernet_ii,
            DissectionLayerKind::ipv4,
            DissectionLayerKind::tcp,
        });
        const auto* facts = find_geneve_facts(steps);
        PFL_REQUIRE(facts != nullptr);
        // Fixture 17 carries an 8-byte Geneve option block, so the encoded
        // option length is two 4-byte words.
        PFL_EXPECT(facts->option_length_words == 2U);
    }

    {
        const ScopedTestContext fixture_context {"fixture=parsing/geneve/27_geneve_unsupported_and_nested_matrix.pcap | packet=2"};
        const auto packets = require_raw_fixture_packets("parsing/geneve/27_geneve_unsupported_and_nested_matrix.pcap");
        const auto steps = collect_shadow_steps(packets[2U], registry);
        expect_step_kinds(steps, {
            DissectionLayerKind::ethernet_ii,
            DissectionLayerKind::ipv4,
            DissectionLayerKind::udp,
            DissectionLayerKind::geneve,
            DissectionLayerKind::ethernet_ii,
            DissectionLayerKind::ipv4,
            DissectionLayerKind::udp,
        });
        PFL_EXPECT(static_cast<std::size_t>(std::count_if(steps.begin(), steps.end(), [](const DissectionStep& step) {
            return step.layer == DissectionLayerKind::geneve;
        })) == 1U);
    }

    {
        const ScopedTestContext fixture_context {"fixture=parsing/geneve/34_geneve_nested_gtpu_no_recursion.pcap"};
        const auto steps = collect_shadow_steps(
            require_raw_fixture_packet("parsing/geneve/34_geneve_nested_gtpu_no_recursion.pcap"),
            registry
        );
        expect_step_kinds(steps, {
            DissectionLayerKind::ethernet_ii,
            DissectionLayerKind::ipv4,
            DissectionLayerKind::udp,
            DissectionLayerKind::geneve,
            DissectionLayerKind::ethernet_ii,
            DissectionLayerKind::ipv4,
            DissectionLayerKind::udp,
        });
    }
}

void expect_geneve_identity_behavior() {
    const auto built = make_common_direct_registry();
    PFL_REQUIRE(built.ok());
    const auto& registry = *built.registry;

    auto expect_identity_cardinality = [&registry](
        const std::string_view fixture,
        const std::size_t expected_shadow_count,
        const std::size_t expected_legacy_count
    ) {
        const auto context_text = "fixture=" + std::string(fixture) + " | identity";
        const ScopedTestContext fixture_context {context_text.c_str()};

        const auto packets = require_raw_fixture_packets(std::filesystem::path {std::string(fixture)});
        std::set<std::string> shadow_identities {};
        std::set<std::string> legacy_identities {};
        for (const auto& packet : packets) {
            shadow_identities.emplace(shadow_flow_identity_text(run_shadow(packet, registry)));
            legacy_identities.emplace(legacy_flow_identity_text(decode_legacy_direct(packet)));
        }

        PFL_EXPECT(shadow_identities.size() == expected_shadow_count);
        PFL_EXPECT(legacy_identities.size() == expected_legacy_count);
        PFL_EXPECT(shadow_identities == legacy_identities);
    };

    expect_identity_cardinality("parsing/geneve/11_geneve_inner_ipv4_tcp_bidirectional.pcap", 1U, 1U);
    expect_identity_cardinality("parsing/geneve/12_geneve_same_outer_tuple_different_inner_flows.pcap", 2U, 2U);
    expect_identity_cardinality("parsing/geneve/16_geneve_vni_boundary_values.pcap", 2U, 2U);
    expect_identity_cardinality("parsing/geneve/19_geneve_same_inner_tuple_different_vni.pcap", 2U, 2U);
    expect_identity_cardinality("parsing/geneve/21_geneve_identity_outer_carrier_variation_same_flow.pcap", 1U, 1U);
    expect_identity_cardinality("parsing/geneve/22_geneve_identity_outer_and_inner_vlan_splits.pcap", 3U, 3U);
    expect_identity_cardinality("parsing/geneve/30_geneve_vni_byte_order_distinct_values.pcap", 2U, 2U);
}

void expect_geneve_declared_bounds_and_fallback_contracts() {
    const auto built = make_common_direct_registry();
    PFL_REQUIRE(built.ok());
    const auto& registry = *built.registry;

    {
        const auto packets = require_raw_fixture_packets("parsing/geneve/28_geneve_udp_declared_bounds_matrix.pcap");
        expect_packet_shadow_matches_legacy(registry, FixturePacketExpectation {
            .fixture = "parsing/geneve/28_geneve_udp_declared_bounds_matrix.pcap",
            .packet_index = 0U,
            .expected_path = "EthernetII -> IPv4 -> UDP",
            .expected_stop_reason = StopReason::terminal_protocol,
        });
        expect_packet_shadow_matches_legacy(registry, FixturePacketExpectation {
            .fixture = "parsing/geneve/28_geneve_udp_declared_bounds_matrix.pcap",
            .packet_index = 1U,
            .expected_path = "EthernetII -> IPv4 -> UDP",
            .expected_stop_reason = StopReason::terminal_protocol,
        });
        PFL_REQUIRE(packets.size() == 4U);

        const ScopedTestContext packet2_context {"fixture=parsing/geneve/28_geneve_udp_declared_bounds_matrix.pcap | packet=2 | bounds"};
        const auto packet2_steps = collect_shadow_steps(packets[2U], registry);
        const auto packet2_shadow = run_shadow(packets[2U], registry);
        PFL_REQUIRE(packet2_steps.size() == 3U);
        expect_step_kinds(packet2_steps, {
            DissectionLayerKind::ethernet_ii,
            DissectionLayerKind::ipv4,
            DissectionLayerKind::udp,
        });
        PFL_EXPECT(packet2_steps[2U].status == ParseStatus::malformed);
        PFL_EXPECT(packet2_steps[2U].stop_reason == StopReason::malformed);
        PFL_EXPECT(std::holds_alternative<std::monostate>(packet2_steps[2U].facts));
        PFL_EXPECT(find_geneve_facts(packet2_steps) == nullptr);
        PFL_EXPECT(packet2_shadow.outcome == ImportDissectionOutcome::unrecognized);
        PFL_EXPECT(packet2_shadow.stop_reason == StopReason::malformed);
        // The packet remains unrecognized, but the outer Ethernet/IPv4 shell
        // was successfully decoded before UDP declared-length validation
        // failed. That diagnostic traversal path is not a persistent flow
        // identity.
        PFL_EXPECT(format_shadow_path(packet2_shadow) == "EthernetII -> IPv4");
        PFL_EXPECT(packet2_shadow.terminal_protocol == ProtocolId::udp);
        PFL_EXPECT(packet2_shadow.family == DissectionAddressFamily::ipv4);
        PFL_EXPECT(packet2_shadow.has_flow_addresses);
        PFL_EXPECT(!packet2_shadow.has_ports);
        PFL_EXPECT(!packet2_shadow.has_transport_payload_length);
        PFL_EXPECT(!packet2_shadow.has_tcp_flags);

        ProtocolPathRegistry packet2_registry {};
        ProtocolPathId packet2_protocol_path_id = kInvalidProtocolPathId;
        if (packet2_shadow.outcome == ImportDissectionOutcome::recognized_flow) {
            packet2_protocol_path_id = packet2_registry.intern(shadow_path(packet2_shadow));
        }
        PFL_EXPECT(packet2_registry.size() == 0U);
        PFL_EXPECT(packet2_protocol_path_id == kInvalidProtocolPathId);

        expect_packet_shadow_matches_legacy(registry, FixturePacketExpectation {
            .fixture = "parsing/geneve/28_geneve_udp_declared_bounds_matrix.pcap",
            .packet_index = 3U,
            .expected_path = "EthernetII -> IPv4 -> UDP -> Geneve(vni=100) -> EthernetII -> IPv4 -> TCP",
            .expected_stop_reason = StopReason::terminal_protocol,
        });
    }

}

void expect_geneve_unsupported_inner_and_nonrecursive_behavior() {
    const auto built = make_common_direct_registry();
    PFL_REQUIRE(built.ok());
    const auto& registry = *built.registry;

    {
        const auto packets = require_raw_fixture_packets("parsing/geneve/33_geneve_inner_unsupported_ethernet_payloads.pcap");
        PFL_REQUIRE(packets.size() == 6U);
        for (std::size_t packet_index = 0U; packet_index < packets.size(); ++packet_index) {
            const auto context_text =
                "fixture=parsing/geneve/33_geneve_inner_unsupported_ethernet_payloads.pcap | packet=" +
                std::to_string(packet_index);
            const ScopedTestContext packet_context {context_text};
            const auto shadow = run_shadow(packets[packet_index], registry);
            PFL_EXPECT(shadow.outcome == ImportDissectionOutcome::recognized_flow);
            PFL_EXPECT(shadow.stop_reason == StopReason::terminal_protocol);
            PFL_EXPECT(format_shadow_path(shadow) == "EthernetII -> IPv4 -> UDP");
        }
    }

    {
        const auto packets = require_raw_fixture_packets("parsing/geneve/27_geneve_unsupported_and_nested_matrix.pcap");
        PFL_REQUIRE(packets.size() == 4U);
        const ScopedTestContext packet2_context {"fixture=parsing/geneve/27_geneve_unsupported_and_nested_matrix.pcap | packet=2 | nested_geneve"};
        const auto packet2_shadow = run_shadow(packets[2U], registry);
        PFL_EXPECT(packet2_shadow.outcome == ImportDissectionOutcome::recognized_flow);
        PFL_EXPECT(format_shadow_path(packet2_shadow) ==
            "EthernetII -> IPv4 -> UDP -> Geneve(vni=100) -> EthernetII -> IPv4 -> UDP");

        const ScopedTestContext packet3_context {"fixture=parsing/geneve/27_geneve_unsupported_and_nested_matrix.pcap | packet=3 | nested_vxlan"};
        const auto packet3_shadow = run_shadow(packets[3U], registry);
        PFL_EXPECT(packet3_shadow.outcome == ImportDissectionOutcome::recognized_flow);
        PFL_EXPECT(format_shadow_path(packet3_shadow) ==
            "EthernetII -> IPv4 -> UDP -> Geneve(vni=100) -> EthernetII -> IPv4 -> UDP");
    }

    {
        const auto packets = require_raw_fixture_packets("parsing/geneve/34_geneve_nested_gtpu_no_recursion.pcap");
        PFL_REQUIRE(packets.size() == 1U);
        const auto shadow = run_shadow(packets[0U], registry);
        PFL_EXPECT(shadow.outcome == ImportDissectionOutcome::recognized_flow);
        PFL_EXPECT(format_shadow_path(shadow) ==
            "EthernetII -> IPv4 -> UDP -> Geneve(vni=100) -> EthernetII -> IPv4 -> UDP");
    }
}

}  // namespace

void run_common_direct_geneve_dissection_tests() {
    expect_geneve_direct_parser_and_udp_dispatch();
    expect_geneve_registry_mappings();
    expect_geneve_fixture_packet_parity();
    expect_geneve_selected_step_sequences_and_facts();
    expect_geneve_identity_behavior();
    expect_geneve_declared_bounds_and_fallback_contracts();
    expect_geneve_unsupported_inner_and_nonrecursive_behavior();
}

}  // namespace pfl::tests::common_direct_test
