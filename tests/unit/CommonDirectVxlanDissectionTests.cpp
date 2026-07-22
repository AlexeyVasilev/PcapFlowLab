#include <algorithm>
#include <array>
#include <optional>
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

std::vector<std::uint8_t> make_vxlan_bytes(
    const std::uint32_t vni,
    const std::vector<std::uint8_t>& inner_frame,
    const std::uint8_t flags = detail::kVxlanFlagI,
    const std::uint8_t reserved_1 = 0U,
    const std::uint8_t reserved_2 = 0U,
    const std::uint8_t reserved_3 = 0U,
    const std::uint8_t trailing_reserved = 0U
) {
    std::vector<std::uint8_t> bytes {
        flags,
        reserved_1,
        reserved_2,
        reserved_3,
        static_cast<std::uint8_t>((vni >> 16U) & 0xFFU),
        static_cast<std::uint8_t>((vni >> 8U) & 0xFFU),
        static_cast<std::uint8_t>(vni & 0xFFU),
        trailing_reserved,
    };
    bytes.insert(bytes.end(), inner_frame.begin(), inner_frame.end());
    return bytes;
}

const VxlanFacts* find_vxlan_facts(const std::vector<DissectionStep>& steps) {
    for (const auto& step : steps) {
        if (step.layer != DissectionLayerKind::vxlan) {
            continue;
        }

        if (const auto* facts = std::get_if<VxlanFacts>(&step.facts); facts != nullptr) {
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

void expect_vxlan_direct_parser_and_udp_dispatch() {
    const auto inner_ipv4_tcp = make_ethernet_frame_with_payload(
        detail::kEtherTypeIpv4,
        make_ipv4_payload_packet(
            ipv4(10, 40, 0, 10),
            ipv4(10, 40, 0, 20),
            detail::kIpProtocolTcp,
            make_ipv4_tcp_segment(49440U, 443U, 4U, 0x18U)
        )
    );

    {
        const auto vxlan_bytes = make_vxlan_bytes(0x010203U, inner_ipv4_tcp);
        const auto parsed = parse_vxlan_header(make_declared_root_slice(vxlan_bytes, vxlan_bytes.size()));
        PFL_EXPECT(parsed.status == ParseStatus::complete);
        PFL_EXPECT(parsed.flags == detail::kVxlanFlagI);
        PFL_EXPECT(parsed.vni == 0x010203U);
        PFL_EXPECT(parsed.header_length == detail::kVxlanHeaderSize);
        PFL_EXPECT(parsed.declared_payload_length == inner_ipv4_tcp.size());
    }

    {
        const auto vxlan_bytes = make_vxlan_bytes(0x030201U, inner_ipv4_tcp);
        const auto parsed = parse_vxlan_header(make_declared_root_slice(vxlan_bytes, vxlan_bytes.size()));
        PFL_EXPECT(parsed.status == ParseStatus::complete);
        PFL_EXPECT(parsed.vni == 0x030201U);
    }

    {
        const auto zero_vni = parse_vxlan_header(make_declared_root_slice(
            make_vxlan_bytes(0U, inner_ipv4_tcp),
            detail::kVxlanHeaderSize + inner_ipv4_tcp.size()
        ));
        PFL_EXPECT(zero_vni.status == ParseStatus::complete);
        PFL_EXPECT(zero_vni.vni == 0U);

        const auto max_vni = parse_vxlan_header(make_declared_root_slice(
            make_vxlan_bytes(0xFFFFFFU, inner_ipv4_tcp),
            detail::kVxlanHeaderSize + inner_ipv4_tcp.size()
        ));
        PFL_EXPECT(max_vni.status == ParseStatus::complete);
        PFL_EXPECT(max_vni.vni == 0xFFFFFFU);
    }

    {
        auto truncated_header = make_vxlan_bytes(100U, inner_ipv4_tcp);
        truncated_header.resize(detail::kVxlanHeaderSize - 1U);
        const auto parsed = parse_vxlan_header(make_declared_root_slice(truncated_header, detail::kVxlanHeaderSize));
        PFL_EXPECT(parsed.status == ParseStatus::truncated);
    }

    {
        const auto parsed = parse_vxlan_header(make_declared_root_slice(
            make_vxlan_bytes(100U, inner_ipv4_tcp),
            detail::kVxlanHeaderSize - 1U
        ));
        PFL_EXPECT(parsed.status == ParseStatus::malformed);
    }

    {
        const auto clear_i = parse_vxlan_header(make_declared_root_slice(
            make_vxlan_bytes(100U, inner_ipv4_tcp, 0x00U),
            detail::kVxlanHeaderSize + inner_ipv4_tcp.size()
        ));
        PFL_EXPECT(clear_i.status == ParseStatus::unsupported_variant);
        PFL_EXPECT(clear_i.vni == 100U);

        const auto reserved = parse_vxlan_header(make_declared_root_slice(
            make_vxlan_bytes(100U, inner_ipv4_tcp, detail::kVxlanFlagI, 0x01U, 0U, 0U),
            detail::kVxlanHeaderSize + inner_ipv4_tcp.size()
        ));
        PFL_EXPECT(reserved.status == ParseStatus::unsupported_variant);

        const auto trailing = parse_vxlan_header(make_declared_root_slice(
            make_vxlan_bytes(100U, inner_ipv4_tcp, detail::kVxlanFlagI, 0U, 0U, 0U, 0x01U),
            detail::kVxlanHeaderSize + inner_ipv4_tcp.size()
        ));
        PFL_EXPECT(trailing.status == ParseStatus::unsupported_variant);
    }

    {
        auto bounded_bytes = make_vxlan_bytes(100U, inner_ipv4_tcp);
        bounded_bytes.insert(bounded_bytes.end(), {0xdeU, 0xadU, 0xbeU, 0xefU});
        const auto step = dissect_vxlan(make_declared_root_slice(
            bounded_bytes,
            detail::kVxlanHeaderSize + inner_ipv4_tcp.size()
        ));
        PFL_EXPECT(step.layer == DissectionLayerKind::vxlan);
        PFL_EXPECT(step.status == ParseStatus::complete);
        PFL_EXPECT(step.stop_reason == StopReason::none);
        PFL_REQUIRE(step.path_contribution.has_value());
        PFL_EXPECT(*step.path_contribution == LayerKey::vxlan(100U));
        PFL_REQUIRE(step.handoff.has_value());
        PFL_EXPECT(step.handoff->selector.domain == SelectorDomain::vxlan_inner_frame);
        PFL_EXPECT(step.handoff->selector.value == kVxlanInnerFrameSelectorValue);
        PFL_REQUIRE(step.handoff->child.has_value());
        PFL_EXPECT(step.handoff->child->source_offset() == detail::kVxlanHeaderSize);
        PFL_EXPECT(step.handoff->child->declared_end() - step.handoff->child->source_offset() == inner_ipv4_tcp.size());
        const auto* facts = std::get_if<VxlanFacts>(&step.facts);
        PFL_REQUIRE(facts != nullptr);
        PFL_EXPECT(facts->flags == detail::kVxlanFlagI);
        PFL_EXPECT(facts->vni == 100U);
        PFL_EXPECT(step.bounds.header.declared.length() == detail::kVxlanHeaderSize);
        PFL_REQUIRE(step.bounds.payload.has_value());
        PFL_EXPECT(step.bounds.payload->declared.length() == inner_ipv4_tcp.size());
        PFL_EXPECT(step.bounds.payload->captured.length() == inner_ipv4_tcp.size());
    }

    {
        const auto outer_udp_packet = make_raw_packet(make_ethernet_ipv4_udp_packet_with_bytes_payload(
            ipv4(203, 0, 113, 40),
            ipv4(203, 0, 113, 41),
            53000U,
            detail::kUdpPortVxlan,
            make_vxlan_bytes(100U, inner_ipv4_tcp)
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
        PFL_EXPECT(udp_step.handoff->selector.value == detail::kUdpPortVxlan);
        PFL_REQUIRE(udp_step.handoff->child.has_value());
        PFL_EXPECT(udp_step.handoff->child->source_offset() == udp_slice.source_offset() + detail::kUdpHeaderSize);

        const auto terminal_udp_step = dissect_udp_terminal(udp_slice);
        PFL_EXPECT(terminal_udp_step.layer == DissectionLayerKind::udp);
        PFL_EXPECT(terminal_udp_step.status == ParseStatus::complete);
        PFL_EXPECT(terminal_udp_step.stop_reason == StopReason::terminal_protocol);
        PFL_EXPECT(!terminal_udp_step.handoff.has_value());
    }

    {
        const auto wrong_port_packet = make_raw_packet(make_ethernet_ipv4_udp_packet_with_bytes_payload(
            ipv4(203, 0, 113, 40),
            ipv4(203, 0, 113, 41),
            53001U,
            8472U,
            make_vxlan_bytes(100U, inner_ipv4_tcp)
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

void expect_vxlan_registry_mappings() {
    const auto built = make_common_direct_registry();
    PFL_REQUIRE(built.ok());
    const auto& registry = *built.registry;

    PFL_EXPECT(registry.entry_count() == 139U);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::udp_destination_port_candidate,
        .value = detail::kUdpPortVxlan,
    }) == dissect_vxlan);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::udp_destination_port_candidate,
        .value = 8472U,
    }) == nullptr);

    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::vxlan_inner_frame,
        .value = kVxlanInnerFrameSelectorValue,
    }) == dissect_vxlan_inner_ethernet);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::vxlan_inner_ieee8023_payload,
        .value = kVxlanInnerIeee8023PayloadSelectorValue,
    }) == dissect_vxlan_inner_llc_snap);

    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::vxlan_inner_ether_type,
        .value = detail::kEtherTypeIpv4,
    }) == dissect_vxlan_inner_ipv4);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::vxlan_inner_ether_type,
        .value = detail::kEtherTypeIpv6,
    }) == dissect_vxlan_inner_ipv6);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::vxlan_inner_ether_type,
        .value = detail::kEtherTypeVlan,
    }) == dissect_vxlan_inner_vlan);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::vxlan_inner_ether_type,
        .value = detail::kEtherTypeQinq,
    }) == dissect_vxlan_inner_vlan);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::vxlan_inner_ether_type,
        .value = detail::kEtherTypeLegacyVlan,
    }) == dissect_vxlan_inner_vlan);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::vxlan_inner_ether_type,
        .value = detail::kEtherTypeArp,
    }) == nullptr);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::vxlan_inner_ether_type,
        .value = detail::kEtherTypePppoeSession,
    }) == nullptr);

    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::vxlan_inner_llc_snap_pid,
        .value = detail::kEtherTypeIpv4,
    }) == dissect_vxlan_inner_ipv4);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::vxlan_inner_llc_snap_pid,
        .value = detail::kEtherTypeIpv6,
    }) == dissect_vxlan_inner_ipv6);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::vxlan_inner_llc_snap_pid,
        .value = detail::kEtherTypeArp,
    }) == nullptr);

    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::vxlan_inner_ip_protocol,
        .value = detail::kIpProtocolTcp,
    }) == dissect_tcp);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::vxlan_inner_ip_protocol,
        .value = detail::kIpProtocolUdp,
    }) == dissect_udp_terminal);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::vxlan_inner_ip_protocol,
        .value = detail::kIpProtocolSctp,
    }) == dissect_sctp);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::vxlan_inner_ip_protocol,
        .value = detail::kIpProtocolGre,
    }) == nullptr);

    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::vxlan_inner_ipv6_next_header,
        .value = detail::kIpProtocolTcp,
    }) == dissect_tcp);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::vxlan_inner_ipv6_next_header,
        .value = detail::kIpProtocolUdp,
    }) == dissect_udp_terminal);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::vxlan_inner_ipv6_next_header,
        .value = detail::kIpProtocolSctp,
    }) == dissect_sctp);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::vxlan_inner_ipv6_next_header,
        .value = detail::kIpProtocolGre,
    }) == nullptr);
}

void expect_vxlan_fixture_packet_parity() {
    const auto built = make_common_direct_registry();
    PFL_REQUIRE(built.ok());
    const auto& registry = *built.registry;

    const std::array expectations {
        FixturePacketExpectation {"parsing/vxlan/01_vxlan_inner_ipv4_tcp.pcap", 0U, "EthernetII -> IPv4 -> UDP -> VXLAN(vni=100) -> EthernetII -> IPv4 -> TCP"},
        FixturePacketExpectation {"parsing/vxlan/02_vxlan_inner_ipv4_udp.pcap", 0U, "EthernetII -> IPv4 -> UDP -> VXLAN(vni=100) -> EthernetII -> IPv4 -> UDP"},
        FixturePacketExpectation {"parsing/vxlan/03_vxlan_inner_ipv6_tcp.pcap", 0U, "EthernetII -> IPv4 -> UDP -> VXLAN(vni=100) -> EthernetII -> IPv6 -> TCP"},
        FixturePacketExpectation {"parsing/vxlan/04_vxlan_inner_ipv6_udp.pcap", 0U, "EthernetII -> IPv4 -> UDP -> VXLAN(vni=100) -> EthernetII -> IPv6 -> UDP"},
        FixturePacketExpectation {"parsing/vxlan/05_vxlan_truncated_header.pcap", 0U},
        FixturePacketExpectation {"parsing/vxlan/06_vxlan_invalid_flags_or_reserved_bits.pcap", 0U},
        FixturePacketExpectation {"parsing/vxlan/07_vxlan_truncated_inner_ethernet.pcap", 0U},
        FixturePacketExpectation {"parsing/vxlan/08_vxlan_truncated_inner_ipv4.pcap", 0U},
        FixturePacketExpectation {"parsing/vxlan/09_vxlan_unsupported_inner_ethertype.pcap", 0U},
        FixturePacketExpectation {"parsing/vxlan/10_vxlan_same_inner_tuple_different_vni.pcap", 0U, "EthernetII -> IPv4 -> UDP -> VXLAN(vni=100) -> EthernetII -> IPv4 -> TCP"},
        FixturePacketExpectation {"parsing/vxlan/10_vxlan_same_inner_tuple_different_vni.pcap", 1U, "EthernetII -> IPv4 -> UDP -> VXLAN(vni=200) -> EthernetII -> IPv4 -> TCP"},
        FixturePacketExpectation {"parsing/vxlan/11_vxlan_inner_ipv4_tcp_bidirectional.pcap", 0U, "EthernetII -> IPv4 -> UDP -> VXLAN(vni=100) -> EthernetII -> IPv4 -> TCP"},
        FixturePacketExpectation {"parsing/vxlan/11_vxlan_inner_ipv4_tcp_bidirectional.pcap", 1U, "EthernetII -> IPv4 -> UDP -> VXLAN(vni=100) -> EthernetII -> IPv4 -> TCP"},
        FixturePacketExpectation {"parsing/vxlan/12_vxlan_same_outer_tuple_different_inner_flows.pcap", 0U, "EthernetII -> IPv4 -> UDP -> VXLAN(vni=100) -> EthernetII -> IPv4 -> TCP"},
        FixturePacketExpectation {"parsing/vxlan/12_vxlan_same_outer_tuple_different_inner_flows.pcap", 1U, "EthernetII -> IPv4 -> UDP -> VXLAN(vni=100) -> EthernetII -> IPv4 -> TCP"},
        FixturePacketExpectation {"parsing/vxlan/13_vxlan_inner_vlan_ipv4_tcp.pcap", 0U, "EthernetII -> IPv4 -> UDP -> VXLAN(vni=100) -> EthernetII -> VLAN(vid=140) -> IPv4 -> TCP"},
        FixturePacketExpectation {"parsing/vxlan/14_vxlan_outer_ipv6_inner_ipv4_tcp.pcap", 0U, "EthernetII -> IPv6 -> UDP -> VXLAN(vni=100) -> EthernetII -> IPv4 -> TCP"},
        FixturePacketExpectation {"parsing/vxlan/15_vxlan_wrong_udp_port_valid_vxlan_payload.pcap", 0U, "EthernetII -> IPv4 -> UDP"},
        FixturePacketExpectation {"parsing/vxlan/16_vxlan_vni_boundary_values.pcap", 0U, "EthernetII -> IPv4 -> UDP -> VXLAN(vni=0) -> EthernetII -> IPv4 -> TCP"},
        FixturePacketExpectation {"parsing/vxlan/16_vxlan_vni_boundary_values.pcap", 1U, "EthernetII -> IPv4 -> UDP -> VXLAN(vni=16777215) -> EthernetII -> IPv4 -> TCP"},
        FixturePacketExpectation {"parsing/vxlan/17_vxlan_udp_port_and_header_matrix.pcap", 0U, "EthernetII -> IPv4 -> UDP -> VXLAN(vni=100) -> EthernetII -> IPv4 -> TCP"},
        FixturePacketExpectation {"parsing/vxlan/17_vxlan_udp_port_and_header_matrix.pcap", 1U, "EthernetII -> IPv4 -> UDP"},
        FixturePacketExpectation {"parsing/vxlan/17_vxlan_udp_port_and_header_matrix.pcap", 2U, "EthernetII -> IPv4 -> UDP"},
        FixturePacketExpectation {"parsing/vxlan/17_vxlan_udp_port_and_header_matrix.pcap", 3U, "EthernetII -> IPv4 -> UDP"},
        FixturePacketExpectation {"parsing/vxlan/17_vxlan_udp_port_and_header_matrix.pcap", 4U, "EthernetII -> IPv4 -> UDP"},
        FixturePacketExpectation {"parsing/vxlan/17_vxlan_udp_port_and_header_matrix.pcap", 5U, "EthernetII -> IPv4 -> UDP"},
        FixturePacketExpectation {"parsing/vxlan/18_vxlan_outer_tagged_contexts.pcap", 0U, "EthernetII -> VLAN(vid=201) -> IPv4 -> UDP -> VXLAN(vni=100) -> EthernetII -> IPv4 -> UDP"},
        FixturePacketExpectation {"parsing/vxlan/18_vxlan_outer_tagged_contexts.pcap", 1U, "EthernetII -> VLAN(vid=401) -> VLAN(vid=402) -> IPv6 -> UDP -> VXLAN(vni=100) -> EthernetII -> IPv6 -> TCP"},
        FixturePacketExpectation {"parsing/vxlan/18_vxlan_outer_tagged_contexts.pcap", 2U, "EthernetII -> VLAN(vid=501) -> IPv4 -> UDP -> VXLAN(vni=100) -> EthernetII -> IPv4 -> TCP"},
        FixturePacketExpectation {"parsing/vxlan/19_vxlan_outer_ipv6_inner_ipv6_udp.pcap", 0U, "EthernetII -> IPv6 -> UDP -> VXLAN(vni=100) -> EthernetII -> IPv6 -> UDP"},
        FixturePacketExpectation {"parsing/vxlan/20_vxlan_linux_sll_ipv4_inner_ipv4_udp.pcap", 0U, "LinuxSll -> IPv4 -> UDP -> VXLAN(vni=100) -> EthernetII -> IPv4 -> UDP"},
        FixturePacketExpectation {"parsing/vxlan/21_vxlan_linux_sll2_ipv6_inner_ipv6_udp.pcap", 0U, "LinuxSll2 -> IPv6 -> UDP -> VXLAN(vni=100) -> EthernetII -> IPv6 -> UDP"},
        FixturePacketExpectation {"parsing/vxlan/22_vxlan_identity_outer_carrier_variation_same_flow.pcap", 0U, "EthernetII -> IPv4 -> UDP -> VXLAN(vni=100) -> EthernetII -> IPv4 -> TCP"},
        FixturePacketExpectation {"parsing/vxlan/22_vxlan_identity_outer_carrier_variation_same_flow.pcap", 1U, "EthernetII -> IPv4 -> UDP -> VXLAN(vni=100) -> EthernetII -> IPv4 -> TCP"},
        FixturePacketExpectation {"parsing/vxlan/22_vxlan_identity_outer_carrier_variation_same_flow.pcap", 2U, "EthernetII -> IPv4 -> UDP -> VXLAN(vni=100) -> EthernetII -> IPv4 -> TCP"},
        FixturePacketExpectation {"parsing/vxlan/22_vxlan_identity_outer_carrier_variation_same_flow.pcap", 3U, "EthernetII -> IPv4 -> UDP -> VXLAN(vni=100) -> EthernetII -> IPv4 -> TCP"},
        FixturePacketExpectation {"parsing/vxlan/23_vxlan_identity_outer_and_inner_vlan_splits.pcap", 0U, "EthernetII -> VLAN(vid=141) -> IPv4 -> UDP -> VXLAN(vni=100) -> EthernetII -> IPv4 -> TCP"},
        FixturePacketExpectation {"parsing/vxlan/23_vxlan_identity_outer_and_inner_vlan_splits.pcap", 1U, "EthernetII -> VLAN(vid=142) -> IPv4 -> UDP -> VXLAN(vni=100) -> EthernetII -> IPv4 -> TCP"},
        FixturePacketExpectation {"parsing/vxlan/23_vxlan_identity_outer_and_inner_vlan_splits.pcap", 2U, "EthernetII -> IPv4 -> UDP -> VXLAN(vni=100) -> EthernetII -> VLAN(vid=200) -> IPv4 -> TCP"},
        FixturePacketExpectation {"parsing/vxlan/23_vxlan_identity_outer_and_inner_vlan_splits.pcap", 3U, "EthernetII -> IPv4 -> UDP -> VXLAN(vni=100) -> EthernetII -> VLAN(vid=201) -> IPv4 -> TCP"},
        FixturePacketExpectation {"parsing/vxlan/24_vxlan_outer_ipv4_fragmentation.pcap", 0U, "EthernetII -> IPv4", StopReason::needs_reassembly},
        FixturePacketExpectation {"parsing/vxlan/24_vxlan_outer_ipv4_fragmentation.pcap", 1U, "EthernetII -> IPv4", StopReason::needs_reassembly},
        FixturePacketExpectation {"parsing/vxlan/24_vxlan_outer_ipv4_fragmentation.pcap", 2U, "EthernetII -> IPv4", StopReason::needs_reassembly},
        FixturePacketExpectation {"parsing/vxlan/24_vxlan_outer_ipv4_fragmentation.pcap", 3U, std::nullopt, StopReason::truncated},
        FixturePacketExpectation {"parsing/vxlan/25_vxlan_outer_ipv6_fragmentation.pcap", 0U, "EthernetII -> IPv6", StopReason::needs_reassembly},
        FixturePacketExpectation {"parsing/vxlan/25_vxlan_outer_ipv6_fragmentation.pcap", 1U, "EthernetII -> IPv6", StopReason::needs_reassembly},
        FixturePacketExpectation {"parsing/vxlan/25_vxlan_outer_ipv6_fragmentation.pcap", 2U, "EthernetII -> IPv6", StopReason::needs_reassembly},
        FixturePacketExpectation {"parsing/vxlan/25_vxlan_outer_ipv6_fragmentation.pcap", 3U, std::nullopt, StopReason::truncated},
        FixturePacketExpectation {"parsing/vxlan/26_vxlan_udp_declared_bounds_matrix.pcap", 0U, "EthernetII -> IPv4 -> UDP -> VXLAN(vni=100) -> EthernetII -> IPv4 -> TCP"},
        FixturePacketExpectation {"parsing/vxlan/26_vxlan_udp_declared_bounds_matrix.pcap", 1U, "EthernetII -> IPv4 -> UDP"},
        FixturePacketExpectation {"parsing/vxlan/26_vxlan_udp_declared_bounds_matrix.pcap", 2U, "EthernetII -> IPv4 -> UDP -> VXLAN(vni=100) -> EthernetII -> IPv4 -> TCP"},
        FixturePacketExpectation {"parsing/vxlan/26_vxlan_udp_declared_bounds_matrix.pcap", 3U, "EthernetII -> IPv4 -> UDP -> VXLAN(vni=100) -> EthernetII -> IPv4 -> TCP"},
        FixturePacketExpectation {"parsing/vxlan/27_vxlan_inner_supported_and_visible_matrix.pcap", 0U, "EthernetII -> IPv4 -> UDP"},
        FixturePacketExpectation {"parsing/vxlan/27_vxlan_inner_supported_and_visible_matrix.pcap", 1U, "EthernetII -> IPv4 -> UDP -> VXLAN(vni=100) -> EthernetII -> VLAN(vid=551) -> VLAN(vid=552) -> IPv6 -> TCP"},
        FixturePacketExpectation {"parsing/vxlan/27_vxlan_inner_supported_and_visible_matrix.pcap", 2U, "EthernetII -> IPv4 -> UDP -> VXLAN(vni=100) -> IEEE 802.3 -> LLC/SNAP -> IPv4 -> UDP"},
        FixturePacketExpectation {"parsing/vxlan/28_vxlan_unsupported_and_nested_matrix.pcap", 0U, "EthernetII -> IPv4 -> UDP"},
        FixturePacketExpectation {"parsing/vxlan/28_vxlan_unsupported_and_nested_matrix.pcap", 1U, "EthernetII -> IPv4 -> UDP"},
        FixturePacketExpectation {"parsing/vxlan/28_vxlan_unsupported_and_nested_matrix.pcap", 2U, "EthernetII -> IPv4 -> UDP"},
        FixturePacketExpectation {"parsing/vxlan/28_vxlan_unsupported_and_nested_matrix.pcap", 3U, "EthernetII -> IPv4 -> UDP"},
        FixturePacketExpectation {"parsing/vxlan/28_vxlan_unsupported_and_nested_matrix.pcap", 4U, "EthernetII -> IPv4 -> UDP"},
        FixturePacketExpectation {"parsing/vxlan/28_vxlan_unsupported_and_nested_matrix.pcap", 5U, "EthernetII -> IPv4 -> UDP -> VXLAN(vni=100) -> EthernetII -> IPv4 -> UDP"},
        FixturePacketExpectation {"parsing/vxlan/28_vxlan_unsupported_and_nested_matrix.pcap", 6U, "EthernetII -> IPv4 -> UDP -> VXLAN(vni=100) -> EthernetII -> IPv4 -> UDP"},
        FixturePacketExpectation {"parsing/vxlan/28_vxlan_unsupported_and_nested_matrix.pcap", 7U, "EthernetII -> IPv4 -> UDP -> VXLAN(vni=100) -> EthernetII -> IPv4 -> UDP"},
        FixturePacketExpectation {"parsing/vxlan/29_vxlan_capture_truncation_matrix.pcap", 0U, std::nullopt, StopReason::truncated},
        FixturePacketExpectation {"parsing/vxlan/29_vxlan_capture_truncation_matrix.pcap", 1U, "EthernetII -> IPv4 -> UDP"},
        FixturePacketExpectation {"parsing/vxlan/29_vxlan_capture_truncation_matrix.pcap", 2U, "EthernetII -> IPv4 -> UDP"},
        FixturePacketExpectation {"parsing/vxlan/29_vxlan_capture_truncation_matrix.pcap", 3U, "EthernetII -> IPv4 -> UDP"},
        FixturePacketExpectation {"parsing/vxlan/30_vxlan_vni_byte_order_distinct_values.pcap", 0U, "EthernetII -> IPv4 -> UDP -> VXLAN(vni=66051) -> EthernetII -> IPv4 -> TCP"},
        FixturePacketExpectation {"parsing/vxlan/30_vxlan_vni_byte_order_distinct_values.pcap", 1U, "EthernetII -> IPv4 -> UDP -> VXLAN(vni=197121) -> EthernetII -> IPv4 -> TCP"},
    };

    for (const auto& expectation : expectations) {
        expect_packet_shadow_matches_legacy(registry, expectation);
    }
}

void expect_vxlan_selected_step_sequences_and_facts() {
    const auto built = make_common_direct_registry();
    PFL_REQUIRE(built.ok());
    const auto& registry = *built.registry;

    {
        const ScopedTestContext fixture_context {"fixture=parsing/vxlan/01_vxlan_inner_ipv4_tcp.pcap"};
        const auto steps = collect_shadow_steps(
            require_raw_fixture_packet("parsing/vxlan/01_vxlan_inner_ipv4_tcp.pcap"),
            registry
        );
        expect_step_kinds(steps, {
            DissectionLayerKind::ethernet_ii,
            DissectionLayerKind::ipv4,
            DissectionLayerKind::udp,
            DissectionLayerKind::vxlan,
            DissectionLayerKind::ethernet_ii,
            DissectionLayerKind::ipv4,
            DissectionLayerKind::tcp,
        });
        const auto* facts = find_vxlan_facts(steps);
        PFL_REQUIRE(facts != nullptr);
        PFL_EXPECT(facts->vni == 100U);
    }

    {
        const ScopedTestContext fixture_context {"fixture=parsing/vxlan/13_vxlan_inner_vlan_ipv4_tcp.pcap"};
        const auto steps = collect_shadow_steps(
            require_raw_fixture_packet("parsing/vxlan/13_vxlan_inner_vlan_ipv4_tcp.pcap"),
            registry
        );
        expect_step_kinds(steps, {
            DissectionLayerKind::ethernet_ii,
            DissectionLayerKind::ipv4,
            DissectionLayerKind::udp,
            DissectionLayerKind::vxlan,
            DissectionLayerKind::ethernet_ii,
            DissectionLayerKind::vlan,
            DissectionLayerKind::ipv4,
            DissectionLayerKind::tcp,
        });
    }

    {
        const ScopedTestContext fixture_context {"fixture=parsing/vxlan/27_vxlan_inner_supported_and_visible_matrix.pcap | packet=2"};
        const auto packets = require_raw_fixture_packets("parsing/vxlan/27_vxlan_inner_supported_and_visible_matrix.pcap");
        const auto steps = collect_shadow_steps(packets[2U], registry);
        expect_step_kinds(steps, {
            DissectionLayerKind::ethernet_ii,
            DissectionLayerKind::ipv4,
            DissectionLayerKind::udp,
            DissectionLayerKind::vxlan,
            DissectionLayerKind::ieee8023,
            DissectionLayerKind::llc_snap,
            DissectionLayerKind::ipv4,
            DissectionLayerKind::udp,
        });
    }

    {
        const ScopedTestContext fixture_context {"fixture=parsing/vxlan/28_vxlan_unsupported_and_nested_matrix.pcap | packet=5"};
        const auto packets = require_raw_fixture_packets("parsing/vxlan/28_vxlan_unsupported_and_nested_matrix.pcap");
        const auto steps = collect_shadow_steps(packets[5U], registry);
        expect_step_kinds(steps, {
            DissectionLayerKind::ethernet_ii,
            DissectionLayerKind::ipv4,
            DissectionLayerKind::udp,
            DissectionLayerKind::vxlan,
            DissectionLayerKind::ethernet_ii,
            DissectionLayerKind::ipv4,
            DissectionLayerKind::udp,
        });
        PFL_EXPECT(static_cast<std::size_t>(std::count_if(steps.begin(), steps.end(), [](const DissectionStep& step) {
            return step.layer == DissectionLayerKind::vxlan;
        })) == 1U);
    }
}

void expect_vxlan_identity_behavior() {
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

    expect_identity_cardinality("parsing/vxlan/10_vxlan_same_inner_tuple_different_vni.pcap", 2U, 2U);
    expect_identity_cardinality("parsing/vxlan/11_vxlan_inner_ipv4_tcp_bidirectional.pcap", 1U, 1U);
    expect_identity_cardinality("parsing/vxlan/12_vxlan_same_outer_tuple_different_inner_flows.pcap", 2U, 2U);
    expect_identity_cardinality("parsing/vxlan/16_vxlan_vni_boundary_values.pcap", 2U, 2U);
    expect_identity_cardinality("parsing/vxlan/22_vxlan_identity_outer_carrier_variation_same_flow.pcap", 1U, 1U);
    expect_identity_cardinality("parsing/vxlan/23_vxlan_identity_outer_and_inner_vlan_splits.pcap", 4U, 4U);
    expect_identity_cardinality("parsing/vxlan/30_vxlan_vni_byte_order_distinct_values.pcap", 2U, 2U);

    {
        const ScopedTestContext fixture_context {"fixture=parsing/vxlan/30_vxlan_vni_byte_order_distinct_values.pcap | vni_facts"};
        const auto packets = require_raw_fixture_packets("parsing/vxlan/30_vxlan_vni_byte_order_distinct_values.pcap");
        const auto first_steps = collect_shadow_steps(packets[0U], registry);
        const auto second_steps = collect_shadow_steps(packets[1U], registry);
        const auto* first_facts = find_vxlan_facts(first_steps);
        const auto* second_facts = find_vxlan_facts(second_steps);
        PFL_REQUIRE(first_facts != nullptr);
        PFL_REQUIRE(second_facts != nullptr);
        PFL_EXPECT(first_facts->vni == 66051U);
        PFL_EXPECT(second_facts->vni == 197121U);
    }
}

}  // namespace

void run_common_direct_vxlan_dissection_tests() {
    expect_vxlan_direct_parser_and_udp_dispatch();
    expect_vxlan_registry_mappings();
    expect_vxlan_fixture_packet_parity();
    expect_vxlan_selected_step_sequences_and_facts();
    expect_vxlan_identity_behavior();
}

}  // namespace pfl::tests::common_direct_test
