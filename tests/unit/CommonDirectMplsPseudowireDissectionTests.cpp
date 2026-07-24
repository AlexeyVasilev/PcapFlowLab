#include "CommonDirectDissectionTestSupport.h"

#include <algorithm>
#include <array>
#include <optional>
#include <string_view>
#include <utility>
#include <vector>

#include "PcapTestUtils.h"
#include "core/decode/PacketDecodeSupport.h"
#include "core/dissection/modules/MplsPseudowireModule.h"

namespace pfl::tests::common_direct_test {

namespace {

using LabelList = std::initializer_list<std::uint32_t>;

DissectionRegistry require_registry() {
    auto built = make_common_direct_registry();
    PFL_REQUIRE(built.ok());
    return std::move(*built.registry);
}

std::vector<std::uint8_t> make_inner_ethernet_frame(
    const std::array<std::uint8_t, 6>& dst_mac,
    const std::array<std::uint8_t, 6>& src_mac,
    const std::uint16_t ether_type,
    const std::vector<std::uint8_t>& payload
) {
    std::vector<std::uint8_t> bytes {};
    bytes.insert(bytes.end(), dst_mac.begin(), dst_mac.end());
    bytes.insert(bytes.end(), src_mac.begin(), src_mac.end());
    append_be16(bytes, ether_type);
    bytes.insert(bytes.end(), payload.begin(), payload.end());
    return bytes;
}

std::vector<std::uint8_t> make_default_inner_ipv4_udp_frame() {
    return make_inner_ethernet_frame(
        {0x02, 0x00, 0x00, 0x00, 0x51, 0x02},
        {0x02, 0x00, 0x00, 0x00, 0x51, 0x01},
        detail::kEtherTypeIpv4,
        make_ipv4_payload_packet(
            ipv4(192, 0, 2, 50),
            ipv4(198, 51, 100, 50),
            detail::kIpProtocolUdp,
            make_ipv4_udp_segment(53560U, 443U, 0U)
        )
    );
}

std::vector<std::uint8_t> make_default_inner_ipv6_udp_frame() {
    return make_inner_ethernet_frame(
        {0x02, 0x00, 0x00, 0x00, 0x51, 0x02},
        {0x02, 0x00, 0x00, 0x00, 0x51, 0x01},
        detail::kEtherTypeIpv6,
        make_ipv6_payload_packet(
            ipv6({0x20, 0x01, 0x0d, 0xb8, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10}),
            ipv6({0x20, 0x01, 0x0d, 0xb8, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20}),
            detail::kIpProtocolUdp,
            make_ipv6_udp_segment(53560U, 443U, 0U)
        )
    );
}

std::vector<std::uint8_t> make_mpls_pseudowire_packet(
    const LabelList labels,
    const std::vector<std::uint8_t>& inner_payload,
    const std::optional<std::pair<std::uint16_t, std::uint16_t>>& control_word = std::nullopt,
    const std::vector<std::pair<std::uint16_t, std::uint16_t>>& outer_vlan_tags = {}
) {
    std::vector<std::uint8_t> mpls_payload {};
    std::size_t index = 0U;
    for (const auto label : labels) {
        ++index;
        append_mpls_label(mpls_payload, label, index == labels.size());
    }
    if (control_word.has_value()) {
        append_be16(mpls_payload, control_word->first);
        append_be16(mpls_payload, control_word->second);
    }
    mpls_payload.insert(mpls_payload.end(), inner_payload.begin(), inner_payload.end());

    auto packet = make_ethernet_frame_with_payload(detail::kEtherTypeMplsUnicast, mpls_payload);
    if (!outer_vlan_tags.empty()) {
        packet = add_vlan_tags(packet, outer_vlan_tags);
    }
    return packet;
}

const MplsPseudowireFacts* find_mpls_pseudowire_facts(
    const std::vector<DissectionStep>& steps,
    const std::size_t occurrence = 0U
) {
    std::size_t seen = 0U;
    for (const auto& step : steps) {
        if (step.layer != DissectionLayerKind::mpls_pseudowire) {
            continue;
        }
        if (seen == occurrence) {
            return std::get_if<MplsPseudowireFacts>(&step.facts);
        }
        ++seen;
    }
    return nullptr;
}

bool step_kinds_contain(
    const std::vector<DissectionStep>& steps,
    const DissectionLayerKind kind
) {
    return std::any_of(steps.begin(), steps.end(), [&](const DissectionStep& step) {
        return step.layer == kind;
    });
}

void expect_shadow_flow_fixture(
    const DissectionRegistry& registry,
    const std::filesystem::path& relative_path,
    const std::optional<std::string_view>& expected_path,
    const std::vector<DissectionLayerKind>& expected_kinds,
    const bool expect_control_word,
    const std::optional<std::uint16_t>& expected_sequence = std::nullopt
) {
    const auto packet = require_raw_fixture_packet(relative_path);
    const auto legacy = decode_legacy_direct(packet);
    const auto shadow = run_shadow(packet, registry);
    const auto steps = collect_shadow_steps(packet, registry);

    PFL_REQUIRE(legacy.recognized_flow);
    PFL_EXPECT(shadow.outcome == ImportDissectionOutcome::recognized_flow);
    PFL_EXPECT(shadow.stop_reason == StopReason::terminal_protocol);
    PFL_EXPECT(shadow_path(shadow) == legacy.path);
    const auto legacy_path_text = format_protocol_path(legacy.path);
    PFL_EXPECT(format_shadow_path(shadow) == legacy_path_text);
    if (expected_path.has_value()) {
        PFL_EXPECT(legacy_path_text == *expected_path);
    }
    PFL_EXPECT(shadow.terminal_protocol == legacy.protocol);
    PFL_EXPECT(shadow.family == legacy.family);
    PFL_EXPECT(shadow.has_flow_addresses == legacy.has_addresses);
    if (legacy.family == DissectionAddressFamily::ipv4) {
        PFL_EXPECT(shadow.src_addr_v4 == legacy.src_addr_v4);
        PFL_EXPECT(shadow.dst_addr_v4 == legacy.dst_addr_v4);
    } else if (legacy.family == DissectionAddressFamily::ipv6) {
        PFL_EXPECT(shadow.src_addr_v6 == legacy.src_addr_v6);
        PFL_EXPECT(shadow.dst_addr_v6 == legacy.dst_addr_v6);
    }
    PFL_EXPECT(shadow.has_ports == legacy.has_ports);
    PFL_EXPECT(shadow.src_port == legacy.src_port);
    PFL_EXPECT(shadow.dst_port == legacy.dst_port);
    PFL_EXPECT(shadow.has_transport_payload_length == legacy.has_payload_length);
    PFL_EXPECT(shadow.captured_transport_payload_length == legacy.captured_payload_length);
    PFL_EXPECT(shadow.has_tcp_flags == legacy.has_tcp_flags);
    PFL_EXPECT(shadow.tcp_flags == legacy.tcp_flags);
    PFL_EXPECT((collect_step_kinds(steps) == expected_kinds));

    const auto* pw_facts = find_mpls_pseudowire_facts(steps);
    PFL_REQUIRE(pw_facts != nullptr);
    PFL_EXPECT(pw_facts->has_control_word == expect_control_word);
    if (expected_sequence.has_value()) {
        PFL_EXPECT(pw_facts->sequence == *expected_sequence);
    }
}

void expect_shadow_arp_fixture(
    const DissectionRegistry& registry,
    const std::filesystem::path& relative_path,
    const std::optional<std::string_view>& expected_path
) {
    const auto packet = require_raw_fixture_packet(relative_path);
    const auto legacy = decode_legacy_direct(packet);
    const auto shadow = run_shadow(packet, registry);
    const auto steps = collect_shadow_steps(packet, registry);

    PFL_REQUIRE(legacy.recognized_flow);
    PFL_EXPECT(legacy.protocol == ProtocolId::arp);
    const auto legacy_path_text = format_protocol_path(legacy.path);
    if (expected_path.has_value()) {
        PFL_EXPECT(legacy_path_text == *expected_path);
    }
    PFL_EXPECT(shadow.outcome == ImportDissectionOutcome::recognized_flow);
    PFL_EXPECT(shadow.stop_reason == StopReason::terminal_protocol);
    PFL_EXPECT(shadow.terminal_protocol == ProtocolId::arp);
    PFL_EXPECT(shadow.family == legacy.family);
    PFL_EXPECT(shadow.has_flow_addresses == legacy.has_addresses);
    PFL_EXPECT(shadow.src_addr_v4 == legacy.src_addr_v4);
    PFL_EXPECT(shadow.dst_addr_v4 == legacy.dst_addr_v4);
    PFL_EXPECT(shadow_path(shadow) == legacy.path);
    PFL_EXPECT(format_shadow_path(shadow) == legacy_path_text);
    PFL_EXPECT(shadow.has_arp_addresses);
    PFL_EXPECT(!shadow.has_ports);
    PFL_EXPECT(step_kinds_contain(steps, DissectionLayerKind::mpls_pseudowire));
}

void expect_negative_fixture(
    const DissectionRegistry& registry,
    const std::filesystem::path& relative_path,
    const std::optional<StopReason>& expected_stop_reason,
    const std::string& expected_outer_path,
    const std::vector<DissectionLayerKind>& expected_kinds,
    const bool expect_pseudowire_step,
    const bool expect_control_word
) {
    const auto packet = require_raw_fixture_packet(relative_path);
    const auto shadow = run_shadow(packet, registry);
    const auto steps = collect_shadow_steps(packet, registry);

    PFL_EXPECT(shadow.outcome == ImportDissectionOutcome::unrecognized);
    if (expected_stop_reason.has_value()) {
        PFL_EXPECT(shadow.stop_reason == *expected_stop_reason);
    }
    PFL_EXPECT(format_shadow_path(shadow) == expected_outer_path);
    PFL_EXPECT(format_shadow_path(shadow).find("MPLS PW") == std::string::npos);
    PFL_EXPECT(!shadow.has_flow_addresses);
    PFL_EXPECT(!shadow.has_ports);
    PFL_EXPECT((collect_step_kinds(steps) == expected_kinds));
    PFL_EXPECT(step_kinds_contain(steps, DissectionLayerKind::mpls_pseudowire) == expect_pseudowire_step);

    const auto* pw_facts = find_mpls_pseudowire_facts(steps);
    if (expect_control_word) {
        PFL_REQUIRE(pw_facts != nullptr);
        PFL_EXPECT(pw_facts->has_control_word);
    } else if (pw_facts != nullptr) {
        PFL_EXPECT(!pw_facts->has_control_word);
    }
}

void expect_mpls_pseudowire_registry_mappings() {
    const auto registry = require_registry();

    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::mpls_bos_payload,
        .value = kMplsBosPayloadSelectorValue,
    }) == dissect_mpls_bos_payload);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::mpls_pw_inner_frame,
        .value = kMplsPseudowireInnerFrameSelectorValue,
    }) == dissect_mpls_pseudowire_inner_ethernet);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::mpls_pw_inner_ether_type,
        .value = detail::kEtherTypeIpv4,
    }) != nullptr);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::mpls_pw_inner_ether_type,
        .value = detail::kEtherTypeIpv6,
    }) != nullptr);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::mpls_pw_inner_ether_type,
        .value = detail::kEtherTypeArp,
    }) != nullptr);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::mpls_pw_inner_ether_type,
        .value = detail::kEtherTypeVlan,
    }) == dissect_mpls_pseudowire_inner_vlan);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::mpls_pw_inner_ether_type,
        .value = detail::kEtherTypeQinq,
    }) == dissect_mpls_pseudowire_inner_vlan);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::mpls_pw_inner_ether_type,
        .value = detail::kEtherTypeLegacyVlan,
    }) == dissect_mpls_pseudowire_inner_vlan);

    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::mpls_pw_inner_ether_type,
        .value = detail::kEtherTypePppoeDiscovery,
    }) == nullptr);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::mpls_pw_inner_ether_type,
        .value = detail::kEtherTypePppoeSession,
    }) == nullptr);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::mpls_pw_inner_ether_type,
        .value = detail::kEtherTypeMplsUnicast,
    }) == nullptr);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::mpls_pw_inner_ether_type,
        .value = detail::kEtherTypePbb,
    }) == nullptr);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::mpls_pw_inner_ether_type,
        .value = detail::kEtherTypeMacsec,
    }) == nullptr);
}

void expect_mpls_pseudowire_direct_parser_cases() {
    const auto registry = require_registry();

    {
        const auto packet = make_raw_packet(make_mpls_pseudowire_packet(
            {24050U, 16050U},
            make_default_inner_ipv4_udp_frame()
        ));
        const auto shadow = run_shadow(packet, registry);
        const auto steps = collect_shadow_steps(packet, registry);
        PFL_EXPECT(shadow.outcome == ImportDissectionOutcome::recognized_flow);
        PFL_EXPECT(format_shadow_path(shadow) == "EthernetII -> MPLS(label=24050) -> MPLS(label=16050) -> MPLS PW -> EthernetII -> IPv4 -> UDP");
        PFL_EXPECT((collect_step_kinds(steps) == std::vector<DissectionLayerKind> {
            DissectionLayerKind::ethernet_ii,
            DissectionLayerKind::mpls,
            DissectionLayerKind::mpls,
            DissectionLayerKind::mpls_pseudowire,
            DissectionLayerKind::ethernet_ii,
            DissectionLayerKind::ipv4,
            DissectionLayerKind::udp,
        }));
        const auto* pw_facts = find_mpls_pseudowire_facts(steps);
        PFL_REQUIRE(pw_facts != nullptr);
        PFL_EXPECT(!pw_facts->has_control_word);
    }

    {
        const auto packet = make_raw_packet(make_mpls_pseudowire_packet(
            {24050U, 16050U},
            make_default_inner_ipv6_udp_frame(),
            std::pair<std::uint16_t, std::uint16_t> {0x0000U, 0xFFFFU}
        ));
        const auto shadow = run_shadow(packet, registry);
        const auto steps = collect_shadow_steps(packet, registry);
        PFL_EXPECT(shadow.outcome == ImportDissectionOutcome::recognized_flow);
        PFL_EXPECT((collect_step_kinds(steps) == std::vector<DissectionLayerKind> {
            DissectionLayerKind::ethernet_ii,
            DissectionLayerKind::mpls,
            DissectionLayerKind::mpls,
            DissectionLayerKind::mpls_pseudowire,
            DissectionLayerKind::ethernet_ii,
            DissectionLayerKind::ipv6,
            DissectionLayerKind::udp,
        }));
        const auto* pw_facts = find_mpls_pseudowire_facts(steps);
        PFL_REQUIRE(pw_facts != nullptr);
        PFL_EXPECT(pw_facts->has_control_word);
        PFL_EXPECT(pw_facts->control_word_flags == 0U);
        PFL_EXPECT(pw_facts->sequence == 0xFFFFU);
    }

    {
        const auto control_word_only = make_declared_root_slice({0x00U, 0x00U, 0x12U}, 3U);
        const auto parsed = parse_mpls_pseudowire_control_word(control_word_only);
        PFL_EXPECT(parsed.status == ParseStatus::truncated);
        PFL_EXPECT(parsed.header_length == 4U);
    }
}

void expect_mpls_pseudowire_success_fixtures() {
    const auto registry = require_registry();

    struct FlowFixtureExpectation {
        const char* fixture;
        std::optional<std::string_view> path;
        std::vector<DissectionLayerKind> kinds;
        bool has_control_word;
    };

    const std::vector<FlowFixtureExpectation> expectations {
        {"parsing/mpls_pw/01_mpls_pw_eth_ipv4_tcp_no_cw.pcap", "EthernetII -> MPLS(label=24050) -> MPLS(label=16050) -> MPLS PW -> EthernetII -> IPv4 -> TCP", {DissectionLayerKind::ethernet_ii, DissectionLayerKind::mpls, DissectionLayerKind::mpls, DissectionLayerKind::mpls_pseudowire, DissectionLayerKind::ethernet_ii, DissectionLayerKind::ipv4, DissectionLayerKind::tcp}, false},
        {"parsing/mpls_pw/02_mpls_pw_eth_ipv4_udp_no_cw.pcap", "EthernetII -> MPLS(label=24050) -> MPLS(label=16050) -> MPLS PW -> EthernetII -> IPv4 -> UDP", {DissectionLayerKind::ethernet_ii, DissectionLayerKind::mpls, DissectionLayerKind::mpls, DissectionLayerKind::mpls_pseudowire, DissectionLayerKind::ethernet_ii, DissectionLayerKind::ipv4, DissectionLayerKind::udp}, false},
        {"parsing/mpls_pw/03_mpls_pw_eth_ipv6_tcp_cw.pcap", "EthernetII -> MPLS(label=24050) -> MPLS(label=16050) -> MPLS PW -> EthernetII -> IPv6 -> TCP", {DissectionLayerKind::ethernet_ii, DissectionLayerKind::mpls, DissectionLayerKind::mpls, DissectionLayerKind::mpls_pseudowire, DissectionLayerKind::ethernet_ii, DissectionLayerKind::ipv6, DissectionLayerKind::tcp}, true},
        {"parsing/mpls_pw/04_mpls_pw_eth_ipv6_udp_cw.pcap", "EthernetII -> MPLS(label=24050) -> MPLS(label=16050) -> MPLS PW -> EthernetII -> IPv6 -> UDP", {DissectionLayerKind::ethernet_ii, DissectionLayerKind::mpls, DissectionLayerKind::mpls, DissectionLayerKind::mpls_pseudowire, DissectionLayerKind::ethernet_ii, DissectionLayerKind::ipv6, DissectionLayerKind::udp}, true},
        {"parsing/mpls_pw/06_mpls_pw_eth_vlan_ipv4_tcp_cw.pcap", std::nullopt, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::mpls, DissectionLayerKind::mpls, DissectionLayerKind::mpls_pseudowire, DissectionLayerKind::ethernet_ii, DissectionLayerKind::vlan, DissectionLayerKind::ipv4, DissectionLayerKind::tcp}, true},
        {"parsing/mpls_pw/07_mpls_pw_eth_qinq_ipv4_udp_cw.pcap", std::nullopt, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::mpls, DissectionLayerKind::mpls, DissectionLayerKind::mpls_pseudowire, DissectionLayerKind::ethernet_ii, DissectionLayerKind::vlan, DissectionLayerKind::vlan, DissectionLayerKind::ipv4, DissectionLayerKind::udp}, true},
        {"parsing/mpls_pw/08_mpls_pw_eth_llc_snap_ipv4_udp_cw.pcap", "EthernetII -> MPLS(label=24050) -> MPLS(label=16050) -> MPLS PW -> IEEE 802.3 -> LLC/SNAP -> IPv4 -> UDP", {DissectionLayerKind::ethernet_ii, DissectionLayerKind::mpls, DissectionLayerKind::mpls, DissectionLayerKind::mpls_pseudowire, DissectionLayerKind::ieee8023, DissectionLayerKind::llc_snap, DissectionLayerKind::ipv4, DissectionLayerKind::udp}, true},
        {"parsing/mpls_pw/15_mpls_pw_ambiguous_no_cw_inner_ethernet.pcap", "EthernetII -> MPLS(label=24050) -> MPLS(label=16050) -> MPLS PW -> EthernetII -> IPv4 -> UDP", {DissectionLayerKind::ethernet_ii, DissectionLayerKind::mpls, DissectionLayerKind::mpls, DissectionLayerKind::mpls_pseudowire, DissectionLayerKind::ethernet_ii, DissectionLayerKind::ipv4, DissectionLayerKind::udp}, false},
        {"parsing/mpls_pw/16_mpls_pw_outer_vlan_inner_qinq_ipv4_udp_cw.pcap", "EthernetII -> VLAN(vid=300) -> MPLS(label=24050) -> MPLS(label=16050) -> MPLS PW -> EthernetII -> VLAN(vid=100) -> VLAN(vid=200) -> IPv4 -> UDP", {DissectionLayerKind::ethernet_ii, DissectionLayerKind::vlan, DissectionLayerKind::mpls, DissectionLayerKind::mpls, DissectionLayerKind::mpls_pseudowire, DissectionLayerKind::ethernet_ii, DissectionLayerKind::vlan, DissectionLayerKind::vlan, DissectionLayerKind::ipv4, DissectionLayerKind::udp}, true},
        {"parsing/mpls_pw/17_mpls_pw_outer_qinq_inner_ipv4_udp_cw.pcap", "EthernetII -> VLAN(vid=310) -> VLAN(vid=311) -> MPLS(label=24050) -> MPLS(label=16050) -> MPLS PW -> EthernetII -> IPv4 -> UDP", {DissectionLayerKind::ethernet_ii, DissectionLayerKind::vlan, DissectionLayerKind::vlan, DissectionLayerKind::mpls, DissectionLayerKind::mpls, DissectionLayerKind::mpls_pseudowire, DissectionLayerKind::ethernet_ii, DissectionLayerKind::ipv4, DissectionLayerKind::udp}, true},
        {"parsing/mpls_pw/18_mpls_pw_outer_legacy_vlan_ipv4_tcp_cw.pcap", "EthernetII -> VLAN(vid=320) -> MPLS(label=24050) -> MPLS(label=16050) -> MPLS PW -> EthernetII -> IPv4 -> TCP", {DissectionLayerKind::ethernet_ii, DissectionLayerKind::vlan, DissectionLayerKind::mpls, DissectionLayerKind::mpls, DissectionLayerKind::mpls_pseudowire, DissectionLayerKind::ethernet_ii, DissectionLayerKind::ipv4, DissectionLayerKind::tcp}, true},
    };

    for (const auto& expectation : expectations) {
        ScopedTestContext fixture_context {std::string {"fixture="} + expectation.fixture};
        expect_shadow_flow_fixture(
            registry,
            expectation.fixture,
            expectation.path,
            expectation.kinds,
            expectation.has_control_word
        );
    }

    {
        ScopedTestContext fixture_context {"fixture=parsing/mpls_pw/05_mpls_pw_eth_arp_cw.pcap"};
        expect_shadow_arp_fixture(
            registry,
            "parsing/mpls_pw/05_mpls_pw_eth_arp_cw.pcap",
            std::nullopt
        );
    }

    {
        ScopedTestContext fixture_context {"fixture=parsing/mpls_pw/14_mpls_pw_control_word_with_sequence.pcap"};
        expect_shadow_flow_fixture(
            registry,
            "parsing/mpls_pw/14_mpls_pw_control_word_with_sequence.pcap",
            "EthernetII -> MPLS(label=24050) -> MPLS(label=16050) -> MPLS PW -> EthernetII -> IPv4 -> UDP",
            {
                DissectionLayerKind::ethernet_ii,
                DissectionLayerKind::mpls,
                DissectionLayerKind::mpls,
                DissectionLayerKind::mpls_pseudowire,
                DissectionLayerKind::ethernet_ii,
                DissectionLayerKind::ipv4,
                DissectionLayerKind::udp,
            },
            true,
            0x1234U
        );
    }
}

void expect_mpls_pseudowire_negative_and_ambiguous_fixtures() {
    const auto registry = require_registry();

    {
        ScopedTestContext fixture_context {"fixture=parsing/mpls_pw/09_mpls_pw_unknown_inner_ethertype_cw.pcap"};
        expect_negative_fixture(
            registry,
            "parsing/mpls_pw/09_mpls_pw_unknown_inner_ethertype_cw.pcap",
            StopReason::unknown_next_protocol,
            "EthernetII -> MPLS(label=24050) -> MPLS(label=16050)",
            {DissectionLayerKind::ethernet_ii, DissectionLayerKind::mpls, DissectionLayerKind::mpls, DissectionLayerKind::mpls_pseudowire, DissectionLayerKind::ethernet_ii},
            true,
            true
        );
    }

    {
        ScopedTestContext fixture_context {"fixture=parsing/mpls_pw/10_mpls_pw_truncated_label_stack.pcap"};
        expect_negative_fixture(
            registry,
            "parsing/mpls_pw/10_mpls_pw_truncated_label_stack.pcap",
            StopReason::malformed,
            "EthernetII",
            {DissectionLayerKind::ethernet_ii, DissectionLayerKind::mpls},
            false,
            false
        );
    }

    {
        ScopedTestContext fixture_context {"fixture=parsing/mpls_pw/11_mpls_pw_truncated_control_word.pcap"};
        expect_negative_fixture(
            registry,
            "parsing/mpls_pw/11_mpls_pw_truncated_control_word.pcap",
            StopReason::truncated,
            "EthernetII -> MPLS(label=24050) -> MPLS(label=16050)",
            {DissectionLayerKind::ethernet_ii, DissectionLayerKind::mpls, DissectionLayerKind::mpls, DissectionLayerKind::mpls_pseudowire},
            true,
            false
        );
    }

    {
        ScopedTestContext fixture_context {"fixture=parsing/mpls_pw/12_mpls_pw_truncated_inner_ethernet.pcap"};
        expect_negative_fixture(
            registry,
            "parsing/mpls_pw/12_mpls_pw_truncated_inner_ethernet.pcap",
            StopReason::truncated,
            "EthernetII -> MPLS(label=24050) -> MPLS(label=16050)",
            {DissectionLayerKind::ethernet_ii, DissectionLayerKind::mpls, DissectionLayerKind::mpls, DissectionLayerKind::mpls_pseudowire, DissectionLayerKind::ethernet_ii},
            true,
            true
        );
    }

    {
        ScopedTestContext fixture_context {"fixture=parsing/mpls_pw/13_mpls_pw_truncated_inner_ipv4.pcap"};
        expect_negative_fixture(
            registry,
            "parsing/mpls_pw/13_mpls_pw_truncated_inner_ipv4.pcap",
            StopReason::truncated,
            "EthernetII -> MPLS(label=24050) -> MPLS(label=16050)",
            {DissectionLayerKind::ethernet_ii, DissectionLayerKind::mpls, DissectionLayerKind::mpls, DissectionLayerKind::mpls_pseudowire, DissectionLayerKind::ethernet_ii, DissectionLayerKind::ipv4},
            true,
            true
        );
    }

    {
        ScopedTestContext fixture_context {"fixture=parsing/mpls_pw/19_mpls_pw_ambiguous_no_cw_mac_starts_with_4.pcap"};
        const auto packet = require_raw_fixture_packet("parsing/mpls_pw/19_mpls_pw_ambiguous_no_cw_mac_starts_with_4.pcap");
        const auto shadow = run_shadow(packet, registry);
        const auto steps = collect_shadow_steps(packet, registry);
        PFL_EXPECT(shadow.outcome == ImportDissectionOutcome::unrecognized);
        PFL_EXPECT((shadow.stop_reason == StopReason::malformed || shadow.stop_reason == StopReason::truncated));
        PFL_EXPECT(format_shadow_path(shadow) == "EthernetII -> MPLS(label=24050) -> MPLS(label=16050)");
        PFL_EXPECT(!step_kinds_contain(steps, DissectionLayerKind::mpls_pseudowire));
        PFL_EXPECT(step_kinds_contain(steps, DissectionLayerKind::ipv4));
    }

    {
        ScopedTestContext fixture_context {"fixture=parsing/mpls_pw/20_mpls_pw_ambiguous_no_cw_mac_starts_with_6.pcap"};
        const auto packet = require_raw_fixture_packet("parsing/mpls_pw/20_mpls_pw_ambiguous_no_cw_mac_starts_with_6.pcap");
        const auto shadow = run_shadow(packet, registry);
        const auto steps = collect_shadow_steps(packet, registry);
        PFL_EXPECT(shadow.outcome == ImportDissectionOutcome::unrecognized);
        PFL_EXPECT((shadow.stop_reason == StopReason::malformed || shadow.stop_reason == StopReason::truncated));
        PFL_EXPECT(format_shadow_path(shadow) == "EthernetII -> MPLS(label=24050) -> MPLS(label=16050)");
        PFL_EXPECT(!step_kinds_contain(steps, DissectionLayerKind::mpls_pseudowire));
        PFL_EXPECT(step_kinds_contain(steps, DissectionLayerKind::ipv6));
    }

    {
        ScopedTestContext fixture_context {"fixture=parsing/mpls_pw/21_mpls_pw_inner_pppoe_session_no_cw.pcap"};
        expect_negative_fixture(
            registry,
            "parsing/mpls_pw/21_mpls_pw_inner_pppoe_session_no_cw.pcap",
            StopReason::unknown_next_protocol,
            "EthernetII -> MPLS(label=24050) -> MPLS(label=16050)",
            {DissectionLayerKind::ethernet_ii, DissectionLayerKind::mpls, DissectionLayerKind::mpls, DissectionLayerKind::mpls_pseudowire, DissectionLayerKind::ethernet_ii},
            true,
            false
        );
    }

    {
        ScopedTestContext fixture_context {"fixture=parsing/mpls_pw/22_mpls_pw_inner_mpls_no_cw.pcap"};
        expect_negative_fixture(
            registry,
            "parsing/mpls_pw/22_mpls_pw_inner_mpls_no_cw.pcap",
            StopReason::unknown_next_protocol,
            "EthernetII -> MPLS(label=24050) -> MPLS(label=16050)",
            {DissectionLayerKind::ethernet_ii, DissectionLayerKind::mpls, DissectionLayerKind::mpls, DissectionLayerKind::mpls_pseudowire, DissectionLayerKind::ethernet_ii},
            true,
            false
        );
    }

    {
        ScopedTestContext fixture_context {"fixture=parsing/mpls_pw/23_mpls_pw_nonzero_cw_flags_not_recognized.pcap"};
        expect_negative_fixture(
            registry,
            "parsing/mpls_pw/23_mpls_pw_nonzero_cw_flags_not_recognized.pcap",
            StopReason::truncated,
            "EthernetII -> MPLS(label=24050) -> MPLS(label=16050)",
            {DissectionLayerKind::ethernet_ii, DissectionLayerKind::mpls, DissectionLayerKind::mpls, DissectionLayerKind::mpls_pseudowire, DissectionLayerKind::ethernet_ii},
            true,
            false
        );
    }
}

void expect_mpls_pseudowire_identity_cases() {
    const auto registry = require_registry();

    const auto base_packet = make_raw_packet(make_mpls_pseudowire_packet(
        {24050U, 16050U},
        make_default_inner_ipv4_udp_frame()
    ));
    const auto tc_ttl_variant = make_raw_packet(make_ethernet_frame_with_payload(
        detail::kEtherTypeMplsUnicast,
        make_mpls_payload_with_labels(
            {24050U, 16050U},
            make_default_inner_ipv4_udp_frame(),
            5U,
            1U
        )
    ));
    const auto label_variant = make_raw_packet(make_mpls_pseudowire_packet(
        {24051U, 16050U},
        make_default_inner_ipv4_udp_frame()
    ));
    const auto cw_presence_variant = make_raw_packet(make_mpls_pseudowire_packet(
        {24050U, 16050U},
        make_default_inner_ipv4_udp_frame(),
        std::pair<std::uint16_t, std::uint16_t> {0x0000U, 0x2222U}
    ));
    const auto cw_sequence_variant = make_raw_packet(make_mpls_pseudowire_packet(
        {24050U, 16050U},
        make_default_inner_ipv4_udp_frame(),
        std::pair<std::uint16_t, std::uint16_t> {0x0000U, 0xFFFFU}
    ));

    const auto base_shadow = run_shadow(base_packet, registry);
    const auto tc_ttl_shadow = run_shadow(tc_ttl_variant, registry);
    const auto label_shadow = run_shadow(label_variant, registry);
    const auto cw_presence_shadow = run_shadow(cw_presence_variant, registry);
    const auto cw_sequence_shadow = run_shadow(cw_sequence_variant, registry);

    PFL_EXPECT(base_shadow.outcome == ImportDissectionOutcome::recognized_flow);
    PFL_EXPECT(format_shadow_path(base_shadow) == format_shadow_path(tc_ttl_shadow));
    PFL_EXPECT(format_shadow_path(base_shadow) == format_shadow_path(cw_presence_shadow));
    PFL_EXPECT(format_shadow_path(base_shadow) == format_shadow_path(cw_sequence_shadow));
    PFL_EXPECT(format_shadow_path(base_shadow) != format_shadow_path(label_shadow));
}

}  // namespace

void run_common_direct_mpls_pseudowire_dissection_tests() {
    expect_mpls_pseudowire_registry_mappings();
    expect_mpls_pseudowire_direct_parser_cases();
    expect_mpls_pseudowire_success_fixtures();
    expect_mpls_pseudowire_negative_and_ambiguous_fixtures();
    expect_mpls_pseudowire_identity_cases();
}

}  // namespace pfl::tests::common_direct_test
