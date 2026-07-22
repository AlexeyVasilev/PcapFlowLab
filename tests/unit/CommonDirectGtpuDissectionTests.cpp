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

constexpr std::array<std::string_view, 31> kGtpuFixtures {{
    "parsing/gtpu/01_gtpu_inner_ipv4_tcp.pcap",
    "parsing/gtpu/02_gtpu_inner_ipv4_udp.pcap",
    "parsing/gtpu/03_gtpu_inner_ipv6_tcp.pcap",
    "parsing/gtpu/04_gtpu_inner_ipv6_udp.pcap",
    "parsing/gtpu/05_gtpu_truncated_base_header.pcap",
    "parsing/gtpu/06_gtpu_invalid_version.pcap",
    "parsing/gtpu/07_gtpu_unsupported_message_type.pcap",
    "parsing/gtpu/08_gtpu_truncated_inner_ipv4.pcap",
    "parsing/gtpu/09_gtpu_truncated_inner_ipv6.pcap",
    "parsing/gtpu/10_gtpu_unknown_inner_payload.pcap",
    "parsing/gtpu/11_gtpu_inner_ipv4_tcp_bidirectional.pcap",
    "parsing/gtpu/12_gtpu_same_outer_tuple_different_inner_flows.pcap",
    "parsing/gtpu/13_gtpu_outer_ipv6_inner_ipv4_tcp.pcap",
    "parsing/gtpu/14_gtpu_wrong_udp_port_valid_gtpu_payload.pcap",
    "parsing/gtpu/15_gtpu_teid_boundary_values.pcap",
    "parsing/gtpu/16_gtpu_with_sequence_inner_ipv4_tcp.pcap",
    "parsing/gtpu/17_gtpu_with_npdu_inner_ipv4_tcp.pcap",
    "parsing/gtpu/18_gtpu_with_extension_header_inner_ipv4_tcp.pcap",
    "parsing/gtpu/19_gtpu_truncated_optional_header.pcap",
    "parsing/gtpu/20_gtpu_truncated_extension_header.pcap",
    "parsing/gtpu/21_gtpu_same_inner_tuple_different_teid.pcap",
    "parsing/gtpu/22_gtpu_udp_port_direction_matrix.pcap",
    "parsing/gtpu/23_gtpu_control_message_matrix.pcap",
    "parsing/gtpu/24_gtpu_flag_matrix_inner_ipv4_tcp.pcap",
    "parsing/gtpu/25_gtpu_outer_tagged_contexts.pcap",
    "parsing/gtpu/26_gtpu_outer_ipv6_inner_ipv6_udp.pcap",
    "parsing/gtpu/27_gtpu_linux_sll_inner_ipv4_udp.pcap",
    "parsing/gtpu/28_gtpu_linux_sll2_inner_ipv6_tcp.pcap",
    "parsing/gtpu/29_gtpu_nested_overlay_udp_terminal.pcap",
    "parsing/gtpu/30_gtpu_outer_ipv4_fragmentation.pcap",
    "parsing/gtpu/31_gtpu_outer_ipv6_fragmentation.pcap",
}};

constexpr std::array<FixturePacketExpectation, 10> kSelectedExpectations {{
    {"parsing/gtpu/05_gtpu_truncated_base_header.pcap", 0U, "EthernetII -> IPv4 -> UDP", StopReason::terminal_protocol},
    {"parsing/gtpu/06_gtpu_invalid_version.pcap", 0U, "EthernetII -> IPv4 -> UDP", StopReason::terminal_protocol},
    {"parsing/gtpu/07_gtpu_unsupported_message_type.pcap", 0U, "EthernetII -> IPv4 -> UDP", StopReason::terminal_protocol},
    {"parsing/gtpu/08_gtpu_truncated_inner_ipv4.pcap", 0U, "EthernetII -> IPv4 -> UDP", StopReason::terminal_protocol},
    {"parsing/gtpu/09_gtpu_truncated_inner_ipv6.pcap", 0U, "EthernetII -> IPv4 -> UDP", StopReason::terminal_protocol},
    {"parsing/gtpu/10_gtpu_unknown_inner_payload.pcap", 0U, "EthernetII -> IPv4 -> UDP", StopReason::terminal_protocol},
    {"parsing/gtpu/19_gtpu_truncated_optional_header.pcap", 0U, "EthernetII -> IPv4 -> UDP", StopReason::terminal_protocol},
    {"parsing/gtpu/20_gtpu_truncated_extension_header.pcap", 0U, "EthernetII -> IPv4 -> UDP", StopReason::terminal_protocol},
    {"parsing/gtpu/30_gtpu_outer_ipv4_fragmentation.pcap", 0U, "EthernetII -> IPv4", StopReason::needs_reassembly},
    {"parsing/gtpu/31_gtpu_outer_ipv6_fragmentation.pcap", 0U, "EthernetII -> IPv6", StopReason::needs_reassembly},
}};

std::vector<std::uint8_t> make_gtpu_bytes(
    const std::uint8_t flags,
    const std::uint8_t message_type,
    const std::uint32_t teid,
    const std::vector<std::uint8_t>& inner_payload,
    const std::optional<std::uint16_t>& sequence_number = std::nullopt,
    const std::optional<std::uint8_t>& npdu_number = std::nullopt,
    const std::optional<std::uint8_t>& first_extension_header_type = std::nullopt,
    const std::vector<std::uint8_t>& extension_headers = {}
) {
    std::vector<std::uint8_t> bytes {flags, message_type};
    const auto optional_fields_size =
        (first_extension_header_type.has_value() || sequence_number.has_value() || npdu_number.has_value())
            ? detail::kGtpuOptionalFieldsSize
            : 0U;
    const auto payload_length = optional_fields_size + extension_headers.size() + inner_payload.size();
    append_be16(bytes, static_cast<std::uint16_t>(payload_length));
    append_be32(bytes, teid);
    if (optional_fields_size != 0U) {
        append_be16(bytes, sequence_number.value_or(0U));
        bytes.push_back(npdu_number.value_or(0U));
        bytes.push_back(first_extension_header_type.value_or(0U));
    }
    bytes.insert(bytes.end(), extension_headers.begin(), extension_headers.end());
    bytes.insert(bytes.end(), inner_payload.begin(), inner_payload.end());
    return bytes;
}

const GtpuFacts* find_gtpu_facts(const std::vector<DissectionStep>& steps) {
    for (const auto& step : steps) {
        if (step.layer != DissectionLayerKind::gtpu) {
            continue;
        }
        if (const auto* facts = std::get_if<GtpuFacts>(&step.facts); facts != nullptr) {
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

void expect_gtpu_direct_parser_and_udp_dispatch() {
    const auto inner_ipv4_tcp = make_ipv4_payload_packet(
        ipv4(10, 60, 0, 10),
        ipv4(10, 60, 0, 20),
        detail::kIpProtocolTcp,
        make_ipv4_tcp_segment(49660U, 443U, 4U, 0x18U)
    );

    {
        const auto gtpu_bytes = make_gtpu_bytes(
            static_cast<std::uint8_t>(0x30U | detail::kGtpuFlagSequenceNumber | detail::kGtpuFlagNpduNumber |
                                      detail::kGtpuFlagExtensionHeader),
            detail::kGtpuMessageTypeTPdu,
            0x01020304U,
            inner_ipv4_tcp,
            0x1234U,
            0x5aU,
            0x85U,
            {0x01U, 0xdeU, 0xadU, 0x00U}
        );
        const auto parsed = parse_gtpu_header(make_declared_root_slice(gtpu_bytes, gtpu_bytes.size()));
        PFL_EXPECT(parsed.status == ParseStatus::complete);
        PFL_EXPECT(parsed.version == 1U);
        PFL_EXPECT(parsed.message_type == detail::kGtpuMessageTypeTPdu);
        PFL_EXPECT(parsed.teid == 0x01020304U);
        PFL_EXPECT(parsed.has_optional_fields);
        PFL_EXPECT(parsed.has_sequence_number);
        PFL_EXPECT(parsed.has_npdu_number);
        PFL_EXPECT(parsed.has_extension_headers);
        PFL_EXPECT(parsed.sequence_number == 0x1234U);
        PFL_EXPECT(parsed.npdu_number == 0x5aU);
        PFL_EXPECT(parsed.first_extension_header_type == 0x85U);
        PFL_EXPECT(parsed.inner_payload_type == detail::kEtherTypeIpv4);
        PFL_EXPECT(parsed.header_length == 16U);
        PFL_EXPECT(parsed.packet_length == gtpu_bytes.size());
    }

    {
        auto truncated_header = make_gtpu_bytes(0x30U, detail::kGtpuMessageTypeTPdu, 0x01020304U, inner_ipv4_tcp);
        truncated_header.resize(detail::kGtpuBaseHeaderSize - 1U);
        const auto parsed = parse_gtpu_header(make_declared_root_slice(truncated_header, detail::kGtpuBaseHeaderSize));
        PFL_EXPECT(parsed.status == ParseStatus::truncated);
    }

    {
        const auto parsed = parse_gtpu_header(make_declared_root_slice(
            make_gtpu_bytes(0x30U, detail::kGtpuMessageTypeTPdu, 0x01020304U, inner_ipv4_tcp),
            detail::kGtpuBaseHeaderSize - 1U
        ));
        PFL_EXPECT(parsed.status == ParseStatus::malformed);
    }

    {
        const auto clear_pt = parse_gtpu_header(make_declared_root_slice(
            make_gtpu_bytes(0x20U, detail::kGtpuMessageTypeTPdu, 0x01020304U, inner_ipv4_tcp),
            detail::kGtpuBaseHeaderSize + inner_ipv4_tcp.size()
        ));
        PFL_EXPECT(clear_pt.status == ParseStatus::unsupported_variant);

        const auto wrong_version = parse_gtpu_header(make_declared_root_slice(
            make_gtpu_bytes(0x50U, detail::kGtpuMessageTypeTPdu, 0x01020304U, inner_ipv4_tcp),
            detail::kGtpuBaseHeaderSize + inner_ipv4_tcp.size()
        ));
        PFL_EXPECT(wrong_version.status == ParseStatus::unsupported_variant);
    }

    {
        const auto built = make_common_direct_registry();
        PFL_REQUIRE(built.ok());
        const auto outer_udp_packet = make_raw_packet(make_ethernet_ipv4_udp_packet_with_bytes_payload(
            ipv4(203, 0, 113, 60),
            ipv4(203, 0, 113, 61),
            55000U,
            detail::kUdpPortGtpu,
            make_gtpu_bytes(0x30U, detail::kGtpuMessageTypeTPdu, 0x01020304U, inner_ipv4_tcp)
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
        PFL_EXPECT(udp_step.handoff->selector.value == detail::kUdpPortGtpu);

        const auto steps = collect_shadow_steps(outer_udp_packet, *built.registry);
        expect_step_kinds(
            steps,
            {
                DissectionLayerKind::ethernet_ii,
                DissectionLayerKind::ipv4,
                DissectionLayerKind::udp,
                DissectionLayerKind::gtpu,
                DissectionLayerKind::ipv4,
                DissectionLayerKind::tcp,
            }
        );
        const auto* facts = find_gtpu_facts(steps);
        PFL_REQUIRE(facts != nullptr);
        PFL_EXPECT(facts->teid == 0x01020304U);
    }
}

void expect_gtpu_registry_mappings() {
    const auto built = make_common_direct_registry();
    PFL_REQUIRE(built.ok());
    const auto& registry = *built.registry;

    PFL_EXPECT(registry.entry_count() == 139U);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::udp_destination_port_candidate,
        .value = detail::kUdpPortGtpu,
    }) == dissect_gtpu);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::gtpu_inner_payload,
        .value = detail::kEtherTypeIpv4,
    }) == dissect_gtpu_inner_ipv4);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::gtpu_inner_payload,
        .value = detail::kEtherTypeIpv6,
    }) == dissect_gtpu_inner_ipv6);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::gtpu_inner_ip_protocol,
        .value = detail::kIpProtocolTcp,
    }) == dissect_tcp);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::gtpu_inner_ip_protocol,
        .value = detail::kIpProtocolUdp,
    }) == dissect_udp_terminal);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::gtpu_inner_ip_protocol,
        .value = detail::kIpProtocolSctp,
    }) == dissect_sctp);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::gtpu_inner_ipv6_next_header,
        .value = detail::kIpProtocolTcp,
    }) == dissect_tcp);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::gtpu_inner_ipv6_next_header,
        .value = detail::kIpProtocolUdp,
    }) == dissect_udp_terminal);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::gtpu_inner_ipv6_next_header,
        .value = detail::kIpProtocolSctp,
    }) == dissect_sctp);
    PFL_EXPECT(registry.find(ProtocolSelector {
        .domain = SelectorDomain::gtpu_inner_ip_protocol,
        .value = detail::kIpProtocolGre,
    }) == nullptr);
}

void expect_all_gtpu_fixture_packets_shadow_match_legacy() {
    const auto built = make_common_direct_registry();
    PFL_REQUIRE(built.ok());
    const auto& registry = *built.registry;

    for (const auto fixture : kGtpuFixtures) {
        const auto packets = require_raw_fixture_packets(std::filesystem::path {std::string(fixture)});
        for (std::size_t packet_index = 0U; packet_index < packets.size(); ++packet_index) {
            expect_packet_shadow_matches_legacy(
                registry,
                FixturePacketExpectation {
                    .fixture = fixture,
                    .packet_index = packet_index,
                }
            );
        }
    }
}

void expect_selected_gtpu_negative_semantics() {
    const auto built = make_common_direct_registry();
    PFL_REQUIRE(built.ok());
    const auto& registry = *built.registry;

    for (const auto& expectation : kSelectedExpectations) {
        expect_packet_shadow_matches_legacy(registry, expectation);
    }
}

void expect_gtpu_identity_splits_match_legacy() {
    const auto built = make_common_direct_registry();
    PFL_REQUIRE(built.ok());
    const auto& registry = *built.registry;

    constexpr std::array<std::pair<std::string_view, std::size_t>, 3> kIdentityCases {{
        {"parsing/gtpu/11_gtpu_inner_ipv4_tcp_bidirectional.pcap", 1U},
        {"parsing/gtpu/12_gtpu_same_outer_tuple_different_inner_flows.pcap", 2U},
        {"parsing/gtpu/21_gtpu_same_inner_tuple_different_teid.pcap", 2U},
    }};

    for (const auto& [fixture, expected_count] : kIdentityCases) {
        const ScopedTestContext context {
            "fixture=" + std::string(fixture) + " | identity"
        };
        const auto packets = require_raw_fixture_packets(std::filesystem::path {std::string(fixture)});
        std::set<std::string> shadow_identities {};
        std::set<std::string> legacy_identities {};

        for (const auto& packet : packets) {
            const auto shadow = run_shadow(packet, registry);
            if (shadow.outcome == ImportDissectionOutcome::recognized_flow) {
                shadow_identities.emplace(shadow_flow_identity_text(shadow));
            }

            const auto legacy = decode_legacy_direct(packet);
            if (legacy.recognized_flow) {
                legacy_identities.emplace(legacy_flow_identity_text(legacy));
            }
        }

        PFL_EXPECT(shadow_identities.size() == expected_count);
        PFL_EXPECT(legacy_identities.size() == expected_count);
        PFL_EXPECT(shadow_identities == legacy_identities);
    }
}

void expect_gtpu_nested_inner_udp_remains_terminal() {
    const auto built = make_common_direct_registry();
    PFL_REQUIRE(built.ok());
    const auto& registry = *built.registry;

    const auto packets =
        require_raw_fixture_packets(std::filesystem::path {"parsing/gtpu/29_gtpu_nested_overlay_udp_terminal.pcap"});
    PFL_REQUIRE(packets.size() == 3U);

    for (std::size_t packet_index = 0U; packet_index < packets.size(); ++packet_index) {
        const ScopedTestContext context {
            "fixture=parsing/gtpu/29_gtpu_nested_overlay_udp_terminal.pcap | packet=" + std::to_string(packet_index)
        };
        const auto steps = collect_shadow_steps(packets[packet_index], registry);
        expect_step_kinds(
            steps,
            {
                DissectionLayerKind::ethernet_ii,
                DissectionLayerKind::ipv4,
                DissectionLayerKind::udp,
                DissectionLayerKind::gtpu,
                DissectionLayerKind::ipv4,
                DissectionLayerKind::udp,
            }
        );
        PFL_EXPECT(std::count_if(steps.begin(), steps.end(), [](const auto& step) {
            return step.layer == DissectionLayerKind::gtpu;
        }) == 1);
    }
}

}  // namespace

void run_common_direct_gtpu_dissection_tests() {
    expect_gtpu_direct_parser_and_udp_dispatch();
    expect_gtpu_registry_mappings();
    expect_all_gtpu_fixture_packets_shadow_match_legacy();
    expect_selected_gtpu_negative_semantics();
    expect_gtpu_identity_splits_match_legacy();
    expect_gtpu_nested_inner_udp_remains_terminal();
}

}  // namespace pfl::tests::common_direct_test
