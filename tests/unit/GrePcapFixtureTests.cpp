#include <algorithm>
#include <array>
#include <filesystem>
#include <set>
#include <string>
#include <string_view>
#include <vector>

#include "TestSupport.h"
#include "app/session/CaptureSession.h"
#include "app/session/FlowRows.h"
#include "core/domain/ProtocolPath.h"

namespace pfl::tests {

namespace {

constexpr bool kEnableGreParserExpectationTests = false;

struct GreFixtureExpectation {
    std::string_view file_name;
    std::uint64_t expected_total_packets;
    std::uint64_t expected_future_flow_count;
    std::string_view expected_future_protocol_path;
    bool is_positive_decode_fixture;
};

constexpr std::array<GreFixtureExpectation, 22> kGreFixtureExpectations {{
    {"01_gre_ipv4_tcp.pcap", 1U, 1U, "EthernetII -> IPv4 -> GRE -> IPv4 -> TCP", true},
    {"02_gre_ipv4_udp.pcap", 1U, 1U, "EthernetII -> IPv4 -> GRE -> IPv4 -> UDP", true},
    {"03_gre_ipv6_tcp.pcap", 1U, 1U, "EthernetII -> IPv4 -> GRE -> IPv6 -> TCP", true},
    {"04_gre_ipv6_udp.pcap", 1U, 1U, "EthernetII -> IPv4 -> GRE -> IPv6 -> UDP", true},
    {"05_ipv6_outer_gre_ipv4_tcp.pcap", 1U, 1U, "EthernetII -> IPv6 -> GRE -> IPv4 -> TCP", true},
    {"06_ipv6_outer_gre_ipv6_udp.pcap", 1U, 1U, "EthernetII -> IPv6 -> GRE -> IPv6 -> UDP", true},
    {"07_gre_key_ipv4_udp.pcap", 1U, 1U, "EthernetII -> IPv4 -> GRE(key=0x11111111) -> IPv4 -> UDP", true},
    {"08_gre_sequence_ipv4_tcp.pcap", 1U, 1U, "EthernetII -> IPv4 -> GRE -> IPv4 -> TCP", true},
    {"09_gre_checksum_ipv4_udp.pcap", 1U, 1U, "EthernetII -> IPv4 -> GRE -> IPv4 -> UDP", true},
    {"10_gre_checksum_key_sequence_ipv4_udp.pcap", 1U, 1U, "EthernetII -> IPv4 -> GRE(key=0x11111111) -> IPv4 -> UDP", true},
    {"11_gre_teb_ethernet_ipv4_tcp.pcap", 1U, 1U, "EthernetII -> IPv4 -> GRE -> EthernetII -> IPv4 -> TCP", true},
    {"12_gre_teb_ethernet_vlan_ipv4_udp.pcap", 1U, 1U, "EthernetII -> IPv4 -> GRE -> EthernetII -> VLAN(vid=130) -> IPv4 -> UDP", true},
    {"13_outer_vlan_gre_ipv4_udp.pcap", 1U, 1U, "EthernetII -> VLAN(vid=330) -> IPv4 -> GRE -> IPv4 -> UDP", true},
    {"14_outer_qinq_gre_ipv4_tcp.pcap", 1U, 1U, "EthernetII -> VLAN(vid=331) -> VLAN(vid=330) -> IPv4 -> GRE -> IPv4 -> TCP", true},
    {"15_gre_mpls_ipv4_udp.pcap", 1U, 1U, "EthernetII -> IPv4 -> GRE -> MPLS(label=16030) -> IPv4 -> UDP", true},
    {"16_gre_unknown_protocol_type.pcap", 1U, 0U, "", false},
    {"17_gre_version1_pptp_like_unsupported.pcap", 1U, 0U, "", false},
    {"18_gre_truncated_base_header.pcap", 1U, 0U, "", false},
    {"19_gre_truncated_key_field.pcap", 1U, 0U, "", false},
    {"20_gre_truncated_inner_ipv4.pcap", 1U, 0U, "", false},
    {"21_gre_same_inner_tuple_different_keys.pcap", 2U, 2U, "EthernetII -> IPv4 -> GRE(key=...) -> IPv4 -> UDP", true},
    {"22_gre_same_inner_tuple_same_key_two_packets.pcap", 2U, 1U, "EthernetII -> IPv4 -> GRE(key=0x11111111) -> IPv4 -> UDP", true},
}};

constexpr std::array<std::string_view, 12> kSupportedGreFixturesNow {{
    "01_gre_ipv4_tcp.pcap",
    "02_gre_ipv4_udp.pcap",
    "03_gre_ipv6_tcp.pcap",
    "04_gre_ipv6_udp.pcap",
    "05_ipv6_outer_gre_ipv4_tcp.pcap",
    "06_ipv6_outer_gre_ipv6_udp.pcap",
    "07_gre_key_ipv4_udp.pcap",
    "08_gre_sequence_ipv4_tcp.pcap",
    "09_gre_checksum_ipv4_udp.pcap",
    "10_gre_checksum_key_sequence_ipv4_udp.pcap",
    "13_outer_vlan_gre_ipv4_udp.pcap",
    "14_outer_qinq_gre_ipv4_tcp.pcap",
}};

constexpr std::array<std::string_view, 8> kUnsupportedGreFixturesNow {{
    "11_gre_teb_ethernet_ipv4_tcp.pcap",
    "12_gre_teb_ethernet_vlan_ipv4_udp.pcap",
    "15_gre_mpls_ipv4_udp.pcap",
    "16_gre_unknown_protocol_type.pcap",
    "17_gre_version1_pptp_like_unsupported.pcap",
    "18_gre_truncated_base_header.pcap",
    "19_gre_truncated_key_field.pcap",
    "20_gre_truncated_inner_ipv4.pcap",
}};

constexpr std::array<std::string_view, 2> kStagedGreKeyIdentityFixtures {{
    "21_gre_same_inner_tuple_different_keys.pcap",
    "22_gre_same_inner_tuple_same_key_two_packets.pcap",
}};

std::filesystem::path fixture_dir() {
    return std::filesystem::path(__FILE__).parent_path().parent_path() / "data" / "parsing" / "gre";
}

std::filesystem::path fixture_path(std::string_view file_name) {
    return fixture_dir() / std::filesystem::path(file_name);
}

const GreFixtureExpectation& require_expectation(std::string_view file_name) {
    const auto found = std::find_if(kGreFixtureExpectations.begin(), kGreFixtureExpectations.end(), [&](const auto& expectation) {
        return expectation.file_name == file_name;
    });
    PFL_REQUIRE(found != kGreFixtureExpectations.end());
    return *found;
}

std::string_view expected_current_protocol_path(std::string_view file_name) {
    if (file_name == "07_gre_key_ipv4_udp.pcap" ||
        file_name == "10_gre_checksum_key_sequence_ipv4_udp.pcap") {
        return "EthernetII -> IPv4 -> GRE -> IPv4 -> UDP";
    }
    return require_expectation(file_name).expected_future_protocol_path;
}

std::set<std::string> expected_fixture_file_names() {
    std::set<std::string> names {};
    for (const auto& expectation : kGreFixtureExpectations) {
        names.emplace(expectation.file_name);
    }
    return names;
}

std::set<std::string> actual_fixture_file_names() {
    std::set<std::string> names {};
    for (const auto& entry : std::filesystem::directory_iterator(fixture_dir())) {
        if (!entry.is_regular_file()) {
            continue;
        }
        if (entry.path().extension() == ".pcap") {
            names.emplace(entry.path().filename().string());
        }
    }
    return names;
}

void expect_gre_fixture_files_exist() {
    for (const auto& expectation : kGreFixtureExpectations) {
        PFL_EXPECT(std::filesystem::exists(fixture_path(expectation.file_name)));
    }
}

void expect_gre_future_expectation_table_covers_all_fixtures() {
    PFL_EXPECT(expected_fixture_file_names() == actual_fixture_file_names());
}

void expect_gre_fixtures_import_without_crash() {
    for (const auto& expectation : kGreFixtureExpectations) {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path(expectation.file_name)));
    }
}

void expect_gre_fixtures_have_expected_total_packet_records() {
    for (const auto& expectation : kGreFixtureExpectations) {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path(expectation.file_name)));

        const auto storage = session.storage_summary();
        PFL_EXPECT(storage.total_packets_seen == expectation.expected_total_packets);
        PFL_EXPECT(storage.total_packets_seen == storage.recognized_packets + storage.unrecognized_packets);
    }
}

void expect_supported_gre_v0_ip_fixtures_decode() {
    for (const auto fixture_name : kSupportedGreFixturesNow) {
        CaptureSession session {};
        const auto& expectation = require_expectation(fixture_name);
        PFL_REQUIRE(session.open_capture(fixture_path(fixture_name)));

        const auto storage = session.storage_summary();
        PFL_EXPECT(storage.total_packets_seen == expectation.expected_total_packets);
        PFL_EXPECT(storage.recognized_packets == expectation.expected_total_packets);
        PFL_EXPECT(storage.unrecognized_packets == 0U);
        PFL_EXPECT(session.unrecognized_packet_count() == 0U);
        PFL_EXPECT(session.summary().packet_count == expectation.expected_total_packets);

        const auto rows = session.list_flows();
        PFL_EXPECT(rows.size() == static_cast<std::size_t>(expectation.expected_future_flow_count));

        const auto expected_path = expected_current_protocol_path(fixture_name);
        const bool found_expected_path = std::any_of(rows.begin(), rows.end(), [&](const FlowRow& row) {
            if (row.protocol_path_id == kInvalidProtocolPathId) {
                return false;
            }
            const auto* path = session.state().protocol_path_registry.find(row.protocol_path_id);
            return path != nullptr && format_protocol_path(*path) == expected_path;
        });
        PFL_EXPECT(found_expected_path);
    }
}

void expect_unsupported_gre_payloads_remain_unrecognized() {
    for (const auto fixture_name : kUnsupportedGreFixturesNow) {
        CaptureSession session {};
        const auto& expectation = require_expectation(fixture_name);
        PFL_REQUIRE(session.open_capture(fixture_path(fixture_name)));

        const auto storage = session.storage_summary();
        PFL_EXPECT(storage.total_packets_seen == expectation.expected_total_packets);
        PFL_EXPECT(storage.recognized_packets == 0U);
        PFL_EXPECT(storage.unrecognized_packets == expectation.expected_total_packets);
        PFL_EXPECT(session.summary().packet_count == 0U);
        PFL_EXPECT(session.list_flows().empty());
        PFL_EXPECT(session.unrecognized_packet_count() == static_cast<std::size_t>(expectation.expected_total_packets));
    }
}

void expect_staged_gre_key_identity_fixtures_import_without_strict_identity_assertions() {
    for (const auto fixture_name : kStagedGreKeyIdentityFixtures) {
        CaptureSession session {};
        const auto& expectation = require_expectation(fixture_name);
        PFL_REQUIRE(session.open_capture(fixture_path(fixture_name)));

        const auto storage = session.storage_summary();
        PFL_EXPECT(storage.total_packets_seen == expectation.expected_total_packets);
        PFL_EXPECT(storage.total_packets_seen == storage.recognized_packets + storage.unrecognized_packets);
    }
}

void expect_gre_truncated_fixtures_import_without_crash() {
    constexpr std::array<std::string_view, 3> truncated_fixtures {{
        "18_gre_truncated_base_header.pcap",
        "19_gre_truncated_key_field.pcap",
        "20_gre_truncated_inner_ipv4.pcap",
    }};

    for (const auto fixture_name : truncated_fixtures) {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path(fixture_name)));
        const auto storage = session.storage_summary();
        PFL_EXPECT(storage.total_packets_seen == 1U);
        PFL_EXPECT(session.list_flows().empty());
        PFL_EXPECT(session.unrecognized_packet_count() == 1U);
    }
}

void run_future_gre_parser_expectation_tests() {
    // Enable this once the staged GRE work lands as well:
    // key-aware identity, GRE TEB continuation, and GRE/MPLS continuation.
    for (const auto& expectation : kGreFixtureExpectations) {
        if (expectation.expected_future_flow_count == 0U) {
            continue;
        }

        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path(expectation.file_name)));

        const auto rows = session.list_flows();
        PFL_EXPECT(rows.size() == static_cast<std::size_t>(expectation.expected_future_flow_count));

        if (!expectation.expected_future_protocol_path.empty()) {
            const bool found_expected_path = std::any_of(rows.begin(), rows.end(), [&](const FlowRow& row) {
                if (row.protocol_path_id == kInvalidProtocolPathId) {
                    return false;
                }
                const auto* path = session.state().protocol_path_registry.find(row.protocol_path_id);
                return path != nullptr && format_protocol_path(*path) == expectation.expected_future_protocol_path;
            });
            PFL_EXPECT(found_expected_path);
        }
    }
}

}  // namespace

void run_gre_pcap_fixture_tests() {
    expect_gre_fixture_files_exist();
    expect_gre_future_expectation_table_covers_all_fixtures();
    expect_gre_fixtures_import_without_crash();
    expect_gre_fixtures_have_expected_total_packet_records();
    expect_supported_gre_v0_ip_fixtures_decode();
    expect_unsupported_gre_payloads_remain_unrecognized();
    expect_staged_gre_key_identity_fixtures_import_without_strict_identity_assertions();
    expect_gre_truncated_fixtures_import_without_crash();

    if constexpr (kEnableGreParserExpectationTests) {
        run_future_gre_parser_expectation_tests();
    }
}

}  // namespace pfl::tests
