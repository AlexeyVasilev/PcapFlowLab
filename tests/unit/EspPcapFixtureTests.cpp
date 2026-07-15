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

namespace pfl::tests {

namespace {

constexpr bool kEnableEspParserExpectationTests = false;

struct EspFixtureExpectation {
    std::string_view file_name;
    std::uint64_t expected_total_packets;
    std::uint64_t expected_future_flow_count;
    std::string_view expected_future_protocol_path;
    bool is_direct_protocol50_fixture;
    bool is_nat_t_staged_fixture;
};

constexpr std::array<EspFixtureExpectation, 18> kEspFixtureExpectations {{
    {"01_ipv4_esp_basic.pcap", 1U, 1U, "EthernetII -> IPv4 -> ESP(spi=0x01020304)", true, false},
    {"02_ipv6_esp_basic.pcap", 1U, 1U, "EthernetII -> IPv6 -> ESP(spi=0x01020304)", true, false},
    {"03_ipv4_esp_same_hosts_different_spi.pcap", 2U, 2U, "", true, false},
    {"04_ipv4_esp_same_spi_two_packets.pcap", 2U, 1U, "EthernetII -> IPv4 -> ESP(spi=0x01020304)", true, false},
    {"05_ipv6_esp_same_hosts_different_spi.pcap", 2U, 2U, "", true, false},
    {"06_outer_vlan_ipv4_esp.pcap", 1U, 1U, "EthernetII -> VLAN(vid=550) -> IPv4 -> ESP(spi=0x01020304)", true, false},
    {"07_outer_qinq_ipv4_esp.pcap", 1U, 1U, "EthernetII -> VLAN(vid=551) -> VLAN(vid=552) -> IPv4 -> ESP(spi=0x01020304)", true, false},
    {"08_ipv4_esp_large_opaque_payload.pcap", 1U, 1U, "EthernetII -> IPv4 -> ESP(spi=0x01020304)", true, false},
    {"09_ipv4_esp_minimal_header_only.pcap", 1U, 1U, "EthernetII -> IPv4 -> ESP(spi=0x01020304)", true, false},
    {"10_ipv4_esp_truncated_header.pcap", 1U, 0U, "", true, false},
    {"11_ipv4_esp_truncated_spi_only.pcap", 1U, 0U, "", true, false},
    {"12_ipv6_esp_truncated_header.pcap", 1U, 0U, "", true, false},
    {"13_ipv4_esp_zero_spi.pcap", 1U, 1U, "EthernetII -> IPv4 -> ESP(spi=0x00000000)", true, false},
    {"14_ipv4_esp_high_spi_value.pcap", 1U, 1U, "EthernetII -> IPv4 -> ESP(spi=0xffffffff)", true, false},
    {"15_ipv4_esp_sequence_wrapish_values.pcap", 2U, 1U, "EthernetII -> IPv4 -> ESP(spi=0x01020304)", true, false},
    {"16_udp4500_nat_t_esp_non_ike_marker.pcap", 1U, 1U, "", false, true},
    {"17_udp4500_nat_t_ike_marker_staged.pcap", 1U, 0U, "", false, true},
    {"18_ipv4_esp_two_directions_different_spi.pcap", 2U, 2U, "", true, false},
}};

constexpr std::array<std::string_view, 16> kDirectProtocol50FixturesNow {{
    "01_ipv4_esp_basic.pcap",
    "02_ipv6_esp_basic.pcap",
    "03_ipv4_esp_same_hosts_different_spi.pcap",
    "04_ipv4_esp_same_spi_two_packets.pcap",
    "05_ipv6_esp_same_hosts_different_spi.pcap",
    "06_outer_vlan_ipv4_esp.pcap",
    "07_outer_qinq_ipv4_esp.pcap",
    "08_ipv4_esp_large_opaque_payload.pcap",
    "09_ipv4_esp_minimal_header_only.pcap",
    "10_ipv4_esp_truncated_header.pcap",
    "11_ipv4_esp_truncated_spi_only.pcap",
    "12_ipv6_esp_truncated_header.pcap",
    "13_ipv4_esp_zero_spi.pcap",
    "14_ipv4_esp_high_spi_value.pcap",
    "15_ipv4_esp_sequence_wrapish_values.pcap",
    "18_ipv4_esp_two_directions_different_spi.pcap",
}};

constexpr std::array<std::string_view, 3> kTruncatedEspFixturesNow {{
    "10_ipv4_esp_truncated_header.pcap",
    "11_ipv4_esp_truncated_spi_only.pcap",
    "12_ipv6_esp_truncated_header.pcap",
}};

constexpr std::array<std::string_view, 2> kNatTEspFixturesNow {{
    "16_udp4500_nat_t_esp_non_ike_marker.pcap",
    "17_udp4500_nat_t_ike_marker_staged.pcap",
}};

std::filesystem::path fixture_dir() {
    return std::filesystem::path(__FILE__).parent_path().parent_path() / "data" / "parsing" / "esp";
}

std::filesystem::path fixture_path(std::string_view file_name) {
    return fixture_dir() / std::filesystem::path(file_name);
}

const EspFixtureExpectation& require_expectation(std::string_view file_name) {
    const auto found = std::find_if(kEspFixtureExpectations.begin(), kEspFixtureExpectations.end(), [&](const auto& expectation) {
        return expectation.file_name == file_name;
    });
    PFL_REQUIRE(found != kEspFixtureExpectations.end());
    return *found;
}

std::set<std::string> expected_fixture_file_names() {
    std::set<std::string> names {};
    for (const auto& expectation : kEspFixtureExpectations) {
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

bool has_normal_tcp_udp_flow(const std::vector<FlowRow>& rows) {
    return std::any_of(rows.begin(), rows.end(), [](const FlowRow& row) {
        return row.protocol_text == "TCP" || row.protocol_text == "UDP";
    });
}

void expect_esp_fixture_files_exist() {
    for (const auto& expectation : kEspFixtureExpectations) {
        PFL_EXPECT(std::filesystem::exists(fixture_path(expectation.file_name)));
    }
}

void expect_esp_future_expectation_table_covers_all_fixtures() {
    const auto expected_names = expected_fixture_file_names();
    const auto actual_names = actual_fixture_file_names();
    PFL_EXPECT(kEspFixtureExpectations.size() == expected_names.size());
    PFL_EXPECT(expected_names == actual_names);
}

void expect_esp_fixtures_import_without_crash() {
    for (const auto& expectation : kEspFixtureExpectations) {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path(expectation.file_name)));
    }
}

void expect_esp_fixtures_have_expected_total_packet_records() {
    for (const auto& expectation : kEspFixtureExpectations) {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path(expectation.file_name)));

        const auto storage = session.storage_summary();
        PFL_EXPECT(storage.total_packets_seen == expectation.expected_total_packets);
        PFL_EXPECT(storage.total_packets_seen == storage.recognized_packets + storage.unrecognized_packets);
    }
}

void expect_esp_direct_protocol50_fixtures_do_not_create_tcp_udp_flows_before_parser() {
    for (const auto fixture_name : kDirectProtocol50FixturesNow) {
        CaptureSession session {};
        const auto& expectation = require_expectation(fixture_name);
        PFL_REQUIRE(session.open_capture(fixture_path(fixture_name)));

        const auto storage = session.storage_summary();
        PFL_EXPECT(storage.total_packets_seen == expectation.expected_total_packets);

        const auto rows = session.list_flows();
        PFL_EXPECT(!has_normal_tcp_udp_flow(rows));
    }
}

void expect_esp_truncated_fixtures_import_without_crash() {
    for (const auto fixture_name : kTruncatedEspFixturesNow) {
        CaptureSession session {};
        const auto& expectation = require_expectation(fixture_name);
        PFL_REQUIRE(session.open_capture(fixture_path(fixture_name)));

        const auto storage = session.storage_summary();
        PFL_EXPECT(storage.total_packets_seen == expectation.expected_total_packets);
        PFL_EXPECT(storage.total_packets_seen == storage.recognized_packets + storage.unrecognized_packets);
        PFL_EXPECT(!has_normal_tcp_udp_flow(session.list_flows()));
    }
}

void expect_esp_nat_t_fixtures_are_staged_and_import_safely() {
    for (const auto fixture_name : kNatTEspFixturesNow) {
        CaptureSession session {};
        const auto& expectation = require_expectation(fixture_name);
        PFL_REQUIRE(expectation.is_nat_t_staged_fixture);
        PFL_REQUIRE(session.open_capture(fixture_path(fixture_name)));

        const auto storage = session.storage_summary();
        PFL_EXPECT(storage.total_packets_seen == expectation.expected_total_packets);
        PFL_EXPECT(storage.total_packets_seen == storage.recognized_packets + storage.unrecognized_packets);
    }
}

void run_future_esp_parser_expectation_tests() {
    // Enable this once ESP parser support is implemented.
    for (const auto& expectation : kEspFixtureExpectations) {
        if (expectation.expected_future_flow_count == 0U) {
            continue;
        }

        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path(expectation.file_name)));

        const auto storage = session.storage_summary();
        PFL_EXPECT(storage.total_packets_seen == expectation.expected_total_packets);
        (void)session;
    }
}

}  // namespace

void run_esp_pcap_fixture_tests() {
    expect_esp_fixture_files_exist();
    expect_esp_future_expectation_table_covers_all_fixtures();
    expect_esp_fixtures_import_without_crash();
    expect_esp_fixtures_have_expected_total_packet_records();
    expect_esp_direct_protocol50_fixtures_do_not_create_tcp_udp_flows_before_parser();
    expect_esp_truncated_fixtures_import_without_crash();
    expect_esp_nat_t_fixtures_are_staged_and_import_safely();

    if constexpr (kEnableEspParserExpectationTests) {
        run_future_esp_parser_expectation_tests();
    }
}

}  // namespace pfl::tests
