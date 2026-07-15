#include <algorithm>
#include <array>
#include <filesystem>
#include <set>
#include <string>
#include <string_view>

#include "TestSupport.h"
#include "app/session/CaptureSession.h"

namespace pfl::tests {

namespace {

struct IpEncapsulationFixtureExpectation {
    std::string_view file_name;
    std::uint64_t expected_total_packets;
};

constexpr std::array<IpEncapsulationFixtureExpectation, 20> kIpEncapsulationFixtureExpectations {{
    {"01_ipv4_in_ipv4_tcp.pcap", 1U},
    {"02_ipv4_in_ipv4_udp.pcap", 1U},
    {"03_ipv6_in_ipv4_tcp.pcap", 1U},
    {"04_ipv6_in_ipv4_udp.pcap", 1U},
    {"05_ipv4_in_ipv6_tcp.pcap", 1U},
    {"06_ipv4_in_ipv6_udp.pcap", 1U},
    {"07_ipv6_in_ipv6_tcp.pcap", 1U},
    {"08_ipv6_in_ipv6_udp.pcap", 1U},
    {"09_outer_vlan_ipv4_in_ipv4_udp.pcap", 1U},
    {"10_outer_qinq_ipv6_in_ipv4_tcp.pcap", 1U},
    {"11_outer_vlan_ipv4_in_ipv6_udp.pcap", 1U},
    {"12_nested_ipv4_in_ipv4_in_ipv4_udp.pcap", 1U},
    {"13_same_inner_tuple_different_outer_ipv4_tunnels.pcap", 2U},
    {"14_same_inner_tuple_same_outer_ipv4_two_packets.pcap", 2U},
    {"15_ipv4_in_ipv4_inner_icmp.pcap", 1U},
    {"16_ipv6_in_ipv4_inner_icmpv6.pcap", 1U},
    {"17_truncated_inner_ipv4_header.pcap", 1U},
    {"18_truncated_inner_ipv6_header.pcap", 1U},
    {"19_outer_ipv4_proto4_payload_too_short.pcap", 1U},
    {"20_ipv6_next41_payload_too_short.pcap", 1U},
}};

std::filesystem::path fixture_dir() {
    return std::filesystem::path(__FILE__).parent_path().parent_path() / "data" / "parsing" / "ip_encapsulation";
}

std::filesystem::path fixture_path(std::string_view file_name) {
    return fixture_dir() / std::filesystem::path(file_name);
}

std::set<std::string> expected_fixture_file_names() {
    std::set<std::string> names {};
    for (const auto& expectation : kIpEncapsulationFixtureExpectations) {
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

void expect_fixture_files_exist() {
    for (const auto& expectation : kIpEncapsulationFixtureExpectations) {
        PFL_EXPECT(std::filesystem::exists(fixture_path(expectation.file_name)));
    }
}

void expect_expectation_table_covers_fixture_directory() {
    PFL_REQUIRE(kIpEncapsulationFixtureExpectations.size() == 20U);

    const auto expected_names = expected_fixture_file_names();
    const auto actual_names = actual_fixture_file_names();

    PFL_EXPECT(expected_names.size() == kIpEncapsulationFixtureExpectations.size());
    PFL_EXPECT(expected_names == actual_names);
}

void expect_fixtures_import_without_crash() {
    for (const auto& expectation : kIpEncapsulationFixtureExpectations) {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path(expectation.file_name)));
    }
}

void expect_total_packet_accounting() {
    for (const auto& expectation : kIpEncapsulationFixtureExpectations) {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path(expectation.file_name)));

        const auto storage = session.storage_summary();
        PFL_EXPECT(storage.total_packets_seen == expectation.expected_total_packets);
        PFL_EXPECT(storage.recognized_packets + storage.unrecognized_packets == storage.total_packets_seen);
    }
}

}  // namespace

void run_ip_encapsulation_pcap_fixture_tests() {
    expect_fixture_files_exist();
    expect_expectation_table_covers_fixture_directory();
    expect_fixtures_import_without_crash();
    expect_total_packet_accounting();
}

}  // namespace pfl::tests
