#include <algorithm>
#include <array>
#include <cstdint>
#include <filesystem>
#include <set>
#include <string>
#include <string_view>

#include "TestSupport.h"
#include "app/session/CaptureSession.h"

namespace pfl::tests {

namespace {

struct AhFixtureExpectation {
    std::string_view file_name;
    std::uint64_t expected_total_packets;
};

constexpr std::array<AhFixtureExpectation, 20> kAhFixtureExpectations {{
    {"01_ipv4_ah_tcp.pcap", 1U},
    {"02_ipv4_ah_udp.pcap", 1U},
    {"03_ipv6_ah_tcp.pcap", 1U},
    {"04_ipv6_ah_udp.pcap", 1U},
    {"05_ipv4_ah_same_tuple_different_spi.pcap", 2U},
    {"06_ipv4_ah_same_spi_two_packets.pcap", 2U},
    {"07_ipv6_ah_same_tuple_different_spi.pcap", 2U},
    {"08_ipv4_ah_same_spi_different_sequence.pcap", 2U},
    {"09_outer_vlan_ipv4_ah_udp.pcap", 1U},
    {"10_outer_qinq_ipv4_ah_tcp.pcap", 1U},
    {"11_ipv6_hop_by_hop_ah_udp.pcap", 1U},
    {"12_ipv4_ah_inner_ipv4_udp.pcap", 1U},
    {"13_ipv4_ah_inner_ipv6_tcp.pcap", 1U},
    {"14_ipv6_ah_inner_ipv4_udp.pcap", 1U},
    {"15_ipv6_ah_inner_ipv6_tcp.pcap", 1U},
    {"16_ah_truncated_fixed_header.pcap", 1U},
    {"17_ah_invalid_payload_length_too_small.pcap", 1U},
    {"18_ah_payload_length_exceeds_packet.pcap", 1U},
    {"19_ah_truncated_icv.pcap", 1U},
    {"20_ah_unsupported_next_header.pcap", 1U},
}};

std::filesystem::path fixture_dir() {
    return std::filesystem::path(__FILE__).parent_path().parent_path() / "data" / "parsing" / "ah";
}

std::filesystem::path fixture_path(std::string_view file_name) {
    return fixture_dir() / std::filesystem::path(file_name);
}

std::set<std::string> expected_fixture_file_names() {
    std::set<std::string> names {};
    for (const auto& expectation : kAhFixtureExpectations) {
        names.emplace(expectation.file_name);
    }
    return names;
}

std::set<std::string> actual_fixture_file_names() {
    std::set<std::string> names {};
    if (!std::filesystem::exists(fixture_dir())) {
        return names;
    }

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

void expect_ah_expectation_filenames_are_unique() {
    PFL_EXPECT(expected_fixture_file_names().size() == kAhFixtureExpectations.size());
}

void expect_ah_fixture_files_exist() {
    for (const auto& expectation : kAhFixtureExpectations) {
        PFL_EXPECT(std::filesystem::exists(fixture_path(expectation.file_name)));
    }
}

void expect_ah_expectation_table_covers_all_fixtures() {
    PFL_EXPECT(expected_fixture_file_names() == actual_fixture_file_names());
}

void expect_ah_fixtures_import_without_crash() {
    for (const auto& expectation : kAhFixtureExpectations) {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path(expectation.file_name)));
    }
}

void expect_ah_fixtures_have_expected_total_packets_and_accounting() {
    for (const auto& expectation : kAhFixtureExpectations) {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path(expectation.file_name)));

        const auto storage = session.storage_summary();
        PFL_EXPECT(storage.total_packets_seen == expectation.expected_total_packets);
        PFL_EXPECT(storage.total_packets_seen == storage.recognized_packets + storage.unrecognized_packets);
    }
}

}  // namespace

void run_ah_pcap_fixture_tests() {
    expect_ah_expectation_filenames_are_unique();
    expect_ah_fixture_files_exist();
    expect_ah_expectation_table_covers_all_fixtures();
    expect_ah_fixtures_import_without_crash();
    expect_ah_fixtures_have_expected_total_packets_and_accounting();
}

}  // namespace pfl::tests
