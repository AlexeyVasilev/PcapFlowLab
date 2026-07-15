#include <algorithm>
#include <array>
#include <filesystem>
#include <set>
#include <string>
#include <string_view>

#include "TestSupport.h"
#include "app/session/CaptureSession.h"
#include "app/session/FlowRows.h"
#include "app/session/SessionFormatting.h"
#include "core/domain/ProtocolPath.h"

namespace pfl::tests {

namespace {

struct IpEncapsulationFixtureExpectation {
    std::string_view file_name;
    std::uint64_t expected_total_packets;
};

struct SupportedIpEncapsulationExpectation {
    std::string_view file_name;
    std::uint64_t expected_total_packets;
    std::uint64_t expected_flow_packets;
    FlowAddressFamily family;
    std::string_view protocol_text;
    std::string_view address_a;
    std::uint16_t port_a;
    std::string_view address_b;
    std::uint16_t port_b;
    std::string_view expected_protocol_path;
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

constexpr std::array<SupportedIpEncapsulationExpectation, 5> kSupportedIpEncapsulationFixturesNow {{
    {
        "01_ipv4_in_ipv4_tcp.pcap",
        1U,
        1U,
        FlowAddressFamily::ipv4,
        "TCP",
        "10.60.0.10",
        49160U,
        "10.60.0.20",
        443U,
        "EthernetII -> IPv4 -> IPv4 -> TCP",
    },
    {
        "02_ipv4_in_ipv4_udp.pcap",
        1U,
        1U,
        FlowAddressFamily::ipv4,
        "UDP",
        "10.60.0.10",
        53600U,
        "10.60.0.20",
        443U,
        "EthernetII -> IPv4 -> IPv4 -> UDP",
    },
    {
        "09_outer_vlan_ipv4_in_ipv4_udp.pcap",
        1U,
        1U,
        FlowAddressFamily::ipv4,
        "UDP",
        "10.60.0.10",
        53600U,
        "10.60.0.20",
        443U,
        "EthernetII -> VLAN(vid=660) -> IPv4 -> IPv4 -> UDP",
    },
    {
        "13_same_inner_tuple_different_outer_ipv4_tunnels.pcap",
        2U,
        2U,
        FlowAddressFamily::ipv4,
        "UDP",
        "10.60.0.10",
        53600U,
        "10.60.0.20",
        443U,
        "EthernetII -> IPv4 -> IPv4 -> UDP",
    },
    {
        "14_same_inner_tuple_same_outer_ipv4_two_packets.pcap",
        2U,
        2U,
        FlowAddressFamily::ipv4,
        "UDP",
        "10.60.0.10",
        53600U,
        "10.60.0.20",
        443U,
        "EthernetII -> IPv4 -> IPv4 -> UDP",
    },
}};

constexpr std::array<SupportedIpEncapsulationExpectation, 3> kSupportedIpv6InIpv4FixturesNow {{
    {
        "03_ipv6_in_ipv4_tcp.pcap",
        1U,
        1U,
        FlowAddressFamily::ipv6,
        "TCP",
        "2001:0db8:0061:0000:0000:0000:0000:0010",
        49160U,
        "2001:0db8:0061:0000:0000:0000:0000:0020",
        443U,
        "EthernetII -> IPv4 -> IPv6 -> TCP",
    },
    {
        "04_ipv6_in_ipv4_udp.pcap",
        1U,
        1U,
        FlowAddressFamily::ipv6,
        "UDP",
        "2001:0db8:0061:0000:0000:0000:0000:0010",
        53600U,
        "2001:0db8:0061:0000:0000:0000:0000:0020",
        443U,
        "EthernetII -> IPv4 -> IPv6 -> UDP",
    },
    {
        "10_outer_qinq_ipv6_in_ipv4_tcp.pcap",
        1U,
        1U,
        FlowAddressFamily::ipv6,
        "TCP",
        "2001:0db8:0061:0000:0000:0000:0000:0010",
        49160U,
        "2001:0db8:0061:0000:0000:0000:0000:0020",
        443U,
        "EthernetII -> VLAN(vid=661) -> VLAN(vid=662) -> IPv4 -> IPv6 -> TCP",
    },
}};

constexpr std::array<SupportedIpEncapsulationExpectation, 3> kSupportedIpv4InIpv6FixturesNow {{
    {
        "05_ipv4_in_ipv6_tcp.pcap",
        1U,
        1U,
        FlowAddressFamily::ipv4,
        "TCP",
        "10.60.0.10",
        49160U,
        "10.60.0.20",
        443U,
        "EthernetII -> IPv6 -> IPv4 -> TCP",
    },
    {
        "06_ipv4_in_ipv6_udp.pcap",
        1U,
        1U,
        FlowAddressFamily::ipv4,
        "UDP",
        "10.60.0.10",
        53600U,
        "10.60.0.20",
        443U,
        "EthernetII -> IPv6 -> IPv4 -> UDP",
    },
    {
        "11_outer_vlan_ipv4_in_ipv6_udp.pcap",
        1U,
        1U,
        FlowAddressFamily::ipv4,
        "UDP",
        "10.60.0.10",
        53600U,
        "10.60.0.20",
        443U,
        "EthernetII -> VLAN(vid=660) -> IPv6 -> IPv4 -> UDP",
    },
}};

constexpr std::array<SupportedIpEncapsulationExpectation, 2> kSupportedIpv6InIpv6FixturesNow {{
    {
        "07_ipv6_in_ipv6_tcp.pcap",
        1U,
        1U,
        FlowAddressFamily::ipv6,
        "TCP",
        "2001:0db8:0061:0000:0000:0000:0000:0010",
        49160U,
        "2001:0db8:0061:0000:0000:0000:0000:0020",
        443U,
        "EthernetII -> IPv6 -> IPv6 -> TCP",
    },
    {
        "08_ipv6_in_ipv6_udp.pcap",
        1U,
        1U,
        FlowAddressFamily::ipv6,
        "UDP",
        "2001:0db8:0061:0000:0000:0000:0000:0010",
        53600U,
        "2001:0db8:0061:0000:0000:0000:0000:0020",
        443U,
        "EthernetII -> IPv6 -> IPv6 -> UDP",
    },
}};

constexpr std::array<std::string_view, 4> kConservativeMalformedFixturesNow {{
    "17_truncated_inner_ipv4_header.pcap",
    "18_truncated_inner_ipv6_header.pcap",
    "19_outer_ipv4_proto4_payload_too_short.pcap",
    "20_ipv6_next41_payload_too_short.pcap",
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

bool row_matches_tuple(
    const FlowRow& row,
    const FlowAddressFamily family,
    const std::string_view protocol_text,
    const std::string_view address_a,
    const std::uint16_t port_a,
    const std::string_view address_b,
    const std::uint16_t port_b
) {
    if (row.family != family || row.protocol_text != protocol_text) {
        return false;
    }

    const bool forward_match =
        row.address_a == address_a &&
        row.port_a == port_a &&
        row.address_b == address_b &&
        row.port_b == port_b;
    const bool reverse_match =
        row.address_a == address_b &&
        row.port_a == port_b &&
        row.address_b == address_a &&
        row.port_b == port_a;
    return forward_match || reverse_match;
}

const FlowRow* find_flow_by_tuple(
    const std::vector<FlowRow>& rows,
    const FlowAddressFamily family,
    const std::string_view protocol_text,
    const std::string_view address_a,
    const std::uint16_t port_a,
    const std::string_view address_b,
    const std::uint16_t port_b
) {
    for (const auto& row : rows) {
        if (row_matches_tuple(row, family, protocol_text, address_a, port_a, address_b, port_b)) {
            return &row;
        }
    }
    return nullptr;
}

bool has_protocol_path(const CaptureSession& session, const FlowRow& row, const std::string_view expected_path) {
    if (row.protocol_path_id == kInvalidProtocolPathId) {
        return false;
    }

    const auto* path = session.state().protocol_path_registry.find(row.protocol_path_id);
    return path != nullptr && format_protocol_path(*path) == expected_path;
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

void expect_supported_ipv4_in_ipv4_tcp_udp_decode() {
    for (const auto& expectation : kSupportedIpEncapsulationFixturesNow) {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path(expectation.file_name)));

        const auto storage = session.storage_summary();
        PFL_EXPECT(storage.total_packets_seen == expectation.expected_total_packets);
        PFL_EXPECT(storage.recognized_packets == expectation.expected_total_packets);
        PFL_EXPECT(storage.unrecognized_packets == 0U);
        PFL_EXPECT(session.unrecognized_packet_count() == 0U);

        const auto rows = session.list_flows();
        PFL_EXPECT(rows.size() == 1U);

        const auto* flow = find_flow_by_tuple(
            rows,
            expectation.family,
            expectation.protocol_text,
            expectation.address_a,
            expectation.port_a,
            expectation.address_b,
            expectation.port_b
        );
        PFL_REQUIRE(flow != nullptr);
        PFL_EXPECT(flow->packet_count == expectation.expected_flow_packets);
        PFL_EXPECT(has_protocol_path(session, *flow, expectation.expected_protocol_path));
    }
}

void expect_supported_ipv6_in_ipv4_tcp_udp_decode() {
    for (const auto& expectation : kSupportedIpv6InIpv4FixturesNow) {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path(expectation.file_name)));

        const auto storage = session.storage_summary();
        PFL_EXPECT(storage.total_packets_seen == expectation.expected_total_packets);
        PFL_EXPECT(storage.recognized_packets == expectation.expected_total_packets);
        PFL_EXPECT(storage.unrecognized_packets == 0U);
        PFL_EXPECT(session.unrecognized_packet_count() == 0U);

        const auto rows = session.list_flows();
        PFL_EXPECT(rows.size() == 1U);

        const auto* flow = find_flow_by_tuple(
            rows,
            expectation.family,
            expectation.protocol_text,
            expectation.address_a,
            expectation.port_a,
            expectation.address_b,
            expectation.port_b
        );
        PFL_REQUIRE(flow != nullptr);
        PFL_EXPECT(flow->packet_count == expectation.expected_flow_packets);
        PFL_EXPECT(has_protocol_path(session, *flow, expectation.expected_protocol_path));
    }
}

void expect_supported_ipv4_in_ipv6_tcp_udp_decode() {
    for (const auto& expectation : kSupportedIpv4InIpv6FixturesNow) {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path(expectation.file_name)));

        const auto storage = session.storage_summary();
        PFL_EXPECT(storage.total_packets_seen == expectation.expected_total_packets);
        PFL_EXPECT(storage.recognized_packets == expectation.expected_total_packets);
        PFL_EXPECT(storage.unrecognized_packets == 0U);
        PFL_EXPECT(session.unrecognized_packet_count() == 0U);

        const auto rows = session.list_flows();
        PFL_EXPECT(rows.size() == 1U);

        const auto* flow = find_flow_by_tuple(
            rows,
            expectation.family,
            expectation.protocol_text,
            expectation.address_a,
            expectation.port_a,
            expectation.address_b,
            expectation.port_b
        );
        PFL_REQUIRE(flow != nullptr);
        PFL_EXPECT(flow->packet_count == expectation.expected_flow_packets);
        PFL_EXPECT(has_protocol_path(session, *flow, expectation.expected_protocol_path));
    }
}

void expect_supported_ipv6_in_ipv6_tcp_udp_decode() {
    for (const auto& expectation : kSupportedIpv6InIpv6FixturesNow) {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path(expectation.file_name)));

        const auto storage = session.storage_summary();
        PFL_EXPECT(storage.total_packets_seen == expectation.expected_total_packets);
        PFL_EXPECT(storage.recognized_packets == expectation.expected_total_packets);
        PFL_EXPECT(storage.unrecognized_packets == 0U);
        PFL_EXPECT(session.unrecognized_packet_count() == 0U);

        const auto rows = session.list_flows();
        PFL_EXPECT(rows.size() == 1U);

        const auto* flow = find_flow_by_tuple(
            rows,
            expectation.family,
            expectation.protocol_text,
            expectation.address_a,
            expectation.port_a,
            expectation.address_b,
            expectation.port_b
        );
        PFL_REQUIRE(flow != nullptr);
        PFL_EXPECT(flow->packet_count == expectation.expected_flow_packets);
        PFL_EXPECT(has_protocol_path(session, *flow, expectation.expected_protocol_path));
    }
}

void expect_malformed_inner_ip_remains_unrecognized() {
    for (const auto fixture_name : kConservativeMalformedFixturesNow) {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path(fixture_name)));

        const auto storage = session.storage_summary();
        PFL_EXPECT(storage.total_packets_seen == 1U);
        PFL_EXPECT(storage.recognized_packets == 0U);
        PFL_EXPECT(storage.unrecognized_packets == 1U);
        PFL_EXPECT(session.unrecognized_packet_count() == 1U);
        PFL_EXPECT(session.list_flows().empty());
    }
}

}  // namespace

void run_ip_encapsulation_pcap_fixture_tests() {
    expect_fixture_files_exist();
    expect_expectation_table_covers_fixture_directory();
    expect_fixtures_import_without_crash();
    expect_total_packet_accounting();
    expect_supported_ipv4_in_ipv4_tcp_udp_decode();
    expect_supported_ipv6_in_ipv4_tcp_udp_decode();
    expect_supported_ipv4_in_ipv6_tcp_udp_decode();
    expect_supported_ipv6_in_ipv6_tcp_udp_decode();
    expect_malformed_inner_ip_remains_unrecognized();
}

}  // namespace pfl::tests
