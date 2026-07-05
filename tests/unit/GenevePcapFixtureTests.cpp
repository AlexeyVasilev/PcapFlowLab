#include <filesystem>
#include <string>
#include <vector>

#include "TestSupport.h"
#include "app/session/CaptureSession.h"
#include "app/session/FlowRows.h"

namespace pfl::tests {

namespace {

std::filesystem::path fixture_path(const std::filesystem::path& relative_path) {
    return std::filesystem::path(__FILE__).parent_path().parent_path() / "data" / relative_path;
}

bool row_matches_tuple(
    const FlowRow& row,
    const FlowAddressFamily family,
    const std::string& protocol,
    const std::string& address_a,
    const std::uint16_t port_a,
    const std::string& address_b,
    const std::uint16_t port_b
) {
    if (row.family != family || row.protocol_text != protocol) {
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
    const std::string& protocol,
    const std::string& address_a,
    const std::uint16_t port_a,
    const std::string& address_b,
    const std::uint16_t port_b
) {
    for (const auto& row : rows) {
        if (row_matches_tuple(row, family, protocol, address_a, port_a, address_b, port_b)) {
            return &row;
        }
    }
    return nullptr;
}

void expect_inner_flow_present(
    const std::filesystem::path& relative_path,
    const FlowAddressFamily family,
    const std::string& protocol,
    const std::string& address_a,
    const std::uint16_t port_a,
    const std::string& address_b,
    const std::uint16_t port_b,
    const std::uint64_t expected_packet_count
) {
    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(fixture_path(relative_path)));

    const auto rows = session.list_flows();
    const auto* flow = find_flow_by_tuple(rows, family, protocol, address_a, port_a, address_b, port_b);
    PFL_EXPECT(flow != nullptr);
    if (flow == nullptr) {
        return;
    }

    PFL_EXPECT(flow->packet_count == expected_packet_count);
}

void expect_inner_flow_absent(
    const std::filesystem::path& relative_path,
    const FlowAddressFamily family,
    const std::string& protocol,
    const std::string& address_a,
    const std::uint16_t port_a,
    const std::string& address_b,
    const std::uint16_t port_b
) {
    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(fixture_path(relative_path)));

    const auto rows = session.list_flows();
    const auto* flow = find_flow_by_tuple(rows, family, protocol, address_a, port_a, address_b, port_b);
    PFL_EXPECT(flow == nullptr);
}

}  // namespace

void run_geneve_pcap_fixture_tests() {
    expect_inner_flow_present(
        "parsing/geneve/01_geneve_inner_ipv4_tcp.pcap",
        FlowAddressFamily::ipv4,
        "TCP",
        "10.50.0.10",
        49550U,
        "10.50.0.20",
        443U,
        1U
    );

    expect_inner_flow_present(
        "parsing/geneve/02_geneve_inner_ipv4_udp.pcap",
        FlowAddressFamily::ipv4,
        "UDP",
        "10.50.0.10",
        53650U,
        "10.50.0.20",
        443U,
        1U
    );

    expect_inner_flow_present(
        "parsing/geneve/03_geneve_inner_ipv6_tcp.pcap",
        FlowAddressFamily::ipv6,
        "TCP",
        "2001:0db8:0050:0000:0000:0000:0000:0010",
        49550U,
        "2001:0db8:0050:0000:0000:0000:0000:0020",
        443U,
        1U
    );

    expect_inner_flow_present(
        "parsing/geneve/04_geneve_inner_ipv6_udp.pcap",
        FlowAddressFamily::ipv6,
        "UDP",
        "2001:0db8:0050:0000:0000:0000:0000:0010",
        53650U,
        "2001:0db8:0050:0000:0000:0000:0000:0020",
        443U,
        1U
    );

    expect_inner_flow_present(
        "parsing/geneve/11_geneve_inner_ipv4_tcp_bidirectional.pcap",
        FlowAddressFamily::ipv4,
        "TCP",
        "10.50.0.10",
        49550U,
        "10.50.0.20",
        443U,
        2U
    );

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/geneve/12_geneve_same_outer_tuple_different_inner_flows.pcap")));
        const auto rows = session.list_flows();
        const auto* first_flow = find_flow_by_tuple(
            rows,
            FlowAddressFamily::ipv4,
            "TCP",
            "10.50.0.10",
            10011U,
            "10.50.0.20",
            443U
        );
        const auto* second_flow = find_flow_by_tuple(
            rows,
            FlowAddressFamily::ipv4,
            "TCP",
            "10.50.0.10",
            10012U,
            "10.50.0.20",
            443U
        );
        PFL_EXPECT(first_flow != nullptr);
        PFL_EXPECT(second_flow != nullptr);
        if (first_flow != nullptr) {
            PFL_EXPECT(first_flow->packet_count == 1U);
        }
        if (second_flow != nullptr) {
            PFL_EXPECT(second_flow->packet_count == 1U);
        }
    }

    expect_inner_flow_present(
        "parsing/geneve/13_geneve_inner_vlan_ipv4_tcp.pcap",
        FlowAddressFamily::ipv4,
        "TCP",
        "10.50.0.10",
        49550U,
        "10.50.0.20",
        443U,
        1U
    );

    expect_inner_flow_present(
        "parsing/geneve/14_geneve_outer_ipv6_inner_ipv4_tcp.pcap",
        FlowAddressFamily::ipv4,
        "TCP",
        "10.50.0.10",
        49550U,
        "10.50.0.20",
        443U,
        1U
    );

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/geneve/16_geneve_vni_boundary_values.pcap")));
        const auto rows = session.list_flows();
        const auto* first_flow = find_flow_by_tuple(
            rows,
            FlowAddressFamily::ipv4,
            "TCP",
            "10.50.0.10",
            49550U,
            "10.50.0.20",
            443U
        );
        const auto* second_flow = find_flow_by_tuple(
            rows,
            FlowAddressFamily::ipv4,
            "TCP",
            "10.50.0.11",
            10011U,
            "10.50.0.21",
            443U
        );
        PFL_EXPECT(first_flow != nullptr);
        PFL_EXPECT(second_flow != nullptr);
        // Known branch limitation: VNI remains presentation metadata, not flow identity.
    }

    // Geneve option length is encoded in 4-byte units. Fixture 17 carries one
    // deterministic 8-byte option block before the inner Ethernet payload.
    expect_inner_flow_present(
        "parsing/geneve/17_geneve_with_options_inner_ipv4_tcp.pcap",
        FlowAddressFamily::ipv4,
        "TCP",
        "10.50.0.10",
        49550U,
        "10.50.0.20",
        443U,
        1U
    );

    expect_inner_flow_absent(
        "parsing/geneve/05_geneve_truncated_base_header.pcap",
        FlowAddressFamily::ipv4,
        "TCP",
        "10.50.0.10",
        49550U,
        "10.50.0.20",
        443U
    );

    expect_inner_flow_absent(
        "parsing/geneve/06_geneve_invalid_version.pcap",
        FlowAddressFamily::ipv4,
        "UDP",
        "10.50.0.10",
        53650U,
        "10.50.0.20",
        443U
    );

    expect_inner_flow_absent(
        "parsing/geneve/07_geneve_options_length_truncated.pcap",
        FlowAddressFamily::ipv4,
        "TCP",
        "10.50.0.10",
        49550U,
        "10.50.0.20",
        443U
    );

    expect_inner_flow_absent(
        "parsing/geneve/08_geneve_truncated_inner_ethernet.pcap",
        FlowAddressFamily::ipv4,
        "TCP",
        "10.50.0.10",
        49550U,
        "10.50.0.20",
        443U
    );

    expect_inner_flow_absent(
        "parsing/geneve/09_geneve_truncated_inner_ipv4.pcap",
        FlowAddressFamily::ipv4,
        "TCP",
        "10.50.0.10",
        49550U,
        "10.50.0.20",
        443U
    );

    expect_inner_flow_absent(
        "parsing/geneve/10_geneve_unsupported_protocol_type.pcap",
        FlowAddressFamily::ipv4,
        "TCP",
        "10.50.0.10",
        49550U,
        "10.50.0.20",
        443U
    );

    expect_inner_flow_absent(
        "parsing/geneve/15_geneve_wrong_udp_port_valid_geneve_payload.pcap",
        FlowAddressFamily::ipv4,
        "TCP",
        "10.50.0.10",
        49550U,
        "10.50.0.20",
        443U
    );
}

}  // namespace pfl::tests
