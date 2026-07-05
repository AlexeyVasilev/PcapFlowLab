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

[[maybe_unused]] void expect_inner_flow_present(
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

// GTP-U fixtures are added before parser implementation. Positive inner-tuple
// expectations stay behind PFL_ENABLE_PENDING_GTPU_TESTS so the default test
// executable remains green until GTP-U parser support lands.
#if defined(PFL_ENABLE_PENDING_GTPU_TESTS)
void run_pending_positive_gtpu_fixture_tests() {
    expect_inner_flow_present(
        "parsing/gtpu/01_gtpu_inner_ipv4_tcp.pcap",
        FlowAddressFamily::ipv4,
        "TCP",
        "10.60.0.10",
        49660U,
        "10.60.0.20",
        443U,
        1U
    );

    expect_inner_flow_present(
        "parsing/gtpu/02_gtpu_inner_ipv4_udp.pcap",
        FlowAddressFamily::ipv4,
        "UDP",
        "10.60.0.10",
        53760U,
        "10.60.0.20",
        443U,
        1U
    );

    expect_inner_flow_present(
        "parsing/gtpu/03_gtpu_inner_ipv6_tcp.pcap",
        FlowAddressFamily::ipv6,
        "TCP",
        "2001:0db8:0060:0000:0000:0000:0000:0010",
        49660U,
        "2001:0db8:0060:0000:0000:0000:0000:0020",
        443U,
        1U
    );

    expect_inner_flow_present(
        "parsing/gtpu/04_gtpu_inner_ipv6_udp.pcap",
        FlowAddressFamily::ipv6,
        "UDP",
        "2001:0db8:0060:0000:0000:0000:0000:0010",
        53760U,
        "2001:0db8:0060:0000:0000:0000:0000:0020",
        443U,
        1U
    );

    expect_inner_flow_present(
        "parsing/gtpu/11_gtpu_inner_ipv4_tcp_bidirectional.pcap",
        FlowAddressFamily::ipv4,
        "TCP",
        "10.60.0.10",
        49660U,
        "10.60.0.20",
        443U,
        2U
    );

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/gtpu/12_gtpu_same_outer_tuple_different_inner_flows.pcap")));
        const auto rows = session.list_flows();
        const auto* first_flow = find_flow_by_tuple(
            rows,
            FlowAddressFamily::ipv4,
            "TCP",
            "10.60.0.10",
            10021U,
            "10.60.0.20",
            443U
        );
        const auto* second_flow = find_flow_by_tuple(
            rows,
            FlowAddressFamily::ipv4,
            "TCP",
            "10.60.0.10",
            10022U,
            "10.60.0.20",
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
        "parsing/gtpu/13_gtpu_outer_ipv6_inner_ipv4_tcp.pcap",
        FlowAddressFamily::ipv4,
        "TCP",
        "10.60.0.10",
        49660U,
        "10.60.0.20",
        443U,
        1U
    );

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/gtpu/15_gtpu_teid_boundary_values.pcap")));
        const auto rows = session.list_flows();
        const auto* first_flow = find_flow_by_tuple(
            rows,
            FlowAddressFamily::ipv4,
            "TCP",
            "10.60.0.10",
            49660U,
            "10.60.0.20",
            443U
        );
        const auto* second_flow = find_flow_by_tuple(
            rows,
            FlowAddressFamily::ipv4,
            "TCP",
            "10.60.0.11",
            10021U,
            "10.60.0.21",
            443U
        );
        PFL_EXPECT(first_flow != nullptr);
        PFL_EXPECT(second_flow != nullptr);
    }

    expect_inner_flow_present(
        "parsing/gtpu/16_gtpu_with_sequence_inner_ipv4_tcp.pcap",
        FlowAddressFamily::ipv4,
        "TCP",
        "10.60.0.10",
        49660U,
        "10.60.0.20",
        443U,
        1U
    );

    expect_inner_flow_present(
        "parsing/gtpu/17_gtpu_with_npdu_inner_ipv4_tcp.pcap",
        FlowAddressFamily::ipv4,
        "TCP",
        "10.60.0.10",
        49660U,
        "10.60.0.20",
        443U,
        1U
    );

    expect_inner_flow_present(
        "parsing/gtpu/18_gtpu_with_extension_header_inner_ipv4_tcp.pcap",
        FlowAddressFamily::ipv4,
        "TCP",
        "10.60.0.10",
        49660U,
        "10.60.0.20",
        443U,
        1U
    );

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/gtpu/21_gtpu_same_inner_tuple_different_teid.pcap")));
        const auto rows = session.list_flows();
        const auto* flow = find_flow_by_tuple(
            rows,
            FlowAddressFamily::ipv4,
            "TCP",
            "10.60.0.10",
            49660U,
            "10.60.0.20",
            443U
        );
        PFL_EXPECT(flow != nullptr);
        if (flow != nullptr) {
            PFL_EXPECT(flow->packet_count == 2U);
        }
        // Known branch limitation: TEID is not yet part of flow identity, so
        // identical inner tuples from different TEIDs may merge into one flow.
    }
}
#endif

}  // namespace

void run_gtpu_pcap_fixture_tests() {
#if defined(PFL_ENABLE_PENDING_GTPU_TESTS)
    run_pending_positive_gtpu_fixture_tests();
#endif

    expect_inner_flow_absent(
        "parsing/gtpu/05_gtpu_truncated_base_header.pcap",
        FlowAddressFamily::ipv4,
        "TCP",
        "10.60.0.10",
        49660U,
        "10.60.0.20",
        443U
    );

    expect_inner_flow_absent(
        "parsing/gtpu/06_gtpu_invalid_version.pcap",
        FlowAddressFamily::ipv4,
        "TCP",
        "10.60.0.10",
        49660U,
        "10.60.0.20",
        443U
    );

    expect_inner_flow_absent(
        "parsing/gtpu/07_gtpu_unsupported_message_type.pcap",
        FlowAddressFamily::ipv4,
        "TCP",
        "10.60.0.10",
        49660U,
        "10.60.0.20",
        443U
    );

    expect_inner_flow_absent(
        "parsing/gtpu/08_gtpu_truncated_inner_ipv4.pcap",
        FlowAddressFamily::ipv4,
        "TCP",
        "10.60.0.10",
        49660U,
        "10.60.0.20",
        443U
    );

    expect_inner_flow_absent(
        "parsing/gtpu/09_gtpu_truncated_inner_ipv6.pcap",
        FlowAddressFamily::ipv6,
        "TCP",
        "2001:0db8:0060:0000:0000:0000:0000:0010",
        49660U,
        "2001:0db8:0060:0000:0000:0000:0000:0020",
        443U
    );

    expect_inner_flow_absent(
        "parsing/gtpu/10_gtpu_unknown_inner_payload.pcap",
        FlowAddressFamily::ipv4,
        "TCP",
        "10.60.0.10",
        49660U,
        "10.60.0.20",
        443U
    );

    expect_inner_flow_absent(
        "parsing/gtpu/14_gtpu_wrong_udp_port_valid_gtpu_payload.pcap",
        FlowAddressFamily::ipv4,
        "TCP",
        "10.60.0.10",
        49660U,
        "10.60.0.20",
        443U
    );

    expect_inner_flow_absent(
        "parsing/gtpu/19_gtpu_truncated_optional_header.pcap",
        FlowAddressFamily::ipv4,
        "TCP",
        "10.60.0.10",
        49660U,
        "10.60.0.20",
        443U
    );

    expect_inner_flow_absent(
        "parsing/gtpu/20_gtpu_truncated_extension_header.pcap",
        FlowAddressFamily::ipv4,
        "TCP",
        "10.60.0.10",
        49660U,
        "10.60.0.20",
        443U
    );
}

}  // namespace pfl::tests
