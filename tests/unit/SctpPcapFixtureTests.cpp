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

void expect_current_non_sctp_negative_behavior() {
    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(fixture_path("parsing/sctp/21_non_sctp_negative.pcap")));

    PFL_EXPECT(session.summary().packet_count == 1U);

    const auto rows = session.list_flows();
    PFL_EXPECT(rows.size() == 1U);

    const auto* udp_flow = find_flow_by_tuple(
        rows,
        FlowAddressFamily::ipv4,
        "UDP",
        "10.132.0.10",
        43000U,
        "10.132.0.20",
        43001U
    );
    PFL_REQUIRE(udp_flow != nullptr);
    PFL_EXPECT(udp_flow->packet_count == 1U);

    PFL_EXPECT(session.list_unrecognized_packets().empty());
}

#if defined(PFL_ENABLE_PENDING_SCTP_TESTS)

void expect_future_sctp_flow_present(
    const std::filesystem::path& relative_path,
    const FlowAddressFamily family,
    const std::string& address_a,
    const std::uint16_t port_a,
    const std::string& address_b,
    const std::uint16_t port_b,
    const std::uint64_t expected_packet_count
) {
    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(fixture_path(relative_path)));

    const auto rows = session.list_flows();
    const auto* flow = find_flow_by_tuple(rows, family, "SCTP", address_a, port_a, address_b, port_b);
    PFL_EXPECT(flow != nullptr);
    if (flow == nullptr) {
        return;
    }

    PFL_EXPECT(flow->packet_count == expected_packet_count);
}

void expect_future_sctp_flow_absent(
    const std::filesystem::path& relative_path,
    const FlowAddressFamily family,
    const std::string& address_a,
    const std::uint16_t port_a,
    const std::string& address_b,
    const std::uint16_t port_b
) {
    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(fixture_path(relative_path)));

    const auto rows = session.list_flows();
    const auto* flow = find_flow_by_tuple(rows, family, "SCTP", address_a, port_a, address_b, port_b);
    PFL_EXPECT(flow == nullptr);
}

void run_pending_future_sctp_fixture_expectations() {
    constexpr std::uint16_t kSctpSourcePort = 49132U;
    constexpr std::uint16_t kSctpDestinationPort = 36412U;

    const auto expect_ipv4_single_packet = [&](const std::filesystem::path& relative_path) {
        expect_future_sctp_flow_present(
            relative_path,
            FlowAddressFamily::ipv4,
            "10.132.0.10",
            kSctpSourcePort,
            "10.132.0.20",
            kSctpDestinationPort,
            1U
        );
    };

    expect_ipv4_single_packet("parsing/sctp/01_sctp_ipv4_data_s1ap.pcap");
    expect_future_sctp_flow_present(
        "parsing/sctp/02_sctp_ipv6_data_s1ap.pcap",
        FlowAddressFamily::ipv6,
        "2001:db8:132::10",
        kSctpSourcePort,
        "2001:db8:132::20",
        kSctpDestinationPort,
        1U
    );
    expect_ipv4_single_packet("parsing/sctp/03_sctp_ipv4_data_m3ua.pcap");
    expect_ipv4_single_packet("parsing/sctp/04_sctp_ipv4_data_dua.pcap");
    expect_ipv4_single_packet("parsing/sctp/05_sctp_ipv4_data_nbap.pcap");
    expect_ipv4_single_packet("parsing/sctp/06_sctp_ipv4_data_x2ap.pcap");
    expect_ipv4_single_packet("parsing/sctp/07_sctp_ipv4_data_diameter.pcap");
    expect_ipv4_single_packet("parsing/sctp/08_sctp_ipv4_data_ngap.pcap");
    expect_ipv4_single_packet("parsing/sctp/09_sctp_ipv4_data_unknown_ppid.pcap");
    expect_ipv4_single_packet("parsing/sctp/10_sctp_ipv4_init.pcap");
    expect_ipv4_single_packet("parsing/sctp/11_sctp_ipv4_sack.pcap");
    expect_future_sctp_flow_absent(
        "parsing/sctp/12_sctp_truncated_common_header.pcap",
        FlowAddressFamily::ipv4,
        "10.132.0.10",
        kSctpSourcePort,
        "10.132.0.20",
        kSctpDestinationPort
    );
    expect_ipv4_single_packet("parsing/sctp/13_sctp_truncated_data_chunk_header.pcap");
    expect_ipv4_single_packet("parsing/sctp/14_sctp_truncated_data_chunk_ppid.pcap");
    expect_future_sctp_flow_present(
        "parsing/sctp/15_sctp_ipv4_bidirectional_flow.pcap",
        FlowAddressFamily::ipv4,
        "10.132.0.10",
        kSctpSourcePort,
        "10.132.0.20",
        kSctpDestinationPort,
        2U
    );
    expect_ipv4_single_packet("parsing/sctp/16_sctp_vlan_ipv4_data_s1ap.pcap");
    expect_ipv4_single_packet("parsing/sctp/17_sctp_mpls_ipv4_data_s1ap.pcap");
    expect_ipv4_single_packet("parsing/sctp/18_sctp_vxlan_inner_ipv4_data_s1ap.pcap");
    expect_ipv4_single_packet("parsing/sctp/19_sctp_geneve_inner_ipv4_data_m3ua.pcap");
    expect_ipv4_single_packet("parsing/sctp/20_sctp_gtpu_inner_ipv4_data_s1ap.pcap");
    expect_ipv4_single_packet("parsing/sctp/22_sctp_ipv4_data_m2ap.pcap");
    expect_ipv4_single_packet("parsing/sctp/23_sctp_ipv4_data_m3ap.pcap");
    expect_ipv4_single_packet("parsing/sctp/24_sctp_ipv4_data_f1ap.pcap");
}

#endif

}  // namespace

void run_sctp_pcap_fixture_tests() {
    expect_current_non_sctp_negative_behavior();

#if defined(PFL_ENABLE_PENDING_SCTP_TESTS)
    // SCTP fixtures are committed ahead of transport/parser support.
    // Enable these expectations during SCTP implementation work only.
    run_pending_future_sctp_fixture_expectations();
#endif
}

}  // namespace pfl::tests
