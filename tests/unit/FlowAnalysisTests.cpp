#include <filesystem>
#include <vector>

#include "TestSupport.h"
#include "PcapTestUtils.h"
#include "app/session/CaptureSession.h"

namespace pfl::tests {

namespace {

std::vector<std::uint8_t> make_http_request_payload() {
    constexpr char request[] =
        "GET /analysis HTTP/1.1\r\n"
        "Host: analysis.example\r\n"
        "\r\n";
    return std::vector<std::uint8_t>(request, request + sizeof(request) - 1);
}

}  // namespace

void run_flow_analysis_tests() {
    const auto request_packet = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
        ipv4(10, 0, 0, 1), ipv4(10, 0, 0, 2), 40000, 80, make_http_request_payload(), 0x18
    );
    const auto response_packet = make_ethernet_ipv4_tcp_packet_with_payload(
        ipv4(10, 0, 0, 2), ipv4(10, 0, 0, 1), 80, 40000, 20, 0x18
    );
    const auto follow_up_packet = make_ethernet_ipv4_tcp_packet_with_payload(
        ipv4(10, 0, 0, 1), ipv4(10, 0, 0, 2), 40000, 80, 10, 0x18
    );
    const auto other_flow_packet = make_ethernet_ipv4_udp_packet(
        ipv4(10, 0, 0, 3), ipv4(10, 0, 0, 4), 53000, 53
    );

    const auto capture_path = write_temp_pcap(
        "pfl_flow_analysis_mvp.pcap",
        make_classic_pcap({
            {100, request_packet},
            {250, response_packet},
            {450, follow_up_packet},
            {600, other_flow_packet},
        })
    );

    CaptureSession session {};
    PFL_EXPECT(session.open_capture(capture_path));

    const auto rows = session.list_flows();
    PFL_EXPECT(rows.size() == 2);

    std::size_t http_flow_index = rows.size();
    for (const auto& row : rows) {
        if (row.protocol_hint == "http") {
            http_flow_index = row.index;
            break;
        }
    }
    PFL_EXPECT(http_flow_index < rows.size());

    const auto analysis = session.get_flow_analysis(http_flow_index);
    PFL_EXPECT(analysis.has_value());
    PFL_EXPECT(analysis->total_packets == 3U);
    PFL_EXPECT(analysis->total_bytes == static_cast<std::uint64_t>(request_packet.size() + response_packet.size() + follow_up_packet.size()));
    PFL_EXPECT(analysis->duration_us == 2000350U);
    PFL_EXPECT(analysis->packets_a_to_b == 2U);
    PFL_EXPECT(analysis->packets_b_to_a == 1U);
    PFL_EXPECT(analysis->bytes_a_to_b == static_cast<std::uint64_t>(request_packet.size() + follow_up_packet.size()));
    PFL_EXPECT(analysis->bytes_b_to_a == static_cast<std::uint64_t>(response_packet.size()));
    PFL_EXPECT(analysis->protocol_hint == "http");
    PFL_EXPECT(analysis->service_hint == "analysis.example");

    PFL_EXPECT(!session.get_flow_analysis(99U).has_value());
}

}  // namespace pfl::tests
