#include <string>
#include <vector>

#include "TestSupport.h"
#include "PcapTestUtils.h"
#include "app/session/CaptureSession.h"

namespace pfl::tests {

namespace {

std::string direction_for_packet(const std::vector<PacketRow>& packet_rows, const std::uint64_t packet_index) {
    for (const auto& row : packet_rows) {
        if (row.packet_index == packet_index) {
            return row.direction_text;
        }
    }

    PFL_EXPECT(false);
    return {};
}

}  // namespace

void run_stream_query_tests() {
    const auto forward_payload = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
        ipv4(10, 40, 0, 1), ipv4(10, 40, 0, 2), 51000, 443, std::vector<std::uint8_t> {'A', 'B', 'C'}, 0x18);
    const auto reverse_ack = make_ethernet_ipv4_tcp_packet(
        ipv4(10, 40, 0, 2), ipv4(10, 40, 0, 1), 443, 51000);
    const auto reverse_payload = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
        ipv4(10, 40, 0, 2), ipv4(10, 40, 0, 1), 443, 51000, std::vector<std::uint8_t> {'O', 'K'}, 0x18);

    const auto path = write_temp_pcap(
        "pfl_stream_query.pcap",
        make_classic_pcap({
            {100, forward_payload},
            {200, reverse_ack},
            {300, reverse_payload},
        })
    );

    CaptureSession session {};
    PFL_EXPECT(session.open_capture(path));

    const auto packet_rows = session.list_flow_packets(0);
    PFL_EXPECT(packet_rows.size() == 3);

    const auto stream_rows = session.list_flow_stream_items(0);
    PFL_EXPECT(stream_rows.size() == 2);
    PFL_EXPECT(stream_rows[0].stream_item_index == 1);
    PFL_EXPECT(stream_rows[1].stream_item_index == 2);
    PFL_EXPECT(stream_rows[0].packet_indices == std::vector<std::uint64_t> {0});
    PFL_EXPECT(stream_rows[1].packet_indices == std::vector<std::uint64_t> {2});
    PFL_EXPECT(stream_rows[0].direction_text == direction_for_packet(packet_rows, 0));
    PFL_EXPECT(stream_rows[1].direction_text == direction_for_packet(packet_rows, 2));
    PFL_EXPECT(stream_rows[0].byte_count == 3);
    PFL_EXPECT(stream_rows[1].byte_count == 2);
    PFL_EXPECT(stream_rows[0].packet_count == 1);
    PFL_EXPECT(stream_rows[1].packet_count == 1);
    PFL_EXPECT(stream_rows[0].label == "TCP Payload");
    PFL_EXPECT(stream_rows[1].label == "TCP Payload");

    const auto dns_payload = std::vector<std::uint8_t> {
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x03, 'a', 'p', 'i',
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x00,
        0x00, 0x01, 0x00, 0x01,
    };
    const auto dns_packet = make_ethernet_ipv4_udp_packet_with_bytes_payload(
        ipv4(10, 41, 0, 1), ipv4(10, 41, 0, 2), 53000, 53, dns_payload);
    const auto dns_path = write_temp_pcap(
        "pfl_stream_query_dns.pcap",
        make_classic_pcap({{100, dns_packet}})
    );

    CaptureSession dns_session {};
    PFL_EXPECT(dns_session.open_capture(dns_path));
    const auto dns_rows = dns_session.list_flow_stream_items(0);
    PFL_EXPECT(dns_rows.size() == 1);
    PFL_EXPECT(dns_rows[0].label == "UDP Payload");
    PFL_EXPECT(dns_rows[0].byte_count == dns_payload.size());
}

}  // namespace pfl::tests
