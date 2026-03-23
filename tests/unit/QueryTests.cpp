#include <variant>

#include "TestSupport.h"
#include "app/session/CaptureSession.h"
#include "PcapTestUtils.h"

namespace pfl::tests {

void run_query_tests() {
    const auto tcp_packet = make_ethernet_ipv4_tcp_packet(ipv4(10, 0, 0, 1), ipv4(10, 0, 0, 2), 12345, 443);
    const auto udp_packet = make_ethernet_ipv4_udp_packet(ipv4(10, 0, 0, 3), ipv4(10, 0, 0, 4), 5353, 53);
    const auto path = write_temp_pcap(
        "pfl_query_layer.pcap",
        make_classic_pcap({{100, tcp_packet}, {200, udp_packet}})
    );

    CaptureSession session {};
    PFL_EXPECT(session.open_capture(path));

    const auto rows = session.list_flows();
    PFL_EXPECT(rows.size() == 2);
    PFL_EXPECT(rows[0].index == 0);
    PFL_EXPECT(rows[1].index == 1);
    PFL_EXPECT(rows[0].family == FlowAddressFamily::ipv4);
    PFL_EXPECT(rows[1].family == FlowAddressFamily::ipv4);
    PFL_EXPECT(std::holds_alternative<ConnectionKeyV4>(rows[0].key));
    PFL_EXPECT(std::holds_alternative<ConnectionKeyV4>(rows[1].key));

    const auto& tcp_key = std::get<ConnectionKeyV4>(rows[0].key);
    PFL_EXPECT(tcp_key.protocol == ProtocolId::tcp);
    PFL_EXPECT(rows[0].packet_count == 1);
    PFL_EXPECT(rows[0].total_bytes == tcp_packet.size());
    PFL_EXPECT(tcp_key.first.addr == ipv4(10, 0, 0, 1));
    PFL_EXPECT(tcp_key.second.addr == ipv4(10, 0, 0, 2));

    const auto& udp_key = std::get<ConnectionKeyV4>(rows[1].key);
    PFL_EXPECT(udp_key.protocol == ProtocolId::udp);
    PFL_EXPECT(rows[1].packet_count == 1);
    PFL_EXPECT(rows[1].total_bytes == udp_packet.size());

    const auto first_flow_packets = session.flow_packets(0);
    PFL_EXPECT(first_flow_packets.has_value());
    PFL_EXPECT(first_flow_packets->size() == 1);
    PFL_EXPECT(first_flow_packets->front().packet_index == 0);
    PFL_EXPECT(first_flow_packets->front().captured_length == tcp_packet.size());

    const auto second_flow_packets = session.flow_packets(1);
    PFL_EXPECT(second_flow_packets.has_value());
    PFL_EXPECT(second_flow_packets->size() == 1);
    PFL_EXPECT(second_flow_packets->front().packet_index == 1);
    PFL_EXPECT(second_flow_packets->front().captured_length == udp_packet.size());
    PFL_EXPECT(second_flow_packets->front().byte_offset == 40 + tcp_packet.size() + 16);

    const auto second_flow_rows = session.list_flow_packets(1);
    PFL_EXPECT(second_flow_rows.size() == 1);
    PFL_EXPECT(second_flow_rows.front().packet_index == 1);
    PFL_EXPECT(second_flow_rows.front().captured_length == udp_packet.size());
    PFL_EXPECT(second_flow_rows.front().original_length == udp_packet.size());
    PFL_EXPECT(second_flow_rows.front().timestamp_text == "00:00:02.000200");

    PFL_EXPECT(!session.flow_packets(99).has_value());
    PFL_EXPECT(session.list_flow_packets(99).empty());

    const auto packet = session.find_packet(1);
    PFL_EXPECT(packet.has_value());
    PFL_EXPECT(packet->packet_index == 1);
    PFL_EXPECT(packet->captured_length == udp_packet.size());
    PFL_EXPECT(packet->byte_offset == 40 + tcp_packet.size() + 16);

    PFL_EXPECT(!session.find_packet(999).has_value());
}

}  // namespace pfl::tests


