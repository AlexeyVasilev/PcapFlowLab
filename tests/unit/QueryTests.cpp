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

    const auto ipv4_rows = session.list_ipv4_flows();
    PFL_EXPECT(ipv4_rows.size() == 2);
    PFL_EXPECT(session.list_ipv6_flows().empty());

    bool found_tcp = false;
    bool found_udp = false;
    for (const auto& row : ipv4_rows) {
        if (row.key.protocol == ProtocolId::tcp) {
            found_tcp = true;
            PFL_EXPECT(row.packet_count == 1);
            PFL_EXPECT(row.total_bytes == tcp_packet.size());
            PFL_EXPECT(row.key.first.addr == ipv4(10, 0, 0, 1));
            PFL_EXPECT(row.key.second.addr == ipv4(10, 0, 0, 2));
        }

        if (row.key.protocol == ProtocolId::udp) {
            found_udp = true;
            PFL_EXPECT(row.packet_count == 1);
            PFL_EXPECT(row.total_bytes == udp_packet.size());
        }
    }

    PFL_EXPECT(found_tcp);
    PFL_EXPECT(found_udp);

    const auto packet = session.find_packet(1);
    PFL_EXPECT(packet.has_value());
    PFL_EXPECT(packet->packet_index == 1);
    PFL_EXPECT(packet->captured_length == udp_packet.size());
    PFL_EXPECT(packet->byte_offset == 40 + tcp_packet.size() + 16);

    PFL_EXPECT(!session.find_packet(999).has_value());
}

}  // namespace pfl::tests
