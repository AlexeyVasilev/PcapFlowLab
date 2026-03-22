#include <vector>

#include "TestSupport.h"
#include "app/session/CaptureSession.h"
#include "core/io/CaptureFilePacketReader.h"
#include "core/io/FileByteSource.h"
#include "PcapTestUtils.h"

namespace pfl::tests {

void run_packet_access_tests() {
    const auto tcp_packet = make_ethernet_ipv4_tcp_packet(ipv4(10, 0, 0, 1), ipv4(10, 0, 0, 2), 12345, 443);
    const auto reverse_tcp_packet = make_ethernet_ipv4_tcp_packet(ipv4(10, 0, 0, 2), ipv4(10, 0, 0, 1), 443, 12345);
    const auto path = write_temp_pcap(
        "pfl_packet_access.pcap",
        make_classic_pcap({{100, tcp_packet}, {200, reverse_tcp_packet}})
    );

    {
        FileByteSource source {path};
        PFL_EXPECT(source.is_open());

        std::vector<std::uint8_t> prefix(4);
        PFL_EXPECT(source.read_at(0, std::span<std::uint8_t>(prefix)));
        PFL_EXPECT(prefix[0] == 0xd4);
        PFL_EXPECT(prefix[1] == 0xc3);
        PFL_EXPECT(prefix[2] == 0xb2);
        PFL_EXPECT(prefix[3] == 0xa1);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(path));
        const auto key = make_connection_key(FlowKeyV4 {
            .src_addr = ipv4(10, 0, 0, 1),
            .dst_addr = ipv4(10, 0, 0, 2),
            .src_port = 12345,
            .dst_port = 443,
            .protocol = ProtocolId::tcp,
        });
        const auto* connection = session.state().ipv4_connections.find(key);
        PFL_EXPECT(connection != nullptr);
        PFL_EXPECT(connection->has_flow_a);

        const auto packet_bytes = session.read_packet_data(connection->flow_a.packets.front());
        PFL_EXPECT(packet_bytes == tcp_packet);
        PFL_EXPECT(connection->flow_a.packets.front().byte_offset == 40);
    }

    {
        CaptureFilePacketReader reader {path};
        PFL_EXPECT(reader.is_open());

        const PacketRef invalid_packet {
            .packet_index = 999,
            .byte_offset = 1'000'000,
            .captured_length = 32,
            .original_length = 32,
        };
        const auto bytes = reader.read_packet_data(invalid_packet);
        PFL_EXPECT(bytes.empty());

        std::vector<std::uint8_t> out {};
        PFL_EXPECT(!reader.read_packet_data(invalid_packet, out));
    }
}

}  // namespace pfl::tests
