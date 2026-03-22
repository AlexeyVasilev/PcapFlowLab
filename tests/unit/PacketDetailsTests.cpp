#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "TestSupport.h"
#include "app/session/CaptureSession.h"
#include "core/domain/PacketDetails.h"
#include "core/domain/PacketRef.h"
#include "core/services/HexDumpService.h"
#include "core/services/PacketDetailsService.h"
#include "PcapTestUtils.h"

namespace pfl::tests {

void run_packet_details_tests() {
    const auto tcp_packet = make_ethernet_ipv4_tcp_packet(ipv4(10, 0, 0, 1), ipv4(10, 0, 0, 2), 12345, 443);
    const auto udp_packet = make_ethernet_ipv4_udp_packet(ipv4(10, 0, 0, 3), ipv4(10, 0, 0, 4), 5353, 53);

    {
        PacketDetailsService service {};
        const PacketRef packet_ref {
            .packet_index = 7,
            .byte_offset = 40,
            .captured_length = static_cast<std::uint32_t>(tcp_packet.size()),
            .original_length = static_cast<std::uint32_t>(tcp_packet.size()),
        };

        const auto details = service.decode(tcp_packet, packet_ref);
        PFL_EXPECT(details.has_value());
        PFL_EXPECT(details->has_ethernet);
        PFL_EXPECT(details->ethernet.ether_type == 0x0800);
        PFL_EXPECT(details->has_ipv4);
        PFL_EXPECT(details->ipv4.src_addr == ipv4(10, 0, 0, 1));
        PFL_EXPECT(details->ipv4.dst_addr == ipv4(10, 0, 0, 2));
        PFL_EXPECT(details->ipv4.protocol == 6);
        PFL_EXPECT(details->has_tcp);
        PFL_EXPECT(details->tcp.src_port == 12345);
        PFL_EXPECT(details->tcp.dst_port == 443);
        PFL_EXPECT(details->tcp.flags == 0x10);
    }

    {
        PacketDetailsService service {};
        const PacketRef packet_ref {
            .packet_index = 8,
            .byte_offset = 80,
            .captured_length = static_cast<std::uint32_t>(udp_packet.size()),
            .original_length = static_cast<std::uint32_t>(udp_packet.size()),
        };

        const auto details = service.decode(udp_packet, packet_ref);
        PFL_EXPECT(details.has_value());
        PFL_EXPECT(details->has_ipv4);
        PFL_EXPECT(details->ipv4.protocol == 17);
        PFL_EXPECT(details->has_udp);
        PFL_EXPECT(details->udp.src_port == 5353);
        PFL_EXPECT(details->udp.dst_port == 53);
        PFL_EXPECT(details->udp.length == 8);
    }

    {
        const auto path = write_temp_pcap("pfl_packet_details_session.pcap", make_classic_pcap({{100, tcp_packet}}));
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(path));
        PFL_EXPECT(session.state().ipv4_connections.size() == 1);

        const auto key = make_connection_key(FlowKeyV4 {
            .src_addr = ipv4(10, 0, 0, 1),
            .dst_addr = ipv4(10, 0, 0, 2),
            .src_port = 12345,
            .dst_port = 443,
            .protocol = ProtocolId::tcp,
        });
        const auto* connection = session.state().ipv4_connections.find(key);
        PFL_EXPECT(connection != nullptr);

        const auto details = session.read_packet_details(connection->flow_a.packets.front());
        PFL_EXPECT(details.has_value());
        PFL_EXPECT(details->packet_index == 0);
        PFL_EXPECT(details->has_tcp);
        PFL_EXPECT(details->tcp.dst_port == 443);

        const auto hex_dump = session.read_packet_hex_dump(connection->flow_a.packets.front());
        PFL_EXPECT(!hex_dump.empty());
        PFL_EXPECT(hex_dump.find("00000000") != std::string::npos);
    }

    {
        HexDumpService service {};
        const std::vector<std::uint8_t> bytes {
            0x00, 0x01, 0x41, 0x42, 0x7f, 0x20, 0x10, 0x11,
            0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
            0x30, 0x31, 0x32, 0x33,
        };

        const auto dump = service.format(bytes);
        PFL_EXPECT(dump.find("00000000") != std::string::npos);
        PFL_EXPECT(dump.find("00000010") != std::string::npos);
        PFL_EXPECT(dump.find("00 01 41 42 7f 20") != std::string::npos);
        PFL_EXPECT(dump.find("|..AB.") != std::string::npos);
    }

    {
        PacketDetailsService service {};
        const std::vector<std::uint8_t> short_packet {0x00, 0x01, 0x02};
        const PacketRef packet_ref {
            .packet_index = 9,
            .byte_offset = 0,
            .captured_length = 3,
            .original_length = 3,
        };

        PFL_EXPECT(!service.decode(short_packet, packet_ref).has_value());

        HexDumpService hex_dump {};
        PFL_EXPECT(hex_dump.format(std::span<const std::uint8_t> {}).empty());
    }
}

}  // namespace pfl::tests
