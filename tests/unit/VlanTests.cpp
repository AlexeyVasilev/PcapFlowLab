#include <cstdint>

#include "TestSupport.h"
#include "app/session/CaptureSession.h"
#include "core/decode/PacketDecoder.h"
#include "core/domain/PacketRef.h"
#include "core/services/PacketDetailsService.h"
#include "PcapTestUtils.h"

namespace pfl::tests {

void run_vlan_tests() {
    {
        const auto packet = make_single_tagged_ethernet_ipv4_tcp_packet(
            ipv4(192, 168, 1, 10),
            ipv4(192, 168, 1, 20),
            12345,
            443,
            100
        );
        const auto path = write_temp_pcap("pfl_vlan_single_tcp.pcap", make_classic_pcap({{100, packet}}));

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(path));
        PFL_EXPECT(session.summary().packet_count == 1);
        PFL_EXPECT(session.summary().flow_count == 1);
        PFL_EXPECT(session.state().ipv4_connections.size() == 1);

        const auto key = make_connection_key(FlowKeyV4 {
            .src_addr = ipv4(192, 168, 1, 10),
            .dst_addr = ipv4(192, 168, 1, 20),
            .src_port = 12345,
            .dst_port = 443,
            .protocol = ProtocolId::tcp,
        });
        const auto* connection = session.state().ipv4_connections.find(key);
        PFL_EXPECT(connection != nullptr);
        PFL_EXPECT(connection->has_flow_a);
        PFL_EXPECT(connection->flow_a.packet_count == 1);

        const auto details = session.read_packet_details(connection->flow_a.packets.front());
        PFL_EXPECT(details.has_value());
        PFL_EXPECT(details->has_ethernet);
        PFL_EXPECT(details->ethernet.ether_type == 0x8100);
        PFL_EXPECT(details->has_vlan);
        PFL_EXPECT(details->vlan_tags.size() == 1);
        PFL_EXPECT(details->vlan_tags[0].tci == 100);
        PFL_EXPECT(details->vlan_tags[0].encapsulated_ether_type == 0x0800);
        PFL_EXPECT(details->has_ipv4);
        PFL_EXPECT(details->ipv4.src_addr == ipv4(192, 168, 1, 10));
        PFL_EXPECT(details->ipv4.dst_addr == ipv4(192, 168, 1, 20));
        PFL_EXPECT(details->has_tcp);
        PFL_EXPECT(details->tcp.src_port == 12345);
        PFL_EXPECT(details->tcp.dst_port == 443);
    }

    {
        const auto packet = make_double_tagged_ethernet_ipv4_udp_packet(
            ipv4(172, 16, 0, 1),
            ipv4(172, 16, 0, 2),
            5353,
            53,
            200,
            300
        );
        const auto path = write_temp_pcap("pfl_vlan_double_udp.pcap", make_classic_pcap({{100, packet}}));

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(path));
        PFL_EXPECT(session.summary().packet_count == 1);
        PFL_EXPECT(session.summary().flow_count == 1);
        PFL_EXPECT(session.state().ipv4_connections.size() == 1);

        const auto key = make_connection_key(FlowKeyV4 {
            .src_addr = ipv4(172, 16, 0, 1),
            .dst_addr = ipv4(172, 16, 0, 2),
            .src_port = 5353,
            .dst_port = 53,
            .protocol = ProtocolId::udp,
        });
        const auto* connection = session.state().ipv4_connections.find(key);
        PFL_EXPECT(connection != nullptr);
        PFL_EXPECT(connection->has_flow_a);

        const auto details = session.read_packet_details(connection->flow_a.packets.front());
        PFL_EXPECT(details.has_value());
        PFL_EXPECT(details->has_ethernet);
        PFL_EXPECT(details->ethernet.ether_type == 0x88A8);
        PFL_EXPECT(details->has_vlan);
        PFL_EXPECT(details->vlan_tags.size() == 2);
        PFL_EXPECT(details->vlan_tags[0].tci == 200);
        PFL_EXPECT(details->vlan_tags[0].encapsulated_ether_type == 0x8100);
        PFL_EXPECT(details->vlan_tags[1].tci == 300);
        PFL_EXPECT(details->vlan_tags[1].encapsulated_ether_type == 0x0800);
        PFL_EXPECT(details->has_ipv4);
        PFL_EXPECT(details->has_udp);
        PFL_EXPECT(details->udp.src_port == 5353);
        PFL_EXPECT(details->udp.dst_port == 53);
    }

    {
        const std::vector<std::uint8_t> malformed_vlan_packet {
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
            0x81, 0x00,
            0x00,
        };

        PacketDecoder decoder {};
        const RawPcapPacket raw_packet {
            .packet_index = 99,
            .ts_sec = 1,
            .ts_usec = 1,
            .captured_length = static_cast<std::uint32_t>(malformed_vlan_packet.size()),
            .original_length = static_cast<std::uint32_t>(malformed_vlan_packet.size()),
            .data_offset = 64,
            .bytes = malformed_vlan_packet,
        };
        const auto decoded = decoder.decode_ethernet(raw_packet);
        PFL_EXPECT(!decoded.has_value());

        PacketDetailsService service {};
        const PacketRef packet_ref {
            .packet_index = 99,
            .byte_offset = 64,
            .captured_length = static_cast<std::uint32_t>(malformed_vlan_packet.size()),
            .original_length = static_cast<std::uint32_t>(malformed_vlan_packet.size()),
        };
        PFL_EXPECT(!service.decode(malformed_vlan_packet, packet_ref).has_value());
    }
}

}  // namespace pfl::tests
