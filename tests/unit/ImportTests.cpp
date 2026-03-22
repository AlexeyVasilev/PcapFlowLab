#include <array>
#include <cstdint>

#include "TestSupport.h"
#include "app/session/CaptureSession.h"
#include "core/decode/PacketDecoder.h"
#include "core/domain/CaptureState.h"
#include "core/io/PcapReader.h"
#include "core/services/CaptureImporter.h"
#include "PcapTestUtils.h"

namespace pfl::tests {

void run_import_tests() {
    const auto tcp_packet = make_ethernet_ipv4_tcp_packet(ipv4(10, 0, 0, 1), ipv4(10, 0, 0, 2), 12345, 443);
    const auto udp_packet = make_ethernet_ipv4_udp_packet(ipv4(10, 0, 0, 3), ipv4(10, 0, 0, 4), 5353, 53);

    {
        const auto path = write_temp_pcap("pfl_reader_basic.pcap", make_classic_pcap({{100, tcp_packet}}));
        PcapReader reader {};
        PFL_EXPECT(reader.open(path));
        PFL_EXPECT(reader.data_link_type() == 1);

        const auto packet = reader.read_next();
        PFL_EXPECT(packet.has_value());
        PFL_EXPECT(packet->packet_index == 0);
        PFL_EXPECT(packet->captured_length == tcp_packet.size());
        PFL_EXPECT(packet->original_length == tcp_packet.size());
        PFL_EXPECT(packet->data_offset == 40);
        PFL_EXPECT(packet->bytes == tcp_packet);
        PFL_EXPECT(!reader.read_next().has_value());
    }

    {
        PacketDecoder decoder {};
        const RawPcapPacket raw_packet {
            .packet_index = 3,
            .ts_sec = 1,
            .ts_usec = 10,
            .captured_length = static_cast<std::uint32_t>(tcp_packet.size()),
            .original_length = static_cast<std::uint32_t>(tcp_packet.size()),
            .data_offset = 128,
            .bytes = tcp_packet,
        };

        const auto decoded = decoder.decode_ethernet(raw_packet);
        PFL_EXPECT(decoded.ipv4.has_value());
        PFL_EXPECT(!decoded.ipv6.has_value());
        PFL_EXPECT(decoded.ipv4->flow_key.src_addr == ipv4(10, 0, 0, 1));
        PFL_EXPECT(decoded.ipv4->flow_key.dst_addr == ipv4(10, 0, 0, 2));
        PFL_EXPECT(decoded.ipv4->flow_key.src_port == 12345);
        PFL_EXPECT(decoded.ipv4->flow_key.dst_port == 443);
        PFL_EXPECT(decoded.ipv4->flow_key.protocol == ProtocolId::tcp);
        PFL_EXPECT(decoded.ipv4->packet_ref.packet_index == 3);
        PFL_EXPECT(decoded.ipv4->packet_ref.byte_offset == 128);
    }

    {
        PacketDecoder decoder {};
        const RawPcapPacket raw_packet {
            .packet_index = 4,
            .ts_sec = 1,
            .ts_usec = 11,
            .captured_length = static_cast<std::uint32_t>(udp_packet.size()),
            .original_length = static_cast<std::uint32_t>(udp_packet.size()),
            .data_offset = 256,
            .bytes = udp_packet,
        };

        const auto decoded = decoder.decode_ethernet(raw_packet);
        PFL_EXPECT(decoded.ipv4.has_value());
        PFL_EXPECT(decoded.ipv4->flow_key.src_addr == ipv4(10, 0, 0, 3));
        PFL_EXPECT(decoded.ipv4->flow_key.dst_addr == ipv4(10, 0, 0, 4));
        PFL_EXPECT(decoded.ipv4->flow_key.src_port == 5353);
        PFL_EXPECT(decoded.ipv4->flow_key.dst_port == 53);
        PFL_EXPECT(decoded.ipv4->flow_key.protocol == ProtocolId::udp);
    }

    {
        const auto path = write_temp_pcap(
            "pfl_import_counts.pcap",
            make_classic_pcap({{100, tcp_packet}, {200, udp_packet}})
        );

        CaptureState state {};
        CaptureImporter importer {};
        PFL_EXPECT(importer.import_pcap(path, state));
        PFL_EXPECT(state.summary.packet_count == 2);
        PFL_EXPECT(state.summary.flow_count == 2);
        PFL_EXPECT(state.ipv4_connections.size() == 2);
    }

    {
        const auto reverse_tcp_packet = make_ethernet_ipv4_tcp_packet(ipv4(10, 0, 0, 2), ipv4(10, 0, 0, 1), 443, 12345);
        const auto path = write_temp_pcap(
            "pfl_import_reverse_flow.pcap",
            make_classic_pcap({{100, tcp_packet}, {200, reverse_tcp_packet}})
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(path));
        PFL_EXPECT(session.summary().packet_count == 2);
        PFL_EXPECT(session.summary().flow_count == 1);
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
        PFL_EXPECT(connection->has_flow_a);
        PFL_EXPECT(connection->has_flow_b);
        PFL_EXPECT(connection->flow_a.packet_count == 1);
        PFL_EXPECT(connection->flow_b.packet_count == 1);
    }
}

}  // namespace pfl::tests
