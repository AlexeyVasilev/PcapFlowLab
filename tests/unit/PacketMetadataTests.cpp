#include <cstdint>
#include <filesystem>

#include "TestSupport.h"
#include "app/session/CaptureSession.h"
#include "core/decode/PacketDecoder.h"
#include "core/index/ImportCheckpointReader.h"
#include "core/services/ChunkedCaptureImporter.h"
#include "PcapTestUtils.h"

namespace pfl::tests {

void run_packet_metadata_tests() {
    const auto tcp_packet = make_ethernet_ipv4_tcp_packet_with_payload(
        ipv4(10, 0, 0, 1),
        ipv4(10, 0, 0, 2),
        12345,
        443,
        5,
        0x12
    );
    const auto udp_packet = make_ethernet_ipv4_udp_packet_with_payload(
        ipv4(10, 0, 0, 3),
        ipv4(10, 0, 0, 4),
        5353,
        53,
        7
    );

    {
        const auto path = write_temp_pcap(
            "pfl_packet_metadata_tcp_udp.pcap",
            make_classic_pcap({{100, tcp_packet}, {200, udp_packet}})
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(path));

        const auto tcp_ref = session.find_packet(0);
        PFL_EXPECT(tcp_ref.has_value());
        PFL_EXPECT(tcp_ref->payload_length == 5);
        PFL_EXPECT(tcp_ref->tcp_flags == 0x12);

        const auto udp_ref = session.find_packet(1);
        PFL_EXPECT(udp_ref.has_value());
        PFL_EXPECT(udp_ref->payload_length == 7);
        PFL_EXPECT(udp_ref->tcp_flags == 0);

        const auto rows = session.list_flow_packets(0);
        PFL_EXPECT(!rows.empty());
        PFL_EXPECT(rows.front().payload_length == 5);
        PFL_EXPECT(rows.front().tcp_flags_text == "ACK|SYN");
    }

    {
        const auto source_path = write_temp_pcap(
            "pfl_packet_metadata_roundtrip.pcap",
            make_classic_pcap({{100, tcp_packet}, {200, udp_packet}})
        );
        const auto index_path = std::filesystem::temp_directory_path() / "pfl_packet_metadata.idx";
        std::filesystem::remove(index_path);

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(source_path));
        PFL_EXPECT(session.save_index(index_path));

        CaptureSession loaded_session {};
        PFL_EXPECT(loaded_session.load_index(index_path));

        const auto tcp_ref = loaded_session.find_packet(0);
        PFL_EXPECT(tcp_ref.has_value());
        PFL_EXPECT(tcp_ref->payload_length == 5);
        PFL_EXPECT(tcp_ref->tcp_flags == 0x12);

        const auto udp_ref = loaded_session.find_packet(1);
        PFL_EXPECT(udp_ref.has_value());
        PFL_EXPECT(udp_ref->payload_length == 7);
        PFL_EXPECT(udp_ref->tcp_flags == 0);
    }

    {
        const auto source_path = write_temp_pcap(
            "pfl_packet_metadata_checkpoint.pcap",
            make_classic_pcap({{100, tcp_packet}, {200, udp_packet}})
        );
        const auto checkpoint_path = std::filesystem::temp_directory_path() / "pfl_packet_metadata.ckp";
        std::filesystem::remove(checkpoint_path);

        ChunkedCaptureImporter importer {};
        PFL_EXPECT(importer.import_chunk(source_path, checkpoint_path, 1) == ChunkedImportStatus::checkpoint_saved);

        ImportCheckpointReader reader {};
        ImportCheckpoint checkpoint {};
        PFL_EXPECT(reader.read(checkpoint_path, checkpoint));
        PFL_EXPECT(checkpoint.state.summary.packet_count == 1);
        PFL_EXPECT(checkpoint.state.ipv4_connections.size() == 1);

        const auto* connection = checkpoint.state.ipv4_connections.find(make_connection_key(FlowKeyV4 {
            .src_addr = ipv4(10, 0, 0, 1),
            .dst_addr = ipv4(10, 0, 0, 2),
            .src_port = 12345,
            .dst_port = 443,
            .protocol = ProtocolId::tcp,
        }));
        PFL_EXPECT(connection != nullptr);
        PFL_EXPECT(connection->has_flow_a);
        PFL_EXPECT(!connection->flow_a.packets.empty());
        PFL_EXPECT(connection->flow_a.packets.front().payload_length == 5);
        PFL_EXPECT(connection->flow_a.packets.front().tcp_flags == 0x12);
    }

    {
        PacketDecoder decoder {};

        auto malformed_tcp = tcp_packet;
        malformed_tcp[16] = 0x00;
        malformed_tcp[17] = 0x10;

        const RawPcapPacket raw_tcp {
            .packet_index = 0,
            .ts_sec = 1,
            .ts_usec = 0,
            .captured_length = static_cast<std::uint32_t>(malformed_tcp.size()),
            .original_length = static_cast<std::uint32_t>(malformed_tcp.size()),
            .data_offset = 40,
            .bytes = malformed_tcp,
        };
        PFL_EXPECT(!decoder.decode_ethernet(raw_tcp).has_value());

        auto malformed_udp = udp_packet;
        malformed_udp[38] = 0x00;
        malformed_udp[39] = 0x06;

        const RawPcapPacket raw_udp {
            .packet_index = 1,
            .ts_sec = 1,
            .ts_usec = 0,
            .captured_length = static_cast<std::uint32_t>(malformed_udp.size()),
            .original_length = static_cast<std::uint32_t>(malformed_udp.size()),
            .data_offset = 80,
            .bytes = malformed_udp,
        };
        PFL_EXPECT(!decoder.decode_ethernet(raw_udp).has_value());
    }
}

}  // namespace pfl::tests
