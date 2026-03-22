#include <filesystem>
#include <vector>

#include "TestSupport.h"
#include "app/session/CaptureSession.h"
#include "core/io/PcapReader.h"
#include "core/io/PcapWriter.h"
#include "PcapTestUtils.h"

namespace pfl::tests {

namespace {

std::vector<RawPcapPacket> read_all_packets(const std::filesystem::path& path) {
    PcapReader reader {};
    PFL_EXPECT(reader.open(path));

    std::vector<RawPcapPacket> packets {};
    while (const auto packet = reader.read_next()) {
        packets.push_back(*packet);
    }

    return packets;
}

}  // namespace

void run_export_tests() {
    const auto tcp_packet = make_ethernet_ipv4_tcp_packet(ipv4(10, 0, 0, 1), ipv4(10, 0, 0, 2), 12345, 443);
    const auto udp_packet = make_ethernet_ipv4_udp_packet(ipv4(10, 0, 0, 3), ipv4(10, 0, 0, 4), 5353, 53);

    {
        const auto path = std::filesystem::temp_directory_path() / "pfl_writer_basic.pcap";
        PcapWriter writer {};
        PFL_EXPECT(writer.open(path));
        PFL_EXPECT(writer.is_open());

        const PacketRef first_packet {
            .packet_index = 0,
            .captured_length = static_cast<std::uint32_t>(tcp_packet.size()),
            .original_length = static_cast<std::uint32_t>(tcp_packet.size()),
            .ts_sec = 10,
            .ts_usec = 20,
        };
        const PacketRef second_packet {
            .packet_index = 1,
            .captured_length = static_cast<std::uint32_t>(udp_packet.size()),
            .original_length = static_cast<std::uint32_t>(udp_packet.size()),
            .ts_sec = 11,
            .ts_usec = 21,
        };

        PFL_EXPECT(writer.write_packet(first_packet, tcp_packet));
        PFL_EXPECT(writer.write_packet(second_packet, udp_packet));
        writer.close();

        const auto packets = read_all_packets(path);
        PFL_EXPECT(packets.size() == 2);
        PFL_EXPECT(packets[0].ts_sec == 10);
        PFL_EXPECT(packets[0].ts_usec == 20);
        PFL_EXPECT(packets[0].bytes == tcp_packet);
        PFL_EXPECT(packets[1].ts_sec == 11);
        PFL_EXPECT(packets[1].ts_usec == 21);
        PFL_EXPECT(packets[1].bytes == udp_packet);
    }

    {
        const auto forward_packet = make_ethernet_ipv4_tcp_packet(ipv4(192, 168, 0, 1), ipv4(192, 168, 0, 2), 12345, 443);
        const auto reverse_packet = make_ethernet_ipv4_tcp_packet(ipv4(192, 168, 0, 2), ipv4(192, 168, 0, 1), 443, 12345);
        const auto source_path = write_temp_pcap(
            "pfl_export_roundtrip_source.pcap",
            make_classic_pcap({{100, forward_packet}, {200, reverse_packet}, {300, forward_packet}, {400, reverse_packet}})
        );
        const auto output_path = std::filesystem::temp_directory_path() / "pfl_export_roundtrip_output.pcap";
        std::filesystem::remove(output_path);

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(source_path));
        const auto rows = session.list_flows();
        PFL_EXPECT(rows.size() == 1);
        PFL_EXPECT(session.export_flow_to_pcap(0, output_path));

        CaptureSession exported_session {};
        PFL_EXPECT(exported_session.open_capture(output_path));
        PFL_EXPECT(exported_session.summary().packet_count == 4);
        PFL_EXPECT(exported_session.summary().flow_count == 1);
        PFL_EXPECT(exported_session.list_flows().size() == 1);

        const auto exported_packets = read_all_packets(output_path);
        PFL_EXPECT(exported_packets.size() == 4);
        PFL_EXPECT(exported_packets[0].bytes == forward_packet);
        PFL_EXPECT(exported_packets[1].bytes == reverse_packet);
        PFL_EXPECT(exported_packets[2].bytes == forward_packet);
        PFL_EXPECT(exported_packets[3].bytes == reverse_packet);
        PFL_EXPECT(exported_packets[0].ts_usec == 100);
        PFL_EXPECT(exported_packets[1].ts_usec == 200);
        PFL_EXPECT(exported_packets[2].ts_usec == 300);
        PFL_EXPECT(exported_packets[3].ts_usec == 400);
    }

    {
        const auto source_path = write_temp_pcap(
            "pfl_export_invalid_source.pcap",
            make_classic_pcap({{100, tcp_packet}})
        );
        const auto output_path = std::filesystem::temp_directory_path() / "pfl_export_invalid_output.pcap";
        std::filesystem::remove(output_path);

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(source_path));
        PFL_EXPECT(!session.export_flow_to_pcap(99, output_path));
        PFL_EXPECT(!std::filesystem::exists(output_path));
    }
}

}  // namespace pfl::tests
