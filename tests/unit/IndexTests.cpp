#include <filesystem>
#include <vector>

#include "TestSupport.h"
#include "app/session/CaptureSession.h"
#include "core/index/CaptureIndex.h"
#include "core/index/CaptureIndexReader.h"
#include "PcapTestUtils.h"

namespace pfl::tests {

void run_index_tests() {
    const auto forward_packet = make_ethernet_ipv4_tcp_packet(ipv4(172, 16, 0, 10), ipv4(172, 16, 0, 20), 40000, 443);
    const auto reverse_packet = make_ethernet_ipv4_tcp_packet(ipv4(172, 16, 0, 20), ipv4(172, 16, 0, 10), 443, 40000);
    const auto source_path = write_temp_pcap(
        "pfl_index_roundtrip_source.pcap",
        make_classic_pcap({{100, forward_packet}, {200, reverse_packet}})
    );
    const auto index_path = std::filesystem::temp_directory_path() / "pfl_capture_state.idx";
    std::filesystem::remove(index_path);

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(source_path));
        PFL_EXPECT(session.summary().packet_count == 2);
        PFL_EXPECT(session.summary().flow_count == 1);
        PFL_EXPECT(session.save_index(index_path));
        PFL_EXPECT(std::filesystem::exists(index_path));

        CaptureSession loaded_session {};
        PFL_EXPECT(loaded_session.load_index(index_path));
        PFL_EXPECT(loaded_session.has_capture());
        PFL_EXPECT(loaded_session.capture_path() == source_path);
        PFL_EXPECT(loaded_session.summary().packet_count == session.summary().packet_count);
        PFL_EXPECT(loaded_session.summary().flow_count == session.summary().flow_count);
        PFL_EXPECT(loaded_session.summary().total_bytes == session.summary().total_bytes);
        PFL_EXPECT(loaded_session.list_flows().size() == session.list_flows().size());

        const auto first_packet = loaded_session.find_packet(0);
        PFL_EXPECT(first_packet.has_value());
        PFL_EXPECT(first_packet->ts_usec == 100);
        PFL_EXPECT(first_packet->captured_length == forward_packet.size());

        const auto second_packet = loaded_session.find_packet(1);
        PFL_EXPECT(second_packet.has_value());
        PFL_EXPECT(second_packet->ts_usec == 200);
        PFL_EXPECT(second_packet->captured_length == reverse_packet.size());

        const auto reloaded_bytes = loaded_session.read_packet_data(*first_packet);
        PFL_EXPECT(reloaded_bytes == forward_packet);

        const auto details = loaded_session.read_packet_details(*first_packet);
        PFL_EXPECT(details.has_value());
        PFL_EXPECT(details->has_ipv4);
        PFL_EXPECT(details->has_tcp);
        PFL_EXPECT(details->ipv4.src_addr == ipv4(172, 16, 0, 10));
        PFL_EXPECT(details->ipv4.dst_addr == ipv4(172, 16, 0, 20));
        PFL_EXPECT(details->tcp.src_port == 40000);
        PFL_EXPECT(details->tcp.dst_port == 443);
    }

    {
        CaptureIndexReader reader {};
        CaptureState loaded_state {};
        std::filesystem::path loaded_capture_path {};
        CaptureSourceInfo source_info {};
        PFL_EXPECT(reader.read(index_path, loaded_state, loaded_capture_path, &source_info));
        PFL_EXPECT(loaded_capture_path == source_path);
        PFL_EXPECT(source_info.capture_path == source_path);
        PFL_EXPECT(loaded_state.summary.packet_count == 2);
        PFL_EXPECT(loaded_state.summary.flow_count == 1);
        PFL_EXPECT(loaded_state.ipv4_connections.size() == 1);
        PFL_EXPECT(loaded_state.ipv6_connections.size() == 0);
        PFL_EXPECT(validate_capture_source(source_info));

        auto mismatched_info = source_info;
        mismatched_info.file_size += 1;
        PFL_EXPECT(!validate_capture_source(mismatched_info, source_path));
    }

    {
        const auto truncated_index_path = write_temp_binary_file("pfl_capture_state_truncated.idx", {0x50, 0x46, 0x4c});
        CaptureSession session {};
        PFL_EXPECT(!session.load_index(truncated_index_path));

        CaptureIndexReader reader {};
        CaptureState state {};
        std::filesystem::path capture_path {};
        PFL_EXPECT(!reader.read(truncated_index_path, state, capture_path));
    }

    {
        CaptureSourceInfo source_info {};
        PFL_EXPECT(read_capture_source_info(source_path, source_info));
        PFL_EXPECT(validate_capture_source(source_info, source_path));

        auto mismatched_info = source_info;
        mismatched_info.last_write_time += 1;
        PFL_EXPECT(!validate_capture_source(mismatched_info, source_path));
    }
}

}  // namespace pfl::tests
