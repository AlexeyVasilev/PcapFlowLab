#include <filesystem>
#include <vector>

#include "TestSupport.h"
#include "PcapTestUtils.h"
#include "app/session/CaptureSession.h"
#include "core/reassembly/ReassemblyTypes.h"
#include "core/services/CaptureImporter.h"

namespace pfl::tests {

namespace {

std::vector<std::uint8_t> make_reassembly_test_payload() {
    constexpr char payload[] =
        "GET /reassembly HTTP/1.1\r\n"
        "Host: example.test\r\n"
        "\r\n";
    return std::vector<std::uint8_t>(payload, payload + sizeof(payload) - 1);
}

std::filesystem::path write_reassembly_test_capture() {
    const auto packet = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
        ipv4(10, 10, 0, 1), ipv4(10, 10, 0, 2), 40000, 80, make_reassembly_test_payload(), 0x18);
    return write_temp_pcap(
        "pfl_reassembly_architecture.pcap",
        make_classic_pcap({{100, packet}})
    );
}

}  // namespace

void run_reassembly_architecture_tests() {
    {
        ReassemblyResult result {};
        PFL_EXPECT(result.empty());
        result.packet_indices.push_back(7);
        PFL_EXPECT(result.empty());
        result.bytes.push_back(0x01U);
        PFL_EXPECT(!result.empty());
    }

    const auto capture_path = write_reassembly_test_capture();

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(capture_path, CaptureImportOptions {.mode = ImportMode::fast}));
        const auto initial_summary = session.summary();
        const auto result = session.reassemble_flow_direction(ReassemblyRequest {.flow_index = 0});
        PFL_EXPECT(!result.has_value());
        PFL_EXPECT(session.summary().packet_count == initial_summary.packet_count);
        PFL_EXPECT(session.summary().flow_count == initial_summary.flow_count);
        PFL_EXPECT(session.summary().total_bytes == initial_summary.total_bytes);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(capture_path, CaptureImportOptions {.mode = ImportMode::deep}));
        const auto flow_rows = session.list_flows();
        PFL_EXPECT(flow_rows.size() == 1);
        const auto result = session.reassemble_flow_direction(ReassemblyRequest {
            .flow_index = 0,
            .direction = Direction::a_to_b,
        });
        PFL_EXPECT(result.has_value());
        PFL_EXPECT(result->bytes == make_reassembly_test_payload());
        PFL_EXPECT(result->packet_indices == std::vector<std::uint64_t> {0});
        PFL_EXPECT(result->payload_packets_used == 1U);
        PFL_EXPECT(result->total_packets_seen == 1U);

        const auto packet_rows = session.list_flow_packets(0);
        PFL_EXPECT(packet_rows.size() == 1);
        PFL_EXPECT(packet_rows.front().packet_index == 0);
    }
}

}  // namespace pfl::tests
