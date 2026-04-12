#include <filesystem>
#include <string_view>
#include <vector>

#include "TestSupport.h"
#include "PcapTestUtils.h"
#include "app/session/CaptureSession.h"
#include "core/reassembly/ReassemblyTypes.h"
#include "core/services/CaptureImporter.h"

namespace pfl::tests {

namespace {

constexpr std::string_view kDirectionAToB {"A\xE2\x86\x92" "B"};

bool has_flag(const ReassemblyResult& result, const ReassemblyQualityFlag flag) {
    return (result.quality_flags & static_cast<std::uint32_t>(flag)) != 0U;
}

Direction direction_for_packet(const CaptureSession& session, const std::size_t flow_index, const std::uint64_t packet_index) {
    const auto packet_rows = session.list_flow_packets(flow_index);
    for (const auto& row : packet_rows) {
        if (row.packet_index != packet_index) {
            continue;
        }

        return row.direction_text == kDirectionAToB ? Direction::a_to_b : Direction::b_to_a;
    }

    PFL_EXPECT(false);
    return Direction::a_to_b;
}

std::filesystem::path write_tcp_reassembly_capture() {
    const auto packet0 = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
        ipv4(10, 0, 0, 1), ipv4(10, 0, 0, 2), 41000, 80, std::vector<std::uint8_t> {'G', 'E', 'T', ' '}, 0x18);
    const auto packet1 = make_ethernet_ipv4_tcp_packet(
        ipv4(10, 0, 0, 2), ipv4(10, 0, 0, 1), 80, 41000);
    const auto packet2 = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
        ipv4(10, 0, 0, 1), ipv4(10, 0, 0, 2), 41000, 80, std::vector<std::uint8_t> {'/', 'v', '1'}, 0x18);
    const auto packet3 = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
        ipv4(10, 0, 0, 1), ipv4(10, 0, 0, 2), 41000, 80, std::vector<std::uint8_t> {'\r', '\n'}, 0x18);

    return write_temp_pcap(
        "pfl_reassembly_v1_tcp.pcap",
        make_classic_pcap({
            {100, packet0},
            {200, packet1},
            {300, packet2},
            {400, packet3},
        })
    );
}

std::filesystem::path write_udp_capture() {
    const auto packet = make_ethernet_ipv4_udp_packet_with_bytes_payload(
        ipv4(10, 1, 0, 1), ipv4(10, 1, 0, 2), 53000, 53, std::vector<std::uint8_t> {0x01, 0x02, 0x03});
    return write_temp_pcap("pfl_reassembly_v1_udp.pcap", make_classic_pcap({{100, packet}}));
}

std::filesystem::path write_zero_payload_capture() {
    const auto packet0 = make_ethernet_ipv4_tcp_packet(
        ipv4(10, 2, 0, 1), ipv4(10, 2, 0, 2), 42000, 443);
    const auto packet1 = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
        ipv4(10, 2, 0, 1), ipv4(10, 2, 0, 2), 42000, 443, std::vector<std::uint8_t> {'O', 'K'}, 0x18);
    return write_temp_pcap(
        "pfl_reassembly_v1_zero_payload.pcap",
        make_classic_pcap({
            {100, packet0},
            {200, packet1},
        })
    );
}

std::filesystem::path write_fragmented_tcp_capture() {
    const auto fragment = make_ethernet_ipv4_fragment_packet(
        ipv4(10, 3, 0, 1),
        ipv4(10, 3, 0, 2),
        6,
        0x2000,
        std::vector<std::uint8_t> {0x00, 0x50, 0x00, 0x00, 0xaa, 0xbb, 0xcc, 0xdd}
    );
    return write_temp_pcap("pfl_reassembly_v1_fragmented.pcap", make_classic_pcap({{100, fragment}}));
}

std::filesystem::path write_duplicate_tcp_segment_capture() {
    const auto packet0 = make_ethernet_ipv4_tcp_packet_with_bytes_payload_and_sequence(
        ipv4(10, 4, 0, 1), ipv4(10, 4, 0, 2), 43000, 443, std::vector<std::uint8_t> {'A', 'B', 'C'}, 1000U, 2000U, 0x18);
    const auto packet1 = make_ethernet_ipv4_tcp_packet_with_bytes_payload_and_sequence(
        ipv4(10, 4, 0, 1), ipv4(10, 4, 0, 2), 43000, 443, std::vector<std::uint8_t> {'A', 'B', 'C'}, 1000U, 2000U, 0x18);
    return write_temp_pcap(
        "pfl_reassembly_v1_duplicate_segment.pcap",
        make_classic_pcap({
            {100, packet0},
            {200, packet1},
        })
    );
}

std::filesystem::path write_similar_tcp_segment_capture() {
    const auto packet0 = make_ethernet_ipv4_tcp_packet_with_bytes_payload_and_sequence(
        ipv4(10, 4, 1, 1), ipv4(10, 4, 1, 2), 43001, 443, std::vector<std::uint8_t> {'A', 'B', 'C'}, 1000U, 2000U, 0x18);
    const auto packet1 = make_ethernet_ipv4_tcp_packet_with_bytes_payload_and_sequence(
        ipv4(10, 4, 1, 1), ipv4(10, 4, 1, 2), 43001, 443, std::vector<std::uint8_t> {'X', 'Y', 'Z'}, 1000U, 2000U, 0x18);
    return write_temp_pcap(
        "pfl_reassembly_v1_similar_segment.pcap",
        make_classic_pcap({
            {100, packet0},
            {200, packet1},
        })
    );
}

std::filesystem::path write_partially_overlapping_tcp_segment_capture() {
    const auto packet0 = make_ethernet_ipv4_tcp_packet_with_bytes_payload_and_sequence(
        ipv4(10, 4, 2, 1), ipv4(10, 4, 2, 2), 43002, 443, std::vector<std::uint8_t> {'A', 'B', 'C', 'D', 'E'}, 1000U, 2000U, 0x18);
    const auto packet1 = make_ethernet_ipv4_tcp_packet_with_bytes_payload_and_sequence(
        ipv4(10, 4, 2, 1), ipv4(10, 4, 2, 2), 43002, 443, std::vector<std::uint8_t> {'C', 'D', 'E', 'F', 'G'}, 1002U, 2000U, 0x18);
    return write_temp_pcap(
        "pfl_reassembly_v1_partial_overlap_segment.pcap",
        make_classic_pcap({
            {100, packet0},
            {200, packet1},
        })
    );
}

}  // namespace

void run_reassembly_v1_tests() {
    const auto tcp_capture_path = write_tcp_reassembly_capture();

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(tcp_capture_path, CaptureImportOptions {.mode = ImportMode::deep}));
        const auto direction = direction_for_packet(session, 0, 0);
        const auto expected_bytes = std::vector<std::uint8_t> {'G', 'E', 'T', ' ', '/', 'v', '1', '\r', '\n'};
        const auto expected_packet_indices = std::vector<std::uint64_t> {0, 2, 3};

        const auto result = session.reassemble_flow_direction(ReassemblyRequest {
            .flow_index = 0,
            .direction = direction,
            .max_packets = 16,
            .max_bytes = 1024,
        });

        PFL_EXPECT(result.has_value());
        PFL_EXPECT(result->bytes == expected_bytes);
        PFL_EXPECT(result->packet_indices == expected_packet_indices);
        PFL_EXPECT(result->payload_packets_used == 3U);
        PFL_EXPECT(result->total_packets_seen == 3U);
        PFL_EXPECT(has_flag(*result, ReassemblyQualityFlag::packet_order_only));
        PFL_EXPECT(has_flag(*result, ReassemblyQualityFlag::may_contain_retransmissions));
        PFL_EXPECT(!has_flag(*result, ReassemblyQualityFlag::truncated_by_packet_budget));
        PFL_EXPECT(!has_flag(*result, ReassemblyQualityFlag::truncated_by_byte_budget));
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(tcp_capture_path, CaptureImportOptions {.mode = ImportMode::fast}));
        const auto direction = direction_for_packet(session, 0, 0);
        const auto result = session.reassemble_flow_direction(ReassemblyRequest {
            .flow_index = 0,
            .direction = direction,
            .max_packets = 16,
            .max_bytes = 1024,
        });
        const auto expected_fast_bytes = std::vector<std::uint8_t> {'G', 'E', 'T', ' ', '/', 'v', '1', '\r', '\n'};
        const auto expected_fast_packet_indices = std::vector<std::uint64_t> {0, 2, 3};
        PFL_EXPECT(result.has_value());
        PFL_EXPECT(result->bytes == expected_fast_bytes);
        PFL_EXPECT(result->packet_indices == expected_fast_packet_indices);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(write_udp_capture(), CaptureImportOptions {.mode = ImportMode::deep}));
        const auto result = session.reassemble_flow_direction(ReassemblyRequest {.flow_index = 0});
        PFL_EXPECT(!result.has_value());
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(tcp_capture_path, CaptureImportOptions {.mode = ImportMode::deep}));
        const auto direction = direction_for_packet(session, 0, 0);
        const auto expected_bytes = std::vector<std::uint8_t> {'G', 'E', 'T', ' ', '/', 'v', '1'};
        const auto expected_packet_indices = std::vector<std::uint64_t> {0, 2};

        const auto result = session.reassemble_flow_direction(ReassemblyRequest {
            .flow_index = 0,
            .direction = direction,
            .max_packets = 2,
            .max_bytes = 1024,
        });

        PFL_EXPECT(result.has_value());
        PFL_EXPECT(result->bytes == expected_bytes);
        PFL_EXPECT(result->packet_indices == expected_packet_indices);
        PFL_EXPECT(result->payload_packets_used == 2U);
        PFL_EXPECT(result->total_packets_seen == 2U);
        PFL_EXPECT(has_flag(*result, ReassemblyQualityFlag::truncated_by_packet_budget));
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(tcp_capture_path, CaptureImportOptions {.mode = ImportMode::deep}));
        const auto direction = direction_for_packet(session, 0, 0);
        const auto expected_bytes = std::vector<std::uint8_t> {'G', 'E', 'T', ' ', '/'};
        const auto expected_packet_indices = std::vector<std::uint64_t> {0, 2};

        const auto result = session.reassemble_flow_direction(ReassemblyRequest {
            .flow_index = 0,
            .direction = direction,
            .max_packets = 16,
            .max_bytes = 5,
        });

        PFL_EXPECT(result.has_value());
        PFL_EXPECT(result->bytes == expected_bytes);
        PFL_EXPECT(result->packet_indices == expected_packet_indices);
        PFL_EXPECT(result->payload_packets_used == 2U);
        PFL_EXPECT(result->total_packets_seen == 2U);
        PFL_EXPECT(has_flag(*result, ReassemblyQualityFlag::truncated_by_byte_budget));
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(write_zero_payload_capture(), CaptureImportOptions {.mode = ImportMode::deep}));
        const auto direction = direction_for_packet(session, 0, 0);
        const auto expected_bytes = std::vector<std::uint8_t> {'O', 'K'};
        const auto expected_packet_indices = std::vector<std::uint64_t> {1};

        const auto result = session.reassemble_flow_direction(ReassemblyRequest {
            .flow_index = 0,
            .direction = direction,
            .max_packets = 16,
            .max_bytes = 1024,
        });

        PFL_EXPECT(result.has_value());
        PFL_EXPECT(result->bytes == expected_bytes);
        PFL_EXPECT(result->packet_indices == expected_packet_indices);
        PFL_EXPECT(result->payload_packets_used == 1U);
        PFL_EXPECT(result->total_packets_seen == 2U);
        PFL_EXPECT(has_flag(*result, ReassemblyQualityFlag::contains_non_payload_packets));
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(write_fragmented_tcp_capture(), CaptureImportOptions {.mode = ImportMode::deep}));
        const auto direction = direction_for_packet(session, 0, 0);

        const auto result = session.reassemble_flow_direction(ReassemblyRequest {
            .flow_index = 0,
            .direction = direction,
            .max_packets = 16,
            .max_bytes = 1024,
        });

        PFL_EXPECT(result.has_value());
        PFL_EXPECT(result->bytes.empty());
        PFL_EXPECT(result->packet_indices.empty());
        PFL_EXPECT(result->payload_packets_used == 0U);
        PFL_EXPECT(result->total_packets_seen == 1U);
        PFL_EXPECT(has_flag(*result, ReassemblyQualityFlag::packet_order_only));
        PFL_EXPECT(has_flag(*result, ReassemblyQualityFlag::may_contain_transport_gaps));
        PFL_EXPECT(has_flag(*result, ReassemblyQualityFlag::may_contain_retransmissions));
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(write_duplicate_tcp_segment_capture(), CaptureImportOptions {.mode = ImportMode::deep}));
        const auto direction = direction_for_packet(session, 0, 0);
        const auto suppressed_packet_indices = session.suspected_tcp_retransmission_packet_indices(0);
        const auto expected_bytes = std::vector<std::uint8_t> {'A', 'B', 'C'};
        const auto expected_packet_indices = std::vector<std::uint64_t> {0U};
        PFL_EXPECT(suppressed_packet_indices == std::vector<std::uint64_t> {1U});
        session.set_selected_flow_tcp_payload_suppression(0U, suppressed_packet_indices);

        const auto result = session.reassemble_flow_direction(ReassemblyRequest {
            .flow_index = 0,
            .direction = direction,
            .max_packets = 16,
            .max_bytes = 1024,
        });

        PFL_EXPECT(result.has_value());
        PFL_EXPECT(result->bytes == expected_bytes);
        PFL_EXPECT(result->packet_indices == expected_packet_indices);
        PFL_EXPECT(result->payload_packets_used == 1U);
        PFL_EXPECT(result->total_packets_seen == 2U);
        PFL_EXPECT(has_flag(*result, ReassemblyQualityFlag::duplicate_tcp_segment_suppressed));
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(write_similar_tcp_segment_capture(), CaptureImportOptions {.mode = ImportMode::deep}));
        const auto direction = direction_for_packet(session, 0, 0);
        const auto suppressed_packet_indices = session.suspected_tcp_retransmission_packet_indices(0);
        const auto expected_bytes = std::vector<std::uint8_t> {'A', 'B', 'C', 'X', 'Y', 'Z'};
        const auto expected_packet_indices = std::vector<std::uint64_t> {0U, 1U};
        PFL_EXPECT(suppressed_packet_indices.empty());
        session.set_selected_flow_tcp_payload_suppression(0U, suppressed_packet_indices);

        const auto result = session.reassemble_flow_direction(ReassemblyRequest {
            .flow_index = 0,
            .direction = direction,
            .max_packets = 16,
            .max_bytes = 1024,
        });

        PFL_EXPECT(result.has_value());
        PFL_EXPECT(result->bytes == expected_bytes);
        PFL_EXPECT(result->packet_indices == expected_packet_indices);
        PFL_EXPECT(!has_flag(*result, ReassemblyQualityFlag::duplicate_tcp_segment_suppressed));
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(write_partially_overlapping_tcp_segment_capture(), CaptureImportOptions {.mode = ImportMode::deep}));
        const auto direction = direction_for_packet(session, 0, 0);
        const auto suppressed_packet_indices = session.suspected_tcp_retransmission_packet_indices(0);
        const auto expected_bytes = std::vector<std::uint8_t> {'A', 'B', 'C', 'D', 'E', 'F', 'G'};
        const auto expected_packet_indices = std::vector<std::uint64_t> {0U, 1U};
        PFL_EXPECT(suppressed_packet_indices.empty());
        session.set_selected_flow_tcp_payload_suppression(0U, suppressed_packet_indices);

        const auto result = session.reassemble_flow_direction(ReassemblyRequest {
            .flow_index = 0,
            .direction = direction,
            .max_packets = 16,
            .max_bytes = 1024,
        });

        PFL_EXPECT(result.has_value());
        PFL_EXPECT(result->bytes == expected_bytes);
        PFL_EXPECT(result->packet_indices == expected_packet_indices);
        PFL_EXPECT(result->payload_packets_used == 2U);
        PFL_EXPECT(result->total_packets_seen == 2U);
        PFL_EXPECT(has_flag(*result, ReassemblyQualityFlag::duplicate_tcp_segment_suppressed));
    }
}

}  // namespace pfl::tests
