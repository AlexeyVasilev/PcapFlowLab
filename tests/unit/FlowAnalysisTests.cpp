#include <filesystem>
#include <vector>

#include "TestSupport.h"
#include "PcapTestUtils.h"
#include "app/session/CaptureSession.h"

namespace pfl::tests {

namespace {

std::vector<std::uint8_t> make_http_request_payload() {
    constexpr char request[] =
        "GET /analysis HTTP/1.1\r\n"
        "Host: analysis.example\r\n"
        "\r\n";
    return std::vector<std::uint8_t>(request, request + sizeof(request) - 1);
}

std::uint64_t packet_histogram_count(const FlowAnalysisResult& analysis, const std::string& bucket_label) {
    for (const auto& row : analysis.packet_size_histogram_rows) {
        if (row.bucket_label == bucket_label) {
            return row.packet_count;
        }
    }

    return 0U;
}

std::uint64_t inter_arrival_histogram_count(const FlowAnalysisResult& analysis, const std::string& bucket_label) {
    for (const auto& row : analysis.inter_arrival_histogram_rows) {
        if (row.bucket_label == bucket_label) {
            return row.packet_count;
        }
    }

    return 0U;
}

}  // namespace

void run_flow_analysis_tests() {
    const auto request_packet = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
        ipv4(10, 0, 0, 1), ipv4(10, 0, 0, 2), 40000, 80, make_http_request_payload(), 0x18
    );
    const auto response_packet = make_ethernet_ipv4_tcp_packet_with_payload(
        ipv4(10, 0, 0, 2), ipv4(10, 0, 0, 1), 80, 40000, 20, 0x18
    );
    const auto follow_up_packet = make_ethernet_ipv4_tcp_packet_with_payload(
        ipv4(10, 0, 0, 1), ipv4(10, 0, 0, 2), 40000, 80, 10, 0x18
    );
    const auto other_flow_packet = make_ethernet_ipv4_udp_packet(
        ipv4(10, 0, 0, 3), ipv4(10, 0, 0, 4), 53000, 53
    );

    const auto capture_path = write_temp_pcap(
        "pfl_flow_analysis_mvp.pcap",
        make_classic_pcap({
            {100, request_packet},
            {250, response_packet},
            {450, follow_up_packet},
            {600, other_flow_packet},
        })
    );

    CaptureSession session {};
    PFL_EXPECT(session.open_capture(capture_path));

    const auto rows = session.list_flows();
    PFL_EXPECT(rows.size() == 2);

    std::size_t http_flow_index = rows.size();
    for (const auto& row : rows) {
        if (row.protocol_hint == "http") {
            http_flow_index = row.index;
            break;
        }
    }
    PFL_EXPECT(http_flow_index < rows.size());

    const auto analysis = session.get_flow_analysis(http_flow_index);
    PFL_EXPECT(analysis.has_value());
    PFL_EXPECT(analysis->total_packets == 3U);
    PFL_EXPECT(analysis->total_bytes == static_cast<std::uint64_t>(request_packet.size() + response_packet.size() + follow_up_packet.size()));
    PFL_EXPECT(analysis->duration_us == 2000350U);
    PFL_EXPECT(analysis->packets_a_to_b == 2U);
    PFL_EXPECT(analysis->packets_b_to_a == 1U);
    PFL_EXPECT(analysis->bytes_a_to_b == static_cast<std::uint64_t>(request_packet.size() + follow_up_packet.size()));
    PFL_EXPECT(analysis->bytes_b_to_a == static_cast<std::uint64_t>(response_packet.size()));
    PFL_EXPECT(analysis->first_packet_timestamp_text == "00:00:01.000100");
    PFL_EXPECT(analysis->last_packet_timestamp_text == "00:00:03.000450");
    PFL_EXPECT(analysis->largest_gap_us == 1000200U);
    PFL_EXPECT(analysis->timeline_packet_count_considered == 3U);
    PFL_EXPECT(analysis->protocol_hint == "http");
    PFL_EXPECT(analysis->service_hint == "analysis.example");
    PFL_EXPECT(analysis->inter_arrival_histogram_rows.size() == 6U);
    PFL_EXPECT(inter_arrival_histogram_count(*analysis, "0-99 us") == 0U);
    PFL_EXPECT(inter_arrival_histogram_count(*analysis, "100-999 us") == 0U);
    PFL_EXPECT(inter_arrival_histogram_count(*analysis, "1-9.9 ms") == 0U);
    PFL_EXPECT(inter_arrival_histogram_count(*analysis, "10-99 ms") == 0U);
    PFL_EXPECT(inter_arrival_histogram_count(*analysis, "100-999 ms") == 0U);
    PFL_EXPECT(inter_arrival_histogram_count(*analysis, "1 s+") == 2U);
    PFL_EXPECT(analysis->packet_size_histogram_rows.size() == 7U);
    PFL_EXPECT(packet_histogram_count(*analysis, "0-63") == 0U);
    PFL_EXPECT(packet_histogram_count(*analysis, "64-127") == 3U);
    PFL_EXPECT(packet_histogram_count(*analysis, "128-255") == 0U);
    PFL_EXPECT(packet_histogram_count(*analysis, "256-511") == 0U);
    PFL_EXPECT(packet_histogram_count(*analysis, "512-1023") == 0U);
    PFL_EXPECT(packet_histogram_count(*analysis, "1024-1518") == 0U);
    PFL_EXPECT(packet_histogram_count(*analysis, "1519+") == 0U);
    PFL_EXPECT(analysis->sequence_preview_rows.size() == 3U);
    PFL_EXPECT(analysis->sequence_preview_rows[0].flow_packet_number == 1U);
    PFL_EXPECT(analysis->sequence_preview_rows[0].direction_text == "A->B");
    PFL_EXPECT(analysis->sequence_preview_rows[0].delta_time_us == 0U);
    PFL_EXPECT(analysis->sequence_preview_rows[0].captured_length == request_packet.size());
    PFL_EXPECT(analysis->sequence_preview_rows[0].payload_length == make_http_request_payload().size());
    PFL_EXPECT(analysis->sequence_preview_rows[1].flow_packet_number == 2U);
    PFL_EXPECT(analysis->sequence_preview_rows[1].direction_text == "B->A");
    PFL_EXPECT(analysis->sequence_preview_rows[1].delta_time_us == 1000150U);
    PFL_EXPECT(analysis->sequence_preview_rows[1].captured_length == response_packet.size());
    PFL_EXPECT(analysis->sequence_preview_rows[1].payload_length == 20U);
    PFL_EXPECT(analysis->sequence_preview_rows[2].flow_packet_number == 3U);
    PFL_EXPECT(analysis->sequence_preview_rows[2].direction_text == "A->B");
    PFL_EXPECT(analysis->sequence_preview_rows[2].delta_time_us == 1000200U);
    PFL_EXPECT(analysis->sequence_preview_rows[2].captured_length == follow_up_packet.size());
    PFL_EXPECT(analysis->sequence_preview_rows[2].payload_length == 10U);

    PFL_EXPECT(!session.get_flow_analysis(99U).has_value());

    std::vector<std::pair<std::uint32_t, std::vector<std::uint8_t>>> heavy_packets {};
    heavy_packets.reserve(25);
    for (std::uint32_t index = 0; index < 25U; ++index) {
        heavy_packets.push_back({100U + index, request_packet});
    }

    const auto heavy_capture_path = write_temp_pcap(
        "pfl_flow_analysis_sequence_bound.pcap",
        make_classic_pcap(heavy_packets)
    );

    CaptureSession heavy_session {};
    PFL_EXPECT(heavy_session.open_capture(heavy_capture_path));
    const auto heavy_rows = heavy_session.list_flows();
    PFL_EXPECT(heavy_rows.size() == 1U);
    const auto heavy_analysis = heavy_session.get_flow_analysis(heavy_rows.front().index);
    PFL_EXPECT(heavy_analysis.has_value());
    PFL_EXPECT(heavy_analysis->total_packets == 25U);
    PFL_EXPECT(heavy_analysis->timeline_packet_count_considered == 25U);
    PFL_EXPECT(heavy_analysis->largest_gap_us > 0U);
    PFL_EXPECT(inter_arrival_histogram_count(*heavy_analysis, "1 s+") == 24U);
    PFL_EXPECT(packet_histogram_count(*heavy_analysis, "64-127") == 25U);
    PFL_EXPECT(heavy_analysis->sequence_preview_rows.size() == 20U);
    PFL_EXPECT(heavy_analysis->sequence_preview_rows.front().flow_packet_number == 1U);
    PFL_EXPECT(heavy_analysis->sequence_preview_rows.back().flow_packet_number == 20U);

    const auto bucket_0_63_packet = make_ethernet_ipv4_tcp_packet_with_payload(
        ipv4(10, 1, 0, 1), ipv4(10, 1, 0, 2), 41000, 443, 0, 0x18
    );
    const auto bucket_64_127_packet = make_ethernet_ipv4_tcp_packet_with_payload(
        ipv4(10, 1, 0, 1), ipv4(10, 1, 0, 2), 41000, 443, 10, 0x18
    );
    const auto bucket_128_255_packet = make_ethernet_ipv4_tcp_packet_with_payload(
        ipv4(10, 1, 0, 1), ipv4(10, 1, 0, 2), 41000, 443, 80, 0x18
    );
    const auto bucket_256_511_packet = make_ethernet_ipv4_tcp_packet_with_payload(
        ipv4(10, 1, 0, 1), ipv4(10, 1, 0, 2), 41000, 443, 220, 0x18
    );
    const auto bucket_512_1023_packet = make_ethernet_ipv4_tcp_packet_with_payload(
        ipv4(10, 1, 0, 1), ipv4(10, 1, 0, 2), 41000, 443, 470, 0x18
    );
    const auto bucket_1024_1518_packet = make_ethernet_ipv4_tcp_packet_with_payload(
        ipv4(10, 1, 0, 1), ipv4(10, 1, 0, 2), 41000, 443, 1000, 0x18
    );
    const auto bucket_1519_plus_packet = make_ethernet_ipv4_tcp_packet_with_payload(
        ipv4(10, 1, 0, 1), ipv4(10, 1, 0, 2), 41000, 443, 1600, 0x18
    );

    const auto histogram_capture_path = write_temp_pcap(
        "pfl_flow_analysis_histogram.pcap",
        make_classic_pcap({
            {100U, bucket_0_63_packet},
            {110U, bucket_64_127_packet},
            {120U, bucket_128_255_packet},
            {130U, bucket_256_511_packet},
            {140U, bucket_512_1023_packet},
            {150U, bucket_1024_1518_packet},
            {160U, bucket_1519_plus_packet},
        })
    );

    CaptureSession histogram_session {};
    PFL_EXPECT(histogram_session.open_capture(histogram_capture_path));
    const auto histogram_rows = histogram_session.list_flows();
    PFL_EXPECT(histogram_rows.size() == 1U);
    const auto histogram_analysis = histogram_session.get_flow_analysis(histogram_rows.front().index);
    PFL_EXPECT(histogram_analysis.has_value());
    PFL_EXPECT(histogram_analysis->total_packets == 7U);
    PFL_EXPECT(histogram_analysis->packet_size_histogram_rows.size() == 7U);
    PFL_EXPECT(packet_histogram_count(*histogram_analysis, "0-63") == 1U);
    PFL_EXPECT(packet_histogram_count(*histogram_analysis, "64-127") == 1U);
    PFL_EXPECT(packet_histogram_count(*histogram_analysis, "128-255") == 1U);
    PFL_EXPECT(packet_histogram_count(*histogram_analysis, "256-511") == 1U);
    PFL_EXPECT(packet_histogram_count(*histogram_analysis, "512-1023") == 1U);
    PFL_EXPECT(packet_histogram_count(*histogram_analysis, "1024-1518") == 1U);
    PFL_EXPECT(packet_histogram_count(*histogram_analysis, "1519+") == 1U);
    PFL_EXPECT(
        packet_histogram_count(*histogram_analysis, "0-63") +
        packet_histogram_count(*histogram_analysis, "64-127") +
        packet_histogram_count(*histogram_analysis, "128-255") +
        packet_histogram_count(*histogram_analysis, "256-511") +
        packet_histogram_count(*histogram_analysis, "512-1023") +
        packet_histogram_count(*histogram_analysis, "1024-1518") +
        packet_histogram_count(*histogram_analysis, "1519+") == histogram_analysis->total_packets
    );

    const auto inter_arrival_packet = make_ethernet_ipv4_tcp_packet_with_payload(
        ipv4(10, 2, 0, 1), ipv4(10, 2, 0, 2), 42000, 8080, 12, 0x18
    );
    const auto inter_arrival_capture_path = write_temp_pcap(
        "pfl_flow_analysis_inter_arrival_histogram.pcapng",
        make_pcapng({
            make_pcapng_section_header_block(),
            make_pcapng_interface_description_block(),
            make_pcapng_enhanced_packet_block(0U, 1U, 0U, inter_arrival_packet),
            make_pcapng_enhanced_packet_block(0U, 1U, 50U, inter_arrival_packet),
            make_pcapng_enhanced_packet_block(0U, 1U, 550U, inter_arrival_packet),
            make_pcapng_enhanced_packet_block(0U, 1U, 5550U, inter_arrival_packet),
            make_pcapng_enhanced_packet_block(0U, 1U, 55550U, inter_arrival_packet),
            make_pcapng_enhanced_packet_block(0U, 1U, 555550U, inter_arrival_packet),
            make_pcapng_enhanced_packet_block(0U, 3U, 555550U, inter_arrival_packet),
        })
    );

    CaptureSession inter_arrival_session {};
    PFL_EXPECT(inter_arrival_session.open_capture(inter_arrival_capture_path));
    const auto inter_arrival_rows = inter_arrival_session.list_flows();
    PFL_EXPECT(inter_arrival_rows.size() == 1U);
    const auto inter_arrival_analysis = inter_arrival_session.get_flow_analysis(inter_arrival_rows.front().index);
    PFL_EXPECT(inter_arrival_analysis.has_value());
    PFL_EXPECT(inter_arrival_analysis->total_packets == 7U);
    PFL_EXPECT(inter_arrival_analysis->inter_arrival_histogram_rows.size() == 6U);
    PFL_EXPECT(inter_arrival_histogram_count(*inter_arrival_analysis, "0-99 us") == 1U);
    PFL_EXPECT(inter_arrival_histogram_count(*inter_arrival_analysis, "100-999 us") == 1U);
    PFL_EXPECT(inter_arrival_histogram_count(*inter_arrival_analysis, "1-9.9 ms") == 1U);
    PFL_EXPECT(inter_arrival_histogram_count(*inter_arrival_analysis, "10-99 ms") == 1U);
    PFL_EXPECT(inter_arrival_histogram_count(*inter_arrival_analysis, "100-999 ms") == 1U);
    PFL_EXPECT(inter_arrival_histogram_count(*inter_arrival_analysis, "1 s+") == 1U);
    PFL_EXPECT(
        inter_arrival_histogram_count(*inter_arrival_analysis, "0-99 us") +
        inter_arrival_histogram_count(*inter_arrival_analysis, "100-999 us") +
        inter_arrival_histogram_count(*inter_arrival_analysis, "1-9.9 ms") +
        inter_arrival_histogram_count(*inter_arrival_analysis, "10-99 ms") +
        inter_arrival_histogram_count(*inter_arrival_analysis, "100-999 ms") +
        inter_arrival_histogram_count(*inter_arrival_analysis, "1 s+") == inter_arrival_analysis->total_packets - 1U
    );
}

}  // namespace pfl::tests
