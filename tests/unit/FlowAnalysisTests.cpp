#include <filesystem>
#include <cmath>
#include <vector>

#include "TestSupport.h"
#include "PcapTestUtils.h"
#include "app/session/CaptureSession.h"
#include "core/services/FlowAnalysisService.h"

namespace pfl::tests {

namespace {

std::vector<std::uint8_t> make_http_request_payload() {
    constexpr char request[] =
        "GET /analysis HTTP/1.1\r\n"
        "Host: analysis.example\r\n"
        "\r\n";
    return std::vector<std::uint8_t>(request, request + sizeof(request) - 1);
}

std::uint64_t packet_histogram_count(const std::vector<FlowAnalysisPacketSizeHistogramRow>& rows, const std::string& bucket_label) {
    for (const auto& row : rows) {
        if (row.bucket_label == bucket_label) {
            return row.packet_count;
        }
    }

    return 0U;
}

std::uint64_t packet_histogram_count(const FlowAnalysisResult& analysis, const std::string& bucket_label) {
    return packet_histogram_count(analysis.packet_size_histogram_rows, bucket_label);
}

std::uint64_t inter_arrival_histogram_count(const std::vector<FlowAnalysisInterArrivalHistogramRow>& rows, const std::string& bucket_label) {
    for (const auto& row : rows) {
        if (row.bucket_label == bucket_label) {
            return row.packet_count;
        }
    }

    return 0U;
}

std::uint64_t inter_arrival_histogram_count(const FlowAnalysisResult& analysis, const std::string& bucket_label) {
    return inter_arrival_histogram_count(analysis.inter_arrival_histogram_rows, bucket_label);
}

template <typename Row>
std::uint64_t histogram_total_count(const std::vector<Row>& rows) {
    std::uint64_t total = 0U;
    for (const auto& row : rows) {
        total += row.packet_count;
    }
    return total;
}

bool nearly_equal(const double left, const double right, const double epsilon = 0.001) {
    return std::fabs(left - right) <= epsilon;
}
const FlowAnalysisRatePoint* rate_point_at(const std::vector<FlowAnalysisRatePoint>& points, const std::uint64_t x_us) {
    for (const auto& point : points) {
        if (point.relative_time_us == x_us) {
            return &point;
        }
    }

    return nullptr;
}

bool has_constant_window_spacing(const std::vector<FlowAnalysisRatePoint>& points, const std::uint64_t window_us) {
    if (points.size() < 2U) {
        return true;
    }

    for (std::size_t index = 1; index < points.size(); ++index) {
        if (points[index].relative_time_us - points[index - 1U].relative_time_us != window_us) {
            return false;
        }
    }

    return true;
}

double total_packets_from_rate_series(const std::vector<FlowAnalysisRatePoint>& points, const std::uint64_t window_us) {
    const auto window_seconds = static_cast<double>(window_us) / 1000000.0;
    double total_packets = 0.0;
    for (const auto& point : points) {
        total_packets += point.packets_per_second * window_seconds;
    }

    return total_packets;
}

double total_bytes_from_rate_series(const std::vector<FlowAnalysisRatePoint>& points, const std::uint64_t window_us) {
    const auto window_seconds = static_cast<double>(window_us) / 1000000.0;
    double total_bytes = 0.0;
    for (const auto& point : points) {
        total_bytes += point.data_per_second * window_seconds;
    }

    return total_bytes;
}

PacketRef make_analysis_packet_ref(
    const std::uint64_t packet_index,
    const std::uint32_t ts_usec,
    const std::uint32_t captured_length,
    const std::uint32_t payload_length,
    const std::uint8_t tcp_flags = 0U
) {
    return PacketRef {
        .packet_index = packet_index,
        .captured_length = captured_length,
        .original_length = captured_length,
        .ts_sec = 1U,
        .ts_usec = ts_usec,
        .payload_length = payload_length,
        .tcp_flags = tcp_flags,
    };
}

PacketRef make_analysis_packet_ref_at(
    const std::uint64_t packet_index,
    const std::uint64_t timestamp_us,
    const std::uint32_t captured_length,
    const std::uint32_t payload_length,
    const std::uint8_t tcp_flags = 0U
) {
    return PacketRef {
        .packet_index = packet_index,
        .captured_length = captured_length,
        .original_length = captured_length,
        .ts_sec = static_cast<std::uint32_t>(1U + (timestamp_us / 1000000ULL)),
        .ts_usec = static_cast<std::uint32_t>(timestamp_us % 1000000ULL),
        .payload_length = payload_length,
        .tcp_flags = tcp_flags,
    };
}

ConnectionV4 make_protocol_panel_connection(
    const FlowProtocolHint protocol_hint,
    const ProtocolId transport_protocol,
    const std::vector<PacketRef>& flow_a_packets,
    const std::vector<PacketRef>& flow_b_packets,
    const std::string& service_hint = {},
    const QuicVersionHint quic_version = QuicVersionHint::unknown,
    const TlsVersionHint tls_version = TlsVersionHint::unknown
) {
    ConnectionV4 connection {};
    connection.key.protocol = transport_protocol;
    connection.protocol_hint = protocol_hint;
    connection.service_hint = service_hint;
    connection.quic_version = quic_version;
    connection.tls_version = tls_version;
    connection.flow_a.packets = flow_a_packets;
    connection.flow_b.packets = flow_b_packets;
    connection.flow_a.packet_count = static_cast<std::uint64_t>(connection.flow_a.packets.size());
    connection.flow_b.packet_count = static_cast<std::uint64_t>(connection.flow_b.packets.size());

    for (const auto& packet : connection.flow_a.packets) {
        connection.flow_a.total_bytes += packet.captured_length;
    }

    for (const auto& packet : connection.flow_b.packets) {
        connection.flow_b.total_bytes += packet.captured_length;
    }

    connection.packet_count = connection.flow_a.packet_count + connection.flow_b.packet_count;
    connection.total_bytes = connection.flow_a.total_bytes + connection.flow_b.total_bytes;
    return connection;
}

ConnectionV4 make_burst_summary_connection(
    const std::vector<PacketRef>& flow_a_packets,
    const std::vector<PacketRef>& flow_b_packets
) {
    return make_protocol_panel_connection(FlowProtocolHint::unknown, ProtocolId::tcp, flow_a_packets, flow_b_packets);
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
    PFL_EXPECT(analysis->packet_ratio_text == "2 : 1");
    PFL_EXPECT(analysis->byte_ratio_text == "2.3 : 1");
    PFL_EXPECT(analysis->packet_direction_text == "Balanced");
    PFL_EXPECT(analysis->data_direction_text == "Mostly A->B");
    PFL_EXPECT(analysis->first_packet_timestamp_text == "00:00:01.000100");
    PFL_EXPECT(analysis->last_packet_timestamp_text == "00:00:03.000450");
    PFL_EXPECT(analysis->largest_gap_us == 1000200U);
    PFL_EXPECT(analysis->timeline_packet_count_considered == 3U);
    PFL_EXPECT(nearly_equal(analysis->packets_per_second, 1.4997375456));
    PFL_EXPECT(nearly_equal(
        analysis->bytes_per_second,
        (static_cast<double>(request_packet.size() + response_packet.size() + follow_up_packet.size()) * 1000000.0) / 2000350.0
    ));
    PFL_EXPECT(nearly_equal(
        analysis->average_packet_size_bytes,
        static_cast<double>(request_packet.size() + response_packet.size() + follow_up_packet.size()) / 3.0
    ));
    PFL_EXPECT(nearly_equal(analysis->average_inter_arrival_us, 1000175.0));
    PFL_EXPECT(analysis->min_packet_size_bytes == follow_up_packet.size());
    PFL_EXPECT(analysis->max_packet_size_bytes == request_packet.size());
    PFL_EXPECT(analysis->min_packet_size_a_to_b_bytes == follow_up_packet.size());
    PFL_EXPECT(analysis->max_packet_size_a_to_b_bytes == request_packet.size());
    PFL_EXPECT(analysis->min_packet_size_b_to_a_bytes == response_packet.size());
    PFL_EXPECT(analysis->max_packet_size_b_to_a_bytes == response_packet.size());
    PFL_EXPECT(analysis->protocol_hint == "http");
    PFL_EXPECT(analysis->service_hint == "analysis.example");
    PFL_EXPECT(analysis->inter_arrival_histogram_rows.size() == 9U);
    PFL_EXPECT(inter_arrival_histogram_count(*analysis, "0-9 us") == 0U);
    PFL_EXPECT(inter_arrival_histogram_count(*analysis, "10-99 us") == 0U);
    PFL_EXPECT(inter_arrival_histogram_count(*analysis, "100-999 us") == 0U);
    PFL_EXPECT(inter_arrival_histogram_count(*analysis, "1-9.9 ms") == 0U);
    PFL_EXPECT(inter_arrival_histogram_count(*analysis, "10-99 ms") == 0U);
    PFL_EXPECT(inter_arrival_histogram_count(*analysis, "100-499 ms") == 0U);
    PFL_EXPECT(inter_arrival_histogram_count(*analysis, "500-999 ms") == 0U);
    PFL_EXPECT(inter_arrival_histogram_count(*analysis, "1-8 s") == 2U);
    PFL_EXPECT(inter_arrival_histogram_count(*analysis, "8 s+") == 0U);
    PFL_EXPECT(analysis->packet_size_histogram_rows.size() == 10U);
    PFL_EXPECT(packet_histogram_count(*analysis, "0-63") == 0U);
    PFL_EXPECT(packet_histogram_count(*analysis, "64-127") == 3U);
    PFL_EXPECT(packet_histogram_count(*analysis, "128-255") == 0U);
    PFL_EXPECT(packet_histogram_count(*analysis, "256-511") == 0U);
    PFL_EXPECT(packet_histogram_count(*analysis, "512-1023") == 0U);
    PFL_EXPECT(packet_histogram_count(*analysis, "1024-1399") == 0U);
    PFL_EXPECT(packet_histogram_count(*analysis, "1400-1499") == 0U);
    PFL_EXPECT(packet_histogram_count(*analysis, "1500-2499") == 0U);
    PFL_EXPECT(packet_histogram_count(*analysis, "2500-5000") == 0U);
    PFL_EXPECT(packet_histogram_count(*analysis, "5001+") == 0U);
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
    PFL_EXPECT(inter_arrival_histogram_count(*heavy_analysis, "1-8 s") == 24U);
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
    const auto bucket_1024_1399_packet = make_ethernet_ipv4_tcp_packet_with_payload(
        ipv4(10, 1, 0, 1), ipv4(10, 1, 0, 2), 41000, 443, 1000, 0x18
    );
    const auto bucket_1400_1499_packet = make_ethernet_ipv4_tcp_packet_with_payload(
        ipv4(10, 1, 0, 1), ipv4(10, 1, 0, 2), 41000, 443, 1376, 0x18
    );
    const auto bucket_1500_2499_packet = make_ethernet_ipv4_tcp_packet_with_payload(
        ipv4(10, 1, 0, 1), ipv4(10, 1, 0, 2), 41000, 443, 1476, 0x18
    );
    const auto bucket_2500_5000_packet = make_ethernet_ipv4_tcp_packet_with_payload(
        ipv4(10, 1, 0, 1), ipv4(10, 1, 0, 2), 41000, 443, 2476, 0x18
    );
    const auto bucket_5001_plus_packet = make_ethernet_ipv4_tcp_packet_with_payload(
        ipv4(10, 1, 0, 1), ipv4(10, 1, 0, 2), 41000, 443, 5000, 0x18
    );

    const auto histogram_capture_path = write_temp_pcap(
        "pfl_flow_analysis_histogram.pcap",
        make_classic_pcap({
            {100U, bucket_0_63_packet},
            {110U, bucket_64_127_packet},
            {120U, bucket_128_255_packet},
            {130U, bucket_256_511_packet},
            {140U, bucket_512_1023_packet},
            {150U, bucket_1024_1399_packet},
            {160U, bucket_1400_1499_packet},
            {170U, bucket_1500_2499_packet},
            {180U, bucket_2500_5000_packet},
            {190U, bucket_5001_plus_packet},
        })
    );

    CaptureSession histogram_session {};
    PFL_EXPECT(histogram_session.open_capture(histogram_capture_path));
    const auto histogram_rows = histogram_session.list_flows();
    PFL_EXPECT(histogram_rows.size() == 1U);
    const auto histogram_analysis = histogram_session.get_flow_analysis(histogram_rows.front().index);
    PFL_EXPECT(histogram_analysis.has_value());
    PFL_EXPECT(histogram_analysis->total_packets == 10U);
    PFL_EXPECT(histogram_analysis->packet_size_histogram_rows.size() == 10U);
    PFL_EXPECT(packet_histogram_count(*histogram_analysis, "0-63") == 1U);
    PFL_EXPECT(packet_histogram_count(*histogram_analysis, "64-127") == 1U);
    PFL_EXPECT(packet_histogram_count(*histogram_analysis, "128-255") == 1U);
    PFL_EXPECT(packet_histogram_count(*histogram_analysis, "256-511") == 1U);
    PFL_EXPECT(packet_histogram_count(*histogram_analysis, "512-1023") == 1U);
    PFL_EXPECT(packet_histogram_count(*histogram_analysis, "1024-1399") == 1U);
    PFL_EXPECT(packet_histogram_count(*histogram_analysis, "1400-1499") == 1U);
    PFL_EXPECT(packet_histogram_count(*histogram_analysis, "1500-2499") == 1U);
    PFL_EXPECT(packet_histogram_count(*histogram_analysis, "2500-5000") == 1U);
    PFL_EXPECT(packet_histogram_count(*histogram_analysis, "5001+") == 1U);
    PFL_EXPECT(
        packet_histogram_count(*histogram_analysis, "0-63") +
        packet_histogram_count(*histogram_analysis, "64-127") +
        packet_histogram_count(*histogram_analysis, "128-255") +
        packet_histogram_count(*histogram_analysis, "256-511") +
        packet_histogram_count(*histogram_analysis, "512-1023") +
        packet_histogram_count(*histogram_analysis, "1024-1399") +
        packet_histogram_count(*histogram_analysis, "1400-1499") +
        packet_histogram_count(*histogram_analysis, "1500-2499") +
        packet_histogram_count(*histogram_analysis, "2500-5000") +
        packet_histogram_count(*histogram_analysis, "5001+") == histogram_analysis->total_packets
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
    PFL_EXPECT(inter_arrival_analysis->inter_arrival_histogram_rows.size() == 9U);
    PFL_EXPECT(inter_arrival_histogram_count(*inter_arrival_analysis, "0-9 us") == 0U);
    PFL_EXPECT(inter_arrival_histogram_count(*inter_arrival_analysis, "10-99 us") == 1U);
    PFL_EXPECT(inter_arrival_histogram_count(*inter_arrival_analysis, "100-999 us") == 1U);
    PFL_EXPECT(inter_arrival_histogram_count(*inter_arrival_analysis, "1-9.9 ms") == 1U);
    PFL_EXPECT(inter_arrival_histogram_count(*inter_arrival_analysis, "10-99 ms") == 1U);
    PFL_EXPECT(inter_arrival_histogram_count(*inter_arrival_analysis, "100-499 ms") == 0U);
    PFL_EXPECT(inter_arrival_histogram_count(*inter_arrival_analysis, "500-999 ms") == 1U);
    PFL_EXPECT(inter_arrival_histogram_count(*inter_arrival_analysis, "1-8 s") == 1U);
    PFL_EXPECT(inter_arrival_histogram_count(*inter_arrival_analysis, "8 s+") == 0U);
    PFL_EXPECT(
        inter_arrival_histogram_count(*inter_arrival_analysis, "0-9 us") +
        inter_arrival_histogram_count(*inter_arrival_analysis, "10-99 us") +
        inter_arrival_histogram_count(*inter_arrival_analysis, "100-999 us") +
        inter_arrival_histogram_count(*inter_arrival_analysis, "1-9.9 ms") +
        inter_arrival_histogram_count(*inter_arrival_analysis, "10-99 ms") +
        inter_arrival_histogram_count(*inter_arrival_analysis, "100-499 ms") +
        inter_arrival_histogram_count(*inter_arrival_analysis, "500-999 ms") +
        inter_arrival_histogram_count(*inter_arrival_analysis, "1-8 s") +
        inter_arrival_histogram_count(*inter_arrival_analysis, "8 s+") == inter_arrival_analysis->total_packets - 1U
    );

    const auto directional_histogram_connection = make_protocol_panel_connection(
        FlowProtocolHint::unknown,
        ProtocolId::tcp,
        {
            make_analysis_packet_ref_at(0U, 0U, 63U, 0U),
            make_analysis_packet_ref_at(2U, 99U, 1400U, 0U),
            make_analysis_packet_ref_at(4U, 9999U, 5001U, 0U),
            make_analysis_packet_ref_at(6U, 499999U, 1500U, 0U),
            make_analysis_packet_ref_at(8U, 7999999U, 1024U, 0U),
        },
        {
            make_analysis_packet_ref_at(1U, 9U, 64U, 0U),
            make_analysis_packet_ref_at(3U, 999U, 2500U, 0U),
            make_analysis_packet_ref_at(5U, 99999U, 512U, 0U),
            make_analysis_packet_ref_at(7U, 999999U, 128U, 0U),
            make_analysis_packet_ref_at(9U, 16000000U, 5000U, 0U),
        }
    );
    FlowAnalysisService directional_histogram_service {};
    const auto directional_histogram_analysis = directional_histogram_service.analyze(directional_histogram_connection);
    PFL_EXPECT(directional_histogram_analysis.packet_size_histograms.histogram_all.size() == 10U);
    PFL_EXPECT(directional_histogram_analysis.packet_size_histograms.histogram_a_to_b.size() == 10U);
    PFL_EXPECT(directional_histogram_analysis.packet_size_histograms.histogram_b_to_a.size() == 10U);
    PFL_EXPECT(packet_histogram_count(directional_histogram_analysis.packet_size_histograms.histogram_a_to_b, "0-63") == 1U);
    PFL_EXPECT(packet_histogram_count(directional_histogram_analysis.packet_size_histograms.histogram_a_to_b, "1400-1499") == 1U);
    PFL_EXPECT(packet_histogram_count(directional_histogram_analysis.packet_size_histograms.histogram_a_to_b, "1500-2499") == 1U);
    PFL_EXPECT(packet_histogram_count(directional_histogram_analysis.packet_size_histograms.histogram_a_to_b, "1024-1399") == 1U);
    PFL_EXPECT(packet_histogram_count(directional_histogram_analysis.packet_size_histograms.histogram_a_to_b, "5001+") == 1U);
    PFL_EXPECT(packet_histogram_count(directional_histogram_analysis.packet_size_histograms.histogram_b_to_a, "64-127") == 1U);
    PFL_EXPECT(packet_histogram_count(directional_histogram_analysis.packet_size_histograms.histogram_b_to_a, "128-255") == 1U);
    PFL_EXPECT(packet_histogram_count(directional_histogram_analysis.packet_size_histograms.histogram_b_to_a, "512-1023") == 1U);
    PFL_EXPECT(packet_histogram_count(directional_histogram_analysis.packet_size_histograms.histogram_b_to_a, "2500-5000") == 2U);
    PFL_EXPECT(histogram_total_count(directional_histogram_analysis.packet_size_histograms.histogram_all) == 10U);
    PFL_EXPECT(
        histogram_total_count(directional_histogram_analysis.packet_size_histograms.histogram_all) ==
        histogram_total_count(directional_histogram_analysis.packet_size_histograms.histogram_a_to_b) +
        histogram_total_count(directional_histogram_analysis.packet_size_histograms.histogram_b_to_a)
    );
    PFL_EXPECT(directional_histogram_analysis.inter_arrival_histograms.histogram_all.size() == 9U);
    PFL_EXPECT(inter_arrival_histogram_count(directional_histogram_analysis.inter_arrival_histograms.histogram_all, "0-9 us") == 1U);
    PFL_EXPECT(inter_arrival_histogram_count(directional_histogram_analysis.inter_arrival_histograms.histogram_all, "10-99 us") == 1U);
    PFL_EXPECT(inter_arrival_histogram_count(directional_histogram_analysis.inter_arrival_histograms.histogram_all, "100-999 us") == 1U);
    PFL_EXPECT(inter_arrival_histogram_count(directional_histogram_analysis.inter_arrival_histograms.histogram_all, "1-9.9 ms") == 1U);
    PFL_EXPECT(inter_arrival_histogram_count(directional_histogram_analysis.inter_arrival_histograms.histogram_all, "10-99 ms") == 1U);
    PFL_EXPECT(inter_arrival_histogram_count(directional_histogram_analysis.inter_arrival_histograms.histogram_all, "100-499 ms") == 1U);
    PFL_EXPECT(inter_arrival_histogram_count(directional_histogram_analysis.inter_arrival_histograms.histogram_all, "500-999 ms") == 1U);
    PFL_EXPECT(inter_arrival_histogram_count(directional_histogram_analysis.inter_arrival_histograms.histogram_all, "1-8 s") == 1U);
    PFL_EXPECT(inter_arrival_histogram_count(directional_histogram_analysis.inter_arrival_histograms.histogram_all, "8 s+") == 1U);
    PFL_EXPECT(inter_arrival_histogram_count(directional_histogram_analysis.inter_arrival_histograms.histogram_a_to_b, "10-99 us") == 1U);
    PFL_EXPECT(inter_arrival_histogram_count(directional_histogram_analysis.inter_arrival_histograms.histogram_a_to_b, "1-9.9 ms") == 1U);
    PFL_EXPECT(inter_arrival_histogram_count(directional_histogram_analysis.inter_arrival_histograms.histogram_a_to_b, "100-499 ms") == 1U);
    PFL_EXPECT(inter_arrival_histogram_count(directional_histogram_analysis.inter_arrival_histograms.histogram_a_to_b, "1-8 s") == 1U);
    PFL_EXPECT(inter_arrival_histogram_count(directional_histogram_analysis.inter_arrival_histograms.histogram_b_to_a, "0-9 us") == 1U);
    PFL_EXPECT(inter_arrival_histogram_count(directional_histogram_analysis.inter_arrival_histograms.histogram_b_to_a, "100-999 us") == 1U);
    PFL_EXPECT(inter_arrival_histogram_count(directional_histogram_analysis.inter_arrival_histograms.histogram_b_to_a, "10-99 ms") == 1U);
    PFL_EXPECT(inter_arrival_histogram_count(directional_histogram_analysis.inter_arrival_histograms.histogram_b_to_a, "500-999 ms") == 1U);
    PFL_EXPECT(inter_arrival_histogram_count(directional_histogram_analysis.inter_arrival_histograms.histogram_b_to_a, "8 s+") == 1U);
    PFL_EXPECT(
        histogram_total_count(directional_histogram_analysis.inter_arrival_histograms.histogram_all) ==
        histogram_total_count(directional_histogram_analysis.inter_arrival_histograms.histogram_a_to_b) +
        histogram_total_count(directional_histogram_analysis.inter_arrival_histograms.histogram_b_to_a)
    );

    const auto single_packet_capture_path = write_temp_pcap(
        "pfl_flow_analysis_single_packet_metrics.pcap",
        make_classic_pcap({
            {100U, request_packet},
        })
    );

    CaptureSession single_packet_session {};
    PFL_EXPECT(single_packet_session.open_capture(single_packet_capture_path));
    const auto single_packet_rows = single_packet_session.list_flows();
    PFL_EXPECT(single_packet_rows.size() == 1U);
    const auto single_packet_analysis = single_packet_session.get_flow_analysis(single_packet_rows.front().index);
    PFL_EXPECT(single_packet_analysis.has_value());
    PFL_EXPECT(single_packet_analysis->total_packets == 1U);
    PFL_EXPECT(single_packet_analysis->duration_us == 0U);
    PFL_EXPECT(nearly_equal(single_packet_analysis->packets_per_second, 0.0));
    PFL_EXPECT(nearly_equal(single_packet_analysis->bytes_per_second, 0.0));
    PFL_EXPECT(nearly_equal(single_packet_analysis->average_packet_size_bytes, static_cast<double>(request_packet.size())));
    PFL_EXPECT(nearly_equal(single_packet_analysis->average_inter_arrival_us, 0.0));
    PFL_EXPECT(single_packet_analysis->min_packet_size_bytes == request_packet.size());
    PFL_EXPECT(single_packet_analysis->max_packet_size_bytes == request_packet.size());
    PFL_EXPECT(single_packet_analysis->min_packet_size_a_to_b_bytes == request_packet.size());
    PFL_EXPECT(single_packet_analysis->max_packet_size_a_to_b_bytes == request_packet.size());
    PFL_EXPECT(single_packet_analysis->min_packet_size_b_to_a_bytes == 0U);
    PFL_EXPECT(single_packet_analysis->max_packet_size_b_to_a_bytes == 0U);
    PFL_EXPECT(single_packet_analysis->packet_ratio_text == "1 : 0");
    PFL_EXPECT(single_packet_analysis->byte_ratio_text == "1 : 0");
    PFL_EXPECT(single_packet_analysis->packet_direction_text == "Mostly A->B");
    PFL_EXPECT(single_packet_analysis->data_direction_text == "Mostly A->B");

    const auto ratio_packet_a = make_ethernet_ipv4_tcp_packet_with_payload(
        ipv4(10, 3, 0, 1), ipv4(10, 3, 0, 2), 43000, 443, 40, 0x18
    );
    const auto ratio_packet_b = make_ethernet_ipv4_tcp_packet_with_payload(
        ipv4(10, 3, 0, 2), ipv4(10, 3, 0, 1), 443, 43000, 40, 0x18
    );

    const auto balanced_capture_path = write_temp_pcap(
        "pfl_flow_analysis_directional_ratio_balanced.pcap",
        make_classic_pcap({
            {100U, ratio_packet_a},
            {200U, ratio_packet_a},
            {300U, ratio_packet_b},
        })
    );

    CaptureSession balanced_session {};
    PFL_EXPECT(balanced_session.open_capture(balanced_capture_path));
    const auto balanced_rows = balanced_session.list_flows();
    PFL_EXPECT(balanced_rows.size() == 1U);
    const auto balanced_analysis = balanced_session.get_flow_analysis(balanced_rows.front().index);
    PFL_EXPECT(balanced_analysis.has_value());
    PFL_EXPECT(balanced_analysis->packet_ratio_text == "2 : 1");
    PFL_EXPECT(balanced_analysis->byte_ratio_text == "2 : 1");
    PFL_EXPECT(balanced_analysis->packet_direction_text == "Balanced");
    PFL_EXPECT(balanced_analysis->data_direction_text == "Balanced");

    const auto a_dominant_capture_path = write_temp_pcap(
        "pfl_flow_analysis_directional_ratio_a_dominant.pcap",
        make_classic_pcap({
            {100U, ratio_packet_a},
            {200U, ratio_packet_a},
            {300U, ratio_packet_a},
            {400U, ratio_packet_a},
            {500U, ratio_packet_b},
        })
    );

    CaptureSession a_dominant_session {};
    PFL_EXPECT(a_dominant_session.open_capture(a_dominant_capture_path));
    const auto a_dominant_rows = a_dominant_session.list_flows();
    PFL_EXPECT(a_dominant_rows.size() == 1U);
    const auto a_dominant_analysis = a_dominant_session.get_flow_analysis(a_dominant_rows.front().index);
    PFL_EXPECT(a_dominant_analysis.has_value());
    PFL_EXPECT(a_dominant_analysis->packet_ratio_text == "4 : 1");
    PFL_EXPECT(a_dominant_analysis->byte_ratio_text == "4 : 1");
    PFL_EXPECT(a_dominant_analysis->packet_direction_text == "Mostly A->B");
    PFL_EXPECT(a_dominant_analysis->data_direction_text == "Mostly A->B");

    const auto b_dominant_capture_path = write_temp_pcap(
        "pfl_flow_analysis_directional_ratio_b_dominant.pcap",
        make_classic_pcap({
            {100U, ratio_packet_a},
            {200U, ratio_packet_b},
            {300U, ratio_packet_b},
            {400U, ratio_packet_b},
            {500U, ratio_packet_b},
        })
    );

    CaptureSession b_dominant_session {};
    PFL_EXPECT(b_dominant_session.open_capture(b_dominant_capture_path));
    const auto b_dominant_rows = b_dominant_session.list_flows();
    PFL_EXPECT(b_dominant_rows.size() == 1U);
    const auto b_dominant_analysis = b_dominant_session.get_flow_analysis(b_dominant_rows.front().index);
    PFL_EXPECT(b_dominant_analysis.has_value());
    PFL_EXPECT(b_dominant_analysis->packet_ratio_text == "1 : 4");
    PFL_EXPECT(b_dominant_analysis->byte_ratio_text == "1 : 4");
    PFL_EXPECT(b_dominant_analysis->packet_direction_text == "Mostly B->A");
    PFL_EXPECT(b_dominant_analysis->data_direction_text == "Mostly B->A");

    const auto packet_balanced_byte_skewed_connection = make_protocol_panel_connection(
        FlowProtocolHint::unknown,
        ProtocolId::tcp,
        {
            make_analysis_packet_ref(0U, 100U, 1200U, 0U),
            make_analysis_packet_ref(2U, 300U, 1200U, 0U),
        },
        {
            make_analysis_packet_ref(1U, 200U, 100U, 0U),
            make_analysis_packet_ref(3U, 400U, 100U, 0U),
        }
    );
    FlowAnalysisService direction_summary_service {};
    const auto packet_balanced_byte_skewed_analysis = direction_summary_service.analyze(packet_balanced_byte_skewed_connection);
    PFL_EXPECT(packet_balanced_byte_skewed_analysis.packet_direction_text == "Balanced");
    PFL_EXPECT(packet_balanced_byte_skewed_analysis.data_direction_text == "Mostly A->B");

    const auto byte_balanced_packet_skewed_connection = make_protocol_panel_connection(
        FlowProtocolHint::unknown,
        ProtocolId::tcp,
        {
            make_analysis_packet_ref(0U, 100U, 100U, 0U),
            make_analysis_packet_ref(2U, 300U, 100U, 0U),
            make_analysis_packet_ref(4U, 500U, 100U, 0U),
            make_analysis_packet_ref(6U, 700U, 100U, 0U),
        },
        {
            make_analysis_packet_ref(1U, 200U, 400U, 0U),
        }
    );
    const auto byte_balanced_packet_skewed_analysis = direction_summary_service.analyze(byte_balanced_packet_skewed_connection);
    PFL_EXPECT(byte_balanced_packet_skewed_analysis.packet_direction_text == "Mostly A->B");
    PFL_EXPECT(byte_balanced_packet_skewed_analysis.data_direction_text == "Balanced");

    const auto zero_direction_analysis = direction_summary_service.analyze(make_protocol_panel_connection(
        FlowProtocolHint::unknown,
        ProtocolId::tcp,
        {},
        {}
    ));
    PFL_EXPECT(zero_direction_analysis.packet_direction_text == "Balanced");
    PFL_EXPECT(zero_direction_analysis.data_direction_text == "Balanced");

    const auto b_only_connection = make_protocol_panel_connection(
        FlowProtocolHint::unknown,
        ProtocolId::tcp,
        {},
        {
            make_analysis_packet_ref(0U, 100U, 256U, 0U),
            make_analysis_packet_ref(1U, 200U, 256U, 0U),
        }
    );
    const auto b_only_analysis = direction_summary_service.analyze(b_only_connection);
    PFL_EXPECT(b_only_analysis.packet_direction_text == "Mostly B->A");
    PFL_EXPECT(b_only_analysis.data_direction_text == "Mostly B->A");

    FlowAnalysisService analysis_service {};

    const auto tls_connection = make_protocol_panel_connection(
        FlowProtocolHint::tls,
        ProtocolId::tcp,
        {
            make_analysis_packet_ref(0U, 100U, 96U, 42U, 0x02U),
            make_analysis_packet_ref(2U, 300U, 88U, 30U, 0x01U),
        },
        {
            make_analysis_packet_ref(1U, 200U, 90U, 28U, 0x12U),
            make_analysis_packet_ref(3U, 400U, 84U, 24U, 0x04U),
        },
        "auth.split.io",
        QuicVersionHint::unknown,
        TlsVersionHint::tls12
    );
    const auto tls_analysis = analysis_service.analyze(tls_connection);
    PFL_EXPECT(tls_analysis.protocol_panel_version_text == "TLS 1.2");
    PFL_EXPECT(tls_analysis.protocol_panel_service_text == "auth.split.io");
    PFL_EXPECT(tls_analysis.has_tcp_control_counts);
    PFL_EXPECT(tls_analysis.tcp_syn_packets == 2U);
    PFL_EXPECT(tls_analysis.tcp_fin_packets == 1U);
    PFL_EXPECT(tls_analysis.tcp_rst_packets == 1U);
    PFL_EXPECT(tls_analysis.protocol_panel_fallback_text.empty());

    const auto quic_connection = make_protocol_panel_connection(
        FlowProtocolHint::quic,
        ProtocolId::udp,
        {
            make_analysis_packet_ref(0U, 100U, 120U, 80U),
        },
        {
            make_analysis_packet_ref(1U, 200U, 110U, 70U),
        },
        "bag.itunes.apple.com",
        QuicVersionHint::v1
    );
    const auto quic_analysis = analysis_service.analyze(quic_connection);
    PFL_EXPECT(quic_analysis.protocol_panel_version_text == "QUIC v1");
    PFL_EXPECT(quic_analysis.protocol_panel_service_text == "bag.itunes.apple.com");
    PFL_EXPECT(!quic_analysis.has_tcp_control_counts);
    PFL_EXPECT(quic_analysis.protocol_panel_fallback_text.empty());

    const auto fallback_connection = make_protocol_panel_connection(
        FlowProtocolHint::dns,
        ProtocolId::udp,
        {
            make_analysis_packet_ref(0U, 100U, 72U, 30U),
        },
        {}
    );
    const auto fallback_analysis = analysis_service.analyze(fallback_connection);
    PFL_EXPECT(fallback_analysis.protocol_panel_version_text.empty());
    PFL_EXPECT(fallback_analysis.protocol_panel_service_text.empty());
    PFL_EXPECT(!fallback_analysis.has_tcp_control_counts);
    PFL_EXPECT(fallback_analysis.protocol_panel_fallback_text == "No protocol-specific metadata available");

    const auto burst_connection = make_burst_summary_connection(
        {
            make_analysis_packet_ref(0U, 100U, 80U, 10U),
            make_analysis_packet_ref(2U, 800U, 100U, 30U),
            make_analysis_packet_ref(4U, 200500U, 120U, 50U),
        },
        {
            make_analysis_packet_ref(1U, 500U, 90U, 20U),
            make_analysis_packet_ref(3U, 200000U, 110U, 40U),
            make_analysis_packet_ref(5U, 400000U, 70U, 12U),
        }
    );
    const auto burst_analysis = analysis_service.analyze(burst_connection);
    PFL_EXPECT(burst_analysis.burst_count == 2U);
    PFL_EXPECT(burst_analysis.longest_burst_packet_count == 3U);
    PFL_EXPECT(burst_analysis.largest_burst_bytes == 270U);
    PFL_EXPECT(burst_analysis.idle_gap_count == 2U);
    PFL_EXPECT(burst_analysis.largest_idle_gap_us == 199500U);

    const auto single_burst_packet_connection = make_burst_summary_connection(
        {
            make_analysis_packet_ref(0U, 100U, 64U, 10U),
        },
        {}
    );
    const auto single_burst_packet_analysis = analysis_service.analyze(single_burst_packet_connection);
    PFL_EXPECT(single_burst_packet_analysis.burst_count == 0U);
    PFL_EXPECT(single_burst_packet_analysis.longest_burst_packet_count == 0U);
    PFL_EXPECT(single_burst_packet_analysis.largest_burst_bytes == 0U);
    PFL_EXPECT(single_burst_packet_analysis.idle_gap_count == 0U);
    PFL_EXPECT(single_burst_packet_analysis.largest_idle_gap_us == 0U);

    const auto rate_graph_connection = make_protocol_panel_connection(
        FlowProtocolHint::unknown,
        ProtocolId::tcp,
        {
            make_analysis_packet_ref_at(0U, 0U, 100U, 0U),
            make_analysis_packet_ref_at(1U, 5000U, 200U, 0U),
            make_analysis_packet_ref_at(3U, 41000U, 300U, 0U),
        },
        {
            make_analysis_packet_ref_at(2U, 25000U, 400U, 0U),
        }
    );
    const auto rate_graph_analysis = analysis_service.analyze(rate_graph_connection);
    PFL_EXPECT(rate_graph_analysis.rate_graph.available);
    PFL_EXPECT(rate_graph_analysis.rate_graph.status_text.empty());
    PFL_EXPECT(rate_graph_analysis.rate_graph.window_us == 10000U);
    PFL_EXPECT(rate_graph_analysis.rate_graph.points_a_to_b.size() == rate_graph_analysis.rate_graph.points_b_to_a.size());
    PFL_EXPECT(rate_graph_analysis.rate_graph.points_a_to_b.size() == 5U);
    PFL_EXPECT(has_constant_window_spacing(rate_graph_analysis.rate_graph.points_a_to_b, rate_graph_analysis.rate_graph.window_us));
    PFL_EXPECT(has_constant_window_spacing(rate_graph_analysis.rate_graph.points_b_to_a, rate_graph_analysis.rate_graph.window_us));

    const auto* a_start_point = rate_point_at(rate_graph_analysis.rate_graph.points_a_to_b, 0U);
    PFL_EXPECT(a_start_point != nullptr);
    PFL_EXPECT(nearly_equal(a_start_point->packets_per_second, 200.0));
    PFL_EXPECT(nearly_equal(a_start_point->data_per_second, 30000.0));

    const auto* b_mid_point = rate_point_at(rate_graph_analysis.rate_graph.points_b_to_a, 20000U);
    PFL_EXPECT(b_mid_point != nullptr);
    PFL_EXPECT(nearly_equal(b_mid_point->packets_per_second, 100.0));
    PFL_EXPECT(nearly_equal(b_mid_point->data_per_second, 40000.0));

    const auto* a_tail_point = rate_point_at(rate_graph_analysis.rate_graph.points_a_to_b, 40000U);
    PFL_EXPECT(a_tail_point != nullptr);
    PFL_EXPECT(nearly_equal(a_tail_point->packets_per_second, 100.0));
    PFL_EXPECT(nearly_equal(a_tail_point->data_per_second, 30000.0));

    const auto* empty_a_window = rate_point_at(rate_graph_analysis.rate_graph.points_a_to_b, 10000U);
    PFL_EXPECT(empty_a_window != nullptr);
    PFL_EXPECT(nearly_equal(empty_a_window->packets_per_second, 0.0));
    PFL_EXPECT(nearly_equal(empty_a_window->data_per_second, 0.0));

    const auto* empty_b_window = rate_point_at(rate_graph_analysis.rate_graph.points_b_to_a, 10000U);
    PFL_EXPECT(empty_b_window != nullptr);
    PFL_EXPECT(nearly_equal(empty_b_window->packets_per_second, 0.0));
    PFL_EXPECT(nearly_equal(empty_b_window->data_per_second, 0.0));

    const auto total_packets_from_series =
        total_packets_from_rate_series(rate_graph_analysis.rate_graph.points_a_to_b, rate_graph_analysis.rate_graph.window_us)
        + total_packets_from_rate_series(rate_graph_analysis.rate_graph.points_b_to_a, rate_graph_analysis.rate_graph.window_us);
    const auto total_bytes_from_series =
        total_bytes_from_rate_series(rate_graph_analysis.rate_graph.points_a_to_b, rate_graph_analysis.rate_graph.window_us)
        + total_bytes_from_rate_series(rate_graph_analysis.rate_graph.points_b_to_a, rate_graph_analysis.rate_graph.window_us);
    PFL_EXPECT(nearly_equal(total_packets_from_series, 4.0));
    PFL_EXPECT(nearly_equal(total_bytes_from_series, 1000.0));

    std::vector<PacketRef> capped_rate_a_packets {};
    std::vector<PacketRef> capped_rate_b_packets {};
    capped_rate_a_packets.reserve(120U);
    capped_rate_b_packets.reserve(120U);
    for (std::uint64_t index = 0; index < 240U; ++index) {
        const auto timestamp_us = index * 1000000U;
        if ((index % 2U) == 0U) {
            capped_rate_a_packets.push_back(make_analysis_packet_ref_at(index, timestamp_us, 120U, 0U));
        } else {
            capped_rate_b_packets.push_back(make_analysis_packet_ref_at(index, timestamp_us, 80U, 0U));
        }
    }

    const auto capped_rate_connection = make_protocol_panel_connection(
        FlowProtocolHint::unknown,
        ProtocolId::udp,
        capped_rate_a_packets,
        capped_rate_b_packets
    );
    const auto capped_rate_analysis = analysis_service.analyze(capped_rate_connection);
    PFL_EXPECT(capped_rate_analysis.rate_graph.available);
    PFL_EXPECT(capped_rate_analysis.rate_graph.window_us >= 1000000U);
    PFL_EXPECT(capped_rate_analysis.rate_graph.points_a_to_b.size() <= 100U);
    PFL_EXPECT(capped_rate_analysis.rate_graph.points_a_to_b.size() == capped_rate_analysis.rate_graph.points_b_to_a.size());

    const auto short_rate_analysis = analysis_service.analyze(make_protocol_panel_connection(
        FlowProtocolHint::unknown,
        ProtocolId::tcp,
        {
            make_analysis_packet_ref_at(0U, 0U, 90U, 0U),
        },
        {}
    ));
    PFL_EXPECT(!short_rate_analysis.rate_graph.available);
    PFL_EXPECT(short_rate_analysis.rate_graph.points_a_to_b.empty());
    PFL_EXPECT(short_rate_analysis.rate_graph.points_b_to_a.empty());
    PFL_EXPECT(short_rate_analysis.rate_graph.status_text == "Flow too short for rate graph");
    const auto empty_connection = make_burst_summary_connection({}, {});
    const auto empty_analysis = analysis_service.analyze(empty_connection);
    PFL_EXPECT(empty_analysis.total_packets == 0U);
    PFL_EXPECT(empty_analysis.burst_count == 0U);
    PFL_EXPECT(empty_analysis.longest_burst_packet_count == 0U);
    PFL_EXPECT(empty_analysis.largest_burst_bytes == 0U);
    PFL_EXPECT(empty_analysis.idle_gap_count == 0U);
    PFL_EXPECT(empty_analysis.largest_idle_gap_us == 0U);
    PFL_EXPECT(!empty_analysis.rate_graph.available);
    PFL_EXPECT(empty_analysis.rate_graph.points_a_to_b.empty());
    PFL_EXPECT(empty_analysis.rate_graph.points_b_to_a.empty());
    PFL_EXPECT(empty_analysis.rate_graph.status_text == "Flow too short for rate graph");
}

}  // namespace pfl::tests



