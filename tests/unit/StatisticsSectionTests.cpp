#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "TestSupport.h"
#include "PcapTestUtils.h"
#include "app/frontend/FrontendSessionAdapter.h"
#include "app/frontend/FrontendSessionAdapterBridge.h"
#include "app/session/CaptureSession.h"
#include "app/session/SessionFlowHelpers.h"
#include "core/domain/Connection.h"

namespace pfl::tests {

namespace {

std::filesystem::path fixture_path(const std::filesystem::path& relative_path) {
    return std::filesystem::path(__FILE__).parent_path().parent_path() / "data" / relative_path;
}

struct HistogramInputConnections {
    std::vector<ConnectionV4> storage {};
    std::vector<session_detail::ListedConnectionRef> refs {};
};

HistogramInputConnections make_histogram_input_connections(const std::vector<std::uint64_t>& packet_counts) {
    HistogramInputConnections input {};
    input.storage.reserve(packet_counts.size());
    input.refs.reserve(packet_counts.size());

    for (std::size_t index = 0U; index < packet_counts.size(); ++index) {
        ConnectionV4 connection {};
        connection.packet_count = packet_counts[index];
        connection.key.first.addr = ipv4(10, 0, 0, static_cast<std::uint8_t>(index + 1U));
        connection.key.first.port = static_cast<std::uint16_t>(1000U + index);
        connection.key.second.addr = ipv4(10, 0, 1, static_cast<std::uint8_t>(index + 1U));
        connection.key.second.port = static_cast<std::uint16_t>(2000U + index);
        input.storage.push_back(connection);
    }

    for (auto& connection : input.storage) {
        input.refs.push_back(session_detail::ListedConnectionRef {
            .family = FlowAddressFamily::ipv4,
            .ipv4 = &connection,
            .ipv6 = nullptr,
        });
    }

    return input;
}

const FlowPacketCountHistogramBucket* find_bucket(
    const FlowPacketCountHistogram& histogram,
    const std::string_view stable_id
) {
    for (const auto& bucket : histogram.buckets) {
        if (bucket.stable_id == stable_id) {
            return &bucket;
        }
    }
    return nullptr;
}

const FrontendFlowPacketCountHistogramBucketDto* find_bucket(
    const FrontendFlowPacketCountHistogramDto& histogram,
    const std::string_view stable_id
) {
    for (const auto& bucket : histogram.buckets) {
        if (bucket.bucket_id == stable_id) {
            return &bucket;
        }
    }
    return nullptr;
}

void expect_histogram_bucket(
    const FlowPacketCountHistogram& histogram,
    const std::string_view stable_id,
    const std::uint64_t expected_count,
    const std::uint64_t expected_lower_bound,
    const std::optional<std::uint64_t> expected_upper_bound
) {
    const auto* bucket = find_bucket(histogram, stable_id);
    PFL_REQUIRE(bucket != nullptr);
    PFL_EXPECT(bucket->flow_count == expected_count);
    PFL_EXPECT(bucket->lower_bound_inclusive == expected_lower_bound);
    PFL_EXPECT(bucket->upper_bound_inclusive == expected_upper_bound);
}

void expect_histogram_equal(const FlowPacketCountHistogram& left, const FlowPacketCountHistogram& right) {
    PFL_EXPECT(left.total_flow_count == right.total_flow_count);
    PFL_EXPECT(left.maximum_bucket_flow_count == right.maximum_bucket_flow_count);
    PFL_EXPECT(left.excluded_zero_packet_flow_count == right.excluded_zero_packet_flow_count);
    PFL_EXPECT(left.buckets.size() == right.buckets.size());

    for (std::size_t index = 0U; index < left.buckets.size(); ++index) {
        PFL_EXPECT(left.buckets[index].stable_id == right.buckets[index].stable_id);
        PFL_EXPECT(left.buckets[index].lower_bound_inclusive == right.buckets[index].lower_bound_inclusive);
        PFL_EXPECT(left.buckets[index].upper_bound_inclusive == right.buckets[index].upper_bound_inclusive);
        PFL_EXPECT(left.buckets[index].flow_count == right.buckets[index].flow_count);
    }
}

std::string take_bridge_string(char* value) {
    PFL_REQUIRE(value != nullptr);
    const std::string text {value};
    pfl_frontend_string_free(value);
    return text;
}

bool contains_text(const std::string& text, const std::string_view fragment) {
    return text.find(fragment) != std::string::npos;
}

void expect_flow_packet_count_histogram_boundaries() {
    const auto input = make_histogram_input_connections({
        1U, 2U, 3U, 5U, 6U, 10U, 11U, 25U, 26U, 50U, 51U,
        100U, 101U, 250U, 251U, 500U, 501U, 1000U, 1001U, 5000U, 5001U
    });
    const auto histogram = session_detail::build_flow_packet_count_histogram(input.refs);

    PFL_EXPECT(histogram.total_flow_count == 21U);
    PFL_EXPECT(histogram.maximum_bucket_flow_count == 2U);
    PFL_EXPECT(histogram.excluded_zero_packet_flow_count == 0U);
    PFL_EXPECT(histogram.buckets.size() == 12U);

    expect_histogram_bucket(histogram, "packets_1", 1U, 1U, 1U);
    expect_histogram_bucket(histogram, "packets_2", 1U, 2U, 2U);
    expect_histogram_bucket(histogram, "packets_3_5", 2U, 3U, 5U);
    expect_histogram_bucket(histogram, "packets_6_10", 2U, 6U, 10U);
    expect_histogram_bucket(histogram, "packets_11_25", 2U, 11U, 25U);
    expect_histogram_bucket(histogram, "packets_26_50", 2U, 26U, 50U);
    expect_histogram_bucket(histogram, "packets_51_100", 2U, 51U, 100U);
    expect_histogram_bucket(histogram, "packets_101_250", 2U, 101U, 250U);
    expect_histogram_bucket(histogram, "packets_251_500", 2U, 251U, 500U);
    expect_histogram_bucket(histogram, "packets_501_1000", 2U, 501U, 1000U);
    expect_histogram_bucket(histogram, "packets_1001_5000", 2U, 1001U, 5000U);
    expect_histogram_bucket(histogram, "packets_5001_plus", 1U, 5001U, std::nullopt);

    std::uint64_t summed_flow_count {0};
    for (const auto& bucket : histogram.buckets) {
        summed_flow_count += bucket.flow_count;
    }
    PFL_EXPECT(summed_flow_count == histogram.total_flow_count);
}

void expect_flow_packet_count_histogram_zero_packet_behavior() {
    const auto input = make_histogram_input_connections({0U, 1U, 2U, 2U});
    const auto histogram = session_detail::build_flow_packet_count_histogram(input.refs);

    PFL_EXPECT(histogram.total_flow_count == 3U);
    PFL_EXPECT(histogram.maximum_bucket_flow_count == 2U);
    PFL_EXPECT(histogram.excluded_zero_packet_flow_count == 1U);
    expect_histogram_bucket(histogram, "packets_1", 1U, 1U, 1U);
    expect_histogram_bucket(histogram, "packets_2", 2U, 2U, 2U);
}

void expect_flow_packet_count_histogram_supports_empty_inputs() {
    const auto input = make_histogram_input_connections({});
    const auto histogram = session_detail::build_flow_packet_count_histogram(input.refs);

    PFL_EXPECT(histogram.total_flow_count == 0U);
    PFL_EXPECT(histogram.maximum_bucket_flow_count == 0U);
    PFL_EXPECT(histogram.excluded_zero_packet_flow_count == 0U);
    PFL_EXPECT(histogram.buckets.size() == 12U);
    for (const auto& bucket : histogram.buckets) {
        PFL_EXPECT(bucket.flow_count == 0U);
    }
}

void expect_flow_packet_count_histogram_survives_index_roundtrip() {
    const auto tcp_ab = make_ethernet_ipv4_tcp_packet(ipv4(10, 0, 0, 1), ipv4(10, 0, 0, 2), 1111, 80);
    const auto tcp_ba = make_ethernet_ipv4_tcp_packet(ipv4(10, 0, 0, 2), ipv4(10, 0, 0, 1), 80, 1111);
    const auto udp_single = make_ethernet_ipv4_udp_packet(ipv4(10, 0, 0, 3), ipv4(10, 0, 0, 4), 4000, 53);
    const auto capture_path = write_temp_pcap(
        "pfl_statistics_histogram_roundtrip.pcap",
        make_classic_pcap({
            {100, tcp_ab},
            {200, tcp_ba},
            {300, udp_single},
        })
    );

    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(capture_path));
    const auto imported_histogram = session.flow_packet_count_histogram();

    const auto index_path = std::filesystem::temp_directory_path() / "pfl_statistics_histogram_roundtrip.idx";
    std::filesystem::remove(index_path);
    PFL_REQUIRE(session.save_index(index_path));

    CaptureSession loaded_session {};
    PFL_REQUIRE(loaded_session.load_index(index_path));
    const auto loaded_histogram = loaded_session.flow_packet_count_histogram();
    expect_histogram_equal(imported_histogram, loaded_histogram);
}

void expect_flow_packet_count_histogram_is_cached_per_capture() {
    const auto first_capture = write_temp_pcap(
        "pfl_statistics_histogram_cache_first.pcap",
        make_classic_pcap({
            {100, make_ethernet_ipv4_tcp_packet(ipv4(10, 0, 0, 1), ipv4(10, 0, 0, 2), 1111, 80)},
        })
    );
    const auto second_capture = write_temp_pcap(
        "pfl_statistics_histogram_cache_second.pcap",
        make_classic_pcap({
            {100, make_ethernet_ipv4_tcp_packet(ipv4(10, 0, 1, 1), ipv4(10, 0, 1, 2), 1112, 80)},
            {200, make_ethernet_ipv4_tcp_packet(ipv4(10, 0, 1, 2), ipv4(10, 0, 1, 1), 80, 1112)},
        })
    );

    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(first_capture));
    const auto first_histogram = session.flow_packet_count_histogram();
    auto* cached_connection = const_cast<ConnectionV4*>(session.state().ipv4_connections.list().front());
    cached_connection->packet_count = 5001U;
    const auto cached_histogram = session.flow_packet_count_histogram();
    expect_histogram_equal(first_histogram, cached_histogram);

    PFL_REQUIRE(session.open_capture(second_capture));
    const auto second_histogram = session.flow_packet_count_histogram();
    PFL_EXPECT(second_histogram.total_flow_count == 1U);
    expect_histogram_bucket(second_histogram, "packets_2", 1U, 2U, 2U);
}

void expect_overview_excludes_optional_statistics_sections() {
    const auto tcp_ab = make_ethernet_ipv4_tcp_packet(ipv4(10, 0, 0, 1), ipv4(10, 0, 0, 2), 1111, 80);
    const auto tcp_ba = make_ethernet_ipv4_tcp_packet(ipv4(10, 0, 0, 2), ipv4(10, 0, 0, 1), 80, 1111);
    const auto udp_ac = make_ethernet_ipv4_udp_packet(ipv4(10, 0, 0, 1), ipv4(10, 0, 0, 3), 1111, 22);
    const auto udp_de = make_ethernet_ipv4_udp_packet(ipv4(10, 0, 0, 4), ipv4(10, 0, 0, 5), 53000, 53);
    const auto capture_path = write_temp_pcap(
        "pfl_statistics_sections_adapter_parity.pcap",
        make_classic_pcap({
            {100, tcp_ab},
            {200, tcp_ba},
            {300, udp_ac},
            {400, udp_de},
        })
    );

    FrontendSessionAdapter adapter {};
    PFL_REQUIRE(adapter.open_capture(capture_path).opened);

    const auto overview = adapter.get_overview();
    const auto hint_statistics = adapter.get_protocol_hint_statistics();
    const auto quic_tls_statistics = adapter.get_quic_tls_statistics();
    const auto top_statistics = adapter.get_top_endpoint_port_statistics(5U);
    const auto histogram = adapter.get_flow_packet_count_histogram();

    PFL_EXPECT(overview.has_capture);
    PFL_EXPECT(overview.summary.flow_count == 3U);
    PFL_EXPECT(overview.protocol_summary.tcp.flow_count == 1U);
    PFL_EXPECT(overview.protocol_summary.udp.flow_count == 2U);

    PFL_EXPECT(hint_statistics.has_capture);
    PFL_EXPECT(hint_statistics.protocol_hints.size() == 13U);

    PFL_EXPECT(quic_tls_statistics.has_capture);
    PFL_EXPECT(quic_tls_statistics.quic_recognition.total_flows == 0U);
    PFL_EXPECT(quic_tls_statistics.tls_recognition.total_flows == 0U);

    PFL_EXPECT(top_statistics.has_capture);
    PFL_EXPECT(top_statistics.limit == 5U);
    PFL_EXPECT(!top_statistics.top_endpoints.empty());
    PFL_EXPECT(!top_statistics.top_ports.empty());

    PFL_EXPECT(histogram.has_capture);
    PFL_EXPECT(histogram.total_flow_count == 3U);
    PFL_EXPECT(histogram.maximum_bucket_flow_count == 2U);
    PFL_REQUIRE(find_bucket(histogram, "packets_1") != nullptr);
    PFL_REQUIRE(find_bucket(histogram, "packets_2") != nullptr);
    PFL_EXPECT(find_bucket(histogram, "packets_1")->label == "1");
    PFL_EXPECT(find_bucket(histogram, "packets_2")->label == "2");
}

void expect_quic_tls_section_keeps_one_empty_side() {
    {
        FrontendSessionAdapter adapter {};
        PFL_REQUIRE(adapter.open_capture(fixture_path("parsing/tls/tls_1_2_badssl_baseline_14.pcap")).opened);
        const auto statistics = adapter.get_quic_tls_statistics();
        PFL_EXPECT(statistics.has_capture);
        PFL_EXPECT(statistics.tls_recognition.total_flows > 0U);
        PFL_EXPECT(statistics.quic_recognition.total_flows == 0U);
    }

    {
        FrontendSessionAdapter adapter {};
        PFL_REQUIRE(adapter.open_capture(fixture_path("parsing/quic/quic_initial_ack_decrypt_ok_1.pcap")).opened);
        const auto statistics = adapter.get_quic_tls_statistics();
        PFL_EXPECT(statistics.has_capture);
        PFL_EXPECT(statistics.quic_recognition.total_flows > 0U);
        PFL_EXPECT(statistics.tls_recognition.total_flows == 0U);
    }
}

void expect_statistics_section_requests_handle_missing_capture() {
    FrontendSessionAdapter adapter {};

    const auto histogram = adapter.get_flow_packet_count_histogram();
    const auto hints = adapter.get_protocol_hint_statistics();
    const auto quic_tls = adapter.get_quic_tls_statistics();
    const auto top = adapter.get_top_endpoint_port_statistics(5U);

    PFL_EXPECT(!histogram.has_capture);
    PFL_EXPECT(histogram.buckets.empty());
    PFL_EXPECT(!hints.has_capture);
    PFL_EXPECT(hints.protocol_hints.empty());
    PFL_EXPECT(!quic_tls.has_capture);
    PFL_EXPECT(quic_tls.quic_recognition.total_flows == 0U);
    PFL_EXPECT(quic_tls.tls_recognition.total_flows == 0U);
    PFL_EXPECT(!top.has_capture);
    PFL_EXPECT(top.top_endpoints.empty());
    PFL_EXPECT(top.top_ports.empty());
}

void expect_statistics_section_bridge_json_shapes() {
    auto* handle = pfl_frontend_session_adapter_new();
    PFL_REQUIRE(handle != nullptr);

    const auto capture_path = write_temp_pcap(
        "pfl_statistics_sections_bridge_json.pcap",
        make_classic_pcap({
            {100, make_ethernet_ipv4_tcp_packet(ipv4(10, 0, 0, 1), ipv4(10, 0, 0, 2), 1111, 80)},
            {200, make_ethernet_ipv4_tcp_packet(ipv4(10, 0, 0, 2), ipv4(10, 0, 0, 1), 80, 1111)},
        })
    );
    const auto open_json = take_bridge_string(
        pfl_frontend_session_adapter_open_capture_json(handle, capture_path.string().c_str())
    );
    PFL_EXPECT(contains_text(open_json, "\"opened\":true"));

    const auto histogram_json = take_bridge_string(pfl_frontend_session_adapter_get_flow_packet_count_histogram_json(handle));
    PFL_EXPECT(contains_text(histogram_json, "\"maximum_bucket_flow_count\""));
    PFL_EXPECT(contains_text(histogram_json, "\"excluded_zero_packet_flow_count\""));
    PFL_EXPECT(contains_text(histogram_json, "\"bucket_id\":\"packets_2\""));
    PFL_EXPECT(contains_text(histogram_json, "\"label\":\"2\""));

    const auto overview_json = take_bridge_string(pfl_frontend_session_adapter_get_overview_json(handle));
    PFL_EXPECT(contains_text(overview_json, "\"protocol_summary\""));
    PFL_EXPECT(contains_text(overview_json, "\"protocol_path_presentations\""));
    PFL_EXPECT(!contains_text(overview_json, "\"protocol_hints\""));
    PFL_EXPECT(!contains_text(overview_json, "\"quic_recognition\""));
    PFL_EXPECT(!contains_text(overview_json, "\"tls_recognition\""));
    PFL_EXPECT(!contains_text(overview_json, "\"top_endpoints\""));
    PFL_EXPECT(!contains_text(overview_json, "\"top_ports\""));

    const auto hints_json = take_bridge_string(pfl_frontend_session_adapter_get_protocol_hint_statistics_json(handle));
    PFL_EXPECT(contains_text(hints_json, "\"protocol_hints\""));
    PFL_EXPECT(contains_text(hints_json, "\"group\""));
    PFL_EXPECT(contains_text(hints_json, "\"protocol_label\""));

    const auto quic_tls_json = take_bridge_string(pfl_frontend_session_adapter_get_quic_tls_statistics_json(handle));
    PFL_EXPECT(contains_text(quic_tls_json, "\"quic_recognition\""));
    PFL_EXPECT(contains_text(quic_tls_json, "\"tls_recognition\""));

    const auto top_json = take_bridge_string(pfl_frontend_session_adapter_get_top_endpoint_port_statistics_json(handle, 5U));
    PFL_EXPECT(contains_text(top_json, "\"top_endpoints\""));
    PFL_EXPECT(contains_text(top_json, "\"top_ports\""));
    PFL_EXPECT(contains_text(top_json, "\"limit\":5"));

    pfl_frontend_session_adapter_free(handle);
}

}  // namespace

void run_statistics_section_tests() {
    expect_flow_packet_count_histogram_boundaries();
    expect_flow_packet_count_histogram_zero_packet_behavior();
    expect_flow_packet_count_histogram_supports_empty_inputs();
    expect_flow_packet_count_histogram_survives_index_roundtrip();
    expect_flow_packet_count_histogram_is_cached_per_capture();
    expect_overview_excludes_optional_statistics_sections();
    expect_quic_tls_section_keeps_one_empty_side();
    expect_statistics_section_requests_handle_missing_capture();
    expect_statistics_section_bridge_json_shapes();
}

}  // namespace pfl::tests
