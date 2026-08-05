#include <cstdint>
#include <filesystem>
#include <limits>
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
#include "core/domain/CapturePacketSizeStatistics.h"
#include "core/domain/Connection.h"
#include "core/index/CaptureIndex.h"

namespace pfl::tests {

namespace {

std::filesystem::path fixture_path(const std::filesystem::path& relative_path) {
    return std::filesystem::path(__FILE__).parent_path().parent_path() / "data" / relative_path;
}

struct HistogramInputConnections {
    std::vector<ConnectionV4> storage {};
    std::vector<session_detail::ListedConnectionRef> refs {};
};

struct HistogramFlowInput {
    std::uint64_t packet_count {0};
    std::uint64_t original_byte_count {0};
};

HistogramInputConnections make_histogram_input_connections(const std::vector<HistogramFlowInput>& flows) {
    HistogramInputConnections input {};
    input.storage.reserve(flows.size());
    input.refs.reserve(flows.size());

    for (std::size_t index = 0U; index < flows.size(); ++index) {
        ConnectionV4 connection {};
        connection.packet_count = flows[index].packet_count;
        connection.total_bytes = flows[index].original_byte_count;
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

const CapturePacketSizeStatisticsBucket* find_bucket(
    const CapturePacketSizeStatistics& statistics,
    const std::string_view stable_id
) {
    for (const auto& bucket : statistics.buckets) {
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

const FrontendCapturePacketSizeStatisticsBucketDto* find_bucket(
    const FrontendCapturePacketSizeStatisticsDto& statistics,
    const std::string_view stable_id
) {
    for (const auto& bucket : statistics.buckets) {
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
    const std::uint64_t expected_original_byte_count,
    const std::uint64_t expected_lower_bound,
    const std::optional<std::uint64_t> expected_upper_bound
) {
    const auto* bucket = find_bucket(histogram, stable_id);
    PFL_REQUIRE(bucket != nullptr);
    PFL_EXPECT(bucket->flow_count == expected_count);
    PFL_EXPECT(bucket->original_byte_count == expected_original_byte_count);
    PFL_EXPECT(bucket->lower_bound_inclusive == expected_lower_bound);
    PFL_EXPECT(bucket->upper_bound_inclusive == expected_upper_bound);
}

void expect_capture_packet_size_bucket(
    const CapturePacketSizeStatistics& statistics,
    const std::string_view stable_id,
    const std::uint64_t expected_packet_count,
    const std::uint32_t expected_lower_bound,
    const std::optional<std::uint32_t> expected_upper_bound
) {
    const auto* bucket = find_bucket(statistics, stable_id);
    PFL_REQUIRE(bucket != nullptr);
    PFL_EXPECT(bucket->packet_count == expected_packet_count);
    PFL_EXPECT(bucket->lower_bound_inclusive == expected_lower_bound);
    PFL_EXPECT(bucket->upper_bound_inclusive == expected_upper_bound);
}

void expect_histogram_equal(const FlowPacketCountHistogram& left, const FlowPacketCountHistogram& right) {
    PFL_EXPECT(left.total_flow_count == right.total_flow_count);
    PFL_EXPECT(left.total_original_byte_count == right.total_original_byte_count);
    PFL_EXPECT(left.maximum_bucket_flow_count == right.maximum_bucket_flow_count);
    PFL_EXPECT(left.maximum_bucket_original_byte_count == right.maximum_bucket_original_byte_count);
    PFL_EXPECT(left.excluded_zero_packet_flow_count == right.excluded_zero_packet_flow_count);
    PFL_EXPECT(left.excluded_zero_packet_original_byte_count == right.excluded_zero_packet_original_byte_count);
    PFL_EXPECT(left.buckets.size() == right.buckets.size());

    for (std::size_t index = 0U; index < left.buckets.size(); ++index) {
        PFL_EXPECT(left.buckets[index].stable_id == right.buckets[index].stable_id);
        PFL_EXPECT(left.buckets[index].lower_bound_inclusive == right.buckets[index].lower_bound_inclusive);
        PFL_EXPECT(left.buckets[index].upper_bound_inclusive == right.buckets[index].upper_bound_inclusive);
        PFL_EXPECT(left.buckets[index].flow_count == right.buckets[index].flow_count);
        PFL_EXPECT(left.buckets[index].original_byte_count == right.buckets[index].original_byte_count);
    }
}

std::vector<std::uint8_t> malformed_ipv4_frame() {
    std::vector<std::uint8_t> bytes {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
        0x08, 0x00,
        0x45, 0x00, 0x00,
    };
    return bytes;
}

std::vector<std::uint8_t> unrecognized_ethernet_frame() {
    std::vector<std::uint8_t> bytes {
        0x10, 0x20, 0x30, 0x40, 0x50, 0x60,
        0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0,
        0x88, 0xb5,
        0x01, 0x02, 0x03, 0x04,
    };
    return bytes;
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
        {1U, 100U},
        {2U, 200U},
        {3U, 300U},
        {5U, 500U},
        {6U, 600U},
        {10U, 1000U},
        {11U, 1100U},
        {25U, 2500U},
        {26U, 2600U},
        {50U, 5000U},
        {51U, 5100U},
        {100U, 10000U},
        {101U, 10100U},
        {250U, 25000U},
        {251U, 25100U},
        {500U, 50000U},
        {501U, 50100U},
        {1000U, 100000U},
        {1001U, 100100U},
        {5000U, 500000U},
        {5001U, 500100U},
    });
    const auto histogram = session_detail::build_flow_packet_count_histogram(input.refs);

    PFL_EXPECT(histogram.total_flow_count == 21U);
    PFL_EXPECT(histogram.total_original_byte_count == 1389500U);
    PFL_EXPECT(histogram.maximum_bucket_flow_count == 2U);
    PFL_EXPECT(histogram.maximum_bucket_original_byte_count == 600100U);
    PFL_EXPECT(histogram.excluded_zero_packet_flow_count == 0U);
    PFL_EXPECT(histogram.excluded_zero_packet_original_byte_count == 0U);
    PFL_EXPECT(histogram.buckets.size() == 12U);

    expect_histogram_bucket(histogram, "packets_1", 1U, 100U, 1U, 1U);
    expect_histogram_bucket(histogram, "packets_2", 1U, 200U, 2U, 2U);
    expect_histogram_bucket(histogram, "packets_3_5", 2U, 800U, 3U, 5U);
    expect_histogram_bucket(histogram, "packets_6_10", 2U, 1600U, 6U, 10U);
    expect_histogram_bucket(histogram, "packets_11_25", 2U, 3600U, 11U, 25U);
    expect_histogram_bucket(histogram, "packets_26_50", 2U, 7600U, 26U, 50U);
    expect_histogram_bucket(histogram, "packets_51_100", 2U, 15100U, 51U, 100U);
    expect_histogram_bucket(histogram, "packets_101_250", 2U, 35100U, 101U, 250U);
    expect_histogram_bucket(histogram, "packets_251_500", 2U, 75100U, 251U, 500U);
    expect_histogram_bucket(histogram, "packets_501_1000", 2U, 150100U, 501U, 1000U);
    expect_histogram_bucket(histogram, "packets_1001_5000", 2U, 600100U, 1001U, 5000U);
    expect_histogram_bucket(histogram, "packets_5001_plus", 1U, 500100U, 5001U, std::nullopt);

    std::uint64_t summed_flow_count {0};
    std::uint64_t summed_original_byte_count {0};
    for (const auto& bucket : histogram.buckets) {
        summed_flow_count += bucket.flow_count;
        summed_original_byte_count += bucket.original_byte_count;
    }
    PFL_EXPECT(summed_flow_count == histogram.total_flow_count);
    PFL_EXPECT(summed_original_byte_count == histogram.total_original_byte_count);
}

void expect_flow_packet_count_histogram_zero_packet_behavior() {
    const auto input = make_histogram_input_connections({
        {0U, 4096U},
        {1U, 0U},
        {2U, 512U},
        {2U, 1536U},
    });
    const auto histogram = session_detail::build_flow_packet_count_histogram(input.refs);

    PFL_EXPECT(histogram.total_flow_count == 3U);
    PFL_EXPECT(histogram.total_original_byte_count == 2048U);
    PFL_EXPECT(histogram.maximum_bucket_flow_count == 2U);
    PFL_EXPECT(histogram.maximum_bucket_original_byte_count == 2048U);
    PFL_EXPECT(histogram.excluded_zero_packet_flow_count == 1U);
    PFL_EXPECT(histogram.excluded_zero_packet_original_byte_count == 4096U);
    expect_histogram_bucket(histogram, "packets_1", 1U, 0U, 1U, 1U);
    expect_histogram_bucket(histogram, "packets_2", 2U, 2048U, 2U, 2U);
}

void expect_flow_packet_count_histogram_supports_empty_inputs() {
    const auto input = make_histogram_input_connections(std::vector<HistogramFlowInput> {});
    const auto histogram = session_detail::build_flow_packet_count_histogram(input.refs);

    PFL_EXPECT(histogram.total_flow_count == 0U);
    PFL_EXPECT(histogram.total_original_byte_count == 0U);
    PFL_EXPECT(histogram.maximum_bucket_flow_count == 0U);
    PFL_EXPECT(histogram.maximum_bucket_original_byte_count == 0U);
    PFL_EXPECT(histogram.excluded_zero_packet_flow_count == 0U);
    PFL_EXPECT(histogram.excluded_zero_packet_original_byte_count == 0U);
    PFL_EXPECT(histogram.buckets.size() == 12U);
    for (const auto& bucket : histogram.buckets) {
        PFL_EXPECT(bucket.flow_count == 0U);
        PFL_EXPECT(bucket.original_byte_count == 0U);
    }
}

void expect_flow_packet_count_histogram_handles_large_original_byte_totals() {
    const auto near_max = std::numeric_limits<std::uint64_t>::max() - 4096U;
    const auto input = make_histogram_input_connections({
        {1U, 1024U},
        {2U, near_max},
        {2U, 512U},
    });
    const auto histogram = session_detail::build_flow_packet_count_histogram(input.refs);

    const auto expected_bucket_two_total = near_max + 512U;
    const auto expected_histogram_total = expected_bucket_two_total + 1024U;
    PFL_EXPECT(histogram.total_flow_count == 3U);
    PFL_EXPECT(histogram.total_original_byte_count == expected_histogram_total);
    PFL_EXPECT(histogram.maximum_bucket_original_byte_count == expected_bucket_two_total);
    expect_histogram_bucket(histogram, "packets_1", 1U, 1024U, 1U, 1U);
    expect_histogram_bucket(histogram, "packets_2", 2U, expected_bucket_two_total, 2U, 2U);
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
    cached_connection->total_bytes = 999999U;
    const auto cached_histogram = session.flow_packet_count_histogram();
    expect_histogram_equal(first_histogram, cached_histogram);

    PFL_REQUIRE(session.open_capture(second_capture));
    const auto second_histogram = session.flow_packet_count_histogram();
    PFL_EXPECT(second_histogram.total_flow_count == 1U);
    PFL_EXPECT(second_histogram.total_original_byte_count > 0U);
    expect_histogram_bucket(
        second_histogram,
        "packets_2",
        1U,
        second_histogram.total_original_byte_count,
        2U,
        2U
    );
}

void expect_capture_packet_size_statistics_boundaries() {
    CapturePacketSizeStatistics statistics {};
    const std::vector<std::uint32_t> lengths {
        0U,
        63U,
        64U,
        127U,
        128U,
        255U,
        256U,
        511U,
        512U,
        1023U,
        1024U,
        1399U,
        1400U,
        1499U,
        1500U,
        2499U,
        2500U,
        5000U,
        5001U,
        9000U,
        9001U,
        16000U,
        16001U,
        25000U,
        25001U,
        std::numeric_limits<std::uint32_t>::max(),
    };

    for (const auto length : lengths) {
        accumulate_capture_packet_size(statistics, length);
    }

    PFL_EXPECT(statistics.total_packet_count == lengths.size());
    PFL_EXPECT(statistics.maximum_bucket_packet_count == 2U);
    PFL_EXPECT(statistics.maximum_captured_packet_length == std::numeric_limits<std::uint32_t>::max());
    expect_capture_packet_size_bucket(statistics, "captured_bytes_0_63", 2U, 0U, 63U);
    expect_capture_packet_size_bucket(statistics, "captured_bytes_64_127", 2U, 64U, 127U);
    expect_capture_packet_size_bucket(statistics, "captured_bytes_128_255", 2U, 128U, 255U);
    expect_capture_packet_size_bucket(statistics, "captured_bytes_256_511", 2U, 256U, 511U);
    expect_capture_packet_size_bucket(statistics, "captured_bytes_512_1023", 2U, 512U, 1023U);
    expect_capture_packet_size_bucket(statistics, "captured_bytes_1024_1399", 2U, 1024U, 1399U);
    expect_capture_packet_size_bucket(statistics, "captured_bytes_1400_1499", 2U, 1400U, 1499U);
    expect_capture_packet_size_bucket(statistics, "captured_bytes_1500_2499", 2U, 1500U, 2499U);
    expect_capture_packet_size_bucket(statistics, "captured_bytes_2500_5000", 2U, 2500U, 5000U);
    expect_capture_packet_size_bucket(statistics, "captured_bytes_5001_9000", 2U, 5001U, 9000U);
    expect_capture_packet_size_bucket(statistics, "captured_bytes_9001_16000", 2U, 9001U, 16000U);
    expect_capture_packet_size_bucket(statistics, "captured_bytes_16001_25000", 2U, 16001U, 25000U);
    expect_capture_packet_size_bucket(statistics, "captured_bytes_25001_plus", 2U, 25001U, std::nullopt);
}

void expect_capture_packet_size_statistics_supports_empty_state() {
    const CapturePacketSizeStatistics statistics {};
    PFL_EXPECT(statistics.total_packet_count == 0U);
    PFL_EXPECT(statistics.maximum_bucket_packet_count == 0U);
    PFL_EXPECT(statistics.maximum_captured_packet_length == 0U);
    for (const auto& bucket : statistics.buckets) {
        PFL_EXPECT(bucket.packet_count == 0U);
    }
}

void expect_capture_packet_size_statistics_counts_recognized_and_unrecognized_packets() {
    const auto recognized_packet = make_ethernet_ipv4_tcp_packet(ipv4(10, 60, 0, 1), ipv4(10, 60, 0, 2), 6001, 443);
    const auto unrecognized_packet = unrecognized_ethernet_frame();
    const auto capture_path = write_temp_pcap(
        "pfl_capture_packet_size_recognized_unrecognized.pcap",
        make_classic_pcap({
            {100U, recognized_packet},
            {200U, unrecognized_packet},
        })
    );

    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(capture_path));

    const auto& statistics = session.packet_size_statistics();
    PFL_EXPECT(statistics.total_packet_count == 2U);
    PFL_EXPECT(statistics.maximum_bucket_packet_count == 2U);
    PFL_EXPECT(statistics.maximum_captured_packet_length == static_cast<std::uint32_t>(recognized_packet.size()));
    PFL_EXPECT(session.summary().packet_count == 1U);
    PFL_EXPECT(session.unrecognized_packet_count() == 1U);
}

void expect_capture_packet_size_statistics_counts_decode_malformed_packets() {
    const auto recognized_packet = make_ethernet_ipv4_tcp_packet(ipv4(10, 61, 0, 1), ipv4(10, 61, 0, 2), 6101, 443);
    const auto malformed_packet = malformed_ipv4_frame();
    const auto capture_path = write_temp_pcap(
        "pfl_capture_packet_size_malformed.pcap",
        make_classic_pcap({
            {100U, recognized_packet},
            {200U, malformed_packet},
        })
    );

    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(capture_path));

    const auto& statistics = session.packet_size_statistics();
    PFL_EXPECT(statistics.total_packet_count == 2U);
    PFL_EXPECT(statistics.maximum_captured_packet_length == static_cast<std::uint32_t>(recognized_packet.size()));
    expect_capture_packet_size_bucket(statistics, "captured_bytes_0_63", 2U, 0U, 63U);
}

void expect_capture_packet_size_statistics_excludes_unreadable_truncated_tail() {
    const auto first_packet = make_ethernet_ipv4_tcp_packet(ipv4(10, 62, 0, 1), ipv4(10, 62, 0, 2), 6201, 443);
    const auto second_packet = make_ethernet_ipv4_tcp_packet(ipv4(10, 62, 0, 3), ipv4(10, 62, 0, 4), 6202, 443);
    auto truncated_capture = make_classic_pcap({
        {100U, first_packet},
        {200U, second_packet},
    });
    truncated_capture.resize(truncated_capture.size() - 8U);

    const auto capture_path = write_temp_pcap(
        "pfl_capture_packet_size_truncated_tail.pcap",
        truncated_capture
    );

    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(capture_path));

    const auto& statistics = session.packet_size_statistics();
    PFL_EXPECT(statistics.total_packet_count == 1U);
    PFL_EXPECT(statistics.maximum_bucket_packet_count == 1U);
    PFL_EXPECT(statistics.maximum_captured_packet_length == static_cast<std::uint32_t>(first_packet.size()));
}

void expect_capture_packet_size_statistics_counts_supported_pcapng_packets() {
    const auto recognized_packet = make_ethernet_ipv4_tcp_packet(ipv4(10, 63, 0, 1), ipv4(10, 63, 0, 2), 6301, 443);
    const auto unrecognized_packet = unrecognized_ethernet_frame();
    const auto capture_path = write_temp_pcap(
        "pfl_capture_packet_size_pcapng.pcapng",
        make_pcapng({
            make_pcapng_section_header_block(),
            make_pcapng_interface_description_block(),
            make_pcapng_enhanced_packet_block(0U, 1U, 100U, recognized_packet),
            make_pcapng_enhanced_packet_block(0U, 2U, 200U, unrecognized_packet),
        })
    );

    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(capture_path));

    const auto& statistics = session.packet_size_statistics();
    PFL_EXPECT(statistics.total_packet_count == 2U);
    PFL_EXPECT(statistics.maximum_captured_packet_length == static_cast<std::uint32_t>(recognized_packet.size()));
}

void expect_capture_packet_size_statistics_survives_index_roundtrip() {
    const auto recognized_packet = make_ethernet_ipv4_tcp_packet(ipv4(10, 64, 0, 1), ipv4(10, 64, 0, 2), 6401, 443);
    const auto unrecognized_packet = unrecognized_ethernet_frame();
    const auto capture_path = write_temp_pcap(
        "pfl_capture_packet_size_roundtrip.pcap",
        make_classic_pcap({
            {100U, recognized_packet},
            {200U, unrecognized_packet},
        })
    );

    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(capture_path));
    const auto imported_statistics = session.packet_size_statistics();

    const auto index_path = std::filesystem::temp_directory_path() / "pfl_capture_packet_size_roundtrip.idx";
    std::filesystem::remove(index_path);
    PFL_REQUIRE(session.save_index(index_path));
    PFL_EXPECT(kCaptureIndexVersion == 13U);

    CaptureSession loaded_session {};
    PFL_REQUIRE(loaded_session.load_index(index_path));
    const auto loaded_statistics = loaded_session.packet_size_statistics();

    PFL_EXPECT(imported_statistics.total_packet_count == loaded_statistics.total_packet_count);
    PFL_EXPECT(imported_statistics.maximum_bucket_packet_count == loaded_statistics.maximum_bucket_packet_count);
    PFL_EXPECT(imported_statistics.maximum_captured_packet_length == loaded_statistics.maximum_captured_packet_length);
    PFL_EXPECT(imported_statistics.buckets.size() == loaded_statistics.buckets.size());
    for (std::size_t index = 0U; index < imported_statistics.buckets.size(); ++index) {
        PFL_EXPECT(imported_statistics.buckets[index].stable_id == loaded_statistics.buckets[index].stable_id);
        PFL_EXPECT(imported_statistics.buckets[index].packet_count == loaded_statistics.buckets[index].packet_count);
    }
    PFL_EXPECT(
        loaded_statistics.total_packet_count ==
        loaded_session.summary().packet_count +
            static_cast<std::uint64_t>(loaded_session.unrecognized_packet_count())
    );
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
    const auto packet_size_statistics = adapter.get_capture_packet_size_statistics();
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

    PFL_EXPECT(packet_size_statistics.has_capture);
    PFL_EXPECT(packet_size_statistics.total_packet_count == 4U);
    PFL_EXPECT(packet_size_statistics.maximum_captured_packet_length > 0U);
    PFL_EXPECT(!packet_size_statistics.maximum_captured_packet_length_text.empty());
    PFL_REQUIRE(find_bucket(packet_size_statistics, "captured_bytes_0_63") != nullptr);
    PFL_EXPECT(find_bucket(packet_size_statistics, "captured_bytes_0_63")->label == "0-63");

    PFL_EXPECT(histogram.has_capture);
    PFL_EXPECT(histogram.total_flow_count == 3U);
    PFL_EXPECT(histogram.total_original_byte_count > 0U);
    PFL_EXPECT(histogram.maximum_bucket_flow_count == 2U);
    PFL_EXPECT(histogram.maximum_bucket_original_byte_count > 0U);
    PFL_EXPECT(histogram.excluded_zero_packet_original_byte_count == 0U);
    PFL_REQUIRE(find_bucket(histogram, "packets_1") != nullptr);
    PFL_REQUIRE(find_bucket(histogram, "packets_2") != nullptr);
    PFL_EXPECT(find_bucket(histogram, "packets_1")->label == "1");
    PFL_EXPECT(find_bucket(histogram, "packets_2")->label == "2");
    PFL_EXPECT(find_bucket(histogram, "packets_1")->normalized_flow_fraction == 1.0);
    PFL_EXPECT(find_bucket(histogram, "packets_2")->normalized_flow_fraction == 0.5);
    PFL_EXPECT(find_bucket(histogram, "packets_1")->original_byte_count_text.find('B') != std::string::npos);
    PFL_EXPECT(find_bucket(histogram, "packets_2")->normalized_original_byte_fraction > 0.0);
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

    const auto packet_size_statistics = adapter.get_capture_packet_size_statistics();
    const auto histogram = adapter.get_flow_packet_count_histogram();
    const auto hints = adapter.get_protocol_hint_statistics();
    const auto quic_tls = adapter.get_quic_tls_statistics();
    const auto top = adapter.get_top_endpoint_port_statistics(5U);

    PFL_EXPECT(!packet_size_statistics.has_capture);
    PFL_EXPECT(packet_size_statistics.total_packet_count == 0U);
    PFL_EXPECT(packet_size_statistics.maximum_bucket_packet_count == 0U);
    PFL_EXPECT(packet_size_statistics.maximum_captured_packet_length == 0U);
    PFL_EXPECT(packet_size_statistics.maximum_captured_packet_length_text.empty());
    PFL_EXPECT(packet_size_statistics.buckets.empty());
    PFL_EXPECT(!histogram.has_capture);
    PFL_EXPECT(histogram.total_original_byte_count == 0U);
    PFL_EXPECT(histogram.maximum_bucket_original_byte_count == 0U);
    PFL_EXPECT(histogram.excluded_zero_packet_original_byte_count == 0U);
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
    const auto packet_size_json = take_bridge_string(
        pfl_frontend_session_adapter_get_capture_packet_size_statistics_json(handle)
    );
    PFL_EXPECT(contains_text(packet_size_json, "\"total_packet_count\""));
    PFL_EXPECT(contains_text(packet_size_json, "\"maximum_bucket_packet_count\""));
    PFL_EXPECT(contains_text(packet_size_json, "\"maximum_captured_packet_length\""));
    PFL_EXPECT(contains_text(packet_size_json, "\"maximum_captured_packet_length_text\""));
    PFL_EXPECT(contains_text(packet_size_json, "\"bucket_id\":\"captured_bytes_0_63\""));
    PFL_EXPECT(contains_text(packet_size_json, "\"label\":\"0-63\""));
    PFL_EXPECT(contains_text(packet_size_json, "\"normalized_fraction\""));
    PFL_EXPECT(contains_text(histogram_json, "\"total_original_byte_count\""));
    PFL_EXPECT(contains_text(histogram_json, "\"maximum_bucket_flow_count\""));
    PFL_EXPECT(contains_text(histogram_json, "\"maximum_bucket_original_byte_count\""));
    PFL_EXPECT(contains_text(histogram_json, "\"excluded_zero_packet_flow_count\""));
    PFL_EXPECT(contains_text(histogram_json, "\"excluded_zero_packet_original_byte_count\""));
    PFL_EXPECT(contains_text(histogram_json, "\"bucket_id\":\"packets_2\""));
    PFL_EXPECT(contains_text(histogram_json, "\"label\":\"2\""));
    PFL_EXPECT(contains_text(histogram_json, "\"original_byte_count\""));
    PFL_EXPECT(contains_text(histogram_json, "\"original_byte_count_text\""));
    PFL_EXPECT(contains_text(histogram_json, "\"normalized_flow_fraction\""));
    PFL_EXPECT(contains_text(histogram_json, "\"normalized_original_byte_fraction\""));

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
    expect_flow_packet_count_histogram_handles_large_original_byte_totals();
    expect_flow_packet_count_histogram_survives_index_roundtrip();
    expect_flow_packet_count_histogram_is_cached_per_capture();
    expect_capture_packet_size_statistics_boundaries();
    expect_capture_packet_size_statistics_supports_empty_state();
    expect_capture_packet_size_statistics_counts_recognized_and_unrecognized_packets();
    expect_capture_packet_size_statistics_counts_decode_malformed_packets();
    expect_capture_packet_size_statistics_excludes_unreadable_truncated_tail();
    expect_capture_packet_size_statistics_counts_supported_pcapng_packets();
    expect_capture_packet_size_statistics_survives_index_roundtrip();
    expect_overview_excludes_optional_statistics_sections();
    expect_quic_tls_section_keeps_one_empty_side();
    expect_statistics_section_requests_handle_missing_capture();
    expect_statistics_section_bridge_json_shapes();
}

}  // namespace pfl::tests
