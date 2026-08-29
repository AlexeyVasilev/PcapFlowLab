#include <cstdint>
#include <filesystem>
#include <fstream>
#include <limits>
#include <numeric>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "TestSupport.h"
#include "PcapTestUtils.h"
#include "app/frontend/FrontendSessionAdapter.h"
#include "app/frontend/FrontendSessionAdapterBridge.h"
#include "app/frontend/FrontendStatisticsOverview.h"
#include "app/session/CaptureSession.h"
#include "app/session/SessionFlowHelpers.h"
#include "core/domain/CapturePacketSizeStatistics.h"
#include "core/domain/Connection.h"
#include "core/index/CaptureIndex.h"
#include "core/io/PcapReader.h"
#include "core/services/CaptureImportProcessor.h"

namespace pfl::tests {

namespace {

std::filesystem::path fixture_path(const std::filesystem::path& relative_path) {
    return std::filesystem::path(__FILE__).parent_path().parent_path() / "data" / relative_path;
}

std::string read_text_file(const std::filesystem::path& path) {
    std::ifstream stream {path, std::ios::binary};
    PFL_REQUIRE(stream.is_open());
    return std::string(std::istreambuf_iterator<char> {stream}, std::istreambuf_iterator<char> {});
}

std::string utf8_path_string(const std::filesystem::path& path) {
#if defined(__cpp_char8_t)
    const auto utf8 = path.u8string();
    std::string result {};
    result.reserve(utf8.size());
    for (const auto ch : utf8) {
        result.push_back(static_cast<char>(ch));
    }
    return result;
#else
    return path.u8string();
#endif
}

std::filesystem::path path_from_explicit_utf8(std::string_view utf8) {
#if defined(__cpp_char8_t)
    std::u8string utf8_native {};
    utf8_native.reserve(utf8.size());
    for (const char ch : utf8) {
        utf8_native.push_back(static_cast<char8_t>(static_cast<unsigned char>(ch)));
    }
    return std::filesystem::path {utf8_native};
#else
    return std::filesystem::u8path(utf8.begin(), utf8.end());
#endif
}

std::filesystem::path write_temp_capture_file(
    const std::filesystem::path& file_name,
    const std::vector<std::uint8_t>& bytes
) {
    const auto path = std::filesystem::temp_directory_path() / file_name;
    std::ofstream stream {path, std::ios::binary | std::ios::trunc};
    PFL_REQUIRE(stream.is_open());
    stream.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    PFL_REQUIRE(stream.good());
    return path;
}

struct HistogramInputConnections {
    std::vector<ConnectionV4> storage {};
    std::vector<session_detail::ListedConnectionRef> refs {};
};

struct HistogramFlowInput {
    std::uint64_t packet_count {0};
    std::uint64_t original_byte_count {0};
    std::optional<std::uint64_t> captured_byte_count {};
};

HistogramInputConnections make_histogram_input_connections(const std::vector<HistogramFlowInput>& flows) {
    HistogramInputConnections input {};
    input.storage.reserve(flows.size());
    input.refs.reserve(flows.size());

    for (std::size_t index = 0U; index < flows.size(); ++index) {
        ConnectionV4 connection {};
        connection.packet_count = flows[index].packet_count;
        connection.total_bytes = flows[index].original_byte_count;
        connection.aggregate_stats.captured_bytes = flows[index].captured_byte_count.value_or(
            flows[index].original_byte_count
        );
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

session_detail::ListedConnectionRef listed_connection_ref(ConnectionV4& connection) {
    return session_detail::ListedConnectionRef {
        .family = FlowAddressFamily::ipv4,
        .ipv4 = &connection,
        .ipv6 = nullptr,
    };
}

session_detail::ListedConnectionRef listed_connection_ref(ConnectionV6& connection) {
    return session_detail::ListedConnectionRef {
        .family = FlowAddressFamily::ipv6,
        .ipv4 = nullptr,
        .ipv6 = &connection,
    };
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

const CapturePacketSizeStatisticsBucket* find_bucket(
    const CapturePacketSizeDistribution& distribution,
    const std::string_view stable_id
) {
    for (const auto& bucket : distribution.buckets) {
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
    const std::uint64_t expected_captured_byte_count,
    const std::uint64_t expected_original_byte_count,
    const std::uint64_t expected_lower_bound,
    const std::optional<std::uint64_t> expected_upper_bound
) {
    const auto* bucket = find_bucket(histogram, stable_id);
    PFL_REQUIRE(bucket != nullptr);
    PFL_EXPECT(bucket->flow_count == expected_count);
    PFL_EXPECT(bucket->captured_byte_count == expected_captured_byte_count);
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

void expect_capture_packet_size_bucket(
    const CapturePacketSizeDistribution& distribution,
    const std::string_view stable_id,
    const std::uint64_t expected_packet_count,
    const std::uint32_t expected_lower_bound,
    const std::optional<std::uint32_t> expected_upper_bound
) {
    const auto* bucket = find_bucket(distribution, stable_id);
    PFL_REQUIRE(bucket != nullptr);
    PFL_EXPECT(bucket->packet_count == expected_packet_count);
    PFL_EXPECT(bucket->lower_bound_inclusive == expected_lower_bound);
    PFL_EXPECT(bucket->upper_bound_inclusive == expected_upper_bound);
}

void expect_capture_packet_statistics_equal(
    const CapturePacketStatistics& left,
    const CapturePacketStatistics& right
) {
    PFL_EXPECT(left.total_packet_count == right.total_packet_count);
    PFL_EXPECT(left.total_captured_bytes == right.total_captured_bytes);
    PFL_EXPECT(left.total_original_bytes == right.total_original_bytes);
    PFL_EXPECT(left.timestamp_range.available == right.timestamp_range.available);
    PFL_EXPECT(left.timestamp_range.earliest_timestamp_us == right.timestamp_range.earliest_timestamp_us);
    PFL_EXPECT(left.timestamp_range.latest_timestamp_us == right.timestamp_range.latest_timestamp_us);
    PFL_EXPECT(left.truncated_packet_count == right.truncated_packet_count);
    PFL_EXPECT(left.maximum_captured_packet_length == right.maximum_captured_packet_length);
    PFL_EXPECT(left.maximum_original_packet_length == right.maximum_original_packet_length);
    PFL_EXPECT(left.captured_size_distribution.maximum_bucket_packet_count ==
        right.captured_size_distribution.maximum_bucket_packet_count);
    PFL_EXPECT(left.original_size_distribution.maximum_bucket_packet_count ==
        right.original_size_distribution.maximum_bucket_packet_count);
    PFL_EXPECT(left.unrecognized_packet_count == right.unrecognized_packet_count);
    PFL_EXPECT(left.unrecognized_captured_bytes == right.unrecognized_captured_bytes);
    PFL_EXPECT(left.unrecognized_original_bytes == right.unrecognized_original_bytes);
    PFL_EXPECT(left.captured_size_distribution.buckets.size() == right.captured_size_distribution.buckets.size());
    PFL_EXPECT(left.original_size_distribution.buckets.size() == right.original_size_distribution.buckets.size());

    for (std::size_t index = 0U; index < left.captured_size_distribution.buckets.size(); ++index) {
        PFL_EXPECT(left.captured_size_distribution.buckets[index].stable_id ==
            right.captured_size_distribution.buckets[index].stable_id);
        PFL_EXPECT(left.captured_size_distribution.buckets[index].packet_count ==
            right.captured_size_distribution.buckets[index].packet_count);
    }

    for (std::size_t index = 0U; index < left.original_size_distribution.buckets.size(); ++index) {
        PFL_EXPECT(left.original_size_distribution.buckets[index].stable_id ==
            right.original_size_distribution.buckets[index].stable_id);
        PFL_EXPECT(left.original_size_distribution.buckets[index].packet_count ==
            right.original_size_distribution.buckets[index].packet_count);
    }
}

void expect_capture_packet_statistics_invariants(const CapturePacketStatistics& statistics) {
    std::uint64_t captured_histogram_packet_count = 0U;
    for (const auto& bucket : statistics.captured_size_distribution.buckets) {
        captured_histogram_packet_count += bucket.packet_count;
    }

    std::uint64_t original_histogram_packet_count = 0U;
    for (const auto& bucket : statistics.original_size_distribution.buckets) {
        original_histogram_packet_count += bucket.packet_count;
    }

    PFL_EXPECT(captured_histogram_packet_count == statistics.total_packet_count);
    PFL_EXPECT(original_histogram_packet_count == statistics.total_packet_count);
    PFL_EXPECT(statistics.truncated_packet_count <= statistics.total_packet_count);
    PFL_EXPECT(statistics.unrecognized_packet_count <= statistics.total_packet_count);
    PFL_EXPECT(statistics.unrecognized_captured_bytes <= statistics.total_captured_bytes);
    PFL_EXPECT(statistics.unrecognized_original_bytes <= statistics.total_original_bytes);
}

void expect_histogram_equal(const FlowPacketCountHistogram& left, const FlowPacketCountHistogram& right) {
    PFL_EXPECT(left.total_flow_count == right.total_flow_count);
    PFL_EXPECT(left.total_captured_byte_count == right.total_captured_byte_count);
    PFL_EXPECT(left.total_original_byte_count == right.total_original_byte_count);
    PFL_EXPECT(left.maximum_bucket_flow_count == right.maximum_bucket_flow_count);
    PFL_EXPECT(left.maximum_bucket_captured_byte_count == right.maximum_bucket_captured_byte_count);
    PFL_EXPECT(left.maximum_bucket_original_byte_count == right.maximum_bucket_original_byte_count);
    PFL_EXPECT(left.excluded_zero_packet_flow_count == right.excluded_zero_packet_flow_count);
    PFL_EXPECT(left.excluded_zero_packet_captured_byte_count == right.excluded_zero_packet_captured_byte_count);
    PFL_EXPECT(left.excluded_zero_packet_original_byte_count == right.excluded_zero_packet_original_byte_count);
    PFL_EXPECT(left.buckets.size() == right.buckets.size());

    for (std::size_t index = 0U; index < left.buckets.size(); ++index) {
        PFL_EXPECT(left.buckets[index].stable_id == right.buckets[index].stable_id);
        PFL_EXPECT(left.buckets[index].lower_bound_inclusive == right.buckets[index].lower_bound_inclusive);
        PFL_EXPECT(left.buckets[index].upper_bound_inclusive == right.buckets[index].upper_bound_inclusive);
        PFL_EXPECT(left.buckets[index].flow_count == right.buckets[index].flow_count);
        PFL_EXPECT(left.buckets[index].captured_byte_count == right.buckets[index].captured_byte_count);
        PFL_EXPECT(left.buckets[index].original_byte_count == right.buckets[index].original_byte_count);
    }
}

void expect_quic_tls_summary_equal(const CaptureQuicTlsSummary& left, const CaptureQuicTlsSummary& right) {
    PFL_EXPECT(left.quic.total_flows == right.quic.total_flows);
    PFL_EXPECT(left.quic.with_sni == right.quic.with_sni);
    PFL_EXPECT(left.quic.without_sni == right.quic.without_sni);
    PFL_EXPECT(left.quic.version_v1 == right.quic.version_v1);
    PFL_EXPECT(left.quic.version_draft29 == right.quic.version_draft29);
    PFL_EXPECT(left.quic.version_v2 == right.quic.version_v2);
    PFL_EXPECT(left.quic.version_unknown == right.quic.version_unknown);
    PFL_EXPECT(left.tls.total_flows == right.tls.total_flows);
    PFL_EXPECT(left.tls.with_sni == right.tls.with_sni);
    PFL_EXPECT(left.tls.without_sni == right.tls.without_sni);
    PFL_EXPECT(left.tls.version_tls12 == right.tls.version_tls12);
    PFL_EXPECT(left.tls.version_tls13 == right.tls.version_tls13);
    PFL_EXPECT(left.tls.version_unknown == right.tls.version_unknown);
}

void expect_top_summary_equal(const CaptureTopSummary& left, const CaptureTopSummary& right) {
    PFL_EXPECT(left.endpoints_by_bytes.size() == right.endpoints_by_bytes.size());
    PFL_EXPECT(left.ports_by_bytes.size() == right.ports_by_bytes.size());

    for (std::size_t index = 0; index < left.endpoints_by_bytes.size(); ++index) {
        PFL_EXPECT(left.endpoints_by_bytes[index].endpoint == right.endpoints_by_bytes[index].endpoint);
        PFL_EXPECT(left.endpoints_by_bytes[index].packet_count == right.endpoints_by_bytes[index].packet_count);
        PFL_EXPECT(left.endpoints_by_bytes[index].total_bytes == right.endpoints_by_bytes[index].total_bytes);
    }

    for (std::size_t index = 0; index < left.ports_by_bytes.size(); ++index) {
        PFL_EXPECT(left.ports_by_bytes[index].port == right.ports_by_bytes[index].port);
        PFL_EXPECT(left.ports_by_bytes[index].packet_count == right.ports_by_bytes[index].packet_count);
        PFL_EXPECT(left.ports_by_bytes[index].total_bytes == right.ports_by_bytes[index].total_bytes);
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

std::vector<std::uint8_t> large_unrecognized_ethernet_frame() {
    auto bytes = unrecognized_ethernet_frame();
    bytes.resize(256U, 0x5aU);
    return bytes;
}

std::vector<std::uint8_t> large_recognized_tcp_frame_without_payload() {
    auto bytes = make_ethernet_ipv4_tcp_packet(ipv4(10, 65, 0, 1), ipv4(10, 65, 0, 2), 6501, 443);
    bytes.resize(256U, 0x00U);
    return bytes;
}

void write_le32(std::vector<std::uint8_t>& bytes, const std::size_t offset, const std::uint32_t value) {
    PFL_REQUIRE(offset + 4U <= bytes.size());
    bytes[offset + 0U] = static_cast<std::uint8_t>(value & 0xffU);
    bytes[offset + 1U] = static_cast<std::uint8_t>((value >> 8U) & 0xffU);
    bytes[offset + 2U] = static_cast<std::uint8_t>((value >> 16U) & 0xffU);
    bytes[offset + 3U] = static_cast<std::uint8_t>((value >> 24U) & 0xffU);
}

std::vector<std::uint8_t> make_single_packet_classic_pcap_with_declared_capture_length(
    const std::vector<std::uint8_t>& packet_bytes,
    const std::uint32_t declared_captured_length,
    const std::uint32_t declared_original_length,
    const std::size_t retained_packet_bytes
) {
    auto capture = make_classic_pcap({{100U, packet_bytes}});
    constexpr std::size_t kPacketHeaderOffset = 24U;
    constexpr std::size_t kIncludedLengthOffset = kPacketHeaderOffset + 8U;
    constexpr std::size_t kOriginalLengthOffset = kPacketHeaderOffset + 12U;
    write_le32(capture, kIncludedLengthOffset, declared_captured_length);
    write_le32(capture, kOriginalLengthOffset, declared_original_length);
    capture.resize(kPacketHeaderOffset + 16U + retained_packet_bytes);
    return capture;
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

std::string unavailable_text() {
    return std::string("\xE2\x80\x94");
}

void expect_not_nan_or_inf_text(const std::string& text) {
    PFL_EXPECT(!contains_text(text, "NaN"));
    PFL_EXPECT(!contains_text(text, "nan"));
    PFL_EXPECT(!contains_text(text, "Inf"));
    PFL_EXPECT(!contains_text(text, "inf"));
}

void expect_shared_statistics_formatting_helpers() {
    using session_detail::format_statistics_compact_size_value;
    using session_detail::format_statistics_count_with_percent_text;
    using session_detail::format_statistics_percent_text;
    using session_detail::format_statistics_size_value;
    using session_detail::format_statistics_size_with_percent_text;

    PFL_EXPECT(format_statistics_compact_size_value(0U) == "0 B");
    PFL_EXPECT(format_statistics_compact_size_value(162U) == "162 B");
    PFL_EXPECT(format_statistics_compact_size_value(1536U) == "1.5 KB");
    PFL_EXPECT(format_statistics_compact_size_value(3430649U) == "3.3 MB");
    PFL_EXPECT(format_statistics_compact_size_value(12285799U) == "11.7 MB");
    PFL_EXPECT(format_statistics_compact_size_value(15716610U) == "15 MB");

    PFL_EXPECT(format_statistics_size_value(0U) == "0 B");
    PFL_EXPECT(format_statistics_size_value(1490U) == "1.5 KB (1 490 B)");
    PFL_EXPECT(format_statistics_size_value(1522U) == "1.5 KB (1 522 B)");
    PFL_EXPECT(format_statistics_size_value(1536U) == "1.5 KB (1 536 B)");

    PFL_EXPECT(format_statistics_percent_text(0.0) == "0%");
    PFL_EXPECT(format_statistics_percent_text(48.0) == "48%");
    PFL_EXPECT(format_statistics_percent_text(0.21) == "0.21%");
    PFL_EXPECT(format_statistics_percent_text(0.03) == "0.03%");
    PFL_EXPECT(format_statistics_percent_text(0.009) == "<0.01%");

    PFL_EXPECT(format_statistics_count_with_percent_text(102U, 48.0) == "102 (48%)");
    PFL_EXPECT(format_statistics_count_with_percent_text(4901U, 26.0) == "4 901 (26%)");
    PFL_EXPECT(format_statistics_size_with_percent_text(3430649U, 22.0) == "3.3 MB (22%)");
    PFL_EXPECT(format_statistics_size_with_percent_text(136U, 0.009) == "136 B (<0.01%)");
    PFL_EXPECT(format_statistics_count_with_percent_text(0U, 0.0) == "0 (0%)");
    PFL_EXPECT(format_statistics_size_with_percent_text(0U, 0.0) == "0 B (0%)");
    PFL_EXPECT(session_detail::format_statistics_bucket_label(1U, 1U) == "1");
    PFL_EXPECT(session_detail::format_statistics_bucket_label(3U, 5U) == "3-5");
    PFL_EXPECT(session_detail::format_statistics_bucket_label(5001U, std::nullopt) == "5001+");
    PFL_EXPECT(session_detail::format_statistics_bucket_label(0U, 63U) == "0-63");
    PFL_EXPECT(
        session_detail::format_statistics_bucket_label(
            std::numeric_limits<std::uint64_t>::max() - 1U,
            std::nullopt
        ) == std::to_string(std::numeric_limits<std::uint64_t>::max() - 1U) + '+'
    );
}

void expect_protocol_hint_statistics_rows_handle_zero_denominators() {
    const auto rows = session_detail::build_protocol_hint_statistics_rows(CaptureProtocolSummary {});
    PFL_EXPECT(rows.size() == 13U);
    for (const auto& row : rows) {
        PFL_EXPECT(row.flow_count == 0U);
        PFL_EXPECT(row.packet_count == 0U);
        PFL_EXPECT(row.captured_bytes == 0U);
        PFL_EXPECT(row.original_bytes == 0U);
        PFL_EXPECT(row.flow_count_text == "0 (0%)");
        PFL_EXPECT(row.packet_count_text == "0 (0%)");
        PFL_EXPECT(row.captured_bytes_text == "0 B (0%)");
        PFL_EXPECT(row.original_bytes_text == "0 B (0%)");
    }
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
    PFL_EXPECT(histogram.total_captured_byte_count == 1389500U);
    PFL_EXPECT(histogram.total_original_byte_count == 1389500U);
    PFL_EXPECT(histogram.maximum_bucket_flow_count == 2U);
    PFL_EXPECT(histogram.maximum_bucket_captured_byte_count == 600100U);
    PFL_EXPECT(histogram.maximum_bucket_original_byte_count == 600100U);
    PFL_EXPECT(histogram.excluded_zero_packet_flow_count == 0U);
    PFL_EXPECT(histogram.excluded_zero_packet_captured_byte_count == 0U);
    PFL_EXPECT(histogram.excluded_zero_packet_original_byte_count == 0U);
    PFL_EXPECT(histogram.buckets.size() == 12U);

    expect_histogram_bucket(histogram, "packets_1", 1U, 100U, 100U, 1U, 1U);
    expect_histogram_bucket(histogram, "packets_2", 1U, 200U, 200U, 2U, 2U);
    expect_histogram_bucket(histogram, "packets_3_5", 2U, 800U, 800U, 3U, 5U);
    expect_histogram_bucket(histogram, "packets_6_10", 2U, 1600U, 1600U, 6U, 10U);
    expect_histogram_bucket(histogram, "packets_11_25", 2U, 3600U, 3600U, 11U, 25U);
    expect_histogram_bucket(histogram, "packets_26_50", 2U, 7600U, 7600U, 26U, 50U);
    expect_histogram_bucket(histogram, "packets_51_100", 2U, 15100U, 15100U, 51U, 100U);
    expect_histogram_bucket(histogram, "packets_101_250", 2U, 35100U, 35100U, 101U, 250U);
    expect_histogram_bucket(histogram, "packets_251_500", 2U, 75100U, 75100U, 251U, 500U);
    expect_histogram_bucket(histogram, "packets_501_1000", 2U, 150100U, 150100U, 501U, 1000U);
    expect_histogram_bucket(histogram, "packets_1001_5000", 2U, 600100U, 600100U, 1001U, 5000U);
    expect_histogram_bucket(histogram, "packets_5001_plus", 1U, 500100U, 500100U, 5001U, std::nullopt);

    std::uint64_t summed_flow_count {0};
    std::uint64_t summed_captured_byte_count {0};
    std::uint64_t summed_original_byte_count {0};
    for (const auto& bucket : histogram.buckets) {
        summed_flow_count += bucket.flow_count;
        summed_captured_byte_count += bucket.captured_byte_count;
        summed_original_byte_count += bucket.original_byte_count;
    }
    PFL_EXPECT(summed_flow_count == histogram.total_flow_count);
    PFL_EXPECT(summed_captured_byte_count == histogram.total_captured_byte_count);
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
    PFL_EXPECT(histogram.total_captured_byte_count == 2048U);
    PFL_EXPECT(histogram.total_original_byte_count == 2048U);
    PFL_EXPECT(histogram.maximum_bucket_flow_count == 2U);
    PFL_EXPECT(histogram.maximum_bucket_captured_byte_count == 2048U);
    PFL_EXPECT(histogram.maximum_bucket_original_byte_count == 2048U);
    PFL_EXPECT(histogram.excluded_zero_packet_flow_count == 1U);
    PFL_EXPECT(histogram.excluded_zero_packet_captured_byte_count == 4096U);
    PFL_EXPECT(histogram.excluded_zero_packet_original_byte_count == 4096U);
    expect_histogram_bucket(histogram, "packets_1", 1U, 0U, 0U, 1U, 1U);
    expect_histogram_bucket(histogram, "packets_2", 2U, 2048U, 2048U, 2U, 2U);
}

void expect_flow_packet_count_histogram_supports_empty_inputs() {
    const auto input = make_histogram_input_connections(std::vector<HistogramFlowInput> {});
    const auto histogram = session_detail::build_flow_packet_count_histogram(input.refs);

    PFL_EXPECT(histogram.total_flow_count == 0U);
    PFL_EXPECT(histogram.total_captured_byte_count == 0U);
    PFL_EXPECT(histogram.total_original_byte_count == 0U);
    PFL_EXPECT(histogram.maximum_bucket_flow_count == 0U);
    PFL_EXPECT(histogram.maximum_bucket_captured_byte_count == 0U);
    PFL_EXPECT(histogram.maximum_bucket_original_byte_count == 0U);
    PFL_EXPECT(histogram.excluded_zero_packet_flow_count == 0U);
    PFL_EXPECT(histogram.excluded_zero_packet_captured_byte_count == 0U);
    PFL_EXPECT(histogram.excluded_zero_packet_original_byte_count == 0U);
    PFL_EXPECT(histogram.buckets.size() == 12U);
    for (const auto& bucket : histogram.buckets) {
        PFL_EXPECT(bucket.flow_count == 0U);
        PFL_EXPECT(bucket.captured_byte_count == 0U);
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
    PFL_EXPECT(histogram.total_captured_byte_count == expected_histogram_total);
    PFL_EXPECT(histogram.total_original_byte_count == expected_histogram_total);
    PFL_EXPECT(histogram.maximum_bucket_captured_byte_count == expected_bucket_two_total);
    PFL_EXPECT(histogram.maximum_bucket_original_byte_count == expected_bucket_two_total);
    expect_histogram_bucket(histogram, "packets_1", 1U, 1024U, 1024U, 1U, 1U);
    expect_histogram_bucket(histogram, "packets_2", 2U, expected_bucket_two_total, expected_bucket_two_total, 2U, 2U);
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
    cached_connection->aggregate_stats.captured_bytes = 777777U;
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
        second_histogram.total_captured_byte_count,
        second_histogram.total_original_byte_count,
        2U,
        2U
    );
}

void expect_capture_general_statistics_support_empty_inputs() {
    const std::vector<session_detail::ListedConnectionRef> no_connections {};
    const auto statistics = session_detail::build_capture_general_statistics(
        std::span<const session_detail::ListedConnectionRef>(no_connections.data(), no_connections.size()),
        20U
    );

    PFL_EXPECT(statistics.flow_characteristics.total_flow_count == 0U);
    PFL_EXPECT(statistics.flow_characteristics.only_a_to_b_flow_count == 0U);
    PFL_EXPECT(statistics.flow_characteristics.service_recognized_flow_count == 0U);
    PFL_EXPECT(statistics.packet_direction_distribution.mostly_a_to_b_flow_count == 0U);
    PFL_EXPECT(statistics.packet_direction_distribution.balanced_flow_count == 0U);
    PFL_EXPECT(statistics.packet_direction_distribution.mostly_b_to_a_flow_count == 0U);
    PFL_EXPECT(statistics.original_byte_direction_distribution.mostly_a_to_b_flow_count == 0U);
    PFL_EXPECT(statistics.original_byte_direction_distribution.balanced_flow_count == 0U);
    PFL_EXPECT(statistics.original_byte_direction_distribution.mostly_b_to_a_flow_count == 0U);
    PFL_EXPECT(statistics.top_summary.endpoints_by_bytes.empty());
    PFL_EXPECT(statistics.top_summary.ports_by_bytes.empty());
    PFL_EXPECT(statistics.flow_packet_count_histogram.total_flow_count == 0U);
    PFL_EXPECT(statistics.flow_packet_count_histogram.total_captured_byte_count == 0U);
    PFL_EXPECT(statistics.flow_packet_count_histogram.total_original_byte_count == 0U);
    PFL_EXPECT(statistics.flow_packet_count_histogram.buckets.size() == 12U);
}

void expect_capture_general_statistics_track_flow_characteristics_distributions_and_captured_bytes() {
    ConnectionV4 unknown_tcp {};
    unknown_tcp.has_flow_a = true;
    unknown_tcp.flow_a.packet_count = 1U;
    unknown_tcp.flow_a.total_bytes = 100U;
    unknown_tcp.packet_count = 1U;
    unknown_tcp.total_bytes = 100U;
    unknown_tcp.aggregate_stats.captured_bytes = 90U;
    unknown_tcp.service_hint = "alpha.example";
    unknown_tcp.key.protocol = ProtocolId::tcp;
    unknown_tcp.key.first.addr = ipv4(10, 10, 0, 1);
    unknown_tcp.key.first.port = 1111U;
    unknown_tcp.key.second.addr = ipv4(10, 10, 0, 2);
    unknown_tcp.key.second.port = 80U;

    ConnectionV6 confirmed_quic {};
    confirmed_quic.has_flow_a = true;
    confirmed_quic.has_flow_b = true;
    confirmed_quic.flow_a.packet_count = 2U;
    confirmed_quic.flow_b.packet_count = 1U;
    confirmed_quic.flow_a.total_bytes = 200U;
    confirmed_quic.flow_b.total_bytes = 100U;
    confirmed_quic.packet_count = 3U;
    confirmed_quic.total_bytes = 300U;
    confirmed_quic.aggregate_stats.captured_bytes = 250U;
    confirmed_quic.protocol_hint = FlowProtocolHint::quic;
    confirmed_quic.quic_version = QuicVersionHint::v1;
    confirmed_quic.service_hint = "quic.example";
    confirmed_quic.key.protocol = ProtocolId::udp;
    confirmed_quic.key.first.addr = ipv6({0x20, 0x01, 0x0d, 0xb8, 0x00, 0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01});
    confirmed_quic.key.first.port = 2200U;
    confirmed_quic.key.second.addr = ipv6({0x20, 0x01, 0x0d, 0xb8, 0x00, 0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02});
    confirmed_quic.key.second.port = 443U;

    ConnectionV4 confirmed_tls {};
    confirmed_tls.has_flow_a = true;
    confirmed_tls.has_flow_b = true;
    confirmed_tls.flow_a.packet_count = 1U;
    confirmed_tls.flow_b.packet_count = 4U;
    confirmed_tls.flow_a.total_bytes = 100U;
    confirmed_tls.flow_b.total_bytes = 400U;
    confirmed_tls.packet_count = 5U;
    confirmed_tls.total_bytes = 500U;
    confirmed_tls.aggregate_stats.captured_bytes = 450U;
    confirmed_tls.protocol_hint = FlowProtocolHint::tls;
    confirmed_tls.tls_version = TlsVersionHint::tls13;
    confirmed_tls.key.protocol = ProtocolId::tcp;
    confirmed_tls.key.first.addr = ipv4(10, 10, 0, 3);
    confirmed_tls.key.first.port = 3333U;
    confirmed_tls.key.second.addr = ipv4(10, 10, 0, 4);
    confirmed_tls.key.second.port = 443U;

    ConnectionV6 possible_tls {};
    possible_tls.has_flow_a = true;
    possible_tls.flow_a.packet_count = 3U;
    possible_tls.flow_a.total_bytes = 600U;
    possible_tls.packet_count = 3U;
    possible_tls.total_bytes = 600U;
    possible_tls.aggregate_stats.captured_bytes = 500U;
    possible_tls.key.protocol = ProtocolId::tcp;
    possible_tls.key.first.addr = ipv6({0x20, 0x01, 0x0d, 0xb8, 0x00, 0x43, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01});
    possible_tls.key.first.port = 4400U;
    possible_tls.key.second.addr = ipv6({0x20, 0x01, 0x0d, 0xb8, 0x00, 0x43, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02});
    possible_tls.key.second.port = 443U;

    std::vector<session_detail::ListedConnectionRef> refs {
        listed_connection_ref(unknown_tcp),
        listed_connection_ref(confirmed_quic),
        listed_connection_ref(confirmed_tls),
        listed_connection_ref(possible_tls),
    };
    const auto statistics = session_detail::build_capture_general_statistics(
        std::span<const session_detail::ListedConnectionRef>(refs.data(), refs.size()),
        20U
    );

    PFL_EXPECT(statistics.protocol.ipv4.flow_count == 2U);
    PFL_EXPECT(statistics.protocol.ipv6.flow_count == 2U);
    PFL_EXPECT(statistics.protocol.tcp.flow_count == 3U);
    PFL_EXPECT(statistics.protocol.udp.flow_count == 1U);
    PFL_EXPECT(statistics.protocol.tcp.captured_bytes == 1040U);
    PFL_EXPECT(statistics.protocol.udp.captured_bytes == 250U);
    PFL_EXPECT(statistics.protocol.hint_unknown_without_possible.flow_count == 1U);
    PFL_EXPECT(statistics.protocol.hint_unknown_without_possible.captured_bytes == 90U);
    PFL_EXPECT(statistics.protocol.hint_possible_tls_candidate.flow_count == 1U);
    PFL_EXPECT(statistics.protocol.hint_possible_tls_candidate.captured_bytes == 500U);
    PFL_EXPECT(statistics.protocol.hint_quic.flow_count == 1U);
    PFL_EXPECT(statistics.protocol.hint_tls.flow_count == 1U);

    PFL_EXPECT(statistics.flow_characteristics.total_flow_count == 4U);
    PFL_EXPECT(statistics.flow_characteristics.only_a_to_b_flow_count == 2U);
    PFL_EXPECT(statistics.flow_characteristics.service_recognized_flow_count == 2U);

    PFL_EXPECT(statistics.packet_direction_distribution.mostly_a_to_b_flow_count == 2U);
    PFL_EXPECT(statistics.packet_direction_distribution.balanced_flow_count == 1U);
    PFL_EXPECT(statistics.packet_direction_distribution.mostly_b_to_a_flow_count == 1U);
    PFL_EXPECT(statistics.original_byte_direction_distribution.mostly_a_to_b_flow_count == 2U);
    PFL_EXPECT(statistics.original_byte_direction_distribution.balanced_flow_count == 1U);
    PFL_EXPECT(statistics.original_byte_direction_distribution.mostly_b_to_a_flow_count == 1U);

    PFL_EXPECT(statistics.flow_packet_count_histogram.total_flow_count == 4U);
    PFL_EXPECT(statistics.flow_packet_count_histogram.total_captured_byte_count == 1290U);
    PFL_EXPECT(statistics.flow_packet_count_histogram.total_original_byte_count == 1500U);
    PFL_EXPECT(statistics.flow_packet_count_histogram.maximum_bucket_flow_count == 3U);
    PFL_EXPECT(statistics.flow_packet_count_histogram.maximum_bucket_captured_byte_count == 1200U);
    PFL_EXPECT(statistics.flow_packet_count_histogram.maximum_bucket_original_byte_count == 1400U);
    expect_histogram_bucket(statistics.flow_packet_count_histogram, "packets_1", 1U, 90U, 100U, 1U, 1U);
    expect_histogram_bucket(statistics.flow_packet_count_histogram, "packets_3_5", 3U, 1200U, 1400U, 3U, 5U);

    PFL_EXPECT(statistics.quic_tls_summary.quic.total_flows == 1U);
    PFL_EXPECT(statistics.quic_tls_summary.quic.with_sni == 1U);
    PFL_EXPECT(statistics.quic_tls_summary.quic.without_sni == 0U);
    PFL_EXPECT(statistics.quic_tls_summary.quic.version_v1 == 1U);
    PFL_EXPECT(statistics.quic_tls_summary.tls.total_flows == 1U);
    PFL_EXPECT(statistics.quic_tls_summary.tls.with_sni == 0U);
    PFL_EXPECT(statistics.quic_tls_summary.tls.without_sni == 1U);
    PFL_EXPECT(statistics.quic_tls_summary.tls.version_tls13 == 1U);
}

void expect_general_statistics_cache_survives_possible_tls_projection_changes() {
    const auto capture_path = write_temp_pcap(
        "pfl_statistics_possible_tls_projection_cache.pcap",
        make_classic_pcap({
            {100U, make_ethernet_ipv4_tcp_packet(ipv4(10, 70, 0, 1), ipv4(10, 70, 0, 2), 47001, 443)},
            {200U, make_ethernet_ipv4_udp_packet(ipv4(10, 70, 0, 3), ipv4(10, 70, 0, 4), 47002, 443)},
            {300U, make_ethernet_ipv4_tcp_packet(ipv4(10, 70, 0, 5), ipv4(10, 70, 0, 6), 47003, 80)},
        })
    );

    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(capture_path));

    const auto baseline_histogram = session.flow_packet_count_histogram();
    const auto baseline_quic_tls = session.quic_tls_summary();
    const auto baseline_top = session.top_summary(5U);
    const auto without_possible = session.protocol_summary();
    PFL_EXPECT(without_possible.hint_unknown.flow_count == 3U);
    PFL_EXPECT(without_possible.hint_possible_tls.flow_count == 0U);
    PFL_EXPECT(without_possible.hint_possible_quic.flow_count == 0U);

    AnalysisSettings settings {};
    settings.use_possible_tls_quic = true;
    session.set_analysis_settings(settings);

    const auto with_possible = session.protocol_summary();
    PFL_EXPECT(with_possible.hint_unknown.flow_count == 1U);
    PFL_EXPECT(with_possible.hint_possible_tls.flow_count == 1U);
    PFL_EXPECT(with_possible.hint_possible_quic.flow_count == 1U);
    PFL_EXPECT(with_possible.tcp.flow_count == without_possible.tcp.flow_count);
    PFL_EXPECT(with_possible.udp.flow_count == without_possible.udp.flow_count);

    expect_histogram_equal(baseline_histogram, session.flow_packet_count_histogram());
    expect_quic_tls_summary_equal(baseline_quic_tls, session.quic_tls_summary());
    expect_top_summary_equal(baseline_top, session.top_summary(5U));
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
    PFL_EXPECT(
        statistics.total_captured_bytes ==
        std::accumulate(lengths.begin(), lengths.end(), std::uint64_t {0})
    );
    PFL_EXPECT(statistics.maximum_bucket_packet_count == 2U);
    PFL_EXPECT(statistics.maximum_captured_packet_length == std::numeric_limits<std::uint32_t>::max());
    expect_capture_packet_size_bucket(statistics, "captured_bytes_0_63", 2U, 0U, 63U);
    expect_capture_packet_size_bucket(statistics, "captured_bytes_64_127", 2U, 64U, 127U);
    expect_capture_packet_size_bucket(statistics, "captured_bytes_128_255", 2U, 128U, 255U);
    expect_capture_packet_size_bucket(statistics, "captured_bytes_256_511", 2U, 256U, 511U);
    expect_capture_packet_size_bucket(statistics, "captured_bytes_512_1023", 2U, 512U, 1023U);
    expect_capture_packet_size_bucket(statistics, "captured_bytes_1024_1399", 2U, 1024U, 1399U);
    expect_capture_packet_size_bucket(statistics, "captured_bytes_1400_1550", 2U, 1400U, 1550U);
    expect_capture_packet_size_bucket(statistics, "captured_bytes_1551_2499", 2U, 1551U, 2499U);
    expect_capture_packet_size_bucket(statistics, "captured_bytes_2500_5000", 2U, 2500U, 5000U);
    expect_capture_packet_size_bucket(statistics, "captured_bytes_5001_9000", 2U, 5001U, 9000U);
    expect_capture_packet_size_bucket(statistics, "captured_bytes_9001_16000", 2U, 9001U, 16000U);
    expect_capture_packet_size_bucket(statistics, "captured_bytes_16001_25000", 2U, 16001U, 25000U);
    expect_capture_packet_size_bucket(statistics, "captured_bytes_25001_plus", 2U, 25001U, std::nullopt);
}

void expect_capture_packet_size_statistics_supports_empty_state() {
    const CapturePacketSizeStatistics statistics {};
    PFL_EXPECT(statistics.total_packet_count == 0U);
    PFL_EXPECT(statistics.total_captured_bytes == 0U);
    PFL_EXPECT(statistics.maximum_bucket_packet_count == 0U);
    PFL_EXPECT(statistics.maximum_captured_packet_length == 0U);
    for (const auto& bucket : statistics.buckets) {
        PFL_EXPECT(bucket.packet_count == 0U);
    }
}

void expect_capture_packet_statistics_supports_empty_state() {
    const CapturePacketStatistics statistics {};
    PFL_EXPECT(statistics.total_packet_count == 0U);
    PFL_EXPECT(statistics.total_captured_bytes == 0U);
    PFL_EXPECT(statistics.total_original_bytes == 0U);
    PFL_EXPECT(!statistics.timestamp_range.available);
    PFL_EXPECT(statistics.timestamp_range.earliest_timestamp_us == 0U);
    PFL_EXPECT(statistics.timestamp_range.latest_timestamp_us == 0U);
    PFL_EXPECT(statistics.truncated_packet_count == 0U);
    PFL_EXPECT(statistics.maximum_captured_packet_length == 0U);
    PFL_EXPECT(statistics.maximum_original_packet_length == 0U);
    PFL_EXPECT(statistics.captured_size_distribution.maximum_bucket_packet_count == 0U);
    PFL_EXPECT(statistics.original_size_distribution.maximum_bucket_packet_count == 0U);
    PFL_EXPECT(statistics.unrecognized_packet_count == 0U);
    PFL_EXPECT(statistics.unrecognized_captured_bytes == 0U);
    PFL_EXPECT(statistics.unrecognized_original_bytes == 0U);
    expect_capture_packet_statistics_invariants(statistics);
}

void expect_capture_packet_statistics_track_single_recognized_packet() {
    const auto recognized_packet = make_ethernet_ipv4_tcp_packet(ipv4(10, 60, 2, 1), ipv4(10, 60, 2, 2), 6003, 443);
    const auto capture_path = write_temp_pcap(
        "pfl_capture_packet_statistics_single_recognized.pcap",
        make_classic_pcap({
            {100U, recognized_packet},
        })
    );

    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(capture_path));

    const auto& statistics = session.packet_statistics();
    PFL_EXPECT(statistics.total_packet_count == 1U);
    PFL_EXPECT(statistics.total_captured_bytes == static_cast<std::uint64_t>(recognized_packet.size()));
    PFL_EXPECT(statistics.total_original_bytes == static_cast<std::uint64_t>(recognized_packet.size()));
    PFL_EXPECT(statistics.timestamp_range.available);
    PFL_EXPECT(statistics.timestamp_range.earliest_timestamp_us == 1'000'100ULL);
    PFL_EXPECT(statistics.timestamp_range.latest_timestamp_us == 1'000'100ULL);
    PFL_EXPECT(statistics.truncated_packet_count == 0U);
    PFL_EXPECT(statistics.maximum_captured_packet_length == static_cast<std::uint32_t>(recognized_packet.size()));
    PFL_EXPECT(statistics.maximum_original_packet_length == static_cast<std::uint32_t>(recognized_packet.size()));
    PFL_EXPECT(statistics.unrecognized_packet_count == 0U);
    PFL_EXPECT(statistics.unrecognized_captured_bytes == 0U);
    PFL_EXPECT(statistics.unrecognized_original_bytes == 0U);
    expect_capture_packet_statistics_invariants(statistics);
    expect_capture_packet_size_bucket(
        statistics.captured_size_distribution,
        "captured_bytes_0_63",
        1U,
        0U,
        63U
    );
    expect_capture_packet_size_bucket(
        statistics.original_size_distribution,
        "original_bytes_0_63",
        1U,
        0U,
        63U
    );
}

void expect_capture_packet_statistics_track_single_truncated_packet() {
    const auto recognized_packet = make_ethernet_ipv4_tcp_packet(ipv4(10, 60, 3, 1), ipv4(10, 60, 3, 2), 6004, 443);
    const auto capture_path = write_temp_pcap(
        "pfl_capture_packet_statistics_single_truncated.pcap",
        make_classic_pcap_with_captured_lengths({
            {
                .ts_usec = 220U,
                .captured_bytes = recognized_packet,
                .original_length = 600U,
            },
        })
    );

    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(capture_path));

    const auto& statistics = session.packet_statistics();
    PFL_EXPECT(statistics.total_packet_count == 1U);
    PFL_EXPECT(statistics.total_captured_bytes == static_cast<std::uint64_t>(recognized_packet.size()));
    PFL_EXPECT(statistics.total_original_bytes == 600U);
    PFL_EXPECT(statistics.timestamp_range.available);
    PFL_EXPECT(statistics.timestamp_range.earliest_timestamp_us == 1'000'220ULL);
    PFL_EXPECT(statistics.timestamp_range.latest_timestamp_us == 1'000'220ULL);
    PFL_EXPECT(statistics.truncated_packet_count == 1U);
    PFL_EXPECT(statistics.maximum_captured_packet_length == static_cast<std::uint32_t>(recognized_packet.size()));
    PFL_EXPECT(statistics.maximum_original_packet_length == 600U);
    PFL_EXPECT(statistics.unrecognized_packet_count == 0U);
    expect_capture_packet_statistics_invariants(statistics);
    expect_capture_packet_size_bucket(
        statistics.captured_size_distribution,
        "captured_bytes_0_63",
        1U,
        0U,
        63U
    );
    expect_capture_packet_size_bucket(
        statistics.original_size_distribution,
        "original_bytes_512_1000",
        1U,
        512U,
        1000U
    );
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
    PFL_EXPECT(
        statistics.total_captured_bytes ==
        static_cast<std::uint64_t>(recognized_packet.size() + unrecognized_packet.size())
    );
    PFL_EXPECT(statistics.maximum_bucket_packet_count == 2U);
    PFL_EXPECT(statistics.maximum_captured_packet_length == static_cast<std::uint32_t>(recognized_packet.size()));
    PFL_EXPECT(session.summary().packet_count == 1U);
    PFL_EXPECT(session.unrecognized_packet_count() == 1U);
}

void expect_capture_packet_statistics_tracks_total_original_timestamp_truncation_and_unrecognized_fields() {
    const auto recognized_packet = make_ethernet_ipv4_tcp_packet(ipv4(10, 60, 1, 1), ipv4(10, 60, 1, 2), 6002, 443);
    const auto unrecognized_packet = large_unrecognized_ethernet_frame();
    const auto capture_path = write_temp_pcap(
        "pfl_capture_packet_statistics_full_runtime_authority.pcap",
        make_classic_pcap_with_captured_lengths({
            {
                .ts_usec = 400U,
                .captured_bytes = recognized_packet,
                .original_length = 300U,
            },
            {
                .ts_usec = 100U,
                .captured_bytes = unrecognized_packet,
                .original_length = 9001U,
            },
        })
    );

    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(capture_path));

    const auto& statistics = session.packet_statistics();
    PFL_EXPECT(statistics.total_packet_count == 2U);
    PFL_EXPECT(
        statistics.total_captured_bytes ==
        static_cast<std::uint64_t>(recognized_packet.size() + unrecognized_packet.size())
    );
    PFL_EXPECT(statistics.total_original_bytes == 9301U);
    PFL_EXPECT(statistics.timestamp_range.available);
    PFL_EXPECT(statistics.timestamp_range.earliest_timestamp_us == 1'000'400ULL);
    PFL_EXPECT(statistics.timestamp_range.latest_timestamp_us == 2'000'100ULL);
    PFL_EXPECT(statistics.truncated_packet_count == 2U);
    PFL_EXPECT(statistics.maximum_captured_packet_length == static_cast<std::uint32_t>(unrecognized_packet.size()));
    PFL_EXPECT(statistics.maximum_original_packet_length == 9001U);
    PFL_EXPECT(statistics.captured_size_distribution.maximum_bucket_packet_count == 1U);
    PFL_EXPECT(statistics.original_size_distribution.maximum_bucket_packet_count == 1U);
    PFL_EXPECT(statistics.unrecognized_packet_count == 1U);
    PFL_EXPECT(statistics.unrecognized_captured_bytes == static_cast<std::uint64_t>(unrecognized_packet.size()));
    PFL_EXPECT(statistics.unrecognized_original_bytes == 9001U);
    expect_capture_packet_statistics_invariants(statistics);
    expect_capture_packet_size_bucket(
        statistics.captured_size_distribution,
        "captured_bytes_0_63",
        1U,
        0U,
        63U
    );
    expect_capture_packet_size_bucket(
        statistics.captured_size_distribution,
        "captured_bytes_256_511",
        1U,
        256U,
        511U
    );
    expect_capture_packet_size_bucket(
        statistics.original_size_distribution,
        "original_bytes_256_511",
        1U,
        256U,
        511U
    );
    expect_capture_packet_size_bucket(
        statistics.original_size_distribution,
        "original_bytes_9001_16000",
        1U,
        9001U,
        16000U
    );
}

void expect_capture_packet_statistics_use_temporal_min_max_for_out_of_order_pcapng_packets() {
    const auto first_packet = make_ethernet_ipv4_tcp_packet(ipv4(10, 60, 4, 1), ipv4(10, 60, 4, 2), 6005, 443);
    const auto second_packet = unrecognized_ethernet_frame();
    const auto third_packet = make_ethernet_ipv4_udp_packet(ipv4(10, 60, 4, 3), ipv4(10, 60, 4, 4), 53005, 53);
    const auto capture_path = write_temp_pcap(
        "pfl_capture_packet_statistics_out_of_order_timestamps.pcapng",
        make_pcapng({
            make_pcapng_section_header_block(),
            make_pcapng_interface_description_block(),
            make_pcapng_enhanced_packet_block(0U, 5U, 900U, first_packet),
            make_pcapng_enhanced_packet_block(0U, 3U, 50U, second_packet),
            make_pcapng_enhanced_packet_block(0U, 4U, 700U, third_packet),
        })
    );

    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(capture_path));

    const auto& statistics = session.packet_statistics();
    PFL_EXPECT(statistics.total_packet_count == 3U);
    PFL_EXPECT(
        statistics.total_captured_bytes ==
        static_cast<std::uint64_t>(first_packet.size() + second_packet.size() + third_packet.size())
    );
    PFL_EXPECT(
        statistics.total_original_bytes ==
        static_cast<std::uint64_t>(first_packet.size() + second_packet.size() + third_packet.size())
    );
    PFL_EXPECT(statistics.timestamp_range.available);
    PFL_EXPECT(statistics.timestamp_range.earliest_timestamp_us == 3'000'050ULL);
    PFL_EXPECT(statistics.timestamp_range.latest_timestamp_us == 5'000'900ULL);
    PFL_EXPECT(statistics.truncated_packet_count == 0U);
    PFL_EXPECT(statistics.unrecognized_packet_count == 1U);
    PFL_EXPECT(statistics.unrecognized_captured_bytes == static_cast<std::uint64_t>(second_packet.size()));
    PFL_EXPECT(statistics.unrecognized_original_bytes == static_cast<std::uint64_t>(second_packet.size()));
    expect_capture_packet_statistics_invariants(statistics);
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
    PFL_EXPECT(
        statistics.total_captured_bytes ==
        static_cast<std::uint64_t>(recognized_packet.size() + malformed_packet.size())
    );
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
    PFL_EXPECT(statistics.total_captured_bytes == static_cast<std::uint64_t>(first_packet.size()));
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
    PFL_EXPECT(
        statistics.total_captured_bytes ==
        static_cast<std::uint64_t>(recognized_packet.size() + unrecognized_packet.size())
    );
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
    PFL_EXPECT(kCaptureIndexVersion == 15U);

    CaptureSession loaded_session {};
    PFL_REQUIRE(loaded_session.load_index(index_path));
    const auto loaded_statistics = loaded_session.packet_size_statistics();

    PFL_EXPECT(imported_statistics.total_packet_count == loaded_statistics.total_packet_count);
    PFL_EXPECT(imported_statistics.total_captured_bytes == loaded_statistics.total_captured_bytes);
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

void expect_capture_packet_statistics_survive_index_roundtrip() {
    const auto recognized_packet = make_ethernet_ipv4_tcp_packet(ipv4(10, 64, 1, 1), ipv4(10, 64, 1, 2), 6402, 443);
    const auto unrecognized_packet = large_unrecognized_ethernet_frame();
    const auto capture_path = write_temp_pcap(
        "pfl_capture_packet_statistics_roundtrip.pcap",
        make_classic_pcap_with_captured_lengths({
            {
                .ts_usec = 250U,
                .captured_bytes = recognized_packet,
                .original_length = 600U,
            },
            {
                .ts_usec = 900U,
                .captured_bytes = unrecognized_packet,
                .original_length = 30'000U,
            },
        })
    );

    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(capture_path));
    const auto imported_statistics = session.packet_statistics();

    const auto index_path = std::filesystem::temp_directory_path() / "pfl_capture_packet_statistics_roundtrip.idx";
    std::filesystem::remove(index_path);
    PFL_REQUIRE(session.save_index(index_path));

    CaptureSession loaded_session {};
    PFL_REQUIRE(loaded_session.load_index(index_path));
    const auto loaded_statistics = loaded_session.packet_statistics();

    expect_capture_packet_statistics_equal(imported_statistics, loaded_statistics);
}

void expect_capture_packet_size_statistics_ignores_unsurfaced_classic_packet_failures() {
    const auto large_packet = large_unrecognized_ethernet_frame();
    const auto capture_path = write_temp_pcap(
        "pfl_capture_packet_size_unsurfaced_classic_failure.pcap",
        make_single_packet_classic_pcap_with_declared_capture_length(
            large_packet,
            static_cast<std::uint32_t>(large_packet.size()),
            static_cast<std::uint32_t>(large_packet.size()),
            220U
        )
    );

    PcapReader reader {};
    PFL_REQUIRE(reader.open(capture_path));
    CaptureState state {};
    const auto result = import_capture_from_reader(reader, state, CaptureImportProcessor {});

    PFL_EXPECT(result == CaptureImportResult::failure);
    PFL_EXPECT(state.summary.packet_count == 0U);
    PFL_EXPECT(state.unrecognized_packets.empty());
    PFL_EXPECT(state.packet_statistics.total_packet_count == 0U);
    PFL_EXPECT(state.packet_statistics.total_captured_bytes == 0U);
    PFL_EXPECT(state.packet_statistics.total_original_bytes == 0U);
    PFL_EXPECT(state.packet_statistics.captured_size_distribution.maximum_bucket_packet_count == 0U);
    PFL_EXPECT(state.packet_statistics.maximum_captured_packet_length == 0U);
    PFL_EXPECT(state.packet_statistics.maximum_original_packet_length == 0U);
    expect_capture_packet_statistics_invariants(state.packet_statistics);
}

void expect_capture_packet_size_statistics_count_surfaced_packet_before_trailing_reader_error() {
    const auto recognized_packet = large_recognized_tcp_frame_without_payload();
    auto capture_bytes = make_classic_pcap({{100U, recognized_packet}});
    capture_bytes.push_back(0xdeU);
    capture_bytes.push_back(0xadU);
    capture_bytes.push_back(0xbeU);
    capture_bytes.push_back(0xefU);
    capture_bytes.push_back(0x01U);
    capture_bytes.push_back(0x02U);
    capture_bytes.push_back(0x03U);
    capture_bytes.push_back(0x04U);
    const auto capture_path = write_temp_pcap(
        "pfl_capture_packet_size_surfaced_before_reader_error.pcap",
        capture_bytes
    );

    PcapReader reader {};
    PFL_REQUIRE(reader.open(capture_path));
    CaptureState state {};
    const auto result = import_capture_from_reader(reader, state, CaptureImportProcessor {});

    PFL_EXPECT(result == CaptureImportResult::partial_success_with_warning);
    PFL_EXPECT(state.summary.packet_count == 1U);
    PFL_EXPECT(state.unrecognized_packets.empty());
    PFL_EXPECT(state.packet_statistics.total_packet_count == 1U);
    PFL_EXPECT(state.packet_statistics.total_captured_bytes == static_cast<std::uint64_t>(recognized_packet.size()));
    PFL_EXPECT(state.packet_statistics.total_original_bytes == static_cast<std::uint64_t>(recognized_packet.size()));
    PFL_EXPECT(state.packet_statistics.captured_size_distribution.maximum_bucket_packet_count == 1U);
    PFL_EXPECT(state.packet_statistics.maximum_captured_packet_length == static_cast<std::uint32_t>(recognized_packet.size()));
    PFL_EXPECT(state.packet_statistics.maximum_original_packet_length == static_cast<std::uint32_t>(recognized_packet.size()));
    PFL_EXPECT(state.packet_statistics.timestamp_range.available);
    PFL_EXPECT(state.packet_statistics.timestamp_range.earliest_timestamp_us == 1'000'100ULL);
    PFL_EXPECT(state.packet_statistics.timestamp_range.latest_timestamp_us == 1'000'100ULL);
    PFL_EXPECT(state.packet_statistics.truncated_packet_count == 0U);
    expect_capture_packet_statistics_invariants(state.packet_statistics);
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
    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(capture_path));

    const auto overview = adapter.get_overview();
    const auto hint_statistics = adapter.get_protocol_hint_statistics();
    const auto quic_tls_statistics = adapter.get_quic_tls_statistics();
    const auto top_statistics = adapter.get_top_endpoint_port_statistics(5U);
    const auto packet_size_statistics = adapter.get_capture_packet_size_statistics();
    const auto histogram = adapter.get_flow_packet_count_histogram();
    const auto expected_capture_time = build_frontend_capture_time_statistics(session.packet_statistics());
    const auto expected_capture_metrics = build_frontend_capture_metrics(session.packet_statistics());
    const auto expected_flow_characteristics =
        build_frontend_flow_characteristics(session.flow_characteristics_statistics());
    const auto expected_packet_direction_distribution =
        build_frontend_packet_direction_distribution(
            session.flow_characteristics_statistics(),
            session.packet_direction_distribution_statistics()
        );
    const auto expected_original_byte_direction_distribution =
        build_frontend_original_byte_direction_distribution(
            session.flow_characteristics_statistics(),
            session.original_byte_direction_distribution_statistics()
        );

    PFL_EXPECT(overview.has_capture);
    PFL_EXPECT(overview.summary.flow_count == 3U);
    PFL_EXPECT(overview.whole_capture_totals.packet_count == overview.summary.packet_count);
    PFL_EXPECT(overview.summary.captured_bytes_text == session_detail::format_statistics_compact_size_value(overview.summary.captured_bytes));
    PFL_EXPECT(overview.summary.original_bytes_text == session_detail::format_statistics_compact_size_value(overview.summary.original_bytes));
    PFL_EXPECT(overview.whole_capture_totals.captured_bytes == overview.summary.captured_bytes);
    PFL_EXPECT(overview.whole_capture_totals.original_bytes == overview.summary.original_bytes);
    PFL_EXPECT(
        overview.whole_capture_totals.captured_bytes_text ==
        session_detail::format_statistics_compact_size_value(overview.whole_capture_totals.captured_bytes)
    );
    PFL_EXPECT(
        overview.whole_capture_totals.original_bytes_text ==
        session_detail::format_statistics_compact_size_value(overview.whole_capture_totals.original_bytes)
    );
    PFL_EXPECT(overview.input_metadata.input_kind == FrontendInputKind::classic_pcap);
    PFL_EXPECT(overview.input_metadata.input_path == capture_path.string());
    PFL_EXPECT(overview.input_metadata.input_file_size == std::filesystem::file_size(capture_path));
    PFL_EXPECT(!overview.input_metadata.source_capture_path.has_value());
    PFL_EXPECT(overview.input_metadata.source_capture_accessible);
    PFL_EXPECT(overview.protocol_summary.tcp.flow_count == 1U);
    PFL_EXPECT(overview.protocol_summary.udp.flow_count == 2U);
    PFL_EXPECT(overview.protocol_summary.tcp.captured_bytes_text
        == session_detail::format_statistics_compact_size_value(overview.protocol_summary.tcp.captured_bytes));
    PFL_EXPECT(overview.protocol_summary.udp.original_bytes_text
        == session_detail::format_statistics_compact_size_value(overview.protocol_summary.udp.original_bytes));
    PFL_EXPECT(overview.capture_time.available);
    PFL_EXPECT(overview.capture_time.capture_start_text == expected_capture_time.capture_start_text);
    PFL_EXPECT(overview.capture_time.capture_end_text == expected_capture_time.capture_end_text);
    PFL_EXPECT(overview.capture_time.duration_text == expected_capture_time.duration_text);
    PFL_EXPECT(overview.capture_metrics.average_captured_packet_size_text
        == expected_capture_metrics.average_captured_packet_size_text);
    PFL_EXPECT(overview.capture_metrics.average_original_packet_size_text
        == expected_capture_metrics.average_original_packet_size_text);
    PFL_EXPECT(overview.capture_metrics.average_packet_rate_text
        == expected_capture_metrics.average_packet_rate_text);
    PFL_EXPECT(overview.capture_metrics.average_captured_data_rate_text
        == expected_capture_metrics.average_captured_data_rate_text);
    PFL_EXPECT(overview.capture_metrics.average_original_data_rate_text
        == expected_capture_metrics.average_original_data_rate_text);
    PFL_EXPECT(overview.capture_metrics.truncated_packets_text
        == expected_capture_metrics.truncated_packets_text);
    PFL_EXPECT(overview.capture_metrics.not_captured_bytes_text
        == expected_capture_metrics.not_captured_bytes_text);
    PFL_EXPECT(overview.capture_metrics.capture_completeness_text
        == expected_capture_metrics.capture_completeness_text);
    PFL_EXPECT(overview.flow_characteristics.total_flow_count == 3U);
    PFL_EXPECT(overview.flow_characteristics.only_a_to_b_flows_text
        == expected_flow_characteristics.only_a_to_b_flows_text);
    PFL_EXPECT(overview.flow_characteristics.service_recognized_flows_text
        == expected_flow_characteristics.service_recognized_flows_text);
    PFL_EXPECT(overview.packet_direction_distribution.rows.size() == 3U);
    PFL_EXPECT(overview.packet_direction_distribution.rows[0].label
        == expected_packet_direction_distribution.rows[0].label);
    PFL_EXPECT(overview.packet_direction_distribution.rows[0].flow_count_text
        == expected_packet_direction_distribution.rows[0].flow_count_text);
    PFL_EXPECT(overview.packet_direction_distribution.rows[0].percent_text
        == expected_packet_direction_distribution.rows[0].percent_text);
    PFL_EXPECT(overview.packet_direction_distribution.rows[1].label
        == expected_packet_direction_distribution.rows[1].label);
    PFL_EXPECT(overview.packet_direction_distribution.rows[1].flow_count_text
        == expected_packet_direction_distribution.rows[1].flow_count_text);
    PFL_EXPECT(overview.packet_direction_distribution.rows[1].percent_text
        == expected_packet_direction_distribution.rows[1].percent_text);
    PFL_EXPECT(overview.packet_direction_distribution.rows[2].label
        == expected_packet_direction_distribution.rows[2].label);
    PFL_EXPECT(overview.packet_direction_distribution.rows[2].flow_count_text
        == expected_packet_direction_distribution.rows[2].flow_count_text);
    PFL_EXPECT(overview.packet_direction_distribution.rows[2].percent_text
        == expected_packet_direction_distribution.rows[2].percent_text);
    PFL_EXPECT(overview.original_byte_direction_distribution.help_text
        == expected_original_byte_direction_distribution.help_text);
    PFL_EXPECT(overview.original_byte_direction_distribution.rows.size() == 3U);
    PFL_EXPECT(overview.original_byte_direction_distribution.rows[0].percent_text
        == expected_original_byte_direction_distribution.rows[0].percent_text);
    PFL_EXPECT(overview.original_byte_direction_distribution.rows[1].percent_text
        == expected_original_byte_direction_distribution.rows[1].percent_text);
    PFL_EXPECT(overview.original_byte_direction_distribution.rows[2].percent_text
        == expected_original_byte_direction_distribution.rows[2].percent_text);
    PFL_EXPECT(overview.statistics_partial_open_warning_text.empty());

    PFL_EXPECT(hint_statistics.has_capture);
    PFL_EXPECT(hint_statistics.protocol_hints.size() == 13U);
    PFL_REQUIRE(!hint_statistics.protocol_hints.empty());
    PFL_EXPECT(hint_statistics.protocol_hints.back().protocol_label == "Unknown");
    PFL_EXPECT(hint_statistics.protocol_hints.back().flow_count_text == "3 (100%)");
    PFL_EXPECT(hint_statistics.protocol_hints.back().packet_count_text == "4 (100%)");
    PFL_EXPECT(
        hint_statistics.protocol_hints.back().captured_bytes_text
        == session_detail::format_statistics_size_with_percent_text(
            hint_statistics.protocol_hints.back().captured_bytes,
            100.0
        )
    );
    PFL_EXPECT(
        hint_statistics.protocol_hints.back().original_bytes_text
        == session_detail::format_statistics_size_with_percent_text(
            hint_statistics.protocol_hints.back().original_bytes,
            100.0
        )
    );

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
    PFL_EXPECT(find_bucket(packet_size_statistics, "captured_bytes_0_63")->packet_count_text == "4");
    PFL_EXPECT(find_bucket(packet_size_statistics, "captured_bytes_0_63")->total_fraction == 1.0);
    PFL_EXPECT(find_bucket(packet_size_statistics, "captured_bytes_0_63")->total_percent_text == "100%");

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
    PFL_EXPECT(find_bucket(histogram, "packets_1")->flow_count_with_total_percent_text == "2 (67%)");
    PFL_EXPECT(find_bucket(histogram, "packets_1")->total_flow_fraction > 0.66);
    PFL_EXPECT(find_bucket(histogram, "packets_1")->total_flow_fraction < 0.67);
    PFL_EXPECT(find_bucket(histogram, "packets_1")->normalized_flow_fraction == 1.0);
    PFL_EXPECT(find_bucket(histogram, "packets_2")->normalized_flow_fraction == 0.5);
    PFL_EXPECT(find_bucket(histogram, "packets_1")->original_byte_count_text.find('B') != std::string::npos);
    PFL_EXPECT(find_bucket(histogram, "packets_1")->original_byte_count_with_total_percent_text.find('%') != std::string::npos);
    PFL_EXPECT(find_bucket(histogram, "packets_2")->normalized_original_byte_fraction > 0.0);
}

void expect_frontend_statistics_overview_helpers_cover_availability_and_direction_distributions() {
    const auto empty_time = build_frontend_capture_time_statistics(CapturePacketStatistics {});
    const auto empty_metrics = build_frontend_capture_metrics(CapturePacketStatistics {});
    const auto empty_characteristics = build_frontend_flow_characteristics(CaptureFlowCharacteristicsStatistics {});
    const auto empty_packet_distribution = build_frontend_packet_direction_distribution(
        CaptureFlowCharacteristicsStatistics {},
        FlowDirectionDistributionStatistics {}
    );
    const auto empty_original_distribution = build_frontend_original_byte_direction_distribution(
        CaptureFlowCharacteristicsStatistics {},
        FlowDirectionDistributionStatistics {}
    );
    const auto unavailable = unavailable_text();

    PFL_EXPECT(!empty_time.available);
    PFL_EXPECT(empty_time.capture_start_text == unavailable);
    PFL_EXPECT(empty_time.capture_end_text == unavailable);
    PFL_EXPECT(empty_time.duration_text == unavailable);
    PFL_EXPECT(empty_metrics.average_captured_packet_size_text == unavailable);
    PFL_EXPECT(empty_metrics.average_original_packet_size_text == unavailable);
    PFL_EXPECT(empty_metrics.average_packet_rate_text == unavailable);
    PFL_EXPECT(empty_metrics.average_captured_data_rate_text == unavailable);
    PFL_EXPECT(empty_metrics.average_original_data_rate_text == unavailable);
    PFL_EXPECT(empty_metrics.truncated_packets_text == "0 (0%)");
    PFL_EXPECT(empty_metrics.not_captured_bytes_text == "0 B");
    PFL_EXPECT(empty_metrics.capture_completeness_text == unavailable);
    PFL_EXPECT(empty_characteristics.only_a_to_b_flows_text == "0 (0%)");
    PFL_EXPECT(empty_characteristics.service_recognized_flows_text == "0 (0%)");
    PFL_EXPECT(empty_packet_distribution.rows.size() == 3U);
    PFL_EXPECT(empty_original_distribution.rows.size() == 3U);
    expect_not_nan_or_inf_text(empty_metrics.average_captured_packet_size_text);
    expect_not_nan_or_inf_text(empty_metrics.average_original_packet_size_text);
    expect_not_nan_or_inf_text(empty_metrics.average_packet_rate_text);
    expect_not_nan_or_inf_text(empty_metrics.average_captured_data_rate_text);
    expect_not_nan_or_inf_text(empty_metrics.average_original_data_rate_text);
    expect_not_nan_or_inf_text(empty_metrics.capture_completeness_text);

    CapturePacketStatistics single_packet_statistics {};
    single_packet_statistics.total_packet_count = 1U;
    single_packet_statistics.total_captured_bytes = 60U;
    single_packet_statistics.total_original_bytes = 100U;
    single_packet_statistics.timestamp_range = CapturePacketTimestampRange {
        .available = true,
        .earliest_timestamp_us = 0U,
        .latest_timestamp_us = 0U,
    };
    single_packet_statistics.truncated_packet_count = 1U;

    const auto single_time = build_frontend_capture_time_statistics(single_packet_statistics);
    const auto single_metrics = build_frontend_capture_metrics(single_packet_statistics);
    PFL_EXPECT(single_time.available);
    PFL_EXPECT(single_time.capture_start_text == "1970-01-01 00:00:00.000 UTC");
    PFL_EXPECT(single_time.capture_end_text == "1970-01-01 00:00:00.000 UTC");
    PFL_EXPECT(single_time.duration_text == "00:00:00.000");
    PFL_EXPECT(single_metrics.average_captured_packet_size_text == "60 B");
    PFL_EXPECT(single_metrics.average_original_packet_size_text == "100 B");
    PFL_EXPECT(single_metrics.average_packet_rate_text == unavailable);
    PFL_EXPECT(single_metrics.average_captured_data_rate_text == unavailable);
    PFL_EXPECT(single_metrics.average_original_data_rate_text == unavailable);
    PFL_EXPECT(single_metrics.truncated_packets_text == "1 (100%)");
    PFL_EXPECT(single_metrics.not_captured_bytes_text == "40 B");
    PFL_EXPECT(single_metrics.capture_completeness_text == "60%");
    expect_not_nan_or_inf_text(single_metrics.average_packet_rate_text);
    expect_not_nan_or_inf_text(single_metrics.average_captured_data_rate_text);
    expect_not_nan_or_inf_text(single_metrics.average_original_data_rate_text);

    CapturePacketStatistics multi_packet_statistics {};
    multi_packet_statistics.total_packet_count = 4U;
    multi_packet_statistics.total_captured_bytes = 2048U;
    multi_packet_statistics.total_original_bytes = 4096U;
    multi_packet_statistics.timestamp_range = CapturePacketTimestampRange {
        .available = true,
        .earliest_timestamp_us = 0U,
        .latest_timestamp_us = 2'000'000U,
    };
    multi_packet_statistics.truncated_packet_count = 1U;

    const auto multi_time = build_frontend_capture_time_statistics(multi_packet_statistics);
    const auto multi_metrics = build_frontend_capture_metrics(multi_packet_statistics);
    PFL_EXPECT(multi_time.capture_start_text == "1970-01-01 00:00:00.000 UTC");
    PFL_EXPECT(multi_time.capture_end_text == "1970-01-01 00:00:02.000 UTC");
    PFL_EXPECT(multi_time.duration_text == "00:00:02.000");
    PFL_EXPECT(multi_metrics.average_captured_packet_size_text == "512 B");
    PFL_EXPECT(multi_metrics.average_original_packet_size_text == "1 KB");
    PFL_EXPECT(multi_metrics.average_packet_rate_text == "2 pkt/s");
    PFL_EXPECT(multi_metrics.average_captured_data_rate_text == "1 KB/s");
    PFL_EXPECT(multi_metrics.average_original_data_rate_text == "2 KB/s");
    PFL_EXPECT(multi_metrics.truncated_packets_text == "1 (25%)");
    PFL_EXPECT(multi_metrics.not_captured_bytes_text == "2 KB (2 048 B)");
    PFL_EXPECT(multi_metrics.capture_completeness_text == "50%");
    expect_not_nan_or_inf_text(multi_metrics.average_captured_packet_size_text);
    expect_not_nan_or_inf_text(multi_metrics.average_original_packet_size_text);
    expect_not_nan_or_inf_text(multi_metrics.average_packet_rate_text);
    expect_not_nan_or_inf_text(multi_metrics.average_captured_data_rate_text);
    expect_not_nan_or_inf_text(multi_metrics.average_original_data_rate_text);
    expect_not_nan_or_inf_text(multi_metrics.capture_completeness_text);

    CapturePacketStatistics complete_statistics {};
    complete_statistics.total_packet_count = 8U;
    complete_statistics.total_captured_bytes = 4096U;
    complete_statistics.total_original_bytes = 4096U;
    const auto complete_metrics = build_frontend_capture_metrics(complete_statistics);
    PFL_EXPECT(complete_metrics.capture_completeness_text == "100%");
    expect_not_nan_or_inf_text(complete_metrics.capture_completeness_text);

    CapturePacketStatistics zero_original_statistics {};
    zero_original_statistics.total_packet_count = 2U;
    zero_original_statistics.total_captured_bytes = 128U;
    zero_original_statistics.total_original_bytes = 0U;
    const auto zero_original_metrics = build_frontend_capture_metrics(zero_original_statistics);
    PFL_EXPECT(zero_original_metrics.average_captured_packet_size_text == "64 B");
    PFL_EXPECT(zero_original_metrics.average_original_packet_size_text == "0 B");
    PFL_EXPECT(zero_original_metrics.capture_completeness_text == unavailable);
    expect_not_nan_or_inf_text(zero_original_metrics.capture_completeness_text);

    CapturePacketStatistics slightly_incomplete_statistics {};
    slightly_incomplete_statistics.total_packet_count = 10U;
    slightly_incomplete_statistics.total_captured_bytes = 9'999U;
    slightly_incomplete_statistics.total_original_bytes = 10'000U;
    slightly_incomplete_statistics.timestamp_range = CapturePacketTimestampRange {
        .available = true,
        .earliest_timestamp_us = 0U,
        .latest_timestamp_us = 732'333U,
    };
    const auto slightly_incomplete_time = build_frontend_capture_time_statistics(slightly_incomplete_statistics);
    const auto slightly_incomplete_metrics = build_frontend_capture_metrics(slightly_incomplete_statistics);
    PFL_EXPECT(slightly_incomplete_time.capture_start_text == "1970-01-01 00:00:00.000 UTC");
    PFL_EXPECT(slightly_incomplete_time.capture_end_text == "1970-01-01 00:00:00.732 UTC");
    PFL_EXPECT(slightly_incomplete_time.duration_text == "00:00:00.732");
    PFL_EXPECT(slightly_incomplete_metrics.average_packet_rate_text == "13.65 pkt/s");
    PFL_EXPECT(slightly_incomplete_metrics.capture_completeness_text != "100%");
    PFL_EXPECT(slightly_incomplete_metrics.capture_completeness_text == "99.99%");
    expect_not_nan_or_inf_text(slightly_incomplete_metrics.average_packet_rate_text);
    expect_not_nan_or_inf_text(slightly_incomplete_metrics.capture_completeness_text);

    CaptureFlowCharacteristicsStatistics flow_characteristics {};
    flow_characteristics.total_flow_count = 10U;
    flow_characteristics.only_a_to_b_flow_count = 2U;
    flow_characteristics.service_recognized_flow_count = 7U;
    const auto packet_direction_distribution_statistics = FlowDirectionDistributionStatistics {
        .mostly_a_to_b_flow_count = 3U,
        .balanced_flow_count = 4U,
        .mostly_b_to_a_flow_count = 3U,
    };
    const auto original_byte_direction_distribution_statistics = FlowDirectionDistributionStatistics {
        .mostly_a_to_b_flow_count = 5U,
        .balanced_flow_count = 1U,
        .mostly_b_to_a_flow_count = 4U,
    };

    const auto characteristics = build_frontend_flow_characteristics(flow_characteristics);
    const auto packet_distribution = build_frontend_packet_direction_distribution(
        flow_characteristics,
        packet_direction_distribution_statistics
    );
    const auto original_distribution = build_frontend_original_byte_direction_distribution(
        flow_characteristics,
        original_byte_direction_distribution_statistics
    );

    PFL_EXPECT(characteristics.only_a_to_b_flows_text == "2 (20%)");
    PFL_EXPECT(characteristics.service_recognized_flows_text == "7 (70%)");
    PFL_EXPECT(packet_distribution.total_flow_count == 10U);
    PFL_EXPECT(packet_distribution.rows.size() == 3U);
    PFL_EXPECT(packet_distribution.rows[0].stable_id == "mostly_a_to_b");
    PFL_EXPECT(packet_distribution.rows[0].label == "Mostly A -> B");
    PFL_EXPECT(packet_distribution.rows[0].flow_count_text == "3");
    PFL_EXPECT(packet_distribution.rows[0].percent_text == "30%");
    PFL_EXPECT(packet_distribution.rows[1].stable_id == "balanced");
    PFL_EXPECT(packet_distribution.rows[1].flow_count_text == "4");
    PFL_EXPECT(packet_distribution.rows[1].percent_text == "40%");
    PFL_EXPECT(packet_distribution.rows[2].stable_id == "mostly_b_to_a");
    PFL_EXPECT(packet_distribution.rows[2].flow_count_text == "3");
    PFL_EXPECT(packet_distribution.rows[2].percent_text == "30%");
    PFL_EXPECT(original_distribution.total_flow_count == 10U);
    PFL_EXPECT(original_distribution.help_text == "Flows grouped by directional original-byte balance.");
    PFL_EXPECT(original_distribution.rows.size() == 3U);
    PFL_EXPECT(original_distribution.rows[0].flow_count_text == "5");
    PFL_EXPECT(original_distribution.rows[0].percent_text == "50%");
    PFL_EXPECT(original_distribution.rows[1].flow_count_text == "1");
    PFL_EXPECT(original_distribution.rows[1].percent_text == "10%");
    PFL_EXPECT(original_distribution.rows[2].flow_count_text == "4");
    PFL_EXPECT(original_distribution.rows[2].percent_text == "40%");
    PFL_EXPECT(build_frontend_statistics_partial_open_warning_text(true)
        == "Statistics cover successfully imported packets only; the capture was opened partially.");
    PFL_EXPECT(build_frontend_statistics_partial_open_warning_text(false).empty());
}

void expect_overview_whole_capture_totals_and_input_metadata_cover_unrecognized_and_index_inputs() {
    const auto recognized_packet = make_ethernet_ipv4_tcp_packet(ipv4(10, 66, 0, 1), ipv4(10, 66, 0, 2), 6601, 443);
    const auto unrecognized_packet = unrecognized_ethernet_frame();
    const auto capture_path = write_temp_pcap(
        "pfl_statistics_overview_whole_capture_totals.pcap",
        make_classic_pcap({
            {100U, recognized_packet},
            {200U, unrecognized_packet},
        })
    );

    FrontendSessionAdapter raw_adapter {};
    PFL_REQUIRE(raw_adapter.open_capture(capture_path).opened);
    const auto raw_overview = raw_adapter.get_overview();
    PFL_EXPECT(raw_overview.input_metadata.input_kind == FrontendInputKind::classic_pcap);
    PFL_EXPECT(raw_overview.input_metadata.input_path == capture_path.string());
    PFL_EXPECT(raw_overview.input_metadata.input_file_size == std::filesystem::file_size(capture_path));
    PFL_EXPECT(!raw_overview.input_metadata.source_capture_path.has_value());
    PFL_EXPECT(raw_overview.input_metadata.source_capture_accessible);
    PFL_EXPECT(raw_overview.whole_capture_totals.packet_count == 2U);
    PFL_EXPECT(raw_overview.whole_capture_totals.packet_count > raw_overview.summary.packet_count);
    PFL_EXPECT(
        raw_overview.whole_capture_totals.captured_bytes ==
        static_cast<std::uint64_t>(recognized_packet.size() + unrecognized_packet.size())
    );
    PFL_EXPECT(
        raw_overview.whole_capture_totals.original_bytes ==
        static_cast<std::uint64_t>(recognized_packet.size() + unrecognized_packet.size())
    );
    PFL_EXPECT(raw_overview.whole_capture_totals.captured_bytes > raw_overview.summary.captured_bytes);
    PFL_EXPECT(raw_overview.whole_capture_totals.original_bytes > raw_overview.summary.original_bytes);

    const auto index_path = std::filesystem::temp_directory_path() / "pfl_statistics_overview_whole_capture_totals.idx";
    std::filesystem::remove(index_path);
    PFL_REQUIRE(raw_adapter.save_index(index_path).saved);
    std::filesystem::remove(capture_path);

    FrontendSessionAdapter index_adapter {};
    PFL_REQUIRE(index_adapter.open_capture(index_path).opened);
    const auto indexed_overview = index_adapter.get_overview();
    PFL_EXPECT(indexed_overview.input_metadata.input_kind == FrontendInputKind::pcap_flow_lab_index);
    PFL_EXPECT(indexed_overview.input_metadata.input_path == index_path.string());
    PFL_EXPECT(indexed_overview.input_metadata.input_file_size == std::filesystem::file_size(index_path));
    PFL_REQUIRE(indexed_overview.input_metadata.source_capture_path.has_value());
    PFL_EXPECT(*indexed_overview.input_metadata.source_capture_path == capture_path.string());
    PFL_EXPECT(!indexed_overview.input_metadata.source_capture_accessible);
    PFL_EXPECT(indexed_overview.whole_capture_totals.packet_count == raw_overview.whole_capture_totals.packet_count);
    PFL_EXPECT(indexed_overview.whole_capture_totals.captured_bytes == raw_overview.whole_capture_totals.captured_bytes);
    PFL_EXPECT(indexed_overview.whole_capture_totals.original_bytes == raw_overview.whole_capture_totals.original_bytes);
    PFL_EXPECT(indexed_overview.capture_time.capture_start_text == raw_overview.capture_time.capture_start_text);
    PFL_EXPECT(indexed_overview.capture_time.capture_end_text == raw_overview.capture_time.capture_end_text);
    PFL_EXPECT(indexed_overview.capture_time.duration_text == raw_overview.capture_time.duration_text);
    PFL_EXPECT(indexed_overview.capture_metrics.average_captured_packet_size_text
        == raw_overview.capture_metrics.average_captured_packet_size_text);
    PFL_EXPECT(indexed_overview.capture_metrics.average_original_packet_size_text
        == raw_overview.capture_metrics.average_original_packet_size_text);
    PFL_EXPECT(indexed_overview.capture_metrics.average_packet_rate_text
        == raw_overview.capture_metrics.average_packet_rate_text);
    PFL_EXPECT(indexed_overview.capture_metrics.average_captured_data_rate_text
        == raw_overview.capture_metrics.average_captured_data_rate_text);
    PFL_EXPECT(indexed_overview.capture_metrics.average_original_data_rate_text
        == raw_overview.capture_metrics.average_original_data_rate_text);
    PFL_EXPECT(indexed_overview.capture_metrics.truncated_packets_text
        == raw_overview.capture_metrics.truncated_packets_text);
    PFL_EXPECT(indexed_overview.capture_metrics.not_captured_bytes_text
        == raw_overview.capture_metrics.not_captured_bytes_text);
    PFL_EXPECT(indexed_overview.capture_metrics.capture_completeness_text
        == raw_overview.capture_metrics.capture_completeness_text);
    PFL_EXPECT(indexed_overview.flow_characteristics.only_a_to_b_flows_text
        == raw_overview.flow_characteristics.only_a_to_b_flows_text);
    PFL_EXPECT(indexed_overview.flow_characteristics.service_recognized_flows_text
        == raw_overview.flow_characteristics.service_recognized_flows_text);
    PFL_EXPECT(indexed_overview.packet_direction_distribution.rows.size()
        == raw_overview.packet_direction_distribution.rows.size());
    PFL_EXPECT(indexed_overview.original_byte_direction_distribution.rows.size()
        == raw_overview.original_byte_direction_distribution.rows.size());
    PFL_EXPECT(indexed_overview.statistics_partial_open_warning_text.empty());

    const auto pcapng_packet = make_ethernet_ipv4_udp_packet(ipv4(10, 67, 0, 1), ipv4(10, 67, 0, 2), 6701, 53);
    const auto pcapng_path = write_temp_pcap(
        "pfl_statistics_overview_input_metadata.pcapng",
        make_pcapng({
            make_pcapng_section_header_block(),
            make_pcapng_interface_description_block(),
            make_pcapng_enhanced_packet_block(0U, 1U, 100U, pcapng_packet),
        })
    );

    FrontendSessionAdapter pcapng_adapter {};
    PFL_REQUIRE(pcapng_adapter.open_capture(pcapng_path).opened);
    const auto pcapng_overview = pcapng_adapter.get_overview();
    PFL_EXPECT(pcapng_overview.input_metadata.input_kind == FrontendInputKind::pcapng);
    PFL_EXPECT(pcapng_overview.input_metadata.input_path == pcapng_path.string());
    PFL_EXPECT(pcapng_overview.input_metadata.input_file_size == std::filesystem::file_size(pcapng_path));
}

void expect_statistics_overview_marks_partial_open_runtime_state() {
    const auto first_packet = make_ethernet_ipv4_tcp_packet(ipv4(10, 77, 0, 1), ipv4(10, 77, 0, 2), 7701, 443);
    const auto second_packet = make_ethernet_ipv4_udp_packet(ipv4(10, 77, 0, 3), ipv4(10, 77, 0, 4), 7702, 53);
    auto partial_capture = make_classic_pcap({
        {100U, first_packet},
        {200U, second_packet},
    });
    partial_capture.resize(partial_capture.size() - 5U);
    const auto capture_path = write_temp_pcap("pfl_statistics_partial_overview_runtime.pcap", partial_capture);

    FrontendSessionAdapter adapter {};
    PFL_REQUIRE(adapter.open_capture(capture_path).opened);
    const auto overview = adapter.get_overview();

    PFL_EXPECT(overview.has_capture);
    PFL_EXPECT(overview.whole_capture_totals.packet_count == 1U);
    PFL_EXPECT(overview.capture_time.available);
    PFL_EXPECT(overview.capture_time.capture_start_text == "1970-01-01 00:00:00.000 UTC");
    PFL_EXPECT(overview.capture_time.capture_end_text == "1970-01-01 00:00:00.000 UTC");
    PFL_EXPECT(overview.capture_time.duration_text == "00:00:00.000");
    PFL_EXPECT(overview.statistics_partial_open_warning_text
        == "Statistics cover successfully imported packets only; the capture was opened partially.");
}

void expect_statistics_adapter_exposes_total_based_percentage_fields() {
    const auto small_recognized_a = make_ethernet_ipv4_tcp_packet(ipv4(10, 68, 0, 1), ipv4(10, 68, 0, 2), 6801, 80);
    const auto small_recognized_b = make_ethernet_ipv4_tcp_packet(ipv4(10, 68, 0, 3), ipv4(10, 68, 0, 4), 6802, 80);
    const auto large_recognized = large_recognized_tcp_frame_without_payload();
    const auto small_unrecognized = unrecognized_ethernet_frame();
    const auto capture_path = write_temp_pcap(
        "pfl_statistics_total_percentage_fields.pcap",
        make_classic_pcap({
            {100U, small_recognized_a},
            {200U, small_recognized_b},
            {300U, large_recognized},
            {400U, small_unrecognized},
        })
    );

    FrontendSessionAdapter adapter {};
    PFL_REQUIRE(adapter.open_capture(capture_path).opened);

    const auto packet_size_statistics = adapter.get_capture_packet_size_statistics();
    const auto* small_bucket = find_bucket(packet_size_statistics, "captured_bytes_0_63");
    const auto* medium_bucket = find_bucket(packet_size_statistics, "captured_bytes_256_511");
    const auto* zero_bucket = find_bucket(packet_size_statistics, "captured_bytes_64_127");
    PFL_REQUIRE(small_bucket != nullptr);
    PFL_REQUIRE(medium_bucket != nullptr);
    PFL_REQUIRE(zero_bucket != nullptr);
    PFL_EXPECT(packet_size_statistics.buckets.size() == kCapturePacketSizeStatisticsBucketCount);
    PFL_EXPECT(small_bucket->packet_count == 3U);
    PFL_EXPECT(small_bucket->normalized_fraction == 1.0);
    PFL_EXPECT(small_bucket->total_fraction == 0.75);
    PFL_EXPECT(small_bucket->total_percent_text == "75%");
    PFL_EXPECT(medium_bucket->packet_count == 1U);
    PFL_EXPECT(medium_bucket->total_percent_text == "25%");
    PFL_EXPECT(zero_bucket->packet_count == 0U);
    PFL_EXPECT(zero_bucket->total_fraction == 0.0);
    PFL_EXPECT(zero_bucket->total_percent_text == "0%");

    const auto histogram = adapter.get_flow_packet_count_histogram();
    const auto* packets_1 = find_bucket(histogram, "packets_1");
    const auto* packets_2 = find_bucket(histogram, "packets_2");
    const auto* packets_3_5 = find_bucket(histogram, "packets_3_5");
    PFL_REQUIRE(packets_1 != nullptr);
    PFL_REQUIRE(packets_2 != nullptr);
    PFL_REQUIRE(packets_3_5 != nullptr);
    PFL_EXPECT(packets_1->flow_count == 2U);
    PFL_EXPECT(packets_1->flow_count_with_total_percent_text == "2 (67%)");
    PFL_EXPECT(packets_1->total_flow_fraction > 0.66);
    PFL_EXPECT(packets_1->total_flow_fraction < 0.67);
    PFL_EXPECT(packets_1->normalized_flow_fraction == 1.0);
    PFL_EXPECT(packets_2->flow_count_with_total_percent_text == "1 (33%)");
    PFL_EXPECT(packets_2->normalized_flow_fraction == 0.5);
    PFL_EXPECT(packets_2->original_byte_count_with_total_percent_text.find('%') != std::string::npos);
    PFL_EXPECT(packets_3_5->flow_count == 0U);
    PFL_EXPECT(packets_3_5->flow_count_with_total_percent_text == "0 (0%)");
    PFL_EXPECT(packets_3_5->total_flow_fraction == 0.0);
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
    PFL_EXPECT(contains_text(packet_size_json, "\"packet_count_text\""));
    PFL_EXPECT(contains_text(packet_size_json, "\"total_fraction\""));
    PFL_EXPECT(contains_text(packet_size_json, "\"total_percent_text\""));
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
    PFL_EXPECT(contains_text(histogram_json, "\"flow_count_with_total_percent_text\""));
    PFL_EXPECT(contains_text(histogram_json, "\"original_byte_count_with_total_percent_text\""));
    PFL_EXPECT(contains_text(histogram_json, "\"total_flow_fraction\""));
    PFL_EXPECT(contains_text(histogram_json, "\"total_original_byte_fraction\""));
    PFL_EXPECT(contains_text(histogram_json, "\"normalized_flow_fraction\""));
    PFL_EXPECT(contains_text(histogram_json, "\"normalized_original_byte_fraction\""));

    const auto overview_json = take_bridge_string(pfl_frontend_session_adapter_get_overview_json(handle));
    PFL_EXPECT(contains_text(overview_json, "\"protocol_summary\""));
    PFL_EXPECT(contains_text(overview_json, "\"captured_bytes_text\""));
    PFL_EXPECT(contains_text(overview_json, "\"original_bytes_text\""));
    PFL_EXPECT(contains_text(overview_json, "\"whole_capture_totals\""));
    PFL_EXPECT(contains_text(overview_json, "\"capture_time\""));
    PFL_EXPECT(contains_text(overview_json, "\"capture_start_text\""));
    PFL_EXPECT(contains_text(overview_json, "\"capture_end_text\""));
    PFL_EXPECT(contains_text(overview_json, "\"duration_text\""));
    PFL_EXPECT(contains_text(overview_json, "\"capture_metrics\""));
    PFL_EXPECT(contains_text(overview_json, "\"average_captured_packet_size_text\""));
    PFL_EXPECT(contains_text(overview_json, "\"average_original_packet_size_text\""));
    PFL_EXPECT(contains_text(overview_json, "\"average_packet_rate_text\""));
    PFL_EXPECT(contains_text(overview_json, "\"average_captured_data_rate_text\""));
    PFL_EXPECT(contains_text(overview_json, "\"average_original_data_rate_text\""));
    PFL_EXPECT(contains_text(overview_json, "\"truncated_packets_text\""));
    PFL_EXPECT(contains_text(overview_json, "\"not_captured_bytes_text\""));
    PFL_EXPECT(contains_text(overview_json, "\"capture_completeness_text\""));
    PFL_EXPECT(contains_text(overview_json, "\"flow_characteristics\""));
    PFL_EXPECT(contains_text(overview_json, "\"only_a_to_b_flows_text\""));
    PFL_EXPECT(contains_text(overview_json, "\"service_recognized_flows_text\""));
    PFL_EXPECT(contains_text(overview_json, "\"packet_direction_distribution\""));
    PFL_EXPECT(contains_text(overview_json, "\"original_byte_direction_distribution\""));
    PFL_EXPECT(contains_text(overview_json, "\"stable_id\":\"mostly_a_to_b\""));
    PFL_EXPECT(contains_text(overview_json, "\"percent_text\""));
    PFL_EXPECT(contains_text(overview_json, "\"statistics_partial_open_warning_text\""));
    PFL_EXPECT(contains_text(overview_json, "\"packet_count\""));
    PFL_EXPECT(contains_text(overview_json, "\"unrecognized_packets\""));
    PFL_EXPECT(contains_text(overview_json, "\"captured_bytes_text\""));
    PFL_EXPECT(contains_text(overview_json, "\"original_bytes_text\""));
    PFL_EXPECT(contains_text(overview_json, "\"input_metadata\""));
    PFL_EXPECT(contains_text(overview_json, "\"input_kind\":\"pcap\""));
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
    PFL_EXPECT(contains_text(hints_json, "\"flow_count_text\""));
    PFL_EXPECT(contains_text(hints_json, "\"packet_count_text\""));
    PFL_EXPECT(contains_text(hints_json, "\"captured_bytes_text\""));
    PFL_EXPECT(contains_text(hints_json, "\"original_bytes_text\""));

    const auto quic_tls_json = take_bridge_string(pfl_frontend_session_adapter_get_quic_tls_statistics_json(handle));
    PFL_EXPECT(contains_text(quic_tls_json, "\"quic_recognition\""));
    PFL_EXPECT(contains_text(quic_tls_json, "\"tls_recognition\""));

    const auto top_json = take_bridge_string(pfl_frontend_session_adapter_get_top_endpoint_port_statistics_json(handle, 5U));
    PFL_EXPECT(contains_text(top_json, "\"top_endpoints\""));
    PFL_EXPECT(contains_text(top_json, "\"top_ports\""));
    PFL_EXPECT(contains_text(top_json, "\"limit\":5"));

    pfl_frontend_session_adapter_free(handle);
}

void expect_protocol_path_tree_bridge_export_contract() {
    auto* handle = pfl_frontend_session_adapter_new();
    PFL_REQUIRE(handle != nullptr);

    const auto capture_path = fixture_path("parsing/vxlan/10_vxlan_same_inner_tuple_different_vni.pcap");
    const auto open_json = take_bridge_string(
        pfl_frontend_session_adapter_open_capture_json(handle, capture_path.string().c_str())
    );
    PFL_EXPECT(contains_text(open_json, "\"opened\":true"));

    const auto output_path = std::filesystem::temp_directory_path()
        / path_from_explicit_utf8("pfl_protocol_path_tree_bridge_тест.txt");
    std::filesystem::remove(output_path);
    const auto output_path_utf8 = utf8_path_string(output_path);
    const auto export_json = take_bridge_string(
        pfl_frontend_session_adapter_export_protocol_path_tree_json(handle, 2U, output_path_utf8.c_str())
    );
    PFL_EXPECT(contains_text(export_json, "\"exported\":true"));
    PFL_EXPECT(contains_text(export_json, "\"error_text\":\"\""));
    PFL_EXPECT(std::filesystem::exists(output_path));

    const auto text = read_text_file(output_path);
    PFL_EXPECT(contains_text(text, "Protocol Path Tree\n"));
    PFL_EXPECT(contains_text(text, "Mode: Terminal paths\n"));
    PFL_EXPECT(contains_text(text, "Layer"));
    PFL_EXPECT(contains_text(
        text,
        "EthernetII -> IPv4 -> UDP -> VXLAN(vni=100) -> EthernetII -> IPv4 -> TCP"));
    PFL_EXPECT(text.find('\t') == std::string::npos);

    pfl_frontend_session_adapter_free(handle);
}

void expect_advanced_flow_filter_text_query_bridge_contract() {
    auto* handle = pfl_frontend_session_adapter_new();
    PFL_REQUIRE(handle != nullptr);

    const auto capture_path = write_temp_capture_file(
        "pfl_bridge_advanced_flow_filter_query.pcap",
        make_classic_pcap({
            {100U, make_ethernet_ipv4_tcp_packet(ipv4(10, 95, 0, 1), ipv4(10, 95, 0, 2), 51001, 80)},
            {200U, make_ethernet_ipv4_udp_packet(ipv4(10, 95, 0, 3), ipv4(10, 95, 0, 4), 53000, 53)},
            {300U, make_ethernet_ipv6_udp_with_hop_by_hop_packet(
                ipv6({0x20, 0x01, 0x0d, 0xb8, 0x00, 0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}),
                ipv6({0x20, 0x01, 0x0d, 0xb8, 0x00, 0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02}),
                54000,
                443
            )},
        })
    );
    const auto open_json = take_bridge_string(
        pfl_frontend_session_adapter_open_capture_json(handle, capture_path.string().c_str())
    );
    PFL_EXPECT(contains_text(open_json, "\"opened\":true"));

    const auto ok_json = take_bridge_string(
        pfl_frontend_session_adapter_query_advanced_flows_text_json(
            handle,
            "format_version = 3\nflow_protocol.include = udp\n",
            nullptr,
            0U
        )
    );
    PFL_EXPECT(contains_text(ok_json, "\"status\":\"ok\""));
    PFL_EXPECT(contains_text(ok_json, "\"configured_rule_count\":1"));
    PFL_EXPECT(contains_text(ok_json, "\"active_rule_count\":1"));
    PFL_EXPECT(contains_text(ok_json, "\"matching_flow_indices\":[1,2]"));
    PFL_EXPECT(contains_text(ok_json, "\"error_text\":\"\""));

    const std::size_t scoped_candidates[] {2U};
    const auto scoped_json = take_bridge_string(
        pfl_frontend_session_adapter_query_advanced_flows_text_json(
            handle,
            "format_version = 3\nflow_protocol.include = udp\n",
            scoped_candidates,
            1U
        )
    );
    PFL_EXPECT(contains_text(scoped_json, "\"status\":\"ok\""));
    PFL_EXPECT(contains_text(scoped_json, "\"matching_flow_indices\":[2]"));
    PFL_EXPECT(contains_text(scoped_json, "\"result_count_before_limit\":1"));

    const std::size_t empty_scope_sentinel = 999U;
    const auto explicit_empty_scope_json = take_bridge_string(
        pfl_frontend_session_adapter_query_advanced_flows_text_json(
            handle,
            "format_version = 3\nflow_protocol.include = udp\n",
            &empty_scope_sentinel,
            0U
        )
    );
    PFL_EXPECT(contains_text(explicit_empty_scope_json, "\"status\":\"ok\""));
    PFL_EXPECT(contains_text(explicit_empty_scope_json, "\"matching_flow_indices\":[]"));
    PFL_EXPECT(contains_text(explicit_empty_scope_json, "\"result_count_before_limit\":0"));
    PFL_EXPECT(contains_text(explicit_empty_scope_json, "\"error_text\":\"\""));

    const auto disabled_json = take_bridge_string(
        pfl_frontend_session_adapter_query_advanced_flows_text_json(
            handle,
            "format_version = 3\nsection.flow_protocol.enabled = false\nflow_protocol.include = udp\n",
            nullptr,
            0U
        )
    );
    PFL_EXPECT(contains_text(disabled_json, "\"status\":\"ok\""));
    PFL_EXPECT(contains_text(disabled_json, "\"configured_rule_count\":1"));
    PFL_EXPECT(contains_text(disabled_json, "\"active_rule_count\":0"));
    PFL_EXPECT(contains_text(disabled_json, "\"matching_flow_indices\":[0,1,2]"));

    const auto invalid_json = take_bridge_string(
        pfl_frontend_session_adapter_query_advanced_flows_text_json(
            handle,
            "format_version = 3\nflow_protocol.include = tcpish\n",
            nullptr,
            0U
        )
    );
    PFL_EXPECT(contains_text(invalid_json, "\"status\":\"invalid_filter_text\""));
    PFL_EXPECT(contains_text(invalid_json, "\"parse_status\":\"invalid_enum_token\""));
    PFL_EXPECT(contains_text(invalid_json, "\"line\":2"));
    PFL_EXPECT(contains_text(invalid_json, "\"key\":\"flow_protocol.include\""));
    PFL_EXPECT(contains_text(invalid_json, "\"token\":\"tcpish\""));

    pfl_frontend_session_adapter_free(handle);
}

}  // namespace

void run_statistics_section_tests() {
    expect_shared_statistics_formatting_helpers();
    expect_protocol_hint_statistics_rows_handle_zero_denominators();
    expect_flow_packet_count_histogram_boundaries();
    expect_flow_packet_count_histogram_zero_packet_behavior();
    expect_flow_packet_count_histogram_supports_empty_inputs();
    expect_flow_packet_count_histogram_handles_large_original_byte_totals();
    expect_flow_packet_count_histogram_survives_index_roundtrip();
    expect_flow_packet_count_histogram_is_cached_per_capture();
    expect_capture_general_statistics_support_empty_inputs();
    expect_capture_general_statistics_track_flow_characteristics_distributions_and_captured_bytes();
    expect_general_statistics_cache_survives_possible_tls_projection_changes();
    expect_capture_packet_size_statistics_boundaries();
    expect_capture_packet_size_statistics_supports_empty_state();
    expect_capture_packet_statistics_supports_empty_state();
    expect_capture_packet_statistics_track_single_recognized_packet();
    expect_capture_packet_statistics_track_single_truncated_packet();
    expect_capture_packet_size_statistics_counts_recognized_and_unrecognized_packets();
    expect_capture_packet_statistics_tracks_total_original_timestamp_truncation_and_unrecognized_fields();
    expect_capture_packet_statistics_use_temporal_min_max_for_out_of_order_pcapng_packets();
    expect_capture_packet_size_statistics_counts_decode_malformed_packets();
    expect_capture_packet_size_statistics_excludes_unreadable_truncated_tail();
    expect_capture_packet_size_statistics_counts_supported_pcapng_packets();
    expect_capture_packet_size_statistics_survives_index_roundtrip();
    expect_capture_packet_statistics_survive_index_roundtrip();
    expect_capture_packet_size_statistics_ignores_unsurfaced_classic_packet_failures();
    expect_capture_packet_size_statistics_count_surfaced_packet_before_trailing_reader_error();
    expect_overview_excludes_optional_statistics_sections();
    expect_frontend_statistics_overview_helpers_cover_availability_and_direction_distributions();
    expect_overview_whole_capture_totals_and_input_metadata_cover_unrecognized_and_index_inputs();
    expect_statistics_overview_marks_partial_open_runtime_state();
    expect_statistics_adapter_exposes_total_based_percentage_fields();
    expect_quic_tls_section_keeps_one_empty_side();
    expect_statistics_section_requests_handle_missing_capture();
    expect_statistics_section_bridge_json_shapes();
    expect_advanced_flow_filter_text_query_bridge_contract();
    expect_protocol_path_tree_bridge_export_contract();
}

}  // namespace pfl::tests
