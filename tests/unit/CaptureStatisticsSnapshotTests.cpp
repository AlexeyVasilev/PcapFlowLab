#include <algorithm>
#include <array>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>
#include <sstream>
#include <string>
#include <vector>

#include "TestSupport.h"
#include "PcapTestUtils.h"
#include "app/session/SessionFlowHelpers.h"
#include "core/domain/CaptureStatisticsSnapshot.h"
#include "core/domain/Connection.h"
#include "core/index/Serialization.h"

namespace pfl::tests {

namespace {

std::vector<std::uint8_t> stream_bytes(const std::ostringstream& stream) {
    const auto serialized = stream.str();
    return std::vector<std::uint8_t>(serialized.begin(), serialized.end());
}

std::vector<std::uint8_t> serialize_snapshot(const CaptureStatisticsSnapshot& snapshot) {
    std::ostringstream stream(std::ios::binary | std::ios::out);
    PFL_REQUIRE(detail::write_capture_statistics_snapshot(stream, snapshot));
    return stream_bytes(stream);
}

bool deserialize_snapshot(const std::vector<std::uint8_t>& bytes, CaptureStatisticsSnapshot& snapshot) {
    std::istringstream stream(
        std::string(reinterpret_cast<const char*>(bytes.data()), bytes.size()),
        std::ios::binary | std::ios::in
    );
    return detail::read_capture_statistics_snapshot(stream, snapshot);
}

std::uint32_t read_le32_at(const std::vector<std::uint8_t>& bytes, const std::size_t offset) {
    return static_cast<std::uint32_t>(bytes[offset]) |
           (static_cast<std::uint32_t>(bytes[offset + 1U]) << 8U) |
           (static_cast<std::uint32_t>(bytes[offset + 2U]) << 16U) |
           (static_cast<std::uint32_t>(bytes[offset + 3U]) << 24U);
}

std::uint64_t read_le64_at(const std::vector<std::uint8_t>& bytes, const std::size_t offset) {
    return static_cast<std::uint64_t>(bytes[offset]) |
           (static_cast<std::uint64_t>(bytes[offset + 1U]) << 8U) |
           (static_cast<std::uint64_t>(bytes[offset + 2U]) << 16U) |
           (static_cast<std::uint64_t>(bytes[offset + 3U]) << 24U) |
           (static_cast<std::uint64_t>(bytes[offset + 4U]) << 32U) |
           (static_cast<std::uint64_t>(bytes[offset + 5U]) << 40U) |
           (static_cast<std::uint64_t>(bytes[offset + 6U]) << 48U) |
           (static_cast<std::uint64_t>(bytes[offset + 7U]) << 56U);
}

void write_le32_at(std::vector<std::uint8_t>& bytes, const std::size_t offset, const std::uint32_t value) {
    bytes[offset + 0U] = static_cast<std::uint8_t>(value & 0xFFU);
    bytes[offset + 1U] = static_cast<std::uint8_t>((value >> 8U) & 0xFFU);
    bytes[offset + 2U] = static_cast<std::uint8_t>((value >> 16U) & 0xFFU);
    bytes[offset + 3U] = static_cast<std::uint8_t>((value >> 24U) & 0xFFU);
}

void fill_distribution_counts(
    CapturePacketSizeDistribution& distribution,
    const std::vector<std::uint64_t>& counts
) {
    PFL_REQUIRE(counts.size() == distribution.buckets.size());
    distribution.maximum_bucket_packet_count = 0U;
    for (std::size_t index = 0U; index < counts.size(); ++index) {
        distribution.buckets[index].packet_count = counts[index];
        distribution.maximum_bucket_packet_count = std::max(
            distribution.maximum_bucket_packet_count,
            counts[index]
        );
    }
}

CaptureStatisticsProtocolCounters counters(
    const std::uint64_t flow_count,
    const std::uint64_t packet_count,
    const std::uint64_t captured_bytes,
    const std::uint64_t original_bytes
) {
    return CaptureStatisticsProtocolCounters {
        .flow_count = flow_count,
        .packet_count = packet_count,
        .captured_bytes = captured_bytes,
        .original_bytes = original_bytes,
    };
}

CaptureStatisticsFlowPacketCountHistogram make_flow_histogram() {
    auto histogram = make_default_capture_statistics_flow_packet_count_histogram();
    histogram.buckets[0].flow_count = 1U;
    histogram.buckets[0].captured_byte_count = 100U;
    histogram.buckets[0].original_byte_count = 120U;
    histogram.buckets[1].flow_count = 1U;
    histogram.buckets[1].captured_byte_count = 200U;
    histogram.buckets[1].original_byte_count = 240U;
    histogram.buckets[2].flow_count = 1U;
    histogram.buckets[2].captured_byte_count = 300U;
    histogram.buckets[2].original_byte_count = 340U;
    histogram.total_flow_count = 3U;
    histogram.total_captured_byte_count = 600U;
    histogram.total_original_byte_count = 700U;
    histogram.maximum_bucket_flow_count = 1U;
    histogram.maximum_bucket_captured_byte_count = 300U;
    histogram.maximum_bucket_original_byte_count = 340U;
    histogram.excluded_zero_packet_flow_count = 1U;
    histogram.excluded_zero_packet_captured_byte_count = 10U;
    histogram.excluded_zero_packet_original_byte_count = 20U;
    return histogram;
}

CaptureStatisticsSnapshot make_valid_snapshot() {
    CaptureStatisticsSnapshot snapshot {};
    snapshot.scope = CaptureStatisticsScope::complete;
    snapshot.total_packet_count = 3U;
    snapshot.total_flow_count = 4U;
    snapshot.total_captured_bytes = 2'500U;
    snapshot.total_original_bytes = 3'000U;
    snapshot.timestamp_range = CapturePacketTimestampRange {
        .available = true,
        .earliest_timestamp_us = 100U,
        .latest_timestamp_us = 300U,
    };
    snapshot.truncated_packet_count = 1U;
    snapshot.maximum_captured_packet_length = 1'500U;
    snapshot.maximum_original_packet_length = 2'000U;
    fill_distribution_counts(snapshot.captured_packet_size_distribution, {1U, 2U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U});
    fill_distribution_counts(snapshot.original_packet_size_distribution, {1U, 1U, 1U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U});
    snapshot.unrecognized_packet_count = 1U;
    snapshot.unrecognized_captured_bytes = 100U;
    snapshot.unrecognized_original_bytes = 120U;
    snapshot.only_a_to_b_flow_count = 1U;
    snapshot.service_recognized_flow_count = 2U;
    snapshot.packet_direction_distribution = CaptureStatisticsDirectionDistribution {
        .mostly_a_to_b_flow_count = 1U,
        .balanced_flow_count = 2U,
        .mostly_b_to_a_flow_count = 1U,
    };
    snapshot.original_byte_direction_distribution = CaptureStatisticsDirectionDistribution {
        .mostly_a_to_b_flow_count = 2U,
        .balanced_flow_count = 1U,
        .mostly_b_to_a_flow_count = 1U,
    };
    snapshot.tcp_flags = CaptureStatisticsTcpFlags {
        .syn_packet_count = 5U,
        .fin_packet_count = 2U,
        .rst_packet_count = 1U,
    };
    snapshot.flow_packet_count_histogram = make_flow_histogram();
    snapshot.transport_protocols = make_default_capture_statistics_transport_protocol_rows();
    snapshot.transport_protocols[0].counters = counters(2U, 6U, 900U, 1'100U);
    snapshot.transport_protocols[1].counters = counters(1U, 3U, 250U, 300U);
    snapshot.transport_protocols[2].counters = counters(0U, 0U, 0U, 0U);
    snapshot.transport_protocols[3].counters = counters(1U, 1U, 40U, 50U);
    snapshot.ip_families = make_default_capture_statistics_ip_family_rows();
    snapshot.ip_families[0].counters = counters(2U, 7U, 940U, 1'150U);
    snapshot.ip_families[1].counters = counters(2U, 3U, 250U, 300U);
    snapshot.detected_protocols = make_default_capture_statistics_detected_protocol_rows();
    snapshot.detected_protocols[0].counters = counters(1U, 2U, 200U, 250U);
    snapshot.detected_protocols[1].counters = counters(1U, 3U, 300U, 360U);
    snapshot.detected_protocols[2].counters = counters(1U, 1U, 80U, 90U);
    snapshot.detected_protocols[3].counters = counters(1U, 2U, 250U, 300U);
    snapshot.detected_protocols[12].counters = counters(1U, 3U, 300U, 360U);
    snapshot.detected_protocols[13].counters = counters(1U, 1U, 40U, 50U);
    snapshot.detected_protocols[14].counters = counters(0U, 0U, 0U, 0U);
    snapshot.detected_protocols[15].counters = counters(1U, 2U, 120U, 150U);
    snapshot.quic_recognition = CaptureStatisticsQuicRecognition {
        .flow_count = 1U,
        .with_sni_count = 1U,
        .without_sni_count = 0U,
        .v1_count = 1U,
        .draft29_count = 0U,
        .v2_count = 0U,
        .version_unavailable_count = 0U,
    };
    snapshot.tls_recognition = CaptureStatisticsTlsRecognition {
        .flow_count = 2U,
        .with_sni_count = 1U,
        .without_sni_count = 1U,
        .tls12_count = 1U,
        .tls13_count = 0U,
        .version_unavailable_count = 1U,
    };
    snapshot.top_endpoints = {
        CaptureStatisticsTopEndpointRow {
            .endpoint = EndpointKeyV4 {.addr = ipv4(10, 0, 0, 1), .port = 443U},
            .flow_count = 2U,
            .packet_count = 4U,
            .captured_bytes = 500U,
            .original_bytes = 600U,
        },
        CaptureStatisticsTopEndpointRow {
            .endpoint = EndpointKeyV6 {
                .addr = ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10}),
                .port = 53U,
            },
            .flow_count = 1U,
            .packet_count = 2U,
            .captured_bytes = 250U,
            .original_bytes = 300U,
        },
    };
    snapshot.top_ports = {
        CaptureStatisticsTopPortRow {.port = 443U, .flow_count = 2U, .packet_count = 4U, .captured_bytes = 500U, .original_bytes = 600U},
        CaptureStatisticsTopPortRow {.port = 53U, .flow_count = 1U, .packet_count = 2U, .captured_bytes = 250U, .original_bytes = 300U},
    };
    snapshot.top_flows = {
        CaptureStatisticsTopFlowRow {
            .canonical_flow_ordinal = 3U,
            .family = CaptureStatisticsAddressFamily::ipv4,
            .connection_key = ConnectionKeyV4 {
                .first = EndpointKeyV4 {.addr = ipv4(10, 0, 0, 1), .port = 40'001U},
                .second = EndpointKeyV4 {.addr = ipv4(10, 0, 0, 2), .port = 443U},
                .protocol = ProtocolId::tcp,
                .protocol_path_id = 11U,
            },
            .endpoint_a = EndpointKeyV4 {.addr = ipv4(10, 0, 0, 1), .port = 40'001U},
            .endpoint_b = EndpointKeyV4 {.addr = ipv4(10, 0, 0, 2), .port = 443U},
            .flow_protocol = ProtocolId::tcp,
            .protocol_hint = FlowProtocolHint::tls,
            .service_hint = "alpha.example",
            .protocol_path_id = 11U,
            .packet_count = 4U,
            .captured_bytes = 500U,
            .original_bytes = 600U,
        },
        CaptureStatisticsTopFlowRow {
            .canonical_flow_ordinal = 7U,
            .family = CaptureStatisticsAddressFamily::ipv6,
            .connection_key = ConnectionKeyV6 {
                .first = EndpointKeyV6 {
                    .addr = ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x21}),
                    .port = 53U,
                },
                .second = EndpointKeyV6 {
                    .addr = ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x22}),
                    .port = 53'000U,
                },
                .protocol = ProtocolId::udp,
                .protocol_path_id = 17U,
            },
            .endpoint_a = EndpointKeyV6 {
                .addr = ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x21}),
                .port = 53U,
            },
            .endpoint_b = EndpointKeyV6 {
                .addr = ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x22}),
                .port = 53'000U,
            },
            .flow_protocol = ProtocolId::udp,
            .protocol_hint = FlowProtocolHint::dns,
            .service_hint = "",
            .protocol_path_id = 17U,
            .packet_count = 2U,
            .captured_bytes = 250U,
            .original_bytes = 300U,
        },
    };
    return snapshot;
}

CaptureStatisticsSnapshot make_rich_snapshot_with_maximum_top_capacities() {
    auto snapshot = make_valid_snapshot();
    snapshot.top_endpoints.clear();
    snapshot.top_ports.clear();
    snapshot.top_flows.clear();

    for (std::uint16_t index = 0U; index < kCaptureStatisticsSnapshotTopEndpointCapacity; ++index) {
        if (index < 10U) {
            snapshot.top_endpoints.push_back(CaptureStatisticsTopEndpointRow {
                .endpoint = EndpointKeyV4 {
                    .addr = ipv4(10, 1, 0, static_cast<std::uint8_t>(index + 1U)),
                    .port = static_cast<std::uint16_t>(1'000U + index),
                },
                .flow_count = static_cast<std::uint64_t>(index + 1U),
                .packet_count = static_cast<std::uint64_t>(index + 2U),
                .captured_bytes = static_cast<std::uint64_t>(500U + index),
                .original_bytes = static_cast<std::uint64_t>(600U + index),
            });
        } else {
            snapshot.top_endpoints.push_back(CaptureStatisticsTopEndpointRow {
                .endpoint = EndpointKeyV6 {
                    .addr = ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, static_cast<std::uint8_t>(index + 1U)}),
                    .port = static_cast<std::uint16_t>(2'000U + index),
                },
                .flow_count = static_cast<std::uint64_t>(index + 1U),
                .packet_count = static_cast<std::uint64_t>(index + 3U),
                .captured_bytes = static_cast<std::uint64_t>(700U + index),
                .original_bytes = static_cast<std::uint64_t>(900U + index),
            });
        }
    }

    for (std::uint16_t index = 0U; index < kCaptureStatisticsSnapshotTopPortCapacity; ++index) {
        snapshot.top_ports.push_back(CaptureStatisticsTopPortRow {
            .port = static_cast<std::uint16_t>(3'000U + index),
            .flow_count = static_cast<std::uint64_t>(index + 1U),
            .packet_count = static_cast<std::uint64_t>(index + 4U),
            .captured_bytes = static_cast<std::uint64_t>(400U + index),
            .original_bytes = static_cast<std::uint64_t>(500U + index),
        });
    }

    for (std::uint32_t index = 0U; index < kCaptureStatisticsSnapshotTopFlowCapacity; ++index) {
        if ((index % 2U) == 0U) {
            snapshot.top_flows.push_back(CaptureStatisticsTopFlowRow {
                .canonical_flow_ordinal = index,
                .family = CaptureStatisticsAddressFamily::ipv4,
                .connection_key = ConnectionKeyV4 {
                    .first = EndpointKeyV4 {.addr = ipv4(10, 2, 0, static_cast<std::uint8_t>(index + 1U)), .port = static_cast<std::uint16_t>(40'000U + index)},
                    .second = EndpointKeyV4 {.addr = ipv4(10, 2, 1, static_cast<std::uint8_t>(index + 1U)), .port = 443U},
                    .protocol = ProtocolId::tcp,
                    .protocol_path_id = static_cast<ProtocolPathId>(100U + index),
                },
                .endpoint_a = EndpointKeyV4 {.addr = ipv4(10, 2, 0, static_cast<std::uint8_t>(index + 1U)), .port = static_cast<std::uint16_t>(40'000U + index)},
                .endpoint_b = EndpointKeyV4 {.addr = ipv4(10, 2, 1, static_cast<std::uint8_t>(index + 1U)), .port = 443U},
                .flow_protocol = ProtocolId::tcp,
                .protocol_hint = FlowProtocolHint::tls,
                .service_hint = "bulk-download.example.test",
                .protocol_path_id = static_cast<ProtocolPathId>(100U + index),
                .packet_count = static_cast<std::uint64_t>(index + 5U),
                .captured_bytes = static_cast<std::uint64_t>(1'000U + index),
                .original_bytes = static_cast<std::uint64_t>(1'100U + index),
            });
        } else {
            snapshot.top_flows.push_back(CaptureStatisticsTopFlowRow {
                .canonical_flow_ordinal = index,
                .family = CaptureStatisticsAddressFamily::ipv6,
                .connection_key = ConnectionKeyV6 {
                    .first = EndpointKeyV6 {
                        .addr = ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, static_cast<std::uint8_t>(index + 1U)}),
                        .port = static_cast<std::uint16_t>(5'000U + index),
                    },
                    .second = EndpointKeyV6 {
                        .addr = ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, static_cast<std::uint8_t>(index + 1U)}),
                        .port = static_cast<std::uint16_t>(6'000U + index),
                    },
                    .protocol = ProtocolId::udp,
                    .protocol_path_id = static_cast<ProtocolPathId>(200U + index),
                },
                .endpoint_a = EndpointKeyV6 {
                    .addr = ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, static_cast<std::uint8_t>(index + 1U)}),
                    .port = static_cast<std::uint16_t>(5'000U + index),
                },
                .endpoint_b = EndpointKeyV6 {
                    .addr = ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, static_cast<std::uint8_t>(index + 1U)}),
                    .port = static_cast<std::uint16_t>(6'000U + index),
                },
                .flow_protocol = ProtocolId::udp,
                .protocol_hint = FlowProtocolHint::dns,
                .service_hint = "",
                .protocol_path_id = static_cast<ProtocolPathId>(200U + index),
                .packet_count = static_cast<std::uint64_t>(index + 7U),
                .captured_bytes = static_cast<std::uint64_t>(1'200U + index),
                .original_bytes = static_cast<std::uint64_t>(1'300U + index),
            });
        }
    }

    return snapshot;
}

const CaptureStatisticsDetectedProtocolRow* find_detected_protocol_row(
    const CaptureStatisticsSnapshot& snapshot,
    const CaptureStatisticsDetectedProtocolCategory category
) {
    for (const auto& row : snapshot.detected_protocols) {
        if (row.category == category) {
            return &row;
        }
    }
    return nullptr;
}

const CaptureStatisticsTransportProtocolRow* find_transport_protocol_row(
    const CaptureStatisticsSnapshot& snapshot,
    const CaptureStatisticsTransportProtocolCategory category
) {
    for (const auto& row : snapshot.transport_protocols) {
        if (row.category == category) {
            return &row;
        }
    }
    return nullptr;
}

std::size_t encoded_endpoint_key_size(const CaptureStatisticsAddressFamily family) {
    return family == CaptureStatisticsAddressFamily::ipv4 ? 6U : 18U;
}

std::size_t service_length_offset_for_first_top_flow(const std::vector<std::uint8_t>& bytes) {
    std::size_t offset = 0U;
    offset += 1U + 8U + 8U + 8U + 8U;
    offset += 1U + 8U + 8U + 8U + 4U + 4U;

    const auto captured_bucket_count = read_le32_at(bytes, offset + 8U);
    offset += 8U + 4U + static_cast<std::size_t>(captured_bucket_count) * 8U;
    const auto original_bucket_count = read_le32_at(bytes, offset + 8U);
    offset += 8U + 4U + static_cast<std::size_t>(original_bucket_count) * 8U;

    offset += 8U * 3U;
    offset += 8U * 2U;
    offset += 8U * 3U;
    offset += 8U * 3U;
    offset += 8U * 3U;
    offset += 8U * 9U;

    const auto flow_bucket_count = read_le32_at(bytes, offset);
    offset += 4U + static_cast<std::size_t>(flow_bucket_count) * (8U * 3U);

    const auto transport_count = read_le32_at(bytes, offset);
    offset += 4U + static_cast<std::size_t>(transport_count) * (1U + 8U * 4U);
    const auto family_count = read_le32_at(bytes, offset);
    offset += 4U + static_cast<std::size_t>(family_count) * (1U + 8U * 4U);
    const auto detected_count = read_le32_at(bytes, offset);
    offset += 4U + static_cast<std::size_t>(detected_count) * (1U + 8U * 4U);

    offset += 8U * 7U;
    offset += 8U * 6U;

    const auto endpoint_count = read_le32_at(bytes, offset);
    offset += 4U;
    for (std::uint32_t index = 0U; index < endpoint_count; ++index) {
        const auto family = static_cast<CaptureStatisticsAddressFamily>(bytes[offset]);
        offset += 1U + encoded_endpoint_key_size(family) + 8U * 4U;
    }

    const auto port_count = read_le32_at(bytes, offset);
    offset += 4U + static_cast<std::size_t>(port_count) * (2U + 8U * 4U);

    const auto flow_count = read_le32_at(bytes, offset);
    PFL_REQUIRE(flow_count > 0U);
    offset += 4U;

    const auto family = static_cast<CaptureStatisticsAddressFamily>(bytes[offset + 4U]);
    offset += 4U + 1U;
    offset += family == CaptureStatisticsAddressFamily::ipv4 ? 17U : 41U;
    offset += encoded_endpoint_key_size(family);
    offset += encoded_endpoint_key_size(family);
    offset += 1U + 1U;
    return offset;
}

void expect_decode_fails(const CaptureStatisticsSnapshot& snapshot) {
    CaptureStatisticsSnapshot decoded {};
    PFL_EXPECT(!deserialize_snapshot(serialize_snapshot(snapshot), decoded));
}

void expect_default_and_scope_variants_are_valid() {
    CaptureStatisticsSnapshot snapshot {};
    PFL_EXPECT(validate_capture_statistics_snapshot(snapshot).ok);

    snapshot.scope = CaptureStatisticsScope::partial;
    PFL_EXPECT(validate_capture_statistics_snapshot(snapshot).ok);

    snapshot.scope = CaptureStatisticsScope::reserved_unknown;
    PFL_EXPECT(validate_capture_statistics_snapshot(snapshot).ok);

    snapshot.total_packet_count = 1U;
    snapshot.total_captured_bytes = 64U;
    snapshot.total_original_bytes = 80U;
    snapshot.timestamp_range = CapturePacketTimestampRange {
        .available = true,
        .earliest_timestamp_us = 123U,
        .latest_timestamp_us = 123U,
    };
    fill_distribution_counts(snapshot.captured_packet_size_distribution, {0U, 1U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U});
    fill_distribution_counts(snapshot.original_packet_size_distribution, {0U, 1U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U});
    PFL_EXPECT(validate_capture_statistics_snapshot(snapshot).ok);
}

void expect_runtime_builder_projects_current_statistics() {
    CapturePacketStatistics packet_statistics {};
    packet_statistics.total_packet_count = 6U;
    packet_statistics.total_captured_bytes = 1'480U;
    packet_statistics.total_original_bytes = 1'700U;
    packet_statistics.timestamp_range = CapturePacketTimestampRange {
        .available = true,
        .earliest_timestamp_us = 10U,
        .latest_timestamp_us = 60U,
    };
    packet_statistics.truncated_packet_count = 1U;
    packet_statistics.maximum_captured_packet_length = 512U;
    packet_statistics.maximum_original_packet_length = 768U;
    fill_distribution_counts(packet_statistics.captured_size_distribution, {1U, 1U, 2U, 2U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U});
    fill_distribution_counts(packet_statistics.original_size_distribution, {0U, 1U, 1U, 3U, 1U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U});
    packet_statistics.unrecognized_packet_count = 1U;
    packet_statistics.unrecognized_captured_bytes = 40U;
    packet_statistics.unrecognized_original_bytes = 50U;

    ConnectionV4 unknown_tcp {};
    unknown_tcp.has_flow_a = true;
    unknown_tcp.packet_count = 1U;
    unknown_tcp.total_bytes = 100U;
    unknown_tcp.flow_a.packet_count = 1U;
    unknown_tcp.flow_a.total_bytes = 100U;
    unknown_tcp.aggregate_stats.captured_bytes = 90U;
    unknown_tcp.aggregate_stats.tcp_syn_count = 1U;
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
    confirmed_tls.aggregate_stats.tcp_fin_count = 1U;
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
    possible_tls.aggregate_stats.tcp_syn_count = 1U;
    possible_tls.aggregate_stats.tcp_rst_count = 2U;
    possible_tls.key.protocol = ProtocolId::tcp;
    possible_tls.key.first.addr = ipv6({0x20, 0x01, 0x0d, 0xb8, 0x00, 0x43, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01});
    possible_tls.key.first.port = 4400U;
    possible_tls.key.second.addr = ipv6({0x20, 0x01, 0x0d, 0xb8, 0x00, 0x43, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02});
    possible_tls.key.second.port = 443U;

    std::vector<session_detail::ListedConnectionRef> refs {
        session_detail::ListedConnectionRef {.family = FlowAddressFamily::ipv4, .ipv4 = &unknown_tcp, .ipv6 = nullptr},
        session_detail::ListedConnectionRef {.family = FlowAddressFamily::ipv6, .ipv4 = nullptr, .ipv6 = &confirmed_quic},
        session_detail::ListedConnectionRef {.family = FlowAddressFamily::ipv4, .ipv4 = &confirmed_tls, .ipv6 = nullptr},
        session_detail::ListedConnectionRef {.family = FlowAddressFamily::ipv6, .ipv4 = nullptr, .ipv6 = &possible_tls},
    };
    const auto general_statistics = session_detail::build_capture_general_statistics(
        std::span<const session_detail::ListedConnectionRef>(refs.data(), refs.size()),
        20U
    );

    const auto snapshot = session_detail::make_capture_statistics_snapshot(
        packet_statistics,
        general_statistics,
        CaptureStatisticsScope::partial
    );

    PFL_EXPECT(snapshot.scope == CaptureStatisticsScope::partial);
    PFL_EXPECT(snapshot.total_packet_count == packet_statistics.total_packet_count);
    PFL_EXPECT(snapshot.total_flow_count == general_statistics.flow_characteristics.total_flow_count);
    PFL_EXPECT(snapshot.total_captured_bytes == packet_statistics.total_captured_bytes);
    PFL_EXPECT(snapshot.unrecognized_packet_count == packet_statistics.unrecognized_packet_count);
    PFL_EXPECT(snapshot.only_a_to_b_flow_count == general_statistics.flow_characteristics.only_a_to_b_flow_count);
    PFL_EXPECT(snapshot.service_recognized_flow_count == general_statistics.flow_characteristics.service_recognized_flow_count);
    PFL_EXPECT(snapshot.packet_direction_distribution.mostly_a_to_b_flow_count == 2U);
    PFL_EXPECT(snapshot.original_byte_direction_distribution.mostly_b_to_a_flow_count == 1U);
    PFL_EXPECT(snapshot.tcp_flags.syn_packet_count == 2U);
    PFL_EXPECT(snapshot.tcp_flags.fin_packet_count == 1U);
    PFL_EXPECT(snapshot.tcp_flags.rst_packet_count == 2U);
    PFL_EXPECT(snapshot.flow_packet_count_histogram.total_flow_count == 4U);
    PFL_EXPECT(snapshot.flow_packet_count_histogram.excluded_zero_packet_flow_count == 0U);
    PFL_REQUIRE(find_transport_protocol_row(snapshot, CaptureStatisticsTransportProtocolCategory::tcp) != nullptr);
    PFL_EXPECT(
        find_transport_protocol_row(snapshot, CaptureStatisticsTransportProtocolCategory::tcp)->counters.captured_bytes
        == 1'040U
    );
    PFL_REQUIRE(find_detected_protocol_row(snapshot, CaptureStatisticsDetectedProtocolCategory::possible_tls_candidate) != nullptr);
    PFL_EXPECT(
        find_detected_protocol_row(snapshot, CaptureStatisticsDetectedProtocolCategory::possible_tls_candidate)
            ->counters.flow_count == 1U
    );
    PFL_REQUIRE(find_detected_protocol_row(snapshot, CaptureStatisticsDetectedProtocolCategory::unknown_without_possible) != nullptr);
    PFL_EXPECT(
        find_detected_protocol_row(snapshot, CaptureStatisticsDetectedProtocolCategory::unknown_without_possible)
            ->counters.captured_bytes == 90U
    );
    PFL_EXPECT(snapshot.quic_recognition.flow_count == 1U);
    PFL_EXPECT(snapshot.quic_recognition.with_sni_count == 1U);
    PFL_EXPECT(snapshot.tls_recognition.flow_count == 1U);
    PFL_EXPECT(snapshot.tls_recognition.without_sni_count == 1U);
    PFL_EXPECT(snapshot.top_endpoints.size() == general_statistics.top_summary.endpoints_by_bytes.size());
    PFL_REQUIRE(!snapshot.top_endpoints.empty());
    PFL_EXPECT(snapshot.top_endpoints.front().endpoint == general_statistics.top_summary.endpoints_by_bytes.front().identity);
    PFL_EXPECT(snapshot.top_endpoints.front().captured_bytes == general_statistics.top_summary.endpoints_by_bytes.front().captured_bytes);
    PFL_REQUIRE(!snapshot.top_flows.empty());
    PFL_EXPECT(snapshot.top_flows.front().connection_key == general_statistics.top_summary.flows_by_original_bytes.front().key);
    PFL_EXPECT(snapshot.top_flows.front().endpoint_a == general_statistics.top_summary.flows_by_original_bytes.front().endpoint_a_key);
    PFL_EXPECT(snapshot.top_flows.front().captured_bytes == general_statistics.top_summary.flows_by_original_bytes.front().captured_bytes);
    PFL_EXPECT(validate_capture_statistics_snapshot(snapshot).ok);
}

void expect_roundtrip_preserves_rich_snapshot() {
    const auto snapshot = make_rich_snapshot_with_maximum_top_capacities();
    CaptureStatisticsSnapshot decoded {};
    PFL_REQUIRE(deserialize_snapshot(serialize_snapshot(snapshot), decoded));
    PFL_EXPECT(decoded == snapshot);
}

void expect_decoder_rejects_malformed_payloads() {
    {
        const auto bytes = serialize_snapshot(make_valid_snapshot());
        CaptureStatisticsSnapshot decoded {};
        PFL_EXPECT(!deserialize_snapshot(std::vector<std::uint8_t>(bytes.begin(), bytes.end() - 1), decoded));
    }

    {
        auto bytes = serialize_snapshot(make_valid_snapshot());
        bytes.push_back(0xAAU);
        CaptureStatisticsSnapshot decoded {};
        PFL_EXPECT(!deserialize_snapshot(bytes, decoded));
    }

    {
        auto snapshot = make_valid_snapshot();
        snapshot.scope = static_cast<CaptureStatisticsScope>(99U);
        expect_decode_fails(snapshot);
    }

    {
        auto snapshot = make_valid_snapshot();
        snapshot.transport_protocols[0].category = static_cast<CaptureStatisticsTransportProtocolCategory>(99U);
        expect_decode_fails(snapshot);
    }

    {
        auto snapshot = make_valid_snapshot();
        snapshot.detected_protocols[0].category = static_cast<CaptureStatisticsDetectedProtocolCategory>(99U);
        expect_decode_fails(snapshot);
    }

    {
        auto snapshot = make_valid_snapshot();
        snapshot.ip_families[0].category = static_cast<CaptureStatisticsIpFamilyCategory>(99U);
        expect_decode_fails(snapshot);
    }

    {
        auto snapshot = make_valid_snapshot();
        snapshot.flow_packet_count_histogram.buckets.push_back(CaptureStatisticsFlowPacketCountBucket {
            .stable_id = "unexpected",
            .lower_bound_inclusive = 99U,
            .upper_bound_inclusive = std::nullopt,
        });
        expect_decode_fails(snapshot);
    }

    {
        auto snapshot = make_rich_snapshot_with_maximum_top_capacities();
        snapshot.top_endpoints.push_back(CaptureStatisticsTopEndpointRow {
            .endpoint = EndpointKeyV4 {.addr = ipv4(127, 0, 0, 1), .port = 1U},
            .flow_count = 1U,
            .packet_count = 1U,
            .captured_bytes = 1U,
            .original_bytes = 1U,
        });
        expect_decode_fails(snapshot);
    }

    {
        auto snapshot = make_rich_snapshot_with_maximum_top_capacities();
        snapshot.top_ports.push_back(CaptureStatisticsTopPortRow {
            .port = 65'000U,
            .flow_count = 1U,
            .packet_count = 1U,
            .captured_bytes = 1U,
            .original_bytes = 1U,
        });
        expect_decode_fails(snapshot);
    }

    {
        auto snapshot = make_rich_snapshot_with_maximum_top_capacities();
        snapshot.top_flows.push_back(snapshot.top_flows.front());
        expect_decode_fails(snapshot);
    }

    {
        auto bytes = serialize_snapshot(make_valid_snapshot());
        const auto service_length_offset = service_length_offset_for_first_top_flow(bytes);
        write_le32_at(
            bytes,
            service_length_offset,
            detail::kMaxCaptureStatisticsSnapshotServiceHintBytes + 1U
        );
        CaptureStatisticsSnapshot decoded {};
        PFL_EXPECT(!deserialize_snapshot(bytes, decoded));
    }

    {
        auto snapshot = make_valid_snapshot();
        snapshot.captured_packet_size_distribution.buckets[0].packet_count = std::numeric_limits<std::uint64_t>::max();
        snapshot.captured_packet_size_distribution.buckets[1].packet_count = 1U;
        snapshot.captured_packet_size_distribution.maximum_bucket_packet_count =
            std::numeric_limits<std::uint64_t>::max();
        expect_decode_fails(snapshot);
    }

    {
        auto snapshot = make_valid_snapshot();
        snapshot.captured_packet_size_distribution.buckets[0].packet_count = 1U;
        snapshot.captured_packet_size_distribution.buckets[1].packet_count = 1U;
        snapshot.captured_packet_size_distribution.maximum_bucket_packet_count = 1U;
        snapshot.total_packet_count = 3U;
        expect_decode_fails(snapshot);
    }

    {
        auto snapshot = make_valid_snapshot();
        snapshot.packet_direction_distribution.balanced_flow_count = 0U;
        expect_decode_fails(snapshot);
    }

    {
        auto snapshot = make_valid_snapshot();
        snapshot.unrecognized_packet_count = snapshot.total_packet_count + 1U;
        expect_decode_fails(snapshot);
    }

    {
        auto snapshot = make_valid_snapshot();
        snapshot.timestamp_range.available = true;
        snapshot.timestamp_range.earliest_timestamp_us = 400U;
        snapshot.timestamp_range.latest_timestamp_us = 300U;
        expect_decode_fails(snapshot);
    }

    {
        auto snapshot = make_valid_snapshot();
        snapshot.timestamp_range.available = false;
        snapshot.timestamp_range.earliest_timestamp_us = 1U;
        expect_decode_fails(snapshot);
    }

    {
        auto snapshot = make_valid_snapshot();
        snapshot.quic_recognition.without_sni_count = 1U;
        expect_decode_fails(snapshot);
    }

    {
        auto snapshot = make_valid_snapshot();
        snapshot.tls_recognition.version_unavailable_count = 0U;
        expect_decode_fails(snapshot);
    }

    {
        auto snapshot = make_valid_snapshot();
        snapshot.top_flows.front().flow_protocol = ProtocolId::udp;
        expect_decode_fails(snapshot);
    }

    {
        auto snapshot = make_valid_snapshot();
        snapshot.top_flows.front().protocol_path_id = 99U;
        expect_decode_fails(snapshot);
    }
}

void expect_encoding_layout_is_stable() {
    const auto bytes = serialize_snapshot(make_valid_snapshot());
    PFL_EXPECT(bytes[0] == static_cast<std::uint8_t>(CaptureStatisticsScope::complete));
    PFL_EXPECT(read_le64_at(bytes, 1U) == 3U);
    PFL_EXPECT(read_le64_at(bytes, 9U) == 4U);
    PFL_EXPECT(read_le64_at(bytes, 17U) == 2'500U);
    PFL_EXPECT(read_le64_at(bytes, 25U) == 3'000U);
    PFL_EXPECT(bytes[33U] == 1U);
    PFL_EXPECT(read_le64_at(bytes, 34U) == 100U);
    PFL_EXPECT(read_le64_at(bytes, 42U) == 300U);

    std::size_t offset = 66U;
    PFL_EXPECT(read_le64_at(bytes, offset) == 2U);
    offset += 8U;
    PFL_EXPECT(read_le32_at(bytes, offset) == kCapturePacketSizeStatisticsBucketCount);
    offset += 4U + static_cast<std::size_t>(kCapturePacketSizeStatisticsBucketCount) * 8U;
    PFL_EXPECT(read_le64_at(bytes, offset) == 1U);
    offset += 8U;
    PFL_EXPECT(read_le32_at(bytes, offset) == kCapturePacketSizeStatisticsBucketCount);

    const auto first_top_flow_service_offset = service_length_offset_for_first_top_flow(bytes);
    PFL_EXPECT(read_le32_at(bytes, first_top_flow_service_offset) == 13U);
}

}  // namespace

void run_capture_statistics_snapshot_tests() {
    expect_default_and_scope_variants_are_valid();
    expect_runtime_builder_projects_current_statistics();
    expect_roundtrip_preserves_rich_snapshot();
    expect_decoder_rejects_malformed_payloads();
    expect_encoding_layout_is_stable();
}

}  // namespace pfl::tests
