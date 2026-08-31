#include <algorithm>
#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <variant>
#include <vector>

#include "TestSupport.h"
#include "PcapTestUtils.h"
#include "core/domain/ProtocolPath.h"
#include "core/index/CaptureIndex.h"
#include "core/index/CaptureIndexReader.h"
#include "core/index/CaptureIndexWriter.h"
#include "core/index/Serialization.h"
#include "core/services/CaptureImporter.h"

namespace pfl::tests {

namespace {

struct SectionInfo {
    std::uint32_t id {0};
    std::uint16_t schema_version {0};
    std::uint16_t flags {0};
    std::size_t offset {0};
    std::size_t total_size {0};
};

std::uint32_t read_le32_at(const std::vector<std::uint8_t>& bytes, const std::size_t offset) {
    return static_cast<std::uint32_t>(bytes[offset]) |
           (static_cast<std::uint32_t>(bytes[offset + 1]) << 8U) |
           (static_cast<std::uint32_t>(bytes[offset + 2]) << 16U) |
           (static_cast<std::uint32_t>(bytes[offset + 3]) << 24U);
}

std::uint16_t read_le16_at(const std::vector<std::uint8_t>& bytes, const std::size_t offset) {
    return static_cast<std::uint16_t>(bytes[offset]) |
           static_cast<std::uint16_t>(static_cast<std::uint16_t>(bytes[offset + 1]) << 8U);
}

std::uint64_t read_le64_at(const std::vector<std::uint8_t>& bytes, const std::size_t offset) {
    return static_cast<std::uint64_t>(bytes[offset]) |
           (static_cast<std::uint64_t>(bytes[offset + 1]) << 8U) |
           (static_cast<std::uint64_t>(bytes[offset + 2]) << 16U) |
           (static_cast<std::uint64_t>(bytes[offset + 3]) << 24U) |
           (static_cast<std::uint64_t>(bytes[offset + 4]) << 32U) |
           (static_cast<std::uint64_t>(bytes[offset + 5]) << 40U) |
           (static_cast<std::uint64_t>(bytes[offset + 6]) << 48U) |
           (static_cast<std::uint64_t>(bytes[offset + 7]) << 56U);
}

void write_le64_at(std::vector<std::uint8_t>& bytes, const std::size_t offset, const std::uint64_t value) {
    bytes[offset] = static_cast<std::uint8_t>(value & 0xFFU);
    bytes[offset + 1] = static_cast<std::uint8_t>((value >> 8U) & 0xFFU);
    bytes[offset + 2] = static_cast<std::uint8_t>((value >> 16U) & 0xFFU);
    bytes[offset + 3] = static_cast<std::uint8_t>((value >> 24U) & 0xFFU);
    bytes[offset + 4] = static_cast<std::uint8_t>((value >> 32U) & 0xFFU);
    bytes[offset + 5] = static_cast<std::uint8_t>((value >> 40U) & 0xFFU);
    bytes[offset + 6] = static_cast<std::uint8_t>((value >> 48U) & 0xFFU);
    bytes[offset + 7] = static_cast<std::uint8_t>((value >> 56U) & 0xFFU);
}

void write_le32_at(std::vector<std::uint8_t>& bytes, const std::size_t offset, const std::uint32_t value) {
    bytes[offset] = static_cast<std::uint8_t>(value & 0xFFU);
    bytes[offset + 1] = static_cast<std::uint8_t>((value >> 8U) & 0xFFU);
    bytes[offset + 2] = static_cast<std::uint8_t>((value >> 16U) & 0xFFU);
    bytes[offset + 3] = static_cast<std::uint8_t>((value >> 24U) & 0xFFU);
}

void write_le16_at(std::vector<std::uint8_t>& bytes, const std::size_t offset, const std::uint16_t value) {
    bytes[offset] = static_cast<std::uint8_t>(value & 0xFFU);
    bytes[offset + 1] = static_cast<std::uint8_t>((value >> 8U) & 0xFFU);
}

std::vector<std::uint8_t> read_file_bytes(const std::filesystem::path& path) {
    std::ifstream stream(path, std::ios::binary);
    PFL_EXPECT(stream.is_open());
    return std::vector<std::uint8_t>(std::istreambuf_iterator<char>(stream), std::istreambuf_iterator<char>());
}

std::vector<std::uint8_t> stream_bytes(const std::ostringstream& stream) {
    const auto serialized = stream.str();
    return std::vector<std::uint8_t>(serialized.begin(), serialized.end());
}

CaptureSourceInfo stable_header_source_info() {
    return CaptureSourceInfo {
        .capture_path = std::filesystem::path("unused-by-v15-helper"),
        .format = CaptureSourceFormat::pcapng,
        .file_size = 987654321ULL,
        .last_write_time = -1234567890123LL,
        .content_fingerprint = 0x0123456789ABCDEFULL,
    };
}

std::string stable_header_unicode_generic_utf8() {
    return "/tmp/\xD1\x82\xD0\xB5\xD1\x81\xD1\x82/\xE4\xBE\x8B/pcap_flow_lab_showcase.pcap";
}

std::filesystem::path stable_header_unicode_path() {
    return detail::filesystem_path_from_generic_utf8(stable_header_unicode_generic_utf8());
}

detail::CaptureIndexStableHeader make_stable_header() {
    const auto source_info = stable_header_source_info();
    return detail::CaptureIndexStableHeader {
        .magic = kStableCaptureIndexMagic,
        .container_format_version = kCaptureIndexStableContainerFormatVersion,
        .header_flags = 0U,
        .header_size = 0U,
        .index_revision = kCaptureIndexStableIndexRevision,
        .writer_application_version = "0.3.0-test",
        .source_format = source_info.format,
        .source_file_size = source_info.file_size,
        .source_last_write_time = source_info.last_write_time,
        .source_content_fingerprint = source_info.content_fingerprint,
        .source_capture_path_utf8 = detail::filesystem_path_to_generic_utf8(stable_header_unicode_path()),
    };
}

std::vector<std::uint8_t> encode_stable_header(
    const detail::CaptureIndexStableHeader& header,
    const std::vector<std::uint8_t>& extension_bytes = {}
) {
    std::ostringstream stream(std::ios::binary | std::ios::out);
    const auto extension = std::span<const std::uint8_t>(extension_bytes.data(), extension_bytes.size());
    PFL_REQUIRE(detail::write_capture_index_stable_header(stream, header, extension));
    return stream_bytes(stream);
}

std::size_t stable_header_size(const std::vector<std::uint8_t>& bytes) {
    PFL_EXPECT(bytes.size() >= detail::kCaptureIndexStableHeaderKnownPrefixSize);
    return static_cast<std::size_t>(read_le32_at(bytes, 12U));
}

std::vector<SectionInfo> parse_sections(const std::vector<std::uint8_t>& bytes) {
    std::vector<SectionInfo> sections {};
    std::size_t offset = stable_header_size(bytes);

    while (offset < bytes.size()) {
        PFL_EXPECT(offset + detail::kCaptureIndexStableSectionHeaderEncodedSize <= bytes.size());
        const auto id = read_le32_at(bytes, offset);
        const auto schema_version = read_le16_at(bytes, offset + 4U);
        const auto flags = read_le16_at(bytes, offset + 6U);
        const auto payload_size = read_le64_at(bytes, offset + 8U);
        PFL_EXPECT(payload_size <= static_cast<std::uint64_t>(bytes.size() - offset - detail::kCaptureIndexStableSectionHeaderEncodedSize));
        const auto total_size = static_cast<std::size_t>(detail::kCaptureIndexStableSectionHeaderEncodedSize + payload_size);
        sections.push_back(SectionInfo {
            .id = id,
            .schema_version = schema_version,
            .flags = flags,
            .offset = offset,
            .total_size = total_size,
        });
        offset += total_size;
    }

    return sections;
}

std::size_t count_sections(const std::vector<std::uint8_t>& bytes, const std::uint32_t section_id) {
    const auto sections = parse_sections(bytes);
    return static_cast<std::size_t>(std::count_if(sections.begin(), sections.end(), [&](const SectionInfo& section) {
        return section.id == section_id;
    }));
}

std::vector<std::uint8_t> remove_section(const std::vector<std::uint8_t>& bytes, const std::uint32_t section_id) {
    const auto sections = parse_sections(bytes);
    std::vector<std::uint8_t> mutated {};
    mutated.insert(mutated.end(), bytes.begin(), bytes.begin() + static_cast<std::ptrdiff_t>(stable_header_size(bytes)));

    bool removed {false};
    for (const auto& section : sections) {
        if (!removed && section.id == section_id) {
            removed = true;
            continue;
        }

        mutated.insert(
            mutated.end(),
            bytes.begin() + static_cast<std::ptrdiff_t>(section.offset),
            bytes.begin() + static_cast<std::ptrdiff_t>(section.offset + section.total_size)
        );
    }

    PFL_EXPECT(removed);
    return mutated;
}

std::vector<std::uint8_t> duplicate_section(const std::vector<std::uint8_t>& bytes, const std::uint32_t section_id) {
    const auto sections = parse_sections(bytes);
    std::vector<std::uint8_t> mutated = bytes;

    for (const auto& section : sections) {
        if (section.id != section_id) {
            continue;
        }

        mutated.insert(
            mutated.end(),
            bytes.begin() + static_cast<std::ptrdiff_t>(section.offset),
            bytes.begin() + static_cast<std::ptrdiff_t>(section.offset + section.total_size)
        );
        return mutated;
    }

    PFL_EXPECT(false);
    return {};
}

std::vector<std::uint8_t> corrupt_first_section_size(const std::vector<std::uint8_t>& bytes) {
    auto mutated = bytes;
    const auto sections = parse_sections(bytes);
    PFL_EXPECT(!sections.empty());
    const auto size_offset = sections.front().offset + 8U;
    write_le64_at(mutated, size_offset, read_le64_at(mutated, size_offset) + 1U);
    return mutated;
}

std::vector<std::uint8_t> append_trailing_garbage(const std::vector<std::uint8_t>& bytes) {
    auto mutated = bytes;
    mutated.push_back(0xAAU);
    mutated.push_back(0x55U);
    mutated.push_back(0x01U);
    return mutated;
}

std::vector<std::uint8_t> make_ipv6_tcp_segment_for_index_test(
    const std::uint16_t src_port,
    const std::uint16_t dst_port
) {
    std::vector<std::uint8_t> bytes {};
    append_be16(bytes, src_port);
    append_be16(bytes, dst_port);
    append_be32(bytes, 0U);
    append_be32(bytes, 0U);
    bytes.push_back(0x50U);
    bytes.push_back(0x10U);
    append_be16(bytes, 0U);
    append_be16(bytes, 0U);
    append_be16(bytes, 0U);
    return bytes;
}

std::uint16_t expected_section_schema_version(const std::uint32_t section_id) {
    switch (static_cast<detail::CaptureIndexSectionId>(section_id)) {
    case detail::CaptureIndexSectionId::summary:
        return detail::kCaptureIndexStableSummarySectionSchemaVersion;
    case detail::CaptureIndexSectionId::protocol_paths:
        return detail::kCaptureIndexStableProtocolPathsSectionSchemaVersion;
    case detail::CaptureIndexSectionId::ipv4_connections:
        return detail::kCaptureIndexStableIpv4ConnectionsSectionSchemaVersion;
    case detail::CaptureIndexSectionId::ipv6_connections:
        return detail::kCaptureIndexStableIpv6ConnectionsSectionSchemaVersion;
    case detail::CaptureIndexSectionId::unrecognized_packets:
        return detail::kCaptureIndexStableUnrecognizedPacketsSectionSchemaVersion;
    case detail::CaptureIndexSectionId::packet_locator:
        return detail::kCaptureIndexStablePacketLocatorSectionSchemaVersion;
    case detail::CaptureIndexSectionId::capture_statistics_snapshot:
        return detail::kCaptureIndexStableCaptureStatisticsSnapshotSectionSchemaVersion;
    case detail::CaptureIndexSectionId::protocol_path_registry_early:
        return detail::kCaptureIndexStableProtocolPathRegistryEarlySectionSchemaVersion;
    case detail::CaptureIndexSectionId::protocol_path_terminal_aggregates:
        return detail::kCaptureIndexStableProtocolPathTerminalAggregatesSectionSchemaVersion;
    default:
        return 0U;
    }
}

void expect_matching_packets(const std::vector<PacketRef>& left, const std::vector<PacketRef>& right) {
    PFL_EXPECT(left.size() == right.size());
    for (std::size_t index = 0; index < left.size(); ++index) {
        PFL_EXPECT(left[index].packet_index == right[index].packet_index);
        PFL_EXPECT(left[index].byte_offset == right[index].byte_offset);
        PFL_EXPECT(left[index].data_link_type == right[index].data_link_type);
        PFL_EXPECT(left[index].captured_length == right[index].captured_length);
        PFL_EXPECT(left[index].original_length == right[index].original_length);
        PFL_EXPECT(left[index].ts_sec == right[index].ts_sec);
        PFL_EXPECT(left[index].ts_usec == right[index].ts_usec);
    }
}

void expect_matching_protocol_path_registries(const ProtocolPathRegistry& left, const ProtocolPathRegistry& right) {
    PFL_EXPECT(left.size() == right.size());
    for (std::size_t index = 0U; index < left.size(); ++index) {
        const auto id = static_cast<ProtocolPathId>(index + 1U);
        const auto* left_path = left.find(id);
        const auto* right_path = right.find(id);
        PFL_REQUIRE(left_path != nullptr);
        PFL_REQUIRE(right_path != nullptr);
        PFL_EXPECT(*left_path == *right_path);
    }
}

void expect_matching_protocol_path_display_statistics(
    const ProtocolPathDisplayStatistics& left,
    const ProtocolPathDisplayStatistics& right
) {
    PFL_EXPECT(left.terminal_path_aggregates == right.terminal_path_aggregates);
}

void expect_matching_flows(const FlowV4& left, const FlowV4& right) {
    PFL_EXPECT(left.key == right.key);
    PFL_EXPECT(left.packet_count == right.packet_count);
    PFL_EXPECT(left.total_bytes == right.total_bytes);
    expect_matching_packets(left.packets, right.packets);
}

void expect_matching_flows(const FlowV6& left, const FlowV6& right) {
    PFL_EXPECT(left.key == right.key);
    PFL_EXPECT(left.packet_count == right.packet_count);
    PFL_EXPECT(left.total_bytes == right.total_bytes);
    expect_matching_packets(left.packets, right.packets);
}

void expect_matching_connections(const ConnectionV4& left, const ConnectionV4& right) {
    PFL_EXPECT(left.key == right.key);
    PFL_EXPECT(left.has_flow_a == right.has_flow_a);
    PFL_EXPECT(left.has_flow_b == right.has_flow_b);
    PFL_EXPECT(left.packet_count == right.packet_count);
    PFL_EXPECT(left.total_bytes == right.total_bytes);
    PFL_EXPECT(left.has_fragmented_packets == right.has_fragmented_packets);
    PFL_EXPECT(left.fragmented_packet_count == right.fragmented_packet_count);
    PFL_EXPECT(left.protocol_hint == right.protocol_hint);
    PFL_EXPECT(left.service_hint == right.service_hint);
    PFL_EXPECT(left.quic_version == right.quic_version);
    PFL_EXPECT(left.tls_version == right.tls_version);
    PFL_EXPECT(left.aggregate_stats.first_timestamp_us == right.aggregate_stats.first_timestamp_us);
    PFL_EXPECT(left.aggregate_stats.last_timestamp_us == right.aggregate_stats.last_timestamp_us);
    PFL_EXPECT(left.aggregate_stats.captured_bytes == right.aggregate_stats.captured_bytes);
    PFL_EXPECT(left.aggregate_stats.truncated_packet_count == right.aggregate_stats.truncated_packet_count);
    PFL_EXPECT(left.aggregate_stats.tcp_syn_count == right.aggregate_stats.tcp_syn_count);
    PFL_EXPECT(left.aggregate_stats.tcp_fin_count == right.aggregate_stats.tcp_fin_count);
    PFL_EXPECT(left.aggregate_stats.tcp_rst_count == right.aggregate_stats.tcp_rst_count);
    PFL_EXPECT(left.aggregate_stats.max_original_packet_length == right.aggregate_stats.max_original_packet_length);
    PFL_EXPECT(left.aggregate_stats.max_captured_packet_length == right.aggregate_stats.max_captured_packet_length);
    if (left.has_flow_a || right.has_flow_a) {
        expect_matching_flows(left.flow_a, right.flow_a);
    }
    if (left.has_flow_b || right.has_flow_b) {
        expect_matching_flows(left.flow_b, right.flow_b);
    }
}

void expect_matching_connections(const ConnectionV6& left, const ConnectionV6& right) {
    PFL_EXPECT(left.key == right.key);
    PFL_EXPECT(left.has_flow_a == right.has_flow_a);
    PFL_EXPECT(left.has_flow_b == right.has_flow_b);
    PFL_EXPECT(left.packet_count == right.packet_count);
    PFL_EXPECT(left.total_bytes == right.total_bytes);
    PFL_EXPECT(left.has_fragmented_packets == right.has_fragmented_packets);
    PFL_EXPECT(left.fragmented_packet_count == right.fragmented_packet_count);
    PFL_EXPECT(left.protocol_hint == right.protocol_hint);
    PFL_EXPECT(left.service_hint == right.service_hint);
    PFL_EXPECT(left.quic_version == right.quic_version);
    PFL_EXPECT(left.tls_version == right.tls_version);
    PFL_EXPECT(left.aggregate_stats.first_timestamp_us == right.aggregate_stats.first_timestamp_us);
    PFL_EXPECT(left.aggregate_stats.last_timestamp_us == right.aggregate_stats.last_timestamp_us);
    PFL_EXPECT(left.aggregate_stats.captured_bytes == right.aggregate_stats.captured_bytes);
    PFL_EXPECT(left.aggregate_stats.truncated_packet_count == right.aggregate_stats.truncated_packet_count);
    PFL_EXPECT(left.aggregate_stats.tcp_syn_count == right.aggregate_stats.tcp_syn_count);
    PFL_EXPECT(left.aggregate_stats.tcp_fin_count == right.aggregate_stats.tcp_fin_count);
    PFL_EXPECT(left.aggregate_stats.tcp_rst_count == right.aggregate_stats.tcp_rst_count);
    PFL_EXPECT(left.aggregate_stats.max_original_packet_length == right.aggregate_stats.max_original_packet_length);
    PFL_EXPECT(left.aggregate_stats.max_captured_packet_length == right.aggregate_stats.max_captured_packet_length);
    if (left.has_flow_a || right.has_flow_a) {
        expect_matching_flows(left.flow_a, right.flow_a);
    }
    if (left.has_flow_b || right.has_flow_b) {
        expect_matching_flows(left.flow_b, right.flow_b);
    }
}

void expect_matching_tables(const ConnectionTableV4& left, const ConnectionTableV4& right) {
    const auto left_connections = detail::sorted_connections(left);
    const auto right_connections = detail::sorted_connections(right);
    PFL_EXPECT(left_connections.size() == right_connections.size());
    for (std::size_t index = 0; index < left_connections.size(); ++index) {
        expect_matching_connections(*left_connections[index], *right_connections[index]);
    }
}

void expect_matching_tables(const ConnectionTableV6& left, const ConnectionTableV6& right) {
    const auto left_connections = detail::sorted_connections(left);
    const auto right_connections = detail::sorted_connections(right);
    PFL_EXPECT(left_connections.size() == right_connections.size());
    for (std::size_t index = 0; index < left_connections.size(); ++index) {
        expect_matching_connections(*left_connections[index], *right_connections[index]);
    }
}

void expect_matching_states(const CaptureState& left, const CaptureState& right) {
    PFL_EXPECT(left.summary.packet_count == right.summary.packet_count);
    PFL_EXPECT(left.summary.flow_count == right.summary.flow_count);
    PFL_EXPECT(left.summary.total_bytes == right.summary.total_bytes);
    PFL_EXPECT(left.packet_locator.size() == right.packet_locator.size());
    for (std::size_t index = 0U; index < left.packet_locator.size(); ++index) {
        PFL_EXPECT(left.packet_locator[index].packet_index == right.packet_locator[index].packet_index);
        PFL_EXPECT(left.packet_locator[index].file_offset == right.packet_locator[index].file_offset);
    }
    expect_matching_protocol_path_registries(left.protocol_path_registry, right.protocol_path_registry);
    expect_matching_tables(left.ipv4_connections, right.ipv4_connections);
    expect_matching_tables(left.ipv6_connections, right.ipv6_connections);
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

CaptureStatisticsProtocolCounters capture_statistics_counters(
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

CaptureStatisticsFlowPacketCountHistogram make_capture_statistics_flow_histogram() {
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

CaptureStatisticsSnapshot make_valid_capture_statistics_snapshot() {
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
    snapshot.flow_packet_count_histogram = make_capture_statistics_flow_histogram();
    snapshot.transport_protocols = make_default_capture_statistics_transport_protocol_rows();
    snapshot.transport_protocols[0].counters = capture_statistics_counters(2U, 6U, 900U, 1'100U);
    snapshot.transport_protocols[1].counters = capture_statistics_counters(1U, 3U, 250U, 300U);
    snapshot.transport_protocols[3].counters = capture_statistics_counters(1U, 1U, 40U, 50U);
    snapshot.ip_families = make_default_capture_statistics_ip_family_rows();
    snapshot.ip_families[0].counters = capture_statistics_counters(2U, 7U, 940U, 1'150U);
    snapshot.ip_families[1].counters = capture_statistics_counters(2U, 3U, 250U, 300U);
    snapshot.detected_protocols = make_default_capture_statistics_detected_protocol_rows();
    snapshot.detected_protocols[0].counters = capture_statistics_counters(1U, 2U, 200U, 250U);
    snapshot.detected_protocols[1].counters = capture_statistics_counters(1U, 3U, 300U, 360U);
    snapshot.detected_protocols[2].counters = capture_statistics_counters(1U, 1U, 80U, 90U);
    snapshot.detected_protocols[3].counters = capture_statistics_counters(1U, 2U, 250U, 300U);
    snapshot.detected_protocols[12].counters = capture_statistics_counters(1U, 3U, 300U, 360U);
    snapshot.detected_protocols[13].counters = capture_statistics_counters(1U, 1U, 40U, 50U);
    snapshot.detected_protocols[15].counters = capture_statistics_counters(1U, 2U, 120U, 150U);
    snapshot.quic_recognition = CaptureStatisticsQuicRecognition {
        .flow_count = 1U,
        .with_sni_count = 1U,
        .v1_count = 1U,
    };
    snapshot.tls_recognition = CaptureStatisticsTlsRecognition {
        .flow_count = 2U,
        .with_sni_count = 1U,
        .without_sni_count = 1U,
        .tls12_count = 1U,
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
    PFL_REQUIRE(validate_capture_statistics_snapshot(snapshot).ok);
    return snapshot;
}

std::vector<std::uint8_t> serialize_capture_statistics_snapshot_payload(
    const CaptureStatisticsSnapshot& snapshot
) {
    std::ostringstream stream(std::ios::binary | std::ios::out);
    PFL_REQUIRE(detail::write_capture_statistics_snapshot(stream, snapshot));
    return stream_bytes(stream);
}

detail::CaptureIndexStableHeader make_v16_stable_header() {
    auto header = make_stable_header();
    header.index_revision = kCaptureIndexStableV16Revision;
    return header;
}

std::vector<std::uint8_t> make_inactive_v16_snapshot_container_bytes(
    const CaptureStatisticsSnapshot& snapshot,
    std::span<const std::uint8_t> trailing_bytes = {}
) {
    std::ostringstream stream(std::ios::binary | std::ios::out);
    PFL_REQUIRE(detail::write_capture_index_stable_header(stream, make_v16_stable_header()));
    PFL_REQUIRE(detail::write_v16_capture_statistics_snapshot_section(stream, snapshot));
    if (!trailing_bytes.empty()) {
        PFL_REQUIRE(detail::write_bytes(stream, trailing_bytes));
    }
    return stream_bytes(stream);
}

ProtocolPathRegistry make_v16_protocol_path_registry_fixture() {
    ProtocolPathRegistry registry {};
    PFL_REQUIRE(registry.intern(ProtocolPath {
        LayerKey::ethernet_ii(),
        LayerKey::ipv4(),
        LayerKey::tcp(),
    }) == 1U);
    PFL_REQUIRE(registry.intern(ProtocolPath {
        LayerKey::ethernet_ii(),
        LayerKey::ipv6(),
        LayerKey::udp(),
    }) == 2U);
    PFL_REQUIRE(registry.intern(ProtocolPath {
        LayerKey::ethernet_ii(),
        LayerKey::ipv4(),
        LayerKey::udp(),
        LayerKey::vxlan(7U),
        LayerKey::ethernet_ii(),
        LayerKey::ipv4(),
        LayerKey::tcp(),
    }) == 3U);

    for (std::uint32_t index = 4U; index <= 17U; ++index) {
        PFL_REQUIRE(registry.intern(ProtocolPath {
            LayerKey::ethernet_ii(),
            LayerKey::vlan(static_cast<std::uint16_t>(100U + index)),
            LayerKey::ipv4(),
            LayerKey::tcp(),
        }) == index);
    }

    return registry;
}

ProtocolPathDisplayStatistics make_valid_protocol_path_display_statistics() {
    return ProtocolPathDisplayStatistics {
        .terminal_path_aggregates = {
            ProtocolPathDisplayAggregateRow {
                .protocol_path_id = 3U,
                .flow_count = 1U,
                .packet_count = 0U,
                .original_byte_count = 700U,
            },
            ProtocolPathDisplayAggregateRow {
                .protocol_path_id = 11U,
                .flow_count = 2U,
                .packet_count = 2U,
                .original_byte_count = 1'200U,
            },
            ProtocolPathDisplayAggregateRow {
                .protocol_path_id = 17U,
                .flow_count = 1U,
                .packet_count = 1U,
                .original_byte_count = 800U,
            },
        },
    };
}

std::vector<std::uint8_t> serialize_protocol_path_display_statistics_payload(
    const ProtocolPathDisplayStatistics& statistics
) {
    std::ostringstream stream(std::ios::binary | std::ios::out);
    PFL_REQUIRE(detail::write_protocol_path_display_statistics(stream, statistics));
    return stream_bytes(stream);
}

detail::CaptureIndexV16FastStatisticsTier make_valid_v16_fast_statistics_tier() {
    const auto registry = make_v16_protocol_path_registry_fixture();
    const auto statistics = make_valid_protocol_path_display_statistics();
    PFL_REQUIRE(validate_protocol_path_display_statistics(registry, statistics).ok);

    auto snapshot = make_valid_capture_statistics_snapshot();
    PFL_REQUIRE(snapshot.top_flows.size() == 2U);
    snapshot.top_flows[0].protocol_path_id = 11U;
    std::get<ConnectionKeyV4>(snapshot.top_flows[0].connection_key).protocol_path_id = 11U;
    snapshot.top_flows[1].protocol_path_id = 17U;
    std::get<ConnectionKeyV6>(snapshot.top_flows[1].connection_key).protocol_path_id = 17U;
    PFL_REQUIRE(validate_capture_statistics_snapshot(snapshot).ok);

    return detail::CaptureIndexV16FastStatisticsTier {
        .capture_statistics_snapshot = std::move(snapshot),
        .protocol_path_registry = registry,
        .protocol_path_display_statistics = statistics,
    };
}

std::vector<std::uint8_t> make_v16_fast_statistics_tier_container_bytes(
    const detail::CaptureIndexV16FastStatisticsTier& tier,
    std::span<const std::uint8_t> trailing_bytes = {}
) {
    std::ostringstream stream(std::ios::binary | std::ios::out);
    PFL_REQUIRE(detail::write_v16_fast_statistics_tier(stream, make_v16_stable_header(), tier));
    if (!trailing_bytes.empty()) {
        PFL_REQUIRE(detail::write_bytes(stream, trailing_bytes));
    }
    return stream_bytes(stream);
}

}  // namespace

void run_index_format_tests() {
    {
        const auto unicode_path = stable_header_unicode_path();
        const auto unicode_utf8 = detail::filesystem_path_to_generic_utf8(unicode_path);
        PFL_EXPECT(unicode_utf8 == stable_header_unicode_generic_utf8());
        PFL_EXPECT(
            detail::filesystem_path_to_generic_utf8(
                detail::filesystem_path_from_generic_utf8(unicode_utf8)
            ) == unicode_utf8
        );

        const auto ascii_path = std::filesystem::path("/tmp/ascii/pcap_flow_lab_showcase.pcap");
        const auto ascii_utf8 = detail::filesystem_path_to_generic_utf8(ascii_path);
        PFL_EXPECT(ascii_utf8 == "/tmp/ascii/pcap_flow_lab_showcase.pcap");
        PFL_EXPECT(
            detail::filesystem_path_to_generic_utf8(
                detail::filesystem_path_from_generic_utf8(ascii_utf8)
            ) == ascii_utf8
        );
    }

    {
        const auto header = make_stable_header();
        const detail::CaptureIndexStableSectionHeader first_section {
            .section_id = 0x00000002U,
            .section_schema_version = 1U,
            .section_flags = detail::kCaptureIndexStableSectionFlagRequired,
            .payload_size = 3U,
        };
        std::ostringstream write_stream(std::ios::binary | std::ios::out);
        PFL_REQUIRE(detail::write_capture_index_stable_header(write_stream, header));
        PFL_REQUIRE(detail::write_capture_index_stable_section_header(write_stream, first_section));
        PFL_REQUIRE(detail::write_bytes(write_stream, std::array<std::uint8_t, 3> {0x10U, 0x20U, 0x30U}));
        const auto encoded_header = stream_bytes(write_stream);

        PFL_EXPECT(read_le64_at(encoded_header, 0U) == kStableCaptureIndexMagic);
        PFL_EXPECT(encoded_header.size() >= detail::kCaptureIndexStableHeaderKnownPrefixSize);
        PFL_EXPECT(read_le16_at(encoded_header, 8U) == kCaptureIndexStableContainerFormatVersion);
        PFL_EXPECT(read_le16_at(encoded_header, 10U) == 0U);
        const auto declared_header_size = read_le32_at(encoded_header, 12U);
        PFL_EXPECT(declared_header_size < encoded_header.size());
        PFL_EXPECT(read_le32_at(encoded_header, 16U) == kCaptureIndexStableIndexRevision);

        const auto encoded_size = detail::encoded_capture_index_stable_header_size(header);
        PFL_REQUIRE(encoded_size.has_value());
        PFL_EXPECT(*encoded_size == declared_header_size);

        detail::CaptureIndexStableHeader decoded_header {};
        std::istringstream read_stream(
            std::string(encoded_header.begin(), encoded_header.end()),
            std::ios::binary | std::ios::in
        );
        PFL_REQUIRE(detail::read_capture_index_stable_header(read_stream, decoded_header));
        PFL_EXPECT(decoded_header.magic == kStableCaptureIndexMagic);
        PFL_EXPECT(decoded_header.container_format_version == kCaptureIndexStableContainerFormatVersion);
        PFL_EXPECT(decoded_header.header_flags == 0U);
        PFL_EXPECT(decoded_header.header_size == declared_header_size);
        PFL_EXPECT(decoded_header.index_revision == kCaptureIndexStableIndexRevision);
        PFL_EXPECT(decoded_header.writer_application_version == header.writer_application_version);
        PFL_EXPECT(decoded_header.source_format == header.source_format);
        PFL_EXPECT(decoded_header.source_file_size == header.source_file_size);
        PFL_EXPECT(decoded_header.source_last_write_time == header.source_last_write_time);
        PFL_EXPECT(decoded_header.source_content_fingerprint == header.source_content_fingerprint);
        PFL_EXPECT(decoded_header.source_capture_path_utf8 == header.source_capture_path_utf8);

        detail::CaptureIndexStableSectionHeader decoded_section {};
        PFL_REQUIRE(detail::read_capture_index_stable_section_header(read_stream, decoded_section));
        PFL_EXPECT(decoded_section.section_id == first_section.section_id);
        PFL_EXPECT(decoded_section.section_schema_version == first_section.section_schema_version);
        PFL_EXPECT(decoded_section.section_flags == first_section.section_flags);
        PFL_EXPECT(decoded_section.payload_size == first_section.payload_size);
    }

    {
        const auto header = make_stable_header();
        const std::vector<std::uint8_t> extension_bytes {0xAAU, 0x55U, 0x10U, 0x20U, 0x30U};
        const detail::CaptureIndexStableSectionHeader first_section {
            .section_id = 0x00000007U,
            .section_schema_version = 3U,
            .section_flags = 0U,
            .payload_size = 0x0102030405060708ULL,
        };
        std::ostringstream stream(std::ios::binary | std::ios::out);
        const auto extension = std::span<const std::uint8_t>(extension_bytes.data(), extension_bytes.size());
        PFL_REQUIRE(detail::write_capture_index_stable_header(stream, header, extension));
        PFL_REQUIRE(detail::write_capture_index_stable_section_header(stream, first_section));
        const auto encoded_header = stream_bytes(stream);
        PFL_EXPECT(read_le32_at(encoded_header, 12U) + detail::kCaptureIndexStableSectionHeaderEncodedSize == encoded_header.size());

        detail::CaptureIndexStableHeader decoded_header {};
        std::istringstream read_stream(
            std::string(encoded_header.begin(), encoded_header.end()),
            std::ios::binary | std::ios::in
        );
        PFL_REQUIRE(detail::read_capture_index_stable_header(read_stream, decoded_header));
        PFL_EXPECT(decoded_header.header_size + detail::kCaptureIndexStableSectionHeaderEncodedSize == encoded_header.size());
        PFL_EXPECT(decoded_header.source_capture_path_utf8 == header.source_capture_path_utf8);

        detail::CaptureIndexStableSectionHeader decoded_section {};
        PFL_REQUIRE(detail::read_capture_index_stable_section_header(read_stream, decoded_section));
        PFL_EXPECT(decoded_section.section_id == first_section.section_id);
        PFL_EXPECT(decoded_section.section_schema_version == first_section.section_schema_version);
        PFL_EXPECT(decoded_section.section_flags == first_section.section_flags);
        PFL_EXPECT(decoded_section.payload_size == first_section.payload_size);
    }

    {
        const auto header = make_stable_header();
        auto encoded_header = encode_stable_header(header);

        write_le16_at(encoded_header, 8U, 1U);
        PFL_EXPECT(read_le16_at(encoded_header, 8U) == 1U);

        write_le32_at(encoded_header, 16U, 15U);
        PFL_EXPECT(read_le32_at(encoded_header, 16U) == 15U);

        auto malformed_small_header = encoded_header;
        write_le32_at(malformed_small_header, 12U, detail::kCaptureIndexStableHeaderKnownPrefixSize - 1U);

        detail::CaptureIndexStableHeader decoded_header {};
        std::istringstream malformed_stream(
            std::string(malformed_small_header.begin(), malformed_small_header.end()),
            std::ios::binary | std::ios::in
        );
        PFL_EXPECT(!detail::read_capture_index_stable_header(malformed_stream, decoded_header));

        auto truncated_header = encoded_header;
        truncated_header.pop_back();
        std::istringstream truncated_stream(
            std::string(truncated_header.begin(), truncated_header.end()),
            std::ios::binary | std::ios::in
        );
        PFL_EXPECT(!detail::read_capture_index_stable_header(truncated_stream, decoded_header));

        auto truncated_writer_string_header = encoded_header;
        const auto writer_string_offset = 20U;
        const auto writer_string_length = read_le32_at(truncated_writer_string_header, writer_string_offset);
        PFL_REQUIRE(writer_string_length > 0U);
        truncated_writer_string_header.resize(truncated_writer_string_header.size() - 1U);
        std::istringstream truncated_writer_string_stream(
            std::string(truncated_writer_string_header.begin(), truncated_writer_string_header.end()),
            std::ios::binary | std::ios::in
        );
        PFL_EXPECT(!detail::read_capture_index_stable_header(truncated_writer_string_stream, decoded_header));
    }

    {
        detail::CaptureIndexStableSectionHeader section_header {
            .section_id = 0x01020304U,
            .section_schema_version = 7U,
            .section_flags = detail::kCaptureIndexStableSectionFlagRequired,
            .payload_size = 0x0102030405060708ULL,
        };
        std::ostringstream stream(std::ios::binary | std::ios::out);
        PFL_REQUIRE(detail::write_capture_index_stable_section_header(stream, section_header));
        const auto encoded_header = stream_bytes(stream);

        PFL_EXPECT(detail::kCaptureIndexStableSectionHeaderEncodedSize == 16U);
        PFL_EXPECT(encoded_header.size() == detail::kCaptureIndexStableSectionHeaderEncodedSize);
        PFL_EXPECT(read_le32_at(encoded_header, 0U) == section_header.section_id);
        PFL_EXPECT(read_le16_at(encoded_header, 4U) == section_header.section_schema_version);
        PFL_EXPECT(read_le16_at(encoded_header, 6U) == detail::kCaptureIndexStableSectionFlagRequired);
        PFL_EXPECT(read_le64_at(encoded_header, 8U) == section_header.payload_size);

        detail::CaptureIndexStableSectionHeader decoded_header {};
        std::istringstream read_stream(
            std::string(encoded_header.begin(), encoded_header.end()),
            std::ios::binary | std::ios::in
        );
        PFL_REQUIRE(detail::read_capture_index_stable_section_header(read_stream, decoded_header));
        PFL_EXPECT(decoded_header.section_id == section_header.section_id);
        PFL_EXPECT(decoded_header.section_schema_version == section_header.section_schema_version);
        PFL_EXPECT(decoded_header.section_flags == section_header.section_flags);
        PFL_EXPECT(decoded_header.payload_size == section_header.payload_size);

        auto truncated_section_header = encoded_header;
        truncated_section_header.pop_back();
        std::istringstream truncated_stream(
            std::string(truncated_section_header.begin(), truncated_section_header.end()),
            std::ios::binary | std::ios::in
        );
        PFL_EXPECT(!detail::read_capture_index_stable_section_header(truncated_stream, decoded_header));
    }

    {
        auto header = make_v16_stable_header();
        const auto encoded_header = encode_stable_header(header);
        PFL_EXPECT(read_le64_at(encoded_header, 0U) == kStableCaptureIndexMagic);
        PFL_EXPECT(read_le16_at(encoded_header, 8U) == kCaptureIndexStableContainerFormatVersion);
        PFL_EXPECT(read_le32_at(encoded_header, 16U) == kCaptureIndexStableV16Revision);
        PFL_EXPECT(kCaptureIndexStableIndexRevision == 15U);
        PFL_EXPECT(kCaptureIndexVersion == 15U);

        detail::CaptureIndexStableHeader decoded_header {};
        std::istringstream read_stream(
            std::string(encoded_header.begin(), encoded_header.end()),
            std::ios::binary | std::ios::in
        );
        PFL_REQUIRE(detail::read_capture_index_stable_header(read_stream, decoded_header));
        PFL_EXPECT(decoded_header.index_revision == kCaptureIndexStableV16Revision);
        PFL_EXPECT(decoded_header.source_capture_path_utf8 == header.source_capture_path_utf8);
    }

    {
        const auto snapshot = make_valid_capture_statistics_snapshot();
        const auto payload = serialize_capture_statistics_snapshot_payload(snapshot);
        const auto container_bytes = make_inactive_v16_snapshot_container_bytes(snapshot);
        const auto sections = parse_sections(container_bytes);
        PFL_REQUIRE(sections.size() == 1U);

        const auto& snapshot_section = sections.front();
        PFL_EXPECT(snapshot_section.id == static_cast<std::uint32_t>(detail::CaptureIndexSectionId::capture_statistics_snapshot));
        PFL_EXPECT(snapshot_section.schema_version == detail::kCaptureIndexStableCaptureStatisticsSnapshotSectionSchemaVersion);
        PFL_EXPECT(snapshot_section.flags == detail::kCaptureIndexStableSectionFlagRequired);
        PFL_EXPECT(snapshot_section.total_size ==
            static_cast<std::size_t>(detail::kCaptureIndexStableSectionHeaderEncodedSize + payload.size()));
        PFL_EXPECT(read_le64_at(container_bytes, snapshot_section.offset + 8U) == payload.size());

        const auto payload_offset = snapshot_section.offset + detail::kCaptureIndexStableSectionHeaderEncodedSize;
        std::vector<std::uint8_t> section_payload(
            container_bytes.begin() + static_cast<std::ptrdiff_t>(payload_offset),
            container_bytes.begin() + static_cast<std::ptrdiff_t>(payload_offset + payload.size())
        );
        PFL_EXPECT(section_payload == payload);

        std::istringstream stream(
            std::string(container_bytes.begin(), container_bytes.end()),
            std::ios::binary | std::ios::in
        );
        detail::CaptureIndexStableHeader decoded_header {};
        PFL_REQUIRE(detail::read_capture_index_stable_header(stream, decoded_header));
        PFL_EXPECT(decoded_header.index_revision == kCaptureIndexStableV16Revision);

        CaptureStatisticsSnapshot decoded_snapshot {};
        const auto read_result = detail::read_v16_capture_statistics_snapshot_section(stream, decoded_snapshot);
        PFL_REQUIRE(static_cast<bool>(read_result));
        PFL_EXPECT(decoded_snapshot == snapshot);
        PFL_EXPECT(stream.peek() == std::char_traits<char>::eof());
    }

    {
        const auto snapshot = make_valid_capture_statistics_snapshot();
        const auto base_bytes = make_inactive_v16_snapshot_container_bytes(snapshot);
        const auto sections = parse_sections(base_bytes);
        PFL_REQUIRE(sections.size() == 1U);
        const auto payload_offset = sections.front().offset + detail::kCaptureIndexStableSectionHeaderEncodedSize;

        auto expect_status = [&](std::vector<std::uint8_t> bytes,
                                 const detail::CaptureStatisticsSnapshotSectionReadStatus status) {
            std::istringstream stream(
                std::string(bytes.begin(), bytes.end()),
                std::ios::binary | std::ios::in
            );
            detail::CaptureIndexStableHeader decoded_header {};
            PFL_REQUIRE(detail::read_capture_index_stable_header(stream, decoded_header));
            CaptureStatisticsSnapshot decoded_snapshot {};
            const auto read_result = detail::read_v16_capture_statistics_snapshot_section(stream, decoded_snapshot);
            PFL_EXPECT(read_result.status == status);
            PFL_EXPECT(decoded_snapshot == CaptureStatisticsSnapshot {});
        };

        {
            auto wrong_section_bytes = base_bytes;
            write_le32_at(
                wrong_section_bytes,
                sections.front().offset,
                static_cast<std::uint32_t>(detail::CaptureIndexSectionId::protocol_path_registry_early)
            );
            expect_status(
                std::move(wrong_section_bytes),
                detail::CaptureStatisticsSnapshotSectionReadStatus::wrong_section_id
            );
        }

        {
            auto invalid_framing_bytes = base_bytes;
            write_le16_at(invalid_framing_bytes, sections.front().offset + 6U, 0U);
            expect_status(
                std::move(invalid_framing_bytes),
                detail::CaptureStatisticsSnapshotSectionReadStatus::invalid_section_framing
            );
        }

        {
            auto wrong_schema_bytes = base_bytes;
            write_le16_at(wrong_schema_bytes, sections.front().offset + 4U, 99U);
            expect_status(
                std::move(wrong_schema_bytes),
                detail::CaptureStatisticsSnapshotSectionReadStatus::unsupported_schema_version
            );
        }

        {
            std::vector<std::uint8_t> truncated_section_header(
                base_bytes.begin(),
                base_bytes.begin() + static_cast<std::ptrdiff_t>(stable_header_size(base_bytes) + 15U)
            );
            expect_status(
                std::move(truncated_section_header),
                detail::CaptureStatisticsSnapshotSectionReadStatus::invalid_section_header
            );
        }

        {
            auto truncated_payload_bytes = base_bytes;
            truncated_payload_bytes.pop_back();
            expect_status(
                std::move(truncated_payload_bytes),
                detail::CaptureStatisticsSnapshotSectionReadStatus::truncated_payload
            );
        }

        {
            auto oversized_payload_bytes = base_bytes;
            write_le64_at(
                oversized_payload_bytes,
                sections.front().offset + 8U,
                detail::max_capture_statistics_snapshot_payload_size_bytes() + 1U
            );
            expect_status(
                std::move(oversized_payload_bytes),
                detail::CaptureStatisticsSnapshotSectionReadStatus::payload_too_large
            );
        }

        {
            auto malformed_payload_bytes = base_bytes;
            malformed_payload_bytes[payload_offset] = 99U;
            expect_status(
                std::move(malformed_payload_bytes),
                detail::CaptureStatisticsSnapshotSectionReadStatus::malformed_snapshot_payload
            );
        }

        {
            auto semantically_invalid_payload_bytes = base_bytes;
            write_le64_at(semantically_invalid_payload_bytes, payload_offset + 1U, 4U);
            std::istringstream stream(
                std::string(
                    semantically_invalid_payload_bytes.begin(),
                    semantically_invalid_payload_bytes.end()
                ),
                std::ios::binary | std::ios::in
            );
            detail::CaptureIndexStableHeader decoded_header {};
            PFL_REQUIRE(detail::read_capture_index_stable_header(stream, decoded_header));
            CaptureStatisticsSnapshot decoded_snapshot {};
            const auto read_result = detail::read_v16_capture_statistics_snapshot_section(stream, decoded_snapshot);
            PFL_EXPECT(read_result.status == detail::CaptureStatisticsSnapshotSectionReadStatus::snapshot_semantic_inconsistency);
            PFL_REQUIRE(read_result.validation_error.has_value());
            PFL_EXPECT(
                read_result.validation_error->code ==
                CaptureStatisticsSnapshotValidationErrorCode::captured_packet_histogram_sum_mismatch
            );
        }
    }

    {
        const auto snapshot = make_valid_capture_statistics_snapshot();
        std::ostringstream stream(std::ios::binary | std::ios::out);
        PFL_REQUIRE(detail::write_capture_index_stable_header(stream, make_v16_stable_header()));
        PFL_REQUIRE(detail::write_v16_capture_statistics_snapshot_section(stream, snapshot));
        const detail::CaptureIndexStableSectionHeader following_section {
            .section_id = static_cast<std::uint32_t>(detail::CaptureIndexSectionId::ipv4_flow_metadata),
            .section_schema_version = 1U,
            .section_flags = detail::kCaptureIndexStableSectionFlagRequired,
            .payload_size = 4U,
        };
        PFL_REQUIRE(detail::write_capture_index_stable_section_header(stream, following_section));
        PFL_REQUIRE(detail::write_bytes(stream, std::array<std::uint8_t, 4> {0xDEU, 0xADU, 0xBEU, 0xEFU}));
        const auto container_bytes = stream_bytes(stream);
        const auto sections = parse_sections(container_bytes);
        PFL_REQUIRE(sections.size() == 2U);

        std::istringstream read_stream(
            std::string(container_bytes.begin(), container_bytes.end()),
            std::ios::binary | std::ios::in
        );
        detail::CaptureIndexStableHeader decoded_header {};
        PFL_REQUIRE(detail::read_capture_index_stable_header(read_stream, decoded_header));
        CaptureStatisticsSnapshot decoded_snapshot {};
        const auto read_result = detail::read_v16_capture_statistics_snapshot_section(read_stream, decoded_snapshot);
        PFL_REQUIRE(static_cast<bool>(read_result));
        PFL_EXPECT(decoded_snapshot == snapshot);
        PFL_EXPECT(
            static_cast<std::size_t>(read_stream.tellg()) ==
            sections.front().offset + sections.front().total_size
        );

        detail::CaptureIndexStableSectionHeader decoded_following_section {};
        PFL_REQUIRE(detail::read_capture_index_stable_section_header(read_stream, decoded_following_section));
        PFL_EXPECT(decoded_following_section.section_id == following_section.section_id);
        PFL_EXPECT(decoded_following_section.payload_size == following_section.payload_size);

        std::vector<std::uint8_t> following_payload {};
        PFL_REQUIRE(detail::read_bounded_section_payload(
            read_stream,
            decoded_following_section.payload_size,
            decoded_following_section.payload_size,
            following_payload
        ));
        PFL_EXPECT((following_payload == std::vector<std::uint8_t> {0xDEU, 0xADU, 0xBEU, 0xEFU}));
    }

    {
        const auto snapshot = make_valid_capture_statistics_snapshot();
        const std::vector<std::uint8_t> malformed_late_bytes {0xAAU, 0x55U, 0x10U};
        const auto container_bytes = make_inactive_v16_snapshot_container_bytes(
            snapshot,
            std::span<const std::uint8_t>(malformed_late_bytes.data(), malformed_late_bytes.size())
        );
        const auto snapshot_section_end =
            stable_header_size(container_bytes) +
            detail::kCaptureIndexStableSectionHeaderEncodedSize +
            serialize_capture_statistics_snapshot_payload(snapshot).size();

        std::istringstream stream(
            std::string(container_bytes.begin(), container_bytes.end()),
            std::ios::binary | std::ios::in
        );
        detail::CaptureIndexStableHeader decoded_header {};
        PFL_REQUIRE(detail::read_capture_index_stable_header(stream, decoded_header));
        CaptureStatisticsSnapshot decoded_snapshot {};
        const auto read_result = detail::read_v16_capture_statistics_snapshot_section(stream, decoded_snapshot);
        PFL_REQUIRE(static_cast<bool>(read_result));
        PFL_EXPECT(decoded_snapshot == snapshot);
        PFL_EXPECT(static_cast<std::size_t>(stream.tellg()) == snapshot_section_end);
        PFL_EXPECT(stream.peek() == static_cast<int>(malformed_late_bytes.front()));
    }

    {
        const auto registry = make_v16_protocol_path_registry_fixture();

        std::ostringstream payload_stream(std::ios::binary | std::ios::out);
        PFL_REQUIRE(detail::write_protocol_path_registry(payload_stream, registry));
        const auto payload = stream_bytes(payload_stream);

        std::ostringstream stream(std::ios::binary | std::ios::out);
        PFL_REQUIRE(detail::write_capture_index_stable_header(stream, make_v16_stable_header()));
        PFL_REQUIRE(detail::write_v16_protocol_path_registry_early_section(stream, registry));
        const auto container_bytes = stream_bytes(stream);
        const auto sections = parse_sections(container_bytes);
        PFL_REQUIRE(sections.size() == 1U);

        const auto& section = sections.front();
        PFL_EXPECT(section.id == static_cast<std::uint32_t>(detail::CaptureIndexSectionId::protocol_path_registry_early));
        PFL_EXPECT(section.schema_version == detail::kCaptureIndexStableProtocolPathRegistryEarlySectionSchemaVersion);
        PFL_EXPECT(section.flags == detail::kCaptureIndexStableSectionFlagRequired);

        const auto payload_offset = section.offset + detail::kCaptureIndexStableSectionHeaderEncodedSize;
        std::vector<std::uint8_t> section_payload(
            container_bytes.begin() + static_cast<std::ptrdiff_t>(payload_offset),
            container_bytes.begin() + static_cast<std::ptrdiff_t>(payload_offset + payload.size())
        );
        PFL_EXPECT(section_payload == payload);

        std::istringstream read_stream(
            std::string(container_bytes.begin(), container_bytes.end()),
            std::ios::binary | std::ios::in
        );
        detail::CaptureIndexStableHeader decoded_header {};
        PFL_REQUIRE(detail::read_capture_index_stable_header(read_stream, decoded_header));
        ProtocolPathRegistry decoded_registry {};
        const auto read_result = detail::read_v16_protocol_path_registry_early_section(
            read_stream,
            decoded_registry
        );
        PFL_REQUIRE(static_cast<bool>(read_result));
        expect_matching_protocol_path_registries(decoded_registry, registry);
        PFL_EXPECT(read_stream.peek() == std::char_traits<char>::eof());
    }

    {
        const auto registry = make_v16_protocol_path_registry_fixture();
        const auto statistics = make_valid_protocol_path_display_statistics();
        const auto payload = serialize_protocol_path_display_statistics_payload(statistics);
        PFL_EXPECT(payload.size() == 8U + (statistics.terminal_path_aggregates.size() * 28U));

        std::ostringstream stream(std::ios::binary | std::ios::out);
        PFL_REQUIRE(detail::write_capture_index_stable_header(stream, make_v16_stable_header()));
        PFL_REQUIRE(detail::write_v16_protocol_path_terminal_aggregates_section(stream, statistics));
        const auto base_bytes = stream_bytes(stream);
        const auto sections = parse_sections(base_bytes);
        PFL_REQUIRE(sections.size() == 1U);
        const auto payload_offset = sections.front().offset + detail::kCaptureIndexStableSectionHeaderEncodedSize;

        std::istringstream read_stream(
            std::string(base_bytes.begin(), base_bytes.end()),
            std::ios::binary | std::ios::in
        );
        detail::CaptureIndexStableHeader decoded_header {};
        PFL_REQUIRE(detail::read_capture_index_stable_header(read_stream, decoded_header));
        ProtocolPathDisplayStatistics decoded_statistics {};
        const auto read_result = detail::read_v16_protocol_path_terminal_aggregates_section(
            read_stream,
            registry,
            decoded_statistics
        );
        PFL_REQUIRE(static_cast<bool>(read_result));
        expect_matching_protocol_path_display_statistics(decoded_statistics, statistics);

        auto expect_display_status =
            [&](std::vector<std::uint8_t> bytes,
                const detail::ProtocolPathDisplayStatisticsSectionReadStatus status,
                const std::optional<ProtocolPathDisplayStatisticsValidationErrorCode> validation_code = std::nullopt) {
                std::istringstream mutated_stream(
                    std::string(bytes.begin(), bytes.end()),
                    std::ios::binary | std::ios::in
                );
                detail::CaptureIndexStableHeader mutated_header {};
                PFL_REQUIRE(detail::read_capture_index_stable_header(mutated_stream, mutated_header));
                ProtocolPathDisplayStatistics mutated_statistics {};
                const auto mutated_result = detail::read_v16_protocol_path_terminal_aggregates_section(
                    mutated_stream,
                    registry,
                    mutated_statistics
                );
                PFL_EXPECT(mutated_result.status == status);
                PFL_EXPECT(mutated_statistics.terminal_path_aggregates.empty());
                if (validation_code.has_value()) {
                    PFL_REQUIRE(mutated_result.validation_error.has_value());
                    PFL_EXPECT(mutated_result.validation_error->code == *validation_code);
                }
            };

        {
            auto invalid_path_id_bytes = base_bytes;
            write_le32_at(invalid_path_id_bytes, payload_offset + 8U, 0U);
            expect_display_status(
                std::move(invalid_path_id_bytes),
                detail::ProtocolPathDisplayStatisticsSectionReadStatus::protocol_path_display_statistics_semantic_inconsistency,
                ProtocolPathDisplayStatisticsValidationErrorCode::invalid_protocol_path_id
            );
        }

        {
            auto unknown_path_id_bytes = base_bytes;
            write_le32_at(unknown_path_id_bytes, payload_offset + 8U, 99U);
            expect_display_status(
                std::move(unknown_path_id_bytes),
                detail::ProtocolPathDisplayStatisticsSectionReadStatus::protocol_path_display_statistics_semantic_inconsistency,
                ProtocolPathDisplayStatisticsValidationErrorCode::unknown_protocol_path_id
            );
        }

        {
            auto duplicate_path_id_bytes = base_bytes;
            write_le32_at(duplicate_path_id_bytes, payload_offset + 36U, 3U);
            expect_display_status(
                std::move(duplicate_path_id_bytes),
                detail::ProtocolPathDisplayStatisticsSectionReadStatus::protocol_path_display_statistics_semantic_inconsistency,
                ProtocolPathDisplayStatisticsValidationErrorCode::duplicate_protocol_path_id
            );
        }

        {
            auto overflow_bytes = base_bytes;
            write_le64_at(overflow_bytes, payload_offset + 12U, (std::numeric_limits<std::uint64_t>::max)());
            expect_display_status(
                std::move(overflow_bytes),
                detail::ProtocolPathDisplayStatisticsSectionReadStatus::protocol_path_display_statistics_semantic_inconsistency,
                ProtocolPathDisplayStatisticsValidationErrorCode::total_flow_count_overflow
            );
        }

        {
            auto wrong_schema_bytes = base_bytes;
            write_le16_at(wrong_schema_bytes, sections.front().offset + 4U, 99U);
            expect_display_status(
                std::move(wrong_schema_bytes),
                detail::ProtocolPathDisplayStatisticsSectionReadStatus::unsupported_schema_version
            );
        }

        {
            auto truncated_payload_bytes = base_bytes;
            truncated_payload_bytes.pop_back();
            expect_display_status(
                std::move(truncated_payload_bytes),
                detail::ProtocolPathDisplayStatisticsSectionReadStatus::truncated_payload
            );
        }
    }

    {
        const auto tier = make_valid_v16_fast_statistics_tier();
        const auto base_bytes = make_v16_fast_statistics_tier_container_bytes(tier);
        const auto sections = parse_sections(base_bytes);
        PFL_REQUIRE(sections.size() == 3U);
        PFL_EXPECT(sections[0].id == static_cast<std::uint32_t>(detail::CaptureIndexSectionId::capture_statistics_snapshot));
        PFL_EXPECT(sections[1].id == static_cast<std::uint32_t>(detail::CaptureIndexSectionId::protocol_path_registry_early));
        PFL_EXPECT(sections[2].id == static_cast<std::uint32_t>(detail::CaptureIndexSectionId::protocol_path_terminal_aggregates));

        std::istringstream read_stream(
            std::string(base_bytes.begin(), base_bytes.end()),
            std::ios::binary | std::ios::in
        );
        detail::CaptureIndexV16FastStatisticsTier decoded_tier {};
        const auto read_result = detail::read_v16_fast_statistics_tier(read_stream, decoded_tier);
        PFL_REQUIRE(static_cast<bool>(read_result));
        PFL_EXPECT(read_result.header.index_revision == kCaptureIndexStableV16Revision);
        PFL_EXPECT(decoded_tier.capture_statistics_snapshot == tier.capture_statistics_snapshot);
        expect_matching_protocol_path_registries(decoded_tier.protocol_path_registry, tier.protocol_path_registry);
        expect_matching_protocol_path_display_statistics(
            decoded_tier.protocol_path_display_statistics,
            tier.protocol_path_display_statistics
        );
        PFL_EXPECT(static_cast<std::size_t>(read_stream.tellg()) == base_bytes.size());
    }

    {
        const auto tier = make_valid_v16_fast_statistics_tier();
        const auto first_chunk = ProtocolPathDisplayStatistics {
            .terminal_path_aggregates = {
                tier.protocol_path_display_statistics.terminal_path_aggregates[0],
                tier.protocol_path_display_statistics.terminal_path_aggregates[1],
            },
        };
        const auto second_chunk = ProtocolPathDisplayStatistics {
            .terminal_path_aggregates = {
                tier.protocol_path_display_statistics.terminal_path_aggregates[2],
            },
        };

        std::ostringstream stream(std::ios::binary | std::ios::out);
        PFL_REQUIRE(detail::write_capture_index_stable_header(stream, make_v16_stable_header()));
        PFL_REQUIRE(detail::write_v16_capture_statistics_snapshot_section(
            stream,
            tier.capture_statistics_snapshot
        ));
        PFL_REQUIRE(detail::write_v16_protocol_path_registry_early_section(
            stream,
            tier.protocol_path_registry
        ));
        PFL_REQUIRE(detail::write_v16_protocol_path_terminal_aggregates_section(stream, first_chunk));
        PFL_REQUIRE(detail::write_v16_protocol_path_terminal_aggregates_section(stream, second_chunk));
        const auto chunked_bytes = stream_bytes(stream);
        const auto sections = parse_sections(chunked_bytes);
        PFL_REQUIRE(sections.size() == 4U);
        PFL_EXPECT(sections[2].id == static_cast<std::uint32_t>(detail::CaptureIndexSectionId::protocol_path_terminal_aggregates));
        PFL_EXPECT(sections[3].id == static_cast<std::uint32_t>(detail::CaptureIndexSectionId::protocol_path_terminal_aggregates));

        std::istringstream read_stream(
            std::string(chunked_bytes.begin(), chunked_bytes.end()),
            std::ios::binary | std::ios::in
        );
        detail::CaptureIndexV16FastStatisticsTier decoded_tier {};
        const auto read_result = detail::read_v16_fast_statistics_tier(read_stream, decoded_tier);
        PFL_REQUIRE(static_cast<bool>(read_result));
        expect_matching_protocol_path_display_statistics(
            decoded_tier.protocol_path_display_statistics,
            tier.protocol_path_display_statistics
        );
        PFL_EXPECT(static_cast<std::size_t>(read_stream.tellg()) == chunked_bytes.size());
    }

    {
        const auto tier = make_valid_v16_fast_statistics_tier();
        const detail::CaptureIndexStableSectionHeader following_section {
            .section_id = static_cast<std::uint32_t>(detail::CaptureIndexSectionId::ipv4_flow_metadata),
            .section_schema_version = 1U,
            .section_flags = detail::kCaptureIndexStableSectionFlagRequired,
            .payload_size = 4U,
        };

        std::ostringstream stream(std::ios::binary | std::ios::out);
        PFL_REQUIRE(detail::write_v16_fast_statistics_tier(stream, make_v16_stable_header(), tier));
        const auto fast_prefix_size = stream_bytes(stream).size();
        PFL_REQUIRE(detail::write_capture_index_stable_section_header(stream, following_section));
        PFL_REQUIRE(detail::write_bytes(stream, std::array<std::uint8_t, 4> {0xDEU, 0xADU, 0xBEU, 0xEFU}));
        const auto container_bytes = stream_bytes(stream);

        std::istringstream read_stream(
            std::string(container_bytes.begin(), container_bytes.end()),
            std::ios::binary | std::ios::in
        );
        detail::CaptureIndexV16FastStatisticsTier decoded_tier {};
        const auto read_result = detail::read_v16_fast_statistics_tier(read_stream, decoded_tier);
        PFL_REQUIRE(static_cast<bool>(read_result));
        PFL_EXPECT(static_cast<std::size_t>(read_stream.tellg()) == fast_prefix_size);

        detail::CaptureIndexStableSectionHeader decoded_following_section {};
        PFL_REQUIRE(detail::read_capture_index_stable_section_header(read_stream, decoded_following_section));
        PFL_EXPECT(decoded_following_section.section_id == following_section.section_id);
        PFL_EXPECT(decoded_following_section.payload_size == following_section.payload_size);

        std::vector<std::uint8_t> following_payload {};
        PFL_REQUIRE(detail::read_bounded_section_payload(
            read_stream,
            decoded_following_section.payload_size,
            decoded_following_section.payload_size,
            following_payload
        ));
        PFL_EXPECT((following_payload == std::vector<std::uint8_t> {0xDEU, 0xADU, 0xBEU, 0xEFU}));
    }

    {
        const auto tier = make_valid_v16_fast_statistics_tier();
        const std::vector<std::uint8_t> malformed_late_bytes {0xAAU, 0x55U, 0x10U};
        const auto container_bytes = make_v16_fast_statistics_tier_container_bytes(
            tier,
            std::span<const std::uint8_t>(malformed_late_bytes.data(), malformed_late_bytes.size())
        );
        const auto fast_prefix_size = container_bytes.size() - malformed_late_bytes.size();

        std::istringstream read_stream(
            std::string(container_bytes.begin(), container_bytes.end()),
            std::ios::binary | std::ios::in
        );
        detail::CaptureIndexV16FastStatisticsTier decoded_tier {};
        const auto read_result = detail::read_v16_fast_statistics_tier(read_stream, decoded_tier);
        PFL_REQUIRE(static_cast<bool>(read_result));
        PFL_EXPECT(static_cast<std::size_t>(read_stream.tellg()) == fast_prefix_size);
        PFL_EXPECT(read_stream.peek() == static_cast<int>(malformed_late_bytes.front()));
    }

    {
        const auto tier = make_valid_v16_fast_statistics_tier();
        const auto base_bytes = make_v16_fast_statistics_tier_container_bytes(tier);
        const auto sections = parse_sections(base_bytes);
        PFL_REQUIRE(sections.size() == 3U);
        const auto snapshot_payload_offset = sections[0].offset + detail::kCaptureIndexStableSectionHeaderEncodedSize;
        const auto registry_payload_offset = sections[1].offset + detail::kCaptureIndexStableSectionHeaderEncodedSize;
        const auto display_payload_offset = sections[2].offset + detail::kCaptureIndexStableSectionHeaderEncodedSize;

        auto expect_fast_tier_status =
            [&](std::vector<std::uint8_t> bytes,
                const detail::CaptureIndexV16FastStatisticsTierReadStatus status,
                const std::optional<ProtocolPathDisplayStatisticsValidationErrorCode> protocol_path_error = std::nullopt) {
                std::istringstream stream(
                    std::string(bytes.begin(), bytes.end()),
                    std::ios::binary | std::ios::in
                );
                detail::CaptureIndexV16FastStatisticsTier decoded_tier {};
                const auto read_result = detail::read_v16_fast_statistics_tier(stream, decoded_tier);
                PFL_EXPECT(read_result.status == status);
                PFL_EXPECT(decoded_tier.capture_statistics_snapshot == CaptureStatisticsSnapshot {});
                PFL_EXPECT(decoded_tier.protocol_path_registry.size() == 0U);
                PFL_EXPECT(decoded_tier.protocol_path_display_statistics.terminal_path_aggregates.empty());
                if (protocol_path_error.has_value()) {
                    PFL_REQUIRE(read_result.protocol_path_validation_error.has_value());
                    PFL_EXPECT(read_result.protocol_path_validation_error->code == *protocol_path_error);
                }
            };

        {
            auto malformed_snapshot_bytes = base_bytes;
            malformed_snapshot_bytes[snapshot_payload_offset] = 99U;
            expect_fast_tier_status(
                std::move(malformed_snapshot_bytes),
                detail::CaptureIndexV16FastStatisticsTierReadStatus::malformed_capture_statistics_snapshot_payload
            );
        }

        {
            auto missing_registry_bytes = remove_section(
                base_bytes,
                static_cast<std::uint32_t>(detail::CaptureIndexSectionId::protocol_path_registry_early)
            );
            missing_registry_bytes = remove_section(
                missing_registry_bytes,
                static_cast<std::uint32_t>(detail::CaptureIndexSectionId::protocol_path_terminal_aggregates)
            );
            expect_fast_tier_status(
                std::move(missing_registry_bytes),
                detail::CaptureIndexV16FastStatisticsTierReadStatus::missing_protocol_path_registry_early_section
            );
        }

        {
            auto missing_display_bytes = remove_section(
                base_bytes,
                static_cast<std::uint32_t>(detail::CaptureIndexSectionId::protocol_path_terminal_aggregates)
            );
            expect_fast_tier_status(
                std::move(missing_display_bytes),
                detail::CaptureIndexV16FastStatisticsTierReadStatus::missing_protocol_path_terminal_aggregates_section
            );
        }

        {
            std::ostringstream wrong_order_stream(std::ios::binary | std::ios::out);
            PFL_REQUIRE(detail::write_capture_index_stable_header(wrong_order_stream, make_v16_stable_header()));
            PFL_REQUIRE(detail::write_v16_capture_statistics_snapshot_section(
                wrong_order_stream,
                tier.capture_statistics_snapshot
            ));
            PFL_REQUIRE(detail::write_v16_protocol_path_terminal_aggregates_section(
                wrong_order_stream,
                tier.protocol_path_display_statistics
            ));
            PFL_REQUIRE(detail::write_v16_protocol_path_registry_early_section(
                wrong_order_stream,
                tier.protocol_path_registry
            ));
            expect_fast_tier_status(
                stream_bytes(wrong_order_stream),
                detail::CaptureIndexV16FastStatisticsTierReadStatus::wrong_fast_section_order
            );
        }

        {
            std::ostringstream duplicate_snapshot_stream(std::ios::binary | std::ios::out);
            PFL_REQUIRE(detail::write_capture_index_stable_header(duplicate_snapshot_stream, make_v16_stable_header()));
            PFL_REQUIRE(detail::write_v16_capture_statistics_snapshot_section(
                duplicate_snapshot_stream,
                tier.capture_statistics_snapshot
            ));
            PFL_REQUIRE(detail::write_v16_capture_statistics_snapshot_section(
                duplicate_snapshot_stream,
                tier.capture_statistics_snapshot
            ));
            PFL_REQUIRE(detail::write_v16_protocol_path_registry_early_section(
                duplicate_snapshot_stream,
                tier.protocol_path_registry
            ));
            PFL_REQUIRE(detail::write_v16_protocol_path_terminal_aggregates_section(
                duplicate_snapshot_stream,
                tier.protocol_path_display_statistics
            ));
            expect_fast_tier_status(
                stream_bytes(duplicate_snapshot_stream),
                detail::CaptureIndexV16FastStatisticsTierReadStatus::duplicate_capture_statistics_snapshot_section
            );
        }

        {
            std::ostringstream duplicate_registry_stream(std::ios::binary | std::ios::out);
            PFL_REQUIRE(detail::write_capture_index_stable_header(duplicate_registry_stream, make_v16_stable_header()));
            PFL_REQUIRE(detail::write_v16_capture_statistics_snapshot_section(
                duplicate_registry_stream,
                tier.capture_statistics_snapshot
            ));
            PFL_REQUIRE(detail::write_v16_protocol_path_registry_early_section(
                duplicate_registry_stream,
                tier.protocol_path_registry
            ));
            PFL_REQUIRE(detail::write_v16_protocol_path_registry_early_section(
                duplicate_registry_stream,
                tier.protocol_path_registry
            ));
            PFL_REQUIRE(detail::write_v16_protocol_path_terminal_aggregates_section(
                duplicate_registry_stream,
                tier.protocol_path_display_statistics
            ));
            expect_fast_tier_status(
                stream_bytes(duplicate_registry_stream),
                detail::CaptureIndexV16FastStatisticsTierReadStatus::duplicate_protocol_path_registry_early_section
            );
        }

        {
            auto malformed_registry_bytes = base_bytes;
            write_le64_at(malformed_registry_bytes, registry_payload_offset, 99U);
            expect_fast_tier_status(
                std::move(malformed_registry_bytes),
                detail::CaptureIndexV16FastStatisticsTierReadStatus::malformed_protocol_path_registry_payload
            );
        }

        {
            auto malformed_display_bytes = base_bytes;
            write_le64_at(malformed_display_bytes, display_payload_offset, 99U);
            expect_fast_tier_status(
                std::move(malformed_display_bytes),
                detail::CaptureIndexV16FastStatisticsTierReadStatus::malformed_protocol_path_terminal_aggregates_payload
            );
        }

        {
            auto unknown_path_bytes = base_bytes;
            write_le32_at(unknown_path_bytes, display_payload_offset + 8U, 99U);
            expect_fast_tier_status(
                std::move(unknown_path_bytes),
                detail::CaptureIndexV16FastStatisticsTierReadStatus::protocol_path_terminal_aggregates_semantic_inconsistency,
                ProtocolPathDisplayStatisticsValidationErrorCode::unknown_protocol_path_id
            );
        }

        {
            auto wrong_schema_bytes = base_bytes;
            write_le16_at(wrong_schema_bytes, sections[1].offset + 4U, 99U);
            expect_fast_tier_status(
                std::move(wrong_schema_bytes),
                detail::CaptureIndexV16FastStatisticsTierReadStatus::unsupported_fast_section_schema
            );
        }

        {
            auto inconsistent_tier = tier;
            inconsistent_tier.capture_statistics_snapshot.top_flows[0].protocol_path_id = 99U;
            std::get<ConnectionKeyV4>(
                inconsistent_tier.capture_statistics_snapshot.top_flows[0].connection_key
            ).protocol_path_id = 99U;
            PFL_REQUIRE(validate_capture_statistics_snapshot(
                inconsistent_tier.capture_statistics_snapshot
            ).ok);

            std::ostringstream inconsistent_stream(std::ios::binary | std::ios::out);
            PFL_REQUIRE(detail::write_capture_index_stable_header(
                inconsistent_stream,
                make_v16_stable_header()
            ));
            PFL_REQUIRE(detail::write_v16_capture_statistics_snapshot_section(
                inconsistent_stream,
                inconsistent_tier.capture_statistics_snapshot
            ));
            PFL_REQUIRE(detail::write_v16_protocol_path_registry_early_section(
                inconsistent_stream,
                inconsistent_tier.protocol_path_registry
            ));
            PFL_REQUIRE(detail::write_v16_protocol_path_terminal_aggregates_section(
                inconsistent_stream,
                inconsistent_tier.protocol_path_display_statistics
            ));
            expect_fast_tier_status(
                stream_bytes(inconsistent_stream),
                detail::CaptureIndexV16FastStatisticsTierReadStatus::fast_tier_cross_section_inconsistency
            );
        }
    }

    const auto forward_packet = make_ethernet_ipv4_tcp_packet(ipv4(192, 168, 10, 1), ipv4(192, 168, 10, 2), 41000, 443);
    const auto reverse_packet = make_ethernet_ipv4_udp_packet(ipv4(192, 168, 10, 2), ipv4(192, 168, 10, 1), 53, 53000);
    const auto source_path = write_temp_pcap(
        "pfl_index_format_source.pcap",
        make_classic_pcap({{100, forward_packet}, {200, reverse_packet}})
    );

    CaptureImporter importer {};
    CaptureState state {};
    PFL_EXPECT(importer.import_capture(source_path, state));
    const auto gre_key_path_id = state.protocol_path_registry.intern(ProtocolPath {
        LayerKey::ethernet_ii(),
        LayerKey::ipv4(),
        LayerKey::gre(0x11111111U),
        LayerKey::ipv4(),
        LayerKey::udp(),
    });
    const auto esp_path_id = state.protocol_path_registry.intern(ProtocolPath {
        LayerKey::ethernet_ii(),
        LayerKey::ipv4(),
        LayerKey::esp(0x01020304U),
    });
    const auto ah_path_id = state.protocol_path_registry.intern(ProtocolPath {
        LayerKey::ethernet_ii(),
        LayerKey::ipv4(),
        LayerKey::ah(0x01020304U),
        LayerKey::tcp(),
    });
    PFL_REQUIRE(gre_key_path_id != kInvalidProtocolPathId);
    PFL_REQUIRE(esp_path_id != kInvalidProtocolPathId);
    PFL_REQUIRE(ah_path_id != kInvalidProtocolPathId);

    const auto index_path = std::filesystem::temp_directory_path() / "pfl_sectioned_index.idx";
    std::filesystem::remove(index_path);

    CaptureIndexWriter index_writer {};
    PFL_EXPECT(index_writer.write(index_path, state, source_path));

    CaptureIndexReader index_reader {};
    CaptureState loaded_state {};
    std::filesystem::path loaded_capture_path {};
    CaptureSourceInfo loaded_source_info {};
    PFL_EXPECT(index_reader.read(index_path, loaded_state, loaded_capture_path, &loaded_source_info));
    PFL_EXPECT(loaded_capture_path == source_path);
    PFL_EXPECT(loaded_source_info.capture_path == source_path);
    expect_matching_states(state, loaded_state);
    const auto* loaded_gre_key_path = loaded_state.protocol_path_registry.find(gre_key_path_id);
    const auto* loaded_esp_path = loaded_state.protocol_path_registry.find(esp_path_id);
    const auto* loaded_ah_path = loaded_state.protocol_path_registry.find(ah_path_id);
    PFL_REQUIRE(loaded_gre_key_path != nullptr);
    PFL_REQUIRE(loaded_esp_path != nullptr);
    PFL_REQUIRE(loaded_ah_path != nullptr);
    PFL_EXPECT(format_protocol_path(*loaded_gre_key_path) == "EthernetII -> IPv4 -> GRE(key=0x11111111) -> IPv4 -> UDP");
    PFL_EXPECT(format_protocol_path(*loaded_esp_path) == "EthernetII -> IPv4 -> ESP(spi=0x01020304)");
    PFL_EXPECT(format_protocol_path(*loaded_ah_path) == "EthernetII -> IPv4 -> AH(spi=0x01020304) -> TCP");

    CaptureIndexInspection inspection {};
    PFL_EXPECT(index_reader.inspect(index_path, inspection));
    PFL_EXPECT(inspection.format_family == CaptureIndexFormatFamily::stable);
    PFL_EXPECT(inspection.magic == kStableCaptureIndexMagic);
    PFL_EXPECT(inspection.stable_container_format_version == kCaptureIndexStableContainerFormatVersion);
    PFL_EXPECT(inspection.stable_index_revision == kCaptureIndexVersion);
    PFL_EXPECT(inspection.source_info.capture_path == source_path);
    PFL_EXPECT(!inspection.sections.empty());
    for (const auto& section : inspection.sections) {
        PFL_EXPECT(section.section_schema_version == expected_section_schema_version(section.section_id));
        PFL_EXPECT((section.section_flags & detail::kCaptureIndexStableSectionFlagRequired) != 0U);
    }

    auto future_revision_bytes = read_file_bytes(index_path);
    write_le32_at(future_revision_bytes, 16U, kCaptureIndexVersion + 1U);
    const auto future_revision_index_path = write_temp_binary_file(
        "pfl_index_future_stable_revision.idx",
        future_revision_bytes
    );
    PFL_EXPECT(index_reader.read(future_revision_index_path, loaded_state, loaded_capture_path, &loaded_source_info));
    PFL_EXPECT(loaded_capture_path == source_path);
    expect_matching_states(state, loaded_state);

    const auto unicode_source_path =
        std::filesystem::temp_directory_path() /
        detail::filesystem_path_from_generic_utf8(
            "pfl_index_utf8/\xD1\x82\xD0\xB5\xD1\x81\xD1\x82/\xE4\xBE\x8B/pcap_flow_lab_showcase.pcap"
        );
    std::filesystem::create_directories(unicode_source_path.parent_path());
    std::filesystem::copy_file(source_path, unicode_source_path, std::filesystem::copy_options::overwrite_existing);

    const auto unicode_index_path = std::filesystem::temp_directory_path() / "pfl_sectioned_index_utf8.idx";
    std::filesystem::remove(unicode_index_path);
    PFL_EXPECT(index_writer.write(unicode_index_path, state, unicode_source_path));

    auto unicode_index_bytes = read_file_bytes(unicode_index_path);
    detail::CaptureIndexStableHeader unicode_header {};
    std::istringstream unicode_header_stream(
        std::string(unicode_index_bytes.begin(), unicode_index_bytes.end()),
        std::ios::binary | std::ios::in
    );
    PFL_REQUIRE(detail::read_capture_index_stable_header(unicode_header_stream, unicode_header));
    PFL_EXPECT(
        unicode_header.source_capture_path_utf8 ==
        detail::filesystem_path_to_generic_utf8(unicode_source_path)
    );

    CaptureState unicode_loaded_state {};
    std::filesystem::path unicode_loaded_capture_path {};
    CaptureSourceInfo unicode_loaded_source_info {};
    PFL_EXPECT(index_reader.read(
        unicode_index_path,
        unicode_loaded_state,
        unicode_loaded_capture_path,
        &unicode_loaded_source_info
    ));
    PFL_EXPECT(
        detail::filesystem_path_to_generic_utf8(unicode_loaded_capture_path) ==
        detail::filesystem_path_to_generic_utf8(unicode_source_path)
    );
    PFL_EXPECT(
        detail::filesystem_path_to_generic_utf8(unicode_loaded_source_info.capture_path) ==
        detail::filesystem_path_to_generic_utf8(unicode_source_path)
    );

    CaptureIndexInspection unicode_inspection {};
    PFL_EXPECT(index_reader.inspect(unicode_index_path, unicode_inspection));
    PFL_EXPECT(
        detail::filesystem_path_to_generic_utf8(unicode_inspection.source_info.capture_path) ==
        detail::filesystem_path_to_generic_utf8(unicode_source_path)
    );

    {
        auto legacy_packet_ref_schema_bytes = read_file_bytes(index_path);
        const auto sections = parse_sections(legacy_packet_ref_schema_bytes);
        const auto ipv4_section = std::find_if(sections.begin(), sections.end(), [](const SectionInfo& section) {
            return section.id == static_cast<std::uint32_t>(detail::CaptureIndexSectionId::ipv4_connections);
        });
        PFL_REQUIRE(ipv4_section != sections.end());
        write_le16_at(legacy_packet_ref_schema_bytes, ipv4_section->offset + 4U, 1U);

        const auto legacy_packet_ref_schema_path = write_temp_binary_file(
            "pfl_index_legacy_packet_ref_schema.idx",
            legacy_packet_ref_schema_bytes
        );
        PFL_EXPECT(!index_reader.read(
            legacy_packet_ref_schema_path,
            loaded_state,
            loaded_capture_path,
            &loaded_source_info
        ));
        PFL_EXPECT(
            index_reader.last_error().reason ==
            "stable index uses legacy packet-ref storage for packet metadata; rebuild the index from the source capture"
        );
    }

    {
        const auto chunked_ipv4_source_path = write_temp_pcap(
            "pfl_index_chunked_ipv4_source.pcap",
            make_classic_pcap({
                {100, make_ethernet_ipv4_tcp_packet(ipv4(10, 0, 0, 1), ipv4(10, 0, 0, 2), 41000, 443)},
                {200, make_ethernet_ipv4_tcp_packet(ipv4(10, 0, 0, 3), ipv4(10, 0, 0, 4), 41001, 443)},
                {300, make_ethernet_ipv4_tcp_packet(ipv4(10, 0, 0, 5), ipv4(10, 0, 0, 6), 41002, 443)},
                {400, make_ethernet_ipv4_tcp_packet(ipv4(10, 0, 0, 7), ipv4(10, 0, 0, 8), 41003, 443)},
            })
        );

        CaptureState chunked_ipv4_state {};
        PFL_EXPECT(importer.import_capture(chunked_ipv4_source_path, chunked_ipv4_state));

        const auto chunked_ipv4_index_path = std::filesystem::temp_directory_path() / "pfl_chunked_ipv4_sections.idx";
        std::filesystem::remove(chunked_ipv4_index_path);

        CaptureIndexWriter chunked_writer {};
        PFL_EXPECT(chunked_writer.write(
            chunked_ipv4_index_path,
            chunked_ipv4_state,
            chunked_ipv4_source_path,
            CaptureIndexWriteOptions {.max_connection_section_payload_bytes = 256U},
            nullptr
        ));

        const auto chunked_ipv4_index_bytes = read_file_bytes(chunked_ipv4_index_path);
        PFL_EXPECT(count_sections(
            chunked_ipv4_index_bytes,
            static_cast<std::uint32_t>(detail::CaptureIndexSectionId::ipv4_connections)
        ) > 1U);

        CaptureState loaded_chunked_ipv4_state {};
        std::filesystem::path loaded_chunked_ipv4_capture_path {};
        CaptureSourceInfo loaded_chunked_ipv4_source_info {};
        PFL_EXPECT(index_reader.read(
            chunked_ipv4_index_path,
            loaded_chunked_ipv4_state,
            loaded_chunked_ipv4_capture_path,
            &loaded_chunked_ipv4_source_info
        ));
        PFL_EXPECT(loaded_chunked_ipv4_capture_path == chunked_ipv4_source_path);
        PFL_EXPECT(loaded_chunked_ipv4_source_info.capture_path == chunked_ipv4_source_path);
        expect_matching_states(chunked_ipv4_state, loaded_chunked_ipv4_state);

        auto truncated_chunked_ipv4_bytes = chunked_ipv4_index_bytes;
        PFL_REQUIRE(!truncated_chunked_ipv4_bytes.empty());
        truncated_chunked_ipv4_bytes.pop_back();
        const auto truncated_chunked_ipv4_index_path = write_temp_binary_file(
            "pfl_chunked_ipv4_sections_truncated.idx",
            truncated_chunked_ipv4_bytes
        );
        PFL_EXPECT(!index_reader.read(
            truncated_chunked_ipv4_index_path,
            loaded_chunked_ipv4_state,
            loaded_chunked_ipv4_capture_path,
            &loaded_chunked_ipv4_source_info
        ));
        PFL_EXPECT(index_reader.last_error().reason == "index file is incomplete or was not finalized");
    }

    {
        const auto chunked_ipv6_source_path = write_temp_pcap(
            "pfl_index_chunked_ipv6_source.pcap",
            make_classic_pcap({
                {100, make_ethernet_ipv6_packet(
                    ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}),
                    ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}),
                    6U,
                    make_ipv6_tcp_segment_for_index_test(51000, 443)
                )},
                {200, make_ethernet_ipv6_packet(
                    ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3}),
                    ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4}),
                    6U,
                    make_ipv6_tcp_segment_for_index_test(51001, 443)
                )},
                {300, make_ethernet_ipv6_packet(
                    ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5}),
                    ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6}),
                    6U,
                    make_ipv6_tcp_segment_for_index_test(51002, 443)
                )},
                {400, make_ethernet_ipv6_packet(
                    ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7}),
                    ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8}),
                    6U,
                    make_ipv6_tcp_segment_for_index_test(51003, 443)
                )},
            })
        );

        CaptureState chunked_ipv6_state {};
        PFL_EXPECT(importer.import_capture(chunked_ipv6_source_path, chunked_ipv6_state));

        const auto chunked_ipv6_index_path = std::filesystem::temp_directory_path() / "pfl_chunked_ipv6_sections.idx";
        std::filesystem::remove(chunked_ipv6_index_path);

        CaptureIndexWriter chunked_writer {};
        PFL_EXPECT(chunked_writer.write(
            chunked_ipv6_index_path,
            chunked_ipv6_state,
            chunked_ipv6_source_path,
            CaptureIndexWriteOptions {.max_connection_section_payload_bytes = 256U},
            nullptr
        ));

        const auto chunked_ipv6_index_bytes = read_file_bytes(chunked_ipv6_index_path);
        PFL_EXPECT(count_sections(
            chunked_ipv6_index_bytes,
            static_cast<std::uint32_t>(detail::CaptureIndexSectionId::ipv6_connections)
        ) > 1U);

        CaptureState loaded_chunked_ipv6_state {};
        std::filesystem::path loaded_chunked_ipv6_capture_path {};
        CaptureSourceInfo loaded_chunked_ipv6_source_info {};
        PFL_EXPECT(index_reader.read(
            chunked_ipv6_index_path,
            loaded_chunked_ipv6_state,
            loaded_chunked_ipv6_capture_path,
            &loaded_chunked_ipv6_source_info
        ));
        PFL_EXPECT(loaded_chunked_ipv6_capture_path == chunked_ipv6_source_path);
        PFL_EXPECT(loaded_chunked_ipv6_source_info.capture_path == chunked_ipv6_source_path);
        expect_matching_states(chunked_ipv6_state, loaded_chunked_ipv6_state);
    }

    {
        const auto oversized_single_connection_source_path = write_temp_pcap(
            "pfl_index_oversized_single_connection_source.pcap",
            make_classic_pcap({
                {100, make_ethernet_ipv4_tcp_packet(ipv4(10, 1, 0, 1), ipv4(10, 1, 0, 2), 42000, 443)},
                {200, make_ethernet_ipv4_tcp_packet(ipv4(10, 1, 0, 1), ipv4(10, 1, 0, 2), 42000, 443)},
                {300, make_ethernet_ipv4_tcp_packet(ipv4(10, 1, 0, 2), ipv4(10, 1, 0, 1), 443, 42000)},
            })
        );

        CaptureState oversized_single_connection_state {};
        PFL_EXPECT(importer.import_capture(oversized_single_connection_source_path, oversized_single_connection_state));

        const auto oversized_single_connection_index_path =
            std::filesystem::temp_directory_path() / "pfl_oversized_single_connection.idx";
        std::filesystem::remove(oversized_single_connection_index_path);

        CaptureIndexWriter oversized_single_connection_writer {};
        PFL_EXPECT(oversized_single_connection_writer.write(
            oversized_single_connection_index_path,
            oversized_single_connection_state,
            oversized_single_connection_source_path,
            CaptureIndexWriteOptions {.max_connection_section_payload_bytes = 16U},
            nullptr
        ));

        const auto oversized_single_connection_index_bytes = read_file_bytes(oversized_single_connection_index_path);
        PFL_EXPECT(count_sections(
            oversized_single_connection_index_bytes,
            static_cast<std::uint32_t>(detail::CaptureIndexSectionId::ipv4_connections)
        ) == 1U);

        CaptureState loaded_oversized_single_connection_state {};
        std::filesystem::path loaded_oversized_single_connection_capture_path {};
        CaptureSourceInfo loaded_oversized_single_connection_source_info {};
        PFL_EXPECT(index_reader.read(
            oversized_single_connection_index_path,
            loaded_oversized_single_connection_state,
            loaded_oversized_single_connection_capture_path,
            &loaded_oversized_single_connection_source_info
        ));
        PFL_EXPECT(loaded_oversized_single_connection_capture_path == oversized_single_connection_source_path);
        PFL_EXPECT(loaded_oversized_single_connection_source_info.capture_path == oversized_single_connection_source_path);
        expect_matching_states(oversized_single_connection_state, loaded_oversized_single_connection_state);
    }

    const auto index_bytes = read_file_bytes(index_path);
    auto legacy_version_bytes = index_bytes;
    write_le64_at(legacy_version_bytes, 0U, kLegacyCaptureIndexMagic);
    write_le16_at(legacy_version_bytes, 8U, kLegacyCaptureIndexVersion);
    write_le16_at(legacy_version_bytes, 10U, 0U);
    const auto legacy_version_index_path = write_temp_binary_file(
        "pfl_index_legacy_version.idx",
        legacy_version_bytes
    );
    PFL_EXPECT(!index_reader.read(legacy_version_index_path, loaded_state, loaded_capture_path, &loaded_source_info));
    PFL_EXPECT(index_reader.last_error().reason == "legacy index version 14 is no longer loadable; rebuild the index from the source capture");
    CaptureIndexInspection legacy_inspection {};
    PFL_EXPECT(index_reader.inspect(legacy_version_index_path, legacy_inspection));
    PFL_EXPECT(legacy_inspection.format_family == CaptureIndexFormatFamily::legacy);
    PFL_EXPECT(legacy_inspection.magic == kLegacyCaptureIndexMagic);
    PFL_EXPECT(legacy_inspection.legacy_version == kLegacyCaptureIndexVersion);

    {
        auto invalid_locator_state = state;
        invalid_locator_state.packet_locator = {
            CapturePacketLocatorEntry {.packet_index = 0U, .file_offset = 24U},
            CapturePacketLocatorEntry {.packet_index = 1U, .file_offset = 16U},
        };

        const auto invalid_locator_index_path =
            std::filesystem::temp_directory_path() / "pfl_index_invalid_packet_locator.idx";
        std::filesystem::remove(invalid_locator_index_path);

        CaptureIndexWriter invalid_locator_writer {};
        PFL_REQUIRE(invalid_locator_writer.write(invalid_locator_index_path, invalid_locator_state, source_path));
        PFL_EXPECT(!index_reader.read(
            invalid_locator_index_path,
            loaded_state,
            loaded_capture_path,
            &loaded_source_info
        ));
        PFL_EXPECT(index_reader.last_error().reason == "invalid packet-locator section");
    }

    {
        auto invalid_locator_state = state;
        invalid_locator_state.packet_locator = {
            CapturePacketLocatorEntry {.packet_index = 0U, .file_offset = 24U},
            CapturePacketLocatorEntry {.packet_index = 1U, .file_offset = 24U},
        };

        const auto invalid_locator_index_path =
            std::filesystem::temp_directory_path() / "pfl_index_invalid_packet_locator_equal_offset.idx";
        std::filesystem::remove(invalid_locator_index_path);

        CaptureIndexWriter invalid_locator_writer {};
        PFL_REQUIRE(invalid_locator_writer.write(invalid_locator_index_path, invalid_locator_state, source_path));
        PFL_EXPECT(!index_reader.read(
            invalid_locator_index_path,
            loaded_state,
            loaded_capture_path,
            &loaded_source_info
        ));
        PFL_EXPECT(index_reader.last_error().reason == "invalid packet-locator section");
    }

    const auto malformed_index_path = write_temp_binary_file(
        "pfl_index_section_size_invalid.idx",
        corrupt_first_section_size(index_bytes)
    );
    PFL_EXPECT(!index_reader.read(malformed_index_path, loaded_state, loaded_capture_path, &loaded_source_info));

    auto truncated_tail_bytes = index_bytes;
    PFL_REQUIRE(!truncated_tail_bytes.empty());
    truncated_tail_bytes.pop_back();
    const auto truncated_tail_index_path = write_temp_binary_file(
        "pfl_index_truncated_tail.idx",
        truncated_tail_bytes
    );
    PFL_EXPECT(!index_reader.read(truncated_tail_index_path, loaded_state, loaded_capture_path, &loaded_source_info));
    PFL_EXPECT(index_reader.last_error().reason == "index file is incomplete or was not finalized");

    const auto missing_index_path = write_temp_binary_file(
        "pfl_index_missing_summary.idx",
        remove_section(index_bytes, static_cast<std::uint32_t>(detail::CaptureIndexSectionId::summary))
    );
    PFL_EXPECT(!index_reader.read(missing_index_path, loaded_state, loaded_capture_path, &loaded_source_info));

    const auto missing_protocol_paths_index_path = write_temp_binary_file(
        "pfl_index_missing_protocol_paths.idx",
        remove_section(index_bytes, static_cast<std::uint32_t>(detail::CaptureIndexSectionId::protocol_paths))
    );
    PFL_EXPECT(!index_reader.read(
        missing_protocol_paths_index_path, loaded_state, loaded_capture_path, &loaded_source_info));

    const auto missing_unrecognized_packets_index_path = write_temp_binary_file(
        "pfl_index_missing_unrecognized_packets.idx",
        remove_section(index_bytes, static_cast<std::uint32_t>(detail::CaptureIndexSectionId::unrecognized_packets))
    );
    PFL_EXPECT(!index_reader.read(
        missing_unrecognized_packets_index_path, loaded_state, loaded_capture_path, &loaded_source_info));

    const auto duplicate_index_path = write_temp_binary_file(
        "pfl_index_duplicate_summary.idx",
        duplicate_section(index_bytes, static_cast<std::uint32_t>(detail::CaptureIndexSectionId::summary))
    );
    PFL_EXPECT(!index_reader.read(duplicate_index_path, loaded_state, loaded_capture_path, &loaded_source_info));

    const auto duplicate_protocol_paths_index_path = write_temp_binary_file(
        "pfl_index_duplicate_protocol_paths.idx",
        duplicate_section(index_bytes, static_cast<std::uint32_t>(detail::CaptureIndexSectionId::protocol_paths))
    );
    PFL_EXPECT(!index_reader.read(
        duplicate_protocol_paths_index_path, loaded_state, loaded_capture_path, &loaded_source_info));

    const auto trailing_index_path = write_temp_binary_file(
        "pfl_index_trailing_garbage.idx",
        append_trailing_garbage(index_bytes)
    );
    PFL_EXPECT(!index_reader.read(trailing_index_path, loaded_state, loaded_capture_path, &loaded_source_info));

}

}  // namespace pfl::tests

