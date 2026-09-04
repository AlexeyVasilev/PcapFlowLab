#include <algorithm>
#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <limits>
#include <sstream>
#include <string>
#include <utility>
#include <variant>
#include <vector>

#include "TestSupport.h"
#include "PcapTestUtils.h"
#include "app/session/CaptureSession.h"
#include "app/session/PacketLocatorAccess.h"
#include "app/session/SessionFlowHelpers.h"
#include "app/session/UnrecognizedPacketAccess.h"
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

class ForbiddenRangeCountingStreamBuf final : public std::stringbuf {
public:
    struct Range {
        std::size_t begin {0};
        std::size_t end {0};
    };

    ForbiddenRangeCountingStreamBuf(
        const std::vector<std::uint8_t>& bytes,
        std::vector<Range> forbidden_ranges
    )
        : std::stringbuf(std::string(bytes.begin(), bytes.end()), std::ios::binary | std::ios::in),
          forbidden_ranges_(std::move(forbidden_ranges)) {}

    [[nodiscard]] std::uint64_t forbidden_bytes_read() const noexcept {
        return forbidden_bytes_read_;
    }

protected:
    std::streamsize xsgetn(char* destination, const std::streamsize count) override {
        const auto start = gptr() != nullptr
            ? static_cast<std::size_t>(gptr() - eback())
            : 0U;
        const auto read_count = std::stringbuf::xsgetn(destination, count);
        if (read_count <= 0) {
            return read_count;
        }

        const auto end = start + static_cast<std::size_t>(read_count);
        for (const auto& range : forbidden_ranges_) {
            const auto overlap_begin = std::max(start, range.begin);
            const auto overlap_end = std::min(end, range.end);
            if (overlap_begin < overlap_end) {
                forbidden_bytes_read_ += static_cast<std::uint64_t>(overlap_end - overlap_begin);
            }
        }
        return read_count;
    }

private:
    std::vector<Range> forbidden_ranges_ {};
    std::uint64_t forbidden_bytes_read_ {0};
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

PacketRef packet_ref_for_v16_metadata_test(
    const std::uint64_t packet_index,
    const std::uint32_t original_length,
    const std::uint32_t captured_length,
    const std::uint64_t byte_offset
) {
    return PacketRef {
        .packet_index = packet_index,
        .ts_sec = static_cast<std::uint32_t>(packet_index / 10U),
        .ts_usec = static_cast<std::uint32_t>((packet_index % 10U) * 1000U),
        .byte_offset = byte_offset,
        .data_link_type = kLinkTypeEthernet,
        .captured_length = captured_length,
        .original_length = original_length,
    };
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

const SectionInfo* find_section_occurrence(
    const std::vector<SectionInfo>& sections,
    const std::uint32_t section_id,
    const std::size_t occurrence_index
) {
    std::size_t matched_index {0U};
    for (const auto& section : sections) {
        if (section.id != section_id) {
            continue;
        }

        if (matched_index == occurrence_index) {
            return &section;
        }
        ++matched_index;
    }

    return nullptr;
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

std::vector<std::uint8_t> replace_section_payload(
    const std::vector<std::uint8_t>& bytes,
    const std::uint32_t section_id,
    const std::size_t occurrence_index,
    const std::uint64_t payload_size
) {
    const auto sections = parse_sections(bytes);
    const auto* section = find_section_occurrence(sections, section_id, occurrence_index);
    PFL_REQUIRE(section != nullptr);
    PFL_REQUIRE(payload_size <= static_cast<std::uint64_t>((std::numeric_limits<std::size_t>::max)()));

    auto mutated = bytes;
    const auto payload_begin = section->offset + detail::kCaptureIndexStableSectionHeaderEncodedSize;
    const auto payload_end = section->offset + section->total_size;
    write_le64_at(mutated, section->offset + 8U, payload_size);
    mutated.erase(
        mutated.begin() + static_cast<std::ptrdiff_t>(payload_begin),
        mutated.begin() + static_cast<std::ptrdiff_t>(payload_end)
    );
    mutated.insert(
        mutated.begin() + static_cast<std::ptrdiff_t>(payload_begin),
        static_cast<std::size_t>(payload_size),
        0xA5U
    );
    return mutated;
}

std::vector<ForbiddenRangeCountingStreamBuf::Range> section_payload_ranges(
    const std::vector<std::uint8_t>& bytes,
    const std::vector<std::uint32_t>& section_ids
) {
    const auto sections = parse_sections(bytes);
    std::vector<ForbiddenRangeCountingStreamBuf::Range> ranges {};
    for (const auto& section : sections) {
        if (std::find(section_ids.begin(), section_ids.end(), section.id) == section_ids.end()) {
            continue;
        }

        const auto payload_begin = section.offset + detail::kCaptureIndexStableSectionHeaderEncodedSize;
        const auto payload_end = section.offset + section.total_size;
        if (payload_begin < payload_end) {
            ranges.push_back(ForbiddenRangeCountingStreamBuf::Range {
                .begin = payload_begin,
                .end = payload_end,
            });
        }
    }
    return ranges;
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
    case detail::CaptureIndexSectionId::ipv4_flow_metadata:
        return detail::kCaptureIndexStableIpv4FlowMetadataSectionSchemaVersion;
    case detail::CaptureIndexSectionId::ipv6_flow_metadata:
        return detail::kCaptureIndexStableIpv6FlowMetadataSectionSchemaVersion;
    case detail::CaptureIndexSectionId::protocol_path_membership:
        return detail::kCaptureIndexStableProtocolPathMembershipSectionSchemaVersion;
    case detail::CaptureIndexSectionId::packetref_directory:
        return detail::kCaptureIndexStablePacketRefDirectorySectionSchemaVersion;
    case detail::CaptureIndexSectionId::unrecognized_directory:
        return detail::kCaptureIndexStableUnrecognizedDirectorySectionSchemaVersion;
    case detail::CaptureIndexSectionId::packetref_detail_blocks:
        return detail::kCaptureIndexStablePacketRefDetailBlocksSectionSchemaVersion;
    case detail::CaptureIndexSectionId::unrecognized_reason_blobs:
        return detail::kCaptureIndexStableUnrecognizedReasonBlobsSectionSchemaVersion;
    case detail::CaptureIndexSectionId::packet_locator_v16:
        return detail::kCaptureIndexStablePacketLocatorV16SectionSchemaVersion;
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

void expect_v16_top_flow_ordinals_match_canonical_connections(
    const CaptureStatisticsSnapshot& snapshot,
    const std::vector<session_detail::ListedConnectionRef>& connections
) {
    for (const auto& row : snapshot.top_flows) {
        PFL_REQUIRE(row.canonical_flow_ordinal < connections.size());
        const auto& connection = connections[row.canonical_flow_ordinal];
        if (row.family == CaptureStatisticsAddressFamily::ipv4) {
            PFL_REQUIRE(connection.family == FlowAddressFamily::ipv4);
            PFL_REQUIRE(connection.ipv4 != nullptr);
            PFL_REQUIRE(std::holds_alternative<ConnectionKeyV4>(row.connection_key));
            PFL_EXPECT(std::get<ConnectionKeyV4>(row.connection_key) == connection.ipv4->key);
            continue;
        }

        PFL_REQUIRE(connection.family == FlowAddressFamily::ipv6);
        PFL_REQUIRE(connection.ipv6 != nullptr);
        PFL_REQUIRE(std::holds_alternative<ConnectionKeyV6>(row.connection_key));
        PFL_EXPECT(std::get<ConnectionKeyV6>(row.connection_key) == connection.ipv6->key);
    }
}

void expect_v16_metadata_rows_match_canonical_connections(
    const CaptureIndexV16MetadataTier& metadata,
    const std::vector<session_detail::ListedConnectionRef>& connections
) {
    for (const auto& row : metadata.ipv4_connections) {
        PFL_REQUIRE(row.canonical_connection_ordinal < connections.size());
        const auto& connection = connections[row.canonical_connection_ordinal];
        PFL_REQUIRE(connection.family == FlowAddressFamily::ipv4);
        PFL_REQUIRE(connection.ipv4 != nullptr);
        PFL_EXPECT(row.key == connection.ipv4->key);
    }

    for (const auto& row : metadata.ipv6_connections) {
        PFL_REQUIRE(row.canonical_connection_ordinal < connections.size());
        const auto& connection = connections[row.canonical_connection_ordinal];
        PFL_REQUIRE(connection.family == FlowAddressFamily::ipv6);
        PFL_REQUIRE(connection.ipv6 != nullptr);
        PFL_EXPECT(row.key == connection.ipv6->key);
    }
}

void expect_v16_metadata_matches_plan(
    const CaptureIndexV16MetadataTier& actual,
    const CaptureIndexV16WritePlan& expected_plan,
    const std::vector<std::uint8_t>& container_bytes
) {
    PFL_EXPECT(actual.ipv4_connections == expected_plan.metadata.ipv4_connections);
    PFL_EXPECT(actual.ipv6_connections == expected_plan.metadata.ipv6_connections);
    PFL_EXPECT(actual.protocol_path_membership == expected_plan.metadata.protocol_path_membership);
    PFL_EXPECT(actual.packetref_directory == expected_plan.metadata.packetref_directory);
    PFL_EXPECT(actual.packetref_detail_sections.size() == expected_plan.packetref_detail_sections.size());
    PFL_EXPECT(
        actual.unrecognized_directory_sections.size() ==
        expected_plan.metadata.unrecognized_directory_sections.size());
    PFL_EXPECT(
        actual.unrecognized_reason_sections.size() ==
        expected_plan.metadata.unrecognized_reason_sections.size());
    PFL_EXPECT(
        actual.packet_locator_sections.size() ==
        expected_plan.metadata.packet_locator_sections.size());

    const auto sections = parse_sections(container_bytes);
    for (std::size_t index = 0U; index < actual.packetref_detail_sections.size(); ++index) {
        const auto* detail_section = find_section_occurrence(
            sections,
            static_cast<std::uint32_t>(detail::CaptureIndexSectionId::packetref_detail_blocks),
            index
        );
        PFL_REQUIRE(detail_section != nullptr);
        PFL_EXPECT(actual.packetref_detail_sections[index].section_occurrence_index == index);
        PFL_EXPECT(
            actual.packetref_detail_sections[index].section_occurrence_index ==
            expected_plan.packetref_detail_sections[index].section_occurrence_index);
        PFL_EXPECT(
            actual.packetref_detail_sections[index].payload_size ==
            expected_plan.packetref_detail_sections[index].payload_size);
        PFL_EXPECT(
            actual.packetref_detail_sections[index].payload_file_offset ==
            static_cast<std::uint64_t>(
                detail_section->offset + detail::kCaptureIndexStableSectionHeaderEncodedSize));
    }

    for (std::size_t index = 0U; index < actual.unrecognized_directory_sections.size(); ++index) {
        const auto* directory_section = find_section_occurrence(
            sections,
            static_cast<std::uint32_t>(detail::CaptureIndexSectionId::unrecognized_directory),
            index
        );
        PFL_REQUIRE(directory_section != nullptr);
        PFL_EXPECT(actual.unrecognized_directory_sections[index].section_occurrence_index == index);
        PFL_EXPECT(
            actual.unrecognized_directory_sections[index].section_occurrence_index ==
            expected_plan.metadata.unrecognized_directory_sections[index].section_occurrence_index);
        PFL_EXPECT(
            actual.unrecognized_directory_sections[index].payload_size ==
            expected_plan.metadata.unrecognized_directory_sections[index].payload_size);
        PFL_EXPECT(
            actual.unrecognized_directory_sections[index].logical_row_start ==
            expected_plan.metadata.unrecognized_directory_sections[index].logical_row_start);
        PFL_EXPECT(
            actual.unrecognized_directory_sections[index].row_count ==
            expected_plan.metadata.unrecognized_directory_sections[index].row_count);
        PFL_EXPECT(
            actual.unrecognized_directory_sections[index].payload_file_offset ==
            static_cast<std::uint64_t>(
                directory_section->offset + detail::kCaptureIndexStableSectionHeaderEncodedSize));
    }

    for (std::size_t index = 0U; index < actual.unrecognized_reason_sections.size(); ++index) {
        const auto* reason_section = find_section_occurrence(
            sections,
            static_cast<std::uint32_t>(detail::CaptureIndexSectionId::unrecognized_reason_blobs),
            index
        );
        PFL_REQUIRE(reason_section != nullptr);
        PFL_EXPECT(actual.unrecognized_reason_sections[index].section_occurrence_index == index);
        PFL_EXPECT(
            actual.unrecognized_reason_sections[index].section_occurrence_index ==
            expected_plan.metadata.unrecognized_reason_sections[index].section_occurrence_index);
        PFL_EXPECT(
            actual.unrecognized_reason_sections[index].payload_size ==
            expected_plan.metadata.unrecognized_reason_sections[index].payload_size);
        PFL_EXPECT(
            actual.unrecognized_reason_sections[index].payload_file_offset ==
            static_cast<std::uint64_t>(
                reason_section->offset + detail::kCaptureIndexStableSectionHeaderEncodedSize));
    }

    for (std::size_t index = 0U; index < actual.packet_locator_sections.size(); ++index) {
        const auto* locator_section = find_section_occurrence(
            sections,
            static_cast<std::uint32_t>(detail::CaptureIndexSectionId::packet_locator_v16),
            index
        );
        PFL_REQUIRE(locator_section != nullptr);
        PFL_EXPECT(actual.packet_locator_sections[index].section_occurrence_index == index);
        PFL_EXPECT(
            actual.packet_locator_sections[index].section_occurrence_index ==
            expected_plan.metadata.packet_locator_sections[index].section_occurrence_index);
        PFL_EXPECT(
            actual.packet_locator_sections[index].payload_size ==
            expected_plan.metadata.packet_locator_sections[index].payload_size);
        PFL_EXPECT(
            actual.packet_locator_sections[index].logical_entry_start ==
            expected_plan.metadata.packet_locator_sections[index].logical_entry_start);
        PFL_EXPECT(
            actual.packet_locator_sections[index].entry_count ==
            expected_plan.metadata.packet_locator_sections[index].entry_count);
        PFL_EXPECT(
            actual.packet_locator_sections[index].first_packet_index ==
            expected_plan.metadata.packet_locator_sections[index].first_packet_index);
        PFL_EXPECT(
            actual.packet_locator_sections[index].last_packet_index ==
            expected_plan.metadata.packet_locator_sections[index].last_packet_index);
        PFL_EXPECT(
            actual.packet_locator_sections[index].first_file_offset ==
            expected_plan.metadata.packet_locator_sections[index].first_file_offset);
        PFL_EXPECT(
            actual.packet_locator_sections[index].last_file_offset ==
            expected_plan.metadata.packet_locator_sections[index].last_file_offset);
        PFL_EXPECT(
            actual.packet_locator_sections[index].payload_file_offset ==
            static_cast<std::uint64_t>(
                locator_section->offset + detail::kCaptureIndexStableSectionHeaderEncodedSize));
    }
}

void expect_matching_locator_entry(
    const CapturePacketLocatorEntry& actual,
    const CapturePacketLocatorEntry& expected
) {
    PFL_EXPECT(actual.packet_index == expected.packet_index);
    PFL_EXPECT(actual.file_offset == expected.file_offset);
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
            .canonical_flow_ordinal = 2U,
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
    header.index_revision = kCaptureIndexStableIndexRevision;
    return header;
}

std::vector<std::uint8_t> make_v16_snapshot_container_bytes(
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

CaptureState make_v16_metadata_capture_state_fixture() {
    CaptureState state {};
    const auto ipv4_path_id = state.protocol_path_registry.intern(ProtocolPath {
        LayerKey::ethernet_ii(),
        LayerKey::ipv4(),
        LayerKey::tcp(),
    });
    const auto ipv6_path_id = state.protocol_path_registry.intern(ProtocolPath {
        LayerKey::ethernet_ii(),
        LayerKey::ipv6(),
        LayerKey::udp(),
    });
    PFL_REQUIRE(ipv4_path_id == 1U);
    PFL_REQUIRE(ipv6_path_id == 2U);

    const FlowKeyV4 ipv4_flow_a {
        .src_addr = ipv4(192, 0, 2, 10),
        .dst_addr = ipv4(198, 51, 100, 10),
        .src_port = 41000U,
        .dst_port = 443U,
        .protocol = ProtocolId::tcp,
        .protocol_path_id = ipv4_path_id,
    };
    const FlowKeyV4 ipv4_flow_b {
        .src_addr = ipv4_flow_a.dst_addr,
        .dst_addr = ipv4_flow_a.src_addr,
        .src_port = ipv4_flow_a.dst_port,
        .dst_port = ipv4_flow_a.src_port,
        .protocol = ipv4_flow_a.protocol,
        .protocol_path_id = ipv4_path_id,
    };

    auto& ipv4_connection = state.ipv4_connections.get_or_create(make_connection_key(ipv4_flow_a));
    const auto add_ipv4_packet = [&](const FlowKeyV4& flow_key,
                                     const PacketRef& packet,
                                     const PacketImportMetadata& metadata = {}) {
        ipv4_connection.add_packet(flow_key, packet, metadata);
        observe_capture_packet_statistics(state.packet_statistics, packet, true);
    };

    add_ipv4_packet(
        ipv4_flow_a,
        packet_ref_for_v16_metadata_test(10U, 100U, 100U, 1000U),
        PacketImportMetadata {
            .transport_payload_length = 60U,
            .tcp_flags = static_cast<std::uint8_t>(0x02U),
        }
    );
    add_ipv4_packet(
        ipv4_flow_b,
        packet_ref_for_v16_metadata_test(20U, 110U, 110U, 1100U),
        PacketImportMetadata {
            .transport_payload_length = 70U,
            .tcp_flags = static_cast<std::uint8_t>(0x04U),
        }
    );
    add_ipv4_packet(
        ipv4_flow_a,
        packet_ref_for_v16_metadata_test(40U, 120U, 112U, 1210U),
        PacketImportMetadata {.transport_payload_length = 50U, .is_ip_fragmented = true}
    );
    add_ipv4_packet(
        ipv4_flow_b,
        packet_ref_for_v16_metadata_test(70U, 95U, 90U, 1322U),
        PacketImportMetadata {.transport_payload_length = 40U}
    );
    add_ipv4_packet(
        ipv4_flow_a,
        packet_ref_for_v16_metadata_test(100U, 90U, 90U, 1412U),
        PacketImportMetadata {
            .transport_payload_length = 30U,
            .tcp_flags = static_cast<std::uint8_t>(0x01U),
        }
    );
    ipv4_connection.protocol_hint = FlowProtocolHint::tls;
    ipv4_connection.service_hint = "bulk-download.example.test";
    ipv4_connection.tls_version = TlsVersionHint::tls13;

    const FlowKeyV6 ipv6_flow_a {
        .src_addr = ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}),
        .dst_addr = ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02}),
        .src_port = 53000U,
        .dst_port = 53U,
        .protocol = ProtocolId::udp,
        .protocol_path_id = ipv6_path_id,
    };
    auto& ipv6_connection = state.ipv6_connections.get_or_create(make_connection_key(ipv6_flow_a));
    const auto add_ipv6_packet = [&](const PacketRef& packet, const PacketImportMetadata& metadata = {}) {
        ipv6_connection.add_packet(ipv6_flow_a, packet, metadata);
        observe_capture_packet_statistics(state.packet_statistics, packet, true);
    };
    add_ipv6_packet(
        packet_ref_for_v16_metadata_test(120U, 60U, 60U, 1502U),
        PacketImportMetadata {.transport_payload_length = 20U}
    );
    add_ipv6_packet(
        packet_ref_for_v16_metadata_test(140U, 80U, 75U, 1562U),
        PacketImportMetadata {.transport_payload_length = 25U}
    );
    ipv6_connection.protocol_hint = FlowProtocolHint::dns;

    state.packet_locator = {
        CapturePacketLocatorEntry {.packet_index = 10U, .file_offset = 1000U},
        CapturePacketLocatorEntry {.packet_index = 70U, .file_offset = 1322U},
        CapturePacketLocatorEntry {.packet_index = 120U, .file_offset = 1502U},
    };

    return state;
}

void append_unrecognized_packet_record(
    CaptureState& state,
    const PacketRef& packet,
    std::string reason_text
) {
    state.unrecognized_packets.push_back(UnrecognizedPacketRecord {
        .packet = packet,
        .reason_text = std::move(reason_text),
    });
    observe_capture_packet_statistics(state.packet_statistics, packet, false);
}

CaptureState make_v16_unrecognized_capture_state_fixture() {
    auto state = make_v16_metadata_capture_state_fixture();
    append_unrecognized_packet_record(
        state,
        packet_ref_for_v16_metadata_test(5U, 72U, 72U, 900U),
        "LLC header truncated"
    );
    append_unrecognized_packet_record(
        state,
        packet_ref_for_v16_metadata_test(30U, 48U, 64U, 1115U),
        ""
    );
    append_unrecognized_packet_record(
        state,
        packet_ref_for_v16_metadata_test(160U, 96U, 128U, 1700U),
        "Unsupported or malformed packet"
    );
    return state;
}

std::vector<session_detail::UnrecognizedPacketAccessRow> expected_unrecognized_rows(
    const CaptureState& state
) {
    std::vector<session_detail::UnrecognizedPacketAccessRow> rows {};
    rows.reserve(state.unrecognized_packets.size());
    for (std::size_t index = 0U; index < state.unrecognized_packets.size(); ++index) {
        const auto& record = state.unrecognized_packets[index];
        rows.push_back(session_detail::UnrecognizedPacketAccessRow {
            .row_number = static_cast<std::uint64_t>(index) + 1U,
            .packet_index = record.packet.packet_index,
            .ts_sec = record.packet.ts_sec,
            .ts_usec = record.packet.ts_usec,
            .captured_length = record.packet.captured_length,
            .original_length = record.packet.original_length,
            .reason_text = record.reason_text,
        });
    }
    return rows;
}

void expect_unrecognized_access_rows_match(
    const std::vector<session_detail::UnrecognizedPacketAccessRow>& actual,
    const std::vector<session_detail::UnrecognizedPacketAccessRow>& expected
) {
    PFL_REQUIRE(actual.size() == expected.size());
    for (std::size_t index = 0U; index < expected.size(); ++index) {
        PFL_EXPECT(actual[index] == expected[index]);
    }
}

detail::CaptureIndexV16FastStatisticsTier build_v16_metadata_fast_statistics_tier(
    const CaptureState& state
) {
    const auto connections = session_detail::list_connections(state);
    const auto general_statistics = session_detail::build_capture_general_statistics(connections);
    const auto protocol_path_display_statistics =
        session_detail::build_protocol_path_display_statistics(state, connections);
    return detail::CaptureIndexV16FastStatisticsTier {
        .capture_statistics_snapshot = session_detail::make_capture_statistics_snapshot(
            state.packet_statistics,
            general_statistics,
            CaptureStatisticsScope::complete
        ),
        .protocol_path_registry = state.protocol_path_registry,
        .protocol_path_display_statistics = protocol_path_display_statistics,
    };
}

std::vector<std::uint8_t> make_v16_metadata_container_bytes(
    const detail::CaptureIndexV16FastStatisticsTier& fast_tier,
    const CaptureIndexV16WritePlan& plan
) {
    std::ostringstream stream(std::ios::binary | std::ios::out);
    PFL_REQUIRE(detail::write_capture_index_v16(stream, make_v16_stable_header(), fast_tier, plan));
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
        PFL_EXPECT(read_le32_at(encoded_header, 16U) == kCaptureIndexStableIndexRevision);
        PFL_EXPECT(kCaptureIndexPreviousStableV15Revision == 15U);
        PFL_EXPECT(kCaptureIndexStableIndexRevision == 16U);
        PFL_EXPECT(kCaptureIndexVersion == 16U);

        detail::CaptureIndexStableHeader decoded_header {};
        std::istringstream read_stream(
            std::string(encoded_header.begin(), encoded_header.end()),
            std::ios::binary | std::ios::in
        );
        PFL_REQUIRE(detail::read_capture_index_stable_header(read_stream, decoded_header));
        PFL_EXPECT(decoded_header.index_revision == kCaptureIndexStableIndexRevision);
        PFL_EXPECT(decoded_header.source_capture_path_utf8 == header.source_capture_path_utf8);
    }

    {
        const auto snapshot = make_valid_capture_statistics_snapshot();
        const auto payload = serialize_capture_statistics_snapshot_payload(snapshot);
        const auto container_bytes = make_v16_snapshot_container_bytes(snapshot);
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
        PFL_EXPECT(decoded_header.index_revision == kCaptureIndexStableIndexRevision);

        CaptureStatisticsSnapshot decoded_snapshot {};
        const auto read_result = detail::read_v16_capture_statistics_snapshot_section(stream, decoded_snapshot);
        PFL_REQUIRE(static_cast<bool>(read_result));
        PFL_EXPECT(decoded_snapshot == snapshot);
        PFL_EXPECT(stream.peek() == std::char_traits<char>::eof());
    }

    {
        auto snapshot = make_valid_capture_statistics_snapshot();
        snapshot.scope = CaptureStatisticsScope::reserved_unknown;

        std::ostringstream stream(std::ios::binary | std::ios::out);
        PFL_REQUIRE(detail::write_capture_index_stable_header(stream, make_v16_stable_header()));
        PFL_EXPECT(!detail::write_v16_capture_statistics_snapshot_section(stream, snapshot));
    }

    {
        const auto snapshot = make_valid_capture_statistics_snapshot();
        const auto base_bytes = make_v16_snapshot_container_bytes(snapshot);
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
        const auto container_bytes = make_v16_snapshot_container_bytes(
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
        PFL_EXPECT(read_result.header.index_revision == kCaptureIndexStableIndexRevision);
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

        const auto index_path = write_temp_binary_file(
            "pfl_v16_fast_statistics_reader_ignores_late_corruption.idx",
            container_bytes
        );
        CaptureIndexReader reader {};
        detail::CaptureIndexV16FastStatisticsTier file_tier {};
        detail::CaptureIndexV16FastStatisticsTierReadResult file_read {};
        PFL_REQUIRE(reader.read_v16_fast_statistics(index_path, file_tier, file_read));
        PFL_EXPECT(file_read.header.index_revision == kCaptureIndexStableIndexRevision);
        PFL_EXPECT(file_tier.capture_statistics_snapshot == tier.capture_statistics_snapshot);
        expect_matching_protocol_path_registries(file_tier.protocol_path_registry, tier.protocol_path_registry);
        expect_matching_protocol_path_display_statistics(
            file_tier.protocol_path_display_statistics,
            tier.protocol_path_display_statistics
        );
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
            auto oversized_registry_bytes = base_bytes;
            write_le64_at(
                oversized_registry_bytes,
                sections[1].offset + 8U,
                (std::numeric_limits<std::uint64_t>::max)()
            );
            expect_fast_tier_status(
                std::move(oversized_registry_bytes),
                detail::CaptureIndexV16FastStatisticsTierReadStatus::truncated_fast_section_payload
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

    {
        const auto state = make_v16_metadata_capture_state_fixture();
        const auto fast_tier = build_v16_metadata_fast_statistics_tier(state);
        const auto canonical_connections = session_detail::list_connections(state);
        expect_v16_top_flow_ordinals_match_canonical_connections(
            fast_tier.capture_statistics_snapshot,
            canonical_connections
        );

        const auto plan_result = session_detail::build_capture_index_v16_write_plan(state);
        PFL_REQUIRE(static_cast<bool>(plan_result));
        PFL_EXPECT(plan_result.plan.metadata.connection_count() == canonical_connections.size());
        expect_v16_metadata_rows_match_canonical_connections(
            plan_result.plan.metadata,
            canonical_connections
        );

        const auto container_bytes = make_v16_metadata_container_bytes(fast_tier, plan_result.plan);

        std::istringstream read_stream(
            std::string(container_bytes.begin(), container_bytes.end()),
            std::ios::binary | std::ios::in
        );
        CaptureIndexV16MetadataTier decoded_metadata {};
        const auto read_result = detail::read_v16_metadata_tier(read_stream, decoded_metadata);
        PFL_REQUIRE(static_cast<bool>(read_result));
        PFL_EXPECT(
            read_result.fast_statistics_tier.capture_statistics_snapshot ==
            fast_tier.capture_statistics_snapshot);
        expect_matching_protocol_path_registries(
            read_result.fast_statistics_tier.protocol_path_registry,
            fast_tier.protocol_path_registry
        );
        expect_matching_protocol_path_display_statistics(
            read_result.fast_statistics_tier.protocol_path_display_statistics,
            fast_tier.protocol_path_display_statistics
        );
        expect_v16_metadata_matches_plan(decoded_metadata, plan_result.plan, container_bytes);

        std::istringstream complete_stream(
            std::string(container_bytes.begin(), container_bytes.end()),
            std::ios::binary | std::ios::in
        );
        const auto complete_read = detail::read_capture_index_v16(complete_stream);
        PFL_REQUIRE(static_cast<bool>(complete_read));
        expect_v16_metadata_matches_plan(complete_read.metadata, plan_result.plan, container_bytes);

        const auto session_index_path = write_temp_binary_file(
            "pfl_v16_session_metadata_backed.idx",
            container_bytes
        );
        CaptureSession session {};
        PFL_REQUIRE(session.load_v16_index_for_testing(session_index_path));
        PFL_EXPECT(session.opened_from_index());
        PFL_EXPECT(session.summary().packet_count == state.summary.packet_count);
        PFL_EXPECT(session.summary().flow_count == state.summary.flow_count);
        PFL_EXPECT(session.packet_statistics().total_packet_count == state.packet_statistics.total_packet_count);

        const auto session_rows = session.list_flows();
        const auto listed_connections = session_detail::list_connections(state);
        PFL_REQUIRE(session_rows.size() == listed_connections.size());
        PFL_EXPECT(session.flow_packet_count(0U) == session_detail::packet_count(listed_connections[0U]));
        PFL_EXPECT(session.list_flow_packets(0U).size() == session.flow_packet_count(0U));
        PFL_EXPECT(session.unrecognized_packet_count() == state.packet_statistics.unrecognized_packet_count);
        PFL_EXPECT(session.list_unrecognized_packets().size() == state.unrecognized_packets.size());

        session_detail::AdvancedFlowFilterSpec tcp_filter {};
        tcp_filter.flow_protocol.include.push_back(ProtocolId::tcp);
        const auto tcp_query = session.query_advanced_flows(tcp_filter);
        PFL_EXPECT(tcp_query.status == session_detail::AdvancedFlowQueryStatus::ok);
        PFL_EXPECT(!tcp_query.ordered_flow_indices.empty());

        const auto terminal_summary = session.protocol_path_summary(ProtocolPathStatisticsMode::terminal_paths);
        PFL_REQUIRE(!terminal_summary.rows.empty());
        const auto member_flow_indices = session.protocol_path_summary_flow_indices(
            ProtocolPathStatisticsMode::terminal_paths,
            terminal_summary.rows.front().node_id
        );
        PFL_EXPECT(!member_flow_indices.empty());

        const auto trailing_bytes = append_trailing_garbage(container_bytes);
        std::istringstream trailing_stream(
            std::string(trailing_bytes.begin(), trailing_bytes.end()),
            std::ios::binary | std::ios::in
        );
        const auto trailing_read = detail::read_capture_index_v16(trailing_stream);
        PFL_EXPECT(trailing_read.status == detail::CaptureIndexV16CompleteReadStatus::trailing_data);

        std::istringstream progress_stream(
            std::string(container_bytes.begin(), container_bytes.end()),
            std::ios::binary | std::ios::in
        );
        std::vector<std::uint64_t> progress_offsets {};
        const detail::CaptureIndexV16ReadControl progress_control {
            .progress_callback = [&](const std::uint64_t processed, const std::uint64_t total) {
                PFL_EXPECT(total == static_cast<std::uint64_t>(container_bytes.size()));
                progress_offsets.push_back(processed);
                return true;
            },
            .total_bytes = static_cast<std::uint64_t>(container_bytes.size()),
        };
        const auto progress_read = detail::read_capture_index_v16(progress_stream, &progress_control);
        PFL_REQUIRE(static_cast<bool>(progress_read));
        PFL_REQUIRE(progress_offsets.size() >= 2U);
        PFL_EXPECT(std::is_sorted(progress_offsets.begin(), progress_offsets.end()));
        PFL_EXPECT(progress_offsets.back() == static_cast<std::uint64_t>(container_bytes.size()));

        std::istringstream cancelled_stream(
            std::string(container_bytes.begin(), container_bytes.end()),
            std::ios::binary | std::ios::in
        );
        std::uint32_t progress_callback_count {0};
        const detail::CaptureIndexV16ReadControl cancelling_control {
            .progress_callback = [&](const std::uint64_t, const std::uint64_t) {
                ++progress_callback_count;
                return progress_callback_count < 2U;
            },
            .total_bytes = static_cast<std::uint64_t>(container_bytes.size()),
        };
        const auto cancelled_read = detail::read_capture_index_v16(cancelled_stream, &cancelling_control);
        PFL_EXPECT(cancelled_read.status == detail::CaptureIndexV16CompleteReadStatus::cancelled);
    }

    {
        const auto state = make_v16_metadata_capture_state_fixture();
        const auto fast_tier = build_v16_metadata_fast_statistics_tier(state);
        const auto plan_result = session_detail::build_capture_index_v16_write_plan(state);
        PFL_REQUIRE(static_cast<bool>(plan_result));

        std::ostringstream stream(std::ios::binary | std::ios::out);
        PFL_REQUIRE(detail::write_v16_fast_statistics_tier(stream, make_v16_stable_header(), fast_tier));
        PFL_REQUIRE(detail::write_v16_metadata_tier_sections(stream, plan_result.plan));
        PFL_REQUIRE(detail::write_v16_packetref_detail_sections(stream, plan_result.plan.packetref_detail_sections));
        PFL_REQUIRE(detail::write_v16_unrecognized_reason_sections(stream, plan_result.plan.unrecognized_reason_sections));
        const auto missing_locator_bytes = stream_bytes(stream);

        std::istringstream read_stream(
            std::string(missing_locator_bytes.begin(), missing_locator_bytes.end()),
            std::ios::binary | std::ios::in
        );
        CaptureIndexV16MetadataTier decoded_metadata {};
        const auto read_result = detail::read_v16_metadata_tier(read_stream, decoded_metadata);
        PFL_EXPECT(
            read_result.status ==
            detail::CaptureIndexV16MetadataTierReadStatus::missing_packet_locator_section);
    }

    {
        const CaptureState state {};
        const auto fast_tier = build_v16_metadata_fast_statistics_tier(state);
        const auto plan_result = session_detail::build_capture_index_v16_write_plan(state);
        PFL_REQUIRE(static_cast<bool>(plan_result));

        auto container_bytes = make_v16_metadata_container_bytes(fast_tier, plan_result.plan);
        container_bytes = replace_section_payload(
            container_bytes,
            static_cast<std::uint32_t>(detail::CaptureIndexSectionId::packetref_detail_blocks),
            0U,
            1024U
        );
        container_bytes = replace_section_payload(
            container_bytes,
            static_cast<std::uint32_t>(detail::CaptureIndexSectionId::unrecognized_reason_blobs),
            0U,
            2048U
        );

        const auto forbidden_ranges = section_payload_ranges(
            container_bytes,
            {
                static_cast<std::uint32_t>(detail::CaptureIndexSectionId::packetref_detail_blocks),
                static_cast<std::uint32_t>(detail::CaptureIndexSectionId::unrecognized_reason_blobs),
            }
        );
        PFL_REQUIRE(forbidden_ranges.size() == 2U);

        ForbiddenRangeCountingStreamBuf stream_buffer(container_bytes, forbidden_ranges);
        std::istream read_stream(&stream_buffer);
        CaptureIndexV16MetadataTier decoded_metadata {};
        PFL_REQUIRE(static_cast<bool>(detail::read_v16_metadata_tier(read_stream, decoded_metadata)));
        PFL_EXPECT(stream_buffer.forbidden_bytes_read() == 0U);
    }

    {
        auto state = make_v16_metadata_capture_state_fixture();
        state.packet_locator.clear();
        const auto fast_tier = build_v16_metadata_fast_statistics_tier(state);
        const auto plan_result = session_detail::build_capture_index_v16_write_plan(state);
        PFL_REQUIRE(static_cast<bool>(plan_result));
        PFL_REQUIRE(plan_result.plan.packet_locator_sections.size() == 1U);
        PFL_EXPECT(plan_result.plan.packet_locator_sections.front().entry_count == 0U);
        PFL_EXPECT(plan_result.plan.packet_locator_sections.front().payload_size == 8U);

        const auto container_bytes = make_v16_metadata_container_bytes(fast_tier, plan_result.plan);
        std::istringstream read_stream(
            std::string(container_bytes.begin(), container_bytes.end()),
            std::ios::binary | std::ios::in
        );
        CaptureIndexV16MetadataTier decoded_metadata {};
        PFL_REQUIRE(static_cast<bool>(detail::read_v16_metadata_tier(read_stream, decoded_metadata)));
        expect_v16_metadata_matches_plan(decoded_metadata, plan_result.plan, container_bytes);

        const auto index_path = write_temp_binary_file("pfl_v16_packet_locator_empty.idx", container_bytes);
        session_detail::CaptureIndexV16PacketLocatorAccessSource v16_source(index_path, decoded_metadata);
        PFL_EXPECT(v16_source.lookup(0U).status == session_detail::PacketLocatorAccessStatus::not_found);

        auto mixed_locator_metadata = decoded_metadata;
        mixed_locator_metadata.packet_locator_sections.push_back(CaptureIndexV16PacketLocatorSectionInfo {
            .section_occurrence_index = 1U,
            .payload_file_offset = 0U,
            .payload_size = 8U + kCaptureIndexV16PacketLocatorEncodedStrideBytes,
            .logical_entry_start = 0U,
            .entry_count = 1U,
            .first_packet_index = 10U,
            .last_packet_index = 10U,
            .first_file_offset = 100U,
            .last_file_offset = 100U,
        });
        session_detail::CaptureIndexV16PacketLocatorAccessSource mixed_locator_source(
            index_path,
            mixed_locator_metadata
        );
        PFL_EXPECT(
            mixed_locator_source.lookup(10U).status ==
            session_detail::PacketLocatorAccessStatus::malformed_locator);
    }

    {
        const auto state = make_v16_metadata_capture_state_fixture();
        const auto fast_tier = build_v16_metadata_fast_statistics_tier(state);
        const auto plan_result = session_detail::build_capture_index_v16_write_plan(state);
        PFL_REQUIRE(static_cast<bool>(plan_result));
        const auto container_bytes = make_v16_metadata_container_bytes(fast_tier, plan_result.plan);

        {
            auto mutated_bytes = container_bytes;
            const auto sections = parse_sections(mutated_bytes);
            const auto* ipv4_section = find_section_occurrence(
                sections,
                static_cast<std::uint32_t>(detail::CaptureIndexSectionId::ipv4_flow_metadata),
                0U
            );
            PFL_REQUIRE(ipv4_section != nullptr);
            write_le64_at(
                mutated_bytes,
                ipv4_section->offset + 8U,
                (std::numeric_limits<std::uint64_t>::max)()
            );

            std::istringstream read_stream(
                std::string(mutated_bytes.begin(), mutated_bytes.end()),
                std::ios::binary | std::ios::in
            );
            CaptureIndexV16MetadataTier decoded_metadata {};
            const auto read_result = detail::read_v16_metadata_tier(read_stream, decoded_metadata);
            PFL_EXPECT(
                read_result.status ==
                detail::CaptureIndexV16MetadataTierReadStatus::malformed_ipv4_flow_metadata_payload);
        }

        {
            auto mutated_bytes = container_bytes;
            const auto sections = parse_sections(mutated_bytes);
            const auto* ipv4_section = find_section_occurrence(
                sections,
                static_cast<std::uint32_t>(detail::CaptureIndexSectionId::ipv4_flow_metadata),
                0U
            );
            PFL_REQUIRE(ipv4_section != nullptr);
            write_le64_at(
                mutated_bytes,
                ipv4_section->offset + detail::kCaptureIndexStableSectionHeaderEncodedSize,
                fast_tier.capture_statistics_snapshot.total_flow_count + 1U
            );

            std::istringstream read_stream(
                std::string(mutated_bytes.begin(), mutated_bytes.end()),
                std::ios::binary | std::ios::in
            );
            CaptureIndexV16MetadataTier decoded_metadata {};
            const auto read_result = detail::read_v16_metadata_tier(read_stream, decoded_metadata);
            PFL_EXPECT(
                read_result.status ==
                detail::CaptureIndexV16MetadataTierReadStatus::malformed_ipv4_flow_metadata_payload);
        }

        {
            auto mutated_bytes = container_bytes;
            const auto sections = parse_sections(mutated_bytes);
            const auto* membership_section = find_section_occurrence(
                sections,
                static_cast<std::uint32_t>(detail::CaptureIndexSectionId::protocol_path_membership),
                0U
            );
            PFL_REQUIRE(membership_section != nullptr);
            write_le64_at(
                mutated_bytes,
                membership_section->offset + detail::kCaptureIndexStableSectionHeaderEncodedSize + 8U + 4U,
                fast_tier.capture_statistics_snapshot.total_flow_count + 1U
            );

            std::istringstream read_stream(
                std::string(mutated_bytes.begin(), mutated_bytes.end()),
                std::ios::binary | std::ios::in
            );
            CaptureIndexV16MetadataTier decoded_metadata {};
            const auto read_result = detail::read_v16_metadata_tier(read_stream, decoded_metadata);
            PFL_EXPECT(
                read_result.status ==
                detail::CaptureIndexV16MetadataTierReadStatus::malformed_protocol_path_membership_payload);
        }

        {
            auto mutated_bytes = container_bytes;
            const auto sections = parse_sections(mutated_bytes);
            const auto* directory_section = find_section_occurrence(
                sections,
                static_cast<std::uint32_t>(detail::CaptureIndexSectionId::packetref_directory),
                0U
            );
            PFL_REQUIRE(directory_section != nullptr);
            write_le64_at(
                mutated_bytes,
                directory_section->offset + detail::kCaptureIndexStableSectionHeaderEncodedSize,
                (fast_tier.capture_statistics_snapshot.total_flow_count * 2U) + 1U
            );

            std::istringstream read_stream(
                std::string(mutated_bytes.begin(), mutated_bytes.end()),
                std::ios::binary | std::ios::in
            );
            CaptureIndexV16MetadataTier decoded_metadata {};
            const auto read_result = detail::read_v16_metadata_tier(read_stream, decoded_metadata);
            PFL_EXPECT(
                read_result.status ==
                detail::CaptureIndexV16MetadataTierReadStatus::malformed_packetref_directory_payload);
        }

        {
            auto mutated_bytes = container_bytes;
            const auto sections = parse_sections(mutated_bytes);
            const auto* detail_section = find_section_occurrence(
                sections,
                static_cast<std::uint32_t>(detail::CaptureIndexSectionId::packetref_detail_blocks),
                0U
            );
            PFL_REQUIRE(detail_section != nullptr);
            write_le64_at(
                mutated_bytes,
                detail_section->offset + 8U,
                (std::numeric_limits<std::uint64_t>::max)()
            );

            std::istringstream read_stream(
                std::string(mutated_bytes.begin(), mutated_bytes.end()),
                std::ios::binary | std::ios::in
            );
            CaptureIndexV16MetadataTier decoded_metadata {};
            const auto read_result = detail::read_v16_metadata_tier(read_stream, decoded_metadata);
            PFL_EXPECT(
                read_result.status ==
                detail::CaptureIndexV16MetadataTierReadStatus::detail_section_framing_error);
        }

        {
            auto mutated_bytes = container_bytes;
            const auto sections = parse_sections(mutated_bytes);
            const auto* reason_section = find_section_occurrence(
                sections,
                static_cast<std::uint32_t>(detail::CaptureIndexSectionId::unrecognized_reason_blobs),
                0U
            );
            PFL_REQUIRE(reason_section != nullptr);
            write_le64_at(
                mutated_bytes,
                reason_section->offset + 8U,
                (std::numeric_limits<std::uint64_t>::max)()
            );

            std::istringstream read_stream(
                std::string(mutated_bytes.begin(), mutated_bytes.end()),
                std::ios::binary | std::ios::in
            );
            CaptureIndexV16MetadataTier decoded_metadata {};
            const auto read_result = detail::read_v16_metadata_tier(read_stream, decoded_metadata);
            PFL_EXPECT(
                read_result.status ==
                detail::CaptureIndexV16MetadataTierReadStatus::unrecognized_reason_framing_error);
        }
    }

    {
        auto state = make_v16_metadata_capture_state_fixture();
        state.packet_locator = {
            CapturePacketLocatorEntry {.packet_index = 10U, .file_offset = 1000U},
            CapturePacketLocatorEntry {.packet_index = 20U, .file_offset = 900U},
        };
        const auto plan_result = session_detail::build_capture_index_v16_write_plan(state);
        PFL_EXPECT(
            plan_result.status ==
            CaptureIndexV16WritePlanBuildStatus::invalid_packet_locator_order);
    }

    {
        const auto state = make_v16_metadata_capture_state_fixture();
        const auto fast_tier = build_v16_metadata_fast_statistics_tier(state);
        const auto plan_result = session_detail::build_capture_index_v16_write_plan(state);
        PFL_REQUIRE(static_cast<bool>(plan_result));
        PFL_REQUIRE(plan_result.plan.packet_locator_sections.size() == 1U);
        PFL_EXPECT(plan_result.plan.packet_locator_sections.front().entry_count == state.packet_locator.size());
        PFL_EXPECT(
            plan_result.plan.packet_locator_sections.front().payload_size ==
            8U + state.packet_locator.size() * kCaptureIndexV16PacketLocatorEncodedStrideBytes);

        const auto container_bytes = make_v16_metadata_container_bytes(fast_tier, plan_result.plan);
        const auto index_path = write_temp_binary_file("pfl_v16_packet_locator.idx", container_bytes);

        std::ifstream metadata_stream(index_path, std::ios::binary);
        PFL_REQUIRE(metadata_stream.is_open());
        CaptureIndexV16MetadataTier decoded_metadata {};
        PFL_REQUIRE(static_cast<bool>(detail::read_v16_metadata_tier(metadata_stream, decoded_metadata)));
        expect_v16_metadata_matches_plan(decoded_metadata, plan_result.plan, container_bytes);

        session_detail::ResidentPacketLocatorAccessSource resident_source(
            std::span<const CapturePacketLocatorEntry>(state.packet_locator.data(), state.packet_locator.size())
        );
        session_detail::CaptureIndexV16PacketLocatorAccessSource v16_source(index_path, decoded_metadata);

        const auto first_resident = resident_source.lookup(10U);
        const auto first_v16 = v16_source.lookup(10U);
        PFL_REQUIRE(static_cast<bool>(first_resident));
        PFL_REQUIRE(static_cast<bool>(first_v16));
        PFL_REQUIRE(first_resident.entry.has_value());
        PFL_REQUIRE(first_v16.entry.has_value());
        expect_matching_locator_entry(*first_resident.entry, state.packet_locator[0]);
        expect_matching_locator_entry(*first_v16.entry, state.packet_locator[0]);

        const auto middle_resident = resident_source.lookup(119U);
        const auto middle_v16 = v16_source.lookup(119U);
        PFL_REQUIRE(static_cast<bool>(middle_resident));
        PFL_REQUIRE(static_cast<bool>(middle_v16));
        PFL_REQUIRE(middle_resident.entry.has_value());
        PFL_REQUIRE(middle_v16.entry.has_value());
        expect_matching_locator_entry(*middle_resident.entry, state.packet_locator[1]);
        expect_matching_locator_entry(*middle_v16.entry, state.packet_locator[1]);

        const auto last_resident = resident_source.lookup(140U);
        const auto last_v16 = v16_source.lookup(140U);
        PFL_REQUIRE(static_cast<bool>(last_resident));
        PFL_REQUIRE(static_cast<bool>(last_v16));
        PFL_REQUIRE(last_resident.entry.has_value());
        PFL_REQUIRE(last_v16.entry.has_value());
        expect_matching_locator_entry(*last_resident.entry, state.packet_locator[2]);
        expect_matching_locator_entry(*last_v16.entry, state.packet_locator[2]);

        PFL_EXPECT(resident_source.lookup(9U).status == session_detail::PacketLocatorAccessStatus::not_found);
        PFL_EXPECT(v16_source.lookup(9U).status == session_detail::PacketLocatorAccessStatus::not_found);
    }

    {
        auto state = make_v16_metadata_capture_state_fixture();
        state.packet_locator = {
            CapturePacketLocatorEntry {.packet_index = 10U, .file_offset = 1000U},
            CapturePacketLocatorEntry {.packet_index = 20U, .file_offset = 1100U},
            CapturePacketLocatorEntry {.packet_index = 30U, .file_offset = 1200U},
            CapturePacketLocatorEntry {.packet_index = 40U, .file_offset = 1300U},
            CapturePacketLocatorEntry {.packet_index = 50U, .file_offset = 1400U},
            CapturePacketLocatorEntry {.packet_index = 60U, .file_offset = 1500U},
        };

        const auto fast_tier = build_v16_metadata_fast_statistics_tier(state);
        const auto plan_result = session_detail::build_capture_index_v16_write_plan(
            state,
            CaptureIndexV16PacketRefDetailLayoutOptions {
                .target_section_payload_bytes = 128U * 1024U * 1024U,
                .target_unrecognized_directory_section_payload_bytes = 128U * 1024U * 1024U,
                .target_unrecognized_reason_blob_section_payload_bytes = 128U * 1024U * 1024U,
                .target_packet_locator_section_payload_bytes =
                    8U + (3U * kCaptureIndexV16PacketLocatorEncodedStrideBytes),
            }
        );
        PFL_REQUIRE(static_cast<bool>(plan_result));
        PFL_REQUIRE(plan_result.plan.packet_locator_sections.size() == 2U);
        PFL_EXPECT(plan_result.plan.metadata.packet_locator_sections.front().entry_count == 3U);
        PFL_EXPECT(plan_result.plan.metadata.packet_locator_sections.back().entry_count == 3U);

        const auto container_bytes = make_v16_metadata_container_bytes(fast_tier, plan_result.plan);
        const auto index_path = write_temp_binary_file("pfl_v16_packet_locator_chunked.idx", container_bytes);

        std::ifstream metadata_stream(index_path, std::ios::binary);
        PFL_REQUIRE(metadata_stream.is_open());
        CaptureIndexV16MetadataTier decoded_metadata {};
        PFL_REQUIRE(static_cast<bool>(detail::read_v16_metadata_tier(metadata_stream, decoded_metadata)));
        expect_v16_metadata_matches_plan(decoded_metadata, plan_result.plan, container_bytes);

        session_detail::CaptureIndexV16PacketLocatorAccessSource v16_source(index_path, decoded_metadata);
        const auto cross_chunk_lookup = v16_source.lookup(45U);
        PFL_REQUIRE(static_cast<bool>(cross_chunk_lookup));
        PFL_REQUIRE(cross_chunk_lookup.entry.has_value());
        expect_matching_locator_entry(*cross_chunk_lookup.entry, state.packet_locator[3]);

        auto corrupted_bytes = container_bytes;
        const auto sections = parse_sections(corrupted_bytes);
        const auto* second_locator_section = find_section_occurrence(
            sections,
            static_cast<std::uint32_t>(detail::CaptureIndexSectionId::packet_locator_v16),
            1U
        );
        PFL_REQUIRE(second_locator_section != nullptr);
        write_le64_at(
            corrupted_bytes,
            second_locator_section->offset +
                detail::kCaptureIndexStableSectionHeaderEncodedSize +
                8U +
                kCaptureIndexV16PacketLocatorEncodedStrideBytes,
            5U
        );
        const auto corrupted_path = write_temp_binary_file(
            "pfl_v16_packet_locator_lazy_corrupt.idx",
            corrupted_bytes
        );

        std::ifstream corrupted_metadata_stream(corrupted_path, std::ios::binary);
        PFL_REQUIRE(corrupted_metadata_stream.is_open());
        CaptureIndexV16MetadataTier corrupted_metadata {};
        PFL_REQUIRE(static_cast<bool>(detail::read_v16_metadata_tier(
            corrupted_metadata_stream,
            corrupted_metadata
        )));

        session_detail::CaptureIndexV16PacketLocatorAccessSource corrupted_source(
            corrupted_path,
            corrupted_metadata
        );
        const auto unaffected_lookup = corrupted_source.lookup(25U);
        PFL_REQUIRE(static_cast<bool>(unaffected_lookup));
        PFL_REQUIRE(unaffected_lookup.entry.has_value());
        expect_matching_locator_entry(*unaffected_lookup.entry, state.packet_locator[1]);

        const auto corrupted_lookup = corrupted_source.lookup(50U);
        PFL_EXPECT(
            corrupted_lookup.status ==
            session_detail::PacketLocatorAccessStatus::malformed_locator);
    }

    {
        const auto state = make_v16_metadata_capture_state_fixture();
        const auto fast_tier = build_v16_metadata_fast_statistics_tier(state);
        const auto plan_result = session_detail::build_capture_index_v16_write_plan(state);
        PFL_REQUIRE(static_cast<bool>(plan_result));

        const auto container_bytes = make_v16_metadata_container_bytes(fast_tier, plan_result.plan);
        const auto sections = parse_sections(container_bytes);
        const auto* locator_section = find_section_occurrence(
            sections,
            static_cast<std::uint32_t>(detail::CaptureIndexSectionId::packet_locator_v16),
            0U
        );
        PFL_REQUIRE(locator_section != nullptr);

        auto wrong_schema_bytes = container_bytes;
        write_le16_at(wrong_schema_bytes, locator_section->offset + 4U, 99U);
        std::istringstream wrong_schema_stream(
            std::string(wrong_schema_bytes.begin(), wrong_schema_bytes.end()),
            std::ios::binary | std::ios::in
        );
        CaptureIndexV16MetadataTier wrong_schema_metadata {};
        const auto wrong_schema_result = detail::read_v16_metadata_tier(
            wrong_schema_stream,
            wrong_schema_metadata
        );
        PFL_EXPECT(
            wrong_schema_result.status ==
            detail::CaptureIndexV16MetadataTierReadStatus::unsupported_metadata_section_schema);

        auto wrong_flag_bytes = container_bytes;
        write_le16_at(wrong_flag_bytes, locator_section->offset + 6U, 0U);
        std::istringstream wrong_flag_stream(
            std::string(wrong_flag_bytes.begin(), wrong_flag_bytes.end()),
            std::ios::binary | std::ios::in
        );
        CaptureIndexV16MetadataTier wrong_flag_metadata {};
        const auto wrong_flag_result = detail::read_v16_metadata_tier(
            wrong_flag_stream,
            wrong_flag_metadata
        );
        PFL_EXPECT(
            wrong_flag_result.status ==
            detail::CaptureIndexV16MetadataTierReadStatus::packet_locator_framing_error);
    }

    {
        const auto state = make_v16_metadata_capture_state_fixture();
        const auto fast_tier = build_v16_metadata_fast_statistics_tier(state);
        const auto plan_result = session_detail::build_capture_index_v16_write_plan(state);
        PFL_REQUIRE(static_cast<bool>(plan_result));

        const auto container_bytes = make_v16_metadata_container_bytes(fast_tier, plan_result.plan);

        std::istringstream metadata_stream(
            std::string(container_bytes.begin(), container_bytes.end()),
            std::ios::binary | std::ios::in
        );
        CaptureIndexV16MetadataTier decoded_metadata {};
        PFL_REQUIRE(static_cast<bool>(detail::read_v16_metadata_tier(metadata_stream, decoded_metadata)));

        const auto forward_extent_it = std::find_if(
            decoded_metadata.packetref_directory.begin(),
            decoded_metadata.packetref_directory.end(),
            [](const auto& row) {
                return row.canonical_connection_ordinal == 0U &&
                       row.direction == Direction::a_to_b;
            }
        );
        const auto reverse_extent_it = std::find_if(
            decoded_metadata.packetref_directory.begin(),
            decoded_metadata.packetref_directory.end(),
            [](const auto& row) {
                return row.canonical_connection_ordinal == 0U &&
                       row.direction == Direction::b_to_a;
            }
        );
        PFL_REQUIRE(forward_extent_it != decoded_metadata.packetref_directory.end());
        PFL_REQUIRE(reverse_extent_it != decoded_metadata.packetref_directory.end());
        const auto ipv4_connections = state.ipv4_connections.list();
        PFL_REQUIRE(ipv4_connections.size() == 1U);
        const auto* ipv4_connection = ipv4_connections.front();
        PFL_REQUIRE(ipv4_connection != nullptr);

        std::istringstream partial_stream(
            std::string(container_bytes.begin(), container_bytes.end()),
            std::ios::binary | std::ios::in
        );
        const auto partial_forward = detail::read_v16_packetref_extent_range(
            partial_stream,
            decoded_metadata.packetref_detail_sections,
            *forward_extent_it,
            1U,
            2U
        );
        PFL_REQUIRE(static_cast<bool>(partial_forward));
        PFL_EXPECT(partial_forward.packet_refs.size() == 2U);
        expect_matching_packets(
            partial_forward.packet_refs,
            std::vector<PacketRef> {
                ipv4_connection->flow_a.packets[1],
                ipv4_connection->flow_a.packets[2],
            }
        );

        std::istringstream reverse_stream(
            std::string(container_bytes.begin(), container_bytes.end()),
            std::ios::binary | std::ios::in
        );
        const auto partial_reverse = detail::read_v16_packetref_extent_range(
            reverse_stream,
            decoded_metadata.packetref_detail_sections,
            *reverse_extent_it,
            0U,
            1U
        );
        PFL_REQUIRE(static_cast<bool>(partial_reverse));
        PFL_EXPECT(partial_reverse.packet_refs.size() == 1U);
        expect_matching_packets(
            partial_reverse.packet_refs,
            std::vector<PacketRef> {ipv4_connection->flow_b.packets[0]}
        );

        std::istringstream empty_stream(
            std::string(container_bytes.begin(), container_bytes.end()),
            std::ios::binary | std::ios::in
        );
        const auto empty_read = detail::read_v16_packetref_extent_range(
            empty_stream,
            decoded_metadata.packetref_detail_sections,
            *forward_extent_it,
            forward_extent_it->packet_count,
            4U
        );
        PFL_REQUIRE(static_cast<bool>(empty_read));
        PFL_EXPECT(empty_read.packet_refs.empty());

        std::istringstream zero_limit_stream(
            std::string(container_bytes.begin(), container_bytes.end()),
            std::ios::binary | std::ios::in
        );
        const auto zero_limit_read = detail::read_v16_packetref_extent_range(
            zero_limit_stream,
            decoded_metadata.packetref_detail_sections,
            *forward_extent_it,
            0U,
            0U
        );
        PFL_REQUIRE(static_cast<bool>(zero_limit_read));
        PFL_EXPECT(zero_limit_read.packet_refs.empty());

        std::istringstream invalid_offset_stream(
            std::string(container_bytes.begin(), container_bytes.end()),
            std::ios::binary | std::ios::in
        );
        const auto invalid_offset_read = detail::read_v16_packetref_extent_range(
            invalid_offset_stream,
            decoded_metadata.packetref_detail_sections,
            *forward_extent_it,
            forward_extent_it->packet_count + 1U,
            0U
        );
        PFL_EXPECT(
            invalid_offset_read.status ==
            detail::CaptureIndexV16PacketRefExtentReadStatus::invalid_local_offset);
    }

    {
        const auto state = make_v16_metadata_capture_state_fixture();
        const auto fast_tier = build_v16_metadata_fast_statistics_tier(state);
        const auto plan_result = session_detail::build_capture_index_v16_write_plan(state);
        PFL_REQUIRE(static_cast<bool>(plan_result));

        auto mutated_bytes = make_v16_metadata_container_bytes(fast_tier, plan_result.plan);
        const auto sections = parse_sections(mutated_bytes);
        const auto* directory_section = find_section_occurrence(
            sections,
            static_cast<std::uint32_t>(detail::CaptureIndexSectionId::packetref_directory),
            0U
        );
        PFL_REQUIRE(directory_section != nullptr);
        const auto encoded_length_offset = static_cast<std::size_t>(
            directory_section->offset +
            detail::kCaptureIndexStableSectionHeaderEncodedSize +
            8U +
            25U);
        write_le64_at(
            mutated_bytes,
            encoded_length_offset,
            read_le64_at(mutated_bytes, encoded_length_offset) + 1U
        );

        std::istringstream read_stream(
            std::string(mutated_bytes.begin(), mutated_bytes.end()),
            std::ios::binary | std::ios::in
        );
        CaptureIndexV16MetadataTier decoded_metadata {};
        const auto read_result = detail::read_v16_metadata_tier(read_stream, decoded_metadata);
        PFL_EXPECT(
            read_result.status ==
            detail::CaptureIndexV16MetadataTierReadStatus::packetref_directory_semantic_inconsistency);
        PFL_EXPECT(decoded_metadata == CaptureIndexV16MetadataTier {});
    }

    {
        const auto state = make_v16_metadata_capture_state_fixture();
        const auto fast_tier = build_v16_metadata_fast_statistics_tier(state);
        const auto plan_result = session_detail::build_capture_index_v16_write_plan(state);
        PFL_REQUIRE(static_cast<bool>(plan_result));
        PFL_REQUIRE(!plan_result.plan.packetref_detail_sections.empty());
        PFL_REQUIRE(!plan_result.plan.packetref_detail_sections.front().extents.empty());
        PFL_REQUIRE(plan_result.plan.packetref_detail_sections.front().extents.front().packet_count >= 2U);

        auto mutated_bytes = make_v16_metadata_container_bytes(fast_tier, plan_result.plan);
        const auto sections = parse_sections(mutated_bytes);
        const auto* detail_section = find_section_occurrence(
            sections,
            static_cast<std::uint32_t>(detail::CaptureIndexSectionId::packetref_detail_blocks),
            0U
        );
        PFL_REQUIRE(detail_section != nullptr);
        const auto second_packet_index_offset = static_cast<std::size_t>(
            detail_section->offset +
            detail::kCaptureIndexStableSectionHeaderEncodedSize +
            kCaptureIndexV16PacketRefEncodedStrideBytes);
        write_le64_at(mutated_bytes, second_packet_index_offset, 10U);

        std::istringstream read_stream(
            std::string(mutated_bytes.begin(), mutated_bytes.end()),
            std::ios::binary | std::ios::in
        );
        CaptureIndexV16MetadataTier decoded_metadata {};
        const auto read_result = detail::read_v16_metadata_tier(read_stream, decoded_metadata);
        PFL_REQUIRE(static_cast<bool>(read_result));

        const auto* forward_extent = decoded_metadata.packetref_directory.empty()
            ? nullptr
            : &decoded_metadata.packetref_directory.front();
        PFL_REQUIRE(forward_extent != nullptr);
        std::istringstream extent_stream(
            std::string(mutated_bytes.begin(), mutated_bytes.end()),
            std::ios::binary | std::ios::in
        );
        const auto extent_read = detail::read_v16_packetref_extent_range(
            extent_stream,
            decoded_metadata.packetref_detail_sections,
            *forward_extent,
            0U,
            forward_extent->packet_count
        );
        PFL_EXPECT(
            extent_read.status ==
            detail::CaptureIndexV16PacketRefExtentReadStatus::packet_index_not_strictly_increasing);
    }

    {
        CaptureState oversized_state {};
        const auto path_id = oversized_state.protocol_path_registry.intern(ProtocolPath {
            LayerKey::ethernet_ii(),
            LayerKey::ipv4(),
            LayerKey::tcp(),
        });
        PFL_REQUIRE(path_id == 1U);

        const FlowKeyV4 flow_key {
            .src_addr = ipv4(203, 0, 113, 10),
            .dst_addr = ipv4(203, 0, 113, 20),
            .src_port = 45000U,
            .dst_port = 443U,
            .protocol = ProtocolId::tcp,
            .protocol_path_id = path_id,
        };
        auto& connection = oversized_state.ipv4_connections.get_or_create(make_connection_key(flow_key));
        for (std::uint64_t packet_index = 0U; packet_index < 4U; ++packet_index) {
            const auto packet = packet_ref_for_v16_metadata_test(
                1000U + packet_index,
                128U,
                128U,
                4096U + packet_index * 128U
            );
            connection.add_packet(flow_key, packet);
            observe_capture_packet_statistics(oversized_state.packet_statistics, packet, true);
        }

        const auto plan_result = session_detail::build_capture_index_v16_write_plan(
            oversized_state,
            CaptureIndexV16PacketRefDetailLayoutOptions {
                .target_section_payload_bytes =
                    kCaptureIndexV16PacketRefEncodedStrideBytes * 2U,
            }
        );
        PFL_REQUIRE(static_cast<bool>(plan_result));
        PFL_EXPECT(plan_result.plan.packetref_detail_sections.size() == 1U);
        PFL_REQUIRE(plan_result.plan.packetref_detail_sections.front().extents.size() == 1U);
        PFL_EXPECT(
            plan_result.plan.packetref_detail_sections.front().payload_size ==
            4U * kCaptureIndexV16PacketRefEncodedStrideBytes);
        PFL_EXPECT(plan_result.plan.metadata.packetref_directory.size() == 1U);
        PFL_EXPECT(
            plan_result.plan.metadata.packetref_directory.front().encoded_byte_length ==
            4U * kCaptureIndexV16PacketRefEncodedStrideBytes);
    }

    {
        const auto state = make_v16_metadata_capture_state_fixture();
        const auto fast_tier = build_v16_metadata_fast_statistics_tier(state);
        const auto plan_result = session_detail::build_capture_index_v16_write_plan(state);
        PFL_REQUIRE(static_cast<bool>(plan_result));
        PFL_REQUIRE(plan_result.plan.unrecognized_directory_sections.size() == 1U);
        PFL_EXPECT(plan_result.plan.unrecognized_directory_sections.front().rows.empty());
        PFL_EXPECT(plan_result.plan.unrecognized_directory_sections.front().payload_size == 8U);
        PFL_REQUIRE(plan_result.plan.unrecognized_reason_sections.size() == 1U);
        PFL_EXPECT(plan_result.plan.unrecognized_reason_sections.front().extents.empty());
        PFL_EXPECT(plan_result.plan.unrecognized_reason_sections.front().payload_size == 0U);

        const auto container_bytes = make_v16_metadata_container_bytes(fast_tier, plan_result.plan);
        std::istringstream read_stream(
            std::string(container_bytes.begin(), container_bytes.end()),
            std::ios::binary | std::ios::in
        );
        CaptureIndexV16MetadataTier decoded_metadata {};
        const auto read_result = detail::read_v16_metadata_tier(read_stream, decoded_metadata);
        PFL_REQUIRE(static_cast<bool>(read_result));
        expect_v16_metadata_matches_plan(decoded_metadata, plan_result.plan, container_bytes);

        const auto index_path = write_temp_binary_file("pfl_v16_unrecognized_empty.idx", container_bytes);
        session_detail::CaptureIndexV16UnrecognizedPacketAccessSource source(index_path, decoded_metadata);
        const auto count_result = source.row_count();
        PFL_REQUIRE(static_cast<bool>(count_result));
        PFL_EXPECT(count_result.row_count == 0U);
        const auto empty_read = source.read_range(0U, 32U);
        PFL_REQUIRE(static_cast<bool>(empty_read));
        PFL_EXPECT(empty_read.total_row_count == 0U);
        PFL_EXPECT(empty_read.rows.empty());
    }

    {
        const auto state = make_v16_unrecognized_capture_state_fixture();
        const auto fast_tier = build_v16_metadata_fast_statistics_tier(state);
        const auto plan_result = session_detail::build_capture_index_v16_write_plan(
            state,
            CaptureIndexV16PacketRefDetailLayoutOptions {
                .target_section_payload_bytes = 128U * 1024U * 1024U,
                .target_unrecognized_directory_section_payload_bytes =
                    8U + (2U * kCaptureIndexV16UnrecognizedDirectoryEncodedStrideBytes),
                .target_unrecognized_reason_blob_section_payload_bytes = 24U,
            }
        );
        PFL_REQUIRE(static_cast<bool>(plan_result));
        PFL_REQUIRE(plan_result.plan.unrecognized_directory_sections.size() == 2U);
        PFL_EXPECT(plan_result.plan.metadata.unrecognized_directory_sections.front().row_count == 2U);
        PFL_EXPECT(plan_result.plan.metadata.unrecognized_directory_sections.back().row_count == 1U);

        const auto container_bytes = make_v16_metadata_container_bytes(fast_tier, plan_result.plan);
        const auto expected_rows = expected_unrecognized_rows(state);
        const auto index_path = write_temp_binary_file("pfl_v16_unrecognized_chunked.idx", container_bytes);

        std::ifstream metadata_stream(index_path, std::ios::binary);
        PFL_REQUIRE(metadata_stream.is_open());
        CaptureIndexV16MetadataTier decoded_metadata {};
        PFL_REQUIRE(static_cast<bool>(detail::read_v16_metadata_tier(metadata_stream, decoded_metadata)));
        expect_v16_metadata_matches_plan(decoded_metadata, plan_result.plan, container_bytes);

        session_detail::ResidentUnrecognizedPacketAccessSource resident_source(
            std::span<const UnrecognizedPacketRecord>(
                state.unrecognized_packets.data(),
                state.unrecognized_packets.size()
            )
        );
        session_detail::CaptureIndexV16UnrecognizedPacketAccessSource v16_source(index_path, decoded_metadata);
        const auto resident_rows = resident_source.read_range(0U, 16U);
        const auto v16_rows = v16_source.read_range(0U, 16U);
        PFL_REQUIRE(static_cast<bool>(resident_rows));
        PFL_REQUIRE(static_cast<bool>(v16_rows));
        expect_unrecognized_access_rows_match(resident_rows.rows, expected_rows);
        expect_unrecognized_access_rows_match(v16_rows.rows, expected_rows);

        const auto cross_chunk_rows = v16_source.read_range(1U, 2U);
        PFL_REQUIRE(static_cast<bool>(cross_chunk_rows));
        expect_unrecognized_access_rows_match(
            cross_chunk_rows.rows,
            std::vector<session_detail::UnrecognizedPacketAccessRow> {
                expected_rows[1],
                expected_rows[2],
            }
        );

        std::ifstream directory_stream(index_path, std::ios::binary);
        PFL_REQUIRE(directory_stream.is_open());
        const auto raw_directory_rows = detail::read_v16_unrecognized_directory_range(
            directory_stream,
            decoded_metadata.unrecognized_directory_sections,
            1U,
            2U
        );
        PFL_REQUIRE(static_cast<bool>(raw_directory_rows));
        PFL_EXPECT(raw_directory_rows.total_row_count == expected_rows.size());
        PFL_EXPECT(raw_directory_rows.rows.size() == 2U);
        PFL_EXPECT(raw_directory_rows.rows.front().row_number == 2U);
        PFL_EXPECT(raw_directory_rows.rows.back().row_number == 3U);

        auto prior_row_corrupted_bytes = container_bytes;
        const auto prior_row_corrupted_sections = parse_sections(prior_row_corrupted_bytes);
        const auto* first_directory_section = find_section_occurrence(
            prior_row_corrupted_sections,
            static_cast<std::uint32_t>(detail::CaptureIndexSectionId::unrecognized_directory),
            0U
        );
        PFL_REQUIRE(first_directory_section != nullptr);
        write_le64_at(
            prior_row_corrupted_bytes,
            first_directory_section->offset +
                detail::kCaptureIndexStableSectionHeaderEncodedSize +
                8U,
            99U
        );
        std::istringstream prior_row_corrupted_stream(
            std::string(prior_row_corrupted_bytes.begin(), prior_row_corrupted_bytes.end()),
            std::ios::binary | std::ios::in
        );
        const auto later_page_without_prior_decode = detail::read_v16_unrecognized_directory_range(
            prior_row_corrupted_stream,
            decoded_metadata.unrecognized_directory_sections,
            1U,
            1U
        );
        PFL_REQUIRE(static_cast<bool>(later_page_without_prior_decode));
        PFL_REQUIRE(later_page_without_prior_decode.rows.size() == 1U);
        PFL_EXPECT(later_page_without_prior_decode.rows.front().row_number == 2U);

        const auto empty_tail = v16_source.read_range(expected_rows.size(), 8U);
        PFL_REQUIRE(static_cast<bool>(empty_tail));
        PFL_EXPECT(empty_tail.rows.empty());

        const auto invalid_offset = v16_source.read_range(expected_rows.size() + 1U, 1U);
        PFL_EXPECT(invalid_offset.status == session_detail::UnrecognizedPacketAccessStatus::invalid_offset);

        const auto zero_limit = v16_source.read_range(0U, 0U);
        PFL_REQUIRE(static_cast<bool>(zero_limit));
        PFL_EXPECT(zero_limit.rows.empty());

        const auto overflow_limit = v16_source.read_range(
            1U,
            (std::numeric_limits<std::uint64_t>::max)()
        );
        PFL_EXPECT(
            overflow_limit.status ==
            session_detail::UnrecognizedPacketAccessStatus::invalid_requested_length);
    }

    {
        auto state = make_v16_unrecognized_capture_state_fixture();
        state.unrecognized_packets[1].reason_text = std::string(64U, 'x');

        const auto plan_result = session_detail::build_capture_index_v16_write_plan(
            state,
            CaptureIndexV16PacketRefDetailLayoutOptions {
                .target_section_payload_bytes = 128U * 1024U * 1024U,
                .target_unrecognized_directory_section_payload_bytes = 128U * 1024U * 1024U,
                .target_unrecognized_reason_blob_section_payload_bytes = 16U,
            }
        );
        PFL_REQUIRE(static_cast<bool>(plan_result));
        PFL_REQUIRE(plan_result.plan.unrecognized_reason_sections.size() >= 2U);
        PFL_EXPECT(plan_result.plan.unrecognized_reason_sections[1].extents.size() == 1U);
        PFL_EXPECT(plan_result.plan.unrecognized_reason_sections[1].payload_size == 64U);
        PFL_EXPECT(plan_result.plan.unrecognized_reason_sections[1].extents.front().payload_offset == 0U);
        PFL_EXPECT(plan_result.plan.unrecognized_reason_sections[1].extents.front().reason_text.size() == 64U);
    }

    {
        const auto state = make_v16_unrecognized_capture_state_fixture();
        auto fast_tier = build_v16_metadata_fast_statistics_tier(state);
        ++fast_tier.capture_statistics_snapshot.unrecognized_packet_count;
        PFL_REQUIRE(validate_capture_statistics_snapshot(fast_tier.capture_statistics_snapshot).ok);
        const auto plan_result = session_detail::build_capture_index_v16_write_plan(state);
        PFL_REQUIRE(static_cast<bool>(plan_result));

        const auto container_bytes = make_v16_metadata_container_bytes(fast_tier, plan_result.plan);
        std::istringstream read_stream(
            std::string(container_bytes.begin(), container_bytes.end()),
            std::ios::binary | std::ios::in
        );
        CaptureIndexV16MetadataTier decoded_metadata {};
        const auto read_result = detail::read_v16_metadata_tier(read_stream, decoded_metadata);
        PFL_EXPECT(
            read_result.status ==
            detail::CaptureIndexV16MetadataTierReadStatus::unrecognized_directory_semantic_inconsistency);
    }

    {
        const auto state = make_v16_unrecognized_capture_state_fixture();
        const auto fast_tier = build_v16_metadata_fast_statistics_tier(state);
        const auto plan_result = session_detail::build_capture_index_v16_write_plan(state);
        PFL_REQUIRE(static_cast<bool>(plan_result));

        const auto container_bytes = make_v16_metadata_container_bytes(fast_tier, plan_result.plan);
        const auto sections = parse_sections(container_bytes);
        const auto* directory_section = find_section_occurrence(
            sections,
            static_cast<std::uint32_t>(detail::CaptureIndexSectionId::unrecognized_directory),
            0U
        );
        PFL_REQUIRE(directory_section != nullptr);

        auto wrong_schema_bytes = container_bytes;
        write_le16_at(wrong_schema_bytes, directory_section->offset + 4U, 99U);
        std::istringstream wrong_schema_stream(
            std::string(wrong_schema_bytes.begin(), wrong_schema_bytes.end()),
            std::ios::binary | std::ios::in
        );
        CaptureIndexV16MetadataTier wrong_schema_metadata {};
        const auto wrong_schema_result = detail::read_v16_metadata_tier(wrong_schema_stream, wrong_schema_metadata);
        PFL_EXPECT(
            wrong_schema_result.status ==
            detail::CaptureIndexV16MetadataTierReadStatus::unsupported_metadata_section_schema);

        auto malformed_payload_bytes = container_bytes;
        write_le64_at(
            malformed_payload_bytes,
            directory_section->offset + 8U,
            read_le64_at(malformed_payload_bytes, directory_section->offset + 8U) + 1U
        );
        std::istringstream malformed_payload_stream(
            std::string(malformed_payload_bytes.begin(), malformed_payload_bytes.end()),
            std::ios::binary | std::ios::in
        );
        CaptureIndexV16MetadataTier malformed_payload_metadata {};
        const auto malformed_payload_result =
            detail::read_v16_metadata_tier(malformed_payload_stream, malformed_payload_metadata);
        PFL_EXPECT(
            malformed_payload_result.status ==
            detail::CaptureIndexV16MetadataTierReadStatus::malformed_unrecognized_directory_payload);
    }

    {
        const std::vector<CaptureIndexV16UnrecognizedReasonSectionInfo> reason_sections {
            CaptureIndexV16UnrecognizedReasonSectionInfo {
                .section_occurrence_index = 0U,
                .payload_file_offset = 0U,
                .payload_size = 5U,
            },
        };

        std::istringstream truncated_reason_stream(std::string("abc"), std::ios::binary | std::ios::in);
        const auto truncated_reason = detail::read_v16_unrecognized_reason(
            truncated_reason_stream,
            reason_sections,
            0U,
            0U,
            5U
        );
        PFL_EXPECT(
            truncated_reason.status ==
            detail::CaptureIndexV16UnrecognizedReasonReadStatus::truncated_reason_payload);

        std::istringstream invalid_reason_stream(std::string("abcde"), std::ios::binary | std::ios::in);
        const auto invalid_reason = detail::read_v16_unrecognized_reason(
            invalid_reason_stream,
            reason_sections,
            0U,
            6U,
            1U
        );
        PFL_EXPECT(
            invalid_reason.status ==
            detail::CaptureIndexV16UnrecognizedReasonReadStatus::invalid_reason_range);
    }

    {
        const auto state = make_v16_unrecognized_capture_state_fixture();
        const auto fast_tier = build_v16_metadata_fast_statistics_tier(state);
        auto plan_result = session_detail::build_capture_index_v16_write_plan(
            state,
            CaptureIndexV16PacketRefDetailLayoutOptions {
                .target_section_payload_bytes = 128U * 1024U * 1024U,
                .target_unrecognized_directory_section_payload_bytes =
                    8U + (2U * kCaptureIndexV16UnrecognizedDirectoryEncodedStrideBytes),
                .target_unrecognized_reason_blob_section_payload_bytes = 24U,
            }
        );
        PFL_REQUIRE(static_cast<bool>(plan_result));
        PFL_REQUIRE(!plan_result.plan.unrecognized_directory_sections.empty());
        PFL_REQUIRE(plan_result.plan.unrecognized_directory_sections.size() == 2U);
        PFL_REQUIRE(!plan_result.plan.unrecognized_directory_sections.back().rows.empty());
        plan_result.plan.unrecognized_directory_sections.back().rows.front().reason_section_occurrence_index = 99U;

        const auto container_bytes = make_v16_metadata_container_bytes(fast_tier, plan_result.plan);
        const auto index_path = write_temp_binary_file("pfl_v16_unrecognized_bad_reason_ref.idx", container_bytes);

        std::ifstream metadata_stream(index_path, std::ios::binary);
        PFL_REQUIRE(metadata_stream.is_open());
        CaptureIndexV16MetadataTier decoded_metadata {};
        PFL_REQUIRE(static_cast<bool>(detail::read_v16_metadata_tier(metadata_stream, decoded_metadata)));

        session_detail::CaptureIndexV16UnrecognizedPacketAccessSource v16_source(index_path, decoded_metadata);
        const auto first_page = v16_source.read_range(0U, 2U);
        PFL_REQUIRE(static_cast<bool>(first_page));
        PFL_EXPECT(first_page.rows.size() == 2U);

        const auto broken_page = v16_source.read_range(2U, 1U);
        PFL_EXPECT(
            broken_page.status ==
            session_detail::UnrecognizedPacketAccessStatus::malformed_reason_reference);

        auto broken_topology = decoded_metadata;
        ++broken_topology.unrecognized_directory_sections[1].logical_row_start;
        session_detail::CaptureIndexV16UnrecognizedPacketAccessSource broken_source(index_path, broken_topology);
        const auto broken_count = broken_source.row_count();
        PFL_EXPECT(broken_count.status == session_detail::UnrecognizedPacketAccessStatus::malformed_directory);
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
    detail::CaptureIndexV16CompleteReadResult complete_read {};
    PFL_REQUIRE(index_reader.read_v16_complete(index_path, complete_read));
    PFL_EXPECT(complete_read.header.index_revision == kCaptureIndexVersion);
    PFL_EXPECT(detail::filesystem_path_from_generic_utf8(complete_read.header.source_capture_path_utf8) == source_path);
    PFL_EXPECT(
        complete_read.fast_statistics_tier.capture_statistics_snapshot.total_packet_count ==
        state.summary.packet_count);
    PFL_EXPECT(
        complete_read.fast_statistics_tier.capture_statistics_snapshot.total_flow_count ==
        state.summary.flow_count);
    PFL_EXPECT(complete_read.metadata.connection_count() == session_detail::list_connections(state).size());
    const auto* loaded_gre_key_path = complete_read.fast_statistics_tier.protocol_path_registry.find(gre_key_path_id);
    const auto* loaded_esp_path = complete_read.fast_statistics_tier.protocol_path_registry.find(esp_path_id);
    const auto* loaded_ah_path = complete_read.fast_statistics_tier.protocol_path_registry.find(ah_path_id);
    PFL_REQUIRE(loaded_gre_key_path != nullptr);
    PFL_REQUIRE(loaded_esp_path != nullptr);
    PFL_REQUIRE(loaded_ah_path != nullptr);
    PFL_EXPECT(format_protocol_path(*loaded_gre_key_path) == "EthernetII -> IPv4 -> GRE(key=0x11111111) -> IPv4 -> UDP");
    PFL_EXPECT(format_protocol_path(*loaded_esp_path) == "EthernetII -> IPv4 -> ESP(spi=0x01020304)");
    PFL_EXPECT(format_protocol_path(*loaded_ah_path) == "EthernetII -> IPv4 -> AH(spi=0x01020304) -> TCP");

    CaptureSession loaded_session {};
    PFL_REQUIRE(loaded_session.load_index(index_path));
    PFL_EXPECT(loaded_session.opened_from_index());
    PFL_EXPECT(loaded_session.capture_path() == source_path);
    PFL_EXPECT(loaded_session.summary().packet_count == state.summary.packet_count);
    PFL_EXPECT(loaded_session.summary().flow_count == state.summary.flow_count);
    PFL_EXPECT(loaded_session.packet_statistics().total_packet_count == state.packet_statistics.total_packet_count);
    PFL_EXPECT(loaded_session.list_flows().size() == session_detail::list_connections(state).size());

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

    const auto production_index_bytes = read_file_bytes(index_path);
    for (const auto legacy_section_id : {
             detail::CaptureIndexSectionId::summary,
             detail::CaptureIndexSectionId::protocol_paths,
             detail::CaptureIndexSectionId::ipv4_connections,
             detail::CaptureIndexSectionId::ipv6_connections,
             detail::CaptureIndexSectionId::unrecognized_packets,
             detail::CaptureIndexSectionId::packet_locator,
         }) {
        PFL_EXPECT(count_sections(production_index_bytes, static_cast<std::uint32_t>(legacy_section_id)) == 0U);
    }
    for (const auto v16_section_id : {
             detail::CaptureIndexSectionId::capture_statistics_snapshot,
             detail::CaptureIndexSectionId::protocol_path_registry_early,
             detail::CaptureIndexSectionId::protocol_path_terminal_aggregates,
             detail::CaptureIndexSectionId::ipv4_flow_metadata,
             detail::CaptureIndexSectionId::ipv6_flow_metadata,
             detail::CaptureIndexSectionId::protocol_path_membership,
             detail::CaptureIndexSectionId::packetref_directory,
             detail::CaptureIndexSectionId::unrecognized_directory,
             detail::CaptureIndexSectionId::packetref_detail_blocks,
             detail::CaptureIndexSectionId::unrecognized_reason_blobs,
             detail::CaptureIndexSectionId::packet_locator_v16,
         }) {
        PFL_EXPECT(count_sections(production_index_bytes, static_cast<std::uint32_t>(v16_section_id)) > 0U);
    }

    auto future_revision_bytes = read_file_bytes(index_path);
    write_le32_at(future_revision_bytes, 16U, kCaptureIndexVersion + 1U);
    const auto future_revision_index_path = write_temp_binary_file(
        "pfl_index_future_stable_revision.idx",
        future_revision_bytes
    );
    detail::CaptureIndexV16CompleteReadResult future_revision_read {};
    PFL_EXPECT(!index_reader.read_v16_complete(future_revision_index_path, future_revision_read));
    PFL_EXPECT(index_reader.last_error().reason == "stable index revision is newer than this application supports");
    detail::CaptureIndexV16FastStatisticsTier future_fast_tier {};
    detail::CaptureIndexV16FastStatisticsTierReadResult future_fast_read {};
    PFL_EXPECT(!index_reader.read_v16_fast_statistics(
        future_revision_index_path,
        future_fast_tier,
        future_fast_read
    ));
    PFL_EXPECT(index_reader.last_error().reason == "stable index revision is newer than this application supports");

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

    detail::CaptureIndexV16CompleteReadResult unicode_read {};
    PFL_REQUIRE(index_reader.read_v16_complete(unicode_index_path, unicode_read));
    PFL_EXPECT(
        unicode_read.header.source_capture_path_utf8 ==
        detail::filesystem_path_to_generic_utf8(unicode_source_path)
    );

    CaptureIndexInspection unicode_inspection {};
    PFL_EXPECT(index_reader.inspect(unicode_index_path, unicode_inspection));
    PFL_EXPECT(
        detail::filesystem_path_to_generic_utf8(unicode_inspection.source_info.capture_path) ==
        detail::filesystem_path_to_generic_utf8(unicode_source_path)
    );

    {
        auto previous_stable_revision_bytes = read_file_bytes(index_path);
        write_le32_at(previous_stable_revision_bytes, 16U, kCaptureIndexPreviousStableV15Revision);
        const auto previous_stable_revision_path = write_temp_binary_file(
            "pfl_index_previous_stable_revision.idx",
            previous_stable_revision_bytes
        );
        detail::CaptureIndexV16CompleteReadResult previous_stable_read {};
        PFL_EXPECT(!index_reader.read_v16_complete(previous_stable_revision_path, previous_stable_read));
        PFL_EXPECT(
            index_reader.last_error().reason ==
            "This index uses revision 15 and must be rebuilt with the current version."
        );
        detail::CaptureIndexV16FastStatisticsTier previous_stable_fast_tier {};
        detail::CaptureIndexV16FastStatisticsTierReadResult previous_stable_fast_read {};
        PFL_EXPECT(!index_reader.read_v16_fast_statistics(
            previous_stable_revision_path,
            previous_stable_fast_tier,
            previous_stable_fast_read
        ));
        PFL_EXPECT(
            index_reader.last_error().reason ==
            "This index uses revision 15 and must be rebuilt with the current version."
        );
        CaptureSession previous_stable_session {};
        PFL_EXPECT(!previous_stable_session.load_index(previous_stable_revision_path));
        PFL_EXPECT(
            previous_stable_session.last_open_error_text().find(
                "This index uses revision 15 and must be rebuilt with the current version."
            ) != std::string::npos);
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
            CaptureIndexWriteOptions {.max_connection_section_payload_bytes = 64U},
            nullptr
        ));

        const auto chunked_ipv4_index_bytes = read_file_bytes(chunked_ipv4_index_path);
        PFL_EXPECT(count_sections(
            chunked_ipv4_index_bytes,
            static_cast<std::uint32_t>(detail::CaptureIndexSectionId::packetref_detail_blocks)
        ) > 1U);

        CaptureSession loaded_chunked_ipv4_session {};
        PFL_REQUIRE(loaded_chunked_ipv4_session.load_index(chunked_ipv4_index_path));
        PFL_EXPECT(loaded_chunked_ipv4_session.capture_path() == chunked_ipv4_source_path);
        PFL_EXPECT(loaded_chunked_ipv4_session.summary().packet_count == chunked_ipv4_state.summary.packet_count);
        PFL_EXPECT(loaded_chunked_ipv4_session.summary().flow_count == chunked_ipv4_state.summary.flow_count);

        auto truncated_chunked_ipv4_bytes = chunked_ipv4_index_bytes;
        PFL_REQUIRE(!truncated_chunked_ipv4_bytes.empty());
        truncated_chunked_ipv4_bytes.pop_back();
        const auto truncated_chunked_ipv4_index_path = write_temp_binary_file(
            "pfl_chunked_ipv4_sections_truncated.idx",
            truncated_chunked_ipv4_bytes
        );
        detail::CaptureIndexV16CompleteReadResult truncated_chunked_ipv4_read {};
        PFL_EXPECT(!index_reader.read_v16_complete(truncated_chunked_ipv4_index_path, truncated_chunked_ipv4_read));
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
            CaptureIndexWriteOptions {.max_connection_section_payload_bytes = 64U},
            nullptr
        ));

        const auto chunked_ipv6_index_bytes = read_file_bytes(chunked_ipv6_index_path);
        PFL_EXPECT(count_sections(
            chunked_ipv6_index_bytes,
            static_cast<std::uint32_t>(detail::CaptureIndexSectionId::packetref_detail_blocks)
        ) > 1U);

        CaptureSession loaded_chunked_ipv6_session {};
        PFL_REQUIRE(loaded_chunked_ipv6_session.load_index(chunked_ipv6_index_path));
        PFL_EXPECT(loaded_chunked_ipv6_session.capture_path() == chunked_ipv6_source_path);
        PFL_EXPECT(loaded_chunked_ipv6_session.summary().packet_count == chunked_ipv6_state.summary.packet_count);
        PFL_EXPECT(loaded_chunked_ipv6_session.summary().flow_count == chunked_ipv6_state.summary.flow_count);
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
        detail::CaptureIndexV16CompleteReadResult oversized_single_connection_read {};
        PFL_REQUIRE(index_reader.read_v16_complete(
            oversized_single_connection_index_path,
            oversized_single_connection_read
        ));
        const auto oversized_extent = std::find_if(
            oversized_single_connection_read.metadata.packetref_directory.begin(),
            oversized_single_connection_read.metadata.packetref_directory.end(),
            [](const CaptureIndexV16PacketRefDirectoryEntry& entry) {
                return entry.packet_count == 2U;
            }
        );
        PFL_REQUIRE(oversized_extent != oversized_single_connection_read.metadata.packetref_directory.end());
        PFL_EXPECT(
            oversized_extent->encoded_byte_length ==
            2U * kCaptureIndexV16PacketRefEncodedStrideBytes);

        CaptureSession loaded_oversized_single_connection_session {};
        PFL_REQUIRE(loaded_oversized_single_connection_session.load_index(oversized_single_connection_index_path));
        PFL_EXPECT(loaded_oversized_single_connection_session.capture_path() == oversized_single_connection_source_path);
        PFL_EXPECT(
            loaded_oversized_single_connection_session.summary().packet_count ==
            oversized_single_connection_state.summary.packet_count);
        PFL_EXPECT(
            loaded_oversized_single_connection_session.summary().flow_count ==
            oversized_single_connection_state.summary.flow_count);
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
    detail::CaptureIndexV16CompleteReadResult legacy_version_read {};
    PFL_EXPECT(!index_reader.read_v16_complete(legacy_version_index_path, legacy_version_read));
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
        std::string error_text {};
        PFL_EXPECT(!invalid_locator_writer.write(invalid_locator_index_path, invalid_locator_state, source_path, {}, &error_text));
        PFL_EXPECT(
            error_text ==
            "packet locator entries must be strictly increasing by packet_index and file_offset");
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
        std::string error_text {};
        PFL_EXPECT(!invalid_locator_writer.write(invalid_locator_index_path, invalid_locator_state, source_path, {}, &error_text));
        PFL_EXPECT(
            error_text ==
            "packet locator entries must be strictly increasing by packet_index and file_offset");
    }

    const auto malformed_index_path = write_temp_binary_file(
        "pfl_index_section_size_invalid.idx",
        corrupt_first_section_size(index_bytes)
    );
    detail::CaptureIndexV16CompleteReadResult malformed_read {};
    PFL_EXPECT(!index_reader.read_v16_complete(malformed_index_path, malformed_read));

    auto truncated_tail_bytes = index_bytes;
    PFL_REQUIRE(!truncated_tail_bytes.empty());
    truncated_tail_bytes.pop_back();
    const auto truncated_tail_index_path = write_temp_binary_file(
        "pfl_index_truncated_tail.idx",
        truncated_tail_bytes
    );
    detail::CaptureIndexV16CompleteReadResult truncated_tail_read {};
    PFL_EXPECT(!index_reader.read_v16_complete(truncated_tail_index_path, truncated_tail_read));
    PFL_EXPECT(index_reader.last_error().reason == "index file is incomplete or was not finalized");

    const auto missing_index_path = write_temp_binary_file(
        "pfl_index_missing_capture_statistics_snapshot.idx",
        remove_section(index_bytes, static_cast<std::uint32_t>(detail::CaptureIndexSectionId::capture_statistics_snapshot))
    );
    detail::CaptureIndexV16CompleteReadResult missing_read {};
    PFL_EXPECT(!index_reader.read_v16_complete(missing_index_path, missing_read));

    const auto missing_protocol_paths_index_path = write_temp_binary_file(
        "pfl_index_missing_protocol_path_registry_early.idx",
        remove_section(index_bytes, static_cast<std::uint32_t>(detail::CaptureIndexSectionId::protocol_path_registry_early))
    );
    detail::CaptureIndexV16CompleteReadResult missing_protocol_paths_read {};
    PFL_EXPECT(!index_reader.read_v16_complete(missing_protocol_paths_index_path, missing_protocol_paths_read));

    const auto missing_unrecognized_packets_index_path = write_temp_binary_file(
        "pfl_index_missing_packet_locator_v16.idx",
        remove_section(index_bytes, static_cast<std::uint32_t>(detail::CaptureIndexSectionId::packet_locator_v16))
    );
    detail::CaptureIndexV16CompleteReadResult missing_unrecognized_packets_read {};
    PFL_EXPECT(!index_reader.read_v16_complete(
        missing_unrecognized_packets_index_path,
        missing_unrecognized_packets_read));

    const auto duplicate_index_path = write_temp_binary_file(
        "pfl_index_duplicate_capture_statistics_snapshot.idx",
        duplicate_section(index_bytes, static_cast<std::uint32_t>(detail::CaptureIndexSectionId::capture_statistics_snapshot))
    );
    detail::CaptureIndexV16CompleteReadResult duplicate_read {};
    PFL_EXPECT(!index_reader.read_v16_complete(duplicate_index_path, duplicate_read));

    const auto duplicate_protocol_paths_index_path = write_temp_binary_file(
        "pfl_index_duplicate_protocol_path_registry_early.idx",
        duplicate_section(index_bytes, static_cast<std::uint32_t>(detail::CaptureIndexSectionId::protocol_path_registry_early))
    );
    detail::CaptureIndexV16CompleteReadResult duplicate_protocol_paths_read {};
    PFL_EXPECT(!index_reader.read_v16_complete(
        duplicate_protocol_paths_index_path,
        duplicate_protocol_paths_read));

    const auto trailing_index_path = write_temp_binary_file(
        "pfl_index_trailing_garbage.idx",
        append_trailing_garbage(index_bytes)
    );
    detail::CaptureIndexV16CompleteReadResult trailing_read {};
    PFL_EXPECT(!index_reader.read_v16_complete(trailing_index_path, trailing_read));

}

}  // namespace pfl::tests

