#include <cstdint>
#include <filesystem>
#include <fstream>
#include <vector>

#include "TestSupport.h"
#include "PcapTestUtils.h"
#include "core/index/CaptureIndexReader.h"
#include "core/index/CaptureIndexWriter.h"
#include "core/index/ImportCheckpointReader.h"
#include "core/index/ImportCheckpointWriter.h"
#include "core/index/Serialization.h"
#include "core/services/CaptureImporter.h"

namespace pfl::tests {

namespace {

struct SectionInfo {
    std::uint32_t id {0};
    std::size_t offset {0};
    std::size_t total_size {0};
};

std::uint32_t read_le32_at(const std::vector<std::uint8_t>& bytes, const std::size_t offset) {
    return static_cast<std::uint32_t>(bytes[offset]) |
           (static_cast<std::uint32_t>(bytes[offset + 1]) << 8U) |
           (static_cast<std::uint32_t>(bytes[offset + 2]) << 16U) |
           (static_cast<std::uint32_t>(bytes[offset + 3]) << 24U);
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

std::vector<std::uint8_t> read_file_bytes(const std::filesystem::path& path) {
    std::ifstream stream(path, std::ios::binary);
    PFL_EXPECT(stream.is_open());
    return std::vector<std::uint8_t>(std::istreambuf_iterator<char>(stream), std::istreambuf_iterator<char>());
}

std::vector<SectionInfo> parse_sections(const std::vector<std::uint8_t>& bytes) {
    constexpr std::size_t kHeaderSize = 12;
    std::vector<SectionInfo> sections {};
    std::size_t offset = kHeaderSize;

    while (offset < bytes.size()) {
        PFL_EXPECT(offset + 12U <= bytes.size());
        const auto id = read_le32_at(bytes, offset);
        const auto payload_size = read_le64_at(bytes, offset + 4U);
        PFL_EXPECT(payload_size <= static_cast<std::uint64_t>(bytes.size() - offset - 12U));
        const auto total_size = static_cast<std::size_t>(12U + payload_size);
        sections.push_back(SectionInfo {.id = id, .offset = offset, .total_size = total_size});
        offset += total_size;
    }

    return sections;
}

std::vector<std::uint8_t> remove_section(const std::vector<std::uint8_t>& bytes, const std::uint32_t section_id) {
    const auto sections = parse_sections(bytes);
    std::vector<std::uint8_t> mutated {};
    mutated.insert(mutated.end(), bytes.begin(), bytes.begin() + 12);

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
    const auto size_offset = sections.front().offset + 4U;
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

void expect_matching_packets(const std::vector<PacketRef>& left, const std::vector<PacketRef>& right) {
    PFL_EXPECT(left == right);
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
    PFL_EXPECT(left.protocol_hint == right.protocol_hint);
    PFL_EXPECT(left.service_hint == right.service_hint);
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
    PFL_EXPECT(left.protocol_hint == right.protocol_hint);
    PFL_EXPECT(left.service_hint == right.service_hint);
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
    expect_matching_tables(left.ipv4_connections, right.ipv4_connections);
    expect_matching_tables(left.ipv6_connections, right.ipv6_connections);
}

}  // namespace

void run_index_format_tests() {
    const auto forward_packet = make_ethernet_ipv4_tcp_packet(ipv4(192, 168, 10, 1), ipv4(192, 168, 10, 2), 41000, 443);
    const auto reverse_packet = make_ethernet_ipv4_udp_packet(ipv4(192, 168, 10, 2), ipv4(192, 168, 10, 1), 53, 53000);
    const auto source_path = write_temp_pcap(
        "pfl_index_format_source.pcap",
        make_classic_pcap({{100, forward_packet}, {200, reverse_packet}})
    );

    CaptureImporter importer {};
    CaptureState state {};
    PFL_EXPECT(importer.import_capture(source_path, state));

    const auto index_path = std::filesystem::temp_directory_path() / "pfl_sectioned_index.idx";
    const auto checkpoint_path = std::filesystem::temp_directory_path() / "pfl_sectioned_checkpoint.ckp";
    std::filesystem::remove(index_path);
    std::filesystem::remove(checkpoint_path);

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

    ImportCheckpoint checkpoint {};
    PFL_EXPECT(read_capture_source_info(source_path, checkpoint.source_info));
    checkpoint.packets_processed = 2;
    checkpoint.next_input_offset = 128;
    checkpoint.completed = true;
    checkpoint.state = loaded_state;

    ImportCheckpointWriter checkpoint_writer {};
    PFL_EXPECT(checkpoint_writer.write(checkpoint_path, checkpoint));

    ImportCheckpointReader checkpoint_reader {};
    ImportCheckpoint loaded_checkpoint {};
    PFL_EXPECT(checkpoint_reader.read(checkpoint_path, loaded_checkpoint));
    PFL_EXPECT(loaded_checkpoint.source_info.capture_path == checkpoint.source_info.capture_path);
    PFL_EXPECT(loaded_checkpoint.source_info.format == checkpoint.source_info.format);
    PFL_EXPECT(loaded_checkpoint.source_info.file_size == checkpoint.source_info.file_size);
    PFL_EXPECT(loaded_checkpoint.source_info.last_write_time == checkpoint.source_info.last_write_time);
    PFL_EXPECT(loaded_checkpoint.packets_processed == checkpoint.packets_processed);
    PFL_EXPECT(loaded_checkpoint.next_input_offset == checkpoint.next_input_offset);
    PFL_EXPECT(loaded_checkpoint.completed == checkpoint.completed);
    expect_matching_states(loaded_checkpoint.state, checkpoint.state);

    const auto index_bytes = read_file_bytes(index_path);
    const auto malformed_index_path = write_temp_binary_file(
        "pfl_index_section_size_invalid.idx",
        corrupt_first_section_size(index_bytes)
    );
    PFL_EXPECT(!index_reader.read(malformed_index_path, loaded_state, loaded_capture_path, &loaded_source_info));

    const auto missing_index_path = write_temp_binary_file(
        "pfl_index_missing_summary.idx",
        remove_section(index_bytes, static_cast<std::uint32_t>(detail::CaptureIndexSectionId::summary))
    );
    PFL_EXPECT(!index_reader.read(missing_index_path, loaded_state, loaded_capture_path, &loaded_source_info));

    const auto duplicate_index_path = write_temp_binary_file(
        "pfl_index_duplicate_summary.idx",
        duplicate_section(index_bytes, static_cast<std::uint32_t>(detail::CaptureIndexSectionId::summary))
    );
    PFL_EXPECT(!index_reader.read(duplicate_index_path, loaded_state, loaded_capture_path, &loaded_source_info));

    const auto trailing_index_path = write_temp_binary_file(
        "pfl_index_trailing_garbage.idx",
        append_trailing_garbage(index_bytes)
    );
    PFL_EXPECT(!index_reader.read(trailing_index_path, loaded_state, loaded_capture_path, &loaded_source_info));

    const auto checkpoint_bytes = read_file_bytes(checkpoint_path);
    const auto malformed_checkpoint_path = write_temp_binary_file(
        "pfl_checkpoint_section_size_invalid.ckp",
        corrupt_first_section_size(checkpoint_bytes)
    );
    PFL_EXPECT(!checkpoint_reader.read(malformed_checkpoint_path, loaded_checkpoint));

    const auto missing_checkpoint_path = write_temp_binary_file(
        "pfl_checkpoint_missing_progress.ckp",
        remove_section(checkpoint_bytes, static_cast<std::uint32_t>(detail::ImportCheckpointSectionId::progress))
    );
    PFL_EXPECT(!checkpoint_reader.read(missing_checkpoint_path, loaded_checkpoint));

    const auto duplicate_checkpoint_path = write_temp_binary_file(
        "pfl_checkpoint_duplicate_progress.ckp",
        duplicate_section(checkpoint_bytes, static_cast<std::uint32_t>(detail::ImportCheckpointSectionId::progress))
    );
    PFL_EXPECT(!checkpoint_reader.read(duplicate_checkpoint_path, loaded_checkpoint));

    const auto trailing_checkpoint_path = write_temp_binary_file(
        "pfl_checkpoint_trailing_garbage.ckp",
        append_trailing_garbage(checkpoint_bytes)
    );
    PFL_EXPECT(!checkpoint_reader.read(trailing_checkpoint_path, loaded_checkpoint));
}

}  // namespace pfl::tests

