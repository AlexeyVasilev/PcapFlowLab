#include <filesystem>

#include "TestSupport.h"
#include "app/session/CaptureSession.h"
#include "core/index/ImportCheckpointReader.h"
#include "core/services/ChunkedCaptureImporter.h"
#include "PcapTestUtils.h"

namespace pfl::tests {

namespace {

std::vector<std::uint8_t> unrecognized_ethernet_frame() {
    return std::vector<std::uint8_t> {
        0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU,
        0x00U, 0x11U, 0x22U, 0x33U, 0x44U, 0x55U,
        0x88U, 0xb5U,
        0x01U, 0x02U, 0x03U, 0x04U,
    };
}

void expect_packet_size_statistics_equal(
    const CapturePacketSizeStatistics& actual,
    const CapturePacketSizeStatistics& expected
) {
    PFL_EXPECT(actual.total_packet_count == expected.total_packet_count);
    PFL_EXPECT(actual.total_captured_bytes == expected.total_captured_bytes);
    PFL_EXPECT(actual.maximum_bucket_packet_count == expected.maximum_bucket_packet_count);
    PFL_EXPECT(actual.maximum_captured_packet_length == expected.maximum_captured_packet_length);
    PFL_EXPECT(actual.buckets.size() == expected.buckets.size());
    for (std::size_t index = 0U; index < expected.buckets.size(); ++index) {
        PFL_EXPECT(actual.buckets[index].stable_id == expected.buckets[index].stable_id);
        PFL_EXPECT(actual.buckets[index].packet_count == expected.buckets[index].packet_count);
    }
}

}  // namespace

void run_chunked_import_tests() {
    const auto forward_packet = make_ethernet_ipv4_tcp_packet(ipv4(10, 20, 30, 1), ipv4(10, 20, 30, 2), 50000, 443);
    const auto reverse_packet = make_ethernet_ipv4_tcp_packet(ipv4(10, 20, 30, 2), ipv4(10, 20, 30, 1), 443, 50000);
    const auto source_path = write_temp_pcap(
        "pfl_chunked_source.pcap",
        make_classic_pcap({{100, forward_packet}, {200, reverse_packet}})
    );
    const auto checkpoint_path = std::filesystem::temp_directory_path() / "pfl_chunked_import.ckp";
    const auto index_path = std::filesystem::temp_directory_path() / "pfl_chunked_import.idx";
    std::filesystem::remove(checkpoint_path);
    std::filesystem::remove(index_path);

    CaptureSession one_shot_session {};
    PFL_EXPECT(one_shot_session.open_capture(source_path));

    {
        ChunkedCaptureImporter importer {};
        const auto first_status = importer.import_chunk(source_path, checkpoint_path, 1);
        PFL_EXPECT(first_status == ChunkedImportStatus::checkpoint_saved);
        PFL_EXPECT(std::filesystem::exists(checkpoint_path));

        ImportCheckpointReader checkpoint_reader {};
        ImportCheckpoint checkpoint {};
        PFL_EXPECT(checkpoint_reader.read(checkpoint_path, checkpoint));
        PFL_EXPECT(checkpoint.packets_processed == 1);
        PFL_EXPECT(!checkpoint.completed);
        PFL_EXPECT(checkpoint.state.summary.packet_count == 1);
        PFL_EXPECT(checkpoint.state.summary.flow_count == 1);
        PFL_EXPECT(checkpoint.state.packet_size_statistics.total_packet_count == 1U);
        PFL_EXPECT(checkpoint.state.packet_size_statistics.maximum_bucket_packet_count == 1U);
        PFL_EXPECT(!checkpoint.state.packet_locator.empty());
        PFL_EXPECT(checkpoint.state.packet_locator.front().packet_index == 0U);
        PFL_EXPECT(
            checkpoint.state.packet_size_statistics.maximum_captured_packet_length ==
            static_cast<std::uint32_t>(forward_packet.size())
        );

        const auto second_status = importer.resume_chunk(checkpoint_path, 1);
        PFL_EXPECT(second_status == ChunkedImportStatus::completed);
        PFL_EXPECT(checkpoint_reader.read(checkpoint_path, checkpoint));
        PFL_EXPECT(checkpoint.packets_processed == 2);
        PFL_EXPECT(checkpoint.completed);
        PFL_EXPECT(checkpoint.state.summary.packet_count == one_shot_session.summary().packet_count);
        PFL_EXPECT(checkpoint.state.summary.flow_count == one_shot_session.summary().flow_count);
        PFL_EXPECT(checkpoint.state.summary.total_bytes == one_shot_session.summary().total_bytes);
        PFL_EXPECT(checkpoint.state.packet_locator.size() == one_shot_session.state().packet_locator.size());
        for (std::size_t index = 0U; index < checkpoint.state.packet_locator.size(); ++index) {
            PFL_EXPECT(checkpoint.state.packet_locator[index].packet_index == one_shot_session.state().packet_locator[index].packet_index);
            PFL_EXPECT(checkpoint.state.packet_locator[index].file_offset == one_shot_session.state().packet_locator[index].file_offset);
        }
        expect_packet_size_statistics_equal(
            checkpoint.state.packet_size_statistics,
            one_shot_session.packet_size_statistics()
        );

        PFL_EXPECT(importer.finalize_to_index(checkpoint_path, index_path));
        PFL_EXPECT(std::filesystem::exists(index_path));
    }

    {
        CaptureSession indexed_session {};
        PFL_EXPECT(indexed_session.load_index(index_path));
        PFL_EXPECT(indexed_session.summary().packet_count == one_shot_session.summary().packet_count);
        PFL_EXPECT(indexed_session.summary().flow_count == one_shot_session.summary().flow_count);
        PFL_EXPECT(indexed_session.list_flows().size() == one_shot_session.list_flows().size());
        expect_packet_size_statistics_equal(
            indexed_session.packet_size_statistics(),
            one_shot_session.packet_size_statistics()
        );
        PFL_EXPECT(indexed_session.state().packet_locator.size() == one_shot_session.state().packet_locator.size());
        for (std::size_t index = 0U; index < indexed_session.state().packet_locator.size(); ++index) {
            PFL_EXPECT(indexed_session.state().packet_locator[index].packet_index == one_shot_session.state().packet_locator[index].packet_index);
            PFL_EXPECT(indexed_session.state().packet_locator[index].file_offset == one_shot_session.state().packet_locator[index].file_offset);
        }
    }

    {
        const auto recognized_packet = make_ethernet_ipv4_tcp_packet(ipv4(10, 21, 30, 1), ipv4(10, 21, 30, 2), 50001, 443);
        const auto unrecognized_packet = unrecognized_ethernet_frame();
        const auto statistics_source_path = write_temp_pcap(
            "pfl_chunked_statistics_source.pcap",
            make_classic_pcap(std::vector<std::pair<std::uint32_t, std::vector<std::uint8_t>>> {
                {100U, recognized_packet},
                {200U, unrecognized_packet},
            })
        );
        const auto statistics_checkpoint_path = std::filesystem::temp_directory_path() / "pfl_chunked_statistics.ckp";
        const auto statistics_index_path = std::filesystem::temp_directory_path() / "pfl_chunked_statistics.idx";
        std::filesystem::remove(statistics_checkpoint_path);
        std::filesystem::remove(statistics_index_path);

        CaptureSession one_shot_statistics_session {};
        PFL_REQUIRE(one_shot_statistics_session.open_capture(statistics_source_path));

        ChunkedCaptureImporter importer {};
        PFL_EXPECT(importer.import_chunk(statistics_source_path, statistics_checkpoint_path, 1) == ChunkedImportStatus::checkpoint_saved);

        ImportCheckpointReader checkpoint_reader {};
        ImportCheckpoint checkpoint {};
        PFL_REQUIRE(checkpoint_reader.read(statistics_checkpoint_path, checkpoint));
        PFL_EXPECT(checkpoint.state.summary.packet_count == 1U);
        PFL_EXPECT(checkpoint.state.unrecognized_packets.empty());
        PFL_EXPECT(checkpoint.state.packet_size_statistics.total_packet_count == 1U);
        PFL_EXPECT(
            checkpoint.state.packet_size_statistics.maximum_captured_packet_length ==
            static_cast<std::uint32_t>(recognized_packet.size())
        );

        PFL_EXPECT(importer.resume_chunk(statistics_checkpoint_path, 1) == ChunkedImportStatus::completed);
        PFL_REQUIRE(checkpoint_reader.read(statistics_checkpoint_path, checkpoint));
        PFL_EXPECT(checkpoint.state.summary.packet_count == 1U);
        PFL_EXPECT(checkpoint.state.unrecognized_packets.size() == 1U);
        expect_packet_size_statistics_equal(
            checkpoint.state.packet_size_statistics,
            one_shot_statistics_session.packet_size_statistics()
        );

        PFL_REQUIRE(importer.finalize_to_index(statistics_checkpoint_path, statistics_index_path));
        CaptureSession indexed_statistics_session {};
        PFL_REQUIRE(indexed_statistics_session.load_index(statistics_index_path));
        expect_packet_size_statistics_equal(
            indexed_statistics_session.packet_size_statistics(),
            one_shot_statistics_session.packet_size_statistics()
        );
    }

    {
        const auto validation_source_path = write_temp_pcap(
            "pfl_chunked_validation_source.pcap",
            make_classic_pcap({{100, forward_packet}, {200, reverse_packet}})
        );
        const auto validation_checkpoint_path = std::filesystem::temp_directory_path() / "pfl_chunked_validation.ckp";
        const auto renamed_source_path = std::filesystem::temp_directory_path() / "pfl_chunked_validation.gone";
        std::filesystem::remove(validation_checkpoint_path);
        std::filesystem::remove(renamed_source_path);

        ChunkedCaptureImporter importer {};
        PFL_EXPECT(importer.import_chunk(validation_source_path, validation_checkpoint_path, 1) == ChunkedImportStatus::checkpoint_saved);
        std::filesystem::rename(validation_source_path, renamed_source_path);
        PFL_EXPECT(importer.resume_chunk(validation_checkpoint_path, 1) == ChunkedImportStatus::failed);
    }

    {
        const auto truncated_checkpoint_path = write_temp_binary_file("pfl_chunked_truncated.ckp", {0x50, 0x46, 0x4c, 0x43});
        ImportCheckpointReader reader {};
        ImportCheckpoint checkpoint {};
        PFL_EXPECT(!reader.read(truncated_checkpoint_path, checkpoint));

        ChunkedCaptureImporter importer {};
        PFL_EXPECT(importer.resume_chunk(truncated_checkpoint_path, 1) == ChunkedImportStatus::failed);
        PFL_EXPECT(!importer.finalize_to_index(truncated_checkpoint_path, index_path));
    }
}

}  // namespace pfl::tests

