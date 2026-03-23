#include <filesystem>

#include "TestSupport.h"
#include "app/session/CaptureSession.h"
#include "core/index/ImportCheckpointReader.h"
#include "core/services/ChunkedCaptureImporter.h"
#include "PcapTestUtils.h"

namespace pfl::tests {

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

        const auto second_status = importer.resume_chunk(checkpoint_path, 1);
        PFL_EXPECT(second_status == ChunkedImportStatus::completed);
        PFL_EXPECT(checkpoint_reader.read(checkpoint_path, checkpoint));
        PFL_EXPECT(checkpoint.packets_processed == 2);
        PFL_EXPECT(checkpoint.completed);
        PFL_EXPECT(checkpoint.state.summary.packet_count == one_shot_session.summary().packet_count);
        PFL_EXPECT(checkpoint.state.summary.flow_count == one_shot_session.summary().flow_count);
        PFL_EXPECT(checkpoint.state.summary.total_bytes == one_shot_session.summary().total_bytes);

        PFL_EXPECT(importer.finalize_to_index(checkpoint_path, index_path));
        PFL_EXPECT(std::filesystem::exists(index_path));
    }

    {
        CaptureSession indexed_session {};
        PFL_EXPECT(indexed_session.load_index(index_path));
        PFL_EXPECT(indexed_session.summary().packet_count == one_shot_session.summary().packet_count);
        PFL_EXPECT(indexed_session.summary().flow_count == one_shot_session.summary().flow_count);
        PFL_EXPECT(indexed_session.list_flows().size() == one_shot_session.list_flows().size());
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
