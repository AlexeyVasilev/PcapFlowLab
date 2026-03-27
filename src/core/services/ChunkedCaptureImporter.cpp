#include "core/services/ChunkedCaptureImporter.h"

#include "core/index/CaptureIndexWriter.h"
#include "core/index/ImportCheckpointReader.h"
#include "core/index/ImportCheckpointWriter.h"
#include "core/io/LinkType.h"
#include "core/services/CaptureImportProcessor.h"

namespace pfl {

namespace {

bool save_checkpoint(const std::filesystem::path& checkpoint_path, const ImportCheckpoint& checkpoint) {
    ImportCheckpointWriter writer {};
    return writer.write(checkpoint_path, checkpoint);
}

template <typename Reader>
ChunkedImportStatus import_with_reader(Reader& reader,
                                       ImportCheckpoint& checkpoint,
                                       const std::filesystem::path& checkpoint_path,
                                       std::size_t max_packets_per_chunk,
                                       const CaptureImportProcessor& processor) {
    std::size_t chunk_packet_count {0};

    while (chunk_packet_count < max_packets_per_chunk) {
        const auto packet = reader.read_next();
        if (!packet.has_value()) {
            if (reader.has_error()) {
                return ChunkedImportStatus::failed;
            }

            checkpoint.completed = true;
            checkpoint.next_input_offset = reader.next_input_offset();
            return save_checkpoint(checkpoint_path, checkpoint) ? ChunkedImportStatus::completed : ChunkedImportStatus::failed;
        }

        ++checkpoint.packets_processed;
        ++chunk_packet_count;
        processor.process_packet(*packet, checkpoint.state);
    }

    checkpoint.next_input_offset = reader.next_input_offset();
    checkpoint.completed = reader.at_eof();

    if (!save_checkpoint(checkpoint_path, checkpoint)) {
        return ChunkedImportStatus::failed;
    }

    return checkpoint.completed ? ChunkedImportStatus::completed : ChunkedImportStatus::checkpoint_saved;
}

ChunkedImportStatus import_from_checkpoint(const std::filesystem::path& checkpoint_path,
                                           ImportCheckpoint& checkpoint,
                                           std::size_t max_packets_per_chunk) {
    if (max_packets_per_chunk == 0) {
        return ChunkedImportStatus::failed;
    }

    // Chunked import remains aligned with the current fast pipeline.
    CaptureImportProcessor processor {};

    switch (checkpoint.source_info.format) {
    case CaptureSourceFormat::classic_pcap: {
        PcapReader reader {};
        if (!reader.open(checkpoint.source_info.capture_path, checkpoint.next_input_offset, checkpoint.packets_processed)) {
            return ChunkedImportStatus::failed;
        }

        if (!is_supported_capture_link_type(reader.data_link_type())) {
            return ChunkedImportStatus::failed;
        }

        return import_with_reader(reader, checkpoint, checkpoint_path, max_packets_per_chunk, processor);
    }
    case CaptureSourceFormat::pcapng: {
        PcapNgReader reader {};
        if (!reader.open(checkpoint.source_info.capture_path, checkpoint.next_input_offset, checkpoint.packets_processed)) {
            return ChunkedImportStatus::failed;
        }

        return import_with_reader(reader, checkpoint, checkpoint_path, max_packets_per_chunk, processor);
    }
    default:
        return ChunkedImportStatus::failed;
    }
}

}  // namespace

ChunkedImportStatus ChunkedCaptureImporter::import_chunk(const std::filesystem::path& capture_path,
                                                         const std::filesystem::path& checkpoint_path,
                                                         std::size_t max_packets_per_chunk) {
    ImportCheckpoint checkpoint {};
    if (!read_capture_source_info(capture_path, checkpoint.source_info)) {
        return ChunkedImportStatus::failed;
    }

    return import_from_checkpoint(checkpoint_path, checkpoint, max_packets_per_chunk);
}

ChunkedImportStatus ChunkedCaptureImporter::resume_chunk(const std::filesystem::path& checkpoint_path,
                                                         std::size_t max_packets_per_chunk) {
    ImportCheckpointReader reader {};
    ImportCheckpoint checkpoint {};
    if (!reader.read(checkpoint_path, checkpoint)) {
        return ChunkedImportStatus::failed;
    }

    if (!validate_capture_source(checkpoint.source_info)) {
        return ChunkedImportStatus::failed;
    }

    if (checkpoint.completed) {
        return ChunkedImportStatus::completed;
    }

    return import_from_checkpoint(checkpoint_path, checkpoint, max_packets_per_chunk);
}

bool ChunkedCaptureImporter::finalize_to_index(const std::filesystem::path& checkpoint_path,
                                               const std::filesystem::path& index_path) {
    ImportCheckpointReader reader {};
    ImportCheckpoint checkpoint {};
    if (!reader.read(checkpoint_path, checkpoint)) {
        return false;
    }

    if (!checkpoint.completed) {
        return false;
    }

    if (!validate_capture_source(checkpoint.source_info)) {
        return false;
    }

    CaptureIndexWriter writer {};
    return writer.write(index_path, checkpoint.state, checkpoint.source_info.capture_path);
}

}  // namespace pfl
