#include "core/services/ChunkedCaptureImporter.h"

#include "core/decode/PacketDecoder.h"
#include "core/index/CaptureIndexWriter.h"
#include "core/index/ImportCheckpointReader.h"
#include "core/index/ImportCheckpointWriter.h"
#include "core/io/PcapNgReader.h"
#include "core/io/PcapReader.h"
#include "core/services/PacketIngestor.h"

namespace pfl {

namespace {

constexpr std::uint32_t kEthernetLinkType = 1U;

bool save_checkpoint(const std::filesystem::path& checkpoint_path, const ImportCheckpoint& checkpoint) {
    ImportCheckpointWriter writer {};
    return writer.write(checkpoint_path, checkpoint);
}

template <typename Reader>
ChunkedImportStatus import_with_reader(Reader& reader,
                                       ImportCheckpoint& checkpoint,
                                       const std::filesystem::path& checkpoint_path,
                                       std::size_t max_packets_per_chunk) {
    PacketDecoder decoder {};
    PacketIngestor ingestor {checkpoint.state};
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

        const auto decoded = decoder.decode_ethernet(*packet);
        if (decoded.ipv4.has_value()) {
            ingestor.ingest(*decoded.ipv4);
        } else if (decoded.ipv6.has_value()) {
            ingestor.ingest(*decoded.ipv6);
        }
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

    switch (checkpoint.source_info.format) {
    case CaptureSourceFormat::classic_pcap: {
        PcapReader reader {};
        if (!reader.open(checkpoint.source_info.capture_path, checkpoint.next_input_offset, checkpoint.packets_processed)) {
            return ChunkedImportStatus::failed;
        }

        if (reader.data_link_type() != kEthernetLinkType) {
            return ChunkedImportStatus::failed;
        }

        return import_with_reader(reader, checkpoint, checkpoint_path, max_packets_per_chunk);
    }
    case CaptureSourceFormat::pcapng: {
        PcapNgReader reader {};
        if (!reader.open(checkpoint.source_info.capture_path, checkpoint.next_input_offset, checkpoint.packets_processed)) {
            return ChunkedImportStatus::failed;
        }

        return import_with_reader(reader, checkpoint, checkpoint_path, max_packets_per_chunk);
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
