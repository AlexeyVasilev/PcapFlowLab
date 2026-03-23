#pragma once

#include <cstddef>
#include <filesystem>

namespace pfl {

enum class ChunkedImportStatus {
    completed,
    checkpoint_saved,
    failed,
};

class ChunkedCaptureImporter {
public:
    ChunkedImportStatus import_chunk(const std::filesystem::path& capture_path,
                                     const std::filesystem::path& checkpoint_path,
                                     std::size_t max_packets_per_chunk);

    ChunkedImportStatus resume_chunk(const std::filesystem::path& checkpoint_path,
                                     std::size_t max_packets_per_chunk);

    bool finalize_to_index(const std::filesystem::path& checkpoint_path,
                           const std::filesystem::path& index_path);
};

}  // namespace pfl
