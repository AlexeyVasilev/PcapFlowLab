#pragma once

#include <filesystem>

#include "core/index/ImportCheckpoint.h"

namespace pfl {

class ImportCheckpointWriter {
public:
    bool write(const std::filesystem::path& checkpoint_path,
               const ImportCheckpoint& checkpoint) const;
};

}  // namespace pfl
