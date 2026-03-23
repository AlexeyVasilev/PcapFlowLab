#pragma once

#include <filesystem>

#include "core/index/ImportCheckpoint.h"

namespace pfl {

class ImportCheckpointReader {
public:
    bool read(const std::filesystem::path& checkpoint_path,
              ImportCheckpoint& out_checkpoint) const;
};

}  // namespace pfl
