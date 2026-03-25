#pragma once

#include <cstdint>

#include "core/domain/CaptureState.h"
#include "core/index/CaptureIndex.h"

namespace pfl {

struct ImportCheckpoint {
    CaptureSourceInfo source_info {};
    std::uint64_t packets_processed {0};
    std::uint64_t next_input_offset {0};
    bool completed {false};
    CaptureState state {};
};

inline constexpr std::uint64_t kImportCheckpointMagic = 0x3150544b434c4650ULL;
inline constexpr std::uint16_t kImportCheckpointVersion = 2;

}  // namespace pfl
