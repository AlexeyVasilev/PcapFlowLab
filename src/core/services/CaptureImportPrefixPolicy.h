#pragma once

#include <cstddef>
#include <optional>

#include "core/io/PcapReader.h"

namespace pfl {

inline constexpr std::size_t kMinCapturedLengthForStagedImportBytes = 16U * 1024U;
inline constexpr std::size_t kInitialImportHeaderPrefixBytes = 192U;

[[nodiscard]] std::optional<std::size_t> required_classic_import_prefix_bytes(const RawPcapPacket& packet);

[[nodiscard]] std::size_t grow_adaptive_import_header_prefix(
    std::size_t current_prefix_bytes,
    std::size_t required_bytes
) noexcept;

}  // namespace pfl
