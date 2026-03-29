#pragma once

#include <cstdint>

struct OpenProgress {
    std::uint64_t bytes_processed = 0;
    std::uint64_t packets_processed = 0;
    std::uint64_t total_bytes = 0;  // 0 if unknown

    [[nodiscard]] bool has_total() const noexcept {
        return total_bytes != 0;
    }

    [[nodiscard]] double percent() const noexcept {
        if (total_bytes == 0) {
            return 0.0;
        }

        return static_cast<double>(bytes_processed) /
               static_cast<double>(total_bytes);
    }
};
