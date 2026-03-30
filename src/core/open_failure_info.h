#pragma once

#include <cstdint>
#include <string>

struct OpenFailureInfo {
    std::uint64_t file_offset {0};
    std::uint64_t packet_index {0};
    std::uint64_t bytes_processed {0};
    std::uint64_t packets_processed {0};
    bool has_file_offset {false};
    bool has_packet_index {false};
    std::string reason {};

    [[nodiscard]] bool has_details() const noexcept {
        return has_file_offset || has_packet_index || bytes_processed != 0 || packets_processed != 0 || !reason.empty();
    }
};
