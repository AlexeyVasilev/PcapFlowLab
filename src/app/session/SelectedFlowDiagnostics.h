#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string>

namespace pfl::selected_flow_diagnostics {

struct ReadCounters {
    std::uint64_t read_packet_data_calls {0};
    std::uint64_t read_packet_data_cache_hits {0};
    std::uint64_t read_packet_data_direct_attempts {0};
    std::uint64_t read_packet_data_empty_results {0};
    std::uint64_t capture_file_reader_creations {0};
    std::uint64_t capture_file_reader_open_failures {0};
    std::uint64_t packet_data_reader_calls {0};
    std::uint64_t packet_data_reader_requested_bytes {0};
    std::uint64_t file_byte_source_open_calls {0};
    std::uint64_t file_byte_source_open_failures {0};
    std::uint64_t file_byte_source_seek_calls {0};
    std::uint64_t file_byte_source_read_calls {0};
    std::uint64_t file_byte_source_read_requested_bytes {0};
};

inline bool enabled() noexcept {
    return false;
}

inline void log(std::string) {}

inline void record_read_packet_data_call(bool) noexcept {}
inline void record_read_packet_data_empty_result() noexcept {}
inline void record_capture_file_reader_created(bool) noexcept {}
inline void record_packet_data_reader_call(std::size_t) noexcept {}
inline void record_file_byte_source_open(bool) noexcept {}
inline void record_file_byte_source_read(std::size_t) noexcept {}

inline ReadCounters snapshot_read_counters() noexcept {
    return {};
}

inline ReadCounters delta(const ReadCounters&, const ReadCounters& after) noexcept {
    return after;
}

inline std::string format_read_counter_delta(const ReadCounters&, const ReadCounters&) {
    return {};
}

inline double elapsed_ms(const std::chrono::steady_clock::time_point started_at) noexcept {
    return std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - started_at).count();
}

}  // namespace pfl::selected_flow_diagnostics
