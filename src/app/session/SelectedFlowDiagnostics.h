#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>
#include <string_view>

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
    static const bool value = []() noexcept {
        const char* raw = std::getenv("PFL_SELECTED_FLOW_DIAGNOSTICS");
        if (raw == nullptr) {
            return false;
        }

        const std::string_view text {raw};
        return !text.empty() && text != "0" && text != "false" && text != "FALSE";
    }();
    return value;
}

inline void log(std::string message) {
    if (!enabled()) {
        return;
    }

    static std::mutex log_mutex {};
    std::lock_guard<std::mutex> lock {log_mutex};

    std::ofstream stream {"selected-flow-diagnostics.log", std::ios::binary | std::ios::app};
    if (stream.is_open()) {
        stream << "[selected-flow-diagnostics] " << message << '\n';
        return;
    }

    std::clog << "[selected-flow-diagnostics] " << message << '\n';
}

inline auto& read_packet_data_call_counter() {
    static std::atomic<std::uint64_t> counter {0};
    return counter;
}

inline auto& read_packet_data_cache_hit_counter() {
    static std::atomic<std::uint64_t> counter {0};
    return counter;
}

inline auto& read_packet_data_direct_attempt_counter() {
    static std::atomic<std::uint64_t> counter {0};
    return counter;
}

inline auto& read_packet_data_empty_result_counter() {
    static std::atomic<std::uint64_t> counter {0};
    return counter;
}

inline auto& capture_file_reader_creation_counter() {
    static std::atomic<std::uint64_t> counter {0};
    return counter;
}

inline auto& capture_file_reader_open_failure_counter() {
    static std::atomic<std::uint64_t> counter {0};
    return counter;
}

inline auto& packet_data_reader_call_counter() {
    static std::atomic<std::uint64_t> counter {0};
    return counter;
}

inline auto& packet_data_reader_requested_bytes_counter() {
    static std::atomic<std::uint64_t> counter {0};
    return counter;
}

inline auto& file_byte_source_open_call_counter() {
    static std::atomic<std::uint64_t> counter {0};
    return counter;
}

inline auto& file_byte_source_open_failure_counter() {
    static std::atomic<std::uint64_t> counter {0};
    return counter;
}

inline auto& file_byte_source_seek_call_counter() {
    static std::atomic<std::uint64_t> counter {0};
    return counter;
}

inline auto& file_byte_source_read_call_counter() {
    static std::atomic<std::uint64_t> counter {0};
    return counter;
}

inline auto& file_byte_source_read_requested_bytes_counter() {
    static std::atomic<std::uint64_t> counter {0};
    return counter;
}

inline void record_read_packet_data_call(const bool cache_hit) noexcept {
    if (!enabled()) {
        return;
    }

    read_packet_data_call_counter().fetch_add(1, std::memory_order_relaxed);
    if (cache_hit) {
        read_packet_data_cache_hit_counter().fetch_add(1, std::memory_order_relaxed);
    } else {
        read_packet_data_direct_attempt_counter().fetch_add(1, std::memory_order_relaxed);
    }
}

inline void record_read_packet_data_empty_result() noexcept {
    if (!enabled()) {
        return;
    }

    read_packet_data_empty_result_counter().fetch_add(1, std::memory_order_relaxed);
}

inline void record_capture_file_reader_created(const bool opened) noexcept {
    if (!enabled()) {
        return;
    }

    capture_file_reader_creation_counter().fetch_add(1, std::memory_order_relaxed);
    if (!opened) {
        capture_file_reader_open_failure_counter().fetch_add(1, std::memory_order_relaxed);
    }
}

inline void record_packet_data_reader_call(const std::size_t requested_bytes) noexcept {
    if (!enabled()) {
        return;
    }

    packet_data_reader_call_counter().fetch_add(1, std::memory_order_relaxed);
    packet_data_reader_requested_bytes_counter().fetch_add(
        static_cast<std::uint64_t>(requested_bytes),
        std::memory_order_relaxed
    );
}

inline void record_file_byte_source_open(const bool opened) noexcept {
    if (!enabled()) {
        return;
    }

    file_byte_source_open_call_counter().fetch_add(1, std::memory_order_relaxed);
    if (!opened) {
        file_byte_source_open_failure_counter().fetch_add(1, std::memory_order_relaxed);
    }
}

inline void record_file_byte_source_read(const std::size_t requested_bytes) noexcept {
    if (!enabled()) {
        return;
    }

    file_byte_source_seek_call_counter().fetch_add(1, std::memory_order_relaxed);
    file_byte_source_read_call_counter().fetch_add(1, std::memory_order_relaxed);
    file_byte_source_read_requested_bytes_counter().fetch_add(
        static_cast<std::uint64_t>(requested_bytes),
        std::memory_order_relaxed
    );
}

inline ReadCounters snapshot_read_counters() noexcept {
    if (!enabled()) {
        return {};
    }

    return ReadCounters {
        .read_packet_data_calls = read_packet_data_call_counter().load(std::memory_order_relaxed),
        .read_packet_data_cache_hits = read_packet_data_cache_hit_counter().load(std::memory_order_relaxed),
        .read_packet_data_direct_attempts = read_packet_data_direct_attempt_counter().load(std::memory_order_relaxed),
        .read_packet_data_empty_results = read_packet_data_empty_result_counter().load(std::memory_order_relaxed),
        .capture_file_reader_creations = capture_file_reader_creation_counter().load(std::memory_order_relaxed),
        .capture_file_reader_open_failures = capture_file_reader_open_failure_counter().load(std::memory_order_relaxed),
        .packet_data_reader_calls = packet_data_reader_call_counter().load(std::memory_order_relaxed),
        .packet_data_reader_requested_bytes = packet_data_reader_requested_bytes_counter().load(std::memory_order_relaxed),
        .file_byte_source_open_calls = file_byte_source_open_call_counter().load(std::memory_order_relaxed),
        .file_byte_source_open_failures = file_byte_source_open_failure_counter().load(std::memory_order_relaxed),
        .file_byte_source_seek_calls = file_byte_source_seek_call_counter().load(std::memory_order_relaxed),
        .file_byte_source_read_calls = file_byte_source_read_call_counter().load(std::memory_order_relaxed),
        .file_byte_source_read_requested_bytes = file_byte_source_read_requested_bytes_counter().load(std::memory_order_relaxed),
    };
}

inline ReadCounters delta(const ReadCounters& before, const ReadCounters& after) noexcept {
    return ReadCounters {
        .read_packet_data_calls = after.read_packet_data_calls - before.read_packet_data_calls,
        .read_packet_data_cache_hits = after.read_packet_data_cache_hits - before.read_packet_data_cache_hits,
        .read_packet_data_direct_attempts = after.read_packet_data_direct_attempts - before.read_packet_data_direct_attempts,
        .read_packet_data_empty_results = after.read_packet_data_empty_results - before.read_packet_data_empty_results,
        .capture_file_reader_creations = after.capture_file_reader_creations - before.capture_file_reader_creations,
        .capture_file_reader_open_failures = after.capture_file_reader_open_failures - before.capture_file_reader_open_failures,
        .packet_data_reader_calls = after.packet_data_reader_calls - before.packet_data_reader_calls,
        .packet_data_reader_requested_bytes = after.packet_data_reader_requested_bytes - before.packet_data_reader_requested_bytes,
        .file_byte_source_open_calls = after.file_byte_source_open_calls - before.file_byte_source_open_calls,
        .file_byte_source_open_failures = after.file_byte_source_open_failures - before.file_byte_source_open_failures,
        .file_byte_source_seek_calls = after.file_byte_source_seek_calls - before.file_byte_source_seek_calls,
        .file_byte_source_read_calls = after.file_byte_source_read_calls - before.file_byte_source_read_calls,
        .file_byte_source_read_requested_bytes = after.file_byte_source_read_requested_bytes - before.file_byte_source_read_requested_bytes,
    };
}

inline std::string format_read_counter_delta(const ReadCounters& before, const ReadCounters& after) {
    const auto diff = delta(before, after);
    std::ostringstream out {};
    out << "reads{session_calls=" << diff.read_packet_data_calls
        << ", cache_hits=" << diff.read_packet_data_cache_hits
        << ", direct_attempts=" << diff.read_packet_data_direct_attempts
        << ", empty=" << diff.read_packet_data_empty_results
        << ", reader_creations=" << diff.capture_file_reader_creations
        << ", reader_open_failures=" << diff.capture_file_reader_open_failures
        << ", packet_reader_calls=" << diff.packet_data_reader_calls
        << ", packet_reader_bytes=" << diff.packet_data_reader_requested_bytes
        << ", file_opens=" << diff.file_byte_source_open_calls
        << ", file_open_failures=" << diff.file_byte_source_open_failures
        << ", seeks=" << diff.file_byte_source_seek_calls
        << ", file_reads=" << diff.file_byte_source_read_calls
        << ", file_read_bytes=" << diff.file_byte_source_read_requested_bytes
        << "}";
    return out.str();
}

inline double elapsed_ms(const std::chrono::steady_clock::time_point started_at) noexcept {
    return std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - started_at).count();
}

}  // namespace pfl::selected_flow_diagnostics
