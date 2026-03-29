#pragma once

#include <cstdint>
#include <filesystem>
#include <string>

namespace pfl {

enum class PerfOpenOperationType : std::uint8_t {
    capture_fast,
    capture_deep,
    index_load,
};

struct PerfOpenRecord {
    PerfOpenOperationType operation_type {PerfOpenOperationType::capture_fast};
    std::filesystem::path input_path {};
    std::string input_kind {"unknown"};
    std::uintmax_t file_size_bytes {0};
    bool success {false};
    std::uint64_t elapsed_ms {0};
    std::uint64_t packet_count {0};
    std::uint64_t flow_count {0};
    std::uint64_t total_bytes {0};
    bool opened_from_index {false};
    bool has_source_capture {false};
};

class PerfOpenLogger {
public:
    PerfOpenLogger();
    PerfOpenLogger(const std::filesystem::path& current_directory, const std::filesystem::path& executable_directory);

    [[nodiscard]] bool enabled() const noexcept;
    [[nodiscard]] const std::filesystem::path& log_path() const noexcept;

    void append(const PerfOpenRecord& record) const noexcept;

    [[nodiscard]] static std::string detect_input_kind(const std::filesystem::path& path);
    [[nodiscard]] static std::string operation_type_text(PerfOpenOperationType operation_type);

private:
    std::filesystem::path enabled_directory_ {};
    std::filesystem::path log_path_ {};
};

}  // namespace pfl
