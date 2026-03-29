#include "core/services/PerfOpenLogger.h"

#include <chrono>
#include <ctime>
#include <fstream>
#include <optional>
#include <string_view>
#include <system_error>

#ifdef _WIN32
#include <windows.h>
#endif

namespace pfl {

namespace {

constexpr std::string_view kEnableFileName {"perf-open.enabled"};
constexpr std::string_view kLogFileName {"perf_open_log.csv"};
constexpr std::string_view kCsvHeader {
    "timestamp_utc,operation_type,input_path,input_kind,file_size_bytes,success,elapsed_ms,packet_count,flow_count,total_bytes,opened_from_index,has_source_capture\n"
};

std::optional<std::filesystem::path> current_working_directory() {
    std::error_code error {};
    const auto path = std::filesystem::current_path(error);
    if (error) {
        return std::nullopt;
    }

    return path;
}

#ifdef _WIN32
std::optional<std::filesystem::path> executable_directory() {
    std::wstring buffer(static_cast<std::size_t>(MAX_PATH), L'\0');

    while (true) {
        const auto copied = ::GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
        if (copied == 0U) {
            return std::nullopt;
        }

        if (copied < buffer.size()) {
            buffer.resize(copied);
            return std::filesystem::path {buffer}.parent_path();
        }

        buffer.resize(buffer.size() * 2U);
    }
}
#else
std::optional<std::filesystem::path> executable_directory() {
    return std::nullopt;
}
#endif

bool has_enable_file(const std::filesystem::path& directory) {
    if (directory.empty()) {
        return false;
    }

    std::error_code error {};
    return std::filesystem::exists(directory / kEnableFileName, error) && !error;
}

std::string csv_escape(const std::string& value) {
    if (value.find_first_of(",\"\r\n") == std::string::npos) {
        return value;
    }

    std::string escaped {};
    escaped.reserve(value.size() + 2U);
    escaped.push_back('"');
    for (const auto ch : value) {
        if (ch == '"') {
            escaped.push_back('"');
        }
        escaped.push_back(ch);
    }
    escaped.push_back('"');
    return escaped;
}

std::string csv_escape(const std::filesystem::path& value) {
    return csv_escape(value.generic_string());
}

std::string bool_text(const bool value) {
    return value ? "true" : "false";
}

std::string timestamp_utc_now() {
    const auto now = std::chrono::system_clock::now();
    const auto time = std::chrono::system_clock::to_time_t(now);

    std::tm utc {};
#ifdef _WIN32
    gmtime_s(&utc, &time);
#else
    gmtime_r(&time, &utc);
#endif

    char buffer[32] {};
    if (std::strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%SZ", &utc) == 0U) {
        return {};
    }

    return std::string {buffer};
}

}  // namespace

PerfOpenLogger::PerfOpenLogger()
    : PerfOpenLogger(
        current_working_directory().value_or(std::filesystem::path {}),
        executable_directory().value_or(std::filesystem::path {})
    ) {
}

PerfOpenLogger::PerfOpenLogger(const std::filesystem::path& current_directory, const std::filesystem::path& executable_directory) {
    if (has_enable_file(current_directory)) {
        enabled_directory_ = current_directory;
    } else if (has_enable_file(executable_directory)) {
        enabled_directory_ = executable_directory;
    }

    if (!enabled_directory_.empty()) {
        log_path_ = enabled_directory_ / kLogFileName;
    }
}

bool PerfOpenLogger::enabled() const noexcept {
    return !log_path_.empty();
}

const std::filesystem::path& PerfOpenLogger::log_path() const noexcept {
    return log_path_;
}

void PerfOpenLogger::append(const PerfOpenRecord& record) const noexcept {
    if (!enabled()) {
        return;
    }

    try {
        std::error_code error {};
        const bool file_exists = std::filesystem::exists(log_path_, error) && !error;

        std::ofstream stream(log_path_, std::ios::binary | std::ios::app);
        if (!stream) {
            return;
        }

        if (!file_exists) {
            stream << kCsvHeader;
        }

        stream
            << csv_escape(timestamp_utc_now()) << ','
            << csv_escape(operation_type_text(record.operation_type)) << ','
            << csv_escape(record.input_path) << ','
            << csv_escape(record.input_kind) << ','
            << record.file_size_bytes << ','
            << bool_text(record.success) << ','
            << record.elapsed_ms << ','
            << record.packet_count << ','
            << record.flow_count << ','
            << record.total_bytes << ','
            << bool_text(record.opened_from_index) << ','
            << bool_text(record.has_source_capture) << '\n';
    } catch (...) {
        return;
    }
}

std::string PerfOpenLogger::detect_input_kind(const std::filesystem::path& path) {
    const auto extension = path.extension().generic_string();
    if (extension == ".pcap") {
        return "pcap";
    }
    if (extension == ".pcapng") {
        return "pcapng";
    }
    if (extension == ".idx") {
        return "idx";
    }
    return "unknown";
}

std::string PerfOpenLogger::operation_type_text(const PerfOpenOperationType operation_type) {
    switch (operation_type) {
    case PerfOpenOperationType::capture_fast:
        return "capture_fast";
    case PerfOpenOperationType::capture_deep:
        return "capture_deep";
    case PerfOpenOperationType::index_load:
        return "index_load";
    }

    return "unknown";
}

}  // namespace pfl
