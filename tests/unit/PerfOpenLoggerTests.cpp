#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "TestSupport.h"
#include "PcapTestUtils.h"
#include "app/session/CaptureSession.h"

namespace pfl::tests {

namespace {

class CurrentPathGuard {
public:
    explicit CurrentPathGuard(const std::filesystem::path& path)
        : previous_(std::filesystem::current_path()) {
        std::filesystem::current_path(path);
    }

    ~CurrentPathGuard() {
        std::error_code error {};
        std::filesystem::current_path(previous_, error);
    }

private:
    std::filesystem::path previous_ {};
};

std::filesystem::path make_temp_directory(const std::string& name) {
    const auto path = std::filesystem::temp_directory_path() / name;
    std::error_code error {};
    std::filesystem::remove_all(path, error);
    std::filesystem::create_directories(path, error);
    return path;
}

std::vector<std::string> parse_csv_line(const std::string& line) {
    std::vector<std::string> values {};
    std::string current {};
    bool in_quotes = false;

    for (std::size_t index = 0; index < line.size(); ++index) {
        const auto ch = line[index];
        if (in_quotes) {
            if (ch == '"') {
                if (index + 1U < line.size() && line[index + 1U] == '"') {
                    current.push_back('"');
                    ++index;
                } else {
                    in_quotes = false;
                }
            } else {
                current.push_back(ch);
            }
            continue;
        }

        if (ch == '"') {
            in_quotes = true;
        } else if (ch == ',') {
            values.push_back(current);
            current.clear();
        } else {
            current.push_back(ch);
        }
    }

    values.push_back(current);
    return values;
}

std::vector<std::vector<std::string>> read_csv_rows(const std::filesystem::path& path) {
    std::ifstream stream(path, std::ios::binary);
    std::vector<std::vector<std::string>> rows {};
    std::string line {};
    while (std::getline(stream, line)) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        if (line.empty()) {
            continue;
        }
        rows.push_back(parse_csv_line(line));
    }
    return rows;
}

std::vector<std::uint8_t> make_small_capture_packet() {
    return make_ethernet_ipv4_tcp_packet_with_bytes_payload(
        ipv4(192, 0, 2, 1), ipv4(192, 0, 2, 2), 41000, 443, std::vector<std::uint8_t> {'O', 'K'}, 0x18
    );
}

const std::filesystem::path kPerfEnablePath {"perf-open.enabled"};
const std::filesystem::path kPerfLogPath {"perf_open_log.csv"};

}  // namespace

void run_perf_open_logger_tests() {
    {
        const auto temp_dir = make_temp_directory("pfl_perf_open_disabled");
        const CurrentPathGuard current_path_guard(temp_dir);
        const auto capture_path = write_temp_pcap(
            "pfl_perf_open_disabled_capture.pcap",
            make_classic_pcap({
                {100, make_small_capture_packet()},
            })
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(capture_path, CaptureImportOptions {.mode = ImportMode::fast}));
        PFL_EXPECT(!std::filesystem::exists(kPerfLogPath));
    }

    {
        const auto temp_dir = make_temp_directory("pfl_perf_open_enabled");
        const CurrentPathGuard current_path_guard(temp_dir);
        {
            std::ofstream enable_file(kPerfEnablePath, std::ios::binary | std::ios::trunc);
            enable_file << "enabled\n";
        }

        const auto packet = make_small_capture_packet();
        const auto capture_path = write_temp_pcap(
            "pfl_perf_open_enabled_capture.pcap",
            make_classic_pcap({
                {100, packet},
            })
        );
        const auto index_path = temp_dir / "pfl_perf_open_enabled.idx";

        CaptureSession fast_session {};
        PFL_EXPECT(fast_session.open_capture(capture_path, CaptureImportOptions {.mode = ImportMode::fast}));
        PFL_EXPECT(fast_session.save_index(index_path));

        CaptureSession deep_session {};
        PFL_EXPECT(deep_session.open_capture(capture_path, CaptureImportOptions {.mode = ImportMode::deep}));

        CaptureSession index_session {};
        PFL_EXPECT(index_session.load_index(index_path));

        PFL_EXPECT(std::filesystem::exists(kPerfLogPath));
        const auto rows = read_csv_rows(kPerfLogPath);
        PFL_EXPECT(rows.size() == 4);
        PFL_EXPECT(rows[0].size() == 12);
        PFL_EXPECT(rows[0][0] == "timestamp_utc");
        PFL_EXPECT(rows[0][1] == "operation_type");
        PFL_EXPECT(rows[0][2] == "input_path");
        PFL_EXPECT(rows[1][1] == "capture_fast");
        PFL_EXPECT(rows[2][1] == "capture_deep");
        PFL_EXPECT(rows[3][1] == "index_load");

        PFL_EXPECT(rows[1][5] == "true");
        PFL_EXPECT(rows[2][5] == "true");
        PFL_EXPECT(rows[3][5] == "true");

        PFL_EXPECT(rows[1][7] == "1");
        PFL_EXPECT(rows[1][8] == "1");
        PFL_EXPECT(rows[2][7] == "1");
        PFL_EXPECT(rows[2][8] == "1");
        PFL_EXPECT(rows[3][7] == "1");
        PFL_EXPECT(rows[3][8] == "1");

        PFL_EXPECT(rows[1][9] == std::to_string(packet.size()));
        PFL_EXPECT(rows[2][9] == std::to_string(packet.size()));
        PFL_EXPECT(rows[3][9] == std::to_string(packet.size()));

        PFL_EXPECT(rows[1][10] == "false");
        PFL_EXPECT(rows[1][11] == "true");
        PFL_EXPECT(rows[2][10] == "false");
        PFL_EXPECT(rows[2][11] == "true");
        PFL_EXPECT(rows[3][10] == "true");
        PFL_EXPECT(rows[3][11] == "true");

        PFL_EXPECT(rows[1][3] == "pcap");
        PFL_EXPECT(rows[2][3] == "pcap");
        PFL_EXPECT(rows[3][3] == "idx");
    }
}

}  // namespace pfl::tests
