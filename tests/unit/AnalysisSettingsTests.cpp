#include <vector>

#include "TestSupport.h"
#include "PcapTestUtils.h"
#include "app/session/CaptureSession.h"

namespace pfl::tests {

namespace {

std::vector<std::uint8_t> make_http_request_without_host_payload() {
    constexpr char request[] =
        "GET /fallback/path HTTP/1.1\r\n"
        "User-Agent: PFL\r\n"
        "\r\n";
    return std::vector<std::uint8_t>(request, request + sizeof(request) - 1);
}

std::vector<std::uint8_t> make_http_request_with_host_payload() {
    constexpr char request[] =
        "GET /fallback/path HTTP/1.1\r\n"
        "Host: preferred.example\r\n"
        "User-Agent: PFL\r\n"
        "\r\n";
    return std::vector<std::uint8_t>(request, request + sizeof(request) - 1);
}

std::filesystem::path write_single_http_capture(const std::string& name, const std::vector<std::uint8_t>& payload) {
    return write_temp_pcap(
        name,
        make_classic_pcap({
            {100, make_ethernet_ipv4_tcp_packet_with_bytes_payload(
                ipv4(192, 168, 50, 10), ipv4(93, 184, 216, 34), 51515, 80, payload, 0x18)},
        })
    );
}

}  // namespace

void run_analysis_settings_tests() {
    {
        CaptureSession session {};
        const auto capture_path = write_single_http_capture("pfl_http_settings_default.pcap", make_http_request_without_host_payload());

        PFL_EXPECT(session.open_capture(capture_path));
        const auto rows = session.list_flows();
        PFL_EXPECT(rows.size() == 1);
        PFL_EXPECT(rows[0].protocol_hint == "http");
        PFL_EXPECT(rows[0].service_hint.empty());
    }

    {
        CaptureSession session {};
        const auto capture_path = write_single_http_capture("pfl_http_settings_path_fallback.pcap", make_http_request_without_host_payload());

        PFL_EXPECT(session.open_capture(capture_path, CaptureImportOptions {
            .mode = ImportMode::fast,
            .settings = AnalysisSettings {.http_use_path_as_service_hint = true},
        }));
        const auto rows = session.list_flows();
        PFL_EXPECT(rows.size() == 1);
        PFL_EXPECT(rows[0].protocol_hint == "http");
        PFL_EXPECT(rows[0].service_hint == "/fallback/path");
    }

    {
        CaptureSession session {};
        const auto capture_path = write_single_http_capture("pfl_http_settings_host_preferred.pcap", make_http_request_with_host_payload());

        PFL_EXPECT(session.open_capture(capture_path, CaptureImportOptions {
            .mode = ImportMode::fast,
            .settings = AnalysisSettings {.http_use_path_as_service_hint = true},
        }));
        const auto rows = session.list_flows();
        PFL_EXPECT(rows.size() == 1);
        PFL_EXPECT(rows[0].protocol_hint == "http");
        PFL_EXPECT(rows[0].service_hint == "preferred.example");
    }
}

}  // namespace pfl::tests
