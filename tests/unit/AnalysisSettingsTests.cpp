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

std::vector<std::uint8_t> make_quic_initial_like_payload() {
    return {
        0xC3, 0x00, 0x00, 0x00, 0x01,
        0x08,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x08,
        0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
        0x00,
    };
}

std::vector<std::uint8_t> make_tls_client_hello_payload() {
    const std::vector<std::uint8_t> server_name {'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'o', 'r', 'g'};

    std::vector<std::uint8_t> extension_data {};
    append_be16(extension_data, static_cast<std::uint16_t>(server_name.size() + 3));
    extension_data.push_back(0x00);
    append_be16(extension_data, static_cast<std::uint16_t>(server_name.size()));
    extension_data.insert(extension_data.end(), server_name.begin(), server_name.end());

    std::vector<std::uint8_t> extensions {};
    append_be16(extensions, 0x0000);
    append_be16(extensions, static_cast<std::uint16_t>(extension_data.size()));
    extensions.insert(extensions.end(), extension_data.begin(), extension_data.end());

    std::vector<std::uint8_t> body {};
    body.push_back(0x03);
    body.push_back(0x03);
    for (std::uint8_t index = 0; index < 32; ++index) {
        body.push_back(index);
    }
    body.push_back(0x00);
    append_be16(body, 0x0002);
    append_be16(body, 0x1301);
    body.push_back(0x01);
    body.push_back(0x00);
    append_be16(body, static_cast<std::uint16_t>(extensions.size()));
    body.insert(body.end(), extensions.begin(), extensions.end());

    std::vector<std::uint8_t> payload {};
    payload.push_back(0x16);
    payload.push_back(0x03);
    payload.push_back(0x03);
    append_be16(payload, static_cast<std::uint16_t>(body.size() + 4));
    payload.push_back(0x01);
    payload.push_back(static_cast<std::uint8_t>((body.size() >> 16U) & 0xFFU));
    payload.push_back(static_cast<std::uint8_t>((body.size() >> 8U) & 0xFFU));
    payload.push_back(static_cast<std::uint8_t>(body.size() & 0xFFU));
    payload.insert(payload.end(), body.begin(), body.end());
    return payload;
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

std::filesystem::path write_single_tcp_443_unknown_capture(const std::string& name) {
    return write_temp_pcap(
        name,
        make_classic_pcap({
            {100, make_ethernet_ipv4_tcp_packet_with_payload(
                ipv4(192, 168, 51, 10), ipv4(93, 184, 216, 35), 51516, 443, 24, 0x18)},
        })
    );
}

std::filesystem::path write_single_udp_443_unknown_capture(const std::string& name) {
    return write_temp_pcap(
        name,
        make_classic_pcap({
            {100, make_ethernet_ipv4_udp_packet_with_payload(
                ipv4(192, 168, 52, 10), ipv4(93, 184, 216, 36), 51517, 443, 24)},
        })
    );
}

std::filesystem::path write_single_tls_capture(const std::string& name) {
    return write_temp_pcap(
        name,
        make_classic_pcap({
            {100, make_ethernet_ipv4_tcp_packet_with_bytes_payload(
                ipv4(192, 168, 53, 10), ipv4(93, 184, 216, 37), 51518, 443, make_tls_client_hello_payload(), 0x18)},
        })
    );
}

std::filesystem::path write_single_quic_capture(const std::string& name) {
    return write_temp_pcap(
        name,
        make_classic_pcap({
            {100, make_ethernet_ipv4_udp_packet_with_bytes_payload(
                ipv4(192, 168, 54, 10), ipv4(93, 184, 216, 38), 51519, 443, make_quic_initial_like_payload())},
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

    {
        CaptureSession session {};
        const auto capture_path = write_single_tcp_443_unknown_capture("pfl_possible_tls_setting_off.pcap");

        PFL_EXPECT(session.open_capture(capture_path));
        const auto rows = session.list_flows();
        PFL_EXPECT(rows.size() == 1);
        PFL_EXPECT(rows[0].protocol_hint.empty());
    }

    {
        CaptureSession session {};
        const auto capture_path = write_single_tcp_443_unknown_capture("pfl_possible_tls_setting_on.pcap");

        PFL_EXPECT(session.open_capture(capture_path, CaptureImportOptions {
            .mode = ImportMode::fast,
            .settings = AnalysisSettings {.use_possible_tls_quic = true},
        }));
        const auto rows = session.list_flows();
        PFL_EXPECT(rows.size() == 1);
        PFL_EXPECT(rows[0].protocol_hint == "possible_tls");
    }

    {
        CaptureSession session {};
        const auto capture_path = write_single_udp_443_unknown_capture("pfl_possible_quic_setting_on.pcap");

        PFL_EXPECT(session.open_capture(capture_path, CaptureImportOptions {
            .mode = ImportMode::fast,
            .settings = AnalysisSettings {.use_possible_tls_quic = true},
        }));
        const auto rows = session.list_flows();
        PFL_EXPECT(rows.size() == 1);
        PFL_EXPECT(rows[0].protocol_hint == "possible_quic");
    }

    {
        CaptureSession session {};
        const auto capture_path = write_single_tls_capture("pfl_possible_tls_confirmed_tls.pcap");

        PFL_EXPECT(session.open_capture(capture_path, CaptureImportOptions {
            .mode = ImportMode::fast,
            .settings = AnalysisSettings {.use_possible_tls_quic = true},
        }));
        const auto rows = session.list_flows();
        PFL_EXPECT(rows.size() == 1);
        PFL_EXPECT(rows[0].protocol_hint == "tls");
        PFL_EXPECT(rows[0].service_hint == "example.org");
    }

    {
        CaptureSession session {};
        const auto capture_path = write_single_quic_capture("pfl_possible_tls_confirmed_quic.pcap");

        PFL_EXPECT(session.open_capture(capture_path, CaptureImportOptions {
            .mode = ImportMode::fast,
            .settings = AnalysisSettings {.use_possible_tls_quic = true},
        }));
        const auto rows = session.list_flows();
        PFL_EXPECT(rows.size() == 1);
        PFL_EXPECT(rows[0].protocol_hint == "quic");
    }
}

}  // namespace pfl::tests
