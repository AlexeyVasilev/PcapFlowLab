#include <filesystem>
#include <string>
#include <vector>

#include "TestSupport.h"
#include "PcapTestUtils.h"
#include "app/session/CaptureSession.h"

namespace pfl::tests {

namespace {

constexpr std::string_view kFastModeMessage = "Protocol details are only available in Deep mode.";
constexpr std::string_view kNoProtocolDetailsMessage = "No protocol-specific details available for this packet.";

std::filesystem::path fixture_path(const std::filesystem::path& relative_path) {
    return std::filesystem::path(__FILE__).parent_path().parent_path() / "data" / relative_path;
}

PacketRef require_packet(CaptureSession& session, const std::uint64_t packet_index) {
    const auto packet = session.find_packet(packet_index);
    PFL_EXPECT(packet.has_value());
    return *packet;
}

}  // namespace

void run_packet_protocol_details_tests() {
    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/tls/tls_client_hello_1.pcap"), CaptureImportOptions {.mode = ImportMode::fast}));
        const auto packet = require_packet(session, 0);
        PFL_EXPECT(session.read_packet_protocol_details_text(packet) == kFastModeMessage);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/tls/tls_client_hello_1.pcap"), CaptureImportOptions {.mode = ImportMode::deep}));
        const auto packet = require_packet(session, 0);
        const auto text = session.read_packet_protocol_details_text(packet);
        PFL_EXPECT(text.find("TLS") != std::string::npos);
        PFL_EXPECT(text.find("Record Type: Handshake") != std::string::npos);
        PFL_EXPECT(text.find("Record Version:") != std::string::npos);
        PFL_EXPECT(text.find("Handshake Type: ClientHello") != std::string::npos);
        PFL_EXPECT(text.find("SNI: auth.split.io") != std::string::npos);
    }

    {
        const auto packet_bytes = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
            ipv4(10, 0, 0, 1), ipv4(10, 0, 0, 2), 1111, 80,
            std::vector<std::uint8_t> {'G', 'E', 'T', ' ', '/', ' '}, 0x18);
        const auto capture_path = write_temp_pcap(
            "pfl_protocol_http_only.pcap",
            make_classic_pcap({{100, packet_bytes}})
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(capture_path, CaptureImportOptions {.mode = ImportMode::deep}));
        const auto packet = require_packet(session, 0);
        PFL_EXPECT(session.read_packet_protocol_details_text(packet) == kNoProtocolDetailsMessage);
    }

    {
        const std::vector<std::uint8_t> truncated_tls {0x16, 0x03, 0x03, 0x00, 0x10, 0x01, 0x00};
        const auto packet_bytes = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
            ipv4(10, 0, 0, 3), ipv4(10, 0, 0, 4), 12345, 443, truncated_tls, 0x18);
        const auto capture_path = write_temp_pcap(
            "pfl_protocol_tls_truncated.pcap",
            make_classic_pcap({{100, packet_bytes}})
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(capture_path, CaptureImportOptions {.mode = ImportMode::deep}));
        const auto packet = require_packet(session, 0);
        PFL_EXPECT(session.read_packet_protocol_details_text(packet) == kNoProtocolDetailsMessage);
    }
}

}  // namespace pfl::tests

