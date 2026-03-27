#include <filesystem>
#include <string>
#include <string_view>
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
        PFL_EXPECT(session.open_capture(fixture_path("parsing/dns/dns_request_1.pcap"), CaptureImportOptions {.mode = ImportMode::fast}));
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
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/dns/dns_request_1.pcap"), CaptureImportOptions {.mode = ImportMode::deep}));
        const auto packet = require_packet(session, 0);
        const auto text = session.read_packet_protocol_details_text(packet);
        PFL_EXPECT(text.find("DNS") != std::string::npos);
        PFL_EXPECT(text.find("Message Type: Query") != std::string::npos);
        PFL_EXPECT(text.find("QName: gsp85-ssl.ls.apple.com") != std::string::npos);
        PFL_EXPECT(text.find("QType: HTTPS (65)") != std::string::npos);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/http/http_get_1.pcap"), CaptureImportOptions {.mode = ImportMode::deep}));
        const auto packet = require_packet(session, 0);
        const auto text = session.read_packet_protocol_details_text(packet);
        PFL_EXPECT(text.find("HTTP") != std::string::npos);
        PFL_EXPECT(text.find("Message Type: Request") != std::string::npos);
        PFL_EXPECT(text.find("Method: GET") != std::string::npos);
        PFL_EXPECT(text.find("Path: /components/com_virtuemart/assets/css/vm-ltr-common.css?vmver=8dcacf73") != std::string::npos);
        PFL_EXPECT(text.find("Version: HTTP/1.1") != std::string::npos);
        PFL_EXPECT(text.find("Host: www.kresla-darom.ru") != std::string::npos);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/http/http_answer_2.pcap"), CaptureImportOptions {.mode = ImportMode::deep}));
        const auto packet = require_packet(session, 0);
        const auto text = session.read_packet_protocol_details_text(packet);
        PFL_EXPECT(text.find("HTTP") != std::string::npos);
        PFL_EXPECT(text.find("Message Type: Response") != std::string::npos);
        PFL_EXPECT(text.find("Version: HTTP/1.1") != std::string::npos);
        PFL_EXPECT(text.find("Status Code: 200") != std::string::npos);
    }

    {
        const auto arp_packet = make_ethernet_arp_packet(ipv4(192, 168, 1, 10), ipv4(192, 168, 1, 1), 1);
        const auto capture_path = write_temp_pcap(
            "pfl_protocol_arp_deep.pcap",
            make_classic_pcap({{100, arp_packet}})
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(capture_path, CaptureImportOptions {.mode = ImportMode::deep}));
        const auto packet = require_packet(session, 0);
        const auto text = session.read_packet_protocol_details_text(packet);
        PFL_EXPECT(text.find("ARP") != std::string::npos);
        PFL_EXPECT(text.find("Opcode: 1") != std::string::npos);
        PFL_EXPECT(text.find("Sender IPv4: 192.168.1.10") != std::string::npos);
        PFL_EXPECT(text.find("Target IPv4: 192.168.1.1") != std::string::npos);
    }

    {
        const auto icmp_packet = make_ethernet_ipv4_icmp_packet(ipv4(10, 0, 0, 10), ipv4(10, 0, 0, 20), 8, 0);
        const auto capture_path = write_temp_pcap(
            "pfl_protocol_icmp_deep.pcap",
            make_classic_pcap({{100, icmp_packet}})
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(capture_path, CaptureImportOptions {.mode = ImportMode::deep}));
        const auto packet = require_packet(session, 0);
        const auto text = session.read_packet_protocol_details_text(packet);
        PFL_EXPECT(text.find("ICMP") != std::string::npos);
        PFL_EXPECT(text.find("Type: 8") != std::string::npos);
        PFL_EXPECT(text.find("Code: 0") != std::string::npos);
        PFL_EXPECT(text.find("Source: 10.0.0.10") != std::string::npos);
        PFL_EXPECT(text.find("Destination: 10.0.0.20") != std::string::npos);
    }

    {
        const auto ipv6_src = ipv6({0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01});
        const auto ipv6_dst = ipv6({0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02});
        const auto icmpv6_packet = make_ethernet_ipv6_icmpv6_with_hop_by_hop_packet(ipv6_src, ipv6_dst, 128, 0);
        const auto capture_path = write_temp_pcap(
            "pfl_protocol_icmpv6_deep.pcap",
            make_classic_pcap({{100, icmpv6_packet}})
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(capture_path, CaptureImportOptions {.mode = ImportMode::deep}));
        const auto packet = require_packet(session, 0);
        const auto text = session.read_packet_protocol_details_text(packet);
        PFL_EXPECT(text.find("ICMPv6") != std::string::npos);
        PFL_EXPECT(text.find("Type: 128") != std::string::npos);
        PFL_EXPECT(text.find("Code: 0") != std::string::npos);
        PFL_EXPECT(text.find("Source: 2001:0db8:0000:0000:0000:0000:0000:0001") != std::string::npos);
        PFL_EXPECT(text.find("Destination: 2001:0db8:0000:0000:0000:0000:0000:0002") != std::string::npos);
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
        const std::vector<std::uint8_t> truncated_dns {
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x03, 'w', 'w', 'w', 0x00,
        };
        const auto packet_bytes = make_ethernet_ipv4_udp_packet_with_bytes_payload(
            ipv4(10, 1, 0, 1), ipv4(8, 8, 8, 8), 53000, 53, truncated_dns);
        const auto capture_path = write_temp_pcap(
            "pfl_protocol_dns_truncated.pcap",
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
