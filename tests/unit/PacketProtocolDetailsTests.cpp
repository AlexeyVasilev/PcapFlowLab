#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

#include "TestSupport.h"
#include "PcapTestUtils.h"
#include "app/session/CaptureSession.h"

namespace pfl::tests {

namespace {

void append_be16(std::vector<std::uint8_t>& bytes, const std::uint16_t value) {
    bytes.push_back(static_cast<std::uint8_t>((value >> 8U) & 0xFFU));
    bytes.push_back(static_cast<std::uint8_t>(value & 0xFFU));
}

void append_be24(std::vector<std::uint8_t>& bytes, const std::uint32_t value) {
    bytes.push_back(static_cast<std::uint8_t>((value >> 16U) & 0xFFU));
    bytes.push_back(static_cast<std::uint8_t>((value >> 8U) & 0xFFU));
    bytes.push_back(static_cast<std::uint8_t>(value & 0xFFU));
}

constexpr std::string_view kNoProtocolDetailsMessage = "No protocol-specific details available for this packet.";
constexpr std::string_view kUnavailableProtocolDetailsMessage = "Protocol details unavailable for this packet.";

std::filesystem::path fixture_path(const std::filesystem::path& relative_path) {
    return std::filesystem::path(__FILE__).parent_path().parent_path() / "data" / relative_path;
}

PacketRef require_packet(CaptureSession& session, const std::uint64_t packet_index) {
    const auto packet = session.find_packet(packet_index);
    PFL_EXPECT(packet.has_value());
    return *packet;
}

std::vector<std::uint8_t> make_tls_client_hello_payload() {
    const std::vector<std::uint8_t> server_name {'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'o', 'r', 'g'};

    std::vector<std::uint8_t> extension_data {};
    append_be16(extension_data, static_cast<std::uint16_t>(server_name.size() + 3U));
    extension_data.push_back(0x00U);
    append_be16(extension_data, static_cast<std::uint16_t>(server_name.size()));
    extension_data.insert(extension_data.end(), server_name.begin(), server_name.end());

    std::vector<std::uint8_t> extensions {};
    append_be16(extensions, 0x0000U);
    append_be16(extensions, static_cast<std::uint16_t>(extension_data.size()));
    extensions.insert(extensions.end(), extension_data.begin(), extension_data.end());

    std::vector<std::uint8_t> body {};
    body.push_back(0x03U);
    body.push_back(0x03U);
    for (std::uint8_t index = 0U; index < 32U; ++index) {
        body.push_back(index);
    }
    body.push_back(0x00U);
    append_be16(body, 0x0002U);
    append_be16(body, 0x1301U);
    body.push_back(0x01U);
    body.push_back(0x00U);
    append_be16(body, static_cast<std::uint16_t>(extensions.size()));
    body.insert(body.end(), extensions.begin(), extensions.end());

    std::vector<std::uint8_t> payload {};
    payload.push_back(0x16U);
    payload.push_back(0x03U);
    payload.push_back(0x03U);
    append_be16(payload, static_cast<std::uint16_t>(body.size() + 4U));
    payload.push_back(0x01U);
    payload.push_back(static_cast<std::uint8_t>((body.size() >> 16U) & 0xFFU));
    payload.push_back(static_cast<std::uint8_t>((body.size() >> 8U) & 0xFFU));
    payload.push_back(static_cast<std::uint8_t>(body.size() & 0xFFU));
    payload.insert(payload.end(), body.begin(), body.end());
    return payload;
}

void append_quic_small_varint(std::vector<std::uint8_t>& bytes, const std::uint8_t value) {
    PFL_EXPECT(value < 64U);
    bytes.push_back(value);
}

std::vector<std::uint8_t> make_plaintext_quic_initial_payload(const std::vector<std::uint8_t>& frame_bytes) {
    std::vector<std::uint8_t> payload {
        0xC0U,
        0x00U, 0x00U, 0x00U, 0x01U,
        0x08U,
        0x11U, 0x22U, 0x33U, 0x44U, 0x55U, 0x66U, 0x77U, 0x88U,
        0x08U,
        0x99U, 0xAAU, 0xBBU, 0xCCU, 0xDDU, 0xEEU, 0xFFU, 0x00U,
        0x00U,
    };

    append_quic_small_varint(payload, static_cast<std::uint8_t>(frame_bytes.size() + 1U));
    payload.push_back(0x00U);
    payload.insert(payload.end(), frame_bytes.begin(), frame_bytes.end());
    return payload;
}

std::vector<std::uint8_t> make_quic_crypto_frame_bytes(const std::vector<std::uint8_t>& crypto_bytes) {
    std::vector<std::uint8_t> frame {0x06U, 0x00U};
    append_quic_small_varint(frame, static_cast<std::uint8_t>(crypto_bytes.size()));
    frame.insert(frame.end(), crypto_bytes.begin(), crypto_bytes.end());
    return frame;
}

std::vector<std::uint8_t> make_tls_server_hello_handshake_bytes() {
    std::vector<std::uint8_t> body {};
    append_be16(body, 0x0303U);
    for (std::uint8_t index = 0U; index < 32U; ++index) {
        body.push_back(static_cast<std::uint8_t>(0xA0U + index));
    }
    body.push_back(0x00U);
    append_be16(body, 0x1301U);
    body.push_back(0x00U);

    std::vector<std::uint8_t> extensions {};
    append_be16(extensions, 0x002BU);
    append_be16(extensions, 0x0002U);
    extensions.push_back(0x03U);
    extensions.push_back(0x04U);

    append_be16(body, static_cast<std::uint16_t>(extensions.size()));
    body.insert(body.end(), extensions.begin(), extensions.end());

    std::vector<std::uint8_t> handshake {0x02U};
    append_be24(handshake, static_cast<std::uint32_t>(body.size()));
    handshake.insert(handshake.end(), body.begin(), body.end());
    return handshake;
}

std::vector<std::uint8_t> make_quic_truncated_payload() {
    return {
        0xC0U,
        0x00U, 0x00U, 0x00U, 0x01U,
        0x08U,
        0x11U, 0x22U, 0x33U, 0x44U,
    };
}

}  // namespace

void run_packet_protocol_details_tests() {
    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/tls/tls_client_hello_1.pcap"), CaptureImportOptions {.mode = ImportMode::fast}));
        const auto packet = require_packet(session, 0);
        const auto text = session.read_packet_protocol_details_text(packet);
        PFL_EXPECT(text.find("TLS") != std::string::npos);
        PFL_EXPECT(text.find("Handshake Type: ClientHello") != std::string::npos);
        PFL_EXPECT(text.find("Cipher Suites:") != std::string::npos);
        PFL_EXPECT(text.find("SNI: auth.split.io") != std::string::npos);
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
        PFL_EXPECT(text.find("Handshake Version:") != std::string::npos);
        PFL_EXPECT(text.find("Cipher Suites:") != std::string::npos);
        PFL_EXPECT(text.find("Extensions:") != std::string::npos);
        PFL_EXPECT(text.find("SNI: auth.split.io") != std::string::npos);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/tls/tls_1_3_server_hello_6.pcap"), CaptureImportOptions {.mode = ImportMode::deep}));
        const auto packet = require_packet(session, 0);
        const auto text = session.read_packet_protocol_details_text(packet);
        PFL_EXPECT(text.find("TLS") != std::string::npos);
        PFL_EXPECT(text.find("Handshake Type: ServerHello") != std::string::npos);
        PFL_EXPECT(text.find("Selected TLS Version:") != std::string::npos);
        PFL_EXPECT(text.find("Selected Cipher Suite:") != std::string::npos);
        PFL_EXPECT(text.find("Session ID:") != std::string::npos);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/quic/quic_initial_ch_1.pcap"), CaptureImportOptions {.mode = ImportMode::fast}));
        const auto packet = require_packet(session, 0);
        const auto text = session.read_packet_protocol_details_text(packet);
        PFL_EXPECT(text.find("QUIC") != std::string::npos);
        PFL_EXPECT(text.find("Header Form: Long") != std::string::npos);
        PFL_EXPECT(text.find("Packet Type: Initial") != std::string::npos);
        PFL_EXPECT(text.find("Version:") != std::string::npos);
        PFL_EXPECT(text.find("Destination Connection ID Length:") != std::string::npos);
        PFL_EXPECT(text.find("Source Connection ID Length:") != std::string::npos);
        PFL_EXPECT(text.find("TLS Handshake Type: ClientHello") != std::string::npos);
        PFL_EXPECT(text.find("Cipher Suites:") != std::string::npos);
        PFL_EXPECT(text.find("Supported Versions:") != std::string::npos);
        PFL_EXPECT(text.find("SNI:") != std::string::npos);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/quic/quic_handshake_3.pcap"), CaptureImportOptions {.mode = ImportMode::deep}));
        const auto packet = require_packet(session, 0);
        const auto text = session.read_packet_protocol_details_text(packet);
        PFL_EXPECT(text.find("QUIC") != std::string::npos);
        PFL_EXPECT(text.find("Header Form: Long") != std::string::npos);
        PFL_EXPECT(text.find("Packet Type: Handshake") != std::string::npos);
        PFL_EXPECT(text.find("Destination Connection ID Length:") != std::string::npos);
    }

    {
        const auto packet_bytes = make_ethernet_ipv4_udp_packet_with_bytes_payload(
            ipv4(10, 1, 0, 7), ipv4(8, 8, 8, 8), 54000, 443,
            make_plaintext_quic_initial_payload(make_quic_crypto_frame_bytes(make_tls_server_hello_handshake_bytes())));
        const auto capture_path = write_temp_pcap(
            "pfl_protocol_quic_server_hello_plaintext.pcap",
            make_classic_pcap({{100, packet_bytes}})
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(capture_path, CaptureImportOptions {.mode = ImportMode::deep}));
        const auto packet = require_packet(session, 0);
        const auto text = session.read_packet_protocol_details_text(packet);
        PFL_EXPECT(text.find("QUIC") != std::string::npos);
        PFL_EXPECT(text.find("Frame Presence: CRYPTO") != std::string::npos);
        PFL_EXPECT(text.find("TLS Handshake Type: ServerHello") != std::string::npos);
        PFL_EXPECT(text.find("Selected TLS Version:") != std::string::npos);
        PFL_EXPECT(text.find("Selected Cipher Suite:") != std::string::npos);
    }

    {
        const auto source_path = write_temp_pcap(
            "pfl_protocol_details_missing_source_tls.pcap",
            make_classic_pcap({
                {100, make_ethernet_ipv4_tcp_packet_with_bytes_payload(
                    ipv4(192, 168, 50, 10), ipv4(93, 184, 216, 34), 51515, 443, make_tls_client_hello_payload(), 0x18)},
            })
        );
        const auto index_path = std::filesystem::temp_directory_path() / "pfl_protocol_details_missing_source.idx";
        const auto moved_source_path = std::filesystem::temp_directory_path() / "pfl_protocol_details_missing_source.gone.pcap";
        std::filesystem::remove(index_path);
        std::filesystem::remove(moved_source_path);

        CaptureSession original_session {};
        PFL_EXPECT(original_session.open_capture(source_path, CaptureImportOptions {.mode = ImportMode::fast}));
        PFL_EXPECT(original_session.save_index(index_path));
        std::filesystem::rename(source_path, moved_source_path);

        CaptureSession loaded_session {};
        PFL_EXPECT(loaded_session.load_index(index_path));
        PFL_EXPECT(!loaded_session.has_source_capture());
        const auto packet = require_packet(loaded_session, 0);
        PFL_EXPECT(loaded_session.read_packet_protocol_details_text(packet) == kUnavailableProtocolDetailsMessage);
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
        const auto packet_bytes = make_ethernet_ipv4_udp_packet_with_bytes_payload(
            ipv4(10, 1, 0, 5), ipv4(8, 8, 8, 8), 54000, 443, make_quic_truncated_payload());
        const auto capture_path = write_temp_pcap(
            "pfl_protocol_quic_truncated.pcap",
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
        const auto text = session.read_packet_protocol_details_text(packet);
        PFL_EXPECT(text == kNoProtocolDetailsMessage);
        PFL_EXPECT(text.find("Cipher Suites:") == std::string::npos);
        PFL_EXPECT(text.find("Selected Cipher Suite:") == std::string::npos);
        PFL_EXPECT(text.find("Subject:") == std::string::npos);
    }
}

}  // namespace pfl::tests
