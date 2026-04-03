#include <filesystem>
#include <vector>

#include "TestSupport.h"
#include "app/session/CaptureSession.h"
#include "core/index/ImportCheckpointReader.h"
#include "core/services/ChunkedCaptureImporter.h"
#include "PcapTestUtils.h"

namespace pfl::tests {

namespace {

std::vector<std::uint8_t> make_http_request_payload() {
    constexpr char request[] =
        "GET / HTTP/1.1\r\n"
        "Host: www.example.com\r\n"
        "User-Agent: PFL\r\n"
        "\r\n";
    return std::vector<std::uint8_t>(request, request + sizeof(request) - 1);
}

std::vector<std::uint8_t> make_dns_query_payload() {
    std::vector<std::uint8_t> payload {};
    append_be16(payload, 0x1234);
    append_be16(payload, 0x0100);
    append_be16(payload, 1);
    append_be16(payload, 0);
    append_be16(payload, 0);
    append_be16(payload, 0);
    payload.push_back(7);
    payload.insert(payload.end(), {'e', 'x', 'a', 'm', 'p', 'l', 'e'});
    payload.push_back(3);
    payload.insert(payload.end(), {'c', 'o', 'm'});
    payload.push_back(0);
    append_be16(payload, 1);
    append_be16(payload, 1);
    return payload;
}

std::vector<std::uint8_t> make_quic_initial_like_payload() {
    std::vector<std::uint8_t> payload {
        0xC3, 0x00, 0x00, 0x00, 0x01,
        0x08,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x08,
        0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
        0x00,
    };
    return payload;
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

std::vector<std::uint8_t> make_ssh_banner_payload() {
    constexpr char banner[] = "SSH-2.0-OpenSSH_9.6\r\n";
    return std::vector<std::uint8_t>(banner, banner + sizeof(banner) - 1);
}

std::vector<std::uint8_t> make_stun_binding_request_payload() {
    std::vector<std::uint8_t> payload {};
    append_be16(payload, 0x0001U);
    append_be16(payload, 0x0000U);
    append_be32(payload, 0x2112A442U);
    payload.insert(payload.end(), {
        0x10, 0x11, 0x12, 0x13,
        0x20, 0x21, 0x22, 0x23,
        0x30, 0x31, 0x32, 0x33,
    });
    return payload;
}

std::vector<std::uint8_t> make_bittorrent_handshake_payload() {
    std::vector<std::uint8_t> payload {};
    payload.push_back(19U);
    payload.insert(payload.end(), {
        'B', 'i', 't', 'T', 'o', 'r', 'r', 'e', 'n', 't',
        ' ', 'p', 'r', 'o', 't', 'o', 'c', 'o', 'l',
    });
    payload.insert(payload.end(), 8U, 0x00U);
    for (std::uint8_t index = 0; index < 20U; ++index) {
        payload.push_back(index);
    }
    for (std::uint8_t index = 0; index < 20U; ++index) {
        payload.push_back(static_cast<std::uint8_t>(0x41U + index));
    }
    return payload;
}

std::vector<std::uint8_t> make_smtp_greeting_payload() {
    constexpr char greeting[] = "220 mail.example.org ESMTP ready\r\n";
    return std::vector<std::uint8_t>(greeting, greeting + sizeof(greeting) - 1);
}

std::vector<std::uint8_t> make_smtp_ehlo_payload() {
    constexpr char ehlo[] = "EHLO client.example.org\r\n";
    return std::vector<std::uint8_t>(ehlo, ehlo + sizeof(ehlo) - 1);
}

std::vector<std::uint8_t> make_pop3_ok_payload() {
    constexpr char greeting[] = "+OK POP3 server ready\r\n";
    return std::vector<std::uint8_t>(greeting, greeting + sizeof(greeting) - 1);
}

std::vector<std::uint8_t> make_pop3_user_payload() {
    constexpr char user[] = "USER alex\r\n";
    return std::vector<std::uint8_t>(user, user + sizeof(user) - 1);
}

std::vector<std::uint8_t> make_imap_ok_payload() {
    constexpr char greeting[] = "* OK IMAP4 ready\r\n";
    return std::vector<std::uint8_t>(greeting, greeting + sizeof(greeting) - 1);
}

std::vector<std::uint8_t> make_dhcp_payload() {
    std::vector<std::uint8_t> payload(240U, 0U);
    payload[0] = 0x01U; // BOOTREQUEST
    payload[1] = 0x01U; // Ethernet
    payload[2] = 0x06U; // MAC length
    payload[236] = 0x63U;
    payload[237] = 0x82U;
    payload[238] = 0x53U;
    payload[239] = 0x63U;
    return payload;
}

std::vector<std::uint8_t> make_dual_stun_and_dhcp_payload() {
    auto payload = make_dhcp_payload();
    // Also satisfy the STUN cheap detector shape: 20 + message_length == 240.
    payload[0] = 0x00U;
    payload[1] = 0x01U;
    payload[2] = 0x00U;
    payload[3] = 0xDCU; // 220 bytes, divisible by 4.
    payload[4] = 0x21U;
    payload[5] = 0x12U;
    payload[6] = 0xA4U;
    payload[7] = 0x42U;
    return payload;
}
std::vector<std::uint8_t> make_mdns_payload() {
    std::vector<std::uint8_t> payload {};
    append_be16(payload, 0x0000U);
    append_be16(payload, 0x0000U);
    append_be16(payload, 0x0001U);
    append_be16(payload, 0x0000U);
    append_be16(payload, 0x0000U);
    append_be16(payload, 0x0000U);
    return payload;
}

}  // namespace

void run_flow_hints_tests() {
    {
        const auto path = write_temp_pcap(
            "pfl_flow_hint_tls.pcap",
            make_classic_pcap({
                {100, make_ethernet_ipv4_tcp_packet_with_bytes_payload(
                    ipv4(10, 0, 0, 1), ipv4(10, 0, 0, 2), 50123, 443, make_tls_client_hello_payload(), 0x18)},
            })
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(path));
        const auto rows = session.list_flows();
        PFL_EXPECT(rows.size() == 1);
        PFL_EXPECT(rows[0].protocol_hint == "tls");
        PFL_EXPECT(rows[0].service_hint == "example.org");
    }

    {
        const auto path = write_temp_pcap(
            "pfl_flow_hint_http.pcap",
            make_classic_pcap({
                {100, make_ethernet_ipv4_tcp_packet_with_bytes_payload(
                    ipv4(192, 168, 1, 10), ipv4(93, 184, 216, 34), 51515, 80, make_http_request_payload(), 0x18)},
            })
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(path));
        const auto rows = session.list_flows();
        PFL_EXPECT(rows.size() == 1);
        PFL_EXPECT(rows[0].protocol_hint == "http");
        PFL_EXPECT(rows[0].service_hint == "www.example.com");
    }

    {
        const auto path = write_temp_pcap(
            "pfl_flow_hint_dns.pcap",
            make_classic_pcap({
                {100, make_ethernet_ipv4_udp_packet_with_bytes_payload(
                    ipv4(10, 1, 1, 5), ipv4(8, 8, 8, 8), 53000, 53, make_dns_query_payload())},
            })
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(path));
        const auto rows = session.list_flows();
        PFL_EXPECT(rows.size() == 1);
        PFL_EXPECT(rows[0].protocol_hint == "dns");
        PFL_EXPECT(rows[0].service_hint == "example.com");
    }

    {
        const auto path = write_temp_pcap(
            "pfl_flow_hint_quic.pcap",
            make_classic_pcap({
                {100, make_ethernet_ipv4_udp_packet_with_bytes_payload(
                    ipv4(10, 2, 2, 2), ipv4(1, 1, 1, 1), 54000, 443, make_quic_initial_like_payload())},
            })
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(path));
        const auto rows = session.list_flows();
        PFL_EXPECT(rows.size() == 1);
        PFL_EXPECT(rows[0].protocol_hint == "quic");
        PFL_EXPECT(rows[0].service_hint.empty());
    }

    {
        const auto path = write_temp_pcap(
            "pfl_flow_hint_ssh_positive.pcap",
            make_classic_pcap({
                {100, make_ethernet_ipv4_tcp_packet_with_bytes_payload(
                    ipv4(10, 3, 3, 3), ipv4(10, 3, 3, 4), 53022, 22, make_ssh_banner_payload(), 0x18)},
            })
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(path));
        const auto rows = session.list_flows();
        PFL_EXPECT(rows.size() == 1);
        PFL_EXPECT(rows[0].protocol_hint == "ssh");
        PFL_EXPECT(rows[0].service_hint.empty());
    }

    {
        constexpr char invalid_ssh_banner[] = "SSX-2.0-OpenSSH_9.6\r\n";
        const auto path = write_temp_pcap(
            "pfl_flow_hint_ssh_negative.pcap",
            make_classic_pcap({
                {100, make_ethernet_ipv4_tcp_packet_with_bytes_payload(
                    ipv4(10, 3, 4, 3), ipv4(10, 3, 4, 4), 53022, 22,
                    std::vector<std::uint8_t>(invalid_ssh_banner, invalid_ssh_banner + sizeof(invalid_ssh_banner) - 1), 0x18)},
            })
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(path));
        const auto rows = session.list_flows();
        PFL_EXPECT(rows.size() == 1);
        PFL_EXPECT(rows[0].protocol_hint.empty());
        PFL_EXPECT(rows[0].service_hint.empty());
    }

    {
        const auto path = write_temp_pcap(
            "pfl_flow_hint_stun_positive.pcap",
            make_classic_pcap({
                {100, make_ethernet_ipv4_udp_packet_with_bytes_payload(
                    ipv4(10, 4, 4, 4), ipv4(10, 4, 4, 5), 51000, 3478, make_stun_binding_request_payload())},
            })
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(path));
        const auto rows = session.list_flows();
        PFL_EXPECT(rows.size() == 1);
        PFL_EXPECT(rows[0].protocol_hint == "stun");
        PFL_EXPECT(rows[0].service_hint.empty());
    }

    {
        auto payload = make_stun_binding_request_payload();
        payload[7] ^= 0x01U;

        const auto path = write_temp_pcap(
            "pfl_flow_hint_stun_negative.pcap",
            make_classic_pcap({
                {100, make_ethernet_ipv4_udp_packet_with_bytes_payload(
                    ipv4(10, 4, 5, 4), ipv4(10, 4, 5, 5), 51000, 3478, payload)},
            })
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(path));
        const auto rows = session.list_flows();
        PFL_EXPECT(rows.size() == 1);
        PFL_EXPECT(rows[0].protocol_hint.empty());
        PFL_EXPECT(rows[0].service_hint.empty());
    }

    {
        const auto path = write_temp_pcap(
            "pfl_flow_hint_bittorrent_positive.pcap",
            make_classic_pcap({
                {100, make_ethernet_ipv4_tcp_packet_with_bytes_payload(
                    ipv4(10, 5, 5, 5), ipv4(10, 5, 5, 6), 51413, 6881, make_bittorrent_handshake_payload(), 0x18)},
            })
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(path));
        const auto rows = session.list_flows();
        PFL_EXPECT(rows.size() == 1);
        PFL_EXPECT(rows[0].protocol_hint == "bittorrent");
        PFL_EXPECT(rows[0].service_hint.empty());
    }

    {
        auto payload = make_bittorrent_handshake_payload();
        payload[1] = static_cast<std::uint8_t>('X');

        const auto path = write_temp_pcap(
            "pfl_flow_hint_bittorrent_negative.pcap",
            make_classic_pcap({
                {100, make_ethernet_ipv4_tcp_packet_with_bytes_payload(
                    ipv4(10, 5, 6, 5), ipv4(10, 5, 6, 6), 51413, 6881, payload, 0x18)},
            })
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(path));
        const auto rows = session.list_flows();
        PFL_EXPECT(rows.size() == 1);
        PFL_EXPECT(rows[0].protocol_hint.empty());
        PFL_EXPECT(rows[0].service_hint.empty());
    }

    {
        const auto path = write_temp_pcap(
            "pfl_flow_hint_smtp_positive_greeting.pcap",
            make_classic_pcap({
                {100, make_ethernet_ipv4_tcp_packet_with_bytes_payload(
                    ipv4(10, 9, 9, 9), ipv4(10, 9, 9, 10), 25, 41234, make_smtp_greeting_payload(), 0x18)},
            })
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(path));
        const auto rows = session.list_flows();
        PFL_EXPECT(rows.size() == 1);
        PFL_EXPECT(rows[0].protocol_hint == "smtp");
        PFL_EXPECT(rows[0].service_hint.empty());
    }

    {
        const auto path = write_temp_pcap(
            "pfl_flow_hint_smtp_positive_ehlo.pcap",
            make_classic_pcap({
                {100, make_ethernet_ipv4_tcp_packet_with_bytes_payload(
                    ipv4(10, 9, 10, 9), ipv4(10, 9, 10, 10), 50123, 587, make_smtp_ehlo_payload(), 0x18)},
            })
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(path));
        const auto rows = session.list_flows();
        PFL_EXPECT(rows.size() == 1);
        PFL_EXPECT(rows[0].protocol_hint == "smtp");
        PFL_EXPECT(rows[0].service_hint.empty());
    }

    {
        constexpr char unrelated_payload[] = "NOOPING BUT NOT SMTP\r\n";
        const auto path = write_temp_pcap(
            "pfl_flow_hint_smtp_negative_unrelated_payload.pcap",
            make_classic_pcap({
                {100, make_ethernet_ipv4_tcp_packet_with_bytes_payload(
                    ipv4(10, 9, 11, 9), ipv4(10, 9, 11, 10), 25, 41234,
                    std::vector<std::uint8_t>(unrelated_payload, unrelated_payload + sizeof(unrelated_payload) - 1), 0x18)},
            })
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(path));
        const auto rows = session.list_flows();
        PFL_EXPECT(rows.size() == 1);
        PFL_EXPECT(rows[0].protocol_hint.empty());
        PFL_EXPECT(rows[0].service_hint.empty());
    }

    {
        const auto path = write_temp_pcap(
            "pfl_flow_hint_precedence_tls_over_smtp.pcap",
            make_classic_pcap({
                {100, make_ethernet_ipv4_tcp_packet_with_bytes_payload(
                    ipv4(10, 9, 12, 9), ipv4(10, 9, 12, 10), 50123, 587, make_tls_client_hello_payload(), 0x18)},
            })
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(path));
        const auto rows = session.list_flows();
        PFL_EXPECT(rows.size() == 1);
        PFL_EXPECT(rows[0].protocol_hint == "tls");
        PFL_EXPECT(rows[0].service_hint == "example.org");
    }

    {
        const auto path = write_temp_pcap(
            "pfl_flow_hint_pop3_positive_ok.pcap",
            make_classic_pcap({
                {100, make_ethernet_ipv4_tcp_packet_with_bytes_payload(
                    ipv4(10, 9, 13, 9), ipv4(10, 9, 13, 10), 110, 40110, make_pop3_ok_payload(), 0x18)},
            })
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(path));
        const auto rows = session.list_flows();
        PFL_EXPECT(rows.size() == 1);
        PFL_EXPECT(rows[0].protocol_hint == "pop3");
        PFL_EXPECT(rows[0].service_hint.empty());
    }

    {
        const auto path = write_temp_pcap(
            "pfl_flow_hint_pop3_positive_user.pcap",
            make_classic_pcap({
                {100, make_ethernet_ipv4_tcp_packet_with_bytes_payload(
                    ipv4(10, 9, 14, 9), ipv4(10, 9, 14, 10), 40110, 110, make_pop3_user_payload(), 0x18)},
            })
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(path));
        const auto rows = session.list_flows();
        PFL_EXPECT(rows.size() == 1);
        PFL_EXPECT(rows[0].protocol_hint == "pop3");
        PFL_EXPECT(rows[0].service_hint.empty());
    }

    {
        constexpr char unrelated_payload[] = "HELLO NOT POP3\r\n";
        const auto path = write_temp_pcap(
            "pfl_flow_hint_pop3_negative_unrelated_payload.pcap",
            make_classic_pcap({
                {100, make_ethernet_ipv4_tcp_packet_with_bytes_payload(
                    ipv4(10, 9, 15, 9), ipv4(10, 9, 15, 10), 110, 40110,
                    std::vector<std::uint8_t>(unrelated_payload, unrelated_payload + sizeof(unrelated_payload) - 1), 0x18)},
            })
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(path));
        const auto rows = session.list_flows();
        PFL_EXPECT(rows.size() == 1);
        PFL_EXPECT(rows[0].protocol_hint.empty());
        PFL_EXPECT(rows[0].service_hint.empty());
    }

    {
        const auto path = write_temp_pcap(
            "pfl_flow_hint_precedence_tls_over_pop3.pcap",
            make_classic_pcap({
                {100, make_ethernet_ipv4_tcp_packet_with_bytes_payload(
                    ipv4(10, 9, 16, 9), ipv4(10, 9, 16, 10), 40110, 110, make_tls_client_hello_payload(), 0x18)},
            })
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(path));
        const auto rows = session.list_flows();
        PFL_EXPECT(rows.size() == 1);
        PFL_EXPECT(rows[0].protocol_hint == "tls");
        PFL_EXPECT(rows[0].service_hint == "example.org");
    }

    {
        const auto path = write_temp_pcap(
            "pfl_flow_hint_imap_positive_ok.pcap",
            make_classic_pcap({
                {100, make_ethernet_ipv4_tcp_packet_with_bytes_payload(
                    ipv4(10, 9, 17, 9), ipv4(10, 9, 17, 10), 143, 40143, make_imap_ok_payload(), 0x18)},
            })
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(path));
        const auto rows = session.list_flows();
        PFL_EXPECT(rows.size() == 1);
        PFL_EXPECT(rows[0].protocol_hint == "imap");
        PFL_EXPECT(rows[0].service_hint.empty());
    }

    {
        constexpr char unrelated_payload[] = "HELLO NOT IMAP\r\n";
        const auto path = write_temp_pcap(
            "pfl_flow_hint_imap_negative_unrelated_payload.pcap",
            make_classic_pcap({
                {100, make_ethernet_ipv4_tcp_packet_with_bytes_payload(
                    ipv4(10, 9, 18, 9), ipv4(10, 9, 18, 10), 143, 40143,
                    std::vector<std::uint8_t>(unrelated_payload, unrelated_payload + sizeof(unrelated_payload) - 1), 0x18)},
            })
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(path));
        const auto rows = session.list_flows();
        PFL_EXPECT(rows.size() == 1);
        PFL_EXPECT(rows[0].protocol_hint.empty());
        PFL_EXPECT(rows[0].service_hint.empty());
    }

    {
        const auto path = write_temp_pcap(
            "pfl_flow_hint_precedence_tls_over_imap.pcap",
            make_classic_pcap({
                {100, make_ethernet_ipv4_tcp_packet_with_bytes_payload(
                    ipv4(10, 9, 19, 9), ipv4(10, 9, 19, 10), 40143, 143, make_tls_client_hello_payload(), 0x18)},
            })
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(path));
        const auto rows = session.list_flows();
        PFL_EXPECT(rows.size() == 1);
        PFL_EXPECT(rows[0].protocol_hint == "tls");
        PFL_EXPECT(rows[0].service_hint == "example.org");
    }

    {
        const auto path = write_temp_pcap(
            "pfl_flow_hint_dhcp_positive.pcap",
            make_classic_pcap({
                {100, make_ethernet_ipv4_udp_packet_with_bytes_payload(
                    ipv4(10, 7, 7, 7), ipv4(10, 7, 7, 8), 68, 67, make_dhcp_payload())},
            })
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(path));
        const auto rows = session.list_flows();
        PFL_EXPECT(rows.size() == 1);
        PFL_EXPECT(rows[0].protocol_hint == "dhcp");
        PFL_EXPECT(rows[0].service_hint.empty());
    }

    {
        auto payload = make_dhcp_payload();
        payload[239] ^= 0x01U;

        const auto path = write_temp_pcap(
            "pfl_flow_hint_dhcp_negative_bad_cookie.pcap",
            make_classic_pcap({
                {100, make_ethernet_ipv4_udp_packet_with_bytes_payload(
                    ipv4(10, 7, 8, 7), ipv4(10, 7, 8, 8), 68, 67, payload)},
            })
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(path));
        const auto rows = session.list_flows();
        PFL_EXPECT(rows.size() == 1);
        PFL_EXPECT(rows[0].protocol_hint.empty());
        PFL_EXPECT(rows[0].service_hint.empty());
    }

    {
        const auto path = write_temp_pcap(
            "pfl_flow_hint_precedence_dhcp_over_stun.pcap",
            make_classic_pcap({
                {100, make_ethernet_ipv4_udp_packet_with_bytes_payload(
                    ipv4(10, 7, 9, 7), ipv4(10, 7, 9, 8), 68, 67, make_dual_stun_and_dhcp_payload())},
            })
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(path));
        const auto rows = session.list_flows();
        PFL_EXPECT(rows.size() == 1);
        PFL_EXPECT(rows[0].protocol_hint == "dhcp");
        PFL_EXPECT(rows[0].service_hint.empty());
    }
    {
        const auto path = write_temp_pcap(
            "pfl_flow_hint_mdns_positive.pcap",
            make_classic_pcap({
                {100, make_ethernet_ipv4_udp_packet_with_bytes_payload(
                    ipv4(10, 8, 8, 8), ipv4(224, 0, 0, 251), 5353, 5353, make_mdns_payload())},
            })
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(path));
        const auto rows = session.list_flows();
        PFL_EXPECT(rows.size() == 1);
        PFL_EXPECT(rows[0].protocol_hint == "mdns");
        PFL_EXPECT(rows[0].service_hint.empty());
    }

    {
        std::vector<std::uint8_t> invalid_payload(12U, 0U);

        const auto path = write_temp_pcap(
            "pfl_flow_hint_mdns_negative_invalid_payload.pcap",
            make_classic_pcap({
                {100, make_ethernet_ipv4_udp_packet_with_bytes_payload(
                    ipv4(10, 8, 9, 8), ipv4(224, 0, 0, 251), 5353, 5353, invalid_payload)},
            })
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(path));
        const auto rows = session.list_flows();
        PFL_EXPECT(rows.size() == 1);
        PFL_EXPECT(rows[0].protocol_hint.empty());
        PFL_EXPECT(rows[0].service_hint.empty());
    }

    {
        const auto path = write_temp_pcap(
            "pfl_flow_hint_mdns_negative_unicast_destination.pcap",
            make_classic_pcap({
                {100, make_ethernet_ipv4_udp_packet_with_bytes_payload(
                    ipv4(10, 8, 10, 8), ipv4(10, 8, 10, 9), 5353, 5353, make_mdns_payload())},
            })
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(path));
        const auto rows = session.list_flows();
        PFL_EXPECT(rows.size() == 1);
        PFL_EXPECT(rows[0].protocol_hint.empty());
        PFL_EXPECT(rows[0].service_hint.empty());
    }
    {
        const auto path = write_temp_pcap(
            "pfl_flow_hint_precedence_tls_over_cheap.pcap",
            make_classic_pcap({
                {100, make_ethernet_ipv4_tcp_packet_with_bytes_payload(
                    ipv4(10, 6, 6, 6), ipv4(10, 6, 6, 7), 50123, 443, make_tls_client_hello_payload(), 0x18)},
                {200, make_ethernet_ipv4_tcp_packet_with_bytes_payload(
                    ipv4(10, 6, 6, 6), ipv4(10, 6, 6, 7), 50123, 443, make_ssh_banner_payload(), 0x18)},
            })
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(path));
        const auto rows = session.list_flows();
        PFL_EXPECT(rows.size() == 1);
        PFL_EXPECT(rows[0].protocol_hint == "tls");
        PFL_EXPECT(rows[0].service_hint == "example.org");
    }

    {
        const auto http_capture_path = write_temp_pcap(
            "pfl_flow_hint_roundtrip.pcap",
            make_classic_pcap({
                {100, make_ethernet_ipv4_tcp_packet_with_bytes_payload(
                    ipv4(192, 168, 1, 10), ipv4(93, 184, 216, 34), 51515, 80, make_http_request_payload(), 0x18)},
            })
        );
        const auto index_path = std::filesystem::temp_directory_path() / "pfl_flow_hint_roundtrip.idx";
        const auto checkpoint_path = std::filesystem::temp_directory_path() / "pfl_flow_hint_roundtrip.ckp";
        std::filesystem::remove(index_path);
        std::filesystem::remove(checkpoint_path);

        CaptureSession original_session {};
        PFL_EXPECT(original_session.open_capture(http_capture_path));
        PFL_EXPECT(original_session.save_index(index_path));

        CaptureSession loaded_session {};
        PFL_EXPECT(loaded_session.load_index(index_path));
        const auto loaded_rows = loaded_session.list_flows();
        PFL_EXPECT(loaded_rows.size() == 1);
        PFL_EXPECT(loaded_rows[0].protocol_hint == "http");
        PFL_EXPECT(loaded_rows[0].service_hint == "www.example.com");

        ChunkedCaptureImporter importer {};
        PFL_EXPECT(importer.import_chunk(http_capture_path, checkpoint_path, 1) == ChunkedImportStatus::completed);

        ImportCheckpointReader checkpoint_reader {};
        ImportCheckpoint checkpoint {};
        PFL_EXPECT(checkpoint_reader.read(checkpoint_path, checkpoint));
        PFL_EXPECT(checkpoint.state.ipv4_connections.size() == 1);
        const auto* connection = checkpoint.state.ipv4_connections.list().front();
        PFL_EXPECT(connection->protocol_hint == FlowProtocolHint::http);
        PFL_EXPECT(connection->service_hint == "www.example.com");
    }

    {
        const auto path = write_temp_pcap(
            "pfl_flow_hint_truncated_tls.pcap",
            make_classic_pcap({
                {100, make_ethernet_ipv4_tcp_packet_with_bytes_payload(
                    ipv4(10, 0, 0, 1), ipv4(10, 0, 0, 2), 50123, 443, {0x16, 0x03, 0x03}, 0x10)},
            })
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(path));
        const auto rows = session.list_flows();
        PFL_EXPECT(rows.size() == 1);
        PFL_EXPECT(rows[0].protocol_hint.empty());
        PFL_EXPECT(rows[0].service_hint.empty());
    }
}

}  // namespace pfl::tests

