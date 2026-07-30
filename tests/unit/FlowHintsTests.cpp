#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

#include "TestSupport.h"
#include "app/session/CaptureSession.h"
#include "core/domain/Connection.h"
#include "core/domain/FlowKey.h"
#include "core/index/ImportCheckpointReader.h"
#include "core/services/ChunkedCaptureImporter.h"
#include "core/services/FlowHintService.h"
#include "core/services/PacketPayloadService.h"
#include "PcapTestUtils.h"

namespace pfl::tests {

namespace {

constexpr std::size_t kTlsMaxRecordPayloadSize = (1U << 14U) + 2048U;

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

void append_be24(std::vector<std::uint8_t>& bytes, const std::uint32_t value) {
    bytes.push_back(static_cast<std::uint8_t>((value >> 16U) & 0xFFU));
    bytes.push_back(static_cast<std::uint8_t>((value >> 8U) & 0xFFU));
    bytes.push_back(static_cast<std::uint8_t>(value & 0xFFU));
}

std::vector<std::uint8_t> make_tls_record(
    const std::uint8_t content_type,
    const std::uint16_t legacy_version,
    const std::vector<std::uint8_t>& body
) {
    std::vector<std::uint8_t> record {};
    record.reserve(5U + body.size());
    record.push_back(content_type);
    append_be16(record, legacy_version);
    append_be16(record, static_cast<std::uint16_t>(body.size()));
    record.insert(record.end(), body.begin(), body.end());
    return record;
}

std::vector<std::uint8_t> make_tls_handshake_message(
    const std::uint8_t handshake_type,
    const std::vector<std::uint8_t>& body
) {
    std::vector<std::uint8_t> handshake {};
    handshake.reserve(4U + body.size());
    handshake.push_back(handshake_type);
    append_be24(handshake, static_cast<std::uint32_t>(body.size()));
    handshake.insert(handshake.end(), body.begin(), body.end());
    return handshake;
}

void append_tls_extension(
    std::vector<std::uint8_t>& bytes,
    const std::uint16_t extension_type,
    const std::vector<std::uint8_t>& body
) {
    append_be16(bytes, extension_type);
    append_be16(bytes, static_cast<std::uint16_t>(body.size()));
    bytes.insert(bytes.end(), body.begin(), body.end());
}

std::vector<std::uint8_t> make_tls_server_name_extension_body(const std::string_view server_name) {
    std::vector<std::uint8_t> body {};
    append_be16(body, static_cast<std::uint16_t>(server_name.size() + 3U));
    body.push_back(0x00U);
    append_be16(body, static_cast<std::uint16_t>(server_name.size()));
    body.insert(body.end(), server_name.begin(), server_name.end());
    return body;
}

std::vector<std::uint8_t> make_minimal_client_hello_payload_with_extensions(
    const std::vector<std::uint8_t>& extensions,
    const std::vector<std::uint8_t>& session_id = {},
    const std::vector<std::uint8_t>& cipher_suites = {0x13U, 0x01U},
    const std::vector<std::uint8_t>& compression_methods = {0x00U}
) {
    std::vector<std::uint8_t> body {};
    append_be16(body, 0x0303U);
    for (std::uint8_t index = 0U; index < 32U; ++index) {
        body.push_back(index);
    }
    body.push_back(static_cast<std::uint8_t>(session_id.size()));
    body.insert(body.end(), session_id.begin(), session_id.end());
    append_be16(body, static_cast<std::uint16_t>(cipher_suites.size()));
    body.insert(body.end(), cipher_suites.begin(), cipher_suites.end());
    body.push_back(static_cast<std::uint8_t>(compression_methods.size()));
    body.insert(body.end(), compression_methods.begin(), compression_methods.end());
    append_be16(body, static_cast<std::uint16_t>(extensions.size()));
    body.insert(body.end(), extensions.begin(), extensions.end());
    return make_tls_record(0x16U, 0x0303U, make_tls_handshake_message(0x01U, body));
}

FlowHintUpdate detect_tcp_flow_hint(
    const std::vector<std::uint8_t>& payload,
    const std::uint16_t src_port = 50123U,
    const std::uint16_t dst_port = 443U
) {
    FlowHintService service {};
    const auto packet = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
        ipv4(10, 0, 0, 1),
        ipv4(10, 0, 0, 2),
        src_port,
        dst_port,
        payload,
        0x18
    );
    return service.detect(packet, FlowKeyV4 {
        .src_addr = ipv4(10, 0, 0, 1),
        .dst_addr = ipv4(10, 0, 0, 2),
        .src_port = src_port,
        .dst_port = dst_port,
        .protocol = ProtocolId::tcp,
    });
}

std::vector<std::uint8_t> require_tls_fixture_transport_payload(
    const std::filesystem::path& relative_path,
    const std::uint64_t packet_index
) {
    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(std::filesystem::path(__FILE__).parent_path().parent_path() / "data" / relative_path));
    const auto packet = session.find_packet(packet_index);
    PFL_REQUIRE(packet.has_value());

    const auto packet_bytes = session.read_packet_data(*packet);
    PacketPayloadService payload_service {};
    const auto payload = payload_service.extract_transport_payload(packet_bytes, packet->data_link_type);
    PFL_REQUIRE(!payload.empty());
    return payload;
}

std::vector<std::uint8_t> take_prefix(const std::vector<std::uint8_t>& bytes, const std::size_t count) {
    PFL_REQUIRE(count <= bytes.size());
    return std::vector<std::uint8_t>(
        bytes.begin(),
        bytes.begin() + static_cast<std::vector<std::uint8_t>::difference_type>(count)
    );
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

std::vector<std::uint8_t> make_imap_tagged_login_payload() {
    constexpr char command[] = "A001 LOGIN alex secret\r\n";
    return std::vector<std::uint8_t>(command, command + sizeof(command) - 1);
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

std::vector<std::uint8_t> make_unknown_tcp_payload() {
    return {
        0xF1, 0x02, 0x03, 0x04,
        0xA5, 0xB6, 0xC7, 0xD8,
        0x19, 0x2A, 0x3B, 0x4C,
        0x55, 0x66, 0x77, 0x88,
    };
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
        std::vector<std::uint8_t> extensions {};
        append_tls_extension(extensions, 0x0000U, make_tls_server_name_extension_body("www.youtube.com"));
        append_tls_extension(extensions, 0x0010U, {0x00U, 0x02U, 0x68U, 0x32U});
        auto payload = make_minimal_client_hello_payload_with_extensions(extensions);
        payload.resize(payload.size() - 2U);

        const auto hint = detect_tcp_flow_hint(payload);
        PFL_EXPECT(hint.protocol_hint == FlowProtocolHint::tls);
        PFL_EXPECT(hint.service_hint == "www.youtube.com");
    }

    {
        std::vector<std::uint8_t> extensions {};
        append_tls_extension(extensions, 0x0000U, make_tls_server_name_extension_body("www.youtube.com"));
        const auto payload = make_minimal_client_hello_payload_with_extensions(extensions);
        const auto extension_start = payload.size() - extensions.size();

        const auto truncated_header = detect_tcp_flow_hint(take_prefix(payload, extension_start + 2U));
        PFL_EXPECT(truncated_header.protocol_hint == FlowProtocolHint::tls);
        PFL_EXPECT(truncated_header.service_hint.empty());

        const auto truncated_body = detect_tcp_flow_hint(take_prefix(payload, extension_start + 5U));
        PFL_EXPECT(truncated_body.protocol_hint == FlowProtocolHint::tls);
        PFL_EXPECT(truncated_body.service_hint.empty());

        const auto truncated_hostname = detect_tcp_flow_hint(take_prefix(payload, extension_start + 10U));
        PFL_EXPECT(truncated_hostname.protocol_hint == FlowProtocolHint::tls);
        PFL_EXPECT(truncated_hostname.service_hint.empty());
    }

    {
        std::vector<std::uint8_t> extensions {};
        append_tls_extension(extensions, 0x0000U, make_tls_server_name_extension_body("www.youtube.com"));

        const auto session_id_payload = make_minimal_client_hello_payload_with_extensions(
            extensions,
            {0xAAU, 0xBBU, 0xCCU, 0xDDU}
        );
        const auto cipher_suites_payload = make_minimal_client_hello_payload_with_extensions(
            extensions,
            {},
            {0x13U, 0x01U, 0x13U, 0x02U},
            {0x00U}
        );
        const auto compression_methods_payload = make_minimal_client_hello_payload_with_extensions(
            extensions,
            {},
            {0x13U, 0x01U},
            {0x00U, 0x01U}
        );

        const std::vector<std::vector<std::uint8_t>> truncated_cases {
            take_prefix(session_id_payload, 44U),
            take_prefix(cipher_suites_payload, 46U),
            take_prefix(
                compression_methods_payload,
                compression_methods_payload.size() - (extensions.size() + 3U)
            ),
        };

        for (const auto& truncated_payload : truncated_cases) {
            const auto hint = detect_tcp_flow_hint(truncated_payload);
            PFL_EXPECT(hint.protocol_hint == FlowProtocolHint::tls);
            PFL_EXPECT(hint.service_hint.empty());
        }
    }

    {
        std::vector<std::uint8_t> extensions {};
        append_tls_extension(extensions, 0x000BU, {0x01U, 0x00U});
        append_tls_extension(extensions, 0x0000U, make_tls_server_name_extension_body("www.youtube.com"));
        const auto payload = make_minimal_client_hello_payload_with_extensions(extensions);
        const auto sni_extension_size = static_cast<std::size_t>(4U + make_tls_server_name_extension_body("www.youtube.com").size());
        const auto truncated_before_sni = take_prefix(payload, payload.size() - (sni_extension_size - 2U));

        const auto hint = detect_tcp_flow_hint(truncated_before_sni);
        PFL_EXPECT(hint.protocol_hint == FlowProtocolHint::tls);
        PFL_EXPECT(hint.service_hint.empty());
    }

    {
        const auto split_record_prefix_hint = detect_tcp_flow_hint({
            0x16U, 0x03U, 0x03U, 0x00U, 0x20U,
            0x01U, 0x00U, 0x00U, 0x40U,
        });
        PFL_EXPECT(split_record_prefix_hint.protocol_hint == FlowProtocolHint::tls);
        PFL_EXPECT(split_record_prefix_hint.service_hint.empty());

        const auto zero_length_hint = detect_tcp_flow_hint({0x16U, 0x03U, 0x03U, 0x00U, 0x00U});
        PFL_EXPECT(zero_length_hint.protocol_hint == FlowProtocolHint::unknown);
        PFL_EXPECT(zero_length_hint.service_hint.empty());

        const auto max_length = static_cast<std::uint16_t>(kTlsMaxRecordPayloadSize);
        const auto max_length_hint = detect_tcp_flow_hint({
            0x16U,
            0x03U,
            0x03U,
            static_cast<std::uint8_t>((max_length >> 8U) & 0xFFU),
            static_cast<std::uint8_t>(max_length & 0xFFU),
        });
        PFL_EXPECT(max_length_hint.protocol_hint == FlowProtocolHint::tls);
        PFL_EXPECT(max_length_hint.service_hint.empty());

        const auto over_max_length = static_cast<std::uint16_t>(kTlsMaxRecordPayloadSize + 1U);
        const auto over_max_length_hint = detect_tcp_flow_hint({
            0x16U,
            0x03U,
            0x03U,
            static_cast<std::uint8_t>((over_max_length >> 8U) & 0xFFU),
            static_cast<std::uint8_t>(over_max_length & 0xFFU),
        });
        PFL_EXPECT(over_max_length_hint.protocol_hint == FlowProtocolHint::unknown);
        PFL_EXPECT(over_max_length_hint.service_hint.empty());

        const auto max_ffff_hint = detect_tcp_flow_hint({0x16U, 0x03U, 0x03U, 0xFFU, 0xFFU});
        PFL_EXPECT(max_ffff_hint.protocol_hint == FlowProtocolHint::unknown);
        PFL_EXPECT(max_ffff_hint.service_hint.empty());
    }

    {
        const auto packet4_payload = require_tls_fixture_transport_payload("parsing/tls/tls_1_3_split_client_hello_10.pcap", 3U);
        const auto packet5_payload = require_tls_fixture_transport_payload("parsing/tls/tls_1_3_split_client_hello_10.pcap", 4U);

        const auto packet4_hint = detect_tcp_flow_hint(packet4_payload);
        PFL_EXPECT(packet4_hint.protocol_hint == FlowProtocolHint::tls);
        PFL_EXPECT(packet4_hint.service_hint == "www.youtube.com");

        const auto packet5_hint = detect_tcp_flow_hint(packet5_payload);
        PFL_EXPECT(packet5_hint.protocol_hint == FlowProtocolHint::unknown);
        PFL_EXPECT(packet5_hint.service_hint.empty());
    }

    {
        struct FixtureHintExpectation {
            const char* relative_path {""};
            std::uint64_t packet_index {0U};
            FlowProtocolHint expected_protocol_hint {FlowProtocolHint::unknown};
            const char* expected_service_hint {""};
        };

        const std::vector<FixtureHintExpectation> expectations {
            {
                .relative_path = "parsing/tls/tls_1_0_badssl_baseline_12.pcap",
                .packet_index = 3U,
                .expected_protocol_hint = FlowProtocolHint::tls,
                .expected_service_hint = "tls-v1-0.badssl.com",
            },
            {
                .relative_path = "parsing/tls/tls_1_1_badssl_baseline_13.pcap",
                .packet_index = 3U,
                .expected_protocol_hint = FlowProtocolHint::tls,
                .expected_service_hint = "tls-v1-1.badssl.com",
            },
            {
                .relative_path = "parsing/tls/tls_1_2_badssl_baseline_14.pcap",
                .packet_index = 3U,
                .expected_protocol_hint = FlowProtocolHint::tls,
                .expected_service_hint = "tls-v1-2.badssl.com",
            },
            {
                .relative_path = "parsing/tls/tls_1_2_client_to_tls_1_0_protocol_version_15.pcap",
                .packet_index = 3U,
                .expected_protocol_hint = FlowProtocolHint::tls,
                .expected_service_hint = "tls-v1-0.badssl.com",
            },
            {
                .relative_path = "parsing/tls/tls_1_2_expired_certificate_alert_16.pcap",
                .packet_index = 3U,
                .expected_protocol_hint = FlowProtocolHint::tls,
                .expected_service_hint = "expired.badssl.com",
            },
            {
                .relative_path = "parsing/tls/tls_1_2_self_signed_unknown_ca_17.pcap",
                .packet_index = 3U,
                .expected_protocol_hint = FlowProtocolHint::tls,
                .expected_service_hint = "self-signed.badssl.com",
            },
            {
                .relative_path = "parsing/tls/tls_1_2_client_certificate_missing_18.pcap",
                .packet_index = 3U,
                .expected_protocol_hint = FlowProtocolHint::tls,
                .expected_service_hint = "client-cert-missing.badssl.com",
            },
            {
                .relative_path = "parsing/tls/tls_1_2_status_request_alpn_19.pcap",
                .packet_index = 3U,
                .expected_protocol_hint = FlowProtocolHint::tls,
                .expected_service_hint = "tls-v1-2.badssl.com",
            },
            {
                .relative_path = "parsing/tls/tls_1_2_client_to_tls_1_0_protocol_version_15.pcap",
                .packet_index = 13U,
                .expected_protocol_hint = FlowProtocolHint::tls,
            },
            {
                .relative_path = "parsing/tls/tls_1_2_expired_certificate_alert_16.pcap",
                .packet_index = 13U,
                .expected_protocol_hint = FlowProtocolHint::tls,
            },
            {
                .relative_path = "parsing/tls/tls_1_2_self_signed_unknown_ca_17.pcap",
                .packet_index = 7U,
                .expected_protocol_hint = FlowProtocolHint::tls,
            },
            {
                .relative_path = "parsing/tls/tls_1_2_client_certificate_missing_18.pcap",
                .packet_index = 12U,
                .expected_protocol_hint = FlowProtocolHint::tls,
            },
        };

        for (const auto& expectation : expectations) {
            ScopedTestContext context {
                "fixture=" + std::string {expectation.relative_path} +
                " | packet=" + std::to_string(expectation.packet_index + 1U)
            };
            const auto payload = require_tls_fixture_transport_payload(
                expectation.relative_path,
                expectation.packet_index
            );
            const auto hint = detect_tcp_flow_hint(payload);
            PFL_EXPECT(hint.protocol_hint == expectation.expected_protocol_hint);
            if (std::string_view {expectation.expected_service_hint}.empty()) {
                PFL_EXPECT(hint.service_hint.empty());
            } else {
                PFL_EXPECT(hint.service_hint == expectation.expected_service_hint);
            }
        }
    }

    {
        const auto server_hello_hint = detect_tcp_flow_hint(make_tls_record(
            0x16U,
            0x0303U,
            make_tls_handshake_message(0x02U, {0x00U, 0x01U, 0x02U, 0x03U})
        ));
        PFL_EXPECT(server_hello_hint.protocol_hint == FlowProtocolHint::tls);
        PFL_EXPECT(server_hello_hint.service_hint.empty());

        const auto change_cipher_spec_hint = detect_tcp_flow_hint(make_tls_record(0x14U, 0x0303U, {0x01U}));
        PFL_EXPECT(change_cipher_spec_hint.protocol_hint == FlowProtocolHint::tls);
        PFL_EXPECT(change_cipher_spec_hint.service_hint.empty());

        const auto encrypted_handshake_hint = detect_tcp_flow_hint(make_tls_record(
            0x16U,
            0x0303U,
            make_tls_handshake_message(0x7FU, {0xAAU, 0xBBU, 0xCCU})
        ));
        PFL_EXPECT(encrypted_handshake_hint.protocol_hint == FlowProtocolHint::tls);
        PFL_EXPECT(encrypted_handshake_hint.service_hint.empty());

        const auto app_data_hint = detect_tcp_flow_hint(make_tls_record(0x17U, 0x0303U, {0xAAU, 0xBBU, 0xCCU}));
        PFL_EXPECT(app_data_hint.protocol_hint == FlowProtocolHint::tls);
        PFL_EXPECT(app_data_hint.service_hint.empty());
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
            "pfl_flow_hint_arp_request.pcap",
            make_classic_pcap({
                {100, make_ethernet_arp_packet(ipv4(10, 10, 12, 2), ipv4(10, 10, 12, 1), 1U)},
            })
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(path));
        const auto rows = session.list_flows();
        PFL_EXPECT(rows.size() == 1U);
        PFL_EXPECT(rows[0].protocol_hint.empty());
        PFL_EXPECT(rows[0].service_hint == "Who has 10.10.12.1? Tell 10.10.12.2");
    }

    {
        const auto path = write_temp_pcap(
            "pfl_flow_hint_arp_reply.pcap",
            make_classic_pcap({
                {100, make_ethernet_arp_packet(ipv4(10, 10, 12, 1), ipv4(10, 10, 12, 2), 2U)},
            })
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(path));
        const auto rows = session.list_flows();
        PFL_EXPECT(rows.size() == 1U);
        PFL_EXPECT(rows[0].service_hint == "10.10.12.1 is at 00:11:22:33:44:55");
    }

    {
        const auto path = write_temp_pcap(
            "pfl_flow_hint_arp_probe_and_gratuitous.pcap",
            make_classic_pcap({
                {100, make_ethernet_arp_packet(ipv4(0, 0, 0, 0), ipv4(10, 10, 12, 9), 1U)},
                {110, make_ethernet_arp_packet(ipv4(10, 10, 12, 9), ipv4(10, 10, 12, 9), 1U)},
            })
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(path));
        const auto rows = session.list_flows();
        PFL_EXPECT(rows.size() == 2U);
        PFL_EXPECT(rows[0].service_hint == "ARP probe for 10.10.12.9");
        PFL_EXPECT(rows[1].service_hint == "Gratuitous ARP for 10.10.12.9");
    }

    {
        const auto path = write_temp_pcap(
            "pfl_flow_hint_arp_unknown_opcode.pcap",
            make_classic_pcap({
                {100, make_ethernet_arp_packet_with_fields(
                    {0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
                    {0x0a, 0x0a, 0x0c, 0x02},
                    {0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
                    {0x0a, 0x0a, 0x0c, 0x01},
                    9U
                )},
            })
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(path));
        const auto rows = session.list_flows();
        PFL_EXPECT(rows.size() == 1U);
        PFL_EXPECT(rows[0].service_hint == "ARP opcode 9");
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
        const auto path = write_temp_pcap(
            "pfl_flow_hint_imap_positive_tagged_login.pcap",
            make_classic_pcap({
                {100, make_ethernet_ipv4_tcp_packet_with_bytes_payload(
                    ipv4(10, 9, 17, 11), ipv4(10, 9, 17, 12), 40143, 143, make_imap_tagged_login_payload(), 0x18)},
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
        std::vector<std::pair<std::uint32_t, std::vector<std::uint8_t>>> records {};
        records.push_back({100, make_ethernet_ipv4_tcp_packet_with_bytes_payload(
            ipv4(10, 20, 0, 1), ipv4(10, 20, 0, 2), 52000, 80, make_http_request_payload(), 0x18)});
        for (std::uint32_t packet_index = 0; packet_index < 12U; ++packet_index) {
            records.push_back({101U + packet_index, make_ethernet_ipv4_tcp_packet_with_bytes_payload(
                ipv4(10, 20, 0, 1), ipv4(10, 20, 0, 2), 52000, 80, make_unknown_tcp_payload(), 0x18)});
        }

        const auto path = write_temp_pcap("pfl_flow_hint_settled_http_short_circuit.pcap", make_classic_pcap(records));

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(path));
        const auto rows = session.list_flows();
        PFL_EXPECT(rows.size() == 1U);
        PFL_EXPECT(rows[0].protocol_hint == "http");
        PFL_EXPECT(rows[0].service_hint == "www.example.com");

        const auto connections = session.state().ipv4_connections.list();
        PFL_REQUIRE(connections.size() == 1U);
        const auto* connection = connections.front();
        PFL_EXPECT(connection != nullptr);
        PFL_EXPECT(connection->hint_detection_settled());
        PFL_EXPECT(connection->hint_search_state.unresolved_payload_attempt_count == 0U);
        PFL_EXPECT(!connection->hint_search_state.unresolved_payload_attempt_budget_exhausted);
    }

    {
        std::vector<std::pair<std::uint32_t, std::vector<std::uint8_t>>> records {};
        for (std::uint32_t packet_index = 0; packet_index < 12U; ++packet_index) {
            records.push_back({200U + packet_index, make_ethernet_ipv4_tcp_packet_with_bytes_payload(
                ipv4(10, 21, 0, 1), ipv4(10, 21, 0, 2), 52001, 8080, make_unknown_tcp_payload(), 0x18)});
        }

        const auto path = write_temp_pcap("pfl_flow_hint_unresolved_budget_limit.pcap", make_classic_pcap(records));

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(path));
        const auto rows = session.list_flows();
        PFL_EXPECT(rows.size() == 1U);
        PFL_EXPECT(rows[0].protocol_hint.empty());
        PFL_EXPECT(rows[0].service_hint.empty());

        const auto connections = session.state().ipv4_connections.list();
        PFL_REQUIRE(connections.size() == 1U);
        const auto* connection = connections.front();
        PFL_EXPECT(connection != nullptr);
        PFL_EXPECT(connection->hint_search_state.unresolved_payload_attempt_count ==
                   kMaxUnresolvedHintPayloadAttemptsPerConnection);
        PFL_EXPECT(connection->hint_search_state.unresolved_payload_attempt_budget_exhausted);
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


