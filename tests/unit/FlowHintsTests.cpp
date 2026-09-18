#include <filesystem>
#include <limits>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "TestSupport.h"
#include "app/session/CaptureSession.h"
#include "core/dissection/CommonDirectDissection.h"
#include "core/domain/Connection.h"
#include "core/domain/ConnectionKey.h"
#include "core/domain/FlowKey.h"
#include "core/io/LinkType.h"
#include "core/services/CaptureImportApplication.h"
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

FlowHintUpdate detect_udp_flow_hint(
    const std::vector<std::uint8_t>& payload,
    const std::uint16_t src_port,
    const std::uint16_t dst_port
) {
    FlowHintService service {};
    const auto packet = make_ethernet_ipv4_udp_packet_with_bytes_payload(
        ipv4(10, 0, 1, 1),
        ipv4(10, 0, 1, 2),
        src_port,
        dst_port,
        payload
    );
    return service.detect(packet, FlowKeyV4 {
        .src_addr = ipv4(10, 0, 1, 1),
        .dst_addr = ipv4(10, 0, 1, 2),
        .src_port = src_port,
        .dst_port = dst_port,
        .protocol = ProtocolId::udp,
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

void append_mqtt_variable_byte_integer(std::vector<std::uint8_t>& bytes, std::uint32_t value) {
    do {
        auto encoded_byte = static_cast<std::uint8_t>(value % 128U);
        value /= 128U;
        if (value > 0U) {
            encoded_byte |= 0x80U;
        }
        bytes.push_back(encoded_byte);
    } while (value > 0U);
}

void append_mqtt_utf8_string(std::vector<std::uint8_t>& bytes, const std::string_view value) {
    append_be16(bytes, static_cast<std::uint16_t>(value.size()));
    bytes.insert(bytes.end(), value.begin(), value.end());
}

void append_mqtt_binary_data(std::vector<std::uint8_t>& bytes, const std::vector<std::uint8_t>& value) {
    append_be16(bytes, static_cast<std::uint16_t>(value.size()));
    bytes.insert(bytes.end(), value.begin(), value.end());
}

std::vector<std::uint8_t> make_mqtt_connect_payload(
    const std::string_view protocol_name = "MQTT",
    const std::uint8_t protocol_level = 4U,
    const std::uint8_t connect_flags = 0x02U,
    const std::string_view client_id = "pfl-mqtt-client",
    const std::vector<std::uint8_t>& properties = {},
    const std::vector<std::uint8_t>& will_properties = {},
    const std::string_view will_topic = {},
    const std::vector<std::uint8_t>& will_payload = {},
    const std::string_view username = {},
    const std::vector<std::uint8_t>& password = {}
) {
    std::vector<std::uint8_t> variable_header {};
    append_mqtt_utf8_string(variable_header, protocol_name);
    variable_header.push_back(protocol_level);
    variable_header.push_back(connect_flags);
    append_be16(variable_header, 60U);
    if (protocol_level == 5U) {
        append_mqtt_variable_byte_integer(variable_header, static_cast<std::uint32_t>(properties.size()));
        variable_header.insert(variable_header.end(), properties.begin(), properties.end());
    }

    std::vector<std::uint8_t> body {};
    body.insert(body.end(), variable_header.begin(), variable_header.end());
    append_mqtt_utf8_string(body, client_id);
    if ((connect_flags & 0x04U) != 0U) {
        if (protocol_level == 5U) {
            append_mqtt_variable_byte_integer(body, static_cast<std::uint32_t>(will_properties.size()));
            body.insert(body.end(), will_properties.begin(), will_properties.end());
        }
        append_mqtt_utf8_string(body, will_topic);
        append_mqtt_binary_data(body, will_payload);
    }
    if ((connect_flags & 0x80U) != 0U) {
        append_mqtt_utf8_string(body, username);
    }
    if ((connect_flags & 0x40U) != 0U) {
        append_mqtt_binary_data(body, password);
    }

    std::vector<std::uint8_t> payload {};
    payload.push_back(0x10U);
    append_mqtt_variable_byte_integer(payload, static_cast<std::uint32_t>(body.size()));
    payload.insert(payload.end(), body.begin(), body.end());
    return payload;
}

std::vector<std::uint8_t> make_mqtt5_connect_with_oversized_property_length() {
    std::vector<std::uint8_t> body {};
    append_mqtt_utf8_string(body, "MQTT");
    body.push_back(5U);
    body.push_back(0x02U);
    append_be16(body, 60U);
    body.push_back(5U);
    body.push_back(0x11U);

    std::vector<std::uint8_t> payload {};
    payload.push_back(0x10U);
    append_mqtt_variable_byte_integer(payload, static_cast<std::uint32_t>(body.size()));
    payload.insert(payload.end(), body.begin(), body.end());
    return payload;
}

std::vector<std::uint8_t> make_amqp_header_payload(
    const std::uint8_t protocol_id,
    const std::uint8_t major,
    const std::uint8_t minor,
    const std::uint8_t revision
) {
    return std::vector<std::uint8_t> {
        'A', 'M', 'Q', 'P', protocol_id, major, minor, revision,
    };
}

std::vector<std::uint8_t> make_ntp_payload(
    const std::uint8_t version,
    const std::uint8_t mode,
    const std::uint8_t stratum,
    const std::uint8_t leap_indicator = 0U
) {
    std::vector<std::uint8_t> payload(48U, 0U);
    payload[0] = static_cast<std::uint8_t>(((leap_indicator & 0x03U) << 6U) |
                                           ((version & 0x07U) << 3U) |
                                           (mode & 0x07U));
    payload[1] = stratum;
    payload[2] = 6U; // Poll.
    payload[3] = 0xECU; // Precision -20 encoded as an unsigned byte.
    payload[40] = 0xE7U;
    payload[43] = 0x01U;
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

FlowKeyV4 tls_flow_key_v4(
    const std::uint32_t src_addr = ipv4(10, 80, 0, 1),
    const std::uint32_t dst_addr = ipv4(10, 80, 0, 2),
    const std::uint16_t src_port = 50123U,
    const std::uint16_t dst_port = 443U
) {
    return FlowKeyV4 {
        .src_addr = src_addr,
        .dst_addr = dst_addr,
        .src_port = src_port,
        .dst_port = dst_port,
        .protocol = ProtocolId::tcp,
    };
}

FlowKeyV6 tls_flow_key_v6() {
    return FlowKeyV6 {
        .src_addr = ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x41}),
        .dst_addr = ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x42}),
        .src_port = 50123U,
        .dst_port = 443U,
        .protocol = ProtocolId::tcp,
    };
}

TerminalTransportPayloadBounds terminal_tcp_bounds(const std::size_t payload_offset, const std::size_t payload_size) {
    return TerminalTransportPayloadBounds {
        .payload_offset = payload_offset,
        .declared_end_offset = payload_offset + payload_size,
    };
}

std::vector<std::uint8_t> make_ipv6_tcp_segment(
    const std::uint16_t src_port,
    const std::uint16_t dst_port,
    const std::uint32_t sequence_number,
    const std::vector<std::uint8_t>& payload,
    const std::uint8_t tcp_flags = 0x18U
) {
    std::vector<std::uint8_t> segment {};
    append_be16(segment, src_port);
    append_be16(segment, dst_port);
    append_be32(segment, sequence_number);
    append_be32(segment, 0U);
    segment.push_back(0x50U);
    segment.push_back(tcp_flags);
    append_be16(segment, 0U);
    append_be16(segment, 0U);
    append_be16(segment, 0U);
    segment.insert(segment.end(), payload.begin(), payload.end());
    return segment;
}

std::vector<std::uint8_t> make_ipv6_tls_packet(
    const FlowKeyV6& flow_key,
    const std::uint32_t sequence_number,
    const std::vector<std::uint8_t>& payload,
    const std::uint8_t tcp_flags = 0x18U
) {
    return make_ethernet_ipv6_packet(
        flow_key.src_addr,
        flow_key.dst_addr,
        6U,
        make_ipv6_tcp_segment(flow_key.src_port, flow_key.dst_port, sequence_number, payload, tcp_flags)
    );
}

std::uint32_t tcp_next_sequence(
    const std::uint32_t sequence_number,
    const std::size_t payload_size,
    const std::uint8_t tcp_flags
) {
    PFL_REQUIRE(payload_size <= static_cast<std::size_t>(std::numeric_limits<std::uint32_t>::max()));
    return sequence_number + static_cast<std::uint32_t>(payload_size) + ((tcp_flags & 0x02U) != 0U ? 1U : 0U);
}

std::vector<std::uint8_t> make_client_hello_payload_for_sni(const std::string_view sni) {
    std::vector<std::uint8_t> extensions {};
    append_tls_extension(extensions, 0x000BU, {0x01U, 0x00U});
    append_tls_extension(extensions, 0x0000U, make_tls_server_name_extension_body(sni));
    return make_minimal_client_hello_payload_with_extensions(extensions);
}

std::size_t split_before_sni_name(const std::vector<std::uint8_t>& payload, const std::string_view sni) {
    const auto sni_extension_size = static_cast<std::size_t>(4U + make_tls_server_name_extension_body(sni).size());
    return payload.size() - (sni_extension_size - 2U);
}

std::vector<std::uint8_t> make_large_incomplete_client_hello_prefix(const std::size_t prefix_size) {
    PFL_REQUIRE(prefix_size >= 9U);
    const auto body_size = prefix_size + 512U;
    std::vector<std::uint8_t> body(body_size, std::uint8_t {0x00U});
    body[0] = 0x03U;
    body[1] = 0x03U;
    std::vector<std::uint8_t> record {};
    record.push_back(0x16U);
    append_be16(record, 0x0303U);
    append_be16(record, static_cast<std::uint16_t>(body.size() + 4U));
    record.push_back(0x01U);
    append_be24(record, static_cast<std::uint32_t>(body.size()));
    record.insert(record.end(), body.begin(), body.end());
    return take_prefix(record, prefix_size);
}

std::vector<std::uint8_t> payload_suffix(const std::vector<std::uint8_t>& payload, const std::size_t offset) {
    PFL_REQUIRE(offset <= payload.size());
    return std::vector<std::uint8_t>(
        payload.begin() + static_cast<std::vector<std::uint8_t>::difference_type>(offset),
        payload.end()
    );
}

RawPcapPacket make_import_packet(
    std::vector<std::uint8_t> bytes,
    const std::uint64_t packet_index = 0U
) {
    const auto packet_size = static_cast<std::uint32_t>(bytes.size());
    return RawPcapPacket {
        .packet_index = packet_index,
        .captured_length = packet_size,
        .original_length = packet_size,
        .data_link_type = kLinkTypeEthernet,
        .bytes = std::move(bytes),
    };
}

std::vector<std::uint8_t> make_ipv4_tls_packet(
    const FlowKeyV4& flow_key,
    const std::uint32_t sequence_number,
    const std::vector<std::uint8_t>& payload,
    const std::uint8_t tcp_flags = 0x18U
) {
    return make_ethernet_ipv4_tcp_packet_with_bytes_payload_and_sequence(
        flow_key.src_addr,
        flow_key.dst_addr,
        flow_key.src_port,
        flow_key.dst_port,
        payload,
        sequence_number,
        0U,
        tcp_flags
    );
}

std::vector<std::uint8_t> make_ipv4_reverse_tcp_packet(
    const FlowKeyV4& flow_key,
    const std::uint32_t sequence_number,
    const std::uint32_t acknowledgement_number,
    const std::vector<std::uint8_t>& payload,
    const std::uint8_t tcp_flags = 0x10U
) {
    return make_ethernet_ipv4_tcp_packet_with_bytes_payload_and_sequence(
        flow_key.dst_addr,
        flow_key.src_addr,
        flow_key.dst_port,
        flow_key.src_port,
        payload,
        sequence_number,
        acknowledgement_number,
        tcp_flags
    );
}

std::pair<std::string, std::string> open_single_flow_protocol_and_service(
    const std::string& file_name,
    const std::vector<std::pair<std::uint32_t, std::vector<std::uint8_t>>>& packets
) {
    const auto path = write_temp_pcap(file_name, make_classic_pcap(packets));
    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(path));
    const auto rows = session.list_flows();
    PFL_REQUIRE(rows.size() == 1U);
    return {rows[0].protocol_hint, rows[0].service_hint};
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
        const std::string sni {"edge.microsoft.com"};
        const auto payload = make_client_hello_payload_for_sni(sni);
        const auto split_offset = split_before_sni_name(payload, sni);
        const auto first_payload = take_prefix(payload, split_offset);
        const auto second_payload = payload_suffix(payload, split_offset);
        const auto flow_key = tls_flow_key_v4();
        constexpr std::uint32_t sequence_number = 0x1000U;

        const auto first_packet = make_ethernet_ipv4_tcp_packet_with_bytes_payload_and_sequence(
            flow_key.src_addr,
            flow_key.dst_addr,
            flow_key.src_port,
            flow_key.dst_port,
            first_payload,
            sequence_number,
            0U,
            0x18U
        );
        const auto second_packet = make_ethernet_ipv4_tcp_packet_with_bytes_payload_and_sequence(
            flow_key.src_addr,
            flow_key.dst_addr,
            flow_key.src_port,
            flow_key.dst_port,
            second_payload,
            tcp_next_sequence(sequence_number, first_payload.size(), 0x18U),
            0U,
            0x18U
        );

        FlowHintService service {};
        PFL_EXPECT(service.retain_tls_client_hello_prefix(
            first_packet,
            kLinkTypeEthernet,
            flow_key,
            terminal_tcp_bounds(54U, first_payload.size()),
            sequence_number,
            0x18U
        ));
        PFL_EXPECT(service.has_pending_tls_client_hello(flow_key));
        PFL_EXPECT(service.pending_tls_client_hello_candidate_count() == 1U);
        PFL_EXPECT(service.pending_tls_client_hello_retained_bytes() == first_payload.size());

        const auto hint = service.attempt_tls_client_hello_continuation(
            second_packet,
            kLinkTypeEthernet,
            flow_key,
            terminal_tcp_bounds(54U, second_payload.size()),
            tcp_next_sequence(sequence_number, first_payload.size(), 0x18U)
        );
        PFL_EXPECT(hint.protocol_hint == FlowProtocolHint::tls);
        PFL_EXPECT(hint.service_hint == sni);
        PFL_EXPECT(!service.has_pending_tls_client_hello(flow_key));
        PFL_EXPECT(service.pending_tls_client_hello_candidate_count() == 0U);
        PFL_EXPECT(service.pending_tls_client_hello_retained_bytes() == 0U);
    }

    {
        const std::string sni {"reverse-gap.example.test"};
        const auto payload = make_client_hello_payload_for_sni(sni);
        const auto split_offset = split_before_sni_name(payload, sni);
        const auto first_payload = take_prefix(payload, split_offset);
        const auto second_payload = payload_suffix(payload, split_offset);
        const auto flow_key = tls_flow_key_v4(ipv4(10, 90, 0, 1), ipv4(10, 90, 0, 2));
        constexpr std::uint32_t sequence_number = 0x2000U;
        const auto next_sequence = tcp_next_sequence(sequence_number, first_payload.size(), 0x18U);

        const auto [protocol, service] = open_single_flow_protocol_and_service(
            "pfl_flow_hint_tls_reverse_between_segments.pcap",
            {
                {100U, make_ipv4_tls_packet(flow_key, sequence_number, first_payload)},
                {110U, make_ipv4_reverse_tcp_packet(flow_key, 9000U, next_sequence, std::vector<std::uint8_t> {})},
                {120U, make_ipv4_tls_packet(flow_key, next_sequence, second_payload)},
            }
        );
        PFL_EXPECT(protocol == "tls");
        PFL_EXPECT(service == sni);
    }

    {
        const std::string sni {"zero-budget.example.test"};
        const auto payload = make_client_hello_payload_for_sni(sni);
        const auto split_offset = split_before_sni_name(payload, sni);
        const auto first_payload = take_prefix(payload, split_offset);
        const auto second_payload = payload_suffix(payload, split_offset);
        const auto flow_key = tls_flow_key_v4(ipv4(10, 90, 1, 1), ipv4(10, 90, 1, 2));
        constexpr std::uint32_t sequence_number = 0x3000U;
        const auto next_sequence = tcp_next_sequence(sequence_number, first_payload.size(), 0x18U);

        const auto [protocol, service] = open_single_flow_protocol_and_service(
            "pfl_flow_hint_tls_zero_payload_budget_survives.pcap",
            {
                {100U, make_ipv4_tls_packet(flow_key, sequence_number, first_payload)},
                {110U, make_ipv4_tls_packet(flow_key, next_sequence, std::vector<std::uint8_t> {}, 0x10U)},
                {120U, make_ipv4_tls_packet(flow_key, next_sequence, std::vector<std::uint8_t> {}, 0x10U)},
                {130U, make_ipv4_tls_packet(flow_key, next_sequence, second_payload)},
            }
        );
        PFL_EXPECT(protocol == "tls");
        PFL_EXPECT(service == sni);
    }

    {
        const std::string sni {"expired.example.test"};
        const auto payload = make_client_hello_payload_for_sni(sni);
        const auto split_offset = split_before_sni_name(payload, sni);
        const auto first_payload = take_prefix(payload, split_offset);
        const auto second_payload = payload_suffix(payload, split_offset);
        const auto flow_key = tls_flow_key_v4(ipv4(10, 90, 2, 1), ipv4(10, 90, 2, 2));
        constexpr std::uint32_t sequence_number = 0x4000U;
        const auto next_sequence = tcp_next_sequence(sequence_number, first_payload.size(), 0x18U);

        const auto [protocol, service] = open_single_flow_protocol_and_service(
            "pfl_flow_hint_tls_zero_payload_budget_expires.pcap",
            {
                {100U, make_ipv4_tls_packet(flow_key, sequence_number, first_payload)},
                {110U, make_ipv4_tls_packet(flow_key, next_sequence, std::vector<std::uint8_t> {}, 0x10U)},
                {120U, make_ipv4_tls_packet(flow_key, next_sequence, std::vector<std::uint8_t> {}, 0x10U)},
                {130U, make_ipv4_tls_packet(flow_key, next_sequence, std::vector<std::uint8_t> {}, 0x10U)},
                {140U, make_ipv4_tls_packet(flow_key, next_sequence, second_payload)},
            }
        );
        PFL_EXPECT(protocol == "tls");
        PFL_EXPECT(service.empty());
    }

    {
        const std::string sni {"budget-exhausted.example.test"};
        const auto payload = make_client_hello_payload_for_sni(sni);
        const auto split_offset = split_before_sni_name(payload, sni);
        const auto first_payload = take_prefix(payload, split_offset);
        const auto second_payload = payload_suffix(payload, split_offset);
        const auto flow_key = tls_flow_key_v4(ipv4(10, 90, 3, 1), ipv4(10, 90, 3, 2));
        constexpr std::uint32_t sequence_number = 0x5000U;
        const auto unknown_payload = make_unknown_tcp_payload();
        std::uint32_t cursor = sequence_number;
        std::vector<std::pair<std::uint32_t, std::vector<std::uint8_t>>> packets {};
        for (std::uint32_t index = 0U; index < 9U; ++index) {
            packets.push_back({100U + index, make_ipv4_tls_packet(flow_key, cursor, unknown_payload)});
            cursor = tcp_next_sequence(cursor, unknown_payload.size(), 0x18U);
        }
        packets.push_back({120U, make_ipv4_tls_packet(flow_key, cursor, first_payload)});
        cursor = tcp_next_sequence(cursor, first_payload.size(), 0x18U);
        packets.push_back({130U, make_ipv4_tls_packet(flow_key, cursor, second_payload)});

        const auto [protocol, service] = open_single_flow_protocol_and_service(
            "pfl_flow_hint_tls_pending_after_generic_budget_exhaustion.pcap",
            packets
        );
        PFL_EXPECT(protocol == "tls");
        PFL_EXPECT(service == sni);
    }

    {
        FlowHintService service {};
        const auto flow_key = tls_flow_key_v4(ipv4(10, 80, 1, 1), ipv4(10, 80, 1, 2));
        const auto full_payload = make_client_hello_payload_for_sni("complete.example.test");
        const auto full_packet = make_ethernet_ipv4_tcp_packet_with_bytes_payload_and_sequence(
            flow_key.src_addr,
            flow_key.dst_addr,
            flow_key.src_port,
            flow_key.dst_port,
            full_payload,
            1U,
            0U,
            0x18U
        );
        PFL_EXPECT(!service.retain_tls_client_hello_prefix(
            full_packet,
            kLinkTypeEthernet,
            flow_key,
            terminal_tcp_bounds(54U, full_payload.size()),
            1U,
            0x18U
        ));

        const auto no_sni_payload = make_minimal_client_hello_payload_with_extensions(std::vector<std::uint8_t> {});
        const auto no_sni_flow_key = tls_flow_key_v4(ipv4(10, 80, 2, 1), ipv4(10, 80, 2, 2));
        const auto no_sni_packet = make_ethernet_ipv4_tcp_packet_with_bytes_payload_and_sequence(
            no_sni_flow_key.src_addr,
            no_sni_flow_key.dst_addr,
            no_sni_flow_key.src_port,
            no_sni_flow_key.dst_port,
            no_sni_payload,
            1U,
            0U,
            0x18U
        );
        PFL_EXPECT(!service.retain_tls_client_hello_prefix(
            no_sni_packet,
            kLinkTypeEthernet,
            no_sni_flow_key,
            terminal_tcp_bounds(54U, no_sni_payload.size()),
            1U,
            0x18U
        ));

        const std::vector<std::uint8_t> partial_header_payload {
            0x16U, 0x03U, 0x03U, 0x00U, 0x20U, 0x01U
        };
        const auto partial_header_flow_key = tls_flow_key_v4(ipv4(10, 80, 3, 1), ipv4(10, 80, 3, 2));
        const auto partial_header_packet = make_ethernet_ipv4_tcp_packet_with_bytes_payload_and_sequence(
            partial_header_flow_key.src_addr,
            partial_header_flow_key.dst_addr,
            partial_header_flow_key.src_port,
            partial_header_flow_key.dst_port,
            partial_header_payload,
            1U,
            0U,
            0x18U
        );
        PFL_EXPECT(!service.retain_tls_client_hello_prefix(
            partial_header_packet,
            kLinkTypeEthernet,
            partial_header_flow_key,
            terminal_tcp_bounds(54U, partial_header_payload.size()),
            1U,
            0x18U
        ));

        const auto server_hello_payload = make_tls_record(
            0x16U,
            0x0303U,
            make_tls_handshake_message(0x02U, {0x00U, 0x01U, 0x02U, 0x03U})
        );
        const auto server_hello_flow_key = tls_flow_key_v4(ipv4(10, 80, 4, 1), ipv4(10, 80, 4, 2));
        const auto server_hello_packet = make_ethernet_ipv4_tcp_packet_with_bytes_payload_and_sequence(
            server_hello_flow_key.src_addr,
            server_hello_flow_key.dst_addr,
            server_hello_flow_key.src_port,
            server_hello_flow_key.dst_port,
            server_hello_payload,
            1U,
            0U,
            0x18U
        );
        PFL_EXPECT(!service.retain_tls_client_hello_prefix(
            server_hello_packet,
            kLinkTypeEthernet,
            server_hello_flow_key,
            terminal_tcp_bounds(54U, server_hello_payload.size()),
            1U,
            0x18U
        ));

        const auto fin_payload = take_prefix(full_payload, split_before_sni_name(full_payload, "complete.example.test"));
        const auto fin_flow_key = tls_flow_key_v4(ipv4(10, 80, 5, 1), ipv4(10, 80, 5, 2));
        const auto fin_packet = make_ethernet_ipv4_tcp_packet_with_bytes_payload_and_sequence(
            fin_flow_key.src_addr,
            fin_flow_key.dst_addr,
            fin_flow_key.src_port,
            fin_flow_key.dst_port,
            fin_payload,
            1U,
            0U,
            0x19U
        );
        PFL_EXPECT(!service.retain_tls_client_hello_prefix(
            fin_packet,
            kLinkTypeEthernet,
            fin_flow_key,
            terminal_tcp_bounds(54U, fin_payload.size()),
            1U,
            0x19U
        ));
        PFL_EXPECT(service.pending_tls_client_hello_candidate_count() == 0U);
    }

    {
        const std::string sni {"wrap.example.test"};
        const auto payload = make_client_hello_payload_for_sni(sni);
        const auto split_offset = split_before_sni_name(payload, sni);
        const auto first_payload = take_prefix(payload, split_offset);
        const auto second_payload = payload_suffix(payload, split_offset);
        const auto flow_key = tls_flow_key_v4(ipv4(10, 80, 6, 1), ipv4(10, 80, 6, 2));
        constexpr std::uint32_t sequence_number = 0xFFFFFFF0U;
        constexpr std::uint8_t tcp_flags = 0x02U;
        const auto first_packet = make_ethernet_ipv4_tcp_packet_with_bytes_payload_and_sequence(
            flow_key.src_addr,
            flow_key.dst_addr,
            flow_key.src_port,
            flow_key.dst_port,
            first_payload,
            sequence_number,
            0U,
            tcp_flags
        );
        const auto second_packet = make_ethernet_ipv4_tcp_packet_with_bytes_payload_and_sequence(
            flow_key.src_addr,
            flow_key.dst_addr,
            flow_key.src_port,
            flow_key.dst_port,
            second_payload,
            tcp_next_sequence(sequence_number, first_payload.size(), tcp_flags),
            0U,
            0x18U
        );

        FlowHintService service {};
        PFL_EXPECT(service.retain_tls_client_hello_prefix(
            first_packet,
            kLinkTypeEthernet,
            flow_key,
            terminal_tcp_bounds(54U, first_payload.size()),
            sequence_number,
            tcp_flags
        ));
        const auto hint = service.attempt_tls_client_hello_continuation(
            second_packet,
            kLinkTypeEthernet,
            flow_key,
            terminal_tcp_bounds(54U, second_payload.size()),
            tcp_next_sequence(sequence_number, first_payload.size(), tcp_flags)
        );
        PFL_EXPECT(hint.service_hint == sni);
        PFL_EXPECT(service.pending_tls_client_hello_candidate_count() == 0U);
        PFL_EXPECT(service.pending_tls_client_hello_retained_bytes() == 0U);
    }

    {
        const std::string sni {"gap.example.test"};
        const auto payload = make_client_hello_payload_for_sni(sni);
        const auto split_offset = split_before_sni_name(payload, sni);
        const auto first_payload = take_prefix(payload, split_offset);
        const auto second_payload = payload_suffix(payload, split_offset);
        const auto flow_key = tls_flow_key_v4(ipv4(10, 80, 7, 1), ipv4(10, 80, 7, 2));
        constexpr std::uint32_t sequence_number = 2000U;
        const auto first_packet = make_ethernet_ipv4_tcp_packet_with_bytes_payload_and_sequence(
            flow_key.src_addr,
            flow_key.dst_addr,
            flow_key.src_port,
            flow_key.dst_port,
            first_payload,
            sequence_number,
            0U,
            0x18U
        );
        const auto second_packet = make_ethernet_ipv4_tcp_packet_with_bytes_payload_and_sequence(
            flow_key.src_addr,
            flow_key.dst_addr,
            flow_key.src_port,
            flow_key.dst_port,
            second_payload,
            tcp_next_sequence(sequence_number, first_payload.size(), 0x18U) + 1U,
            0U,
            0x18U
        );

        FlowHintService service {};
        PFL_EXPECT(service.retain_tls_client_hello_prefix(
            first_packet,
            kLinkTypeEthernet,
            flow_key,
            terminal_tcp_bounds(54U, first_payload.size()),
            sequence_number,
            0x18U
        ));
        const auto gap_hint = service.attempt_tls_client_hello_continuation(
            second_packet,
            kLinkTypeEthernet,
            flow_key,
            terminal_tcp_bounds(54U, second_payload.size()),
            tcp_next_sequence(sequence_number, first_payload.size(), 0x18U) + 1U
        );
        PFL_EXPECT(gap_hint.service_hint.empty());
        PFL_EXPECT(!service.has_pending_tls_client_hello(flow_key));
        PFL_EXPECT(service.pending_tls_client_hello_retained_bytes() == 0U);

        PFL_EXPECT(service.retain_tls_client_hello_prefix(
            first_packet,
            kLinkTypeEthernet,
            flow_key,
            terminal_tcp_bounds(54U, first_payload.size()),
            sequence_number,
            0x18U
        ));
        const auto overlap_hint = service.attempt_tls_client_hello_continuation(
            second_packet,
            kLinkTypeEthernet,
            flow_key,
            terminal_tcp_bounds(54U, second_payload.size()),
            tcp_next_sequence(sequence_number, first_payload.size(), 0x18U) - 1U
        );
        PFL_EXPECT(overlap_hint.service_hint.empty());
        PFL_EXPECT(!service.has_pending_tls_client_hello(flow_key));
        PFL_EXPECT(service.pending_tls_client_hello_retained_bytes() == 0U);
    }

    {
        const std::string sni {"truncated.example.test"};
        const auto payload = make_client_hello_payload_for_sni(sni);
        const auto split_offset = split_before_sni_name(payload, sni);
        const auto first_payload = take_prefix(payload, split_offset);
        const auto second_payload = payload_suffix(payload, split_offset);
        const auto flow_key = tls_flow_key_v4(ipv4(10, 80, 8, 1), ipv4(10, 80, 8, 2));
        constexpr std::uint32_t sequence_number = 3000U;
        auto first_packet = make_ethernet_ipv4_tcp_packet_with_bytes_payload_and_sequence(
            flow_key.src_addr,
            flow_key.dst_addr,
            flow_key.src_port,
            flow_key.dst_port,
            first_payload,
            sequence_number,
            0U,
            0x18U
        );
        first_packet.pop_back();

        FlowHintService service {};
        PFL_EXPECT(!service.retain_tls_client_hello_prefix(
            first_packet,
            kLinkTypeEthernet,
            flow_key,
            terminal_tcp_bounds(54U, first_payload.size()),
            sequence_number,
            0x18U
        ));

        const auto full_first_packet = make_ethernet_ipv4_tcp_packet_with_bytes_payload_and_sequence(
            flow_key.src_addr,
            flow_key.dst_addr,
            flow_key.src_port,
            flow_key.dst_port,
            first_payload,
            sequence_number,
            0U,
            0x18U
        );
        PFL_EXPECT(service.retain_tls_client_hello_prefix(
            full_first_packet,
            kLinkTypeEthernet,
            flow_key,
            terminal_tcp_bounds(54U, first_payload.size()),
            sequence_number,
            0x18U
        ));
        const auto short_second_payload = take_prefix(second_payload, second_payload.size() - 1U);
        const auto short_second_packet = make_ethernet_ipv4_tcp_packet_with_bytes_payload_and_sequence(
            flow_key.src_addr,
            flow_key.dst_addr,
            flow_key.src_port,
            flow_key.dst_port,
            short_second_payload,
            tcp_next_sequence(sequence_number, first_payload.size(), 0x18U),
            0U,
            0x18U
        );
        const auto short_second_hint = service.attempt_tls_client_hello_continuation(
            short_second_packet,
            kLinkTypeEthernet,
            flow_key,
            terminal_tcp_bounds(54U, short_second_payload.size()),
            tcp_next_sequence(sequence_number, first_payload.size(), 0x18U)
        );
        PFL_EXPECT(short_second_hint.service_hint.empty());
        PFL_EXPECT(service.pending_tls_client_hello_retained_bytes() == 0U);
    }

    {
        const auto registry_result = dissection::make_common_direct_registry();
        PFL_REQUIRE(registry_result.ok());
        PFL_REQUIRE(registry_result.registry.has_value());

        const auto flow_key = tls_flow_key_v4(ipv4(10, 80, 11, 1), ipv4(10, 80, 11, 2));
        const auto first_payload = make_unknown_tcp_payload();
        const auto second_payload = make_unknown_tcp_payload();
        constexpr std::uint32_t sequence_number = 8000U;

        CaptureState state {};
        FlowHintService service {};
        auto first_packet = make_import_packet(
            make_ipv4_tls_packet(flow_key, sequence_number, first_payload),
            0U
        );
        PFL_REQUIRE(process_packet_with_unified_dissection(
            first_packet,
            state,
            *registry_result.registry,
            service
        ));

        auto* connection = state.ipv4_connections.find(make_connection_key(flow_key));
        PFL_REQUIRE(connection != nullptr);
        PFL_EXPECT(connection->service_hint.empty());

        set_pending_tls_client_hello(connection->hint_search_state, ConnectionFlowSlot::flow_a);
        PFL_REQUIRE(has_pending_tls_client_hello(connection->hint_search_state));
        PFL_EXPECT(!service.has_pending_tls_client_hello(flow_key));

        auto second_packet = make_import_packet(
            make_ipv4_tls_packet(
                flow_key,
                tcp_next_sequence(sequence_number, first_payload.size(), 0x18U),
                second_payload
            ),
            1U
        );
        PFL_REQUIRE(process_packet_with_unified_dissection(
            second_packet,
            state,
            *registry_result.registry,
            service
        ));

        connection = state.ipv4_connections.find(make_connection_key(flow_key));
        PFL_REQUIRE(connection != nullptr);
        PFL_EXPECT(!has_pending_tls_client_hello(connection->hint_search_state));
        PFL_EXPECT(connection->protocol_hint == FlowProtocolHint::unknown);
        PFL_EXPECT(connection->service_hint.empty());
        PFL_EXPECT(!service.has_pending_tls_client_hello(flow_key));
        PFL_EXPECT(service.pending_tls_client_hello_candidate_count() == 0U);
        PFL_EXPECT(service.pending_tls_client_hello_retained_bytes() == 0U);
    }

    {
        const std::string sni {"ipv6.example.test"};
        const auto payload = make_client_hello_payload_for_sni(sni);
        const auto split_offset = split_before_sni_name(payload, sni);
        const auto first_payload = take_prefix(payload, split_offset);
        const auto second_payload = payload_suffix(payload, split_offset);
        const auto flow_key = tls_flow_key_v6();
        constexpr std::uint32_t sequence_number = 4000U;

        FlowHintService service {};
        PFL_EXPECT(service.retain_tls_client_hello_prefix(
            make_ipv6_tls_packet(flow_key, sequence_number, first_payload),
            kLinkTypeEthernet,
            flow_key,
            terminal_tcp_bounds(74U, first_payload.size()),
            sequence_number,
            0x18U
        ));
        const auto hint = service.attempt_tls_client_hello_continuation(
            make_ipv6_tls_packet(flow_key, tcp_next_sequence(sequence_number, first_payload.size(), 0x18U), second_payload),
            kLinkTypeEthernet,
            flow_key,
            terminal_tcp_bounds(74U, second_payload.size()),
            tcp_next_sequence(sequence_number, first_payload.size(), 0x18U)
        );
        PFL_EXPECT(hint.protocol_hint == FlowProtocolHint::tls);
        PFL_EXPECT(hint.service_hint == sni);
        PFL_EXPECT(service.pending_tls_client_hello_candidate_count() == 0U);
    }

    {
        const auto too_large_prefix = make_large_incomplete_client_hello_prefix(4097U);
        const auto flow_key = tls_flow_key_v4(ipv4(10, 80, 9, 1), ipv4(10, 80, 9, 2));
        const auto packet = make_ethernet_ipv4_tcp_packet_with_bytes_payload_and_sequence(
            flow_key.src_addr,
            flow_key.dst_addr,
            flow_key.src_port,
            flow_key.dst_port,
            too_large_prefix,
            1U,
            0U,
            0x18U
        );
        FlowHintService service {};
        PFL_EXPECT(!service.retain_tls_client_hello_prefix(
            packet,
            kLinkTypeEthernet,
            flow_key,
            terminal_tcp_bounds(54U, too_large_prefix.size()),
            1U,
            0x18U
        ));
        PFL_EXPECT(service.pending_tls_client_hello_candidate_count() == 0U);
    }

    {
        const auto small_prefix = make_large_incomplete_client_hello_prefix(64U);
        FlowHintService service {};
        for (std::uint32_t index = 0U; index < 4096U; ++index) {
            const auto flow_key = tls_flow_key_v4(
                ipv4(10, 81, static_cast<std::uint8_t>((index >> 8U) & 0xFFU), static_cast<std::uint8_t>(index & 0xFFU)),
                ipv4(10, 82, 0, 1)
            );
            const auto packet = make_ethernet_ipv4_tcp_packet_with_bytes_payload_and_sequence(
                flow_key.src_addr,
                flow_key.dst_addr,
                flow_key.src_port,
                flow_key.dst_port,
                small_prefix,
                index,
                0U,
                0x18U
            );
            PFL_EXPECT(service.retain_tls_client_hello_prefix(
                packet,
                kLinkTypeEthernet,
                flow_key,
                terminal_tcp_bounds(54U, small_prefix.size()),
                index,
                0x18U
            ));
        }
        PFL_EXPECT(service.pending_tls_client_hello_candidate_count() == 4096U);
        const auto overflow_key = tls_flow_key_v4(ipv4(10, 83, 0, 1), ipv4(10, 84, 0, 1));
        const auto overflow_packet = make_ethernet_ipv4_tcp_packet_with_bytes_payload_and_sequence(
            overflow_key.src_addr,
            overflow_key.dst_addr,
            overflow_key.src_port,
            overflow_key.dst_port,
            small_prefix,
            5000U,
            0U,
            0x18U
        );
        PFL_EXPECT(!service.retain_tls_client_hello_prefix(
            overflow_packet,
            kLinkTypeEthernet,
            overflow_key,
            terminal_tcp_bounds(54U, small_prefix.size()),
            5000U,
            0x18U
        ));
    }

    {
        const auto large_prefix = make_large_incomplete_client_hello_prefix(4096U);
        FlowHintService service {};
        for (std::uint32_t index = 0U; index < 2048U; ++index) {
            const auto flow_key = tls_flow_key_v4(
                ipv4(10, 85, static_cast<std::uint8_t>((index >> 8U) & 0xFFU), static_cast<std::uint8_t>(index & 0xFFU)),
                ipv4(10, 86, 0, 1)
            );
            const auto packet = make_ethernet_ipv4_tcp_packet_with_bytes_payload_and_sequence(
                flow_key.src_addr,
                flow_key.dst_addr,
                flow_key.src_port,
                flow_key.dst_port,
                large_prefix,
                index,
                0U,
                0x18U
            );
            PFL_EXPECT(service.retain_tls_client_hello_prefix(
                packet,
                kLinkTypeEthernet,
                flow_key,
                terminal_tcp_bounds(54U, large_prefix.size()),
                index,
                0x18U
            ));
        }
        PFL_EXPECT(service.pending_tls_client_hello_retained_bytes() == (static_cast<std::size_t>(2048U) * 4096U));
        const auto overflow_key = tls_flow_key_v4(ipv4(10, 87, 0, 1), ipv4(10, 88, 0, 1));
        const auto small_prefix = make_large_incomplete_client_hello_prefix(64U);
        const auto overflow_packet = make_ethernet_ipv4_tcp_packet_with_bytes_payload_and_sequence(
            overflow_key.src_addr,
            overflow_key.dst_addr,
            overflow_key.src_port,
            overflow_key.dst_port,
            small_prefix,
            6000U,
            0U,
            0x18U
        );
        PFL_EXPECT(!service.retain_tls_client_hello_prefix(
            overflow_packet,
            kLinkTypeEthernet,
            overflow_key,
            terminal_tcp_bounds(54U, small_prefix.size()),
            6000U,
            0x18U
        ));
    }

    {
        const std::string sni {"discard.example.test"};
        const auto payload = make_client_hello_payload_for_sni(sni);
        const auto split_offset = split_before_sni_name(payload, sni);
        const auto first_payload = take_prefix(payload, split_offset);
        const auto flow_key = tls_flow_key_v4(ipv4(10, 80, 10, 1), ipv4(10, 80, 10, 2));
        constexpr std::uint32_t sequence_number = 7000U;
        const auto packet = make_ethernet_ipv4_tcp_packet_with_bytes_payload_and_sequence(
            flow_key.src_addr,
            flow_key.dst_addr,
            flow_key.src_port,
            flow_key.dst_port,
            first_payload,
            sequence_number,
            0U,
            0x18U
        );

        FlowHintService service {};
        PFL_EXPECT(service.retain_tls_client_hello_prefix(
            packet,
            kLinkTypeEthernet,
            flow_key,
            terminal_tcp_bounds(54U, first_payload.size()),
            sequence_number,
            0x18U
        ));
        PFL_EXPECT(service.pending_tls_client_hello_retained_bytes() == first_payload.size());
        service.discard_pending_tls_client_hello(flow_key);
        PFL_EXPECT(!service.has_pending_tls_client_hello(flow_key));
        PFL_EXPECT(service.pending_tls_client_hello_retained_bytes() == 0U);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(
            std::filesystem::path(__FILE__).parent_path().parent_path() /
            "data" / "parsing/tls/tls_sni_in_second_segment_20.pcap"
        ));
        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 1U);
        PFL_EXPECT(rows[0].protocol_hint == "tls");
        PFL_EXPECT(rows[0].service_hint == "edge.microsoft.com");
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
        const auto hint = detect_tcp_flow_hint(make_mqtt_connect_payload(), 57000U, 31883U);
        PFL_EXPECT(hint.protocol_hint == FlowProtocolHint::mqtt);
        PFL_EXPECT(hint.service_hint.empty());
    }

    {
        const auto hint = detect_tcp_flow_hint({0x10U, 0x80U}, 57000U, 31883U);
        PFL_EXPECT(hint.protocol_hint == FlowProtocolHint::unknown);
        PFL_EXPECT(hint.service_hint.empty());
    }

    {
        const auto hint = detect_tcp_flow_hint({0x10U, 0x80U, 0x80U, 0x80U, 0x80U, 0x00U}, 57000U, 31883U);
        PFL_EXPECT(hint.protocol_hint == FlowProtocolHint::unknown);
        PFL_EXPECT(hint.service_hint.empty());
    }

    {
        const auto hint = detect_tcp_flow_hint(make_mqtt_connect_payload("MQTT", 4U, 0x1EU), 57000U, 31883U);
        PFL_EXPECT(hint.protocol_hint == FlowProtocolHint::unknown);
        PFL_EXPECT(hint.service_hint.empty());
    }

    {
        const auto hint = detect_tcp_flow_hint(make_mqtt_connect_payload("MQTT", 4U, 0x0AU), 57000U, 31883U);
        PFL_EXPECT(hint.protocol_hint == FlowProtocolHint::unknown);
        PFL_EXPECT(hint.service_hint.empty());
    }

    {
        const auto hint = detect_tcp_flow_hint(make_mqtt_connect_payload("MQTT", 4U, 0x22U), 57000U, 31883U);
        PFL_EXPECT(hint.protocol_hint == FlowProtocolHint::unknown);
        PFL_EXPECT(hint.service_hint.empty());
    }

    {
        const std::vector<std::uint8_t> mqtt_password {'p', 'a', 's', 's'};

        const auto hint = detect_tcp_flow_hint(
            make_mqtt_connect_payload("MQIsdp", 3U, 0x42U, "pfl-mqtt-client", {}, {}, {}, {}, {}, mqtt_password),
            57000U,
            31883U);
        PFL_EXPECT(hint.protocol_hint == FlowProtocolHint::unknown);
        PFL_EXPECT(hint.service_hint.empty());
    }

    {
        const std::vector<std::uint8_t> mqtt_password {'p', 'a', 's', 's'};

        const auto hint = detect_tcp_flow_hint(
            make_mqtt_connect_payload("MQTT", 4U, 0x42U, "pfl-mqtt-client", {}, {}, {}, {}, {}, mqtt_password),
            57000U,
            31883U);
        PFL_EXPECT(hint.protocol_hint == FlowProtocolHint::unknown);
        PFL_EXPECT(hint.service_hint.empty());
    }

    {
        const std::vector<std::uint8_t> mqtt_password {'p', 'a', 's', 's'};

        const auto hint = detect_tcp_flow_hint(
            make_mqtt_connect_payload("MQTT", 5U, 0x42U, "pfl-mqtt-client", {}, {}, {}, {}, {}, mqtt_password),
            57000U,
            31883U);
        PFL_EXPECT(hint.protocol_hint == FlowProtocolHint::mqtt);
        PFL_EXPECT(hint.service_hint.empty());
    }

    {
        const auto hint = detect_tcp_flow_hint(make_mqtt5_connect_with_oversized_property_length(), 57000U, 31883U);
        PFL_EXPECT(hint.protocol_hint == FlowProtocolHint::unknown);
        PFL_EXPECT(hint.service_hint.empty());
    }

    {
        auto payload = make_mqtt_connect_payload();
        payload.push_back(0xC0U);
        payload.push_back(0x00U);

        const auto hint = detect_tcp_flow_hint(payload, 57000U, 31883U);
        PFL_EXPECT(hint.protocol_hint == FlowProtocolHint::mqtt);
        PFL_EXPECT(hint.service_hint.empty());
    }

    {
        const auto hint = detect_tcp_flow_hint(make_amqp_header_payload(0x00U, 0x00U, 0x09U, 0x01U), 58000U, 5672U);
        PFL_EXPECT(hint.protocol_hint == FlowProtocolHint::amqp);
        PFL_EXPECT(hint.service_hint.empty());
    }

    {
        const auto hint = detect_tcp_flow_hint(make_amqp_header_payload(0x00U, 0x01U, 0x00U, 0x00U), 58000U, 5672U);
        PFL_EXPECT(hint.protocol_hint == FlowProtocolHint::amqp);
        PFL_EXPECT(hint.service_hint.empty());
    }

    {
        const auto hint = detect_tcp_flow_hint(make_amqp_header_payload(0x02U, 0x01U, 0x00U, 0x00U), 58000U, 5671U);
        PFL_EXPECT(hint.protocol_hint == FlowProtocolHint::amqp);
        PFL_EXPECT(hint.service_hint.empty());
    }

    {
        const auto hint = detect_tcp_flow_hint(make_amqp_header_payload(0x03U, 0x01U, 0x00U, 0x00U), 58000U, 35672U);
        PFL_EXPECT(hint.protocol_hint == FlowProtocolHint::amqp);
        PFL_EXPECT(hint.service_hint.empty());
    }

    {
        const auto hint = detect_tcp_flow_hint(make_amqp_header_payload(0x00U, 0x00U, 0x09U, 0x01U), 58000U, 35672U);
        PFL_EXPECT(hint.protocol_hint == FlowProtocolHint::amqp);
        PFL_EXPECT(hint.service_hint.empty());
    }

    {
        auto payload = make_amqp_header_payload(0x00U, 0x01U, 0x00U, 0x00U);
        payload.insert(payload.end(), {'t', 'r', 'a', 'i', 'l', 'i', 'n', 'g'});

        const auto hint = detect_tcp_flow_hint(payload, 58000U, 5672U);
        PFL_EXPECT(hint.protocol_hint == FlowProtocolHint::amqp);
        PFL_EXPECT(hint.service_hint.empty());
    }

    {
        auto payload = make_amqp_header_payload(0x00U, 0x00U, 0x09U, 0x01U);
        payload.pop_back();

        const auto hint = detect_tcp_flow_hint(payload, 58000U, 5672U);
        PFL_EXPECT(hint.protocol_hint == FlowProtocolHint::unknown);
        PFL_EXPECT(hint.service_hint.empty());
    }

    {
        const auto hint = detect_tcp_flow_hint(make_amqp_header_payload(0x01U, 0x01U, 0x00U, 0x00U), 58000U, 5672U);
        PFL_EXPECT(hint.protocol_hint == FlowProtocolHint::unknown);
        PFL_EXPECT(hint.service_hint.empty());
    }

    {
        const auto hint = detect_tcp_flow_hint(make_amqp_header_payload(0x00U, 0x00U, 0x09U, 0x00U), 58000U, 5672U);
        PFL_EXPECT(hint.protocol_hint == FlowProtocolHint::unknown);
        PFL_EXPECT(hint.service_hint.empty());
    }

    {
        const auto hint = detect_tcp_flow_hint(make_amqp_header_payload(0x00U, 0x01U, 0x00U, 0x01U), 58000U, 5672U);
        PFL_EXPECT(hint.protocol_hint == FlowProtocolHint::unknown);
        PFL_EXPECT(hint.service_hint.empty());
    }

    {
        std::vector<std::uint8_t> payload {'P', 'F', 'L', '-'};
        const auto amqp_header = make_amqp_header_payload(0x00U, 0x01U, 0x00U, 0x00U);
        payload.insert(payload.end(), amqp_header.begin(), amqp_header.end());

        const auto hint = detect_tcp_flow_hint(payload, 58000U, 5672U);
        PFL_EXPECT(hint.protocol_hint == FlowProtocolHint::unknown);
        PFL_EXPECT(hint.service_hint.empty());
    }

    {
        const auto hint = detect_udp_flow_hint(make_ntp_payload(4U, 3U, 0U), 59000U, 123U);
        PFL_EXPECT(hint.protocol_hint == FlowProtocolHint::ntp);
        PFL_EXPECT(hint.service_hint.empty());
    }

    {
        const auto hint = detect_udp_flow_hint(make_ntp_payload(4U, 4U, 2U), 123U, 59000U);
        PFL_EXPECT(hint.protocol_hint == FlowProtocolHint::ntp);
        PFL_EXPECT(hint.service_hint.empty());
    }

    {
        const auto client_hint = detect_udp_flow_hint(make_ntp_payload(3U, 3U, 0U), 59000U, 123U);
        PFL_EXPECT(client_hint.protocol_hint == FlowProtocolHint::ntp);
        PFL_EXPECT(client_hint.service_hint.empty());

        const auto server_hint = detect_udp_flow_hint(make_ntp_payload(3U, 4U, 3U), 123U, 59000U);
        PFL_EXPECT(server_hint.protocol_hint == FlowProtocolHint::ntp);
        PFL_EXPECT(server_hint.service_hint.empty());
    }

    {
        const auto kod_hint = detect_udp_flow_hint(make_ntp_payload(4U, 4U, 0U), 123U, 59000U);
        PFL_EXPECT(kod_hint.protocol_hint == FlowProtocolHint::ntp);
        PFL_EXPECT(kod_hint.service_hint.empty());

        const auto unsynchronized_hint = detect_udp_flow_hint(make_ntp_payload(4U, 3U, 0U, 3U), 59000U, 123U);
        PFL_EXPECT(unsynchronized_hint.protocol_hint == FlowProtocolHint::ntp);
        PFL_EXPECT(unsynchronized_hint.service_hint.empty());
    }

    {
        const auto max_supported_stratum_hint = detect_udp_flow_hint(make_ntp_payload(4U, 4U, 16U), 123U, 59000U);
        PFL_EXPECT(max_supported_stratum_hint.protocol_hint == FlowProtocolHint::ntp);
        PFL_EXPECT(max_supported_stratum_hint.service_hint.empty());

        const auto unsupported_stratum_hint = detect_udp_flow_hint(make_ntp_payload(4U, 4U, 17U), 123U, 59000U);
        PFL_EXPECT(unsupported_stratum_hint.protocol_hint == FlowProtocolHint::unknown);
        PFL_EXPECT(unsupported_stratum_hint.service_hint.empty());
    }

    {
        const auto ntpv2_hint = detect_udp_flow_hint(make_ntp_payload(2U, 3U, 0U), 59000U, 123U);
        PFL_EXPECT(ntpv2_hint.protocol_hint == FlowProtocolHint::unknown);
        PFL_EXPECT(ntpv2_hint.service_hint.empty());

        const auto broadcast_hint = detect_udp_flow_hint(make_ntp_payload(4U, 5U, 2U), 123U, 59000U);
        PFL_EXPECT(broadcast_hint.protocol_hint == FlowProtocolHint::unknown);
        PFL_EXPECT(broadcast_hint.service_hint.empty());
    }

    {
        auto truncated = make_ntp_payload(4U, 3U, 0U);
        truncated.pop_back();
        const auto truncated_hint = detect_udp_flow_hint(truncated, 59000U, 123U);
        PFL_EXPECT(truncated_hint.protocol_hint == FlowProtocolHint::unknown);
        PFL_EXPECT(truncated_hint.service_hint.empty());

        auto longer = make_ntp_payload(4U, 3U, 0U);
        longer.push_back(0U);
        const auto longer_hint = detect_udp_flow_hint(longer, 59000U, 123U);
        PFL_EXPECT(longer_hint.protocol_hint == FlowProtocolHint::unknown);
        PFL_EXPECT(longer_hint.service_hint.empty());
    }

    {
        auto declared_longer_payload = make_ntp_payload(4U, 3U, 0U);
        declared_longer_payload.push_back(0U);
        auto truncated_packet = make_ethernet_ipv4_udp_packet_with_bytes_payload(
            ipv4(10, 0, 1, 1),
            ipv4(10, 0, 1, 2),
            59000U,
            123U,
            declared_longer_payload
        );
        truncated_packet.pop_back();

        FlowHintService service {};
        const auto hint = service.detect(truncated_packet, FlowKeyV4 {
            .src_addr = ipv4(10, 0, 1, 1),
            .dst_addr = ipv4(10, 0, 1, 2),
            .src_port = 59000U,
            .dst_port = 123U,
            .protocol = ProtocolId::udp,
        });
        PFL_EXPECT(hint.protocol_hint == FlowProtocolHint::unknown);
        PFL_EXPECT(hint.service_hint.empty());
    }

    {
        const auto client_direction_mismatch_hint = detect_udp_flow_hint(make_ntp_payload(4U, 3U, 0U), 123U, 59000U);
        PFL_EXPECT(client_direction_mismatch_hint.protocol_hint == FlowProtocolHint::unknown);
        PFL_EXPECT(client_direction_mismatch_hint.service_hint.empty());

        const auto server_direction_mismatch_hint = detect_udp_flow_hint(make_ntp_payload(4U, 4U, 2U), 59000U, 123U);
        PFL_EXPECT(server_direction_mismatch_hint.protocol_hint == FlowProtocolHint::unknown);
        PFL_EXPECT(server_direction_mismatch_hint.service_hint.empty());

        const auto wrong_port_hint = detect_udp_flow_hint(make_ntp_payload(4U, 3U, 0U), 59000U, 30123U);
        PFL_EXPECT(wrong_port_hint.protocol_hint == FlowProtocolHint::unknown);
        PFL_EXPECT(wrong_port_hint.service_hint.empty());
    }

    {
        std::vector<std::uint8_t> payload(48U, 0xFFU);
        const auto hint = detect_udp_flow_hint(payload, 59000U, 123U);
        PFL_EXPECT(hint.protocol_hint == FlowProtocolHint::unknown);
        PFL_EXPECT(hint.service_hint.empty());
    }

    {
        const auto hint = detect_tcp_flow_hint(make_ntp_payload(4U, 3U, 0U), 59000U, 123U);
        PFL_EXPECT(hint.protocol_hint == FlowProtocolHint::unknown);
        PFL_EXPECT(hint.service_hint.empty());
    }

    {
        const auto hint = detect_udp_flow_hint(make_stun_binding_request_payload(), 123U, 59000U);
        PFL_EXPECT(hint.protocol_hint == FlowProtocolHint::stun);
        PFL_EXPECT(hint.service_hint.empty());
    }

    {
        ConnectionV4 connection {};
        connection.protocol_hint = FlowProtocolHint::mqtt;
        PFL_EXPECT(connection.hint_detection_settled());
    }

    {
        ConnectionV4 connection {};
        connection.protocol_hint = FlowProtocolHint::amqp;
        PFL_EXPECT(connection.hint_detection_settled());
    }

    {
        ConnectionV4 connection {};
        connection.protocol_hint = FlowProtocolHint::ntp;
        PFL_EXPECT(connection.service_hint.empty());
        PFL_EXPECT(connection.hint_detection_settled());
    }

    {
        PFL_EXPECT(std::string_view(flow_protocol_hint_text(FlowProtocolHint::amqp)) == "amqp");
        PFL_EXPECT(std::string_view(flow_protocol_hint_text(FlowProtocolHint::ntp)) == "ntp");
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
        std::filesystem::remove(index_path);

        CaptureSession original_session {};
        PFL_EXPECT(original_session.open_capture(http_capture_path));
        PFL_EXPECT(original_session.save_index(index_path));

        CaptureSession loaded_session {};
        PFL_EXPECT(loaded_session.load_index(index_path));
        const auto loaded_rows = loaded_session.list_flows();
        PFL_EXPECT(loaded_rows.size() == 1);
        PFL_EXPECT(loaded_rows[0].protocol_hint == "http");
        PFL_EXPECT(loaded_rows[0].service_hint == "www.example.com");
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


