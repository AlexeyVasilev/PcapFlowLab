#include <algorithm>
#include <cstddef>
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

std::vector<std::uint8_t> make_tls_record(
    const std::uint8_t content_type,
    const std::uint16_t version,
    const std::vector<std::uint8_t>& body
) {
    std::vector<std::uint8_t> record {};
    record.reserve(5U + body.size());
    record.push_back(content_type);
    append_be16(record, version);
    append_be16(record, static_cast<std::uint16_t>(body.size()));
    record.insert(record.end(), body.begin(), body.end());
    return record;
}

std::vector<std::uint8_t> make_tls_handshake_record(
    const std::uint8_t handshake_type,
    const std::vector<std::uint8_t>& body = {},
    const std::uint16_t version = 0x0303U
) {
    std::vector<std::uint8_t> handshake {};
    handshake.reserve(4U + body.size());
    handshake.push_back(handshake_type);
    append_be24(handshake, static_cast<std::uint32_t>(body.size()));
    handshake.insert(handshake.end(), body.begin(), body.end());
    return make_tls_record(0x16U, version, handshake);
}

std::vector<std::uint8_t> make_tls_change_cipher_spec_record(const std::uint16_t version = 0x0303U) {
    return make_tls_record(0x14U, version, std::vector<std::uint8_t> {0x01U});
}

std::vector<std::uint8_t> make_tls_alert_record(
    const std::uint8_t level = 0x01U,
    const std::uint8_t description = 0x00U,
    const std::uint16_t version = 0x0303U
) {
    return make_tls_record(0x15U, version, std::vector<std::uint8_t> {level, description});
}

std::vector<std::uint8_t> concat_bytes(
    const std::vector<std::uint8_t>& first,
    const std::vector<std::uint8_t>& second
) {
    std::vector<std::uint8_t> combined {};
    combined.reserve(first.size() + second.size());
    combined.insert(combined.end(), first.begin(), first.end());
    combined.insert(combined.end(), second.begin(), second.end());
    return combined;
}

std::vector<std::uint8_t> make_text_bytes(const std::string_view text) {
    return std::vector<std::uint8_t>(text.begin(), text.end());
}

void append_quic_varint(std::vector<std::uint8_t>& bytes, const std::uint64_t value) {
    if (value < 64U) {
        bytes.push_back(static_cast<std::uint8_t>(value));
        return;
    }

    PFL_EXPECT(value < 16384U);
    bytes.push_back(static_cast<std::uint8_t>(0x40U | ((value >> 8U) & 0x3FU)));
    bytes.push_back(static_cast<std::uint8_t>(value & 0xFFU));
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

    append_quic_varint(payload, frame_bytes.size() + 1U);
    payload.push_back(0x00U);
    payload.insert(payload.end(), frame_bytes.begin(), frame_bytes.end());
    return payload;
}

std::vector<std::uint8_t> make_quic_crypto_frame_bytes(const std::vector<std::uint8_t>& crypto_bytes) {
    std::vector<std::uint8_t> frame {0x06U, 0x00U};
    append_quic_varint(frame, crypto_bytes.size());
    frame.insert(frame.end(), crypto_bytes.begin(), crypto_bytes.end());
    return frame;
}

std::vector<std::uint8_t> make_quic_crypto_frame_bytes(
    const std::uint64_t crypto_offset,
    const std::vector<std::uint8_t>& crypto_bytes
) {
    std::vector<std::uint8_t> frame {0x06U};
    append_quic_varint(frame, crypto_offset);
    append_quic_varint(frame, crypto_bytes.size());
    frame.insert(frame.end(), crypto_bytes.begin(), crypto_bytes.end());
    return frame;
}

std::vector<std::uint8_t> make_quic_crypto_frame_bytes() {
    return make_quic_crypto_frame_bytes(std::vector<std::uint8_t> {'a', 'b', 'c'});
}

std::vector<std::uint8_t> make_tls_client_hello_handshake_bytes() {
    const std::vector<std::uint8_t> server_name {'s', 't', 'a', 'g', 'e', '1', '.', 'e', 'x', 'a', 'm', 'p', 'l', 'e'};

    std::vector<std::uint8_t> sni_extension_data {};
    append_be16(sni_extension_data, static_cast<std::uint16_t>(server_name.size() + 3U));
    sni_extension_data.push_back(0x00U);
    append_be16(sni_extension_data, static_cast<std::uint16_t>(server_name.size()));
    sni_extension_data.insert(sni_extension_data.end(), server_name.begin(), server_name.end());

    std::vector<std::uint8_t> supported_versions_extension_data {0x02U, 0x03U, 0x04U};

    std::vector<std::uint8_t> extensions {};
    append_be16(extensions, 0x0000U);
    append_be16(extensions, static_cast<std::uint16_t>(sni_extension_data.size()));
    extensions.insert(extensions.end(), sni_extension_data.begin(), sni_extension_data.end());
    append_be16(extensions, 0x002BU);
    append_be16(extensions, static_cast<std::uint16_t>(supported_versions_extension_data.size()));
    extensions.insert(extensions.end(), supported_versions_extension_data.begin(), supported_versions_extension_data.end());

    std::vector<std::uint8_t> body {};
    body.push_back(0x03U);
    body.push_back(0x03U);
    for (std::uint8_t index = 0U; index < 32U; ++index) {
        body.push_back(static_cast<std::uint8_t>(0x20U + index));
    }
    body.push_back(0x00U);
    append_be16(body, 0x0002U);
    append_be16(body, 0x1301U);
    body.push_back(0x01U);
    body.push_back(0x00U);
    append_be16(body, static_cast<std::uint16_t>(extensions.size()));
    body.insert(body.end(), extensions.begin(), extensions.end());

    std::vector<std::uint8_t> handshake {0x01U};
    append_be24(handshake, static_cast<std::uint32_t>(body.size()));
    handshake.insert(handshake.end(), body.begin(), body.end());
    return handshake;
}

std::vector<std::uint8_t> make_quic_ack_frame_bytes() {
    return {0x02U, 0x00U, 0x00U, 0x00U, 0x00U};
}

std::vector<std::uint8_t> make_quic_padding_frame_bytes(const std::size_t count = 1U) {
    return std::vector<std::uint8_t>(count, 0x00U);
}

std::vector<std::uint8_t> make_quic_ping_frame_bytes() {
    return {0x01U};
}

std::vector<std::uint8_t> make_quic_truncated_payload() {
    return {
        0xC0U,
        0x00U, 0x00U, 0x00U, 0x01U,
        0x08U,
        0x11U, 0x22U, 0x33U, 0x44U,
    };
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

std::string direction_for_packet(const std::vector<PacketRow>& packet_rows, const std::uint64_t packet_index) {
    for (const auto& row : packet_rows) {
        if (row.packet_index == packet_index) {
            return row.direction_text;
        }
    }

    PFL_EXPECT(false);
    return {};
}

std::filesystem::path fixture_path(const std::filesystem::path& relative_path) {
    return std::filesystem::path(__FILE__).parent_path().parent_path() / "data" / relative_path;
}

bool starts_with(const std::string_view value, const std::string_view prefix) {
    return value.rfind(prefix, 0U) == 0U;
}

const StreamItemRow* find_stream_row_by_label(const std::vector<StreamItemRow>& rows, const std::string_view label) {
    const auto it = std::find_if(rows.begin(), rows.end(), [&](const StreamItemRow& row) {
        return row.label == label;
    });
    return it == rows.end() ? nullptr : &(*it);
}

std::size_t count_stream_rows_by_label(const std::vector<StreamItemRow>& rows, const std::string_view label) {
    return static_cast<std::size_t>(std::count_if(rows.begin(), rows.end(), [&](const StreamItemRow& row) {
        return row.label == label;
    }));
}

}  // namespace

void run_stream_query_tests() {
    const auto forward_payload = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
        ipv4(10, 40, 0, 1), ipv4(10, 40, 0, 2), 51000, 443, std::vector<std::uint8_t> {'A', 'B', 'C'}, 0x18);
    const auto reverse_ack = make_ethernet_ipv4_tcp_packet(
        ipv4(10, 40, 0, 2), ipv4(10, 40, 0, 1), 443, 51000);
    const auto reverse_payload = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
        ipv4(10, 40, 0, 2), ipv4(10, 40, 0, 1), 443, 51000, std::vector<std::uint8_t> {'O', 'K'}, 0x18);

    const auto path = write_temp_pcap(
        "pfl_stream_query.pcap",
        make_classic_pcap({
            {100, forward_payload},
            {200, reverse_ack},
            {300, reverse_payload},
        })
    );

    CaptureSession session {};
    PFL_EXPECT(session.open_capture(path));

    const auto packet_rows = session.list_flow_packets(0);
    PFL_EXPECT(packet_rows.size() == 3);

    const auto stream_rows = session.list_flow_stream_items(0);
    PFL_EXPECT(stream_rows.size() == 2);
    PFL_EXPECT(stream_rows[0].stream_item_index == 1);
    PFL_EXPECT(stream_rows[1].stream_item_index == 2);
    PFL_EXPECT(stream_rows[0].packet_indices == std::vector<std::uint64_t> {0});
    PFL_EXPECT(stream_rows[1].packet_indices == std::vector<std::uint64_t> {2});
    PFL_EXPECT(stream_rows[0].direction_text == direction_for_packet(packet_rows, 0));
    PFL_EXPECT(stream_rows[1].direction_text == direction_for_packet(packet_rows, 2));
    PFL_EXPECT(stream_rows[0].byte_count == 3);
    PFL_EXPECT(stream_rows[1].byte_count == 2);
    PFL_EXPECT(stream_rows[0].packet_count == 1);
    PFL_EXPECT(stream_rows[1].packet_count == 1);
    PFL_EXPECT(stream_rows[0].label == "TCP Payload");
    PFL_EXPECT(stream_rows[1].label == "TCP Payload");

    const auto duplicate_segment_packet_a = make_ethernet_ipv4_tcp_packet_with_bytes_payload_and_sequence(
        ipv4(10, 40, 1, 1), ipv4(10, 40, 1, 2), 51001, 443, std::vector<std::uint8_t> {'D', 'U', 'P'}, 1000U, 2000U, 0x18);
    const auto duplicate_segment_packet_b = make_ethernet_ipv4_tcp_packet_with_bytes_payload_and_sequence(
        ipv4(10, 40, 1, 1), ipv4(10, 40, 1, 2), 51001, 443, std::vector<std::uint8_t> {'D', 'U', 'P'}, 1000U, 2000U, 0x18);
    const auto duplicate_segment_path = write_temp_pcap(
        "pfl_stream_query_duplicate_segment.pcap",
        make_classic_pcap({
            {100, duplicate_segment_packet_a},
            {200, duplicate_segment_packet_b},
        })
    );

    CaptureSession duplicate_segment_session {};
    PFL_EXPECT(duplicate_segment_session.open_capture(duplicate_segment_path));
    const auto duplicate_packet_rows = duplicate_segment_session.list_flow_packets(0);
    PFL_EXPECT(duplicate_packet_rows.size() == 2U);
    const auto duplicate_suppressed_packet_indices = duplicate_segment_session.suspected_tcp_retransmission_packet_indices(0);
    PFL_EXPECT(duplicate_suppressed_packet_indices == std::vector<std::uint64_t> {1U});
    duplicate_segment_session.set_selected_flow_tcp_payload_suppression(0U, duplicate_suppressed_packet_indices);
    const auto duplicate_segment_rows = duplicate_segment_session.list_flow_stream_items(0);
    PFL_EXPECT(duplicate_segment_rows.size() == 1U);
    PFL_EXPECT(duplicate_segment_rows[0].label == "TCP Payload");
    PFL_EXPECT(duplicate_segment_rows[0].packet_count == 1U);
    PFL_EXPECT(duplicate_segment_rows[0].packet_indices == std::vector<std::uint64_t> {0U});

    const auto similar_segment_packet_a = make_ethernet_ipv4_tcp_packet_with_bytes_payload_and_sequence(
        ipv4(10, 40, 2, 1), ipv4(10, 40, 2, 2), 51002, 443, std::vector<std::uint8_t> {'A', 'A', 'A'}, 1000U, 2000U, 0x18);
    const auto similar_segment_packet_b = make_ethernet_ipv4_tcp_packet_with_bytes_payload_and_sequence(
        ipv4(10, 40, 2, 1), ipv4(10, 40, 2, 2), 51002, 443, std::vector<std::uint8_t> {'B', 'B', 'B'}, 1000U, 2000U, 0x18);
    const auto similar_segment_path = write_temp_pcap(
        "pfl_stream_query_similar_segment.pcap",
        make_classic_pcap({
            {100, similar_segment_packet_a},
            {200, similar_segment_packet_b},
        })
    );

    CaptureSession similar_segment_session {};
    PFL_EXPECT(similar_segment_session.open_capture(similar_segment_path));
    const auto similar_suppressed_packet_indices = similar_segment_session.suspected_tcp_retransmission_packet_indices(0);
    PFL_EXPECT(similar_suppressed_packet_indices.empty());
    similar_segment_session.set_selected_flow_tcp_payload_suppression(0U, similar_suppressed_packet_indices);
    const auto similar_segment_rows = similar_segment_session.list_flow_stream_items(0);
    PFL_EXPECT(similar_segment_rows.size() == 2U);
    PFL_EXPECT(similar_segment_rows[0].packet_indices == std::vector<std::uint64_t> {0U});
    PFL_EXPECT(similar_segment_rows[1].packet_indices == std::vector<std::uint64_t> {1U});

    const auto partial_overlap_packet_a = make_ethernet_ipv4_tcp_packet_with_bytes_payload_and_sequence(
        ipv4(10, 40, 3, 1), ipv4(10, 40, 3, 2), 51003, 443, std::vector<std::uint8_t> {'A', 'B', 'C', 'D', 'E'}, 1000U, 2000U, 0x18);
    const auto partial_overlap_packet_b = make_ethernet_ipv4_tcp_packet_with_bytes_payload_and_sequence(
        ipv4(10, 40, 3, 1), ipv4(10, 40, 3, 2), 51003, 443, std::vector<std::uint8_t> {'C', 'D', 'E', 'F', 'G'}, 1002U, 2000U, 0x18);
    const auto partial_overlap_path = write_temp_pcap(
        "pfl_stream_query_partial_overlap_segment.pcap",
        make_classic_pcap({
            {100, partial_overlap_packet_a},
            {200, partial_overlap_packet_b},
        })
    );

    CaptureSession partial_overlap_session {};
    PFL_EXPECT(partial_overlap_session.open_capture(partial_overlap_path));
    const auto partial_overlap_suppressed_packet_indices = partial_overlap_session.suspected_tcp_retransmission_packet_indices(0);
    PFL_EXPECT(partial_overlap_suppressed_packet_indices.empty());
    partial_overlap_session.set_selected_flow_tcp_payload_suppression(0U, partial_overlap_suppressed_packet_indices);
    const auto partial_overlap_rows = partial_overlap_session.list_flow_stream_items(0);
    PFL_EXPECT(partial_overlap_rows.size() == 2U);
    PFL_EXPECT(partial_overlap_rows[0].label == "TCP Payload");
    PFL_EXPECT(partial_overlap_rows[0].byte_count == 5U);
    PFL_EXPECT(partial_overlap_rows[0].packet_indices == std::vector<std::uint64_t> {0U});
    PFL_EXPECT(partial_overlap_rows[1].label == "TCP Payload");
    PFL_EXPECT(partial_overlap_rows[1].byte_count == 2U);
    PFL_EXPECT(partial_overlap_rows[1].packet_indices == std::vector<std::uint64_t> {1U});

    const auto dns_payload = std::vector<std::uint8_t> {
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x03, 'a', 'p', 'i',
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x00,
        0x00, 0x01, 0x00, 0x01,
    };
    const auto dns_packet = make_ethernet_ipv4_udp_packet_with_bytes_payload(
        ipv4(10, 41, 0, 1), ipv4(10, 41, 0, 2), 53000, 53, dns_payload);
    const auto dns_path = write_temp_pcap(
        "pfl_stream_query_dns.pcap",
        make_classic_pcap({{100, dns_packet}})
    );

    CaptureSession dns_session {};
    PFL_EXPECT(dns_session.open_capture(dns_path));
    const auto dns_rows = dns_session.list_flow_stream_items(0);
    PFL_EXPECT(dns_rows.size() == 1);
    PFL_EXPECT(dns_rows[0].label == "UDP Payload");
    PFL_EXPECT(dns_rows[0].byte_count == dns_payload.size());

    const auto server_hello_record = make_tls_handshake_record(0x02U, {0xAA, 0xBB, 0xCC, 0xDD});
    const auto change_cipher_spec_record = make_tls_change_cipher_spec_record();
    const auto tls_multi_payload = concat_bytes(server_hello_record, change_cipher_spec_record);
    const auto tls_multi_packet = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
        ipv4(10, 42, 0, 1), ipv4(10, 42, 0, 2), 443, 52000, tls_multi_payload, 0x18);
    const auto tls_multi_path = write_temp_pcap(
        "pfl_stream_query_tls_multi.pcap",
        make_classic_pcap({{100, tls_multi_packet}})
    );

    CaptureSession tls_multi_session {};
    CaptureImportOptions fast_options {};
    fast_options.mode = ImportMode::fast;

    constexpr std::string_view split_http_request_text =
        "GET /split HTTP/1.1\r\n"
        "Host: split.example\r\n"
        "User-Agent: test\r\n"
        "\r\n";
    const auto split_http_request = make_text_bytes(split_http_request_text);
    const auto split_http_request_a = std::vector<std::uint8_t>(
        split_http_request.begin(),
        split_http_request.begin() + 18
    );
    const auto split_http_request_b = std::vector<std::uint8_t>(
        split_http_request.begin() + 18,
        split_http_request.end()
    );
    const auto split_http_request_packet_a = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
        ipv4(10, 41, 1, 1), ipv4(10, 41, 1, 2), 53010, 80, split_http_request_a, 0x18);
    const auto split_http_request_packet_b = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
        ipv4(10, 41, 1, 1), ipv4(10, 41, 1, 2), 53010, 80, split_http_request_b, 0x18);
    const auto split_http_request_path = write_temp_pcap(
        "pfl_stream_query_http_split_request.pcap",
        make_classic_pcap({
            {100, split_http_request_packet_a},
            {200, split_http_request_packet_b},
        })
    );

    CaptureSession split_http_request_session {};
    PFL_EXPECT(split_http_request_session.open_capture(split_http_request_path, fast_options));
    const auto split_http_request_rows = split_http_request_session.list_flow_stream_items(0);
    PFL_EXPECT(split_http_request_rows.size() == 1);
    PFL_EXPECT(split_http_request_rows[0].label == "HTTP GET /split");
    PFL_EXPECT(split_http_request_rows[0].byte_count == split_http_request.size());
    PFL_EXPECT(split_http_request_rows[0].packet_count == 2);
    const auto expected_http_split_packet_indices = std::vector<std::uint64_t> {0, 1};
    PFL_EXPECT(split_http_request_rows[0].packet_indices == expected_http_split_packet_indices);
    PFL_EXPECT(split_http_request_rows[0].protocol_text.find("Method: GET") != std::string::npos);
    PFL_EXPECT(split_http_request_rows[0].protocol_text.find("Path: /split") != std::string::npos);
    PFL_EXPECT(split_http_request_rows[0].protocol_text.find("Host: split.example") != std::string::npos);

    constexpr std::string_view split_http_response_text =
        "HTTP/1.1 200 OK\r\n"
        "Server: test\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Length: 5\r\n"
        "\r\n";
    const auto split_http_response = make_text_bytes(split_http_response_text);
    const auto split_http_response_a = std::vector<std::uint8_t>(
        split_http_response.begin(),
        split_http_response.begin() + 12
    );
    const auto split_http_response_b = std::vector<std::uint8_t>(
        split_http_response.begin() + 12,
        split_http_response.end()
    );
    const auto split_http_response_packet_a = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
        ipv4(10, 41, 2, 2), ipv4(10, 41, 2, 1), 80, 53011, split_http_response_a, 0x18);
    const auto split_http_response_packet_b = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
        ipv4(10, 41, 2, 2), ipv4(10, 41, 2, 1), 80, 53011, split_http_response_b, 0x18);
    const auto split_http_response_path = write_temp_pcap(
        "pfl_stream_query_http_split_response.pcap",
        make_classic_pcap({
            {100, split_http_response_packet_a},
            {200, split_http_response_packet_b},
        })
    );

    CaptureSession split_http_response_session {};
    PFL_EXPECT(split_http_response_session.open_capture(split_http_response_path, fast_options));
    const auto split_http_response_rows = split_http_response_session.list_flow_stream_items(0);
    PFL_EXPECT(split_http_response_rows.size() == 1);
    PFL_EXPECT(split_http_response_rows[0].label == "HTTP 200 OK");
    PFL_EXPECT(split_http_response_rows[0].byte_count == split_http_response.size());
    PFL_EXPECT(split_http_response_rows[0].packet_count == 2);
    PFL_EXPECT(split_http_response_rows[0].packet_indices == expected_http_split_packet_indices);
    PFL_EXPECT(split_http_response_rows[0].protocol_text.find("Status Code: 200") != std::string::npos);
    PFL_EXPECT(split_http_response_rows[0].protocol_text.find("Reason: OK") != std::string::npos);
    PFL_EXPECT(split_http_response_rows[0].protocol_text.find("Content-Type: text/plain") != std::string::npos);
    PFL_EXPECT(split_http_response_rows[0].protocol_text.find("Content-Length: 5") != std::string::npos);

    constexpr std::string_view http_request_one_text =
        "GET /one HTTP/1.1\r\n"
        "Host: one.example\r\n"
        "\r\n";
    constexpr std::string_view http_request_two_text =
        "GET /two HTTP/1.1\r\n"
        "Host: two.example\r\n"
        "\r\n";
    const auto http_request_one = make_text_bytes(http_request_one_text);
    const auto http_request_two = make_text_bytes(http_request_two_text);
    const auto http_multi_payload = concat_bytes(http_request_one, http_request_two);
    const auto http_multi_split = static_cast<std::ptrdiff_t>(http_request_one.size() + 10U);
    const auto http_multi_payload_a = std::vector<std::uint8_t>(
        http_multi_payload.begin(),
        http_multi_payload.begin() + http_multi_split
    );
    const auto http_multi_payload_b = std::vector<std::uint8_t>(
        http_multi_payload.begin() + http_multi_split,
        http_multi_payload.end()
    );
    const auto http_multi_packet_a = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
        ipv4(10, 41, 3, 1), ipv4(10, 41, 3, 2), 53012, 80, http_multi_payload_a, 0x18);
    const auto http_multi_packet_b = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
        ipv4(10, 41, 3, 1), ipv4(10, 41, 3, 2), 53012, 80, http_multi_payload_b, 0x18);
    const auto http_multi_path = write_temp_pcap(
        "pfl_stream_query_http_multi_headers.pcap",
        make_classic_pcap({
            {100, http_multi_packet_a},
            {200, http_multi_packet_b},
        })
    );

    CaptureSession http_multi_session {};
    PFL_EXPECT(http_multi_session.open_capture(http_multi_path, fast_options));
    const auto http_multi_rows = http_multi_session.list_flow_stream_items(0);
    PFL_EXPECT(http_multi_rows.size() == 2);
    PFL_EXPECT(http_multi_rows[0].label == "HTTP GET /one");
    PFL_EXPECT(http_multi_rows[1].label == "HTTP GET /two");
    PFL_EXPECT(http_multi_rows[0].byte_count == http_request_one.size());
    PFL_EXPECT(http_multi_rows[1].byte_count == http_request_two.size());
    PFL_EXPECT(http_multi_rows[0].packet_indices == std::vector<std::uint64_t> {0});
    PFL_EXPECT(http_multi_rows[1].packet_indices == expected_http_split_packet_indices);
    PFL_EXPECT(http_multi_rows[0].protocol_text.find("Path: /one") != std::string::npos);
    PFL_EXPECT(http_multi_rows[1].protocol_text.find("Path: /two") != std::string::npos);

    constexpr std::string_view http_partial_request_text =
        "GET /ok HTTP/1.1\r\n"
        "Host: ok.example\r\n"
        "\r\n"
        "GET /partial HTTP/1.1\r\n"
        "Host: partial.example\r\n";
    const auto http_partial_payload = make_text_bytes(http_partial_request_text);
    const auto http_partial_split = static_cast<std::ptrdiff_t>(39);
    const auto http_partial_payload_a = std::vector<std::uint8_t>(
        http_partial_payload.begin(),
        http_partial_payload.begin() + http_partial_split
    );
    const auto http_partial_payload_b = std::vector<std::uint8_t>(
        http_partial_payload.begin() + http_partial_split,
        http_partial_payload.end()
    );
    const auto http_partial_packet_a = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
        ipv4(10, 41, 4, 1), ipv4(10, 41, 4, 2), 53013, 80, http_partial_payload_a, 0x18);
    const auto http_partial_packet_b = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
        ipv4(10, 41, 4, 1), ipv4(10, 41, 4, 2), 53013, 80, http_partial_payload_b, 0x18);
    const auto http_partial_path = write_temp_pcap(
        "pfl_stream_query_http_partial_headers.pcap",
        make_classic_pcap({
            {100, http_partial_packet_a},
            {200, http_partial_packet_b},
        })
    );

    CaptureSession http_partial_session {};
    PFL_EXPECT(http_partial_session.open_capture(http_partial_path, fast_options));
    const auto http_partial_rows = http_partial_session.list_flow_stream_items(0);
    PFL_EXPECT(http_partial_rows.size() == 2);
    PFL_EXPECT(http_partial_rows[0].label == "HTTP GET /ok");
    PFL_EXPECT(http_partial_rows[1].label == "HTTP Payload (partial)");
    PFL_EXPECT(http_partial_rows[1].packet_indices == expected_http_split_packet_indices);
    PFL_EXPECT(http_partial_rows[1].protocol_text.find("complete HTTP header block") != std::string::npos);
    PFL_EXPECT(http_partial_rows[1].protocol_text.find("Message Type: Request") == std::string::npos);

    PFL_EXPECT(tls_multi_session.open_capture(tls_multi_path, fast_options));
    const auto tls_multi_summary_before = tls_multi_session.summary();

    const auto tls_multi_rows = tls_multi_session.list_flow_stream_items(0);
    PFL_EXPECT(tls_multi_rows.size() == 2);
    PFL_EXPECT(tls_multi_rows[0].label == "TLS ServerHello");
    PFL_EXPECT(tls_multi_rows[1].label == "TLS ChangeCipherSpec");
    PFL_EXPECT(tls_multi_rows[0].byte_count == server_hello_record.size());
    PFL_EXPECT(tls_multi_rows[1].byte_count == change_cipher_spec_record.size());
    PFL_EXPECT(tls_multi_rows[0].packet_count == 1);
    PFL_EXPECT(tls_multi_rows[1].packet_count == 1);
    PFL_EXPECT(tls_multi_rows[0].packet_indices == std::vector<std::uint64_t> {0});
    PFL_EXPECT(tls_multi_rows[1].packet_indices == std::vector<std::uint64_t> {0});
    PFL_EXPECT(tls_multi_rows[0].protocol_text.find("Handshake Type: ServerHello") != std::string::npos);
    PFL_EXPECT(tls_multi_rows[1].protocol_text.find("Record Type: ChangeCipherSpec") != std::string::npos);
    PFL_EXPECT(!tls_multi_rows[0].payload_hex_text.empty());
    PFL_EXPECT(!tls_multi_rows[1].payload_hex_text.empty());
    PFL_EXPECT(tls_multi_session.summary().packet_count == tls_multi_summary_before.packet_count);
    PFL_EXPECT(tls_multi_session.summary().flow_count == tls_multi_summary_before.flow_count);
    PFL_EXPECT(tls_multi_session.summary().total_bytes == tls_multi_summary_before.total_bytes);

    const auto tls_ccs_packet = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
        ipv4(10, 43, 0, 1), ipv4(10, 43, 0, 2), 52001, 443, make_tls_change_cipher_spec_record(), 0x18);
    const auto tls_ccs_path = write_temp_pcap(
        "pfl_stream_query_tls_ccs.pcap",
        make_classic_pcap({{100, tls_ccs_packet}})
    );

    CaptureSession tls_ccs_session {};
    PFL_EXPECT(tls_ccs_session.open_capture(tls_ccs_path, fast_options));
    const auto tls_ccs_rows = tls_ccs_session.list_flow_stream_items(0);
    PFL_EXPECT(tls_ccs_rows.size() == 1);
    PFL_EXPECT(tls_ccs_rows[0].label == "TLS ChangeCipherSpec");
    PFL_EXPECT(tls_ccs_rows[0].protocol_text.find("ChangeCipherSpec") != std::string::npos);

    const auto tls_alert_packet = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
        ipv4(10, 43, 0, 3), ipv4(10, 43, 0, 4), 52003, 443, make_tls_alert_record(), 0x18);
    const auto tls_alert_path = write_temp_pcap(
        "pfl_stream_query_tls_alert.pcap",
        make_classic_pcap({{100, tls_alert_packet}})
    );

    CaptureSession tls_alert_session {};
    PFL_EXPECT(tls_alert_session.open_capture(tls_alert_path, fast_options));
    const auto tls_alert_rows = tls_alert_session.list_flow_stream_items(0);
    PFL_EXPECT(tls_alert_rows.size() == 1U);
    PFL_EXPECT(tls_alert_rows[0].label == "TLS Alert");
    PFL_EXPECT(tls_alert_rows[0].protocol_text.find("Record Type: Alert") != std::string::npos);
    PFL_EXPECT(tls_alert_rows[0].protocol_text.find("Alert Level: Warning") != std::string::npos);
    PFL_EXPECT(tls_alert_rows[0].protocol_text.find("Alert Description: Close Notify") != std::string::npos);

    std::vector<std::uint8_t> incomplete_tls_record {
        0x17U, 0x03U, 0x03U, 0x00U, 0x04U, 0xDEU, 0xADU,
    };
    const auto tls_partial_payload = concat_bytes(server_hello_record, incomplete_tls_record);
    const auto tls_partial_packet = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
        ipv4(10, 44, 0, 1), ipv4(10, 44, 0, 2), 52002, 443, tls_partial_payload, 0x18);
    const auto tls_partial_path = write_temp_pcap(
        "pfl_stream_query_tls_partial.pcap",
        make_classic_pcap({{100, tls_partial_packet}})
    );

    CaptureSession tls_partial_session {};
    PFL_EXPECT(tls_partial_session.open_capture(tls_partial_path, fast_options));
    const auto tls_partial_rows = tls_partial_session.list_flow_stream_items(0);
    PFL_EXPECT(tls_partial_rows.size() == 2);
    PFL_EXPECT(tls_partial_rows[0].label == "TLS ServerHello");
    PFL_EXPECT(tls_partial_rows[1].label == "TLS Record Fragment (partial)");
    PFL_EXPECT(tls_partial_rows[0].byte_count == server_hello_record.size());
    PFL_EXPECT(tls_partial_rows[1].byte_count == incomplete_tls_record.size());
    PFL_EXPECT(tls_partial_rows[1].protocol_text.find("complete TLS record") != std::string::npos);
    PFL_EXPECT(tls_partial_rows[1].protocol_text.find("ServerHello") == std::string::npos);

    const auto split_server_hello_record = make_tls_handshake_record(0x02U, {0x01, 0x02, 0x03, 0x04, 0x05, 0x06});
    const auto split_packet_payload_a = std::vector<std::uint8_t>(split_server_hello_record.begin(), split_server_hello_record.begin() + 7);
    const auto split_packet_payload_b = std::vector<std::uint8_t>(split_server_hello_record.begin() + 7, split_server_hello_record.end());
    const auto split_tls_packet_a = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
        ipv4(10, 45, 0, 1), ipv4(10, 45, 0, 2), 52003, 443, split_packet_payload_a, 0x18);
    const auto split_tls_packet_b = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
        ipv4(10, 45, 0, 1), ipv4(10, 45, 0, 2), 52003, 443, split_packet_payload_b, 0x18);
    const auto split_tls_path = write_temp_pcap(
        "pfl_stream_query_tls_split_record.pcap",
        make_classic_pcap({
            {100, split_tls_packet_a},
            {200, split_tls_packet_b},
        })
    );

    CaptureSession split_tls_session {};
    PFL_EXPECT(split_tls_session.open_capture(split_tls_path, fast_options));
    const auto split_tls_rows = split_tls_session.list_flow_stream_items(0);
    PFL_EXPECT(split_tls_rows.size() == 1);
    PFL_EXPECT(split_tls_rows[0].label == "TLS ServerHello");
    PFL_EXPECT(split_tls_rows[0].byte_count == split_server_hello_record.size());
    PFL_EXPECT(split_tls_rows[0].packet_count == 2);
    const auto expected_split_packet_indices = std::vector<std::uint64_t> {0, 1};
    PFL_EXPECT(split_tls_rows[0].packet_indices == expected_split_packet_indices);
    PFL_EXPECT(split_tls_rows[0].protocol_text.find("Handshake Type: ServerHello") != std::string::npos);
    PFL_EXPECT(!split_tls_rows[0].payload_hex_text.empty());

    const auto split_app_data_record = make_tls_record(0x17U, 0x0303U, {0xDEU, 0xADU, 0xBEU, 0xEFU, 0x11U, 0x22U});
    const auto split_app_payload_a = std::vector<std::uint8_t>(
        split_app_data_record.begin(),
        split_app_data_record.begin() + 6
    );
    const auto split_app_payload_b = std::vector<std::uint8_t>(
        split_app_data_record.begin() + 6,
        split_app_data_record.end()
    );
    const auto split_app_packet_a = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
        ipv4(10, 46, 0, 1), ipv4(10, 46, 0, 2), 52004, 443, split_app_payload_a, 0x18);
    const auto split_app_packet_b = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
        ipv4(10, 46, 0, 1), ipv4(10, 46, 0, 2), 52004, 443, split_app_payload_b, 0x18);
    const auto split_app_path = write_temp_pcap(
        "pfl_stream_query_tls_split_appdata.pcap",
        make_classic_pcap({
            {100, split_app_packet_a},
            {200, split_app_packet_b},
        })
    );

    CaptureSession split_app_session {};
    PFL_EXPECT(split_app_session.open_capture(split_app_path, fast_options));
    const auto split_app_rows = split_app_session.list_flow_stream_items(0);
    PFL_EXPECT(split_app_rows.size() == 1);
    PFL_EXPECT(split_app_rows[0].label == "TLS AppData");
    PFL_EXPECT(split_app_rows[0].byte_count == split_app_data_record.size());
    PFL_EXPECT(split_app_rows[0].packet_count == 2);
    PFL_EXPECT(split_app_rows[0].packet_indices == expected_split_packet_indices);
    PFL_EXPECT(split_app_rows[0].protocol_text.find("Record Type: ApplicationData") != std::string::npos);
    PFL_EXPECT(!split_app_rows[0].payload_hex_text.empty());

    const auto multi_record_server_hello = make_tls_handshake_record(0x02U, {0x10U, 0x11U, 0x12U, 0x13U});
    const auto multi_record_ccs = make_tls_change_cipher_spec_record();
    const auto multi_record_app_data = make_tls_record(0x17U, 0x0303U, {0x21U, 0x22U, 0x23U, 0x24U, 0x25U});
    const auto multi_record_payload = concat_bytes(
        concat_bytes(multi_record_server_hello, multi_record_ccs),
        multi_record_app_data
    );
    const auto multi_record_split = static_cast<std::ptrdiff_t>(multi_record_server_hello.size() + 2U);
    const auto multi_record_payload_a = std::vector<std::uint8_t>(
        multi_record_payload.begin(),
        multi_record_payload.begin() + multi_record_split
    );
    const auto multi_record_payload_b = std::vector<std::uint8_t>(
        multi_record_payload.begin() + multi_record_split,
        multi_record_payload.end()
    );
    const auto multi_record_packet_a = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
        ipv4(10, 47, 0, 1), ipv4(10, 47, 0, 2), 52005, 443, multi_record_payload_a, 0x18);
    const auto multi_record_packet_b = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
        ipv4(10, 47, 0, 1), ipv4(10, 47, 0, 2), 52005, 443, multi_record_payload_b, 0x18);
    const auto multi_record_path = write_temp_pcap(
        "pfl_stream_query_tls_reassembled_sequence.pcap",
        make_classic_pcap({
            {100, multi_record_packet_a},
            {200, multi_record_packet_b},
        })
    );

    CaptureSession multi_record_session {};
    PFL_EXPECT(multi_record_session.open_capture(multi_record_path, fast_options));
    const auto multi_record_rows = multi_record_session.list_flow_stream_items(0);
    PFL_EXPECT(multi_record_rows.size() == 3);
    PFL_EXPECT(multi_record_rows[0].label == "TLS ServerHello");
    PFL_EXPECT(multi_record_rows[1].label == "TLS ChangeCipherSpec");
    PFL_EXPECT(multi_record_rows[2].label == "TLS AppData");
    PFL_EXPECT(multi_record_rows[0].byte_count == multi_record_server_hello.size());
    PFL_EXPECT(multi_record_rows[1].byte_count == multi_record_ccs.size());
    PFL_EXPECT(multi_record_rows[2].byte_count == multi_record_app_data.size());
    PFL_EXPECT(multi_record_rows[0].packet_indices == std::vector<std::uint64_t> {0});
    PFL_EXPECT(multi_record_rows[1].packet_indices == expected_split_packet_indices);
    PFL_EXPECT(multi_record_rows[2].packet_indices == std::vector<std::uint64_t> {1});
    PFL_EXPECT(multi_record_rows[0].protocol_text.find("Handshake Type: ServerHello") != std::string::npos);
    PFL_EXPECT(multi_record_rows[1].protocol_text.find("Record Type: ChangeCipherSpec") != std::string::npos);
    PFL_EXPECT(multi_record_rows[2].protocol_text.find("Record Type: ApplicationData") != std::string::npos);

    const auto incomplete_reassembled_app_data = std::vector<std::uint8_t> {
        0x17U, 0x03U, 0x03U, 0x00U, 0x04U, 0xAAU, 0xBBU,
    };
    const auto reassembled_partial_payload = concat_bytes(server_hello_record, incomplete_reassembled_app_data);
    const auto reassembled_partial_split = static_cast<std::ptrdiff_t>(server_hello_record.size() + 2U);
    const auto reassembled_partial_payload_a = std::vector<std::uint8_t>(
        reassembled_partial_payload.begin(),
        reassembled_partial_payload.begin() + reassembled_partial_split
    );
    const auto reassembled_partial_payload_b = std::vector<std::uint8_t>(
        reassembled_partial_payload.begin() + reassembled_partial_split,
        reassembled_partial_payload.end()
    );
    const auto reassembled_partial_packet_a = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
        ipv4(10, 48, 0, 1), ipv4(10, 48, 0, 2), 52006, 443, reassembled_partial_payload_a, 0x18);
    const auto reassembled_partial_packet_b = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
        ipv4(10, 48, 0, 1), ipv4(10, 48, 0, 2), 52006, 443, reassembled_partial_payload_b, 0x18);
    const auto reassembled_partial_path = write_temp_pcap(
        "pfl_stream_query_tls_reassembled_partial.pcap",
        make_classic_pcap({
            {100, reassembled_partial_packet_a},
            {200, reassembled_partial_packet_b},
        })
    );

    CaptureSession reassembled_partial_session {};
    PFL_EXPECT(reassembled_partial_session.open_capture(reassembled_partial_path, fast_options));
    const auto reassembled_partial_rows = reassembled_partial_session.list_flow_stream_items(0);
    PFL_EXPECT(reassembled_partial_rows.size() == 2);
    PFL_EXPECT(reassembled_partial_rows[0].label == "TLS ServerHello");
    PFL_EXPECT(reassembled_partial_rows[1].label == "TLS Record Fragment (partial)");
    PFL_EXPECT(reassembled_partial_rows[1].packet_indices == expected_split_packet_indices);
    PFL_EXPECT(reassembled_partial_rows[1].protocol_text.find("do not contain a complete TLS record") != std::string::npos);
    PFL_EXPECT(reassembled_partial_rows[1].protocol_text.find("ApplicationData") == std::string::npos);

    std::vector<std::pair<std::uint32_t, std::vector<std::uint8_t>>> bounded_stream_packets {};
    bounded_stream_packets.reserve(31);
    for (std::uint32_t index = 0; index < 31U; ++index) {
        bounded_stream_packets.push_back({
            1000U + index,
            make_ethernet_ipv4_tcp_packet_with_payload(ipv4(10, 60, 0, 1), ipv4(10, 60, 0, 2), 54000, 443, 6, 0x18)
        });
    }
    const auto split_http_request_prefix_rows = split_http_request_session.list_flow_stream_items_for_packet_prefix(0, 30U, 16U);
    PFL_EXPECT(split_http_request_prefix_rows.size() == 1U);
    PFL_EXPECT(split_http_request_prefix_rows[0].label == "HTTP GET /split");

    constexpr std::string_view bounded_prefix_http_text =
        "GET /bounded HTTP/1.1\r\n"
        "Host: bounded.example\r\n"
        "User-Agent: split-test\r\n"
        "Accept: */*\r\n"
        "Connection: keep-alive\r\n"
        "X-Debug: 1234567890\r\n"
        "\r\n";
    const auto bounded_prefix_http_bytes = make_text_bytes(bounded_prefix_http_text);
    std::vector<std::pair<std::uint32_t, std::vector<std::uint8_t>>> bounded_prefix_http_packets {};
    bounded_prefix_http_packets.reserve(40U);
    const auto chunk_size = (bounded_prefix_http_bytes.size() + 39U) / 40U;
    for (std::size_t packetIndex = 0; packetIndex < 40U; ++packetIndex) {
        const auto begin = std::min(packetIndex * chunk_size, bounded_prefix_http_bytes.size());
        const auto end = std::min(begin + chunk_size, bounded_prefix_http_bytes.size());
        const auto fragment = std::vector<std::uint8_t>(bounded_prefix_http_bytes.begin() + static_cast<std::ptrdiff_t>(begin), bounded_prefix_http_bytes.begin() + static_cast<std::ptrdiff_t>(end));
        bounded_prefix_http_packets.push_back({
            static_cast<std::uint32_t>(2000U + packetIndex),
            make_ethernet_ipv4_tcp_packet_with_bytes_payload(ipv4(10, 61, 0, 1), ipv4(10, 61, 0, 2), 54010, 80, fragment, 0x18)
        });
    }
    const auto bounded_prefix_http_path = write_temp_pcap(
        "pfl_stream_query_bounded_prefix_http.pcap",
        make_classic_pcap(bounded_prefix_http_packets)
    );

    CaptureSession bounded_prefix_http_session {};
    PFL_EXPECT(bounded_prefix_http_session.open_capture(bounded_prefix_http_path, fast_options));
    const auto bounded_prefix_rows = bounded_prefix_http_session.list_flow_stream_items_for_packet_prefix(0, 30U, 16U);
    PFL_EXPECT(!bounded_prefix_rows.empty());
    PFL_EXPECT(bounded_prefix_rows.size() <= 16U);
    for (const auto& row : bounded_prefix_rows) {
        for (const auto packet_index : row.packet_indices) {
            PFL_EXPECT(packet_index < 30U);
        }
    }
    bounded_prefix_http_session.prepare_selected_flow_packet_cache(0, 30U);
    auto bounded_prefix_cache = bounded_prefix_http_session.selected_flow_packet_cache_info();
    PFL_EXPECT(bounded_prefix_cache.has_value());
    PFL_EXPECT(bounded_prefix_cache->flow_index == 0U);
    PFL_EXPECT(bounded_prefix_cache->cached_packet_window_count == 30U);
    PFL_EXPECT(!bounded_prefix_cache->limit_reached);
    PFL_EXPECT(bounded_prefix_cache->window_fully_cached);

    bounded_prefix_http_session.prepare_selected_flow_packet_cache(0, 40U);
    bounded_prefix_cache = bounded_prefix_http_session.selected_flow_packet_cache_info();
    PFL_EXPECT(bounded_prefix_cache.has_value());
    PFL_EXPECT(bounded_prefix_cache->cached_packet_window_count == 40U);
    PFL_EXPECT(!bounded_prefix_cache->limit_reached);
    PFL_EXPECT(bounded_prefix_cache->window_fully_cached);

    const auto extended_prefix_rows = bounded_prefix_http_session.list_flow_stream_items_for_packet_prefix(0, 40U, 16U);
    PFL_EXPECT(!extended_prefix_rows.empty());
    PFL_EXPECT(extended_prefix_rows.size() <= 16U);
    for (const auto& row : extended_prefix_rows) {
        for (const auto packet_index : row.packet_indices) {
            PFL_EXPECT(packet_index < 40U);
        }
    }

    std::vector<std::pair<std::uint32_t, std::vector<std::uint8_t>>> mixed_prefix_http_packets {};
    mixed_prefix_http_packets.reserve(80U);
    const auto mixed_chunk_size = (bounded_prefix_http_bytes.size() + 39U) / 40U;
    for (std::size_t packetIndex = 0; packetIndex < 40U; ++packetIndex) {
        const auto begin = std::min(packetIndex * mixed_chunk_size, bounded_prefix_http_bytes.size());
        const auto end = std::min(begin + mixed_chunk_size, bounded_prefix_http_bytes.size());
        const auto fragment = std::vector<std::uint8_t>(
            bounded_prefix_http_bytes.begin() + static_cast<std::ptrdiff_t>(begin),
            bounded_prefix_http_bytes.begin() + static_cast<std::ptrdiff_t>(end)
        );
        mixed_prefix_http_packets.push_back({
            static_cast<std::uint32_t>(3000U + (packetIndex * 2U)),
            make_ethernet_ipv4_tcp_packet_with_bytes_payload(ipv4(10, 62, 0, 1), ipv4(10, 62, 0, 2), 54020, 80, fragment, 0x18)
        });
        mixed_prefix_http_packets.push_back({
            static_cast<std::uint32_t>(3001U + (packetIndex * 2U)),
            make_ethernet_ipv4_tcp_packet(ipv4(10, 62, 0, 2), ipv4(10, 62, 0, 1), 80, 54020)
        });
    }
    const auto mixed_prefix_http_path = write_temp_pcap(
        "pfl_stream_query_bounded_prefix_http_mixed.pcap",
        make_classic_pcap(mixed_prefix_http_packets)
    );

    CaptureSession mixed_prefix_http_session {};
    PFL_EXPECT(mixed_prefix_http_session.open_capture(mixed_prefix_http_path, fast_options));
    const auto mixed_prefix_rows = mixed_prefix_http_session.list_flow_stream_items_for_packet_prefix(0, 30U, 16U);
    PFL_EXPECT(!mixed_prefix_rows.empty());
    for (const auto& row : mixed_prefix_rows) {
        for (const auto packet_index : row.packet_indices) {
            PFL_EXPECT(packet_index < 30U);
        }
    }

    const auto bounded_stream_path = write_temp_pcap(
        "pfl_stream_query_bounded_rows.pcap",
        make_classic_pcap(bounded_stream_packets)
    );

    CaptureSession bounded_stream_session {};
    PFL_EXPECT(bounded_stream_session.open_capture(bounded_stream_path, fast_options));
    PFL_EXPECT(bounded_stream_session.flow_stream_item_count(0) == 31U);

    const auto initial_stream_rows = bounded_stream_session.list_flow_stream_items(0, 0U, 15U);
    PFL_EXPECT(initial_stream_rows.size() == 15U);
    PFL_EXPECT(initial_stream_rows.front().stream_item_index == 1U);
    PFL_EXPECT(initial_stream_rows.back().stream_item_index == 15U);
    PFL_EXPECT(initial_stream_rows.front().label == "TCP Payload");

    const auto next_stream_rows = bounded_stream_session.list_flow_stream_items(0, 15U, 15U);
    PFL_EXPECT(next_stream_rows.size() == 15U);
    PFL_EXPECT(next_stream_rows.front().stream_item_index == 16U);
    PFL_EXPECT(next_stream_rows.back().stream_item_index == 30U);

    const auto tail_stream_rows = bounded_stream_session.list_flow_stream_items(0, 30U, 15U);
    PFL_EXPECT(tail_stream_rows.size() == 1U);
    PFL_EXPECT(tail_stream_rows.front().stream_item_index == 31U);

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/tls/tls_normal_1.pcap"), fast_options));

        const auto rows = session.list_flow_stream_items(0);
        PFL_EXPECT(!rows.empty());

        const auto* client_hello = find_stream_row_by_label(rows, "TLS ClientHello");
        const auto* server_hello = find_stream_row_by_label(rows, "TLS ServerHello");
        const auto* change_cipher_spec = find_stream_row_by_label(rows, "TLS ChangeCipherSpec");
        PFL_EXPECT(client_hello != nullptr);
        PFL_EXPECT(server_hello != nullptr);
        PFL_EXPECT(change_cipher_spec != nullptr);
        PFL_EXPECT(!client_hello->protocol_text.empty());
        PFL_EXPECT(!client_hello->payload_hex_text.empty());
        PFL_EXPECT(client_hello->protocol_text.find("Handshake Version:") != std::string::npos);
        PFL_EXPECT(client_hello->protocol_text.find("Cipher Suites:") != std::string::npos);
        PFL_EXPECT(client_hello->protocol_text.find("Extensions:") != std::string::npos);
        PFL_EXPECT(client_hello->protocol_text.find("SNI:") != std::string::npos);
        PFL_EXPECT(!server_hello->protocol_text.empty());
        PFL_EXPECT(!server_hello->payload_hex_text.empty());
        PFL_EXPECT(server_hello->protocol_text.find("Selected TLS Version:") != std::string::npos);
        PFL_EXPECT(server_hello->protocol_text.find("Selected Cipher Suite:") != std::string::npos);
        PFL_EXPECT(server_hello->protocol_text.find("Extensions:") != std::string::npos);
        PFL_EXPECT(!change_cipher_spec->protocol_text.empty());
        PFL_EXPECT(!change_cipher_spec->payload_hex_text.empty());

        const auto data_like_it = std::find_if(rows.begin(), rows.end(), [](const StreamItemRow& row) {
            return row.label == "TLS AppData" || row.label == "TLS Payload";
        });
        PFL_EXPECT(data_like_it != rows.end());
        PFL_EXPECT(!data_like_it->protocol_text.empty());
        PFL_EXPECT(!data_like_it->payload_hex_text.empty());
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/udp/udp_generic_payload_2.pcap"), fast_options));

        const auto rows = session.list_flow_stream_items(0);
        PFL_EXPECT(!rows.empty());
        for (const auto& row : rows) {
            PFL_EXPECT(row.label == "UDP Payload");
            PFL_EXPECT(!starts_with(row.label, "DNS"));
            PFL_EXPECT(!starts_with(row.label, "QUIC"));
            PFL_EXPECT(row.protocol_text.empty());
            PFL_EXPECT(row.payload_hex_text.empty());
        }
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/quic/quic_initial_ch_1.pcap"), fast_options));

        const auto rows = session.list_flow_stream_items(0);
        const auto* quic_row = find_stream_row_by_label(rows, "QUIC Initial: CRYPTO");
        PFL_EXPECT(quic_row != nullptr);
        PFL_EXPECT(quic_row->protocol_text.find("TLS Handshake Type: ClientHello") != std::string::npos);
        PFL_EXPECT(quic_row->protocol_text.find("Cipher Suites:") != std::string::npos);
        PFL_EXPECT(quic_row->protocol_text.find("SNI:") != std::string::npos);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/quic/quic_test_1.pcap"), fast_options));

        const auto rows = session.list_flow_stream_items(0);
        PFL_EXPECT(!rows.empty());
        PFL_EXPECT(std::any_of(rows.begin(), rows.end(), [](const StreamItemRow& row) {
            return starts_with(row.label, "QUIC ") || row.label == "Handshake" || row.label == "Protected payload" || row.label == "0-RTT";
        }));
        PFL_EXPECT(std::any_of(rows.begin(), rows.end(), [](const StreamItemRow& row) {
            return row.label == "QUIC Initial: CRYPTO";
        }));
        PFL_EXPECT(std::any_of(rows.begin(), rows.end(), [](const StreamItemRow& row) {
            return row.label != "UDP Payload" && !row.protocol_text.empty() && !row.payload_hex_text.empty();
        }));
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/quic/quic_handshake_3.pcap"), fast_options));

        const auto rows = session.list_flow_stream_items(0);
        PFL_EXPECT(rows.size() == 1U);
        PFL_EXPECT(rows[0].label == "Handshake");
        PFL_EXPECT(rows[0].protocol_text.find("Packet Type: Handshake") != std::string::npos);
        PFL_EXPECT(rows[0].protocol_text.find("Header Form: Long") != std::string::npos);
        PFL_EXPECT(!rows[0].payload_hex_text.empty());
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/quic/quic_protected_payload_4.pcap"), fast_options));

        const auto rows = session.list_flow_stream_items(0);
        PFL_EXPECT(rows.size() == 1U);
        PFL_EXPECT(rows[0].label == "Protected payload");
        PFL_EXPECT(rows[0].protocol_text.find("Packet Type: Protected Payload") != std::string::npos);
        PFL_EXPECT(rows[0].protocol_text.find("Header Form: Short") != std::string::npos);
    }

    {
        const auto crypto_packet = make_ethernet_ipv4_udp_packet_with_bytes_payload(
            ipv4(10, 41, 1, 1), ipv4(10, 41, 1, 2), 54000, 443, make_plaintext_quic_initial_payload(make_quic_crypto_frame_bytes()));
        const auto ack_packet = make_ethernet_ipv4_udp_packet_with_bytes_payload(
            ipv4(10, 41, 1, 1), ipv4(10, 41, 1, 2), 54000, 443, make_plaintext_quic_initial_payload(make_quic_ack_frame_bytes()));
        const auto path = write_temp_pcap(
            "pfl_stream_query_quic_plaintext_frames.pcap",
            make_classic_pcap({
                {100, crypto_packet},
                {200, ack_packet},
            })
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(path, fast_options));
        const auto rows = session.list_flow_stream_items(0);
        PFL_EXPECT(rows.size() == 2U);
        PFL_EXPECT(rows[0].label == "QUIC Initial: CRYPTO");
        PFL_EXPECT(rows[0].byte_count == make_quic_crypto_frame_bytes().size());
        PFL_EXPECT(rows[0].protocol_text.find("Frame Presence: CRYPTO") != std::string::npos);
        PFL_EXPECT(rows[1].label == "QUIC Initial: ACK");
        PFL_EXPECT(rows[1].byte_count == make_quic_ack_frame_bytes().size());
        PFL_EXPECT(rows[1].protocol_text.find("Frame Presence: ACK") != std::string::npos);
    }

    {
        const auto crypto_with_padding_packet = make_ethernet_ipv4_udp_packet_with_bytes_payload(
            ipv4(10, 41, 1, 1),
            ipv4(10, 41, 1, 2),
            54000,
            443,
            make_plaintext_quic_initial_payload(concat_bytes(make_quic_crypto_frame_bytes(), make_quic_padding_frame_bytes(3U)))
        );
        const auto ack_with_padding_packet = make_ethernet_ipv4_udp_packet_with_bytes_payload(
            ipv4(10, 41, 1, 1),
            ipv4(10, 41, 1, 2),
            54000,
            443,
            make_plaintext_quic_initial_payload(concat_bytes(make_quic_ack_frame_bytes(), make_quic_padding_frame_bytes(2U)))
        );
        const auto padding_only_packet = make_ethernet_ipv4_udp_packet_with_bytes_payload(
            ipv4(10, 41, 1, 1),
            ipv4(10, 41, 1, 2),
            54000,
            443,
            make_plaintext_quic_initial_payload(make_quic_padding_frame_bytes(4U))
        );
        const auto ping_only_packet = make_ethernet_ipv4_udp_packet_with_bytes_payload(
            ipv4(10, 41, 1, 1),
            ipv4(10, 41, 1, 2),
            54000,
            443,
            make_plaintext_quic_initial_payload(make_quic_ping_frame_bytes())
        );
        const auto path = write_temp_pcap(
            "pfl_stream_query_quic_padding_ping_suppression.pcap",
            make_classic_pcap({
                {100, crypto_with_padding_packet},
                {200, ack_with_padding_packet},
                {300, padding_only_packet},
                {400, ping_only_packet},
            })
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(path, fast_options));
        const auto rows = session.list_flow_stream_items(0);
        PFL_EXPECT(rows.size() == 2U);
        PFL_EXPECT(rows[0].label == "QUIC Initial: CRYPTO");
        PFL_EXPECT(rows[0].protocol_text.find("Frame Presence: CRYPTO, PADDING") != std::string::npos);
        PFL_EXPECT(rows[1].label == "QUIC Initial: ACK");
        PFL_EXPECT(rows[1].protocol_text.find("Frame Presence: ACK, PADDING") != std::string::npos);
        PFL_EXPECT(std::none_of(rows.begin(), rows.end(), [](const StreamItemRow& row) {
            return row.label.find("PADDING") != std::string::npos || row.label.find("PING") != std::string::npos;
        }));
    }

    {
        const auto server_hello_packet = make_ethernet_ipv4_udp_packet_with_bytes_payload(
            ipv4(10, 41, 1, 3), ipv4(10, 41, 1, 4), 54000, 443,
            make_plaintext_quic_initial_payload(make_quic_crypto_frame_bytes(make_tls_server_hello_handshake_bytes())));
        const auto path = write_temp_pcap(
            "pfl_stream_query_quic_server_hello_plaintext.pcap",
            make_classic_pcap({{100, server_hello_packet}})
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(path, fast_options));
        const auto rows = session.list_flow_stream_items(0);
        PFL_EXPECT(rows.size() == 1U);
        PFL_EXPECT(rows[0].label == "QUIC Initial: CRYPTO");
        PFL_EXPECT(rows[0].protocol_text.find("TLS Handshake Type: ServerHello") != std::string::npos);
        PFL_EXPECT(rows[0].protocol_text.find("Selected TLS Version:") != std::string::npos);
        PFL_EXPECT(rows[0].protocol_text.find("Selected Cipher Suite:") != std::string::npos);
    }

    {
        const auto packet = make_ethernet_ipv4_udp_packet_with_bytes_payload(
            ipv4(10, 41, 2, 1), ipv4(10, 41, 2, 2), 54000, 443, make_quic_truncated_payload());
        const auto path = write_temp_pcap(
            "pfl_stream_query_quic_truncated.pcap",
            make_classic_pcap({{100, packet}})
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(path, fast_options));
        const auto rows = session.list_flow_stream_items(0);
        PFL_EXPECT(rows.size() == 1U);
        PFL_EXPECT(rows[0].label == "UDP Payload");
        PFL_EXPECT(rows[0].protocol_text.empty());
        PFL_EXPECT(rows[0].payload_hex_text.empty());
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/http/http_multi_message_3.pcap"), fast_options));

        const auto rows = session.list_flow_stream_items(0);
        PFL_EXPECT(!rows.empty());

        std::size_t request_count = 0U;
        std::size_t response_count = 0U;
        bool saw_multi_packet_http_response = false;
        for (const auto& row : rows) {
            if (starts_with(row.label, "HTTP GET")) {
                ++request_count;
                PFL_EXPECT(!row.protocol_text.empty());
                PFL_EXPECT(!row.payload_hex_text.empty());
            }
            if (starts_with(row.label, "HTTP 200")) {
                ++response_count;
                PFL_EXPECT(!row.protocol_text.empty());
                PFL_EXPECT(!row.payload_hex_text.empty());
                if (row.packet_count > 1U) {
                    saw_multi_packet_http_response = true;
                }
            }
        }

        PFL_EXPECT(request_count >= 3U);
        PFL_EXPECT(response_count >= 3U);
        PFL_EXPECT(saw_multi_packet_http_response);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/http/http_partial_response_4.pcap"), fast_options));

        const auto flows = session.list_flows();
        PFL_EXPECT(flows.size() == 1U);
        PFL_EXPECT(flows[0].packet_count == 8U);

        const auto rows = session.list_flow_stream_items(0);
        PFL_EXPECT(rows.size() == 3U);

        PFL_EXPECT(rows[0].label == "HTTP GET /");
        PFL_EXPECT(rows[1].label == "HTTP 200 OK");
        PFL_EXPECT(rows[2].label == "HTTP Payload (partial)");
        PFL_EXPECT(rows[2].protocol_text.find("complete HTTP header block") != std::string::npos);
    }

    {
        const auto client_hello_packet = make_ethernet_ipv4_udp_packet_with_bytes_payload(
            ipv4(10, 41, 3, 1), ipv4(10, 41, 3, 2), 54020, 443,
            make_plaintext_quic_initial_payload(make_quic_crypto_frame_bytes(make_tls_client_hello_handshake_bytes())));
        const auto server_hello_packet = make_ethernet_ipv4_udp_packet_with_bytes_payload(
            ipv4(10, 41, 3, 2), ipv4(10, 41, 3, 1), 443, 54020,
            make_plaintext_quic_initial_payload(make_quic_crypto_frame_bytes(make_tls_server_hello_handshake_bytes())));
        const auto server_ack_packet = make_ethernet_ipv4_udp_packet_with_bytes_payload(
            ipv4(10, 41, 3, 2), ipv4(10, 41, 3, 1), 443, 54020,
            make_plaintext_quic_initial_payload(make_quic_ack_frame_bytes()));
        const auto path = write_temp_pcap(
            "pfl_stream_query_quic_direction_ownership_stage1.pcap",
            make_classic_pcap(std::vector<std::pair<std::uint32_t, std::vector<std::uint8_t>>> {
                {100U, client_hello_packet},
                {200U, server_hello_packet},
                {300U, server_ack_packet},
            })
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(path, fast_options));

        const auto rows = session.list_flow_stream_items(0);
        const auto client_row = std::find_if(rows.begin(), rows.end(), [](const StreamItemRow& row) {
            return row.packet_indices == std::vector<std::uint64_t> {0U};
        });
        const auto server_row = std::find_if(rows.begin(), rows.end(), [](const StreamItemRow& row) {
            return row.packet_indices == std::vector<std::uint64_t> {1U};
        });
        const auto ack_row = std::find_if(rows.begin(), rows.end(), [](const StreamItemRow& row) {
            return row.packet_indices == std::vector<std::uint64_t> {2U};
        });

        PFL_EXPECT(client_row != rows.end());
        PFL_EXPECT(server_row != rows.end());
        PFL_EXPECT(ack_row != rows.end());

        const auto client_context = session.derive_quic_protocol_details_for_packet_context(0, client_row->packet_indices);
        PFL_EXPECT(client_context.has_value());
        PFL_EXPECT(client_context->find("TLS Handshake Type: ClientHello") != std::string::npos);
        PFL_EXPECT(client_context->find("ServerHello") == std::string::npos);

        const auto server_context = session.derive_quic_protocol_details_for_packet_context(0, server_row->packet_indices);
        PFL_EXPECT(server_context.has_value());
        PFL_EXPECT(server_context->find("TLS Handshake Type: ServerHello") != std::string::npos);
        PFL_EXPECT(server_context->find("ClientHello") == std::string::npos);
        PFL_EXPECT(server_context->find("SNI:") == std::string::npos);

        const auto ack_context = session.derive_quic_protocol_details_for_packet_context(0, ack_row->packet_indices);
        PFL_EXPECT(!ack_context.has_value());
    }

    {
        const auto server_hello_bytes = make_tls_server_hello_handshake_bytes();
        const auto split_offset = server_hello_bytes.size() / 2U;
        const std::vector<std::uint8_t> server_hello_prefix(server_hello_bytes.begin(), server_hello_bytes.begin() + static_cast<std::ptrdiff_t>(split_offset));
        const std::vector<std::uint8_t> server_hello_suffix(server_hello_bytes.begin() + static_cast<std::ptrdiff_t>(split_offset), server_hello_bytes.end());

        const auto client_hello_packet = make_ethernet_ipv4_udp_packet_with_bytes_payload(
            ipv4(10, 41, 4, 1), ipv4(10, 41, 4, 2), 54040, 443,
            make_plaintext_quic_initial_payload(make_quic_crypto_frame_bytes(make_tls_client_hello_handshake_bytes())));
        const auto server_hello_prefix_packet = make_ethernet_ipv4_udp_packet_with_bytes_payload(
            ipv4(10, 41, 4, 2), ipv4(10, 41, 4, 1), 443, 54040,
            make_plaintext_quic_initial_payload(make_quic_crypto_frame_bytes(server_hello_prefix)));
        const auto server_hello_suffix_packet = make_ethernet_ipv4_udp_packet_with_bytes_payload(
            ipv4(10, 41, 4, 2), ipv4(10, 41, 4, 1), 443, 54040,
            make_plaintext_quic_initial_payload(concat_bytes(
                make_quic_crypto_frame_bytes(static_cast<std::uint64_t>(split_offset), server_hello_suffix),
                make_quic_ack_frame_bytes()
            )));
        const auto path = write_temp_pcap(
            "pfl_stream_query_quic_server_hello_bounded_tail_attachment.pcap",
            make_classic_pcap(std::vector<std::pair<std::uint32_t, std::vector<std::uint8_t>>> {
                {100U, client_hello_packet},
                {200U, server_hello_prefix_packet},
                {300U, server_hello_suffix_packet},
            })
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(path, fast_options));

        const auto rows = session.list_flow_stream_items(0);
        const auto server_tail_row = std::find_if(rows.begin(), rows.end(), [](const StreamItemRow& row) {
            return row.packet_indices == std::vector<std::uint64_t> {2U};
        });
        PFL_EXPECT(server_tail_row != rows.end());
        PFL_EXPECT(starts_with(server_tail_row->label, "QUIC "));

        const auto server_tail_context = session.derive_quic_protocol_details_for_packet_context(0, server_tail_row->packet_indices);
        PFL_EXPECT(server_tail_context.has_value());
        PFL_EXPECT(server_tail_context->find("TLS Handshake Type: ServerHello") != std::string::npos);
        PFL_EXPECT(server_tail_context->find("Selected TLS Version:") != std::string::npos);
        PFL_EXPECT(server_tail_context->find("Selected Cipher Suite:") != std::string::npos);
        PFL_EXPECT(server_tail_context->find("ClientHello") == std::string::npos);
        PFL_EXPECT(server_tail_context->find("SNI:") == std::string::npos);
    }

    {
        const auto server_hello_bytes = make_tls_server_hello_handshake_bytes();
        const auto split_offset = server_hello_bytes.size() / 2U;
        const std::vector<std::uint8_t> server_hello_suffix(server_hello_bytes.begin() + static_cast<std::ptrdiff_t>(split_offset), server_hello_bytes.end());

        const auto client_hello_packet = make_ethernet_ipv4_udp_packet_with_bytes_payload(
            ipv4(10, 41, 5, 1), ipv4(10, 41, 5, 2), 54050, 443,
            make_plaintext_quic_initial_payload(make_quic_crypto_frame_bytes(make_tls_client_hello_handshake_bytes())));
        const auto server_hello_suffix_packet = make_ethernet_ipv4_udp_packet_with_bytes_payload(
            ipv4(10, 41, 5, 2), ipv4(10, 41, 5, 1), 443, 54050,
            make_plaintext_quic_initial_payload(make_quic_crypto_frame_bytes(static_cast<std::uint64_t>(split_offset), server_hello_suffix)));
        const auto path = write_temp_pcap(
            "pfl_stream_query_quic_server_hello_insufficient_tail_only.pcap",
            make_classic_pcap(std::vector<std::pair<std::uint32_t, std::vector<std::uint8_t>>> {
                {100U, client_hello_packet},
                {200U, server_hello_suffix_packet},
            })
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(path, fast_options));

        const auto rows = session.list_flow_stream_items(0);
        const auto server_tail_row = std::find_if(rows.begin(), rows.end(), [](const StreamItemRow& row) {
            return row.packet_indices == std::vector<std::uint64_t> {1U};
        });
        PFL_EXPECT(server_tail_row != rows.end());

        const auto server_tail_context = session.derive_quic_protocol_details_for_packet_context(0, server_tail_row->packet_indices);
        PFL_EXPECT(!server_tail_context.has_value());
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/tls/tls_partial_tail_5.pcap"), fast_options));

        const auto rows = session.list_flow_stream_items(0);
        PFL_EXPECT(!rows.empty());
        PFL_EXPECT(find_stream_row_by_label(rows, "TLS ClientHello") != nullptr);
        PFL_EXPECT(find_stream_row_by_label(rows, "TLS ServerHello") != nullptr);
        PFL_EXPECT(find_stream_row_by_label(rows, "TLS ChangeCipherSpec") != nullptr);
        PFL_EXPECT(rows.back().label == "TLS Payload (partial)" || rows.back().label == "TLS Record Fragment (partial)");
        PFL_EXPECT(!rows.front().protocol_text.empty());
        if (rows.back().label == "TLS Record Fragment (partial)") {
            PFL_EXPECT(rows.back().protocol_text.find("complete TLS record") != std::string::npos);
        }
        PFL_EXPECT(rows.back().protocol_text.find("Cipher Suites:") == std::string::npos);
        PFL_EXPECT(rows.back().protocol_text.find("Subject:") == std::string::npos);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/tls/tls_server_handshake_retransmit_6.pcap"), fast_options));

        const auto rows = session.list_flow_stream_items(0);
        PFL_EXPECT(!rows.empty());
        PFL_EXPECT(find_stream_row_by_label(rows, "TLS ClientHello") != nullptr);
        PFL_EXPECT(find_stream_row_by_label(rows, "TLS ServerHello") != nullptr);
        PFL_EXPECT(find_stream_row_by_label(rows, "TLS Certificate") != nullptr);
        PFL_EXPECT(find_stream_row_by_label(rows, "TLS ServerKeyExchange") != nullptr);
        PFL_EXPECT(find_stream_row_by_label(rows, "TLS ServerHelloDone") != nullptr);
        PFL_EXPECT(count_stream_rows_by_label(rows, "TLS ServerHello") == 1U);
        PFL_EXPECT(count_stream_rows_by_label(rows, "TLS Certificate") == 1U);
        PFL_EXPECT(count_stream_rows_by_label(rows, "TLS ServerKeyExchange") == 1U);
        PFL_EXPECT(count_stream_rows_by_label(rows, "TLS ServerHelloDone") == 1U);
        const auto* certificate = find_stream_row_by_label(rows, "TLS Certificate");
        PFL_EXPECT(certificate != nullptr);
        PFL_EXPECT(certificate->protocol_text.find("Certificate Entries:") != std::string::npos);
        PFL_EXPECT(certificate->protocol_text.find("Leaf Certificate Size:") != std::string::npos);
        PFL_EXPECT(std::any_of(rows.begin(), rows.end(), [](const StreamItemRow& row) {
            return (row.label == "TLS Certificate" || row.label == "TLS ServerKeyExchange" || row.label == "TLS ServerHelloDone")
                && row.packet_count > 1U
                && !row.protocol_text.empty();
        }));
        PFL_EXPECT(std::any_of(rows.begin(), rows.end(), [](const StreamItemRow& row) {
            return starts_with(row.label, "TLS ") && row.label != "TCP Payload";
        }));
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/tcp/tcp_generic_payload_7.pcap"), fast_options));

        const auto rows = session.list_flow_stream_items(0);
        PFL_EXPECT(!rows.empty());
        for (const auto& row : rows) {
            PFL_EXPECT(row.label == "TCP Payload");
            PFL_EXPECT(!starts_with(row.label, "HTTP"));
            PFL_EXPECT(!starts_with(row.label, "TLS"));
            PFL_EXPECT(row.protocol_text.empty());
            PFL_EXPECT(row.payload_hex_text.empty());
        }
    }
}

}  // namespace pfl::tests
