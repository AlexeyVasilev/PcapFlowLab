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
        PFL_EXPECT(!server_hello->protocol_text.empty());
        PFL_EXPECT(!server_hello->payload_hex_text.empty());
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
        PFL_EXPECT(rows[0].packet_count == 1U);
        PFL_EXPECT(rows[0].packet_indices.size() == 1U);
        PFL_EXPECT(rows[0].packet_indices[0] == 3U);
        PFL_EXPECT(!rows[0].protocol_text.empty());

        PFL_EXPECT(rows[1].label == "HTTP 200 OK");
        PFL_EXPECT(rows[1].packet_count == 1U);
        PFL_EXPECT(rows[1].packet_indices.size() == 1U);
        PFL_EXPECT(rows[1].packet_indices[0] == 5U);
        PFL_EXPECT(!rows[1].protocol_text.empty());

        PFL_EXPECT(rows[2].label == "HTTP Payload (partial)");
        PFL_EXPECT(rows[2].packet_count == 2U);
        PFL_EXPECT(rows[2].packet_indices.size() == 2U);
        PFL_EXPECT(rows[2].packet_indices[0] == 5U);
        PFL_EXPECT(rows[2].packet_indices[1] == 7U);
        PFL_EXPECT(rows[2].protocol_text.find("complete HTTP header block") != std::string::npos);
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





