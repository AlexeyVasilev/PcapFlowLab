#include <cstddef>
#include <string>
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

std::string direction_for_packet(const std::vector<PacketRow>& packet_rows, const std::uint64_t packet_index) {
    for (const auto& row : packet_rows) {
        if (row.packet_index == packet_index) {
            return row.direction_text;
        }
    }

    PFL_EXPECT(false);
    return {};
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
    PFL_EXPECT(tls_partial_rows[1].label == "TLS Record Fragment");
    PFL_EXPECT(tls_partial_rows[0].byte_count == server_hello_record.size());
    PFL_EXPECT(tls_partial_rows[1].byte_count == incomplete_tls_record.size());
    PFL_EXPECT(tls_partial_rows[1].protocol_text.find("full TLS record body is not available") != std::string::npos);
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
    PFL_EXPECT(reassembled_partial_rows[1].label == "TLS Record Fragment");
    PFL_EXPECT(reassembled_partial_rows[1].packet_indices == expected_split_packet_indices);
    PFL_EXPECT(reassembled_partial_rows[1].protocol_text.find("do not contain a complete TLS record") != std::string::npos);
    PFL_EXPECT(reassembled_partial_rows[1].protocol_text.find("ApplicationData") == std::string::npos);
}

}  // namespace pfl::tests



