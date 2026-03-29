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
    CaptureImportOptions deep_options {};
    deep_options.mode = ImportMode::deep;
    PFL_EXPECT(tls_multi_session.open_capture(tls_multi_path, deep_options));

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

    const auto tls_ccs_packet = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
        ipv4(10, 43, 0, 1), ipv4(10, 43, 0, 2), 52001, 443, make_tls_change_cipher_spec_record(), 0x18);
    const auto tls_ccs_path = write_temp_pcap(
        "pfl_stream_query_tls_ccs.pcap",
        make_classic_pcap({{100, tls_ccs_packet}})
    );

    CaptureSession tls_ccs_session {};
    PFL_EXPECT(tls_ccs_session.open_capture(tls_ccs_path, deep_options));
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
    PFL_EXPECT(tls_partial_session.open_capture(tls_partial_path, deep_options));
    const auto tls_partial_rows = tls_partial_session.list_flow_stream_items(0);
    PFL_EXPECT(tls_partial_rows.size() == 2);
    PFL_EXPECT(tls_partial_rows[0].label == "TLS ServerHello");
    PFL_EXPECT(tls_partial_rows[1].label == "TLS Record Fragment");
    PFL_EXPECT(tls_partial_rows[0].byte_count == server_hello_record.size());
    PFL_EXPECT(tls_partial_rows[1].byte_count == incomplete_tls_record.size());
    PFL_EXPECT(tls_partial_rows[1].protocol_text.find("full TLS record body is not available") != std::string::npos);
    PFL_EXPECT(tls_partial_rows[1].protocol_text.find("ServerHello") == std::string::npos);
}

}  // namespace pfl::tests

