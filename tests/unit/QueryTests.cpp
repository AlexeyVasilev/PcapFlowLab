#include <string>
#include <variant>
#include <vector>

#include "TestSupport.h"
#include "app/session/CaptureSession.h"
#include "PcapTestUtils.h"

namespace pfl::tests {

namespace {

std::vector<std::uint8_t> make_http_request_payload() {
    constexpr char request[] =
        "GET / HTTP/1.1\r\n"
        "Host: hint.example\r\n"
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
    payload.push_back(6);
    payload.insert(payload.end(), {'w', 'i', 'd', 'g', 'e', 't'});
    payload.push_back(7);
    payload.insert(payload.end(), {'e', 'x', 'a', 'm', 'p', 'l', 'e'});
    payload.push_back(0);
    append_be16(payload, 1);
    append_be16(payload, 1);
    return payload;
}

}  // namespace

void run_query_tests() {
    const auto tcp_packet = make_ethernet_ipv4_tcp_packet(ipv4(10, 0, 0, 1), ipv4(10, 0, 0, 2), 12345, 443);
    const auto udp_packet = make_ethernet_ipv4_udp_packet(ipv4(10, 0, 0, 3), ipv4(10, 0, 0, 4), 5353, 53);
    const auto path = write_temp_pcap(
        "pfl_query_layer.pcap",
        make_classic_pcap({{100, tcp_packet}, {200, udp_packet}})
    );

    CaptureSession session {};
    PFL_EXPECT(session.open_capture(path));

    const auto rows = session.list_flows();
    PFL_EXPECT(rows.size() == 2);
    PFL_EXPECT(rows[0].index == 0);
    PFL_EXPECT(rows[1].index == 1);
    PFL_EXPECT(rows[0].family == FlowAddressFamily::ipv4);
    PFL_EXPECT(rows[1].family == FlowAddressFamily::ipv4);
    PFL_EXPECT(std::holds_alternative<ConnectionKeyV4>(rows[0].key));
    PFL_EXPECT(std::holds_alternative<ConnectionKeyV4>(rows[1].key));

    const auto& tcp_key = std::get<ConnectionKeyV4>(rows[0].key);
    PFL_EXPECT(tcp_key.protocol == ProtocolId::tcp);
    PFL_EXPECT(rows[0].protocol_text == "TCP");
    PFL_EXPECT(rows[0].protocol_hint.empty());
    PFL_EXPECT(rows[0].service_hint.empty());
    PFL_EXPECT(rows[0].address_a == "10.0.0.1");
    PFL_EXPECT(rows[0].port_a == 12345);
    PFL_EXPECT(rows[0].endpoint_a == "10.0.0.1:12345");
    PFL_EXPECT(rows[0].address_b == "10.0.0.2");
    PFL_EXPECT(rows[0].port_b == 443);
    PFL_EXPECT(rows[0].endpoint_b == "10.0.0.2:443");
    PFL_EXPECT(rows[0].packet_count == 1);
    PFL_EXPECT(rows[0].total_bytes == tcp_packet.size());
    PFL_EXPECT(tcp_key.first.addr == ipv4(10, 0, 0, 1));
    PFL_EXPECT(tcp_key.second.addr == ipv4(10, 0, 0, 2));

    const auto& udp_key = std::get<ConnectionKeyV4>(rows[1].key);
    PFL_EXPECT(udp_key.protocol == ProtocolId::udp);
    PFL_EXPECT(rows[1].protocol_text == "UDP");
    PFL_EXPECT(rows[1].protocol_hint.empty());
    PFL_EXPECT(rows[1].service_hint.empty());
    PFL_EXPECT(rows[1].address_a == "10.0.0.3");
    PFL_EXPECT(rows[1].port_a == 5353);
    PFL_EXPECT(rows[1].address_b == "10.0.0.4");
    PFL_EXPECT(rows[1].port_b == 53);
    PFL_EXPECT(rows[1].packet_count == 1);
    PFL_EXPECT(rows[1].total_bytes == udp_packet.size());

    const auto first_flow_packets = session.flow_packets(0);
    PFL_EXPECT(first_flow_packets.has_value());
    PFL_EXPECT(first_flow_packets->size() == 1);
    PFL_EXPECT(first_flow_packets->front().packet_index == 0);
    PFL_EXPECT(first_flow_packets->front().captured_length == tcp_packet.size());

    const auto second_flow_packets = session.flow_packets(1);
    PFL_EXPECT(second_flow_packets.has_value());
    PFL_EXPECT(second_flow_packets->size() == 1);
    PFL_EXPECT(second_flow_packets->front().packet_index == 1);
    PFL_EXPECT(second_flow_packets->front().captured_length == udp_packet.size());
    PFL_EXPECT(second_flow_packets->front().byte_offset == 40 + tcp_packet.size() + 16);

    const auto second_flow_rows = session.list_flow_packets(1);
    PFL_EXPECT(second_flow_rows.size() == 1);
    PFL_EXPECT(second_flow_rows.front().packet_index == 1);
    PFL_EXPECT(second_flow_rows.front().direction_text == "A\xE2\x86\x92" "B");
    PFL_EXPECT(second_flow_rows.front().captured_length == udp_packet.size());
    PFL_EXPECT(second_flow_rows.front().original_length == udp_packet.size());
    PFL_EXPECT(second_flow_rows.front().payload_length == 0);
    PFL_EXPECT(second_flow_rows.front().tcp_flags_text.empty());
    PFL_EXPECT(second_flow_rows.front().timestamp_text == "00:00:02.000200");

    PFL_EXPECT(!session.flow_packets(99).has_value());
    PFL_EXPECT(session.list_flow_packets(99).empty());

    const auto packet = session.find_packet(1);
    PFL_EXPECT(packet.has_value());
    PFL_EXPECT(packet->packet_index == 1);
    PFL_EXPECT(packet->captured_length == udp_packet.size());
    PFL_EXPECT(packet->byte_offset == 40 + tcp_packet.size() + 16);

    PFL_EXPECT(!session.find_packet(999).has_value());

    const auto packet_ab = make_ethernet_ipv4_tcp_packet(ipv4(10, 1, 0, 1), ipv4(10, 1, 0, 2), 40000, 80);
    const auto packet_ba = make_ethernet_ipv4_tcp_packet(ipv4(10, 1, 0, 2), ipv4(10, 1, 0, 1), 80, 40000);
    const auto direction_path = write_temp_pcap(
        "pfl_query_direction.pcap",
        make_classic_pcap({{100, packet_ab}, {200, packet_ba}})
    );

    CaptureSession direction_session {};
    PFL_EXPECT(direction_session.open_capture(direction_path));
    const auto direction_rows = direction_session.list_flows();
    PFL_EXPECT(direction_rows.size() == 1);
    const auto packet_rows = direction_session.list_flow_packets(0);
    PFL_EXPECT(packet_rows.size() == 2);
    PFL_EXPECT(packet_rows[0].packet_index == 0);
    PFL_EXPECT(packet_rows[1].packet_index == 1);

    const bool forward_is_a_to_b = direction_rows[0].address_a == "10.1.0.1" && direction_rows[0].port_a == 40000;
    PFL_EXPECT(packet_rows[0].direction_text == (forward_is_a_to_b ? "A\xE2\x86\x92" "B" : "B\xE2\x86\x92" "A"));
    PFL_EXPECT(packet_rows[1].direction_text == (forward_is_a_to_b ? "B\xE2\x86\x92" "A" : "A\xE2\x86\x92" "B"));

    const auto http_packet = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
        ipv4(192, 168, 1, 10), ipv4(93, 184, 216, 34), 51515, 80, make_http_request_payload(), 0x18);
    const auto dns_packet = make_ethernet_ipv4_udp_packet_with_bytes_payload(
        ipv4(10, 0, 0, 5), ipv4(8, 8, 8, 8), 53000, 53, make_dns_query_payload());
    const auto hint_path = write_temp_pcap(
        "pfl_query_hints.pcap",
        make_classic_pcap({{100, http_packet}, {200, dns_packet}})
    );

    CaptureSession hint_session {};
    PFL_EXPECT(hint_session.open_capture(hint_path));
    const auto hint_rows = hint_session.list_flows();
    PFL_EXPECT(hint_rows.size() == 2);

    const auto* http_row = static_cast<const FlowRow*>(nullptr);
    const auto* dns_row = static_cast<const FlowRow*>(nullptr);
    for (const auto& row : hint_rows) {
        if (row.protocol_hint == "http") {
            http_row = &row;
        }
        if (row.protocol_hint == "dns") {
            dns_row = &row;
        }
    }

    PFL_EXPECT(http_row != nullptr);
    PFL_EXPECT(dns_row != nullptr);
    PFL_EXPECT(http_row->service_hint == "hint.example");
    PFL_EXPECT(
        (http_row->address_a == "192.168.1.10" && http_row->port_a == 51515) ||
        (http_row->address_b == "192.168.1.10" && http_row->port_b == 51515)
    );
    PFL_EXPECT(dns_row->service_hint == "widget.example");
    PFL_EXPECT(
        (dns_row->address_a == "8.8.8.8" && dns_row->port_a == 53) ||
        (dns_row->address_b == "8.8.8.8" && dns_row->port_b == 53)
    );
}

}  // namespace pfl::tests


