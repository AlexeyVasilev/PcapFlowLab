#include <string>
#include <variant>
#include <vector>

#include "TestSupport.h"
#include "app/frontend/FrontendSessionAdapter.h"
#include "app/session/CaptureSession.h"
#include "app/session/ProtocolPathPresentation.h"
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

std::vector<std::uint8_t> bytes_payload(std::string_view text) {
    return std::vector<std::uint8_t>(text.begin(), text.end());
}

std::vector<std::uint8_t> make_ipv4_tcp_first_fragment_with_complete_header(
    const std::uint32_t src_addr,
    const std::uint32_t dst_addr,
    const std::uint16_t src_port,
    const std::uint16_t dst_port
) {
    const auto tcp_packet = make_ethernet_ipv4_tcp_packet(src_addr, dst_addr, src_port, dst_port);
    const auto tcp_payload = std::vector<std::uint8_t>(tcp_packet.begin() + 34, tcp_packet.end());
    return make_ethernet_ipv4_fragment_packet(src_addr, dst_addr, 6U, 0x2000U, tcp_payload);
}

std::optional<std::size_t> find_flow_index_by_service_hint(
    const std::vector<FlowRow>& rows,
    const std::string_view service_hint
) {
    for (const auto& row : rows) {
        if (row.service_hint == service_hint) {
            return row.index;
        }
    }

    return std::nullopt;
}

CaptureSession build_shared_flow_query_session() {
    CaptureSession session {};
    auto& state = session.state();

    const auto simple_tcp_path_id = state.protocol_path_registry.intern(ProtocolPath {
        {LayerKey::ethernet_ii(), LayerKey::ipv4(), LayerKey::tcp()}
    });
    const auto simple_udp_path_id = state.protocol_path_registry.intern(ProtocolPath {
        {LayerKey::ethernet_ii(), LayerKey::ipv4(), LayerKey::udp()}
    });
    const auto simple_ipv6_udp_path_id = state.protocol_path_registry.intern(ProtocolPath {
        {LayerKey::ethernet_ii(), LayerKey::ipv6(), LayerKey::udp()}
    });
    const auto vxlan_tcp_path_id = state.protocol_path_registry.intern(ProtocolPath {
        {LayerKey::ethernet_ii(), LayerKey::ipv4(), LayerKey::udp(), LayerKey::vxlan(100U), LayerKey::ethernet_ii(), LayerKey::ipv4(), LayerKey::tcp()}
    });

    const FlowKeyV4 tcp_heavy_flow {
        .src_addr = ipv4(10, 0, 0, 30),
        .dst_addr = ipv4(10, 0, 0, 40),
        .src_port = 43000,
        .dst_port = 22,
        .protocol = ProtocolId::tcp,
    };
    ConnectionV4 tcp_heavy_connection {};
    tcp_heavy_connection.key = make_connection_key(tcp_heavy_flow);
    tcp_heavy_connection.key.protocol_path_id = simple_tcp_path_id;
    tcp_heavy_connection.service_hint = "zz-flow.example";
    for (std::uint64_t packet_offset = 0; packet_offset < 10U; ++packet_offset) {
        tcp_heavy_connection.add_packet(
            tcp_heavy_flow,
            PacketRef {
                .packet_index = packet_offset,
                .ts_sec = 1U,
                .ts_usec = static_cast<std::uint32_t>(100U + packet_offset),
                .captured_length = 66U,
                .original_length = 66U,
            }
        );
    }
    state.ipv4_connections.get_or_create(tcp_heavy_connection.key) = tcp_heavy_connection;

    const FlowKeyV4 http_flow {
        .src_addr = ipv4(10, 0, 0, 10),
        .dst_addr = ipv4(10, 0, 0, 20),
        .src_port = 41000,
        .dst_port = 80,
        .protocol = ProtocolId::tcp,
    };
    ConnectionV4 http_connection {};
    http_connection.key = make_connection_key(http_flow);
    http_connection.key.protocol_path_id = vxlan_tcp_path_id;
    http_connection.protocol_hint = FlowProtocolHint::http;
    http_connection.service_hint = "alpha.example";
    http_connection.add_packet(
        http_flow,
        PacketRef {
            .packet_index = 10U,
            .ts_sec = 2U,
            .ts_usec = 100U,
            .captured_length = 100U,
            .original_length = 100U,
        }
    );
    http_connection.add_packet(
        http_flow,
        PacketRef {
            .packet_index = 11U,
            .ts_sec = 2U,
            .ts_usec = 200U,
            .captured_length = 100U,
            .original_length = 100U,
        }
    );
    state.ipv4_connections.get_or_create(http_connection.key) = http_connection;

    const FlowKeyV4 dns_flow {
        .src_addr = ipv4(10, 0, 0, 11),
        .dst_addr = ipv4(10, 0, 0, 21),
        .src_port = 53000,
        .dst_port = 53,
        .protocol = ProtocolId::udp,
    };
    ConnectionV4 dns_connection {};
    dns_connection.key = make_connection_key(dns_flow);
    dns_connection.key.protocol_path_id = simple_udp_path_id;
    dns_connection.protocol_hint = FlowProtocolHint::dns;
    dns_connection.service_hint = "beta.example";
    dns_connection.add_packet(
        dns_flow,
        PacketRef {
            .packet_index = 12U,
            .ts_sec = 3U,
            .ts_usec = 100U,
            .captured_length = 90U,
            .original_length = 90U,
        }
    );
    state.ipv4_connections.get_or_create(dns_connection.key) = dns_connection;

    const FlowKeyV6 ipv6_udp_flow {
        .src_addr = ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x31}),
        .dst_addr = ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x32}),
        .src_port = 54000,
        .dst_port = 54001,
        .protocol = ProtocolId::udp,
    };
    ConnectionV6 ipv6_udp_connection {};
    ipv6_udp_connection.key = make_connection_key(ipv6_udp_flow);
    ipv6_udp_connection.key.protocol_path_id = simple_ipv6_udp_path_id;
    ipv6_udp_connection.add_packet(
        ipv6_udp_flow,
        PacketRef {
            .packet_index = 13U,
            .ts_sec = 4U,
            .ts_usec = 100U,
            .captured_length = 70U,
            .original_length = 70U,
        }
    );
    state.ipv6_connections.get_or_create(ipv6_udp_connection.key) = ipv6_udp_connection;

    return session;
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
    PFL_REQUIRE(first_flow_packets.has_value());
    PFL_EXPECT(first_flow_packets->size() == 1);
    PFL_EXPECT(first_flow_packets->front().packet_index == 0);
    PFL_EXPECT(first_flow_packets->front().captured_length == tcp_packet.size());

    const auto second_flow_packets = session.flow_packets(1);
    PFL_REQUIRE(second_flow_packets.has_value());
    PFL_EXPECT(second_flow_packets->size() == 1);
    PFL_EXPECT(second_flow_packets->front().packet_index == 1);
    PFL_EXPECT(second_flow_packets->front().captured_length == udp_packet.size());
    PFL_EXPECT(second_flow_packets->front().byte_offset == 40 + tcp_packet.size() + 16);

    const auto second_flow_rows = session.list_flow_packets(1);
    PFL_EXPECT(second_flow_rows.size() == 1);
    PFL_EXPECT(second_flow_rows.front().row_number == 1);
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
    PFL_REQUIRE(packet.has_value());
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
    PFL_EXPECT(packet_rows[0].row_number == 1);
    PFL_EXPECT(packet_rows[1].row_number == 2);
    PFL_EXPECT(packet_rows[0].packet_index == 0);
    PFL_EXPECT(packet_rows[1].packet_index == 1);

    const bool forward_is_a_to_b = direction_rows[0].address_a == "10.1.0.1" && direction_rows[0].port_a == 40000;
    PFL_EXPECT(packet_rows[0].direction_text == (forward_is_a_to_b ? "A\xE2\x86\x92" "B" : "B\xE2\x86\x92" "A"));
    PFL_EXPECT(packet_rows[1].direction_text == (forward_is_a_to_b ? "B\xE2\x86\x92" "A" : "A\xE2\x86\x92" "B"));

    const auto reverse_first_packet = make_ethernet_ipv4_tcp_packet(
        ipv4(203, 0, 113, 20), ipv4(203, 0, 113, 10), 443, 50000);
    const auto reverse_second_packet = make_ethernet_ipv4_tcp_packet(
        ipv4(203, 0, 113, 10), ipv4(203, 0, 113, 20), 50000, 443);
    const auto reverse_first_path = write_temp_pcap(
        "pfl_query_first_observed_orientation.pcap",
        make_classic_pcap({{200, reverse_first_packet}, {100, reverse_second_packet}})
    );

    CaptureSession reverse_first_session {};
    PFL_EXPECT(reverse_first_session.open_capture(reverse_first_path));
    const auto reverse_first_rows = reverse_first_session.list_flows();
    PFL_REQUIRE(reverse_first_rows.size() == 1U);
    PFL_EXPECT(reverse_first_rows[0].address_a == "203.0.113.20");
    PFL_EXPECT(reverse_first_rows[0].port_a == 443U);
    PFL_EXPECT(reverse_first_rows[0].endpoint_a == "203.0.113.20:443");
    PFL_EXPECT(reverse_first_rows[0].address_b == "203.0.113.10");
    PFL_EXPECT(reverse_first_rows[0].port_b == 50000U);
    PFL_EXPECT(reverse_first_rows[0].endpoint_b == "203.0.113.10:50000");
    const auto& reverse_first_key = std::get<ConnectionKeyV4>(reverse_first_rows[0].key);
    PFL_EXPECT(reverse_first_key.first.addr == ipv4(203, 0, 113, 10));
    PFL_EXPECT(reverse_first_key.first.port == 50000U);
    PFL_EXPECT(reverse_first_key.second.addr == ipv4(203, 0, 113, 20));
    PFL_EXPECT(reverse_first_key.second.port == 443U);

    const auto reverse_first_packet_rows = reverse_first_session.list_flow_packets(0);
    PFL_REQUIRE(reverse_first_packet_rows.size() == 2U);
    PFL_EXPECT(reverse_first_packet_rows[0].packet_index == 0U);
    PFL_EXPECT(reverse_first_packet_rows[0].direction_text == "A\xE2\x86\x92" "B");
    PFL_EXPECT(reverse_first_packet_rows[1].packet_index == 1U);
    PFL_EXPECT(reverse_first_packet_rows[1].direction_text == "B\xE2\x86\x92" "A");

    FrontendSessionAdapter reverse_first_adapter {};
    PFL_REQUIRE(reverse_first_adapter.open_capture(reverse_first_path).opened);
    const auto reverse_first_frontend_flows = reverse_first_adapter.get_flows();
    PFL_REQUIRE(reverse_first_frontend_flows.size() == 1U);
    PFL_EXPECT(reverse_first_frontend_flows[0].endpoint_a == reverse_first_rows[0].endpoint_a);
    PFL_EXPECT(reverse_first_frontend_flows[0].endpoint_b == reverse_first_rows[0].endpoint_b);

    const auto same_address_packet = make_ethernet_ipv4_tcp_packet(
        ipv4(127, 0, 0, 1), ipv4(127, 0, 0, 1), 50000, 443);
    const auto same_address_path = write_temp_pcap(
        "pfl_query_same_address_orientation.pcap",
        make_classic_pcap({{100, same_address_packet}})
    );

    CaptureSession same_address_session {};
    PFL_EXPECT(same_address_session.open_capture(same_address_path));
    const auto same_address_rows = same_address_session.list_flows();
    PFL_REQUIRE(same_address_rows.size() == 1U);
    PFL_EXPECT(same_address_rows[0].endpoint_a == "127.0.0.1:50000");
    PFL_EXPECT(same_address_rows[0].endpoint_b == "127.0.0.1:443");
    const auto& same_address_key = std::get<ConnectionKeyV4>(same_address_rows[0].key);
    PFL_EXPECT(same_address_key.first.port == 443U);
    PFL_EXPECT(same_address_key.second.port == 50000U);

    const auto retransmit_duplicate_path = write_temp_pcap(
        "pfl_query_retransmit_duplicate.pcap",
        make_classic_pcap({
            {100, make_ethernet_ipv4_tcp_packet_with_bytes_payload_and_sequence(
                ipv4(10, 2, 0, 1), ipv4(10, 2, 0, 2), 41000, 80, bytes_payload("alpha"), 1000U, 2000U, 0x18)},
            {200, make_ethernet_ipv4_tcp_packet_with_bytes_payload_and_sequence(
                ipv4(10, 2, 0, 1), ipv4(10, 2, 0, 2), 41000, 80, bytes_payload("alpha"), 1000U, 2000U, 0x18)},
        })
    );

    CaptureSession retransmit_duplicate_session {};
    PFL_EXPECT(retransmit_duplicate_session.open_capture(retransmit_duplicate_path));
    const auto duplicate_marks = retransmit_duplicate_session.suspected_tcp_retransmission_packet_indices(0);
    PFL_EXPECT(duplicate_marks.size() == 1U);
    PFL_EXPECT(duplicate_marks[0] == 1U);

    const auto retransmit_payload_mismatch_path = write_temp_pcap(
        "pfl_query_retransmit_payload_mismatch.pcap",
        make_classic_pcap({
            {100, make_ethernet_ipv4_tcp_packet_with_bytes_payload_and_sequence(
                ipv4(10, 2, 1, 1), ipv4(10, 2, 1, 2), 41001, 80, bytes_payload("alpha"), 1000U, 2000U, 0x18)},
            {200, make_ethernet_ipv4_tcp_packet_with_bytes_payload_and_sequence(
                ipv4(10, 2, 1, 1), ipv4(10, 2, 1, 2), 41001, 80, bytes_payload("omega"), 1000U, 2000U, 0x18)},
        })
    );

    CaptureSession retransmit_payload_mismatch_session {};
    PFL_EXPECT(retransmit_payload_mismatch_session.open_capture(retransmit_payload_mismatch_path));
    PFL_EXPECT(retransmit_payload_mismatch_session.suspected_tcp_retransmission_packet_indices(0).empty());

    const auto retransmit_sequence_mismatch_path = write_temp_pcap(
        "pfl_query_retransmit_sequence_mismatch.pcap",
        make_classic_pcap({
            {100, make_ethernet_ipv4_tcp_packet_with_bytes_payload_and_sequence(
                ipv4(10, 2, 2, 1), ipv4(10, 2, 2, 2), 41002, 80, bytes_payload("alpha"), 1000U, 2000U, 0x18)},
            {200, make_ethernet_ipv4_tcp_packet_with_bytes_payload_and_sequence(
                ipv4(10, 2, 2, 1), ipv4(10, 2, 2, 2), 41002, 80, bytes_payload("alpha"), 1001U, 2000U, 0x18)},
            {300, make_ethernet_ipv4_tcp_packet_with_bytes_payload_and_sequence(
                ipv4(10, 2, 2, 2), ipv4(10, 2, 2, 1), 80, 41002, bytes_payload("alpha"), 1000U, 2000U, 0x18)},
        })
    );

    CaptureSession retransmit_sequence_mismatch_session {};
    PFL_EXPECT(retransmit_sequence_mismatch_session.open_capture(retransmit_sequence_mismatch_path));
    PFL_EXPECT(retransmit_sequence_mismatch_session.suspected_tcp_retransmission_packet_indices(0).empty());

    const auto pure_ack_path = write_temp_pcap(
        "pfl_query_retransmit_pure_ack.pcap",
        make_classic_pcap({
            {100, make_ethernet_ipv4_tcp_packet_with_bytes_payload_and_sequence(
                ipv4(10, 2, 3, 1), ipv4(10, 2, 3, 2), 41003, 80, {}, 1000U, 2000U, 0x10)},
            {200, make_ethernet_ipv4_tcp_packet_with_bytes_payload_and_sequence(
                ipv4(10, 2, 3, 1), ipv4(10, 2, 3, 2), 41003, 80, {}, 1000U, 2000U, 0x10)},
        })
    );

    CaptureSession pure_ack_session {};
    PFL_EXPECT(pure_ack_session.open_capture(pure_ack_path));
    PFL_EXPECT(pure_ack_session.suspected_tcp_retransmission_packet_indices(0).empty());
    PFL_EXPECT(!pure_ack_session.selected_flow_packet_cache_info().has_value());

    const auto udp_only_path = write_temp_pcap(
        "pfl_query_retransmit_udp_no_cache.pcap",
        make_classic_pcap({
            {100, make_ethernet_ipv4_udp_packet_with_bytes_payload(
                ipv4(10, 2, 4, 1), ipv4(10, 2, 4, 2), 53000, 53, make_dns_query_payload())},
        })
    );

    CaptureSession udp_only_session {};
    PFL_EXPECT(udp_only_session.open_capture(udp_only_path));
    PFL_EXPECT(udp_only_session.suspected_tcp_retransmission_packet_indices(0).empty());
    PFL_EXPECT(!udp_only_session.selected_flow_packet_cache_info().has_value());
    udp_only_session.set_selected_flow_tcp_payload_suppression(0U, {}, 1U);
    PFL_EXPECT(!udp_only_session.should_suppress_selected_flow_tcp_payload(0U, 0U));

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

    PFL_REQUIRE(http_row != nullptr);
    PFL_REQUIRE(dns_row != nullptr);
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

    std::vector<std::pair<std::uint32_t, std::vector<std::uint8_t>>> heavy_flow_packets {};
    heavy_flow_packets.reserve(65);
    for (std::uint32_t index = 0; index < 65U; ++index) {
        heavy_flow_packets.push_back({100U + index, make_ethernet_ipv4_tcp_packet(ipv4(203, 0, 113, 1), ipv4(203, 0, 113, 2), 50000, 443)});
    }

    const auto heavy_flow_path = write_temp_pcap(
        "pfl_query_bounded_flow_packets.pcap",
        make_classic_pcap(heavy_flow_packets)
    );

    CaptureSession heavy_flow_session {};
    PFL_EXPECT(heavy_flow_session.open_capture(heavy_flow_path));
    PFL_EXPECT(heavy_flow_session.flow_packet_count(0) == 65U);

    const auto initial_rows = heavy_flow_session.list_flow_packets(0, 0U, 30U);
    PFL_EXPECT(initial_rows.size() == 30U);
    PFL_EXPECT(initial_rows.front().row_number == 1U);
    PFL_EXPECT(initial_rows.front().packet_index == 0U);
    PFL_EXPECT(initial_rows.back().row_number == 30U);
    PFL_EXPECT(initial_rows.back().packet_index == 29U);
    const auto repeated_initial_rows = heavy_flow_session.list_flow_packets(0, 0U, 30U);
    PFL_EXPECT(repeated_initial_rows.size() == initial_rows.size());
    for (std::size_t index = 0; index < initial_rows.size(); ++index) {
        PFL_EXPECT(repeated_initial_rows[index].row_number == initial_rows[index].row_number);
        PFL_EXPECT(repeated_initial_rows[index].packet_index == initial_rows[index].packet_index);
        PFL_EXPECT(repeated_initial_rows[index].direction_text == initial_rows[index].direction_text);
        PFL_EXPECT(repeated_initial_rows[index].timestamp_text == initial_rows[index].timestamp_text);
    }

    const auto next_rows = heavy_flow_session.list_flow_packets(0, 30U, 30U);
    PFL_EXPECT(next_rows.size() == 30U);
    PFL_EXPECT(next_rows.front().row_number == 31U);
    PFL_EXPECT(next_rows.front().packet_index == 30U);
    PFL_EXPECT(next_rows.back().row_number == 60U);
    PFL_EXPECT(next_rows.back().packet_index == 59U);

    const auto tail_rows = heavy_flow_session.list_flow_packets(0, 60U, 30U);
    PFL_EXPECT(tail_rows.size() == 5U);
    PFL_EXPECT(tail_rows.front().row_number == 61U);
    PFL_EXPECT(tail_rows.front().packet_index == 60U);
    PFL_EXPECT(tail_rows.back().row_number == 65U);
    PFL_EXPECT(tail_rows.back().packet_index == 64U);

    CaptureSession reopen_cache_invalidation_session {};
    PFL_EXPECT(reopen_cache_invalidation_session.open_capture(path));
    const auto initial_reopen_rows = reopen_cache_invalidation_session.list_flows();
    PFL_EXPECT(initial_reopen_rows.size() == 2U);
    PFL_EXPECT(reopen_cache_invalidation_session.flow_packet_count(0U) == 1U);
    PFL_EXPECT(reopen_cache_invalidation_session.open_capture(heavy_flow_path));
    const auto reopened_rows = reopen_cache_invalidation_session.list_flows();
    PFL_EXPECT(reopened_rows.size() == 1U);
    PFL_EXPECT(reopen_cache_invalidation_session.flow_packet_count(0U) == 65U);
    const auto reopened_packet_rows = reopen_cache_invalidation_session.list_flow_packets(0U, 0U, 30U);
    PFL_EXPECT(reopened_packet_rows.size() == 30U);
    PFL_EXPECT(reopened_packet_rows.front().packet_index == 0U);

    const auto cache_packet_one = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
        ipv4(10, 9, 0, 1), ipv4(10, 9, 0, 2), 42000, 443, bytes_payload("one"), 0x18);
    const auto cache_packet_dns = make_ethernet_ipv4_udp_packet_with_bytes_payload(
        ipv4(10, 9, 1, 1), ipv4(10, 9, 1, 2), 53000, 53, bytes_payload("dns"));
    const auto cache_packet_two = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
        ipv4(10, 9, 0, 1), ipv4(10, 9, 0, 2), 42000, 443, bytes_payload("two"), 0x18);
    const auto cache_packet_three = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
        ipv4(10, 9, 0, 1), ipv4(10, 9, 0, 2), 42000, 443, bytes_payload("three"), 0x18);
    const auto cache_packet_four = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
        ipv4(10, 9, 0, 1), ipv4(10, 9, 0, 2), 42000, 443, bytes_payload("four"), 0x18);
    const auto cache_path = write_temp_pcap(
        "pfl_query_selected_flow_cache.pcap",
        make_classic_pcap({
            {100, cache_packet_one},
            {200, cache_packet_dns},
            {300, cache_packet_two},
            {400, cache_packet_three},
            {500, cache_packet_four},
        })
    );

    CaptureSession cache_session {};
    PFL_EXPECT(cache_session.open_capture(cache_path));
    PFL_EXPECT(!cache_session.selected_flow_packet_cache_info().has_value());

    cache_session.prepare_selected_flow_packet_cache(0, 2U);
    auto cache_info = cache_session.selected_flow_packet_cache_info();
    PFL_REQUIRE(cache_info.has_value());
    PFL_EXPECT(cache_info->flow_index == 0U);
    PFL_EXPECT(cache_info->cached_packet_window_count == 2U);
    PFL_EXPECT(cache_info->cached_packet_contribution_count == 2U);
    PFL_EXPECT(cache_info->total_cached_bytes == 6U);
    PFL_EXPECT(!cache_info->limit_reached);
    PFL_EXPECT(cache_info->window_fully_cached);
    const auto first_selected_flow_packet = cache_session.selected_flow_packet_at(0U, 1U);
    PFL_REQUIRE(first_selected_flow_packet.has_value());
    PFL_EXPECT(first_selected_flow_packet->packet_index == 0U);
    const auto second_selected_flow_packet = cache_session.selected_flow_packet_at(0U, 2U);
    PFL_REQUIRE(second_selected_flow_packet.has_value());
    PFL_EXPECT(second_selected_flow_packet->packet_index == 2U);
    const auto third_selected_flow_packet = cache_session.selected_flow_packet_at(0U, 3U);
    PFL_REQUIRE(third_selected_flow_packet.has_value());
    PFL_EXPECT(third_selected_flow_packet->packet_index == 3U);
    PFL_EXPECT(cache_session.selected_flow_packet_number(0U, 0U) == std::optional<std::uint64_t> {1U});
    PFL_EXPECT(cache_session.selected_flow_packet_number(0U, 2U) == std::optional<std::uint64_t> {2U});
    PFL_EXPECT(!cache_session.selected_flow_cached_packet_number(0U, 3U).has_value());
    PFL_EXPECT(!cache_session.selected_flow_packet_number(0U, 3U).has_value());
    PFL_EXPECT(cache_session.selected_flow_exact_packet_number(0U, 3U) == std::optional<std::uint64_t> {3U});
    PFL_EXPECT(!cache_session.selected_flow_packet_number(0U, 1U).has_value());
    PFL_EXPECT(!cache_session.selected_flow_packet_at(0U, 0U).has_value());
    PFL_EXPECT(!cache_session.selected_flow_packet_at(0U, 5U).has_value());

    const auto cached_flow_packets = cache_session.flow_packets(0);
    PFL_REQUIRE(cached_flow_packets.has_value());
    PFL_EXPECT(cached_flow_packets->size() == 4U);
    PFL_EXPECT(cache_session.read_packet_data((*cached_flow_packets)[0]) == cache_packet_one);
    PFL_EXPECT(cache_session.read_packet_data((*cached_flow_packets)[1]) == cache_packet_two);
    PFL_EXPECT(cache_session.read_selected_flow_transport_payload(0, (*cached_flow_packets)[0]) == bytes_payload("one"));
    PFL_EXPECT(cache_session.read_selected_flow_transport_payload_prefix(0, (*cached_flow_packets)[0], 2U) ==
        std::vector<std::uint8_t>({'o', 'n'}));
    PFL_EXPECT(cache_session.read_selected_flow_transport_payload_slice(0, (*cached_flow_packets)[0], 1U, 2U) ==
        std::vector<std::uint8_t>({'n', 'e'}));
    PFL_EXPECT(cache_session.read_selected_flow_transport_payload(0, (*cached_flow_packets)[1]) == bytes_payload("two"));
    PFL_EXPECT(cache_session.read_selected_flow_transport_payload_prefix(0, (*cached_flow_packets)[1], 99U) ==
        bytes_payload("two"));
    PFL_EXPECT(cache_session.read_selected_flow_transport_payload_slice(0, (*cached_flow_packets)[1], 99U, 2U).empty());

    cache_session.prepare_selected_flow_packet_cache(0, 4U);
    cache_info = cache_session.selected_flow_packet_cache_info();
    PFL_REQUIRE(cache_info.has_value());
    PFL_EXPECT(cache_info->flow_index == 0U);
    PFL_EXPECT(cache_info->cached_packet_window_count == 4U);
    PFL_EXPECT(cache_info->cached_packet_contribution_count == 4U);
    PFL_EXPECT(cache_info->total_cached_bytes == 15U);
    PFL_EXPECT(!cache_info->limit_reached);
    PFL_EXPECT(cache_info->window_fully_cached);
    PFL_EXPECT(cache_session.read_selected_flow_transport_payload(0, (*cached_flow_packets)[0]) == bytes_payload("one"));
    PFL_EXPECT(cache_session.read_packet_data((*cached_flow_packets)[2]) == cache_packet_three);
    PFL_EXPECT(cache_session.read_selected_flow_transport_payload_prefix(0, (*cached_flow_packets)[2], 2U) ==
        std::vector<std::uint8_t>({'t', 'h'}));
    PFL_EXPECT(cache_session.read_selected_flow_transport_payload_slice(0, (*cached_flow_packets)[2], 1U, 2U) ==
        std::vector<std::uint8_t>({'h', 'r'}));
    PFL_EXPECT(cache_session.read_selected_flow_transport_payload(0, (*cached_flow_packets)[3]) == bytes_payload("four"));
    PFL_EXPECT(cache_session.read_packet_data((*cached_flow_packets)[3]) == cache_packet_four);

    cache_session.prepare_selected_flow_packet_cache(1, 1U);
    cache_info = cache_session.selected_flow_packet_cache_info();
    PFL_REQUIRE(cache_info.has_value());
    PFL_EXPECT(cache_info->flow_index == 1U);
    PFL_EXPECT(cache_info->cached_packet_window_count == 1U);
    PFL_EXPECT(cache_info->cached_packet_contribution_count == 1U);
    PFL_EXPECT(cache_info->total_cached_bytes == 3U);
    PFL_EXPECT(cache_info->window_fully_cached);
    const auto cached_udp_flow_packets = cache_session.flow_packets(1);
    PFL_REQUIRE(cached_udp_flow_packets.has_value());
    PFL_EXPECT(cached_udp_flow_packets->size() == 1U);
    PFL_EXPECT(cache_session.read_packet_data((*cached_udp_flow_packets)[0]) == cache_packet_dns);

    cache_session.prepare_selected_flow_packet_cache(0, 2U);
    cache_info = cache_session.selected_flow_packet_cache_info();
    PFL_REQUIRE(cache_info.has_value());
    PFL_EXPECT(cache_info->flow_index == 0U);
    PFL_EXPECT(cache_info->cached_packet_window_count == 2U);
    PFL_EXPECT(cache_info->cached_packet_contribution_count == 2U);
    PFL_EXPECT(cache_info->total_cached_bytes == 6U);

    CaptureSession tcp_contribution_cache_session {};
    PFL_EXPECT(tcp_contribution_cache_session.open_capture(cache_path));
    PFL_EXPECT(tcp_contribution_cache_session.suspected_tcp_retransmission_packet_indices(0U, 2U).empty());
    auto tcp_contribution_cache_info = tcp_contribution_cache_session.selected_flow_packet_cache_info();
    PFL_REQUIRE(tcp_contribution_cache_info.has_value());
    PFL_EXPECT(tcp_contribution_cache_info->flow_index == 0U);
    PFL_EXPECT(tcp_contribution_cache_info->cached_packet_window_count == 2U);
    PFL_EXPECT(tcp_contribution_cache_info->cached_packet_contribution_count == 2U);
    PFL_EXPECT(tcp_contribution_cache_info->total_cached_bytes == 6U);

    PFL_EXPECT(tcp_contribution_cache_session.suspected_tcp_retransmission_packet_indices(0U, 2U).empty());
    tcp_contribution_cache_info = tcp_contribution_cache_session.selected_flow_packet_cache_info();
    PFL_REQUIRE(tcp_contribution_cache_info.has_value());
    PFL_EXPECT(tcp_contribution_cache_info->cached_packet_window_count == 2U);
    PFL_EXPECT(tcp_contribution_cache_info->cached_packet_contribution_count == 2U);
    PFL_EXPECT(tcp_contribution_cache_info->total_cached_bytes == 6U);

    tcp_contribution_cache_session.set_selected_flow_tcp_payload_suppression(0U, {}, 2U);
    PFL_EXPECT(!tcp_contribution_cache_session.should_suppress_selected_flow_tcp_payload(0U, 0U));

    PFL_EXPECT(tcp_contribution_cache_session.suspected_tcp_retransmission_packet_indices(0U, 4U).empty());
    tcp_contribution_cache_info = tcp_contribution_cache_session.selected_flow_packet_cache_info();
    PFL_REQUIRE(tcp_contribution_cache_info.has_value());
    PFL_EXPECT(tcp_contribution_cache_info->cached_packet_window_count == 4U);
    PFL_EXPECT(tcp_contribution_cache_info->cached_packet_contribution_count == 4U);
    PFL_EXPECT(tcp_contribution_cache_info->total_cached_bytes == 15U);

    const auto fragmented_tcp_cache_path = write_temp_pcap(
        "pfl_query_selected_flow_unknown_payload_cache.pcap",
        make_classic_pcap({
            {100U, make_ipv4_tcp_first_fragment_with_complete_header(
                ipv4(10, 71, 0, 1),
                ipv4(10, 71, 0, 2),
                55000,
                443
            )}
        })
    );

    CaptureSession fragmented_tcp_cache_session {};
    PFL_EXPECT(fragmented_tcp_cache_session.open_capture(fragmented_tcp_cache_path));
    const auto fragmented_flow_packets = fragmented_tcp_cache_session.flow_packets(0U);
    PFL_REQUIRE(fragmented_flow_packets.has_value());
    PFL_REQUIRE(fragmented_flow_packets->size() == 1U);

    fragmented_tcp_cache_session.prepare_selected_flow_packet_cache(0U, 1U);
    auto fragmented_cache_info = fragmented_tcp_cache_session.selected_flow_packet_cache_info();
    PFL_REQUIRE(fragmented_cache_info.has_value());
    PFL_EXPECT(fragmented_cache_info->flow_index == 0U);
    PFL_EXPECT(fragmented_cache_info->cached_packet_window_count == 1U);
    PFL_EXPECT(fragmented_cache_info->cached_packet_contribution_count == 1U);
    PFL_EXPECT(fragmented_cache_info->total_cached_bytes == 0U);
    PFL_EXPECT(!fragmented_cache_info->limit_reached);
    PFL_EXPECT(fragmented_cache_info->window_fully_cached);
    PFL_EXPECT(fragmented_tcp_cache_session.read_selected_flow_transport_payload(
        0U,
        (*fragmented_flow_packets)[0]
    ).empty());
    PFL_EXPECT(fragmented_tcp_cache_session.read_selected_flow_transport_payload_prefix(
        0U,
        (*fragmented_flow_packets)[0],
        8U
    ).empty());
    PFL_EXPECT(fragmented_tcp_cache_session.read_selected_flow_transport_payload_slice(
        0U,
        (*fragmented_flow_packets)[0],
        0U,
        8U
    ).empty());

    PFL_EXPECT(fragmented_tcp_cache_session.suspected_tcp_retransmission_packet_indices(0U, 1U).empty());
    fragmented_cache_info = fragmented_tcp_cache_session.selected_flow_packet_cache_info();
    PFL_REQUIRE(fragmented_cache_info.has_value());
    PFL_EXPECT(fragmented_cache_info->cached_packet_window_count == 1U);
    PFL_EXPECT(fragmented_cache_info->cached_packet_contribution_count == 1U);
    PFL_EXPECT(fragmented_cache_info->total_cached_bytes == 0U);
    PFL_EXPECT(!fragmented_cache_info->limit_reached);
    PFL_EXPECT(fragmented_cache_info->window_fully_cached);
    PFL_EXPECT(fragmented_tcp_cache_session.read_selected_flow_transport_payload(
        0U,
        (*fragmented_flow_packets)[0]
    ).empty());
    PFL_EXPECT(fragmented_tcp_cache_session.read_selected_flow_transport_payload_prefix(
        0U,
        (*fragmented_flow_packets)[0],
        8U
    ).empty());
    PFL_EXPECT(fragmented_tcp_cache_session.read_selected_flow_transport_payload_slice(
        0U,
        (*fragmented_flow_packets)[0],
        0U,
        8U
    ).empty());

    {
        const FlowRow filter_row {
            .index = 17U,
            .family = FlowAddressFamily::ipv4,
            .protocol_path_id = kInvalidProtocolPathId,
            .protocol_text = "TCP",
            .protocol_hint = "http",
            .service_hint = "alpha.example",
            .has_fragmented_packets = true,
            .fragmented_packet_count = 7U,
            .address_a = "10.11.12.13",
            .port_a = 41000U,
            .endpoint_a = "10.11.12.13:41000",
            .address_b = "10.11.12.14",
            .port_b = 80U,
            .endpoint_b = "10.11.12.14:80",
            .packet_count = 12U,
            .total_bytes = 2048U,
        };

        PFL_EXPECT(session_detail::flow_row_matches_text_filter(filter_row, "ipv4"));
        PFL_EXPECT(session_detail::flow_row_matches_text_filter(filter_row, "tcp"));
        PFL_EXPECT(session_detail::flow_row_matches_text_filter(filter_row, "HTTP"));
        PFL_EXPECT(session_detail::flow_row_matches_text_filter(filter_row, "alpha.example"));
        PFL_EXPECT(session_detail::flow_row_matches_text_filter(filter_row, "10.11.12.13"));
        PFL_EXPECT(session_detail::flow_row_matches_text_filter(filter_row, "10.11.12.14"));
        PFL_EXPECT(session_detail::flow_row_matches_text_filter(filter_row, "10.11.12.13:41000"));
        PFL_EXPECT(session_detail::flow_row_matches_text_filter(filter_row, "10.11.12.14:80"));
        PFL_EXPECT(session_detail::flow_row_matches_text_filter(filter_row, "41000"));
        PFL_EXPECT(session_detail::flow_row_matches_text_filter(filter_row, "80"));
        PFL_EXPECT(!session_detail::flow_row_matches_text_filter(filter_row, "frag"));
        PFL_EXPECT(!session_detail::flow_row_matches_text_filter(filter_row, "7"));
        PFL_EXPECT(!session_detail::flow_row_matches_text_filter(filter_row, "12"));
        PFL_EXPECT(!session_detail::flow_row_matches_text_filter(filter_row, "2048"));
        PFL_EXPECT(!session_detail::flow_row_matches_text_filter(filter_row, "vxlan"));
    }

    {
        auto query_session = build_shared_flow_query_session();
        const auto rows = query_session.list_flows();
        PFL_REQUIRE(rows.size() == 4U);

        const auto tcp_heavy_index = find_flow_index_by_service_hint(rows, "zz-flow.example");
        const auto http_index = find_flow_index_by_service_hint(rows, "alpha.example");
        const auto dns_index = find_flow_index_by_service_hint(rows, "beta.example");
        PFL_REQUIRE(tcp_heavy_index.has_value());
        PFL_REQUIRE(http_index.has_value());
        PFL_REQUIRE(dns_index.has_value());

        std::optional<std::size_t> ipv6_index {};
        for (const auto& row : rows) {
            if (row.family == FlowAddressFamily::ipv6) {
                ipv6_index = row.index;
                break;
            }
        }
        PFL_REQUIRE(ipv6_index.has_value());

        session_detail::FlowQuery query {};
        auto result = query_session.query_flows(query);
        PFL_EXPECT(result.status == session_detail::FlowQueryStatus::ok);
        PFL_EXPECT(result.ordered_flow_indices == std::vector<std::size_t>({0U, 1U, 2U, 3U}));
        PFL_EXPECT(result.result_count_before_limit == 4U);

        query.selected_flow_indices = std::vector<std::size_t> {*dns_index, *http_index, *dns_index};
        query.text_filter.clear();
        query.sort.reset();
        query.limit.reset();
        result = query_session.query_flows(query);
        PFL_EXPECT(result.status == session_detail::FlowQueryStatus::ok);
        PFL_EXPECT(result.ordered_flow_indices == std::vector<std::size_t>({*http_index, *dns_index}));
        PFL_EXPECT(result.result_count_before_limit == 2U);

        query.selected_flow_indices = std::vector<std::size_t> {99U};
        result = query_session.query_flows(query);
        PFL_EXPECT(result.status == session_detail::FlowQueryStatus::invalid_flow_index);
        PFL_EXPECT(result.invalid_flow_index == std::optional<std::size_t> {99U});
        PFL_EXPECT(result.ordered_flow_indices.empty());
        PFL_EXPECT(result.result_count_before_limit == 0U);

        query.selected_flow_indices.reset();
        query.text_filter = "no-such-flow";
        result = query_session.query_flows(query);
        PFL_EXPECT(result.status == session_detail::FlowQueryStatus::ok);
        PFL_EXPECT(result.ordered_flow_indices.empty());
        PFL_EXPECT(result.result_count_before_limit == 0U);

        query.text_filter = "beta.example";
        result = query_session.query_flows(query);
        PFL_EXPECT(result.status == session_detail::FlowQueryStatus::ok);
        PFL_EXPECT(result.ordered_flow_indices == std::vector<std::size_t>({*dns_index}));
        PFL_EXPECT(result.result_count_before_limit == 1U);

        query.text_filter = "VXLAN";
        result = query_session.query_flows(query);
        PFL_EXPECT(result.status == session_detail::FlowQueryStatus::ok);
        PFL_EXPECT(result.ordered_flow_indices.empty());
        PFL_EXPECT(result.result_count_before_limit == 0U);

        query.text_filter.clear();
        query.sort = session_detail::FlowQuerySortSpec {
            .key = session_detail::FlowQuerySortKey::canonical_index,
            .direction = session_detail::FlowQuerySortDirection::descending,
        };
        result = query_session.query_flows(query);
        PFL_EXPECT(result.ordered_flow_indices == std::vector<std::size_t>({3U, 2U, 1U, 0U}));
        PFL_EXPECT(result.result_count_before_limit == 4U);

        query.sort = session_detail::FlowQuerySortSpec {
            .key = session_detail::FlowQuerySortKey::protocol,
            .direction = session_detail::FlowQuerySortDirection::ascending,
        };
        result = query_session.query_flows(query);
        PFL_EXPECT(result.ordered_flow_indices == std::vector<std::size_t>({*tcp_heavy_index, *http_index, *dns_index, *ipv6_index}));

        query.sort = session_detail::FlowQuerySortSpec {
            .key = session_detail::FlowQuerySortKey::protocol,
            .direction = session_detail::FlowQuerySortDirection::descending,
        };
        result = query_session.query_flows(query);
        PFL_EXPECT(result.ordered_flow_indices == std::vector<std::size_t>({*dns_index, *ipv6_index, *tcp_heavy_index, *http_index}));

        query.sort = session_detail::FlowQuerySortSpec {
            .key = session_detail::FlowQuerySortKey::service,
            .direction = session_detail::FlowQuerySortDirection::ascending,
        };
        result = query_session.query_flows(query);
        PFL_EXPECT(result.ordered_flow_indices == std::vector<std::size_t>({*ipv6_index, *http_index, *dns_index, *tcp_heavy_index}));

        query.sort = session_detail::FlowQuerySortSpec {
            .key = session_detail::FlowQuerySortKey::endpoint_a,
            .direction = session_detail::FlowQuerySortDirection::ascending,
        };
        result = query_session.query_flows(query);
        PFL_EXPECT(result.ordered_flow_indices == std::vector<std::size_t>({*http_index, *dns_index, *tcp_heavy_index, *ipv6_index}));

        query.sort = session_detail::FlowQuerySortSpec {
            .key = session_detail::FlowQuerySortKey::endpoint_b,
            .direction = session_detail::FlowQuerySortDirection::ascending,
        };
        result = query_session.query_flows(query);
        PFL_EXPECT(result.ordered_flow_indices == std::vector<std::size_t>({*http_index, *dns_index, *tcp_heavy_index, *ipv6_index}));

        query.sort = session_detail::FlowQuerySortSpec {
            .key = session_detail::FlowQuerySortKey::packets,
            .direction = session_detail::FlowQuerySortDirection::ascending,
        };
        result = query_session.query_flows(query);
        PFL_EXPECT(result.ordered_flow_indices == std::vector<std::size_t>({*dns_index, *ipv6_index, *http_index, *tcp_heavy_index}));

        query.sort = session_detail::FlowQuerySortSpec {
            .key = session_detail::FlowQuerySortKey::packets,
            .direction = session_detail::FlowQuerySortDirection::descending,
        };
        result = query_session.query_flows(query);
        PFL_EXPECT(result.ordered_flow_indices == std::vector<std::size_t>({*tcp_heavy_index, *http_index, *dns_index, *ipv6_index}));

        query.sort = session_detail::FlowQuerySortSpec {
            .key = session_detail::FlowQuerySortKey::bytes,
            .direction = session_detail::FlowQuerySortDirection::ascending,
        };
        result = query_session.query_flows(query);
        PFL_EXPECT(result.ordered_flow_indices == std::vector<std::size_t>({*ipv6_index, *dns_index, *http_index, *tcp_heavy_index}));
        PFL_EXPECT(result.result_count_before_limit == 4U);
        const auto& http_row = rows[*http_index];
        const auto& dns_row = rows[*dns_index];
        PFL_REQUIRE(dns_row.total_bytes < http_row.total_bytes);
        PFL_REQUIRE(std::to_string(dns_row.total_bytes) > std::to_string(http_row.total_bytes));

        query.selected_flow_indices = std::vector<std::size_t> {*dns_index, *http_index, *tcp_heavy_index};
        query.text_filter = "tcp";
        query.sort = session_detail::FlowQuerySortSpec {
            .key = session_detail::FlowQuerySortKey::bytes,
            .direction = session_detail::FlowQuerySortDirection::ascending,
        };
        query.limit = 1U;
        result = query_session.query_flows(query);
        PFL_EXPECT(result.status == session_detail::FlowQueryStatus::ok);
        PFL_EXPECT(result.ordered_flow_indices == std::vector<std::size_t>({*http_index}));
        PFL_EXPECT(result.result_count_before_limit == 2U);

        query.limit = 0U;
        result = query_session.query_flows(query);
        PFL_EXPECT(result.status == session_detail::FlowQueryStatus::invalid_limit);
        PFL_EXPECT(result.result_count_before_limit == 0U);

        query.limit = 10U;
        query.text_filter = "beta.example";
        query.sort = session_detail::FlowQuerySortSpec {
            .key = session_detail::FlowQuerySortKey::service,
            .direction = session_detail::FlowQuerySortDirection::ascending,
        };
        result = query_session.query_flows(query);
        PFL_EXPECT(result.status == session_detail::FlowQueryStatus::ok);
        PFL_EXPECT(result.ordered_flow_indices == std::vector<std::size_t>({*dns_index}));
        PFL_EXPECT(result.result_count_before_limit == 1U);

        PFL_EXPECT(query_session.protocol_path_compact_text(rows[*http_index].protocol_path_id) == "EII|Ip4|UDP|Vx|EII|Ip4|TCP");
        const auto direct_compact_text =
            session_detail::build_protocol_path_presentation(
                query_session.state().protocol_path_registry,
                rows[*http_index].protocol_path_id
            ).compact_text;
        PFL_EXPECT(query_session.protocol_path_compact_text(rows[*http_index].protocol_path_id) == direct_compact_text);
    }

    {
        CaptureSession session {};
        auto& state = session.state();
        const auto simple_tcp_path_id = state.protocol_path_registry.intern(ProtocolPath {
            {LayerKey::ethernet_ii(), LayerKey::ipv4(), LayerKey::tcp()}
        });

        const auto add_connection = [&](const std::uint8_t host_octet, const std::string& service_hint) {
            const FlowKeyV4 flow {
                .src_addr = ipv4(10, 20, 0, host_octet),
                .dst_addr = ipv4(10, 20, 1, host_octet),
                .src_port = static_cast<std::uint16_t>(40000U + host_octet),
                .dst_port = 443U,
                .protocol = ProtocolId::tcp,
            };
            ConnectionV4 connection {};
            connection.key = make_connection_key(flow);
            connection.key.protocol_path_id = simple_tcp_path_id;
            connection.service_hint = service_hint;
            connection.add_packet(
                flow,
                PacketRef {
                    .packet_index = host_octet,
                    .ts_sec = 5U,
                    .ts_usec = host_octet,
                    .captured_length = 64U,
                    .original_length = 64U,
                }
            );
            state.ipv4_connections.get_or_create(connection.key) = connection;
        };

        add_connection(1U, "bravo");
        add_connection(2U, "alpha");
        add_connection(3U, "Alpha");
        add_connection(4U, "alphabet");
        add_connection(5U, "");

        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 5U);

        const auto empty_index = find_flow_index_by_service_hint(rows, "");
        const auto alpha_lower_index = find_flow_index_by_service_hint(rows, "alpha");
        const auto alpha_upper_index = find_flow_index_by_service_hint(rows, "Alpha");
        const auto alphabet_index = find_flow_index_by_service_hint(rows, "alphabet");
        const auto bravo_index = find_flow_index_by_service_hint(rows, "bravo");
        PFL_REQUIRE(empty_index.has_value());
        PFL_REQUIRE(alpha_lower_index.has_value());
        PFL_REQUIRE(alpha_upper_index.has_value());
        PFL_REQUIRE(alphabet_index.has_value());
        PFL_REQUIRE(bravo_index.has_value());

        session_detail::FlowQuery query {};
        query.sort = session_detail::FlowQuerySortSpec {
            .key = session_detail::FlowQuerySortKey::service,
            .direction = session_detail::FlowQuerySortDirection::ascending,
        };
        const auto result = session.query_flows(query);
        PFL_EXPECT(result.status == session_detail::FlowQueryStatus::ok);
        PFL_EXPECT(result.ordered_flow_indices == std::vector<std::size_t>({
            *empty_index,
            *alpha_upper_index,
            *alpha_lower_index,
            *alphabet_index,
            *bravo_index,
        }));
    }
}

}  // namespace pfl::tests
