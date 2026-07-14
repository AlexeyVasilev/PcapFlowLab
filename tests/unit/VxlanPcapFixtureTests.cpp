#include <filesystem>
#include <string>
#include <vector>

#include "TestSupport.h"
#include "app/session/CaptureSession.h"
#include "app/session/FlowRows.h"
#include "app/session/SessionFormatting.h"

namespace pfl::tests {

namespace {

std::filesystem::path fixture_path(const std::filesystem::path& relative_path) {
    return std::filesystem::path(__FILE__).parent_path().parent_path() / "data" / relative_path;
}

bool row_matches_tuple(
    const FlowRow& row,
    const FlowAddressFamily family,
    const std::string& protocol,
    const std::string& address_a,
    const std::uint16_t port_a,
    const std::string& address_b,
    const std::uint16_t port_b
) {
    if (row.family != family || row.protocol_text != protocol) {
        return false;
    }

    const bool forward_match =
        row.address_a == address_a &&
        row.port_a == port_a &&
        row.address_b == address_b &&
        row.port_b == port_b;
    const bool reverse_match =
        row.address_a == address_b &&
        row.port_a == port_b &&
        row.address_b == address_a &&
        row.port_b == port_a;
    return forward_match || reverse_match;
}

const FlowRow* find_flow_by_tuple(
    const std::vector<FlowRow>& rows,
    const FlowAddressFamily family,
    const std::string& protocol,
    const std::string& address_a,
    const std::uint16_t port_a,
    const std::string& address_b,
    const std::uint16_t port_b
) {
    for (const auto& row : rows) {
        if (row_matches_tuple(row, family, protocol, address_a, port_a, address_b, port_b)) {
            return &row;
        }
    }
    return nullptr;
}

const session_detail::PacketSummaryLayer* find_layer(
    const std::vector<session_detail::PacketSummaryLayer>& layers,
    const std::string& id
) {
    for (const auto& layer : layers) {
        if (layer.id == id) {
            return &layer;
        }
        if (const auto* child = find_layer(layer.children, id); child != nullptr) {
            return child;
        }
    }
    return nullptr;
}

const session_detail::PacketSummaryLayer* find_top_level_layer(
    const std::vector<session_detail::PacketSummaryLayer>& layers,
    const std::string& id
) {
    for (const auto& layer : layers) {
        if (layer.id == id) {
            return &layer;
        }
    }
    return nullptr;
}

std::size_t find_top_level_layer_index(
    const std::vector<session_detail::PacketSummaryLayer>& layers,
    const std::string& id
) {
    for (std::size_t index = 0U; index < layers.size(); ++index) {
        if (layers[index].id == id) {
            return index;
        }
    }
    return layers.size();
}

bool layer_has_field_containing(
    const session_detail::PacketSummaryLayer& layer,
    const std::string& label,
    const std::string& fragment
) {
    for (const auto& field : layer.fields) {
        if (field.label == label && field.value.find(fragment) != std::string::npos) {
            return true;
        }
    }
    return false;
}

bool title_contains_all(
    const session_detail::PacketSummaryLayer& layer,
    const std::initializer_list<std::string> fragments
) {
    for (const auto& fragment : fragments) {
        if (layer.title.find(fragment) == std::string::npos) {
            return false;
        }
    }
    return true;
}

void expect_inner_flow_present(
    const std::filesystem::path& relative_path,
    const FlowAddressFamily family,
    const std::string& protocol,
    const std::string& address_a,
    const std::uint16_t port_a,
    const std::string& address_b,
    const std::uint16_t port_b,
    const std::uint64_t expected_packet_count
) {
    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(fixture_path(relative_path)));

    const auto rows = session.list_flows();
    const auto* flow = find_flow_by_tuple(rows, family, protocol, address_a, port_a, address_b, port_b);
    PFL_EXPECT(flow != nullptr);
    if (flow == nullptr) {
        return;
    }

    PFL_EXPECT(flow->packet_count == expected_packet_count);
}

void expect_inner_flow_absent(
    const std::filesystem::path& relative_path,
    const FlowAddressFamily family,
    const std::string& protocol,
    const std::string& address_a,
    const std::uint16_t port_a,
    const std::string& address_b,
    const std::uint16_t port_b
) {
    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(fixture_path(relative_path)));

    const auto rows = session.list_flows();
    const auto* flow = find_flow_by_tuple(rows, family, protocol, address_a, port_a, address_b, port_b);
    PFL_EXPECT(flow == nullptr);
}

void expect_vxlan_packet_details_present(
    const std::filesystem::path& relative_path,
    const std::uint64_t packet_index,
    const std::uint32_t expected_vni,
    const std::string& expected_inner_network_layer_id,
    const std::string& expected_inner_transport_layer_id,
    const std::string& expected_inner_source,
    const std::string& expected_inner_destination,
    const std::string& expected_inner_source_port,
    const std::string& expected_inner_destination_port,
    const bool expect_inner_vlan = false
) {
    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(fixture_path(relative_path)));

    const auto packet = session.find_packet(packet_index);
    PFL_REQUIRE(packet.has_value());
    const auto details = session.read_packet_details(*packet);
    PFL_REQUIRE(details.has_value());

    PFL_EXPECT(details->has_udp);
    PFL_EXPECT(details->has_vxlan);
    PFL_EXPECT(details->vxlan.present);
    PFL_EXPECT(details->vxlan.i_flag_set);
    PFL_EXPECT(details->vxlan.vni == expected_vni);
    PFL_EXPECT(details->has_inner_ethernet);
    PFL_EXPECT(details->vxlan.has_inner_packet);

    const auto summary_layers = session_detail::build_packet_summary_layers(*details, *packet);
    const auto* udp_layer = find_layer(summary_layers, "udp");
    PFL_REQUIRE(udp_layer != nullptr);
    PFL_EXPECT(layer_has_field_containing(*udp_layer, "Destination Port", "4789"));

    const auto* vxlan_layer = find_layer(summary_layers, "vxlan");
    PFL_REQUIRE(vxlan_layer != nullptr);
    PFL_EXPECT(title_contains_all(*vxlan_layer, {"VXLAN", std::to_string(expected_vni)}));
    PFL_EXPECT(layer_has_field_containing(*vxlan_layer, "Flags", "0x08"));
    PFL_EXPECT(layer_has_field_containing(*vxlan_layer, "VNI Flag", "Set"));
    PFL_EXPECT(layer_has_field_containing(*vxlan_layer, "VNI", std::to_string(expected_vni)));
    PFL_EXPECT(layer_has_field_containing(*vxlan_layer, "Inner Payload", "Ethernet"));
    PFL_EXPECT(vxlan_layer->children.empty());

    const auto* inner_ethernet_layer = find_top_level_layer(summary_layers, "ethernet-inner");
    PFL_REQUIRE(inner_ethernet_layer != nullptr);
    PFL_EXPECT(title_contains_all(*inner_ethernet_layer, {
        "Inner",
        "Src:",
        "Dst:",
        "02:00:00:00:41:01",
        "02:00:00:00:41:02",
    }));
    const auto vxlan_index = find_top_level_layer_index(summary_layers, "vxlan");
    const auto inner_ethernet_index = find_top_level_layer_index(summary_layers, "ethernet-inner");
    const auto inner_network_index = find_top_level_layer_index(summary_layers, expected_inner_network_layer_id);
    const auto inner_transport_index = find_top_level_layer_index(summary_layers, expected_inner_transport_layer_id);
    PFL_REQUIRE(vxlan_index < summary_layers.size());
    PFL_REQUIRE(inner_ethernet_index < summary_layers.size());
    PFL_REQUIRE(inner_network_index < summary_layers.size());
    PFL_REQUIRE(inner_transport_index < summary_layers.size());
    PFL_EXPECT(vxlan_index < inner_ethernet_index);
    if (expect_inner_vlan) {
        const auto* inner_vlan_layer = find_top_level_layer(summary_layers, "vlan-inner");
        const auto inner_vlan_index = find_top_level_layer_index(summary_layers, "vlan-inner");
        PFL_REQUIRE(inner_vlan_layer != nullptr);
        PFL_REQUIRE(inner_vlan_index < summary_layers.size());
        PFL_EXPECT(title_contains_all(*inner_vlan_layer, {"Inner VLAN", "140"}));
        PFL_EXPECT(inner_ethernet_index < inner_vlan_index);
        PFL_EXPECT(inner_vlan_index < inner_network_index);
    } else {
        PFL_EXPECT(inner_ethernet_index < inner_network_index);
    }
    PFL_EXPECT(inner_network_index < inner_transport_index);

    const auto* inner_network_layer = find_top_level_layer(summary_layers, expected_inner_network_layer_id);
    PFL_REQUIRE(inner_network_layer != nullptr);
    if (expected_inner_network_layer_id == "ipv4-inner") {
        PFL_EXPECT(title_contains_all(*inner_network_layer, {
            "Inner IPv4",
            expected_inner_source,
            expected_inner_destination,
        }));
    } else if (expected_inner_network_layer_id == "ipv6-inner") {
        PFL_EXPECT(title_contains_all(*inner_network_layer, {
            "Inner IPv6",
            expected_inner_source,
            expected_inner_destination,
        }));
    }

    const auto* inner_transport_layer = find_top_level_layer(summary_layers, expected_inner_transport_layer_id);
    PFL_REQUIRE(inner_transport_layer != nullptr);
    if (expected_inner_transport_layer_id == "tcp-inner") {
        PFL_EXPECT(title_contains_all(*inner_transport_layer, {"Inner TCP", "Src Port:", "Dst Port:"}));
        PFL_EXPECT(title_contains_all(*inner_transport_layer, {
            expected_inner_source_port,
            expected_inner_destination_port,
        }));
    } else if (expected_inner_transport_layer_id == "udp-inner") {
        PFL_EXPECT(title_contains_all(*inner_transport_layer, {"Inner UDP", "Src Port:", "Dst Port:"}));
        PFL_EXPECT(title_contains_all(*inner_transport_layer, {
            expected_inner_source_port,
            expected_inner_destination_port,
        }));
    }

    const auto protocol_text = session.read_packet_protocol_details_text(*packet);
    PFL_EXPECT(protocol_text.find("Protocol: VXLAN") != std::string::npos);
    PFL_EXPECT(protocol_text.find("VNI Flag: Set") != std::string::npos);
    PFL_EXPECT(protocol_text.find("VNI: " + std::to_string(expected_vni)) != std::string::npos);
    const auto expected_transport_text =
        expected_inner_transport_layer_id == "tcp-inner" ? std::string {"TCP"} :
        expected_inner_transport_layer_id == "udp-inner" ? std::string {"UDP"} :
        expected_inner_transport_layer_id;
    if (expected_inner_network_layer_id == "ipv4-inner") {
        PFL_EXPECT(protocol_text.find("Inner IPv4: " + expected_transport_text) != std::string::npos);
    } else if (expected_inner_network_layer_id == "ipv6-inner") {
        PFL_EXPECT(protocol_text.find("Inner IPv6: " + expected_transport_text) != std::string::npos);
    }
    if (expect_inner_vlan) {
        PFL_EXPECT(protocol_text.find("Inner VLAN: ") != std::string::npos);
    }
}

void expect_vxlan_warning_packet_details(
    const std::filesystem::path& relative_path,
    const std::initializer_list<std::string> expected_vxlan_title_fragments,
    const std::initializer_list<std::string> expected_protocol_fragments,
    const bool expect_vxlan_layer_warning,
    const bool expect_inner_ethernet,
    const bool expect_inner_ipv4,
    const bool expect_inner_udp,
    const bool expect_inner_tcp
) {
    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(fixture_path(relative_path)));

    const auto packet = session.find_packet(0U);
    PFL_REQUIRE(packet.has_value());
    const auto details = session.read_packet_details(*packet);
    PFL_REQUIRE(details.has_value());
    PFL_EXPECT(details->has_udp);
    PFL_EXPECT(details->has_vxlan);

    const auto summary_layers = session_detail::build_packet_summary_layers(*details, *packet);
    const auto* vxlan_layer = find_layer(summary_layers, "vxlan");
    PFL_REQUIRE(vxlan_layer != nullptr);
    PFL_EXPECT(title_contains_all(*vxlan_layer, expected_vxlan_title_fragments));
    PFL_EXPECT(vxlan_layer->warning == expect_vxlan_layer_warning);

    const auto* inner_ethernet_layer = find_top_level_layer(summary_layers, "ethernet-inner");
    PFL_EXPECT((inner_ethernet_layer != nullptr) == expect_inner_ethernet);
    if (expect_inner_ethernet && inner_ethernet_layer != nullptr &&
        relative_path == std::filesystem::path("parsing/vxlan/07_vxlan_truncated_inner_ethernet.pcap")) {
        PFL_EXPECT(inner_ethernet_layer->title.find("truncated") != std::string::npos);
    }
    const auto* inner_ipv4_layer = find_top_level_layer(summary_layers, "ipv4-inner");
    PFL_EXPECT((inner_ipv4_layer != nullptr) == expect_inner_ipv4);
    if (expect_inner_ipv4 && inner_ipv4_layer != nullptr &&
        relative_path == std::filesystem::path("parsing/vxlan/08_vxlan_truncated_inner_ipv4.pcap")) {
        PFL_EXPECT(inner_ipv4_layer->title.find("truncated") != std::string::npos);
    }
    const auto* inner_udp_layer = find_top_level_layer(summary_layers, "udp-inner");
    PFL_EXPECT((inner_udp_layer != nullptr) == expect_inner_udp);
    const auto* inner_tcp_layer = find_top_level_layer(summary_layers, "tcp-inner");
    PFL_EXPECT((inner_tcp_layer != nullptr) == expect_inner_tcp);

    const auto protocol_text = session.read_packet_protocol_details_text(*packet);
    PFL_EXPECT(protocol_text.find("Protocol: VXLAN") != std::string::npos);
    for (const auto& fragment : expected_protocol_fragments) {
        PFL_EXPECT(protocol_text.find(fragment) != std::string::npos);
    }
}

}  // namespace

void run_vxlan_pcap_fixture_tests() {
    expect_inner_flow_present(
        "parsing/vxlan/01_vxlan_inner_ipv4_tcp.pcap",
        FlowAddressFamily::ipv4,
        "TCP",
        "10.40.0.10",
        49440U,
        "10.40.0.20",
        443U,
        1U
    );

    expect_inner_flow_present(
        "parsing/vxlan/02_vxlan_inner_ipv4_udp.pcap",
        FlowAddressFamily::ipv4,
        "UDP",
        "10.40.0.10",
        53540U,
        "10.40.0.20",
        443U,
        1U
    );

    expect_inner_flow_present(
        "parsing/vxlan/03_vxlan_inner_ipv6_tcp.pcap",
        FlowAddressFamily::ipv6,
        "TCP",
        "2001:0db8:0040:0000:0000:0000:0000:0010",
        49440U,
        "2001:0db8:0040:0000:0000:0000:0000:0020",
        443U,
        1U
    );

    expect_inner_flow_present(
        "parsing/vxlan/04_vxlan_inner_ipv6_udp.pcap",
        FlowAddressFamily::ipv6,
        "UDP",
        "2001:0db8:0040:0000:0000:0000:0000:0010",
        53540U,
        "2001:0db8:0040:0000:0000:0000:0000:0020",
        443U,
        1U
    );

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/vxlan/10_vxlan_same_inner_tuple_different_vni.pcap")));
        const auto rows = session.list_flows();
        const auto matching_flow_count = static_cast<std::size_t>(std::count_if(rows.begin(), rows.end(), [&](const FlowRow& row) {
            return row_matches_tuple(
                row,
                FlowAddressFamily::ipv4,
                "TCP",
                "10.40.0.10",
                49440U,
                "10.40.0.20",
                443U
            );
        }));
        PFL_EXPECT(rows.size() == 2U);
        PFL_EXPECT(matching_flow_count == 2U);
        PFL_EXPECT(std::all_of(rows.begin(), rows.end(), [](const FlowRow& row) {
            return row.packet_count == 1U;
        }));
    }

    expect_inner_flow_present(
        "parsing/vxlan/11_vxlan_inner_ipv4_tcp_bidirectional.pcap",
        FlowAddressFamily::ipv4,
        "TCP",
        "10.40.0.10",
        49440U,
        "10.40.0.20",
        443U,
        2U
    );

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/vxlan/12_vxlan_same_outer_tuple_different_inner_flows.pcap")));
        const auto rows = session.list_flows();
        const auto* first_flow = find_flow_by_tuple(
            rows,
            FlowAddressFamily::ipv4,
            "TCP",
            "10.40.0.10",
            10001U,
            "10.40.0.20",
            443U
        );
        const auto* second_flow = find_flow_by_tuple(
            rows,
            FlowAddressFamily::ipv4,
            "TCP",
            "10.40.0.10",
            10002U,
            "10.40.0.20",
            443U
        );
        PFL_EXPECT(first_flow != nullptr);
        PFL_EXPECT(second_flow != nullptr);
        if (first_flow != nullptr) {
            PFL_EXPECT(first_flow->packet_count == 1U);
        }
        if (second_flow != nullptr) {
            PFL_EXPECT(second_flow->packet_count == 1U);
        }
    }

    expect_inner_flow_present(
        "parsing/vxlan/13_vxlan_inner_vlan_ipv4_tcp.pcap",
        FlowAddressFamily::ipv4,
        "TCP",
        "10.40.0.10",
        49440U,
        "10.40.0.20",
        443U,
        1U
    );

    expect_inner_flow_present(
        "parsing/vxlan/14_vxlan_outer_ipv6_inner_ipv4_tcp.pcap",
        FlowAddressFamily::ipv4,
        "TCP",
        "10.40.0.10",
        49440U,
        "10.40.0.20",
        443U,
        1U
    );

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/vxlan/16_vxlan_vni_boundary_values.pcap")));
        const auto rows = session.list_flows();
        const auto* first_flow = find_flow_by_tuple(
            rows,
            FlowAddressFamily::ipv4,
            "TCP",
            "10.40.0.10",
            49440U,
            "10.40.0.20",
            443U
        );
        const auto* second_flow = find_flow_by_tuple(
            rows,
            FlowAddressFamily::ipv4,
            "TCP",
            "10.40.0.11",
            10001U,
            "10.40.0.21",
            443U
        );
        PFL_EXPECT(first_flow != nullptr);
        PFL_EXPECT(second_flow != nullptr);
    }

    expect_inner_flow_absent(
        "parsing/vxlan/05_vxlan_truncated_header.pcap",
        FlowAddressFamily::ipv4,
        "TCP",
        "10.40.0.10",
        49440U,
        "10.40.0.20",
        443U
    );

    expect_inner_flow_absent(
        "parsing/vxlan/06_vxlan_invalid_flags_or_reserved_bits.pcap",
        FlowAddressFamily::ipv4,
        "UDP",
        "10.40.0.10",
        53540U,
        "10.40.0.20",
        443U
    );

    expect_inner_flow_absent(
        "parsing/vxlan/07_vxlan_truncated_inner_ethernet.pcap",
        FlowAddressFamily::ipv4,
        "TCP",
        "10.40.0.10",
        49440U,
        "10.40.0.20",
        443U
    );

    expect_inner_flow_absent(
        "parsing/vxlan/08_vxlan_truncated_inner_ipv4.pcap",
        FlowAddressFamily::ipv4,
        "TCP",
        "10.40.0.10",
        49440U,
        "10.40.0.20",
        443U
    );

    expect_inner_flow_absent(
        "parsing/vxlan/09_vxlan_unsupported_inner_ethertype.pcap",
        FlowAddressFamily::ipv4,
        "TCP",
        "10.40.0.10",
        49440U,
        "10.40.0.20",
        443U
    );

    expect_inner_flow_absent(
        "parsing/vxlan/15_vxlan_wrong_udp_port_valid_vxlan_payload.pcap",
        FlowAddressFamily::ipv4,
        "TCP",
        "10.40.0.10",
        49440U,
        "10.40.0.20",
        443U
    );

    expect_vxlan_warning_packet_details(
        "parsing/vxlan/05_vxlan_truncated_header.pcap",
        {"VXLAN", "malformed"},
        {"Available Header Bytes: 6 / 8", "Warning: VXLAN header is truncated."},
        true,
        false,
        false,
        false,
        false
    );

    expect_vxlan_warning_packet_details(
        "parsing/vxlan/06_vxlan_invalid_flags_or_reserved_bits.pcap",
        {"VXLAN", "invalid"},
        {"VNI Flag: Not set", "VNI: 100", "Warning: VXLAN VNI flag is not set.", "Inner IPv4: UDP"},
        true,
        true,
        true,
        true,
        false
    );

    expect_vxlan_warning_packet_details(
        "parsing/vxlan/07_vxlan_truncated_inner_ethernet.pcap",
        {"VXLAN", "VNI: 100"},
        {"Warning: Inner Ethernet header is truncated."},
        true,
        true,
        false,
        false,
        false
    );

    expect_vxlan_warning_packet_details(
        "parsing/vxlan/08_vxlan_truncated_inner_ipv4.pcap",
        {"VXLAN", "VNI: 100"},
        {"Inner IPv4:", "Warning: Inner IPv4 packet is truncated"},
        false,
        true,
        true,
        false,
        false
    );

    expect_vxlan_packet_details_present(
        "parsing/vxlan/01_vxlan_inner_ipv4_tcp.pcap",
        0U,
        100U,
        "ipv4-inner",
        "tcp-inner",
        "10.40.0.10",
        "10.40.0.20",
        "49440",
        "443"
    );

    expect_vxlan_packet_details_present(
        "parsing/vxlan/02_vxlan_inner_ipv4_udp.pcap",
        0U,
        100U,
        "ipv4-inner",
        "udp-inner",
        "10.40.0.10",
        "10.40.0.20",
        "53540",
        "443"
    );

    expect_vxlan_packet_details_present(
        "parsing/vxlan/03_vxlan_inner_ipv6_tcp.pcap",
        0U,
        100U,
        "ipv6-inner",
        "tcp-inner",
        "2001:0db8:0040:0000:0000:0000:0000:0010",
        "2001:0db8:0040:0000:0000:0000:0000:0020",
        "49440",
        "443"
    );

    expect_vxlan_packet_details_present(
        "parsing/vxlan/04_vxlan_inner_ipv6_udp.pcap",
        0U,
        100U,
        "ipv6-inner",
        "udp-inner",
        "2001:0db8:0040:0000:0000:0000:0000:0010",
        "2001:0db8:0040:0000:0000:0000:0000:0020",
        "53540",
        "443"
    );

    expect_vxlan_packet_details_present(
        "parsing/vxlan/13_vxlan_inner_vlan_ipv4_tcp.pcap",
        0U,
        100U,
        "ipv4-inner",
        "tcp-inner",
        "10.40.0.10",
        "10.40.0.20",
        "49440",
        "443",
        true
    );

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/vxlan/16_vxlan_vni_boundary_values.pcap")));

        const auto first_packet = session.find_packet(0U);
        PFL_REQUIRE(first_packet.has_value());
        const auto first_details = session.read_packet_details(*first_packet);
        PFL_REQUIRE(first_details.has_value());
        PFL_EXPECT(first_details->has_vxlan);
        PFL_EXPECT(first_details->vxlan.vni == 0U);

        const auto second_packet = session.find_packet(1U);
        PFL_REQUIRE(second_packet.has_value());
        const auto second_details = session.read_packet_details(*second_packet);
        PFL_REQUIRE(second_details.has_value());
        PFL_EXPECT(second_details->has_vxlan);
        PFL_EXPECT(second_details->vxlan.vni == 16777215U);
    }

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/vxlan/15_vxlan_wrong_udp_port_valid_vxlan_payload.pcap")));
        const auto packet = session.find_packet(0U);
        PFL_REQUIRE(packet.has_value());
        const auto details = session.read_packet_details(*packet);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(!details->has_vxlan);
        const auto summary_layers = session_detail::build_packet_summary_layers(*details, *packet);
        PFL_EXPECT(find_layer(summary_layers, "vxlan") == nullptr);
        const auto protocol_text = session.read_packet_protocol_details_text(*packet);
        PFL_EXPECT(protocol_text.find("VXLAN") == std::string::npos);
    }
}

}  // namespace pfl::tests
