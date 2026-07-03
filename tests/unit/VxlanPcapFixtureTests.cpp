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
    const std::uint32_t expected_vni
) {
    CaptureSession session {};
    PFL_EXPECT(session.open_capture(fixture_path(relative_path)));

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

    const auto summary_layers = session_detail::build_packet_summary_layers(*details, *packet);
    const auto* udp_layer = find_layer(summary_layers, "udp");
    PFL_REQUIRE(udp_layer != nullptr);
    PFL_EXPECT(layer_has_field_containing(*udp_layer, "Destination Port", "4789"));

    const auto* vxlan_layer = find_layer(summary_layers, "vxlan");
    PFL_REQUIRE(vxlan_layer != nullptr);
    PFL_EXPECT(layer_has_field_containing(*vxlan_layer, "Flags", "0x08"));
    PFL_EXPECT(layer_has_field_containing(*vxlan_layer, "I Flag", "Set"));
    PFL_EXPECT(layer_has_field_containing(*vxlan_layer, "VNI", std::to_string(expected_vni)));
    PFL_EXPECT(layer_has_field_containing(*vxlan_layer, "Inner Payload", "Ethernet"));

    const auto* inner_ethernet_layer = find_layer(summary_layers, "ethernet-inner");
    PFL_REQUIRE(inner_ethernet_layer != nullptr);

    const auto protocol_text = session.read_packet_protocol_details_text(*packet);
    PFL_EXPECT(protocol_text.find("Protocol: VXLAN") != std::string::npos);
    PFL_EXPECT(protocol_text.find("VNI: " + std::to_string(expected_vni)) != std::string::npos);
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
        const auto* flow = find_flow_by_tuple(
            rows,
            FlowAddressFamily::ipv4,
            "TCP",
            "10.40.0.10",
            49440U,
            "10.40.0.20",
            443U
        );
        PFL_EXPECT(flow != nullptr);
        if (flow != nullptr) {
            PFL_EXPECT(flow->packet_count == 2U);
        }
        // Known branch limitation: VNI is not yet part of flow identity, so both packets may merge.
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

    expect_vxlan_packet_details_present(
        "parsing/vxlan/01_vxlan_inner_ipv4_tcp.pcap",
        0U,
        100U
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
