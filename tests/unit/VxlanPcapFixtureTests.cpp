#include <algorithm>
#include <array>
#include <filesystem>
#include <set>
#include <string>
#include <string_view>
#include <vector>

#include "TestSupport.h"
#include "app/session/CaptureSession.h"
#include "app/session/FlowRows.h"
#include "app/session/SessionFormatting.h"
#include "core/domain/ProtocolPath.h"

namespace pfl::tests {

namespace {

std::filesystem::path fixture_path(const std::filesystem::path& relative_path) {
    return std::filesystem::path(__FILE__).parent_path().parent_path() / "data" / relative_path;
}

const ProtocolPath* require_protocol_path(const CaptureSession& session, const ProtocolPathId protocol_path_id) {
    PFL_REQUIRE(protocol_path_id != kInvalidProtocolPathId);
    const auto* path = session.state().protocol_path_registry.find(protocol_path_id);
    PFL_REQUIRE(path != nullptr);
    return path;
}

std::string require_flow_protocol_path_text(const CaptureSession& session, const FlowRow& row) {
    return format_protocol_path(*require_protocol_path(session, row.protocol_path_id));
}

PacketRef require_packet(CaptureSession& session, const std::uint64_t packet_index) {
    const auto packet = session.find_packet(packet_index);
    PFL_REQUIRE(packet.has_value());
    return *packet;
}

constexpr std::array<std::string_view, 30> kExpectedVxlanFixtureFiles {{
    "01_vxlan_inner_ipv4_tcp.pcap",
    "02_vxlan_inner_ipv4_udp.pcap",
    "03_vxlan_inner_ipv6_tcp.pcap",
    "04_vxlan_inner_ipv6_udp.pcap",
    "05_vxlan_truncated_header.pcap",
    "06_vxlan_invalid_flags_or_reserved_bits.pcap",
    "07_vxlan_truncated_inner_ethernet.pcap",
    "08_vxlan_truncated_inner_ipv4.pcap",
    "09_vxlan_unsupported_inner_ethertype.pcap",
    "10_vxlan_same_inner_tuple_different_vni.pcap",
    "11_vxlan_inner_ipv4_tcp_bidirectional.pcap",
    "12_vxlan_same_outer_tuple_different_inner_flows.pcap",
    "13_vxlan_inner_vlan_ipv4_tcp.pcap",
    "14_vxlan_outer_ipv6_inner_ipv4_tcp.pcap",
    "15_vxlan_wrong_udp_port_valid_vxlan_payload.pcap",
    "16_vxlan_vni_boundary_values.pcap",
    "17_vxlan_udp_port_and_header_matrix.pcap",
    "18_vxlan_outer_tagged_contexts.pcap",
    "19_vxlan_outer_ipv6_inner_ipv6_udp.pcap",
    "20_vxlan_linux_sll_ipv4_inner_ipv4_udp.pcap",
    "21_vxlan_linux_sll2_ipv6_inner_ipv6_udp.pcap",
    "22_vxlan_identity_outer_carrier_variation_same_flow.pcap",
    "23_vxlan_identity_outer_and_inner_vlan_splits.pcap",
    "24_vxlan_outer_ipv4_fragmentation.pcap",
    "25_vxlan_outer_ipv6_fragmentation.pcap",
    "26_vxlan_udp_declared_bounds_matrix.pcap",
    "27_vxlan_inner_supported_and_visible_matrix.pcap",
    "28_vxlan_unsupported_and_nested_matrix.pcap",
    "29_vxlan_capture_truncation_matrix.pcap",
    "30_vxlan_vni_byte_order_distinct_values.pcap",
}};

std::set<std::string> expected_fixture_file_names() {
    std::set<std::string> names {};
    for (const auto file_name : kExpectedVxlanFixtureFiles) {
        names.emplace(file_name);
    }
    return names;
}

std::set<std::string> actual_fixture_file_names() {
    std::set<std::string> names {};
    const auto dir = fixture_path("parsing/vxlan");
    for (const auto& entry : std::filesystem::directory_iterator(dir)) {
        if (!entry.is_regular_file()) {
            continue;
        }
        if (entry.path().extension() == ".pcap") {
            names.emplace(entry.path().filename().string());
        }
    }
    return names;
}

void expect_vxlan_fixture_directory_matches_contract() {
    PFL_EXPECT(actual_fixture_file_names() == expected_fixture_file_names());
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

const FlowRow* require_flow_by_tuple(
    const std::vector<FlowRow>& rows,
    const FlowAddressFamily family,
    const std::string& protocol,
    const std::string& address_a,
    const std::uint16_t port_a,
    const std::string& address_b,
    const std::uint16_t port_b
) {
    const auto* row = find_flow_by_tuple(rows, family, protocol, address_a, port_a, address_b, port_b);
    PFL_REQUIRE(row != nullptr);
    return row;
}

void expect_outer_udp_flow(
    const CaptureSession& session,
    const std::vector<FlowRow>& rows,
    const std::string& address_a,
    const std::uint16_t port_a,
    const std::string& address_b,
    const std::uint16_t port_b,
    const std::uint64_t expected_packet_count,
    const std::string& expected_protocol_path
) {
    const auto* row = require_flow_by_tuple(rows, FlowAddressFamily::ipv4, "UDP", address_a, port_a, address_b, port_b);
    PFL_EXPECT(row->packet_count == expected_packet_count);
    PFL_EXPECT(require_flow_protocol_path_text(session, *row) == expected_protocol_path);
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
    expect_vxlan_fixture_directory_matches_contract();

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

    {
        const ScopedTestContext fixture_context {"fixture=parsing/vxlan/17_vxlan_udp_port_and_header_matrix.pcap"};
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/vxlan/17_vxlan_udp_port_and_header_matrix.pcap")));
        PFL_EXPECT(session.summary().packet_count == 6U);
        PFL_EXPECT(session.unrecognized_packet_count() == 0U);
        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 6U);

        const auto* inner_flow = require_flow_by_tuple(
            rows, FlowAddressFamily::ipv4, "TCP", "10.40.0.10", 49440U, "10.40.0.20", 443U);
        PFL_EXPECT(inner_flow->packet_count == 1U);
        PFL_EXPECT(require_flow_protocol_path_text(session, *inner_flow) ==
            "EthernetII -> IPv4 -> UDP -> VXLAN(vni=100) -> EthernetII -> IPv4 -> TCP");

        expect_outer_udp_flow(session, rows, "203.0.113.40", 53171U, "203.0.113.41", 8472U, 1U, "EthernetII -> IPv4 -> UDP");
        expect_outer_udp_flow(session, rows, "203.0.113.40", 4789U, "203.0.113.41", 4799U, 1U, "EthernetII -> IPv4 -> UDP");
        expect_outer_udp_flow(session, rows, "203.0.113.40", 53172U, "203.0.113.41", 4789U, 1U, "EthernetII -> IPv4 -> UDP");
        expect_outer_udp_flow(session, rows, "203.0.113.40", 53173U, "203.0.113.41", 4789U, 1U, "EthernetII -> IPv4 -> UDP");
        expect_outer_udp_flow(session, rows, "203.0.113.40", 53174U, "203.0.113.41", 4789U, 1U, "EthernetII -> IPv4 -> UDP");

        const auto valid_details = session.read_packet_details(require_packet(session, 0U));
        PFL_REQUIRE(valid_details.has_value());
        PFL_EXPECT(valid_details->has_vxlan);
        PFL_EXPECT(valid_details->vxlan.vni == 100U);

        const auto wrong_port_details = session.read_packet_details(require_packet(session, 1U));
        PFL_REQUIRE(wrong_port_details.has_value());
        PFL_EXPECT(!wrong_port_details->has_vxlan);

        const auto src_only_details = session.read_packet_details(require_packet(session, 2U));
        PFL_REQUIRE(src_only_details.has_value());
        PFL_EXPECT(!src_only_details->has_vxlan);

        const auto clear_i_details = session.read_packet_details(require_packet(session, 3U));
        PFL_REQUIRE(clear_i_details.has_value());
        PFL_EXPECT(clear_i_details->has_vxlan);
        PFL_EXPECT(!clear_i_details->vxlan.i_flag_set);
        PFL_EXPECT(clear_i_details->vxlan.invalid_header);

        const auto reserved_flag_details = session.read_packet_details(require_packet(session, 4U));
        PFL_REQUIRE(reserved_flag_details.has_value());
        PFL_EXPECT(reserved_flag_details->has_vxlan);
        PFL_EXPECT(reserved_flag_details->vxlan.invalid_header);

        const auto reserved_bytes_details = session.read_packet_details(require_packet(session, 5U));
        PFL_REQUIRE(reserved_bytes_details.has_value());
        PFL_EXPECT(reserved_bytes_details->has_vxlan);
        PFL_EXPECT(reserved_bytes_details->vxlan.reserved_bits_non_zero);
    }

    expect_inner_flow_present(
        "parsing/vxlan/18_vxlan_outer_tagged_contexts.pcap",
        FlowAddressFamily::ipv4,
        "UDP",
        "10.50.0.10",
        55010U,
        "10.50.0.20",
        8080U,
        1U
    );

    {
        const ScopedTestContext fixture_context {"fixture=parsing/vxlan/18_vxlan_outer_tagged_contexts.pcap"};
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/vxlan/18_vxlan_outer_tagged_contexts.pcap")));
        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 3U);
        PFL_EXPECT(session.unrecognized_packet_count() == 0U);

        const auto* outer_vlan_udp = require_flow_by_tuple(
            rows, FlowAddressFamily::ipv4, "UDP", "10.50.0.10", 55010U, "10.50.0.20", 8080U);
        PFL_EXPECT(require_flow_protocol_path_text(session, *outer_vlan_udp) ==
            "EthernetII -> VLAN(vid=201) -> IPv4 -> UDP -> VXLAN(vni=100) -> EthernetII -> IPv4 -> UDP");

        const auto* outer_qinq_tcp = require_flow_by_tuple(
            rows,
            FlowAddressFamily::ipv6,
            "TCP",
            "2001:0db8:0040:0000:0000:0000:0000:0010",
            55011U,
            "2001:0db8:0040:0000:0000:0000:0000:0020",
            8443U);
        PFL_EXPECT(require_flow_protocol_path_text(session, *outer_qinq_tcp) ==
            "EthernetII -> VLAN(vid=401) -> VLAN(vid=402) -> IPv6 -> UDP -> VXLAN(vni=100) -> EthernetII -> IPv6 -> TCP");

        const auto* outer_9100_tcp = require_flow_by_tuple(
            rows, FlowAddressFamily::ipv4, "TCP", "10.50.0.11", 55012U, "10.50.0.21", 9443U);
        PFL_EXPECT(require_flow_protocol_path_text(session, *outer_9100_tcp) ==
            "EthernetII -> VLAN(vid=501) -> IPv4 -> UDP -> VXLAN(vni=100) -> EthernetII -> IPv4 -> TCP");
    }

    {
        const ScopedTestContext fixture_context {"fixture=parsing/vxlan/19_vxlan_outer_ipv6_inner_ipv6_udp.pcap"};
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/vxlan/19_vxlan_outer_ipv6_inner_ipv6_udp.pcap")));
        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 1U);
        const auto* row = require_flow_by_tuple(
            rows,
            FlowAddressFamily::ipv6,
            "UDP",
            "2001:0db8:0040:0000:0000:0000:0000:0010",
            55020U,
            "2001:0db8:0040:0000:0000:0000:0000:0020",
            53U);
        PFL_EXPECT(require_flow_protocol_path_text(session, *row) ==
            "EthernetII -> IPv6 -> UDP -> VXLAN(vni=100) -> EthernetII -> IPv6 -> UDP");
    }

    {
        const ScopedTestContext fixture_context {"fixture=parsing/vxlan/20_vxlan_linux_sll_ipv4_inner_ipv4_udp.pcap"};
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/vxlan/20_vxlan_linux_sll_ipv4_inner_ipv4_udp.pcap")));
        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 1U);
        const auto* row = require_flow_by_tuple(
            rows, FlowAddressFamily::ipv4, "UDP", "10.60.0.10", 55030U, "10.60.0.20", 1234U);
        PFL_EXPECT(require_flow_protocol_path_text(session, *row) ==
            "LinuxSll -> IPv4 -> UDP -> VXLAN(vni=100) -> EthernetII -> IPv4 -> UDP");
    }

    {
        const ScopedTestContext fixture_context {"fixture=parsing/vxlan/21_vxlan_linux_sll2_ipv6_inner_ipv6_udp.pcap"};
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/vxlan/21_vxlan_linux_sll2_ipv6_inner_ipv6_udp.pcap")));
        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 1U);
        const auto* row = require_flow_by_tuple(
            rows,
            FlowAddressFamily::ipv6,
            "UDP",
            "2001:0db8:0040:0000:0000:0000:0000:0010",
            55031U,
            "2001:0db8:0040:0000:0000:0000:0000:0020",
            5353U);
        PFL_EXPECT(require_flow_protocol_path_text(session, *row) ==
            "LinuxSll2 -> IPv6 -> UDP -> VXLAN(vni=100) -> EthernetII -> IPv6 -> UDP");
    }

    {
        const ScopedTestContext fixture_context {"fixture=parsing/vxlan/22_vxlan_identity_outer_carrier_variation_same_flow.pcap"};
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/vxlan/22_vxlan_identity_outer_carrier_variation_same_flow.pcap")));
        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 1U);
        PFL_EXPECT(session.state().protocol_path_registry.size() == 1U);
        const auto* row = require_flow_by_tuple(
            rows, FlowAddressFamily::ipv4, "TCP", "10.70.0.10", 56000U, "10.70.0.20", 443U);
        PFL_EXPECT(row->packet_count == 4U);
        PFL_EXPECT(require_flow_protocol_path_text(session, *row) ==
            "EthernetII -> IPv4 -> UDP -> VXLAN(vni=100) -> EthernetII -> IPv4 -> TCP");
    }

    {
        const ScopedTestContext fixture_context {"fixture=parsing/vxlan/23_vxlan_identity_outer_and_inner_vlan_splits.pcap"};
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/vxlan/23_vxlan_identity_outer_and_inner_vlan_splits.pcap")));
        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 4U);
        PFL_EXPECT(session.state().protocol_path_registry.size() == 4U);
        PFL_EXPECT(std::all_of(rows.begin(), rows.end(), [](const FlowRow& row) {
            return row.packet_count == 1U;
        }));

        std::set<std::string> observed_paths {};
        for (const auto& row : rows) {
            observed_paths.emplace(require_flow_protocol_path_text(session, row));
        }
        const std::set<std::string> expected_paths {
            "EthernetII -> VLAN(vid=141) -> IPv4 -> UDP -> VXLAN(vni=100) -> EthernetII -> IPv4 -> TCP",
            "EthernetII -> VLAN(vid=142) -> IPv4 -> UDP -> VXLAN(vni=100) -> EthernetII -> IPv4 -> TCP",
            "EthernetII -> IPv4 -> UDP -> VXLAN(vni=100) -> EthernetII -> VLAN(vid=200) -> IPv4 -> TCP",
            "EthernetII -> IPv4 -> UDP -> VXLAN(vni=100) -> EthernetII -> VLAN(vid=201) -> IPv4 -> TCP",
        };
        PFL_EXPECT(observed_paths == expected_paths);
    }

    {
        const ScopedTestContext fixture_context {"fixture=parsing/vxlan/24_vxlan_outer_ipv4_fragmentation.pcap"};
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/vxlan/24_vxlan_outer_ipv4_fragmentation.pcap")));
        PFL_EXPECT(session.summary().packet_count == 3U);
        PFL_EXPECT(session.unrecognized_packet_count() == 1U);
        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 1U);
        PFL_EXPECT(rows[0].packet_count == 3U);
        PFL_EXPECT(rows[0].has_fragmented_packets);
        PFL_EXPECT(require_flow_protocol_path_text(session, rows[0]) == "EthernetII -> IPv4");
        const auto details = session.read_packet_details(require_packet(session, 0U));
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->has_ipv4);
        PFL_EXPECT(!details->has_udp);
        PFL_EXPECT(!details->has_vxlan);
    }

    {
        const ScopedTestContext fixture_context {"fixture=parsing/vxlan/25_vxlan_outer_ipv6_fragmentation.pcap"};
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/vxlan/25_vxlan_outer_ipv6_fragmentation.pcap")));
        PFL_EXPECT(session.summary().packet_count == 3U);
        PFL_EXPECT(session.unrecognized_packet_count() == 1U);
        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 1U);
        PFL_EXPECT(rows[0].packet_count == 3U);
        PFL_EXPECT(rows[0].has_fragmented_packets);
        PFL_EXPECT(require_flow_protocol_path_text(session, rows[0]) == "EthernetII -> IPv6");
        const auto details = session.read_packet_details(require_packet(session, 0U));
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->has_ipv6);
        PFL_EXPECT(!details->has_udp);
        PFL_EXPECT(!details->has_vxlan);
    }

    {
        const ScopedTestContext fixture_context {"fixture=parsing/vxlan/26_vxlan_udp_declared_bounds_matrix.pcap"};
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/vxlan/26_vxlan_udp_declared_bounds_matrix.pcap")));
        PFL_EXPECT(session.summary().packet_count == 4U);
        PFL_EXPECT(session.unrecognized_packet_count() == 0U);
        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 3U);
        expect_outer_udp_flow(session, rows, "203.0.113.90", 53261U, "203.0.113.91", 4789U, 1U, "EthernetII -> IPv4 -> UDP");

        const auto* merged_inner_tcp = require_flow_by_tuple(
            rows, FlowAddressFamily::ipv4, "TCP", "10.74.0.10", 56040U, "10.74.0.20", 443U);
        PFL_EXPECT(merged_inner_tcp->packet_count == 2U);
        PFL_EXPECT(require_flow_protocol_path_text(session, *merged_inner_tcp) ==
            "EthernetII -> IPv4 -> UDP -> VXLAN(vni=100) -> EthernetII -> IPv4 -> TCP");

        const auto* bounded_inner_tcp = require_flow_by_tuple(
            rows, FlowAddressFamily::ipv4, "TCP", "10.74.0.11", 56041U, "10.74.0.21", 443U);
        PFL_EXPECT(bounded_inner_tcp->packet_count == 1U);
        PFL_EXPECT(require_flow_protocol_path_text(session, *bounded_inner_tcp) ==
            "EthernetII -> IPv4 -> UDP -> VXLAN(vni=100) -> EthernetII -> IPv4 -> TCP");

        const auto bounded_packet_zero = session.read_packet_details(require_packet(session, 0U));
        PFL_REQUIRE(bounded_packet_zero.has_value());
        PFL_EXPECT(bounded_packet_zero->has_vxlan);
        PFL_EXPECT(!bounded_packet_zero->vxlan.header_truncated);
        PFL_EXPECT(bounded_packet_zero->vxlan.vni == 100U);
        PFL_EXPECT(bounded_packet_zero->vxlan.has_inner_packet);
        PFL_REQUIRE(bounded_packet_zero->vxlan.inner_packet != nullptr);
        PFL_EXPECT(bounded_packet_zero->vxlan.inner_packet->has_ipv4);
        PFL_EXPECT(bounded_packet_zero->vxlan.inner_packet->has_tcp);

        const auto exact_header = session.read_packet_details(require_packet(session, 1U));
        PFL_REQUIRE(exact_header.has_value());
        PFL_EXPECT(exact_header->has_vxlan);
        PFL_EXPECT(!exact_header->vxlan.header_truncated);
        PFL_EXPECT(!exact_header->vxlan.has_inner_packet);

        const auto bounded_extra = session.read_packet_details(require_packet(session, 2U));
        PFL_REQUIRE(bounded_extra.has_value());
        PFL_EXPECT(bounded_extra->has_vxlan);
        PFL_EXPECT(bounded_extra->vxlan.has_inner_packet);
        PFL_REQUIRE(bounded_extra->vxlan.inner_packet != nullptr);
        PFL_EXPECT(bounded_extra->vxlan.inner_packet->has_ipv4);
        PFL_EXPECT(bounded_extra->vxlan.inner_packet->has_tcp);

        const auto bounded_packet_three = session.read_packet_details(require_packet(session, 3U));
        PFL_REQUIRE(bounded_packet_three.has_value());
        PFL_EXPECT(bounded_packet_three->has_vxlan);
        PFL_EXPECT(!bounded_packet_three->vxlan.header_truncated);
        PFL_EXPECT(bounded_packet_three->vxlan.has_inner_packet);
    }

    {
        const ScopedTestContext fixture_context {"fixture=parsing/vxlan/27_vxlan_inner_supported_and_visible_matrix.pcap"};
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/vxlan/27_vxlan_inner_supported_and_visible_matrix.pcap")));
        PFL_EXPECT(session.summary().packet_count == 3U);
        PFL_EXPECT(session.unrecognized_packet_count() == 0U);
        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 3U);

        expect_outer_udp_flow(session, rows, "203.0.113.92", 53270U, "203.0.113.93", 4789U, 1U, "EthernetII -> IPv4 -> UDP");

        const auto* inner_qinq = require_flow_by_tuple(
            rows,
            FlowAddressFamily::ipv6,
            "TCP",
            "2001:0db8:0040:0000:0000:0000:0000:0010",
            56050U,
            "2001:0db8:0040:0000:0000:0000:0000:0020",
            443U);
        PFL_EXPECT(require_flow_protocol_path_text(session, *inner_qinq) ==
            "EthernetII -> IPv4 -> UDP -> VXLAN(vni=100) -> EthernetII -> VLAN(vid=551) -> VLAN(vid=552) -> IPv6 -> TCP");

        const auto* inner_llc = require_flow_by_tuple(
            rows, FlowAddressFamily::ipv4, "UDP", "10.75.0.11", 56051U, "10.75.0.21", 69U);
        PFL_EXPECT(require_flow_protocol_path_text(session, *inner_llc) ==
            "EthernetII -> IPv4 -> UDP -> VXLAN(vni=100) -> IEEE 802.3 -> LLC/SNAP -> IPv4 -> UDP");
    }

    {
        const ScopedTestContext fixture_context {"fixture=parsing/vxlan/28_vxlan_unsupported_and_nested_matrix.pcap"};
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/vxlan/28_vxlan_unsupported_and_nested_matrix.pcap")));
        PFL_EXPECT(session.summary().packet_count == 8U);
        PFL_EXPECT(session.unrecognized_packet_count() == 0U);
        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 8U);

        for (const auto src_port : {53280U, 53281U, 53282U, 53283U, 53284U}) {
            expect_outer_udp_flow(session, rows, "203.0.113.94", static_cast<std::uint16_t>(src_port), "203.0.113.95", 4789U, 1U, "EthernetII -> IPv4 -> UDP");
        }

        const auto* nested_vxlan_like = require_flow_by_tuple(
            rows, FlowAddressFamily::ipv4, "UDP", "10.76.0.11", 56061U, "10.76.0.21", 4789U);
        PFL_EXPECT(require_flow_protocol_path_text(session, *nested_vxlan_like) ==
            "EthernetII -> IPv4 -> UDP -> VXLAN(vni=100) -> EthernetII -> IPv4 -> UDP");

        const auto* nested_geneve_like = require_flow_by_tuple(
            rows, FlowAddressFamily::ipv4, "UDP", "10.76.0.12", 56062U, "10.76.0.22", 6081U);
        PFL_EXPECT(require_flow_protocol_path_text(session, *nested_geneve_like) ==
            "EthernetII -> IPv4 -> UDP -> VXLAN(vni=100) -> EthernetII -> IPv4 -> UDP");

        const auto* nested_gtpu_like = require_flow_by_tuple(
            rows, FlowAddressFamily::ipv4, "UDP", "10.76.0.13", 56063U, "10.76.0.23", 2152U);
        PFL_EXPECT(require_flow_protocol_path_text(session, *nested_gtpu_like) ==
            "EthernetII -> IPv4 -> UDP -> VXLAN(vni=100) -> EthernetII -> IPv4 -> UDP");
    }

    {
        const ScopedTestContext fixture_context {"fixture=parsing/vxlan/29_vxlan_capture_truncation_matrix.pcap"};
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/vxlan/29_vxlan_capture_truncation_matrix.pcap")));
        PFL_EXPECT(session.summary().packet_count == 3U);
        PFL_EXPECT(session.unrecognized_packet_count() == 1U);
        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 3U);
        expect_outer_udp_flow(session, rows, "203.0.113.96", 53291U, "203.0.113.97", 4789U, 1U, "EthernetII -> IPv4 -> UDP");
        expect_outer_udp_flow(session, rows, "203.0.113.96", 53292U, "203.0.113.97", 4789U, 1U, "EthernetII -> IPv4 -> UDP");
        expect_outer_udp_flow(session, rows, "203.0.113.96", 53293U, "203.0.113.97", 4789U, 1U, "EthernetII -> IPv4 -> UDP");

        const auto outer_udp_truncated = session.read_packet_details(require_packet(session, 0U));
        PFL_REQUIRE(outer_udp_truncated.has_value());
        PFL_EXPECT(outer_udp_truncated->has_ipv4);
        PFL_EXPECT(!outer_udp_truncated->has_udp);
        PFL_EXPECT(!outer_udp_truncated->has_vxlan);

        const auto header_truncated = session.read_packet_details(require_packet(session, 1U));
        PFL_REQUIRE(header_truncated.has_value());
        PFL_EXPECT(header_truncated->has_vxlan);
        PFL_EXPECT(header_truncated->vxlan.header_truncated);

        const auto ethernet_truncated = session.read_packet_details(require_packet(session, 2U));
        PFL_REQUIRE(ethernet_truncated.has_value());
        PFL_EXPECT(ethernet_truncated->has_vxlan);
        PFL_EXPECT(ethernet_truncated->has_inner_ethernet);
        PFL_EXPECT(ethernet_truncated->inner_ethernet.header_truncated);

        const auto ipv4_truncated = session.read_packet_details(require_packet(session, 3U));
        PFL_REQUIRE(ipv4_truncated.has_value());
        PFL_EXPECT(ipv4_truncated->has_vxlan);
        PFL_EXPECT(ipv4_truncated->vxlan.has_inner_packet);
        PFL_REQUIRE(ipv4_truncated->vxlan.inner_packet != nullptr);
        PFL_EXPECT(ipv4_truncated->vxlan.inner_packet->has_ipv4);
        PFL_EXPECT(ipv4_truncated->vxlan.inner_packet->ipv4.header_truncated);
    }

    {
        const ScopedTestContext fixture_context {"fixture=parsing/vxlan/30_vxlan_vni_byte_order_distinct_values.pcap"};
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/vxlan/30_vxlan_vni_byte_order_distinct_values.pcap")));
        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 2U);
        PFL_EXPECT(session.state().protocol_path_registry.size() == 2U);

        const auto* first = require_flow_by_tuple(
            rows, FlowAddressFamily::ipv4, "TCP", "10.78.0.10", 56080U, "10.78.0.20", 443U);
        PFL_EXPECT(first != nullptr);

        const auto first_details = session.read_packet_details(require_packet(session, 0U));
        PFL_REQUIRE(first_details.has_value());
        PFL_EXPECT(first_details->has_vxlan);
        PFL_EXPECT(first_details->vxlan.vni == 66051U);

        const auto second_details = session.read_packet_details(require_packet(session, 1U));
        PFL_REQUIRE(second_details.has_value());
        PFL_EXPECT(second_details->has_vxlan);
        PFL_EXPECT(second_details->vxlan.vni == 197121U);

        std::set<std::string> observed_paths {};
        for (const auto& row : rows) {
            observed_paths.emplace(require_flow_protocol_path_text(session, row));
        }
        const std::set<std::string> expected_paths {
            "EthernetII -> IPv4 -> UDP -> VXLAN(vni=66051) -> EthernetII -> IPv4 -> TCP",
            "EthernetII -> IPv4 -> UDP -> VXLAN(vni=197121) -> EthernetII -> IPv4 -> TCP",
        };
        PFL_EXPECT(observed_paths == expected_paths);
    }
}

}  // namespace pfl::tests
