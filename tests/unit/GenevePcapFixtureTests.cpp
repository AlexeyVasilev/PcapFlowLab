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

constexpr std::array<std::string_view, 34> kExpectedGeneveFixtureFiles {{
    "01_geneve_inner_ipv4_tcp.pcap",
    "02_geneve_inner_ipv4_udp.pcap",
    "03_geneve_inner_ipv6_tcp.pcap",
    "04_geneve_inner_ipv6_udp.pcap",
    "05_geneve_truncated_base_header.pcap",
    "06_geneve_invalid_version.pcap",
    "07_geneve_options_length_truncated.pcap",
    "08_geneve_truncated_inner_ethernet.pcap",
    "09_geneve_truncated_inner_ipv4.pcap",
    "10_geneve_unsupported_protocol_type.pcap",
    "11_geneve_inner_ipv4_tcp_bidirectional.pcap",
    "12_geneve_same_outer_tuple_different_inner_flows.pcap",
    "13_geneve_inner_vlan_ipv4_tcp.pcap",
    "14_geneve_outer_ipv6_inner_ipv4_tcp.pcap",
    "15_geneve_wrong_udp_port_valid_geneve_payload.pcap",
    "16_geneve_vni_boundary_values.pcap",
    "17_geneve_with_options_inner_ipv4_tcp.pcap",
    "18_geneve_udp_port_direction_matrix.pcap",
    "19_geneve_same_inner_tuple_different_vni.pcap",
    "20_geneve_outer_tagged_contexts.pcap",
    "21_geneve_identity_outer_carrier_variation_same_flow.pcap",
    "22_geneve_identity_outer_and_inner_vlan_splits.pcap",
    "23_geneve_outer_ipv4_fragmentation.pcap",
    "24_geneve_outer_ipv6_fragmentation.pcap",
    "25_geneve_option_and_flag_tolerance_matrix.pcap",
    "26_geneve_inner_supported_and_visible_matrix.pcap",
    "27_geneve_unsupported_and_nested_matrix.pcap",
    "28_geneve_udp_declared_bounds_matrix.pcap",
    "29_geneve_capture_truncation_matrix.pcap",
    "30_geneve_vni_byte_order_distinct_values.pcap",
    "31_geneve_linux_cooked_contexts.pcap",
    "32_geneve_linux_cooked_v2_contexts.pcap",
    "33_geneve_inner_unsupported_ethernet_payloads.pcap",
    "34_geneve_nested_gtpu_no_recursion.pcap",
}};

std::set<std::string> expected_fixture_file_names() {
    std::set<std::string> names {};
    for (const auto file_name : kExpectedGeneveFixtureFiles) {
        names.emplace(file_name);
    }
    return names;
}

std::set<std::string> actual_fixture_file_names() {
    std::set<std::string> names {};
    const auto dir = fixture_path("parsing/geneve");
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

void expect_geneve_fixture_directory_matches_contract() {
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

std::size_t count_layers_with_id(
    const std::vector<session_detail::PacketSummaryLayer>& layers,
    const std::string& id
) {
    std::size_t count = 0U;
    for (const auto& layer : layers) {
        if (layer.id == id) {
            ++count;
        }
        count += count_layers_with_id(layer.children, id);
    }
    return count;
}

void expect_geneve_nested_overlay_non_recursion() {
    {
        const ScopedTestContext fixture_context {"fixture=parsing/geneve/27_geneve_unsupported_and_nested_matrix.pcap"};
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/geneve/27_geneve_unsupported_and_nested_matrix.pcap")));
        PFL_EXPECT(session.summary().packet_count == 4U);
        PFL_EXPECT(session.unrecognized_packet_count() == 0U);
        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 4U);
        PFL_EXPECT(session.state().protocol_path_registry.size() == 2U);

        expect_outer_udp_flow(session, rows, "203.0.113.50", 54270U, "203.0.113.51", 6081U, 1U, "EthernetII -> IPv4 -> UDP");
        expect_outer_udp_flow(session, rows, "203.0.113.50", 54271U, "203.0.113.51", 6081U, 1U, "EthernetII -> IPv4 -> UDP");

        const auto* nested_geneve_like = require_flow_by_tuple(
            rows, FlowAddressFamily::ipv4, "UDP", "10.76.0.12", 56062U, "10.76.0.22", 6081U);
        PFL_EXPECT(require_flow_protocol_path_text(session, *nested_geneve_like) ==
            "EthernetII -> IPv4 -> UDP -> Geneve(vni=100) -> EthernetII -> IPv4 -> UDP");

        const auto* nested_vxlan_like = require_flow_by_tuple(
            rows, FlowAddressFamily::ipv4, "UDP", "10.76.0.13", 56063U, "10.76.0.23", 4789U);
        PFL_EXPECT(require_flow_protocol_path_text(session, *nested_vxlan_like) ==
            "EthernetII -> IPv4 -> UDP -> Geneve(vni=100) -> EthernetII -> IPv4 -> UDP");

        const auto nested_geneve_details = session.read_packet_details(require_packet(session, 2U));
        PFL_REQUIRE(nested_geneve_details.has_value());
        const auto nested_geneve_layers = session_detail::build_packet_summary_layers(*nested_geneve_details, require_packet(session, 2U));
        PFL_EXPECT(count_layers_with_id(nested_geneve_layers, "geneve") == 1U);
        PFL_EXPECT(find_layer(nested_geneve_layers, "vxlan") == nullptr);
        PFL_EXPECT(find_layer(nested_geneve_layers, "gtpu") == nullptr);

        const auto nested_vxlan_details = session.read_packet_details(require_packet(session, 3U));
        PFL_REQUIRE(nested_vxlan_details.has_value());
        const auto nested_vxlan_layers = session_detail::build_packet_summary_layers(*nested_vxlan_details, require_packet(session, 3U));
        PFL_EXPECT(count_layers_with_id(nested_vxlan_layers, "geneve") == 1U);
        PFL_EXPECT(find_layer(nested_vxlan_layers, "vxlan") == nullptr);
        PFL_EXPECT(find_layer(nested_vxlan_layers, "gtpu") == nullptr);
    }

    {
        const ScopedTestContext fixture_context {"fixture=parsing/geneve/34_geneve_nested_gtpu_no_recursion.pcap"};
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/geneve/34_geneve_nested_gtpu_no_recursion.pcap")));
        PFL_EXPECT(session.summary().packet_count == 1U);
        PFL_EXPECT(session.unrecognized_packet_count() == 0U);
        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 1U);
        PFL_EXPECT(session.state().protocol_path_registry.size() == 1U);

        const auto* nested_gtpu_like = require_flow_by_tuple(
            rows, FlowAddressFamily::ipv4, "UDP", "203.0.113.60", 55001U, "203.0.113.61", 2152U);
        PFL_EXPECT(require_flow_protocol_path_text(session, *nested_gtpu_like) ==
            "EthernetII -> IPv4 -> UDP -> Geneve(vni=100) -> EthernetII -> IPv4 -> UDP");

        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->has_geneve);
        PFL_EXPECT(details->geneve.has_inner_packet);
        PFL_REQUIRE(details->geneve.inner_packet != nullptr);
        PFL_EXPECT(details->geneve.inner_packet->has_ipv4);
        PFL_EXPECT(details->geneve.inner_packet->has_udp);

        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet);
        PFL_EXPECT(count_layers_with_id(summary_layers, "geneve") == 1U);
        PFL_EXPECT(find_layer(summary_layers, "vxlan") == nullptr);
        PFL_EXPECT(find_layer(summary_layers, "gtpu") == nullptr);
    }
}

void expect_geneve_udp_declared_bounds_matrix() {
    const ScopedTestContext fixture_context {"fixture=parsing/geneve/28_geneve_udp_declared_bounds_matrix.pcap"};
    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(fixture_path("parsing/geneve/28_geneve_udp_declared_bounds_matrix.pcap")));
    PFL_EXPECT(session.summary().packet_count == 3U);
    PFL_EXPECT(session.unrecognized_packet_count() == 1U);
    const auto rows = session.list_flows();
    PFL_REQUIRE(rows.size() == 3U);

    expect_outer_udp_flow(session, rows, "203.0.113.50", 54280U, "203.0.113.51", 6081U, 1U, "EthernetII -> IPv4 -> UDP");
    expect_outer_udp_flow(session, rows, "203.0.113.50", 54281U, "203.0.113.51", 6081U, 1U, "EthernetII -> IPv4 -> UDP");

    const auto* bounded_inner_tcp = require_flow_by_tuple(
        rows, FlowAddressFamily::ipv4, "TCP", "10.50.0.10", 49550U, "10.50.0.20", 443U);
    PFL_EXPECT(bounded_inner_tcp->packet_count == 1U);
    PFL_EXPECT(require_flow_protocol_path_text(session, *bounded_inner_tcp) ==
        "EthernetII -> IPv4 -> UDP -> Geneve(vni=100) -> EthernetII -> IPv4 -> TCP");

    const auto details0 = session.read_packet_details(require_packet(session, 0U));
    PFL_REQUIRE(details0.has_value());
    PFL_EXPECT(details0->has_geneve);
    PFL_EXPECT(!details0->geneve.header_truncated);
    PFL_EXPECT(!details0->geneve.has_inner_packet);

    const auto details1 = session.read_packet_details(require_packet(session, 1U));
    PFL_REQUIRE(details1.has_value());
    PFL_EXPECT(details1->has_geneve);
    PFL_EXPECT(details1->geneve.options_truncated);

    const auto details2 = session.read_packet_details(require_packet(session, 2U));
    PFL_REQUIRE(details2.has_value());
    PFL_EXPECT(details2->has_ipv4);
    PFL_EXPECT(!details2->has_geneve);

    const auto details3 = session.read_packet_details(require_packet(session, 3U));
    PFL_REQUIRE(details3.has_value());
    PFL_EXPECT(details3->has_geneve);
    PFL_EXPECT(details3->geneve.has_inner_packet);
    PFL_REQUIRE(details3->geneve.inner_packet != nullptr);
    PFL_EXPECT(details3->geneve.inner_packet->has_ipv4);
    PFL_EXPECT(details3->geneve.inner_packet->has_tcp);
}

void expect_geneve_unsupported_inner_ethernet_matrix() {
    struct UnsupportedCase {
        std::uint64_t packet_index;
        std::uint16_t outer_src_port;
        std::uint16_t inner_ether_type;
        bool expect_inner_packet;
    };

    constexpr std::array<UnsupportedCase, 6> cases {{
        {0U, 54330U, 0x0806U, false},
        {1U, 54331U, 0x8864U, true},
        {2U, 54332U, 0x8847U, true},
        {3U, 54333U, 0x88e7U, true},
        {4U, 54334U, 0x88e5U, false},
        {5U, 54335U, 0x1234U, false},
    }};

    const ScopedTestContext fixture_context {"fixture=parsing/geneve/33_geneve_inner_unsupported_ethernet_payloads.pcap"};
    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(fixture_path("parsing/geneve/33_geneve_inner_unsupported_ethernet_payloads.pcap")));
    PFL_EXPECT(session.summary().packet_count == 6U);
    PFL_EXPECT(session.unrecognized_packet_count() == 0U);
    const auto rows = session.list_flows();
    PFL_REQUIRE(rows.size() == 6U);
    PFL_EXPECT(session.state().protocol_path_registry.size() == 1U);

    for (const auto& test_case : cases) {
        expect_outer_udp_flow(
            session,
            rows,
            "203.0.113.50",
            test_case.outer_src_port,
            "203.0.113.51",
            6081U,
            1U,
            "EthernetII -> IPv4 -> UDP"
        );

        const auto packet = require_packet(session, test_case.packet_index);
        const auto details = session.read_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->has_geneve);
        PFL_EXPECT(details->geneve.vni == 100U);
        PFL_EXPECT(details->geneve.has_inner_ethernet);
        PFL_EXPECT(details->has_inner_ethernet);
        PFL_EXPECT(!details->inner_ethernet.header_truncated);
        PFL_EXPECT(details->inner_ethernet.ether_type == test_case.inner_ether_type);
        PFL_EXPECT(details->geneve.has_inner_packet == test_case.expect_inner_packet);

        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet);
        PFL_REQUIRE(find_layer(summary_layers, "geneve") != nullptr);
        PFL_REQUIRE(find_top_level_layer(summary_layers, "ethernet-inner") != nullptr);
        PFL_EXPECT(find_layer(summary_layers, "arp") == nullptr);
        PFL_EXPECT(find_layer(summary_layers, "pppoe") == nullptr);
        PFL_EXPECT(find_layer(summary_layers, "mpls") == nullptr);
        PFL_EXPECT(find_layer(summary_layers, "pbb") == nullptr);
        PFL_EXPECT(find_layer(summary_layers, "macsec") == nullptr);

        if (test_case.expect_inner_packet) {
            PFL_REQUIRE(details->geneve.inner_packet != nullptr);
            PFL_EXPECT(details->geneve.inner_packet->has_ipv4);
            PFL_EXPECT(details->geneve.inner_packet->has_udp);
            PFL_EXPECT(find_top_level_layer(summary_layers, "ipv4-inner") != nullptr);
            PFL_EXPECT(find_top_level_layer(summary_layers, "udp-inner") != nullptr);
        } else {
            PFL_EXPECT(details->geneve.inner_packet == nullptr);
            PFL_EXPECT(find_top_level_layer(summary_layers, "ipv4-inner") == nullptr);
            PFL_EXPECT(find_top_level_layer(summary_layers, "ipv6-inner") == nullptr);
            PFL_EXPECT(find_top_level_layer(summary_layers, "tcp-inner") == nullptr);
            PFL_EXPECT(find_top_level_layer(summary_layers, "udp-inner") == nullptr);
            PFL_EXPECT(find_top_level_layer(summary_layers, "sctp-inner") == nullptr);
        }
    }
}

void expect_geneve_packet_details_present(
    const std::filesystem::path& relative_path,
    const std::uint64_t packet_index,
    const std::uint32_t expected_vni,
    const std::uint8_t expected_option_length_words,
    const std::uint16_t expected_option_length_bytes,
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
    PFL_EXPECT(details->has_geneve);
    PFL_EXPECT(details->geneve.present);
    PFL_EXPECT(details->geneve.version == 0U);
    PFL_EXPECT(details->geneve.option_length_words == expected_option_length_words);
    PFL_EXPECT(details->geneve.option_length_bytes == expected_option_length_bytes);
    PFL_EXPECT(details->geneve.protocol_type == 0x6558U);
    PFL_EXPECT(details->geneve.protocol_type_supported);
    PFL_EXPECT(details->geneve.vni == expected_vni);
    PFL_EXPECT(details->has_inner_ethernet);
    PFL_EXPECT(details->geneve.has_inner_packet);

    const auto summary_layers = session_detail::build_packet_summary_layers(*details, *packet);
    const auto* udp_layer = find_layer(summary_layers, "udp");
    PFL_REQUIRE(udp_layer != nullptr);
    PFL_EXPECT(layer_has_field_containing(*udp_layer, "Destination Port", "6081"));

    const auto* geneve_layer = find_layer(summary_layers, "geneve");
    PFL_REQUIRE(geneve_layer != nullptr);
    PFL_EXPECT(title_contains_all(*geneve_layer, {"Geneve", std::to_string(expected_vni)}));
    PFL_EXPECT(layer_has_field_containing(*geneve_layer, "Version", "0"));
    PFL_EXPECT(layer_has_field_containing(
        *geneve_layer,
        "Option Length",
        std::to_string(static_cast<unsigned>(expected_option_length_words)) + " words (" +
            std::to_string(expected_option_length_bytes) + " bytes)"
    ));
    PFL_EXPECT(layer_has_field_containing(*geneve_layer, "Protocol Type", "Ethernet (0x6558)"));
    PFL_EXPECT(layer_has_field_containing(*geneve_layer, "VNI", std::to_string(expected_vni)));
    PFL_EXPECT(layer_has_field_containing(*geneve_layer, "Inner Payload", "Ethernet"));
    if (expected_option_length_bytes > 0U) {
        PFL_EXPECT(layer_has_field_containing(*geneve_layer, "Options Present", "Yes"));
        PFL_EXPECT(layer_has_field_containing(
            *geneve_layer,
            "Options Skipped",
            std::to_string(expected_option_length_bytes) + " bytes"
        ));
    }
    PFL_EXPECT(geneve_layer->children.empty());

    const auto* inner_ethernet_layer = find_top_level_layer(summary_layers, "ethernet-inner");
    PFL_REQUIRE(inner_ethernet_layer != nullptr);
    PFL_EXPECT(title_contains_all(*inner_ethernet_layer, {
        "Inner",
        "Src:",
        "Dst:",
        "02:00:00:00:51:01",
        "02:00:00:00:51:02",
    }));
    const auto geneve_index = find_top_level_layer_index(summary_layers, "geneve");
    const auto inner_ethernet_index = find_top_level_layer_index(summary_layers, "ethernet-inner");
    const auto inner_network_index = find_top_level_layer_index(summary_layers, expected_inner_network_layer_id);
    const auto inner_transport_index = find_top_level_layer_index(summary_layers, expected_inner_transport_layer_id);
    PFL_REQUIRE(geneve_index < summary_layers.size());
    PFL_REQUIRE(inner_ethernet_index < summary_layers.size());
    PFL_REQUIRE(inner_network_index < summary_layers.size());
    PFL_REQUIRE(inner_transport_index < summary_layers.size());
    PFL_EXPECT(geneve_index < inner_ethernet_index);
    if (expect_inner_vlan) {
        const auto* inner_vlan_layer = find_top_level_layer(summary_layers, "vlan-inner");
        const auto inner_vlan_index = find_top_level_layer_index(summary_layers, "vlan-inner");
        PFL_REQUIRE(inner_vlan_layer != nullptr);
        PFL_REQUIRE(inner_vlan_index < summary_layers.size());
        PFL_EXPECT(title_contains_all(*inner_vlan_layer, {"Inner VLAN", "150"}));
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
    PFL_EXPECT(protocol_text.find("Protocol: Geneve") != std::string::npos);
    PFL_EXPECT(protocol_text.find("Version: 0") != std::string::npos);
    PFL_EXPECT(protocol_text.find(
        "Option Length: " + std::to_string(static_cast<unsigned>(expected_option_length_words)) +
        " words (" + std::to_string(expected_option_length_bytes) + " bytes)"
    ) != std::string::npos);
    PFL_EXPECT(protocol_text.find("Protocol Type: Ethernet (0x6558)") != std::string::npos);
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
        PFL_EXPECT(protocol_text.find("Inner VLAN: 150") != std::string::npos);
    }
}

void expect_geneve_warning_packet_details(
    const std::filesystem::path& relative_path,
    const std::initializer_list<std::string> expected_geneve_title_fragments,
    const std::initializer_list<std::string> expected_protocol_fragments,
    const bool expect_geneve_layer_warning,
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
    PFL_EXPECT(details->has_geneve);

    const auto summary_layers = session_detail::build_packet_summary_layers(*details, *packet);
    const auto* geneve_layer = find_layer(summary_layers, "geneve");
    PFL_REQUIRE(geneve_layer != nullptr);
    PFL_EXPECT(title_contains_all(*geneve_layer, expected_geneve_title_fragments));
    PFL_EXPECT(geneve_layer->warning == expect_geneve_layer_warning);

    const auto* inner_ethernet_layer = find_top_level_layer(summary_layers, "ethernet-inner");
    PFL_EXPECT((inner_ethernet_layer != nullptr) == expect_inner_ethernet);
    if (expect_inner_ethernet && inner_ethernet_layer != nullptr &&
        relative_path == std::filesystem::path("parsing/geneve/08_geneve_truncated_inner_ethernet.pcap")) {
        PFL_EXPECT(inner_ethernet_layer->title.find("truncated") != std::string::npos);
    }
    const auto* inner_ipv4_layer = find_top_level_layer(summary_layers, "ipv4-inner");
    PFL_EXPECT((inner_ipv4_layer != nullptr) == expect_inner_ipv4);
    if (expect_inner_ipv4 && inner_ipv4_layer != nullptr &&
        relative_path == std::filesystem::path("parsing/geneve/09_geneve_truncated_inner_ipv4.pcap")) {
        PFL_EXPECT(inner_ipv4_layer->title.find("truncated") != std::string::npos);
    }
    const auto* inner_udp_layer = find_top_level_layer(summary_layers, "udp-inner");
    PFL_EXPECT((inner_udp_layer != nullptr) == expect_inner_udp);
    const auto* inner_tcp_layer = find_top_level_layer(summary_layers, "tcp-inner");
    PFL_EXPECT((inner_tcp_layer != nullptr) == expect_inner_tcp);

    const auto protocol_text = session.read_packet_protocol_details_text(*packet);
    PFL_EXPECT(protocol_text.find("Protocol: Geneve") != std::string::npos);
    for (const auto& fragment : expected_protocol_fragments) {
        PFL_EXPECT(protocol_text.find(fragment) != std::string::npos);
    }
}

}  // namespace

void run_geneve_pcap_fixture_tests() {
    expect_geneve_fixture_directory_matches_contract();

    expect_inner_flow_present(
        "parsing/geneve/01_geneve_inner_ipv4_tcp.pcap",
        FlowAddressFamily::ipv4,
        "TCP",
        "10.50.0.10",
        49550U,
        "10.50.0.20",
        443U,
        1U
    );

    expect_inner_flow_present(
        "parsing/geneve/02_geneve_inner_ipv4_udp.pcap",
        FlowAddressFamily::ipv4,
        "UDP",
        "10.50.0.10",
        53650U,
        "10.50.0.20",
        443U,
        1U
    );

    expect_inner_flow_present(
        "parsing/geneve/03_geneve_inner_ipv6_tcp.pcap",
        FlowAddressFamily::ipv6,
        "TCP",
        "2001:0db8:0050:0000:0000:0000:0000:0010",
        49550U,
        "2001:0db8:0050:0000:0000:0000:0000:0020",
        443U,
        1U
    );

    expect_inner_flow_present(
        "parsing/geneve/04_geneve_inner_ipv6_udp.pcap",
        FlowAddressFamily::ipv6,
        "UDP",
        "2001:0db8:0050:0000:0000:0000:0000:0010",
        53650U,
        "2001:0db8:0050:0000:0000:0000:0000:0020",
        443U,
        1U
    );

    expect_inner_flow_present(
        "parsing/geneve/11_geneve_inner_ipv4_tcp_bidirectional.pcap",
        FlowAddressFamily::ipv4,
        "TCP",
        "10.50.0.10",
        49550U,
        "10.50.0.20",
        443U,
        2U
    );

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/geneve/12_geneve_same_outer_tuple_different_inner_flows.pcap")));
        const auto rows = session.list_flows();
        const auto* first_flow = find_flow_by_tuple(
            rows,
            FlowAddressFamily::ipv4,
            "TCP",
            "10.50.0.10",
            10011U,
            "10.50.0.20",
            443U
        );
        const auto* second_flow = find_flow_by_tuple(
            rows,
            FlowAddressFamily::ipv4,
            "TCP",
            "10.50.0.10",
            10012U,
            "10.50.0.20",
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
        "parsing/geneve/13_geneve_inner_vlan_ipv4_tcp.pcap",
        FlowAddressFamily::ipv4,
        "TCP",
        "10.50.0.10",
        49550U,
        "10.50.0.20",
        443U,
        1U
    );

    expect_inner_flow_present(
        "parsing/geneve/14_geneve_outer_ipv6_inner_ipv4_tcp.pcap",
        FlowAddressFamily::ipv4,
        "TCP",
        "10.50.0.10",
        49550U,
        "10.50.0.20",
        443U,
        1U
    );

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/geneve/16_geneve_vni_boundary_values.pcap")));
        const auto rows = session.list_flows();
        const auto* first_flow = find_flow_by_tuple(
            rows,
            FlowAddressFamily::ipv4,
            "TCP",
            "10.50.0.10",
            49550U,
            "10.50.0.20",
            443U
        );
        const auto* second_flow = find_flow_by_tuple(
            rows,
            FlowAddressFamily::ipv4,
            "TCP",
            "10.50.0.11",
            10011U,
            "10.50.0.21",
            443U
        );
        PFL_EXPECT(first_flow != nullptr);
        PFL_EXPECT(second_flow != nullptr);
        PFL_EXPECT(session.state().protocol_path_registry.size() == 2U);
    }

    // Geneve option length is encoded in 4-byte units. Fixture 17 carries one
    // deterministic 8-byte option block before the inner Ethernet payload.
    expect_inner_flow_present(
        "parsing/geneve/17_geneve_with_options_inner_ipv4_tcp.pcap",
        FlowAddressFamily::ipv4,
        "TCP",
        "10.50.0.10",
        49550U,
        "10.50.0.20",
        443U,
        1U
    );

    expect_inner_flow_absent(
        "parsing/geneve/05_geneve_truncated_base_header.pcap",
        FlowAddressFamily::ipv4,
        "TCP",
        "10.50.0.10",
        49550U,
        "10.50.0.20",
        443U
    );

    expect_inner_flow_absent(
        "parsing/geneve/06_geneve_invalid_version.pcap",
        FlowAddressFamily::ipv4,
        "UDP",
        "10.50.0.10",
        53650U,
        "10.50.0.20",
        443U
    );

    expect_inner_flow_absent(
        "parsing/geneve/07_geneve_options_length_truncated.pcap",
        FlowAddressFamily::ipv4,
        "TCP",
        "10.50.0.10",
        49550U,
        "10.50.0.20",
        443U
    );

    expect_inner_flow_absent(
        "parsing/geneve/08_geneve_truncated_inner_ethernet.pcap",
        FlowAddressFamily::ipv4,
        "TCP",
        "10.50.0.10",
        49550U,
        "10.50.0.20",
        443U
    );

    expect_inner_flow_absent(
        "parsing/geneve/09_geneve_truncated_inner_ipv4.pcap",
        FlowAddressFamily::ipv4,
        "TCP",
        "10.50.0.10",
        49550U,
        "10.50.0.20",
        443U
    );

    expect_inner_flow_absent(
        "parsing/geneve/10_geneve_unsupported_protocol_type.pcap",
        FlowAddressFamily::ipv4,
        "TCP",
        "10.50.0.10",
        49550U,
        "10.50.0.20",
        443U
    );

    expect_inner_flow_absent(
        "parsing/geneve/15_geneve_wrong_udp_port_valid_geneve_payload.pcap",
        FlowAddressFamily::ipv4,
        "TCP",
        "10.50.0.10",
        49550U,
        "10.50.0.20",
        443U
    );

    expect_geneve_warning_packet_details(
        "parsing/geneve/05_geneve_truncated_base_header.pcap",
        {"Geneve", "malformed"},
        {"Available Header Bytes: 6 / 8", "Warning: Geneve header is truncated."},
        true,
        false,
        false,
        false,
        false
    );

    expect_geneve_warning_packet_details(
        "parsing/geneve/06_geneve_invalid_version.pcap",
        {"Geneve", "invalid"},
        {"Version: 1", "Warning: Geneve version is not supported.", "Inner IPv4: TCP"},
        true,
        true,
        true,
        false,
        true
    );

    expect_geneve_warning_packet_details(
        "parsing/geneve/07_geneve_options_length_truncated.pcap",
        {"Geneve", "malformed"},
        {"Option Length: 2 words (8 bytes)", "Warning: Geneve options are truncated."},
        true,
        false,
        false,
        false,
        false
    );

    expect_geneve_warning_packet_details(
        "parsing/geneve/08_geneve_truncated_inner_ethernet.pcap",
        {"Geneve", "VNI: 100"},
        {"Inner Payload: Ethernet", "Warning: Inner Ethernet header is truncated."},
        true,
        true,
        false,
        false,
        false
    );

    expect_geneve_warning_packet_details(
        "parsing/geneve/09_geneve_truncated_inner_ipv4.pcap",
        {"Geneve", "VNI: 100"},
        {"Inner IPv4:", "Warning: Inner IPv4 packet is truncated."},
        false,
        true,
        true,
        false,
        false
    );

    expect_geneve_warning_packet_details(
        "parsing/geneve/10_geneve_unsupported_protocol_type.pcap",
        {"Geneve", "unsupported protocol type"},
        {"Protocol Type: IPv4 (0x0800)", "Warning: Geneve protocol type is not supported."},
        true,
        false,
        false,
        false,
        false
    );

    expect_geneve_packet_details_present(
        "parsing/geneve/01_geneve_inner_ipv4_tcp.pcap",
        0U,
        100U,
        0U,
        0U,
        "ipv4-inner",
        "tcp-inner",
        "10.50.0.10",
        "10.50.0.20",
        "49550",
        "443"
    );

    expect_geneve_packet_details_present(
        "parsing/geneve/02_geneve_inner_ipv4_udp.pcap",
        0U,
        100U,
        0U,
        0U,
        "ipv4-inner",
        "udp-inner",
        "10.50.0.10",
        "10.50.0.20",
        "53650",
        "443"
    );

    expect_geneve_packet_details_present(
        "parsing/geneve/03_geneve_inner_ipv6_tcp.pcap",
        0U,
        100U,
        0U,
        0U,
        "ipv6-inner",
        "tcp-inner",
        "2001:0db8:0050:0000:0000:0000:0000:0010",
        "2001:0db8:0050:0000:0000:0000:0000:0020",
        "49550",
        "443"
    );

    expect_geneve_packet_details_present(
        "parsing/geneve/04_geneve_inner_ipv6_udp.pcap",
        0U,
        100U,
        0U,
        0U,
        "ipv6-inner",
        "udp-inner",
        "2001:0db8:0050:0000:0000:0000:0000:0010",
        "2001:0db8:0050:0000:0000:0000:0000:0020",
        "53650",
        "443"
    );

    expect_geneve_packet_details_present(
        "parsing/geneve/13_geneve_inner_vlan_ipv4_tcp.pcap",
        0U,
        100U,
        0U,
        0U,
        "ipv4-inner",
        "tcp-inner",
        "10.50.0.10",
        "10.50.0.20",
        "49550",
        "443",
        true
    );

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/geneve/16_geneve_vni_boundary_values.pcap")));

        const auto first_packet = session.find_packet(0U);
        PFL_REQUIRE(first_packet.has_value());
        const auto first_details = session.read_packet_details(*first_packet);
        PFL_REQUIRE(first_details.has_value());
        PFL_EXPECT(first_details->has_geneve);
        PFL_EXPECT(first_details->geneve.vni == 0U);
        const auto first_layers = session_detail::build_packet_summary_layers(*first_details, *first_packet);
        const auto* first_geneve_layer = find_layer(first_layers, "geneve");
        PFL_REQUIRE(first_geneve_layer != nullptr);
        PFL_EXPECT(title_contains_all(*first_geneve_layer, {"Geneve", "0"}));

        const auto second_packet = session.find_packet(1U);
        PFL_REQUIRE(second_packet.has_value());
        const auto second_details = session.read_packet_details(*second_packet);
        PFL_REQUIRE(second_details.has_value());
        PFL_EXPECT(second_details->has_geneve);
        PFL_EXPECT(second_details->geneve.vni == 16777215U);
        const auto second_layers = session_detail::build_packet_summary_layers(*second_details, *second_packet);
        const auto* second_geneve_layer = find_layer(second_layers, "geneve");
        PFL_REQUIRE(second_geneve_layer != nullptr);
        PFL_EXPECT(title_contains_all(*second_geneve_layer, {"Geneve", "16777215"}));
    }

    expect_geneve_packet_details_present(
        "parsing/geneve/17_geneve_with_options_inner_ipv4_tcp.pcap",
        0U,
        100U,
        2U,
        8U,
        "ipv4-inner",
        "tcp-inner",
        "10.50.0.10",
        "10.50.0.20",
        "49550",
        "443"
    );

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/geneve/15_geneve_wrong_udp_port_valid_geneve_payload.pcap")));
        const auto packet = session.find_packet(0U);
        PFL_REQUIRE(packet.has_value());
        const auto details = session.read_packet_details(*packet);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(!details->has_geneve);
        const auto summary_layers = session_detail::build_packet_summary_layers(*details, *packet);
        PFL_EXPECT(find_layer(summary_layers, "geneve") == nullptr);
        const auto protocol_text = session.read_packet_protocol_details_text(*packet);
        PFL_EXPECT(protocol_text.find("Geneve") == std::string::npos);
    }

    {
        const ScopedTestContext fixture_context {"fixture=parsing/geneve/18_geneve_udp_port_direction_matrix.pcap"};
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/geneve/18_geneve_udp_port_direction_matrix.pcap")));
        PFL_EXPECT(session.summary().packet_count == 3U);
        PFL_EXPECT(session.unrecognized_packet_count() == 0U);
        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 3U);

        const auto* inner_tcp = require_flow_by_tuple(
            rows, FlowAddressFamily::ipv4, "TCP", "10.50.0.10", 49550U, "10.50.0.20", 443U);
        PFL_EXPECT(inner_tcp->packet_count == 1U);
        PFL_EXPECT(require_flow_protocol_path_text(session, *inner_tcp) ==
            "EthernetII -> IPv4 -> UDP -> Geneve(vni=100) -> EthernetII -> IPv4 -> TCP");

        expect_outer_udp_flow(
            session, rows, "203.0.113.50", 6081U, "203.0.113.51", 6091U, 1U, "EthernetII -> IPv4 -> UDP");

        const auto* inner_udp = require_flow_by_tuple(
            rows, FlowAddressFamily::ipv4, "UDP", "10.50.0.11", 53650U, "10.50.0.21", 443U);
        PFL_EXPECT(inner_udp->packet_count == 1U);
        PFL_EXPECT(require_flow_protocol_path_text(session, *inner_udp) ==
            "EthernetII -> IPv4 -> UDP -> Geneve(vni=101) -> EthernetII -> IPv4 -> UDP");

        const auto details0 = session.read_packet_details(require_packet(session, 0U));
        PFL_REQUIRE(details0.has_value());
        PFL_EXPECT(details0->has_geneve);
        PFL_EXPECT(details0->geneve.vni == 100U);

        const auto details1 = session.read_packet_details(require_packet(session, 1U));
        PFL_REQUIRE(details1.has_value());
        PFL_EXPECT(!details1->has_geneve);

        const auto details2 = session.read_packet_details(require_packet(session, 2U));
        PFL_REQUIRE(details2.has_value());
        PFL_EXPECT(details2->has_geneve);
        PFL_EXPECT(details2->geneve.vni == 101U);
    }

    {
        const ScopedTestContext fixture_context {"fixture=parsing/geneve/19_geneve_same_inner_tuple_different_vni.pcap"};
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/geneve/19_geneve_same_inner_tuple_different_vni.pcap")));
        PFL_EXPECT(session.summary().packet_count == 2U);
        PFL_EXPECT(session.unrecognized_packet_count() == 0U);
        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 2U);
        PFL_EXPECT(session.state().protocol_path_registry.size() == 2U);
        PFL_EXPECT(std::all_of(rows.begin(), rows.end(), [](const FlowRow& row) {
            return row.family == FlowAddressFamily::ipv4 &&
                row.protocol_text == "TCP" &&
                row.address_a == "10.50.0.10" &&
                row.port_a == 49550U &&
                row.address_b == "10.50.0.20" &&
                row.port_b == 443U &&
                row.packet_count == 1U;
        }));

        std::set<std::string> observed_paths {};
        for (const auto& row : rows) {
            observed_paths.emplace(require_flow_protocol_path_text(session, row));
        }
        const std::set<std::string> expected_paths {
            "EthernetII -> IPv4 -> UDP -> Geneve(vni=100) -> EthernetII -> IPv4 -> TCP",
            "EthernetII -> IPv4 -> UDP -> Geneve(vni=200) -> EthernetII -> IPv4 -> TCP",
        };
        PFL_EXPECT(observed_paths == expected_paths);

        const auto first_details = session.read_packet_details(require_packet(session, 0U));
        PFL_REQUIRE(first_details.has_value());
        PFL_EXPECT(first_details->has_geneve);
        PFL_EXPECT(first_details->geneve.vni == 100U);

        const auto second_details = session.read_packet_details(require_packet(session, 1U));
        PFL_REQUIRE(second_details.has_value());
        PFL_EXPECT(second_details->has_geneve);
        PFL_EXPECT(second_details->geneve.vni == 200U);
    }

    {
        const ScopedTestContext fixture_context {"fixture=parsing/geneve/20_geneve_outer_tagged_contexts.pcap"};
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/geneve/20_geneve_outer_tagged_contexts.pcap")));
        PFL_EXPECT(session.summary().packet_count == 3U);
        PFL_EXPECT(session.unrecognized_packet_count() == 0U);
        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 3U);

        const auto* outer_vlan_tcp = require_flow_by_tuple(
            rows, FlowAddressFamily::ipv4, "TCP", "10.50.0.10", 49550U, "10.50.0.20", 443U);
        PFL_EXPECT(require_flow_protocol_path_text(session, *outer_vlan_tcp) ==
            "EthernetII -> VLAN(vid=297) -> IPv4 -> UDP -> Geneve(vni=100) -> EthernetII -> IPv4 -> TCP");

        const auto* outer_qinq_udp = require_flow_by_tuple(
            rows,
            FlowAddressFamily::ipv6,
            "UDP",
            "2001:0db8:0050:0000:0000:0000:0000:0010",
            53650U,
            "2001:0db8:0050:0000:0000:0000:0000:0020",
            443U);
        PFL_EXPECT(require_flow_protocol_path_text(session, *outer_qinq_udp) ==
            "EthernetII -> VLAN(vid=551) -> VLAN(vid=552) -> IPv4 -> UDP -> Geneve(vni=100) -> EthernetII -> IPv6 -> UDP");

        const auto* outer_legacy_vlan_udp = require_flow_by_tuple(
            rows, FlowAddressFamily::ipv4, "UDP", "10.50.0.10", 53651U, "10.50.0.20", 53U);
        PFL_EXPECT(require_flow_protocol_path_text(session, *outer_legacy_vlan_udp) ==
            "EthernetII -> VLAN(vid=413) -> IPv4 -> UDP -> Geneve(vni=100) -> EthernetII -> IPv4 -> UDP");
    }

    {
        const ScopedTestContext fixture_context {"fixture=parsing/geneve/21_geneve_identity_outer_carrier_variation_same_flow.pcap"};
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/geneve/21_geneve_identity_outer_carrier_variation_same_flow.pcap")));
        PFL_EXPECT(session.summary().packet_count == 2U);
        PFL_EXPECT(session.unrecognized_packet_count() == 0U);
        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 1U);
        PFL_EXPECT(session.state().protocol_path_registry.size() == 1U);
        const auto* row = require_flow_by_tuple(
            rows, FlowAddressFamily::ipv4, "TCP", "10.50.0.10", 49550U, "10.50.0.20", 443U);
        PFL_EXPECT(row->packet_count == 2U);
        PFL_EXPECT(require_flow_protocol_path_text(session, *row) ==
            "EthernetII -> IPv4 -> UDP -> Geneve(vni=100) -> EthernetII -> IPv4 -> TCP");
    }

    {
        const ScopedTestContext fixture_context {"fixture=parsing/geneve/22_geneve_identity_outer_and_inner_vlan_splits.pcap"};
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/geneve/22_geneve_identity_outer_and_inner_vlan_splits.pcap")));
        PFL_EXPECT(session.summary().packet_count == 3U);
        PFL_EXPECT(session.unrecognized_packet_count() == 0U);
        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 3U);
        PFL_EXPECT(session.state().protocol_path_registry.size() == 3U);
        PFL_EXPECT(std::all_of(rows.begin(), rows.end(), [](const FlowRow& row) {
            return row.packet_count == 1U;
        }));

        std::set<std::string> observed_paths {};
        for (const auto& row : rows) {
            observed_paths.emplace(require_flow_protocol_path_text(session, row));
        }
        const std::set<std::string> expected_paths {
            "EthernetII -> IPv4 -> UDP -> Geneve(vni=100) -> EthernetII -> IPv4 -> TCP",
            "EthernetII -> VLAN(vid=201) -> IPv4 -> UDP -> Geneve(vni=100) -> EthernetII -> IPv4 -> TCP",
            "EthernetII -> IPv4 -> UDP -> Geneve(vni=100) -> EthernetII -> VLAN(vid=150) -> IPv4 -> TCP",
        };
        PFL_EXPECT(observed_paths == expected_paths);
    }

    {
        const ScopedTestContext fixture_context {"fixture=parsing/geneve/23_geneve_outer_ipv4_fragmentation.pcap"};
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/geneve/23_geneve_outer_ipv4_fragmentation.pcap")));
        PFL_EXPECT(session.summary().packet_count == 3U);
        PFL_EXPECT(session.unrecognized_packet_count() == 0U);
        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 1U);
        PFL_EXPECT(rows[0].packet_count == 3U);
        PFL_EXPECT(rows[0].has_fragmented_packets);
        PFL_EXPECT(require_flow_protocol_path_text(session, rows[0]) == "EthernetII -> IPv4");
        const auto details = session.read_packet_details(require_packet(session, 0U));
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->has_ipv4);
        PFL_EXPECT(!details->has_udp);
        PFL_EXPECT(!details->has_geneve);
    }

    {
        const ScopedTestContext fixture_context {"fixture=parsing/geneve/24_geneve_outer_ipv6_fragmentation.pcap"};
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/geneve/24_geneve_outer_ipv6_fragmentation.pcap")));
        PFL_EXPECT(session.summary().packet_count == 3U);
        PFL_EXPECT(session.unrecognized_packet_count() == 0U);
        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 1U);
        PFL_EXPECT(rows[0].packet_count == 3U);
        PFL_EXPECT(rows[0].has_fragmented_packets);
        PFL_EXPECT(require_flow_protocol_path_text(session, rows[0]) == "EthernetII -> IPv6");
        const auto details = session.read_packet_details(require_packet(session, 0U));
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->has_ipv6);
        PFL_EXPECT(!details->has_udp);
        PFL_EXPECT(!details->has_geneve);
    }

    {
        const ScopedTestContext fixture_context {"fixture=parsing/geneve/25_geneve_option_and_flag_tolerance_matrix.pcap"};
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/geneve/25_geneve_option_and_flag_tolerance_matrix.pcap")));
        PFL_EXPECT(session.summary().packet_count == 5U);
        PFL_EXPECT(session.unrecognized_packet_count() == 0U);
        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 1U);
        PFL_EXPECT(session.state().protocol_path_registry.size() == 1U);
        const auto* row = require_flow_by_tuple(
            rows, FlowAddressFamily::ipv4, "TCP", "10.50.0.10", 49550U, "10.50.0.20", 443U);
        PFL_EXPECT(row->packet_count == 5U);
        PFL_EXPECT(require_flow_protocol_path_text(session, *row) ==
            "EthernetII -> IPv4 -> UDP -> Geneve(vni=100) -> EthernetII -> IPv4 -> TCP");

        const auto details0 = session.read_packet_details(require_packet(session, 0U));
        PFL_REQUIRE(details0.has_value());
        PFL_EXPECT(details0->has_geneve);
        PFL_EXPECT(!details0->geneve.oam_flag);
        PFL_EXPECT(!details0->geneve.critical_flag);
        PFL_EXPECT(details0->geneve.option_length_words == 0U);

        const auto details1 = session.read_packet_details(require_packet(session, 1U));
        PFL_REQUIRE(details1.has_value());
        PFL_EXPECT(details1->has_geneve);
        PFL_EXPECT(details1->geneve.oam_flag);

        const auto details2 = session.read_packet_details(require_packet(session, 2U));
        PFL_REQUIRE(details2.has_value());
        PFL_EXPECT(details2->has_geneve);
        PFL_EXPECT(details2->geneve.critical_flag);

        const auto details3 = session.read_packet_details(require_packet(session, 3U));
        PFL_REQUIRE(details3.has_value());
        PFL_EXPECT(details3->has_geneve);
        PFL_EXPECT(details3->geneve.protocol_type_supported);

        const auto details4 = session.read_packet_details(require_packet(session, 4U));
        PFL_REQUIRE(details4.has_value());
        PFL_EXPECT(details4->has_geneve);
        PFL_EXPECT(details4->geneve.option_length_words == 2U);
        PFL_EXPECT(details4->geneve.option_length_bytes == 8U);
    }

    {
        const ScopedTestContext fixture_context {"fixture=parsing/geneve/26_geneve_inner_supported_and_visible_matrix.pcap"};
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/geneve/26_geneve_inner_supported_and_visible_matrix.pcap")));
        PFL_EXPECT(session.summary().packet_count == 3U);
        PFL_EXPECT(session.unrecognized_packet_count() == 0U);
        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 3U);

        const auto* inner_vlan = require_flow_by_tuple(
            rows, FlowAddressFamily::ipv4, "TCP", "10.50.0.10", 49550U, "10.50.0.20", 443U);
        PFL_EXPECT(require_flow_protocol_path_text(session, *inner_vlan) ==
            "EthernetII -> IPv4 -> UDP -> Geneve(vni=100) -> EthernetII -> VLAN(vid=150) -> IPv4 -> TCP");

        const auto* inner_llc_ipv4 = require_flow_by_tuple(
            rows, FlowAddressFamily::ipv4, "UDP", "10.75.0.11", 56051U, "10.75.0.21", 69U);
        PFL_EXPECT(require_flow_protocol_path_text(session, *inner_llc_ipv4) ==
            "EthernetII -> IPv4 -> UDP -> Geneve(vni=100) -> IEEE 802.3 -> LLC/SNAP -> IPv4 -> UDP");

        const auto* inner_llc_ipv6 = require_flow_by_tuple(
            rows,
            FlowAddressFamily::ipv6,
            "TCP",
            "2001:0db8:0075:0000:0000:0000:0000:0011",
            56052U,
            "2001:0db8:0075:0000:0000:0000:0000:0021",
            443U);
        PFL_EXPECT(require_flow_protocol_path_text(session, *inner_llc_ipv6) ==
            "EthernetII -> IPv4 -> UDP -> Geneve(vni=100) -> IEEE 802.3 -> LLC/SNAP -> IPv6 -> TCP");
    }

    expect_geneve_nested_overlay_non_recursion();
    expect_geneve_udp_declared_bounds_matrix();

    {
        const ScopedTestContext fixture_context {"fixture=parsing/geneve/29_geneve_capture_truncation_matrix.pcap"};
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/geneve/29_geneve_capture_truncation_matrix.pcap")));
        PFL_EXPECT(session.summary().packet_count == 4U);
        PFL_EXPECT(session.unrecognized_packet_count() == 0U);
        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 4U);
        expect_outer_udp_flow(session, rows, "203.0.113.50", 54290U, "203.0.113.51", 6081U, 1U, "EthernetII -> IPv4 -> UDP");
        expect_outer_udp_flow(session, rows, "203.0.113.50", 54291U, "203.0.113.51", 6081U, 1U, "EthernetII -> IPv4 -> UDP");
        expect_outer_udp_flow(session, rows, "203.0.113.50", 54292U, "203.0.113.51", 6081U, 1U, "EthernetII -> IPv4 -> UDP");
        expect_outer_udp_flow(session, rows, "203.0.113.50", 54293U, "203.0.113.51", 6081U, 1U, "EthernetII -> IPv4 -> UDP");

        const auto header_truncated = session.read_packet_details(require_packet(session, 0U));
        PFL_REQUIRE(header_truncated.has_value());
        PFL_EXPECT(header_truncated->has_geneve);
        PFL_EXPECT(header_truncated->geneve.header_truncated);

        const auto options_truncated = session.read_packet_details(require_packet(session, 1U));
        PFL_REQUIRE(options_truncated.has_value());
        PFL_EXPECT(options_truncated->has_geneve);
        PFL_EXPECT(options_truncated->geneve.options_truncated);

        const auto ethernet_truncated = session.read_packet_details(require_packet(session, 2U));
        PFL_REQUIRE(ethernet_truncated.has_value());
        PFL_EXPECT(ethernet_truncated->has_geneve);
        PFL_EXPECT(ethernet_truncated->has_inner_ethernet);
        PFL_EXPECT(ethernet_truncated->inner_ethernet.header_truncated);

        const auto ipv4_truncated = session.read_packet_details(require_packet(session, 3U));
        PFL_REQUIRE(ipv4_truncated.has_value());
        PFL_EXPECT(ipv4_truncated->has_geneve);
        PFL_EXPECT(ipv4_truncated->geneve.has_inner_packet);
        PFL_REQUIRE(ipv4_truncated->geneve.inner_packet != nullptr);
        PFL_EXPECT(ipv4_truncated->geneve.inner_packet->has_ipv4);
        PFL_EXPECT(ipv4_truncated->geneve.inner_packet->ipv4.header_truncated);
    }

    {
        const ScopedTestContext fixture_context {"fixture=parsing/geneve/30_geneve_vni_byte_order_distinct_values.pcap"};
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/geneve/30_geneve_vni_byte_order_distinct_values.pcap")));
        PFL_EXPECT(session.summary().packet_count == 2U);
        PFL_EXPECT(session.unrecognized_packet_count() == 0U);
        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 2U);
        PFL_EXPECT(session.state().protocol_path_registry.size() == 2U);

        const auto first_details = session.read_packet_details(require_packet(session, 0U));
        PFL_REQUIRE(first_details.has_value());
        PFL_EXPECT(first_details->has_geneve);
        PFL_EXPECT(first_details->geneve.vni == 66051U);

        const auto second_details = session.read_packet_details(require_packet(session, 1U));
        PFL_REQUIRE(second_details.has_value());
        PFL_EXPECT(second_details->has_geneve);
        PFL_EXPECT(second_details->geneve.vni == 197121U);

        std::set<std::string> observed_paths {};
        for (const auto& row : rows) {
            observed_paths.emplace(require_flow_protocol_path_text(session, row));
        }
        const std::set<std::string> expected_paths {
            "EthernetII -> IPv4 -> UDP -> Geneve(vni=66051) -> EthernetII -> IPv4 -> TCP",
            "EthernetII -> IPv4 -> UDP -> Geneve(vni=197121) -> EthernetII -> IPv4 -> TCP",
        };
        PFL_EXPECT(observed_paths == expected_paths);
    }

    {
        const ScopedTestContext fixture_context {"fixture=parsing/geneve/31_geneve_linux_cooked_contexts.pcap"};
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/geneve/31_geneve_linux_cooked_contexts.pcap")));
        PFL_EXPECT(session.summary().packet_count == 1U);
        PFL_EXPECT(session.unrecognized_packet_count() == 0U);
        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 1U);
        const auto* row = require_flow_by_tuple(
            rows, FlowAddressFamily::ipv4, "UDP", "10.50.0.10", 53660U, "10.50.0.20", 443U);
        PFL_EXPECT(require_flow_protocol_path_text(session, *row) ==
            "LinuxSll -> IPv4 -> UDP -> Geneve(vni=100) -> EthernetII -> IPv4 -> UDP");
    }

    {
        const ScopedTestContext fixture_context {"fixture=parsing/geneve/32_geneve_linux_cooked_v2_contexts.pcap"};
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/geneve/32_geneve_linux_cooked_v2_contexts.pcap")));
        PFL_EXPECT(session.summary().packet_count == 1U);
        PFL_EXPECT(session.unrecognized_packet_count() == 0U);
        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 1U);
        const auto* row = require_flow_by_tuple(
            rows,
            FlowAddressFamily::ipv6,
            "TCP",
            "2001:0db8:0050:0000:0000:0000:0000:0010",
            53661U,
            "2001:0db8:0050:0000:0000:0000:0000:0020",
            443U);
        PFL_EXPECT(require_flow_protocol_path_text(session, *row) ==
            "LinuxSll2 -> IPv6 -> UDP -> Geneve(vni=100) -> EthernetII -> IPv6 -> TCP");
    }

    expect_geneve_unsupported_inner_ethernet_matrix();
}

}  // namespace pfl::tests
