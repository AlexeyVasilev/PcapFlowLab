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
        // Known branch limitation: VNI remains presentation metadata, not flow identity.
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
}

}  // namespace pfl::tests
