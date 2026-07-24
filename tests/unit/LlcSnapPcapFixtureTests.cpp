#include <array>
#include <algorithm>
#include <filesystem>
#include <initializer_list>
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

PacketRef require_packet(CaptureSession& session, const std::uint64_t packet_index) {
    const auto packet = session.find_packet(packet_index);
    PFL_REQUIRE(packet.has_value());
    return *packet;
}

const session_detail::PacketSummaryLayer* find_layer(
    const std::vector<session_detail::PacketSummaryLayer>& layers,
    const std::string& id,
    const std::size_t occurrence = 0U
) {
    std::size_t seen = 0U;
    for (const auto& layer : layers) {
        if (layer.id != id) {
            continue;
        }
        if (seen == occurrence) {
            return &layer;
        }
        ++seen;
    }
    return nullptr;
}

bool layer_has_field_containing(
    const session_detail::PacketSummaryLayer& layer,
    const std::string& label,
    const std::string& expected_fragment
) {
    return std::any_of(layer.fields.begin(), layer.fields.end(), [&](const session_detail::PacketSummaryField& field) {
        return field.label == label && field.value.find(expected_fragment) != std::string::npos;
    });
}

bool layer_has_field(
    const session_detail::PacketSummaryLayer& layer,
    const std::string& label
) {
    return std::any_of(layer.fields.begin(), layer.fields.end(), [&](const session_detail::PacketSummaryField& field) {
        return field.label == label;
    });
}

void expect_layer_prefix(
    const std::vector<session_detail::PacketSummaryLayer>& layers,
    std::initializer_list<const char*> expected_ids
) {
    PFL_EXPECT(layers.size() >= expected_ids.size());
    if (layers.size() < expected_ids.size()) {
        return;
    }
    std::size_t search_index = 0U;
    for (const auto* expected_id : expected_ids) {
        const auto found = std::find_if(
            layers.begin() + static_cast<std::ptrdiff_t>(search_index),
            layers.end(),
            [&](const session_detail::PacketSummaryLayer& layer) {
                return layer.id == expected_id;
            }
        );
        PFL_EXPECT(found != layers.end());
        if (found == layers.end()) {
            return;
        }
        search_index = static_cast<std::size_t>(std::distance(layers.begin(), found)) + 1U;
    }
}

std::string require_flow_protocol_path_text(const CaptureSession& session, const FlowRow& row) {
    PFL_REQUIRE(row.protocol_path_id != kInvalidProtocolPathId);
    const auto* path = session.state().protocol_path_registry.find(row.protocol_path_id);
    PFL_REQUIRE(path != nullptr);
    return format_protocol_path(*path);
}

void expect_single_supported_flow(
    CaptureSession& session,
    const std::filesystem::path& relative_path,
    const FlowAddressFamily expected_family,
    const std::string& expected_protocol
) {
    PFL_EXPECT(session.open_capture(fixture_path(relative_path)));
    const auto rows = session.list_flows();
    PFL_REQUIRE(rows.size() == 1U);
    PFL_EXPECT(rows[0].family == expected_family);
    PFL_EXPECT(rows[0].protocol_text == expected_protocol);
    PFL_EXPECT(rows[0].packet_count == 1U);
    PFL_EXPECT(session.unrecognized_packet_count() == 0U);
}

void expect_supported_llc_snap_ip_fixture(
    const std::filesystem::path& relative_path,
    const FlowAddressFamily expected_family,
    const std::string& expected_protocol,
    const std::string& expected_address_a,
    const std::uint16_t expected_port_a,
    const std::string& expected_address_b,
    const std::uint16_t expected_port_b,
    const std::size_t expected_vlan_count,
    const std::string& expected_inner_layer,
    const std::string& expected_protocol_path,
    const std::uint32_t expected_transport_payload_length = 17U
) {
    CaptureSession session {};
    expect_single_supported_flow(
        session,
        relative_path,
        expected_family,
        expected_protocol
    );

    const auto flow_rows = session.list_flows();
    PFL_REQUIRE(flow_rows.size() == 1U);
    PFL_EXPECT(require_flow_protocol_path_text(session, flow_rows[0]) == expected_protocol_path);

    const auto packet_rows = session.list_flow_packets(0U);
    PFL_REQUIRE(packet_rows.size() == 1U);
    PFL_EXPECT(packet_rows[0].payload_length == expected_transport_payload_length);

    const auto packet = require_packet(session, 0U);
    const auto details = session.read_packet_details(packet);
    PFL_REQUIRE(details.has_value());
    PFL_EXPECT(details->has_ethernet);
    PFL_EXPECT(details->ethernet.uses_length_field == (expected_vlan_count == 0U));
    PFL_EXPECT(details->has_llc);
    PFL_EXPECT(details->has_snap);
    const auto expected_oui = std::array<std::uint8_t, 3> {0U, 0U, 0U};
    PFL_EXPECT(details->snap.oui == expected_oui);
    PFL_EXPECT(details->has_vlan == (expected_vlan_count > 0U));
    PFL_EXPECT(details->vlan_tags.size() == expected_vlan_count);

    if (expected_inner_layer == "ipv4") {
        PFL_EXPECT(details->has_ipv4);
        PFL_EXPECT(!details->has_ipv6);
        PFL_EXPECT(session_detail::format_ipv4_address(details->ipv4.src_addr) == expected_address_a);
        PFL_EXPECT(session_detail::format_ipv4_address(details->ipv4.dst_addr) == expected_address_b);
    } else {
        PFL_EXPECT(details->has_ipv6);
        PFL_EXPECT(!details->has_ipv4);
        PFL_EXPECT(session_detail::format_ipv6_address(details->ipv6.src_addr) == expected_address_a);
        PFL_EXPECT(session_detail::format_ipv6_address(details->ipv6.dst_addr) == expected_address_b);
    }

    if (expected_protocol == "TCP") {
        PFL_EXPECT(details->has_tcp);
        PFL_EXPECT(!details->has_udp);
        PFL_EXPECT(details->tcp.src_port == expected_port_a);
        PFL_EXPECT(details->tcp.dst_port == expected_port_b);
    } else {
        PFL_EXPECT(details->has_udp);
        PFL_EXPECT(!details->has_tcp);
        PFL_EXPECT(details->udp.src_port == expected_port_a);
        PFL_EXPECT(details->udp.dst_port == expected_port_b);
    }

    const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet);
    if (expected_vlan_count == 0U) {
        expect_layer_prefix(summary_layers, {"frame", "ethernet", "llc", "snap", expected_inner_layer.c_str(), expected_protocol == "TCP" ? "tcp" : "udp"});
    } else if (expected_vlan_count == 1U) {
        expect_layer_prefix(summary_layers, {"frame", "ethernet", "vlan", "llc", "snap", expected_inner_layer.c_str(), expected_protocol == "TCP" ? "tcp" : "udp"});
    } else {
        expect_layer_prefix(summary_layers, {"frame", "ethernet", "vlan", "vlan", "llc", "snap", expected_inner_layer.c_str(), expected_protocol == "TCP" ? "tcp" : "udp"});
    }

    const auto* ethernet_layer = find_layer(summary_layers, "ethernet");
    PFL_REQUIRE(ethernet_layer != nullptr);
    if (expected_vlan_count == 0U) {
        PFL_EXPECT(layer_has_field_containing(*ethernet_layer, "Length", "bytes"));
    } else {
        PFL_EXPECT(layer_has_field(*ethernet_layer, "Type"));
    }
    if (expected_vlan_count == 1U) {
        const auto* vlan_layer = find_layer(summary_layers, "vlan", 0U);
        PFL_REQUIRE(vlan_layer != nullptr);
        PFL_EXPECT(!layer_has_field(*vlan_layer, "Tag Control Information"));
        PFL_EXPECT(layer_has_field_containing(*vlan_layer, "Encapsulated Length", "65 bytes"));
        PFL_EXPECT(!layer_has_field(*vlan_layer, "Encapsulated EtherType"));
    } else if (expected_vlan_count == 2U) {
        const auto* outer_vlan_layer = find_layer(summary_layers, "vlan", 0U);
        const auto* inner_vlan_layer = find_layer(summary_layers, "vlan", 1U);
        PFL_REQUIRE(outer_vlan_layer != nullptr);
        PFL_REQUIRE(inner_vlan_layer != nullptr);
        PFL_EXPECT(!layer_has_field(*outer_vlan_layer, "Tag Control Information"));
        PFL_EXPECT(!layer_has_field(*inner_vlan_layer, "Tag Control Information"));
        PFL_EXPECT(layer_has_field_containing(*outer_vlan_layer, "Encapsulated EtherType", "802.1Q VLAN"));
        PFL_EXPECT(layer_has_field_containing(*inner_vlan_layer, "Encapsulated Length", "53 bytes"));
        PFL_EXPECT(!layer_has_field(*inner_vlan_layer, "Encapsulated EtherType"));
    }
    const auto* llc_layer = find_layer(summary_layers, "llc");
    PFL_REQUIRE(llc_layer != nullptr);
    PFL_EXPECT(layer_has_field_containing(*llc_layer, "DSAP", "0xaa"));
    PFL_EXPECT(!layer_has_field(*llc_layer, "Payload Length"));
    const auto* snap_layer = find_layer(summary_layers, "snap");
    PFL_REQUIRE(snap_layer != nullptr);
    PFL_EXPECT(layer_has_field_containing(*snap_layer, "OUI", "00:00:00"));
    PFL_EXPECT(find_layer(summary_layers, "trailer") == nullptr);
}

void expect_supported_llc_snap_arp_fixture(
    const std::filesystem::path& relative_path,
    const std::string& expected_protocol_path
) {
    CaptureSession session {};
    PFL_EXPECT(session.open_capture(fixture_path(relative_path)));
    PFL_EXPECT(session.summary().flow_count == 1U);
    PFL_EXPECT(session.unrecognized_packet_count() == 0U);
    const auto rows = session.list_flows();
    PFL_REQUIRE(rows.size() == 1U);
    PFL_EXPECT(rows[0].protocol_text == "ARP");
    PFL_EXPECT(require_flow_protocol_path_text(session, rows[0]) == expected_protocol_path);

    const auto packet = require_packet(session, 0U);
    const auto details = session.read_packet_details(packet);
    PFL_REQUIRE(details.has_value());
    PFL_EXPECT(details->has_ethernet);
    PFL_EXPECT(details->ethernet.uses_length_field);
    PFL_EXPECT(details->has_llc);
    PFL_EXPECT(details->has_snap);
    PFL_EXPECT(details->has_arp);
    PFL_EXPECT(!details->has_ipv4);
    PFL_EXPECT(!details->has_ipv6);

    const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet);
    expect_layer_prefix(summary_layers, {"frame", "ethernet", "llc", "snap", "arp"});
}

}  // namespace

void run_llc_snap_pcap_fixture_tests() {
    expect_supported_llc_snap_ip_fixture(
        "parsing/llc_snap/01_llc_snap_ipv4_tcp.pcap",
        FlowAddressFamily::ipv4,
        "TCP",
        "192.0.2.40",
        49170U,
        "198.51.100.40",
        443U,
        0U,
        "ipv4",
        "IEEE 802.3 -> LLC/SNAP -> IPv4 -> TCP"
    );

    expect_supported_llc_snap_ip_fixture(
        "parsing/llc_snap/02_llc_snap_ipv4_udp.pcap",
        FlowAddressFamily::ipv4,
        "UDP",
        "192.0.2.40",
        53550U,
        "198.51.100.40",
        443U,
        0U,
        "ipv4",
        "IEEE 802.3 -> LLC/SNAP -> IPv4 -> UDP"
    );

    expect_supported_llc_snap_ip_fixture(
        "parsing/llc_snap/03_llc_snap_ipv6_tcp.pcap",
        FlowAddressFamily::ipv6,
        "TCP",
        "2001:0db8:0040:0000:0000:0000:0000:0010",
        49170U,
        "2001:0db8:0040:0000:0000:0000:0000:0020",
        443U,
        0U,
        "ipv6",
        "IEEE 802.3 -> LLC/SNAP -> IPv6 -> TCP"
    );

    expect_supported_llc_snap_ip_fixture(
        "parsing/llc_snap/04_llc_snap_ipv6_udp.pcap",
        FlowAddressFamily::ipv6,
        "UDP",
        "2001:0db8:0040:0000:0000:0000:0000:0010",
        53550U,
        "2001:0db8:0040:0000:0000:0000:0000:0020",
        443U,
        0U,
        "ipv6",
        "IEEE 802.3 -> LLC/SNAP -> IPv6 -> UDP"
    );

    expect_supported_llc_snap_arp_fixture(
        "parsing/llc_snap/05_llc_snap_arp.pcap",
        "IEEE 802.3 -> LLC/SNAP"
    );

    expect_supported_llc_snap_ip_fixture(
        "parsing/llc_snap/06_vlan_llc_snap_ipv4_tcp.pcap",
        FlowAddressFamily::ipv4,
        "TCP",
        "192.0.2.40",
        49170U,
        "198.51.100.40",
        443U,
        1U,
        "ipv4",
        "EthernetII -> VLAN(vid=100) -> LLC/SNAP -> IPv4 -> TCP"
    );

    expect_supported_llc_snap_ip_fixture(
        "parsing/llc_snap/07_qinq_llc_snap_ipv4_udp.pcap",
        FlowAddressFamily::ipv4,
        "UDP",
        "192.0.2.40",
        53550U,
        "198.51.100.40",
        443U,
        2U,
        "ipv4",
        "EthernetII -> VLAN(vid=200) -> VLAN(vid=300) -> LLC/SNAP -> IPv4 -> UDP"
    );

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/llc_snap/08_llc_snap_unknown_pid.pcap")));
        PFL_EXPECT(session.list_flows().empty());
        PFL_EXPECT(session.state().protocol_path_registry.size() == 0U);
        PFL_EXPECT(session.unrecognized_packet_count() == 1U);
        const auto rows = session.list_unrecognized_packets(0U, 30U);
        PFL_REQUIRE(rows.size() == 1U);
        PFL_EXPECT(rows[0].reason_text == "Unknown SNAP PID");

        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->has_ethernet);
        PFL_EXPECT(details->ethernet.uses_length_field);
        PFL_EXPECT(details->has_llc);
        PFL_EXPECT(details->has_snap);
        PFL_EXPECT(details->snap.pid == 0x88B5U);
        PFL_EXPECT(details->snap.payload_length > 0U);

        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet);
        expect_layer_prefix(summary_layers, {"frame", "ethernet", "llc", "snap", "snap-payload"});
        const auto* snap_layer = find_layer(summary_layers, "snap");
        PFL_REQUIRE(snap_layer != nullptr);
        PFL_EXPECT(layer_has_field_containing(*snap_layer, "OUI", "00:00:00"));
        PFL_EXPECT(layer_has_field_containing(*snap_layer, "PID", "0x88b5"));
        const auto* data_layer = find_layer(summary_layers, "snap-payload");
        PFL_REQUIRE(data_layer != nullptr);
        PFL_EXPECT(layer_has_field_containing(*data_layer, "Length", "bytes"));
        PFL_EXPECT(layer_has_field(*data_layer, "Raw"));
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/llc_snap/09_llc_snap_nonzero_oui_ipv4_pid.pcap")));
        PFL_EXPECT(session.unrecognized_packet_count() == 0U);
        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 1U);
        PFL_EXPECT(rows[0].family == FlowAddressFamily::ipv4);
        PFL_EXPECT(rows[0].protocol_text == "UDP");
        PFL_EXPECT(require_flow_protocol_path_text(session, rows[0]) == "IEEE 802.3 -> LLC/SNAP -> IPv4 -> UDP");
        const bool forward_match = rows[0].address_a == "192.0.2.40" &&
            rows[0].port_a == 53550U &&
            rows[0].address_b == "198.51.100.40" &&
            rows[0].port_b == 443U;
        const bool reverse_match = rows[0].address_a == "198.51.100.40" &&
            rows[0].port_a == 443U &&
            rows[0].address_b == "192.0.2.40" &&
            rows[0].port_b == 53550U;
        PFL_EXPECT(forward_match || reverse_match);

        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->has_ethernet);
        PFL_EXPECT(details->ethernet.uses_length_field);
        PFL_EXPECT(details->has_llc);
        PFL_EXPECT(details->has_snap);
        PFL_EXPECT(details->has_ipv4);
        PFL_EXPECT(details->has_udp);
        PFL_EXPECT(details->snap.pid == 0x0800U);
        const auto non_ethernet_oui = std::array<std::uint8_t, 3> {0x00U, 0x00U, 0xF8U};
        PFL_EXPECT(details->snap.oui == non_ethernet_oui);
        PFL_EXPECT(session_detail::format_ipv4_address(details->ipv4.src_addr) == "192.0.2.40");
        PFL_EXPECT(session_detail::format_ipv4_address(details->ipv4.dst_addr) == "198.51.100.40");
        PFL_EXPECT(details->udp.src_port == 53550U);
        PFL_EXPECT(details->udp.dst_port == 443U);

        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet);
        expect_layer_prefix(summary_layers, {"frame", "ethernet", "llc", "snap", "ipv4", "udp"});
        const auto* snap_layer = find_layer(summary_layers, "snap");
        PFL_REQUIRE(snap_layer != nullptr);
        PFL_EXPECT(layer_has_field_containing(*snap_layer, "OUI", "00:00:f8"));
        PFL_EXPECT(layer_has_field_containing(*snap_layer, "PID", "IPv4"));
        PFL_EXPECT(find_layer(summary_layers, "snap-payload") == nullptr);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/llc_snap/10_llc_non_snap_ipx_like.pcap")));
        PFL_EXPECT(session.list_flows().empty());
        PFL_EXPECT(session.state().protocol_path_registry.size() == 0U);
        PFL_EXPECT(session.unrecognized_packet_count() == 1U);
        const auto rows = session.list_unrecognized_packets(0U, 30U);
        PFL_REQUIRE(rows.size() == 1U);
        PFL_EXPECT(rows[0].reason_text == "Non-SNAP LLC frame");

        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->has_ethernet);
        PFL_EXPECT(details->ethernet.uses_length_field);
        PFL_EXPECT(details->has_llc);
        PFL_EXPECT(!details->has_snap);
        PFL_EXPECT(details->llc.dsap == 0xE0U);
        PFL_EXPECT(details->llc.ssap == 0xE0U);
        PFL_EXPECT(details->llc.control == 0x03U);
        PFL_EXPECT(details->llc.payload_length > 0U);

        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet);
        expect_layer_prefix(summary_layers, {"frame", "ethernet", "llc", "llc-payload"});
        const auto* data_layer = find_layer(summary_layers, "llc-payload");
        PFL_REQUIRE(data_layer != nullptr);
        PFL_EXPECT(layer_has_field_containing(*data_layer, "Length", "bytes"));
        PFL_EXPECT(layer_has_field(*data_layer, "Raw"));
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/llc_snap/11_llc_snap_truncated_llc_header.pcap")));
        PFL_EXPECT(session.list_flows().empty());
        PFL_EXPECT(session.state().protocol_path_registry.size() == 0U);
        PFL_EXPECT(session.unrecognized_packet_count() == 1U);
        const auto rows = session.list_unrecognized_packets(0U, 30U);
        PFL_REQUIRE(rows.size() == 1U);
        PFL_EXPECT(rows[0].reason_text == "LLC header truncated");

        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->has_ethernet);
        PFL_EXPECT(details->has_llc);
        PFL_EXPECT(details->llc.header_truncated);
        PFL_EXPECT(details->llc.available_header_bytes == 2U);
        PFL_EXPECT(details->llc.dsap == 0xaaU);
        PFL_EXPECT(details->llc.ssap == 0xaaU);
        PFL_EXPECT(!details->has_snap);

        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet);
        expect_layer_prefix(summary_layers, {"frame", "ethernet", "llc"});
        const auto* llc_layer = find_layer(summary_layers, "llc");
        PFL_REQUIRE(llc_layer != nullptr);
        PFL_EXPECT(layer_has_field_containing(*llc_layer, "DSAP", "0xaa"));
        PFL_EXPECT(layer_has_field_containing(*llc_layer, "SSAP", "0xaa"));
        PFL_EXPECT(!layer_has_field(*llc_layer, "Control"));
        PFL_EXPECT(!layer_has_field(*llc_layer, "Payload Length"));
        PFL_EXPECT(layer_has_field_containing(*llc_layer, "Warning", "LLC header is truncated"));
        PFL_EXPECT(find_layer(summary_layers, "snap") == nullptr);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/llc_snap/12_llc_snap_truncated_snap_header.pcap")));
        PFL_EXPECT(session.list_flows().empty());
        PFL_EXPECT(session.state().protocol_path_registry.size() == 0U);
        PFL_EXPECT(session.unrecognized_packet_count() == 1U);
        const auto rows = session.list_unrecognized_packets(0U, 30U);
        PFL_REQUIRE(rows.size() == 1U);
        PFL_EXPECT(rows[0].reason_text == "SNAP header truncated");

        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->has_ethernet);
        PFL_EXPECT(details->has_llc);
        PFL_EXPECT(details->has_snap);
        PFL_EXPECT(details->snap.header_truncated);

        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet);
        expect_layer_prefix(summary_layers, {"frame", "ethernet", "llc", "snap"});
        const auto* snap_layer = find_layer(summary_layers, "snap");
        PFL_REQUIRE(snap_layer != nullptr);
        PFL_EXPECT(layer_has_field_containing(*snap_layer, "Warning", "SNAP header is truncated"));
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/llc_snap/13_llc_snap_truncated_inner_ipv4.pcap")));
        PFL_EXPECT(session.list_flows().empty());
        PFL_EXPECT(session.state().protocol_path_registry.size() == 0U);
        PFL_EXPECT(session.unrecognized_packet_count() == 1U);
        const auto rows = session.list_unrecognized_packets(0U, 30U);
        PFL_REQUIRE(rows.size() == 1U);
        PFL_EXPECT(rows[0].reason_text == "IPv4 header truncated");

        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->has_llc);
        PFL_EXPECT(details->has_snap);
        PFL_EXPECT(details->has_ipv4);
        PFL_EXPECT(details->ipv4.header_truncated);

        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet);
        expect_layer_prefix(summary_layers, {"frame", "ethernet", "llc", "snap", "ipv4"});
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/llc_snap/14_llc_snap_length_short_payload.pcap")));
        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 1U);
        PFL_EXPECT(rows[0].family == FlowAddressFamily::ipv4);
        PFL_EXPECT(rows[0].protocol_text == "UDP");
        PFL_EXPECT(require_flow_protocol_path_text(session, rows[0]) == "IEEE 802.3 -> LLC/SNAP -> IPv4 -> UDP");
        PFL_EXPECT(session.unrecognized_packet_count() == 0U);

        const auto packet_rows = session.list_flow_packets(0U);
        PFL_REQUIRE(packet_rows.size() == 1U);
        PFL_EXPECT(packet_rows[0].payload_length == 10U);
        const auto packet = require_packet(session, packet_rows[0].packet_index);
        const auto details = session.read_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->has_llc);
        PFL_EXPECT(details->has_snap);
        PFL_EXPECT(details->has_ipv4);
        PFL_EXPECT(details->has_udp);
        PFL_EXPECT(details->llc.payload_length_exceeds_captured);
        PFL_EXPECT(details->udp.payload_truncated);

        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet);
        const auto* llc_layer = find_layer(summary_layers, "llc");
        PFL_REQUIRE(llc_layer != nullptr);
        PFL_EXPECT(!layer_has_field(*llc_layer, "Payload Length"));
        PFL_EXPECT(layer_has_field_containing(*llc_layer, "Warning", "exceeds captured payload bytes"));
        const auto* ipv4_layer = find_layer(summary_layers, "ipv4");
        PFL_REQUIRE(ipv4_layer != nullptr);
        PFL_EXPECT(layer_has_field_containing(*ipv4_layer, "Warning", "total length exceeds captured packet bytes"));
        const auto* udp_layer = find_layer(summary_layers, "udp");
        PFL_REQUIRE(udp_layer != nullptr);
        PFL_EXPECT(layer_has_field_containing(*udp_layer, "Warning", "UDP length exceeds available packet bytes"));
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/llc_snap/15_llc_snap_length_extra_payload.pcap")));
        PFL_EXPECT(session.list_flows().empty());
        PFL_EXPECT(session.state().protocol_path_registry.size() == 0U);
        PFL_EXPECT(session.unrecognized_packet_count() == 1U);
        const auto rows = session.list_unrecognized_packets(0U, 30U);
        PFL_REQUIRE(rows.size() == 1U);
        PFL_EXPECT(rows[0].reason_text == "UDP header truncated");
        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->has_llc);
        PFL_EXPECT(details->has_snap);
        PFL_EXPECT(details->has_ipv4);
        PFL_EXPECT(!details->has_udp);
        PFL_EXPECT(details->llc.captured_payload_exceeds_declared);
        PFL_EXPECT(details->ethernet.trailer_length == 30U);
        PFL_EXPECT(!details->ethernet.trailer_preview.empty());

        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet);
        const auto* ethernet_layer = find_layer(summary_layers, "ethernet");
        PFL_REQUIRE(ethernet_layer != nullptr);
        PFL_EXPECT(layer_has_field_containing(*ethernet_layer, "Length", "28 bytes"));
        PFL_EXPECT(layer_has_field_containing(*ethernet_layer, "Warning", "extend beyond the declared IEEE 802.3 payload length"));
        const auto* llc_layer = find_layer(summary_layers, "llc");
        PFL_REQUIRE(llc_layer != nullptr);
        PFL_EXPECT(!layer_has_field(*llc_layer, "Payload Length"));
        const auto* ipv4_layer = find_layer(summary_layers, "ipv4");
        PFL_REQUIRE(ipv4_layer != nullptr);
        PFL_EXPECT(layer_has_field_containing(*ipv4_layer, "Warning", "total length exceeds captured packet bytes"));
        const auto* trailer_layer = find_layer(summary_layers, "trailer");
        PFL_REQUIRE(trailer_layer != nullptr);
        PFL_EXPECT(layer_has_field_containing(*trailer_layer, "Length", "30 bytes"));
        PFL_EXPECT(layer_has_field(*trailer_layer, "Raw"));
        PFL_EXPECT(find_layer(summary_layers, "udp") == nullptr);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/llc_snap/16_llc_truncated_dsap_only.pcap")));
        PFL_EXPECT(session.list_flows().empty());
        PFL_EXPECT(session.state().protocol_path_registry.size() == 0U);
        PFL_EXPECT(session.unrecognized_packet_count() == 1U);
        const auto rows = session.list_unrecognized_packets(0U, 30U);
        PFL_REQUIRE(rows.size() == 1U);
        PFL_EXPECT(rows[0].reason_text == "LLC header truncated");

        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->has_llc);
        PFL_EXPECT(details->llc.header_truncated);
        PFL_EXPECT(details->llc.available_header_bytes == 1U);
        PFL_EXPECT(details->llc.dsap == 0xaaU);
        PFL_EXPECT(!details->has_snap);
        PFL_EXPECT(!details->has_ipv4);
        PFL_EXPECT(!details->has_ipv6);
        PFL_EXPECT(!details->has_arp);

        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet);
        expect_layer_prefix(summary_layers, {"frame", "ethernet", "llc"});
        const auto* llc_layer = find_layer(summary_layers, "llc");
        PFL_REQUIRE(llc_layer != nullptr);
        PFL_EXPECT(layer_has_field_containing(*llc_layer, "DSAP", "0xaa"));
        PFL_EXPECT(!layer_has_field(*llc_layer, "SSAP"));
        PFL_EXPECT(!layer_has_field(*llc_layer, "Control"));
        PFL_EXPECT(find_layer(summary_layers, "snap") == nullptr);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/llc_snap/17_llc_truncated_dsap_ssap.pcap")));
        PFL_EXPECT(session.list_flows().empty());
        PFL_EXPECT(session.state().protocol_path_registry.size() == 0U);
        PFL_EXPECT(session.unrecognized_packet_count() == 1U);
        const auto rows = session.list_unrecognized_packets(0U, 30U);
        PFL_REQUIRE(rows.size() == 1U);
        PFL_EXPECT(rows[0].reason_text == "LLC header truncated");

        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->has_llc);
        PFL_EXPECT(details->llc.header_truncated);
        PFL_EXPECT(details->llc.available_header_bytes == 2U);
        PFL_EXPECT(details->llc.dsap == 0xaaU);
        PFL_EXPECT(details->llc.ssap == 0xaaU);
        PFL_EXPECT(!details->has_snap);

        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet);
        expect_layer_prefix(summary_layers, {"frame", "ethernet", "llc"});
        const auto* llc_layer = find_layer(summary_layers, "llc");
        PFL_REQUIRE(llc_layer != nullptr);
        PFL_EXPECT(layer_has_field_containing(*llc_layer, "DSAP", "0xaa"));
        PFL_EXPECT(layer_has_field_containing(*llc_layer, "SSAP", "0xaa"));
        PFL_EXPECT(!layer_has_field(*llc_layer, "Control"));
        PFL_EXPECT(find_layer(summary_layers, "snap") == nullptr);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/llc_snap/18_llc_non_snap_control.pcap")));
        PFL_EXPECT(session.list_flows().empty());
        PFL_EXPECT(session.state().protocol_path_registry.size() == 0U);
        PFL_EXPECT(session.unrecognized_packet_count() == 1U);
        const auto rows = session.list_unrecognized_packets(0U, 30U);
        PFL_REQUIRE(rows.size() == 1U);
        PFL_EXPECT(rows[0].reason_text == "Non-SNAP LLC frame");

        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->has_llc);
        PFL_EXPECT(!details->has_snap);
        PFL_EXPECT(details->llc.available_header_bytes == 3U);
        PFL_EXPECT(details->llc.dsap == 0xaaU);
        PFL_EXPECT(details->llc.ssap == 0xaaU);
        PFL_EXPECT(details->llc.control == 0x00U);
        PFL_EXPECT(!details->has_ipv4);
        PFL_EXPECT(!details->has_ipv6);

        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet);
        expect_layer_prefix(summary_layers, {"frame", "ethernet", "llc", "llc-payload"});
        PFL_EXPECT(find_layer(summary_layers, "snap") == nullptr);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/llc_snap/19_llc_snap_declared_short_with_captured_tail.pcap")));
        PFL_EXPECT(session.list_flows().empty());
        PFL_EXPECT(session.state().protocol_path_registry.size() == 0U);
        PFL_EXPECT(session.unrecognized_packet_count() == 1U);
        const auto rows = session.list_unrecognized_packets(0U, 30U);
        PFL_REQUIRE(rows.size() == 1U);
        PFL_EXPECT(rows[0].reason_text == "SNAP header truncated");

        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->has_llc);
        PFL_EXPECT(details->llc.captured_payload_exceeds_declared);
        PFL_EXPECT(!details->llc.payload_length_exceeds_captured);
        PFL_EXPECT(details->has_snap);
        PFL_EXPECT(details->snap.header_truncated);
        PFL_EXPECT(!details->has_ipv4);
        PFL_EXPECT(!details->has_udp);
        PFL_EXPECT(details->ethernet.trailer_length > 0U);

        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet);
        expect_layer_prefix(summary_layers, {"frame", "ethernet", "llc", "snap", "trailer"});
        const auto* ethernet_layer = find_layer(summary_layers, "ethernet");
        PFL_REQUIRE(ethernet_layer != nullptr);
        PFL_EXPECT(layer_has_field_containing(*ethernet_layer, "Length", "7 bytes"));
        PFL_EXPECT(layer_has_field_containing(*ethernet_layer, "Warning", "extend beyond the declared IEEE 802.3 payload length"));
        PFL_EXPECT(find_layer(summary_layers, "ipv4") == nullptr);
        PFL_EXPECT(find_layer(summary_layers, "udp") == nullptr);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/llc_snap/20_llc_snap_padding_after_declared_payload.pcap")));
        PFL_EXPECT(session.unrecognized_packet_count() == 0U);
        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 1U);
        PFL_EXPECT(rows[0].family == FlowAddressFamily::ipv4);
        PFL_EXPECT(rows[0].protocol_text == "UDP");
        PFL_EXPECT(require_flow_protocol_path_text(session, rows[0]) == "IEEE 802.3 -> LLC/SNAP -> IPv4 -> UDP");
        const bool forward_match = rows[0].address_a == "192.0.2.50" &&
            rows[0].port_a == 54050U &&
            rows[0].address_b == "198.51.100.50" &&
            rows[0].port_b == 4500U;
        const bool reverse_match = rows[0].address_a == "198.51.100.50" &&
            rows[0].port_a == 4500U &&
            rows[0].address_b == "192.0.2.50" &&
            rows[0].port_b == 54050U;
        PFL_EXPECT(forward_match || reverse_match);

        const auto packet_rows = session.list_flow_packets(0U);
        PFL_REQUIRE(packet_rows.size() == 1U);
        PFL_EXPECT(packet_rows[0].payload_length == 9U);

        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->has_llc);
        PFL_EXPECT(details->has_snap);
        PFL_EXPECT(details->has_ipv4);
        PFL_EXPECT(details->has_udp);
        PFL_EXPECT(details->udp.src_port == 54050U);
        PFL_EXPECT(details->udp.dst_port == 4500U);
        PFL_EXPECT(details->llc.captured_payload_exceeds_declared);
        PFL_EXPECT(details->ethernet.trailer_length == 6U);
        PFL_EXPECT(details->ethernet.trailer_preview.size() == 6U);
        const std::vector<std::uint8_t> expected_trailer_preview {
            0xdeU, 0xadU, 0xbeU, 0xefU, 0xa5U, 0x5aU
        };
        PFL_EXPECT(details->ethernet.trailer_preview == expected_trailer_preview);

        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet);
        expect_layer_prefix(summary_layers, {"frame", "ethernet", "llc", "snap", "ipv4", "udp", "trailer"});
        const auto* trailer_layer = find_layer(summary_layers, "trailer");
        PFL_REQUIRE(trailer_layer != nullptr);
        PFL_EXPECT(layer_has_field_containing(*trailer_layer, "Length", "6 bytes"));
        PFL_EXPECT(layer_has_field(*trailer_layer, "Raw"));
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/llc_snap/21_llc_snap_truncated_inner_ipv6.pcap")));
        PFL_EXPECT(session.list_flows().empty());
        PFL_EXPECT(session.state().protocol_path_registry.size() == 0U);
        PFL_EXPECT(session.unrecognized_packet_count() == 1U);
        const auto rows = session.list_unrecognized_packets(0U, 30U);
        PFL_REQUIRE(rows.size() == 1U);
        PFL_EXPECT(rows[0].reason_text == "IPv6 header truncated");

        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->has_llc);
        PFL_EXPECT(details->has_snap);
        PFL_EXPECT(!details->has_tcp);
        PFL_EXPECT(!details->has_udp);

        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet);
        expect_layer_prefix(summary_layers, {"frame", "ethernet", "llc", "snap"});
        PFL_EXPECT(find_layer(summary_layers, "ipv6") == nullptr);
        PFL_EXPECT(find_layer(summary_layers, "udp") == nullptr);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/llc_snap/22_llc_snap_truncated_inner_arp.pcap")));
        const auto rows = session.list_unrecognized_packets(0U, 30U);
        if (!rows.empty()) {
            PFL_EXPECT(rows[0].reason_text == "ARP header truncated");
        }

        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->has_llc);
        PFL_EXPECT(details->has_snap);
        PFL_EXPECT(details->has_arp);
        PFL_EXPECT(details->arp.fixed_header_truncated || details->arp.address_section_truncated);
        PFL_EXPECT(!details->has_ipv4);
        PFL_EXPECT(!details->has_ipv6);

        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet);
        expect_layer_prefix(summary_layers, {"frame", "ethernet", "llc", "snap"});
        PFL_EXPECT(find_layer(summary_layers, "arp") != nullptr);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/llc_snap/23_vlan_9100_llc_snap_ipv4_udp.pcap")));
        PFL_EXPECT(session.unrecognized_packet_count() == 0U);
        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 1U);
        PFL_EXPECT(rows[0].family == FlowAddressFamily::ipv4);
        PFL_EXPECT(rows[0].protocol_text == "UDP");
        PFL_EXPECT(require_flow_protocol_path_text(session, rows[0]) == "EthernetII -> VLAN(vid=413) -> LLC/SNAP -> IPv4 -> UDP");
        const bool forward_match = rows[0].address_a == "192.0.2.53" &&
            rows[0].port_a == 54053U &&
            rows[0].address_b == "198.51.100.53" &&
            rows[0].port_b == 4530U;
        const bool reverse_match = rows[0].address_a == "198.51.100.53" &&
            rows[0].port_a == 4530U &&
            rows[0].address_b == "192.0.2.53" &&
            rows[0].port_b == 54053U;
        PFL_EXPECT(forward_match || reverse_match);

        const auto packet_rows = session.list_flow_packets(0U);
        PFL_REQUIRE(packet_rows.size() == 1U);
        PFL_EXPECT(packet_rows[0].payload_length == 9U);

        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->has_vlan);
        PFL_EXPECT(details->vlan_tags.size() == 1U);
        PFL_EXPECT(details->vlan_tags[0].tpid == 0x9100U);
        PFL_EXPECT((details->vlan_tags[0].tci & 0x0FFFU) == 413U);
        PFL_EXPECT(details->has_ipv4);
        PFL_EXPECT(details->has_udp);
        PFL_EXPECT(details->udp.src_port == 54053U);
        PFL_EXPECT(details->udp.dst_port == 4530U);

        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet);
        expect_layer_prefix(summary_layers, {"frame", "ethernet", "vlan", "llc", "snap", "ipv4", "udp"});
        const auto* vlan_layer = find_layer(summary_layers, "vlan");
        PFL_REQUIRE(vlan_layer != nullptr);
        PFL_EXPECT(layer_has_field_containing(*vlan_layer, "Encapsulated Length", "45 bytes"));
        PFL_EXPECT(!layer_has_field(*vlan_layer, "Encapsulated EtherType"));
    }
}

}  // namespace pfl::tests
