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
    PFL_EXPECT(packet.has_value());
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
        search_index = static_cast<std::size_t>(std::distance(layers.begin(), found)) + 1U;
    }
}

void expect_single_supported_flow(
    CaptureSession& session,
    const std::filesystem::path& relative_path,
    const FlowAddressFamily expected_family,
    const std::string& expected_protocol
) {
    PFL_EXPECT(session.open_capture(fixture_path(relative_path)));
    const auto rows = session.list_flows();
    PFL_EXPECT(rows.size() == 1U);
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
    const std::string& expected_inner_layer
) {
    CaptureSession session {};
    expect_single_supported_flow(
        session,
        relative_path,
        expected_family,
        expected_protocol
    );

    const auto packet = require_packet(session, 0U);
    const auto details = session.read_packet_details(packet);
    PFL_EXPECT(details.has_value());
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
    PFL_EXPECT(ethernet_layer != nullptr);
    if (expected_vlan_count == 0U) {
        PFL_EXPECT(layer_has_field_containing(*ethernet_layer, "Length", "bytes"));
    } else {
        PFL_EXPECT(layer_has_field(*ethernet_layer, "Type"));
    }
    if (expected_vlan_count == 1U) {
        const auto* vlan_layer = find_layer(summary_layers, "vlan", 0U);
        PFL_EXPECT(vlan_layer != nullptr);
        PFL_EXPECT(!layer_has_field(*vlan_layer, "Tag Control Information"));
        PFL_EXPECT(layer_has_field_containing(*vlan_layer, "Encapsulated Length", "65 bytes"));
        PFL_EXPECT(!layer_has_field(*vlan_layer, "Encapsulated EtherType"));
    } else if (expected_vlan_count == 2U) {
        const auto* outer_vlan_layer = find_layer(summary_layers, "vlan", 0U);
        const auto* inner_vlan_layer = find_layer(summary_layers, "vlan", 1U);
        PFL_EXPECT(outer_vlan_layer != nullptr);
        PFL_EXPECT(inner_vlan_layer != nullptr);
        PFL_EXPECT(!layer_has_field(*outer_vlan_layer, "Tag Control Information"));
        PFL_EXPECT(!layer_has_field(*inner_vlan_layer, "Tag Control Information"));
        PFL_EXPECT(layer_has_field_containing(*outer_vlan_layer, "Encapsulated EtherType", "802.1Q VLAN"));
        PFL_EXPECT(layer_has_field_containing(*inner_vlan_layer, "Encapsulated Length", "53 bytes"));
        PFL_EXPECT(!layer_has_field(*inner_vlan_layer, "Encapsulated EtherType"));
    }
    const auto* llc_layer = find_layer(summary_layers, "llc");
    PFL_EXPECT(llc_layer != nullptr);
    PFL_EXPECT(layer_has_field_containing(*llc_layer, "DSAP", "0xaa"));
    PFL_EXPECT(!layer_has_field(*llc_layer, "Payload Length"));
    const auto* snap_layer = find_layer(summary_layers, "snap");
    PFL_EXPECT(snap_layer != nullptr);
    PFL_EXPECT(layer_has_field_containing(*snap_layer, "OUI", "00:00:00"));
}

void expect_supported_llc_snap_arp_fixture(const std::filesystem::path& relative_path) {
    CaptureSession session {};
    PFL_EXPECT(session.open_capture(fixture_path(relative_path)));
    PFL_EXPECT(session.summary().flow_count == 1U);
    PFL_EXPECT(session.unrecognized_packet_count() == 0U);
    const auto rows = session.list_flows();
    PFL_EXPECT(rows.size() == 1U);
    PFL_EXPECT(rows[0].protocol_text == "ARP");

    const auto packet = require_packet(session, 0U);
    const auto details = session.read_packet_details(packet);
    PFL_EXPECT(details.has_value());
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
        "ipv4"
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
        "ipv4"
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
        "ipv6"
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
        "ipv6"
    );

    expect_supported_llc_snap_arp_fixture("parsing/llc_snap/05_llc_snap_arp.pcap");

    expect_supported_llc_snap_ip_fixture(
        "parsing/llc_snap/06_vlan_llc_snap_ipv4_tcp.pcap",
        FlowAddressFamily::ipv4,
        "TCP",
        "192.0.2.40",
        49170U,
        "198.51.100.40",
        443U,
        1U,
        "ipv4"
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
        "ipv4"
    );

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/llc_snap/08_llc_snap_unknown_pid.pcap")));
        PFL_EXPECT(session.list_flows().empty());
        PFL_EXPECT(session.unrecognized_packet_count() == 1U);
        const auto rows = session.list_unrecognized_packets(0U, 30U);
        PFL_EXPECT(rows.size() == 1U);
        PFL_EXPECT(rows[0].reason_text == "Unknown SNAP PID");

        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_EXPECT(details.has_value());
        PFL_EXPECT(details->has_ethernet);
        PFL_EXPECT(details->ethernet.uses_length_field);
        PFL_EXPECT(details->has_llc);
        PFL_EXPECT(details->has_snap);
        PFL_EXPECT(details->snap.pid == 0x88B5U);
        PFL_EXPECT(details->snap.payload_length > 0U);

        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet);
        expect_layer_prefix(summary_layers, {"frame", "ethernet", "llc", "snap", "snap-payload"});
        const auto* snap_layer = find_layer(summary_layers, "snap");
        PFL_EXPECT(snap_layer != nullptr);
        PFL_EXPECT(layer_has_field_containing(*snap_layer, "OUI", "00:00:00"));
        PFL_EXPECT(layer_has_field_containing(*snap_layer, "PID", "0x88b5"));
        const auto* data_layer = find_layer(summary_layers, "snap-payload");
        PFL_EXPECT(data_layer != nullptr);
        PFL_EXPECT(layer_has_field_containing(*data_layer, "Length", "bytes"));
        PFL_EXPECT(layer_has_field(*data_layer, "Raw"));
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/llc_snap/09_llc_snap_nonzero_oui_ipv4_pid.pcap")));
        PFL_EXPECT(session.unrecognized_packet_count() == 0U);
        const auto rows = session.list_flows();
        PFL_EXPECT(rows.size() == 1U);
        PFL_EXPECT(rows[0].family == FlowAddressFamily::ipv4);
        PFL_EXPECT(rows[0].protocol_text == "UDP");
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
        PFL_EXPECT(details.has_value());
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
        PFL_EXPECT(snap_layer != nullptr);
        PFL_EXPECT(layer_has_field_containing(*snap_layer, "OUI", "00:00:f8"));
        PFL_EXPECT(layer_has_field_containing(*snap_layer, "PID", "IPv4"));
        PFL_EXPECT(find_layer(summary_layers, "snap-payload") == nullptr);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/llc_snap/10_llc_non_snap_ipx_like.pcap")));
        PFL_EXPECT(session.list_flows().empty());
        PFL_EXPECT(session.unrecognized_packet_count() == 1U);
        const auto rows = session.list_unrecognized_packets(0U, 30U);
        PFL_EXPECT(rows.size() == 1U);
        PFL_EXPECT(rows[0].reason_text == "Non-SNAP LLC frame");

        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_EXPECT(details.has_value());
        PFL_EXPECT(details->has_ethernet);
        PFL_EXPECT(details->ethernet.uses_length_field);
        PFL_EXPECT(details->has_llc);
        PFL_EXPECT(!details->has_snap);
        PFL_EXPECT(details->llc.payload_length > 0U);

        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet);
        expect_layer_prefix(summary_layers, {"frame", "ethernet", "llc", "llc-payload"});
        const auto* data_layer = find_layer(summary_layers, "llc-payload");
        PFL_EXPECT(data_layer != nullptr);
        PFL_EXPECT(layer_has_field_containing(*data_layer, "Length", "bytes"));
        PFL_EXPECT(layer_has_field(*data_layer, "Raw"));
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/llc_snap/11_llc_snap_truncated_llc_header.pcap")));
        PFL_EXPECT(session.list_flows().empty());
        PFL_EXPECT(session.unrecognized_packet_count() == 1U);
        const auto rows = session.list_unrecognized_packets(0U, 30U);
        PFL_EXPECT(rows.size() == 1U);
        PFL_EXPECT(rows[0].reason_text == "LLC header truncated");

        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_EXPECT(details.has_value());
        PFL_EXPECT(details->has_ethernet);
        PFL_EXPECT(details->has_llc);
        PFL_EXPECT(details->llc.header_truncated);
        PFL_EXPECT(!details->has_snap);

        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet);
        expect_layer_prefix(summary_layers, {"frame", "ethernet", "llc"});
        const auto* llc_layer = find_layer(summary_layers, "llc");
        PFL_EXPECT(llc_layer != nullptr);
        PFL_EXPECT(!layer_has_field(*llc_layer, "Payload Length"));
        PFL_EXPECT(layer_has_field_containing(*llc_layer, "Warning", "LLC header is truncated"));
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/llc_snap/12_llc_snap_truncated_snap_header.pcap")));
        PFL_EXPECT(session.list_flows().empty());
        PFL_EXPECT(session.unrecognized_packet_count() == 1U);
        const auto rows = session.list_unrecognized_packets(0U, 30U);
        PFL_EXPECT(rows.size() == 1U);
        PFL_EXPECT(rows[0].reason_text == "SNAP header truncated");

        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_EXPECT(details.has_value());
        PFL_EXPECT(details->has_ethernet);
        PFL_EXPECT(details->has_llc);
        PFL_EXPECT(details->has_snap);
        PFL_EXPECT(details->snap.header_truncated);

        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet);
        expect_layer_prefix(summary_layers, {"frame", "ethernet", "llc", "snap"});
        const auto* snap_layer = find_layer(summary_layers, "snap");
        PFL_EXPECT(snap_layer != nullptr);
        PFL_EXPECT(layer_has_field_containing(*snap_layer, "Warning", "SNAP header is truncated"));
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/llc_snap/13_llc_snap_truncated_inner_ipv4.pcap")));
        PFL_EXPECT(session.list_flows().empty());
        PFL_EXPECT(session.unrecognized_packet_count() == 1U);
        const auto rows = session.list_unrecognized_packets(0U, 30U);
        PFL_EXPECT(rows.size() == 1U);
        PFL_EXPECT(rows[0].reason_text == "IPv4 header truncated");

        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_EXPECT(details.has_value());
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
        PFL_EXPECT(rows.size() == 1U);
        PFL_EXPECT(rows[0].family == FlowAddressFamily::ipv4);
        PFL_EXPECT(rows[0].protocol_text == "UDP");
        PFL_EXPECT(session.unrecognized_packet_count() == 0U);

        const auto packet_rows = session.list_flow_packets(0U);
        PFL_EXPECT(packet_rows.size() == 1U);
        const auto packet = require_packet(session, packet_rows[0].packet_index);
        const auto details = session.read_packet_details(packet);
        PFL_EXPECT(details.has_value());
        PFL_EXPECT(details->has_llc);
        PFL_EXPECT(details->has_snap);
        PFL_EXPECT(details->has_ipv4);
        PFL_EXPECT(details->has_udp);
        PFL_EXPECT(details->llc.payload_length_exceeds_captured);
        PFL_EXPECT(details->udp.payload_truncated);

        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet);
        const auto* llc_layer = find_layer(summary_layers, "llc");
        PFL_EXPECT(llc_layer != nullptr);
        PFL_EXPECT(!layer_has_field(*llc_layer, "Payload Length"));
        PFL_EXPECT(layer_has_field_containing(*llc_layer, "Warning", "exceeds captured payload bytes"));
        const auto* ipv4_layer = find_layer(summary_layers, "ipv4");
        PFL_EXPECT(ipv4_layer != nullptr);
        PFL_EXPECT(layer_has_field_containing(*ipv4_layer, "Warning", "total length exceeds captured packet bytes"));
        const auto* udp_layer = find_layer(summary_layers, "udp");
        PFL_EXPECT(udp_layer != nullptr);
        PFL_EXPECT(layer_has_field_containing(*udp_layer, "Warning", "UDP length exceeds available packet bytes"));
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/llc_snap/15_llc_snap_length_extra_payload.pcap")));
        PFL_EXPECT(session.list_flows().empty());
        PFL_EXPECT(session.unrecognized_packet_count() == 1U);
        const auto rows = session.list_unrecognized_packets(0U, 30U);
        PFL_EXPECT(rows.size() == 1U);
        PFL_EXPECT(rows[0].reason_text == "UDP header truncated");
        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_EXPECT(details.has_value());
        PFL_EXPECT(details->has_llc);
        PFL_EXPECT(details->has_snap);
        PFL_EXPECT(details->has_ipv4);
        PFL_EXPECT(!details->has_udp);
        PFL_EXPECT(details->llc.captured_payload_exceeds_declared);

        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet);
        const auto* llc_layer = find_layer(summary_layers, "llc");
        PFL_EXPECT(llc_layer != nullptr);
        PFL_EXPECT(!layer_has_field(*llc_layer, "Payload Length"));
        PFL_EXPECT(layer_has_field_containing(*llc_layer, "Warning", "extend beyond the declared IEEE 802.3 payload length"));
        const auto* ipv4_layer = find_layer(summary_layers, "ipv4");
        PFL_EXPECT(ipv4_layer != nullptr);
        PFL_EXPECT(layer_has_field_containing(*ipv4_layer, "Warning", "total length exceeds captured packet bytes"));
    }
}

}  // namespace pfl::tests
