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

const session_detail::PacketSummaryField* find_field(
    const session_detail::PacketSummaryLayer& layer,
    const std::string& label
) {
    const auto it = std::find_if(layer.fields.begin(), layer.fields.end(), [&](const session_detail::PacketSummaryField& field) {
        return field.label == label;
    });
    return it == layer.fields.end() ? nullptr : &(*it);
}

std::size_t count_layers(
    const std::vector<session_detail::PacketSummaryLayer>& layers,
    const std::string& id
) {
    return static_cast<std::size_t>(std::count_if(layers.begin(), layers.end(), [&](const session_detail::PacketSummaryLayer& layer) {
        return layer.id == id;
    }));
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

void expect_single_flow(
    CaptureSession& session,
    const std::filesystem::path& relative_path,
    const FlowAddressFamily expected_family,
    const std::string& expected_protocol,
    const std::uint64_t expected_packet_count
) {
    PFL_EXPECT(session.open_capture(fixture_path(relative_path)));
    const auto rows = session.list_flows();
    PFL_EXPECT(rows.size() == 1U);
    PFL_EXPECT(rows[0].family == expected_family);
    PFL_EXPECT(rows[0].protocol_text == expected_protocol);
    PFL_EXPECT(rows[0].packet_count == expected_packet_count);
    PFL_EXPECT(session.unrecognized_packet_count() == 0U);
}

void expect_mpls_label_field(
    const session_detail::PacketSummaryLayer& layer,
    const std::string& label,
    const std::string& expected_value
) {
    const auto* field = find_field(layer, label);
    PFL_EXPECT(field != nullptr);
    PFL_EXPECT(field->value == expected_value);
}

}  // namespace

void run_mpls_pcap_fixture_tests() {
    {
        CaptureSession session {};
        expect_single_flow(
            session,
            "parsing/mpls/01_mpls_ipv4_tcp_single_label.pcap",
            FlowAddressFamily::ipv4,
            "TCP",
            1U
        );

        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_EXPECT(details.has_value());
        PFL_EXPECT(details->has_mpls);
        PFL_EXPECT(details->mpls_labels.size() == 1U);
        PFL_EXPECT(details->mpls_labels[0].label == 100U);
        PFL_EXPECT(details->has_ipv4);
        PFL_EXPECT(details->has_tcp);

        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet);
        expect_layer_prefix(summary_layers, {"frame", "ethernet", "mpls", "ipv4", "tcp"});
        PFL_EXPECT(count_layers(summary_layers, "mpls") == 1U);

        const auto* mpls_layer = find_layer(summary_layers, "mpls");
        PFL_EXPECT(mpls_layer != nullptr);
        PFL_EXPECT(mpls_layer->title.find("MPLS Label") != std::string::npos);
        expect_mpls_label_field(*mpls_layer, "Label", "100");
        expect_mpls_label_field(*mpls_layer, "Traffic Class", "0");
        expect_mpls_label_field(*mpls_layer, "Bottom of Stack", "1");
        expect_mpls_label_field(*mpls_layer, "TTL", "64");
    }

    {
        CaptureSession session {};
        expect_single_flow(
            session,
            "parsing/mpls/02_mpls_ipv4_udp_single_label.pcap",
            FlowAddressFamily::ipv4,
            "UDP",
            1U
        );

        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_EXPECT(details.has_value());
        PFL_EXPECT(details->has_mpls);
        PFL_EXPECT(details->has_ipv4);
        PFL_EXPECT(details->has_udp);

        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet);
        expect_layer_prefix(summary_layers, {"frame", "ethernet", "mpls", "ipv4", "udp"});
    }

    {
        CaptureSession session {};
        expect_single_flow(
            session,
            "parsing/mpls/03_mpls_ipv6_tcp_single_label.pcap",
            FlowAddressFamily::ipv6,
            "TCP",
            1U
        );

        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_EXPECT(details.has_value());
        PFL_EXPECT(details->has_mpls);
        PFL_EXPECT(details->has_ipv6);
        PFL_EXPECT(details->has_tcp);

        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet);
        expect_layer_prefix(summary_layers, {"frame", "ethernet", "mpls", "ipv6", "tcp"});
    }

    {
        CaptureSession session {};
        expect_single_flow(
            session,
            "parsing/mpls/04_mpls_ipv6_udp_single_label.pcap",
            FlowAddressFamily::ipv6,
            "UDP",
            1U
        );

        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_EXPECT(details.has_value());
        PFL_EXPECT(details->has_mpls);
        PFL_EXPECT(details->has_ipv6);
        PFL_EXPECT(details->has_udp);

        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet);
        expect_layer_prefix(summary_layers, {"frame", "ethernet", "mpls", "ipv6", "udp"});
    }

    {
        CaptureSession session {};
        expect_single_flow(
            session,
            "parsing/mpls/06_mpls_ipv4_udp_three_labels.pcap",
            FlowAddressFamily::ipv4,
            "UDP",
            1U
        );

        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_EXPECT(details.has_value());
        PFL_EXPECT(details->has_mpls);
        PFL_EXPECT(details->mpls_labels.size() == 3U);
        PFL_EXPECT(details->mpls_labels[0].label == 100U);
        PFL_EXPECT(details->mpls_labels[1].label == 200U);
        PFL_EXPECT(details->mpls_labels[2].label == 300U);

        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet);
        expect_layer_prefix(summary_layers, {"frame", "ethernet", "mpls", "mpls", "mpls", "ipv4", "udp"});
        PFL_EXPECT(count_layers(summary_layers, "mpls") == 3U);
        const auto* first_label = find_layer(summary_layers, "mpls", 0U);
        const auto* second_label = find_layer(summary_layers, "mpls", 1U);
        const auto* third_label = find_layer(summary_layers, "mpls", 2U);
        PFL_EXPECT(first_label != nullptr);
        PFL_EXPECT(second_label != nullptr);
        PFL_EXPECT(third_label != nullptr);
        expect_mpls_label_field(*first_label, "Label", "100");
        expect_mpls_label_field(*second_label, "Label", "200");
        expect_mpls_label_field(*third_label, "Label", "300");
    }

    {
        CaptureSession session {};
        expect_single_flow(
            session,
            "parsing/mpls/08_mpls_multicast_ethertype_ipv4_udp.pcap",
            FlowAddressFamily::ipv4,
            "UDP",
            1U
        );

        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_EXPECT(details.has_value());
        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet);
        const auto* ethernet_layer = find_layer(summary_layers, "ethernet");
        PFL_EXPECT(ethernet_layer != nullptr);
        const auto* type_field = find_field(*ethernet_layer, "Type");
        PFL_EXPECT(type_field != nullptr);
        PFL_EXPECT(type_field->value == "MPLS Multicast (0x8848)");
    }

    {
        CaptureSession session {};
        expect_single_flow(
            session,
            "parsing/mpls/09_mpls_ipv4_explicit_null_label.pcap",
            FlowAddressFamily::ipv4,
            "TCP",
            1U
        );

        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_EXPECT(details.has_value());
        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet);
        const auto* mpls_layer = find_layer(summary_layers, "mpls");
        PFL_EXPECT(mpls_layer != nullptr);
        expect_mpls_label_field(*mpls_layer, "Label", "0");
        expect_mpls_label_field(*mpls_layer, "Label Name", "IPv4 Explicit NULL");
    }

    {
        CaptureSession session {};
        expect_single_flow(
            session,
            "parsing/mpls/10_mpls_ipv6_explicit_null_label.pcap",
            FlowAddressFamily::ipv6,
            "TCP",
            1U
        );

        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_EXPECT(details.has_value());
        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet);
        const auto* mpls_layer = find_layer(summary_layers, "mpls");
        PFL_EXPECT(mpls_layer != nullptr);
        expect_mpls_label_field(*mpls_layer, "Label", "2");
        expect_mpls_label_field(*mpls_layer, "Label Name", "IPv6 Explicit NULL");
    }

    {
        CaptureSession session {};
        expect_single_flow(
            session,
            "parsing/mpls/11_mpls_router_alert_label.pcap",
            FlowAddressFamily::ipv4,
            "UDP",
            1U
        );

        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_EXPECT(details.has_value());
        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet);
        PFL_EXPECT(count_layers(summary_layers, "mpls") == 2U);
        const auto* first_mpls_layer = find_layer(summary_layers, "mpls", 0U);
        PFL_EXPECT(first_mpls_layer != nullptr);
        expect_mpls_label_field(*first_mpls_layer, "Label", "1");
        expect_mpls_label_field(*first_mpls_layer, "Label Name", "Router Alert");
    }

    {
        CaptureSession session {};
        expect_single_flow(
            session,
            "parsing/mpls/13_vlan_mpls_ipv4_tcp.pcap",
            FlowAddressFamily::ipv4,
            "TCP",
            1U
        );

        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_EXPECT(details.has_value());
        PFL_EXPECT(details->has_vlan);
        PFL_EXPECT(details->vlan_tags.size() == 1U);

        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet);
        PFL_EXPECT(find_layer(summary_layers, "frame") != nullptr);
        PFL_EXPECT(find_layer(summary_layers, "ethernet") != nullptr);
        PFL_EXPECT(count_layers(summary_layers, "vlan") == 1U);
        PFL_EXPECT(find_layer(summary_layers, "mpls") != nullptr);
        PFL_EXPECT(find_layer(summary_layers, "ipv4") != nullptr);
        PFL_EXPECT(find_layer(summary_layers, "tcp") != nullptr);
    }

    {
        CaptureSession session {};
        expect_single_flow(
            session,
            "parsing/mpls/14_qinq_mpls_ipv4_udp.pcap",
            FlowAddressFamily::ipv4,
            "UDP",
            1U
        );

        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_EXPECT(details.has_value());
        PFL_EXPECT(details->has_vlan);
        PFL_EXPECT(details->vlan_tags.size() == 2U);

        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet);
        PFL_EXPECT(find_layer(summary_layers, "frame") != nullptr);
        PFL_EXPECT(find_layer(summary_layers, "ethernet") != nullptr);
        PFL_EXPECT(count_layers(summary_layers, "vlan") == 2U);
        PFL_EXPECT(find_layer(summary_layers, "mpls") != nullptr);
        PFL_EXPECT(find_layer(summary_layers, "ipv4") != nullptr);
        PFL_EXPECT(find_layer(summary_layers, "udp") != nullptr);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/mpls/15_mpls_unknown_inner_payload.pcap")));
        PFL_EXPECT(session.list_flows().empty());
        PFL_EXPECT(session.unrecognized_packet_count() == 1U);
        const auto rows = session.list_unrecognized_packets(0U, 30U);
        PFL_EXPECT(rows.size() == 1U);
        PFL_EXPECT(
            rows[0].reason_text == "Unknown MPLS payload" ||
            rows[0].reason_text == "Unknown MPLS pseudowire inner EtherType"
        );

        const auto packet = require_packet(session, rows[0].packet_index);
        const auto details = session.read_packet_details(packet);
        PFL_EXPECT(details.has_value());
        PFL_EXPECT(details->has_mpls);
        PFL_EXPECT(!details->has_ipv4);
        PFL_EXPECT(!details->has_ipv6);
        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet);
        expect_layer_prefix(summary_layers, {"frame", "ethernet", "mpls"});
        PFL_EXPECT(count_layers(summary_layers, "mpls") == 1U);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/mpls/16_mpls_no_inner_payload.pcap")));
        PFL_EXPECT(session.list_flows().empty());
        PFL_EXPECT(session.unrecognized_packet_count() == 1U);
        const auto rows = session.list_unrecognized_packets(0U, 30U);
        PFL_EXPECT(rows.size() == 1U);
        PFL_EXPECT(rows[0].reason_text == "Missing MPLS inner payload");

        const auto packet = require_packet(session, rows[0].packet_index);
        const auto details = session.read_packet_details(packet);
        PFL_EXPECT(details.has_value());
        PFL_EXPECT(details->has_mpls);
        PFL_EXPECT(details->mpls_labels.size() == 1U);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/mpls/17_mpls_truncated_label_header.pcap")));
        PFL_EXPECT(session.list_flows().empty());
        PFL_EXPECT(session.unrecognized_packet_count() == 1U);
        const auto rows = session.list_unrecognized_packets(0U, 30U);
        PFL_EXPECT(rows.size() == 1U);
        PFL_EXPECT(rows[0].reason_text == "MPLS label header truncated");

        const auto packet = require_packet(session, rows[0].packet_index);
        const auto details = session.read_packet_details(packet);
        PFL_EXPECT(details.has_value());
        PFL_EXPECT(details->has_mpls);
        PFL_EXPECT(details->mpls_labels.empty());
        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet);
        expect_layer_prefix(summary_layers, {"frame", "ethernet"});
        PFL_EXPECT(find_layer(summary_layers, "mpls") == nullptr);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/mpls/18_mpls_stack_no_bos_before_payload_end.pcap")));
        PFL_EXPECT(session.list_flows().empty());
        PFL_EXPECT(session.unrecognized_packet_count() == 1U);
        const auto rows = session.list_unrecognized_packets(0U, 30U);
        PFL_EXPECT(rows.size() == 1U);
        PFL_EXPECT(rows[0].reason_text == "MPLS bottom-of-stack not found");

        const auto packet = require_packet(session, rows[0].packet_index);
        const auto details = session.read_packet_details(packet);
        PFL_EXPECT(details.has_value());
        PFL_EXPECT(details->has_mpls);
        PFL_EXPECT(details->mpls_labels.size() == 2U);
        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet);
        expect_layer_prefix(summary_layers, {"frame", "ethernet", "mpls", "mpls"});
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/mpls/19_mpls_second_label_truncated.pcap")));
        PFL_EXPECT(session.list_flows().empty());
        PFL_EXPECT(session.unrecognized_packet_count() == 1U);
        const auto rows = session.list_unrecognized_packets(0U, 30U);
        PFL_EXPECT(rows.size() == 1U);
        PFL_EXPECT(rows[0].reason_text == "MPLS label header truncated");

        const auto packet = require_packet(session, rows[0].packet_index);
        const auto details = session.read_packet_details(packet);
        PFL_EXPECT(details.has_value());
        PFL_EXPECT(details->has_mpls);
        PFL_EXPECT(details->mpls_labels.size() == 1U);
        PFL_EXPECT(details->mpls_labels[0].label == 800U);
        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet);
        expect_layer_prefix(summary_layers, {"frame", "ethernet", "mpls"});
        PFL_EXPECT(count_layers(summary_layers, "mpls") == 1U);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/mpls/21_mpls_snaplen_truncated_inner_tcp.pcap")));
        PFL_EXPECT(session.list_flows().empty());
        PFL_EXPECT(session.unrecognized_packet_count() == 1U);
        const auto rows = session.list_unrecognized_packets(0U, 30U);
        PFL_EXPECT(rows.size() == 1U);
        PFL_EXPECT(rows[0].reason_text == "Inner TCP header truncated");

        const auto packet = require_packet(session, rows[0].packet_index);
        const auto details = session.read_packet_details(packet);
        PFL_EXPECT(details.has_value());
        PFL_EXPECT(details->has_mpls);
        PFL_EXPECT(details->has_ipv4);
        PFL_EXPECT(!details->has_tcp);

        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet);
        PFL_EXPECT(find_layer(summary_layers, "warnings") != nullptr);
        PFL_EXPECT(find_layer(summary_layers, "mpls") != nullptr);
        PFL_EXPECT(find_layer(summary_layers, "ipv4") != nullptr);
        PFL_EXPECT(find_layer(summary_layers, "tcp") == nullptr);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/mpls/22_mpls_two_packets_same_ipv4_tcp_flow.pcap")));
        const auto rows = session.list_flows();
        PFL_EXPECT(rows.size() == 1U);
        PFL_EXPECT(rows[0].packet_count == 2U);
        PFL_EXPECT(rows[0].protocol_text == "TCP");
        PFL_EXPECT(session.unrecognized_packet_count() == 0U);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/mpls/23_mpls_same_inner_flow_different_labels.pcap")));
        const auto rows = session.list_flows();
        PFL_EXPECT(rows.size() == 1U);
        PFL_EXPECT(rows[0].packet_count == 2U);
        PFL_EXPECT(rows[0].protocol_text == "TCP");
        PFL_EXPECT(session.unrecognized_packet_count() == 0U);

        const auto first_packet = require_packet(session, 0U);
        const auto second_packet = require_packet(session, 1U);
        const auto first_details = session.read_packet_details(first_packet);
        const auto second_details = session.read_packet_details(second_packet);
        PFL_EXPECT(first_details.has_value());
        PFL_EXPECT(second_details.has_value());
        PFL_EXPECT(first_details->has_mpls);
        PFL_EXPECT(second_details->has_mpls);
        PFL_EXPECT(first_details->mpls_labels.size() == 1U);
        PFL_EXPECT(second_details->mpls_labels.size() == 1U);
        PFL_EXPECT(first_details->mpls_labels[0].label == 1100U);
        PFL_EXPECT(second_details->mpls_labels[0].label == 1200U);
    }
}

}  // namespace pfl::tests
