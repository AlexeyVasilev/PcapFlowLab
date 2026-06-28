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
    std::size_t index = 0U;
    for (const auto* expected_id : expected_ids) {
        PFL_EXPECT(layers[index].id == expected_id);
        ++index;
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

void expect_single_unrecognized_packet(
    CaptureSession& session,
    const std::filesystem::path& relative_path,
    const std::string& expected_reason
) {
    PFL_EXPECT(session.open_capture(fixture_path(relative_path)));
    PFL_EXPECT(session.list_flows().empty());
    PFL_EXPECT(session.unrecognized_packet_count() == 1U);
    const auto rows = session.list_unrecognized_packets(0U, 30U);
    PFL_EXPECT(rows.size() == 1U);
    PFL_EXPECT(rows[0].row_number == 1U);
    PFL_EXPECT(rows[0].packet_index == 0U);
    PFL_EXPECT(rows[0].reason_text == expected_reason);
}

}  // namespace

void run_vlan_pcap_fixture_tests() {
    {
        CaptureSession session {};
        expect_single_flow(
            session,
            "parsing/vlan/01_vlan_ipv4_tcp.pcap",
            FlowAddressFamily::ipv4,
            "TCP",
            1U
        );

        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_EXPECT(details.has_value());
        PFL_EXPECT(details->has_vlan);
        PFL_EXPECT(details->vlan_tags.size() == 1U);
        PFL_EXPECT(details->has_ipv4);
        PFL_EXPECT(details->has_tcp);

        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet);
        expect_layer_prefix(summary_layers, {"frame", "ethernet", "vlan", "ipv4", "tcp"});
        PFL_EXPECT(count_layers(summary_layers, "vlan") == 1U);
    }

    {
        CaptureSession session {};
        expect_single_flow(
            session,
            "parsing/vlan/02_vlan_ipv4_udp.pcap",
            FlowAddressFamily::ipv4,
            "UDP",
            1U
        );

        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_EXPECT(details.has_value());
        PFL_EXPECT(details->has_vlan);
        PFL_EXPECT(details->vlan_tags.size() == 1U);
        PFL_EXPECT(details->has_ipv4);
        PFL_EXPECT(details->has_udp);

        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet);
        expect_layer_prefix(summary_layers, {"frame", "ethernet", "vlan", "ipv4", "udp"});
    }

    {
        CaptureSession session {};
        expect_single_flow(
            session,
            "parsing/vlan/03_vlan_ipv6_tcp.pcap",
            FlowAddressFamily::ipv6,
            "TCP",
            1U
        );

        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_EXPECT(details.has_value());
        PFL_EXPECT(details->has_vlan);
        PFL_EXPECT(details->vlan_tags.size() == 1U);
        PFL_EXPECT(details->has_ipv6);
        PFL_EXPECT(details->has_tcp);

        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet);
        expect_layer_prefix(summary_layers, {"frame", "ethernet", "vlan", "ipv6", "tcp"});
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/vlan/04_vlan_arp.pcap")));
        PFL_EXPECT(session.summary().flow_count == 1U);
        PFL_EXPECT(session.unrecognized_packet_count() == 0U);
        const auto rows = session.list_flows();
        PFL_EXPECT(rows.size() == 1U);

        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_EXPECT(details.has_value());
        PFL_EXPECT(details->has_vlan);
        PFL_EXPECT(details->vlan_tags.size() == 1U);
        PFL_EXPECT(details->has_arp);

        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet);
        expect_layer_prefix(summary_layers, {"frame", "ethernet", "vlan", "arp"});
    }

    {
        CaptureSession session {};
        expect_single_flow(
            session,
            "parsing/vlan/05_qinq_ipv4_udp.pcap",
            FlowAddressFamily::ipv4,
            "UDP",
            1U
        );

        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_EXPECT(details.has_value());
        PFL_EXPECT(details->has_vlan);
        PFL_EXPECT(details->vlan_tags.size() == 2U);
        PFL_EXPECT(details->has_ipv4);
        PFL_EXPECT(details->has_udp);

        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet);
        expect_layer_prefix(summary_layers, {"frame", "ethernet", "vlan", "vlan", "ipv4", "udp"});
        PFL_EXPECT(count_layers(summary_layers, "vlan") == 2U);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/vlan/06_qinq_arp.pcap")));
        PFL_EXPECT(session.summary().flow_count == 1U);
        PFL_EXPECT(session.unrecognized_packet_count() == 0U);
        const auto rows = session.list_flows();
        PFL_EXPECT(rows.size() == 1U);

        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_EXPECT(details.has_value());
        PFL_EXPECT(details->has_vlan);
        PFL_EXPECT(details->vlan_tags.size() == 2U);
        PFL_EXPECT(details->has_arp);

        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet);
        expect_layer_prefix(summary_layers, {"frame", "ethernet", "vlan", "vlan", "arp"});
    }

    {
        CaptureSession session {};
        expect_single_flow(
            session,
            "parsing/vlan/07_legacy_9100_vlan_ipv4_udp.pcap",
            FlowAddressFamily::ipv4,
            "UDP",
            1U
        );

        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_EXPECT(details.has_value());
        PFL_EXPECT(details->has_vlan);
        PFL_EXPECT(details->vlan_tags.size() == 1U);
        PFL_EXPECT(details->vlan_tags[0].tpid == 0x9100U);
        PFL_EXPECT(details->has_ipv4);
        PFL_EXPECT(details->has_udp);

        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet);
        expect_layer_prefix(summary_layers, {"frame", "ethernet", "vlan", "ipv4", "udp"});
    }

    {
        CaptureSession session {};
        expect_single_flow(
            session,
            "parsing/vlan/08_triple_vlan_ipv4_tcp.pcap",
            FlowAddressFamily::ipv4,
            "TCP",
            1U
        );

        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_EXPECT(details.has_value());
        PFL_EXPECT(details->has_vlan);
        PFL_EXPECT(details->vlan_tags.size() == 3U);
        PFL_EXPECT(details->has_ipv4);
        PFL_EXPECT(details->has_tcp);

        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet);
        expect_layer_prefix(summary_layers, {"frame", "ethernet", "vlan", "vlan", "vlan", "ipv4", "tcp"});
        PFL_EXPECT(count_layers(summary_layers, "vlan") == 3U);
    }

    {
        CaptureSession session {};
        expect_single_unrecognized_packet(
            session,
            "parsing/vlan/09_vlan_unknown_inner_ethertype.pcap",
            "Unsupported or malformed packet"
        );

        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_EXPECT(details.has_value());
        PFL_EXPECT(details->has_ethernet);
        PFL_EXPECT(details->has_vlan);
        PFL_EXPECT(details->vlan_tags.size() == 1U);
        PFL_EXPECT(!details->has_ipv4);
        PFL_EXPECT(!details->has_ipv6);
        PFL_EXPECT(!details->has_arp);

        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet);
        expect_layer_prefix(summary_layers, {"frame", "ethernet", "vlan"});
    }

    {
        CaptureSession session {};
        expect_single_unrecognized_packet(
            session,
            "parsing/vlan/10_vlan_truncated_tag.pcap",
            "Link-layer header truncated"
        );

        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_EXPECT(details.has_value());
        PFL_EXPECT(details->has_ethernet);
        PFL_EXPECT(details->has_vlan);
        PFL_EXPECT(details->vlan_tags.empty());
        PFL_EXPECT(details->vlan_tag_truncated);
        PFL_EXPECT(details->truncated_vlan_tpid == 0x8100U);

        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet);
        PFL_EXPECT(find_layer(summary_layers, "warnings") != nullptr);
        expect_layer_prefix(summary_layers, {"warnings", "frame", "ethernet", "vlan"});
    }

    {
        CaptureSession session {};
        expect_single_unrecognized_packet(
            session,
            "parsing/vlan/11_vlan_truncated_inner_ipv4.pcap",
            "IPv4 header truncated"
        );

        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_EXPECT(details.has_value());
        PFL_EXPECT(details->has_ethernet);
        PFL_EXPECT(details->has_vlan);
        PFL_EXPECT(details->vlan_tags.size() == 1U);
        PFL_EXPECT(!details->has_ipv4);

        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet);
        PFL_EXPECT(find_layer(summary_layers, "warnings") != nullptr);
        expect_layer_prefix(summary_layers, {"warnings", "frame", "ethernet", "vlan"});
        PFL_EXPECT(find_layer(summary_layers, "ipv4") == nullptr);
    }
}

}  // namespace pfl::tests
