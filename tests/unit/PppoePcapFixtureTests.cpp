#include <algorithm>
#include <filesystem>
#include <string>
#include <vector>

#include "TestSupport.h"
#include "app/session/CaptureSession.h"
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

UnrecognizedPacketRow expect_single_unrecognized_packet(
    CaptureSession& session,
    const std::filesystem::path& relative_path
) {
    PFL_EXPECT(session.open_capture(fixture_path(relative_path)));
    PFL_EXPECT(session.summary().packet_count == 0U);
    PFL_EXPECT(session.list_flows().empty());
    PFL_EXPECT(session.unrecognized_packet_count() == 1U);

    const auto rows = session.list_unrecognized_packets(0U, 30U);
    PFL_EXPECT(rows.size() == 1U);
    PFL_EXPECT(rows[0].row_number == 1U);
    PFL_EXPECT(rows[0].packet_index == 0U);
    PFL_EXPECT(!rows[0].reason_text.empty());
    PFL_EXPECT(rows[0].captured_length > 0U);
    PFL_EXPECT(rows[0].original_length >= rows[0].captured_length);
    return rows[0];
}

void expect_ethernet_only_unrecognized(
    CaptureSession& session,
    const std::filesystem::path& relative_path,
    const std::uint16_t expected_ether_type
) {
    const auto row = expect_single_unrecognized_packet(session, relative_path);
    const auto packet = require_packet(session, row.packet_index);
    const auto details = session.read_packet_details(packet);
    PFL_EXPECT(details.has_value());
    PFL_EXPECT(details->has_ethernet);
    PFL_EXPECT(details->ethernet.ether_type == expected_ether_type);
    PFL_EXPECT(!details->has_vlan);
    PFL_EXPECT(!details->has_arp);
    PFL_EXPECT(!details->has_ipv4);
    PFL_EXPECT(!details->has_ipv6);
    PFL_EXPECT(!details->has_tcp);
    PFL_EXPECT(!details->has_udp);

    const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet);
    PFL_EXPECT(find_layer(summary_layers, "frame") != nullptr);
    PFL_EXPECT(find_layer(summary_layers, "ethernet") != nullptr);
    PFL_EXPECT(find_layer(summary_layers, "vlan") == nullptr);
}

void expect_vlan_wrapped_unrecognized(
    CaptureSession& session,
    const std::filesystem::path& relative_path,
    const std::size_t expected_vlan_count
) {
    const auto row = expect_single_unrecognized_packet(session, relative_path);
    const auto packet = require_packet(session, row.packet_index);
    const auto details = session.read_packet_details(packet);
    PFL_EXPECT(details.has_value());
    PFL_EXPECT(details->has_ethernet);
    PFL_EXPECT(details->has_vlan);
    PFL_EXPECT(details->vlan_tags.size() == expected_vlan_count);
    PFL_EXPECT(!details->has_arp);
    PFL_EXPECT(!details->has_ipv4);
    PFL_EXPECT(!details->has_ipv6);
    PFL_EXPECT(!details->has_tcp);
    PFL_EXPECT(!details->has_udp);

    const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet);
    PFL_EXPECT(find_layer(summary_layers, "frame") != nullptr);
    PFL_EXPECT(find_layer(summary_layers, "ethernet") != nullptr);
    PFL_EXPECT(count_layers(summary_layers, "vlan") == expected_vlan_count);
}

}  // namespace

void run_pppoe_pcap_fixture_tests() {
    // Current expectation: PPPoE parser support is not implemented yet, so
    // session data candidates remain safe unrecognized packets instead of
    // becoming normal IPv4/IPv6 flows. Future PPPoE parser work can tighten
    // these expectations.
    for (const auto* relative_path : {
             "parsing/pppoe/01_pppoe_session_ipv4_tcp.pcap",
             "parsing/pppoe/02_pppoe_session_ipv4_udp.pcap",
             "parsing/pppoe/03_pppoe_session_ipv6_tcp.pcap",
             "parsing/pppoe/04_pppoe_session_ipv6_udp.pcap",
         }) {
        CaptureSession session {};
        expect_ethernet_only_unrecognized(session, relative_path, 0x8864U);
    }

    // Current expectation: PPP control protocols remain safe and inspectable
    // only as unrecognized packets until PPPoE/PPP decoding is introduced.
    for (const auto* relative_path : {
             "parsing/pppoe/05_pppoe_session_lcp_config_request.pcap",
             "parsing/pppoe/06_pppoe_session_ipcp_config_request.pcap",
             "parsing/pppoe/07_pppoe_session_ipv6cp_config_request.pcap",
         }) {
        CaptureSession session {};
        expect_ethernet_only_unrecognized(session, relative_path, 0x8864U);
    }

    // Current expectation: discovery packets stay outside normal flow
    // extraction and remain conservative/unrecognized.
    for (const auto* relative_path : {
             "parsing/pppoe/08_pppoe_discovery_padi.pcap",
             "parsing/pppoe/09_pppoe_discovery_pado.pcap",
             "parsing/pppoe/10_pppoe_discovery_padr.pcap",
             "parsing/pppoe/11_pppoe_discovery_pads.pcap",
             "parsing/pppoe/12_pppoe_discovery_padt.pcap",
         }) {
        CaptureSession session {};
        expect_ethernet_only_unrecognized(session, relative_path, 0x8863U);
    }

    // Current expectation: existing VLAN/QinQ support preserves outer shim
    // details, but PPPoE still blocks inner IPv4/UDP/TCP flow extraction.
    {
        CaptureSession session {};
        expect_vlan_wrapped_unrecognized(
            session,
            "parsing/pppoe/13_vlan_pppoe_session_ipv4_tcp.pcap",
            1U
        );
    }

    {
        CaptureSession session {};
        expect_vlan_wrapped_unrecognized(
            session,
            "parsing/pppoe/14_qinq_pppoe_session_ipv4_udp.pcap",
            2U
        );
    }

    // Current expectation: unknown protocol, malformed, truncated, and
    // length-mismatch cases stay safe and visible as unrecognized packets.
    for (const auto* relative_path : {
             "parsing/pppoe/15_pppoe_session_unknown_ppp_protocol.pcap",
             "parsing/pppoe/16_pppoe_truncated_header.pcap",
             "parsing/pppoe/17_pppoe_truncated_ppp_protocol.pcap",
             "parsing/pppoe/18_pppoe_truncated_inner_ipv4.pcap",
             "parsing/pppoe/19_pppoe_bad_length_short_payload.pcap",
             "parsing/pppoe/20_pppoe_bad_length_extra_payload.pcap",
         }) {
        CaptureSession session {};
        expect_single_unrecognized_packet(session, relative_path);
        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_EXPECT(details.has_value());
        PFL_EXPECT(details->has_ethernet);
    }
}

}  // namespace pfl::tests
