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

std::size_t count_layers(
    const std::vector<session_detail::PacketSummaryLayer>& layers,
    const std::string& id
) {
    return static_cast<std::size_t>(std::count_if(layers.begin(), layers.end(), [&](const session_detail::PacketSummaryLayer& layer) {
        return layer.id == id;
    }));
}

void expect_single_unrecognized_mpls_pseudowire_packet(
    const std::filesystem::path& relative_path,
    const std::string& expected_reason,
    const std::size_t expected_mpls_layers,
    const bool expect_partial_mpls_details = true
) {
    CaptureSession session {};
    PFL_EXPECT(session.open_capture(fixture_path(relative_path)));
    PFL_EXPECT(session.list_flows().empty());
    PFL_EXPECT(session.unrecognized_packet_count() == 1U);

    const auto rows = session.list_unrecognized_packets(0U, 30U);
    PFL_EXPECT(rows.size() == 1U);
    PFL_EXPECT(rows[0].row_number == 1U);
    PFL_EXPECT(rows[0].packet_index == 0U);
    PFL_EXPECT(rows[0].reason_text == expected_reason);

    const auto packet = require_packet(session, rows[0].packet_index);
    const auto details = session.read_packet_details(packet);
    PFL_EXPECT(details.has_value());
    PFL_EXPECT(details->has_ethernet);
    PFL_EXPECT(details->has_mpls == expect_partial_mpls_details);
    PFL_EXPECT(!details->has_ipv4);
    PFL_EXPECT(!details->has_ipv6);
    PFL_EXPECT(!details->has_arp);
    PFL_EXPECT(!details->has_vlan);

    const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet);
    if (expected_mpls_layers == 0U) {
        PFL_EXPECT(find_layer(summary_layers, "frame") != nullptr);
        PFL_EXPECT(find_layer(summary_layers, "ethernet") != nullptr);
        PFL_EXPECT(find_layer(summary_layers, "mpls") == nullptr);
    } else {
        PFL_EXPECT(find_layer(summary_layers, "frame") != nullptr);
        PFL_EXPECT(find_layer(summary_layers, "ethernet") != nullptr);
        PFL_EXPECT(count_layers(summary_layers, "mpls") == expected_mpls_layers);
        const auto* first_mpls_layer = find_layer(summary_layers, "mpls");
        PFL_EXPECT(first_mpls_layer != nullptr);
        PFL_EXPECT(layer_has_field_containing(*first_mpls_layer, "Label", ""));
    }
}

}  // namespace

void run_mpls_pseudowire_pcap_fixture_tests() {
    for (const auto* relative_path : {
             "parsing/mpls_pw/01_mpls_pw_eth_ipv4_tcp_no_cw.pcap",
             "parsing/mpls_pw/02_mpls_pw_eth_ipv4_udp_no_cw.pcap",
             "parsing/mpls_pw/03_mpls_pw_eth_ipv6_tcp_cw.pcap",
             "parsing/mpls_pw/04_mpls_pw_eth_ipv6_udp_cw.pcap",
             "parsing/mpls_pw/05_mpls_pw_eth_arp_cw.pcap",
             "parsing/mpls_pw/06_mpls_pw_eth_vlan_ipv4_tcp_cw.pcap",
             "parsing/mpls_pw/07_mpls_pw_eth_qinq_ipv4_udp_cw.pcap",
             "parsing/mpls_pw/08_mpls_pw_eth_llc_snap_ipv4_udp_cw.pcap",
             "parsing/mpls_pw/09_mpls_pw_unknown_inner_ethertype_cw.pcap",
             "parsing/mpls_pw/11_mpls_pw_truncated_control_word.pcap",
             "parsing/mpls_pw/12_mpls_pw_truncated_inner_ethernet.pcap",
             "parsing/mpls_pw/13_mpls_pw_truncated_inner_ipv4.pcap",
             "parsing/mpls_pw/14_mpls_pw_control_word_with_sequence.pcap",
             "parsing/mpls_pw/15_mpls_pw_ambiguous_no_cw_inner_ethernet.pcap",
         }) {
        expect_single_unrecognized_mpls_pseudowire_packet(
            relative_path,
            "Unknown MPLS payload",
            2U
        );
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/mpls_pw/10_mpls_pw_truncated_label_stack.pcap")));
        PFL_EXPECT(session.list_flows().empty());
        PFL_EXPECT(session.unrecognized_packet_count() == 1U);

        const auto rows = session.list_unrecognized_packets(0U, 30U);
        PFL_EXPECT(rows.size() == 1U);
        PFL_EXPECT(rows[0].reason_text == "MPLS label header truncated");

        const auto packet = require_packet(session, rows[0].packet_index);
        const auto details = session.read_packet_details(packet);
        PFL_EXPECT(details.has_value());
        PFL_EXPECT(details->has_ethernet);
        PFL_EXPECT(details->has_mpls);
        PFL_EXPECT(details->mpls_labels.empty());
        PFL_EXPECT(!details->has_ipv4);
        PFL_EXPECT(!details->has_ipv6);

        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet);
        PFL_EXPECT(find_layer(summary_layers, "frame") != nullptr);
        PFL_EXPECT(find_layer(summary_layers, "ethernet") != nullptr);
        PFL_EXPECT(find_layer(summary_layers, "mpls") == nullptr);
    }
}

}  // namespace pfl::tests
