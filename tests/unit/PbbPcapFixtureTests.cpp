#include <algorithm>
#include <filesystem>
#include <initializer_list>
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

bool layer_has_field_label(
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
    std::size_t index = 0U;
    for (const auto* expected_id : expected_ids) {
        PFL_EXPECT(layers[index].id == expected_id);
        ++index;
    }
}

void expect_open_and_basic_open_state(CaptureSession& session, const std::filesystem::path& relative_path) {
    PFL_EXPECT(session.open_capture(fixture_path(relative_path)));
    PFL_EXPECT(session.summary().packet_count == 0U);
    PFL_EXPECT(session.summary().flow_count == 0U);
}

void expect_current_conservative_pbb_no_flow(
    const std::filesystem::path& relative_path,
    const std::size_t expected_outer_vlan_count = 0U
) {
    CaptureSession session {};
    expect_open_and_basic_open_state(session, relative_path);

    PFL_EXPECT(session.list_flows().empty());
    PFL_EXPECT(session.unrecognized_packet_count() == 1U);

    const auto rows = session.list_unrecognized_packets(0U, 30U);
    PFL_EXPECT(rows.size() == 1U);
    PFL_EXPECT(rows[0].row_number == 1U);
    PFL_EXPECT(rows[0].packet_index == 0U);
    PFL_EXPECT(rows[0].reason_text == "Unsupported or malformed packet");

    const auto packet = require_packet(session, 0U);
    const auto details = session.read_packet_details(packet);
    PFL_EXPECT(details.has_value());
    PFL_EXPECT(details->has_ethernet);
    PFL_EXPECT(!details->has_ipv4);
    PFL_EXPECT(!details->has_ipv6);
    PFL_EXPECT(!details->has_arp);
    PFL_EXPECT(details->has_vlan == (expected_outer_vlan_count > 0U));
    PFL_EXPECT(details->vlan_tags.size() == expected_outer_vlan_count);

    const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet);
    if (expected_outer_vlan_count == 0U) {
        expect_layer_prefix(summary_layers, {"frame", "ethernet"});
    } else {
        expect_layer_prefix(summary_layers, {"frame", "ethernet", "vlan"});
    }

    const auto* ethernet_layer = find_layer(summary_layers, "ethernet");
    PFL_EXPECT(ethernet_layer != nullptr);
    PFL_EXPECT(layer_has_field_label(*ethernet_layer, "Type"));

    if (expected_outer_vlan_count > 0U) {
        const auto* vlan_layer = find_layer(summary_layers, "vlan");
        PFL_EXPECT(vlan_layer != nullptr);
        PFL_EXPECT(layer_has_field_label(*vlan_layer, "Encapsulated EtherType"));
    }
}

}  // namespace

void run_pbb_pcap_fixture_tests() {
    // Future-flow MAC-in-MAC candidates. Current conservative baseline is no-flow
    // until 0x88e7 / I-TAG / inner Ethernet continuation support is implemented.
    expect_current_conservative_pbb_no_flow("parsing/pbb/01_pbb_ipv4_tcp.pcap");
    expect_current_conservative_pbb_no_flow("parsing/pbb/02_pbb_ipv4_udp.pcap");
    expect_current_conservative_pbb_no_flow("parsing/pbb/03_pbb_ipv6_tcp.pcap");
    expect_current_conservative_pbb_no_flow("parsing/pbb/04_pbb_ipv6_udp.pcap");
    expect_current_conservative_pbb_no_flow("parsing/pbb/05_pbb_arp.pcap");

    // Future composition candidates. For now they still remain conservative because
    // there is no shared PBB continuation into the inner Ethernet envelope yet.
    expect_current_conservative_pbb_no_flow("parsing/pbb/06_pbb_inner_vlan_ipv4_tcp.pcap");
    expect_current_conservative_pbb_no_flow("parsing/pbb/07_pbb_inner_qinq_ipv4_udp.pcap");
    expect_current_conservative_pbb_no_flow("parsing/pbb/08_pbb_inner_llc_snap_ipv4_udp.pcap");

    // Outer provider VLAN before 0x88e7 is preserved by existing VLAN support even
    // though the inner PBB payload still remains no-flow today.
    expect_current_conservative_pbb_no_flow("parsing/pbb/09_pbb_outer_btag_ipv4_udp.pcap", 1U);
    expect_current_conservative_pbb_no_flow("parsing/pbb/10_pbb_outer_btag_inner_vlan_ipv4_tcp.pcap", 1U);

    // Unknown inner EtherType remains conservative, but current parser still stops
    // before any inner PBB continuation, so the stable externally visible behavior
    // matches the generic 0x88e7 no-flow baseline.
    expect_current_conservative_pbb_no_flow("parsing/pbb/11_pbb_unknown_inner_ethertype.pcap");

    // Malformed/truncated PBB cases are currently safe no-flow robustness fixtures.
    // No richer I-TAG or inner-header truncation reporting is required yet.
    expect_current_conservative_pbb_no_flow("parsing/pbb/12_pbb_truncated_itag.pcap");
    expect_current_conservative_pbb_no_flow("parsing/pbb/13_pbb_truncated_inner_ethernet.pcap");
    expect_current_conservative_pbb_no_flow("parsing/pbb/14_pbb_truncated_inner_ipv4.pcap");

    // Non-default I-TAG metadata is a future presentation candidate. Current
    // conservative behavior still stops at outer Ethernet only.
    expect_current_conservative_pbb_no_flow("parsing/pbb/15_pbb_metadata_nondefault_itag.pcap");
}

}  // namespace pfl::tests
