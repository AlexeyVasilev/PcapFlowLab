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

void expect_open_fixture(CaptureSession& session, const std::filesystem::path& relative_path) {
    PFL_EXPECT(session.open_capture(fixture_path(relative_path)));
}

void expect_conservative_no_flow_macsec_fixture(
    CaptureSession& session,
    const std::filesystem::path& relative_path
) {
    expect_open_fixture(session, relative_path);
    PFL_EXPECT(session.list_flows().empty());
    PFL_EXPECT(session.unrecognized_packet_count() == 1U);

    const auto rows = session.list_unrecognized_packets(0U, 30U);
    PFL_EXPECT(rows.size() == 1U);
    if (!rows.empty()) {
        PFL_EXPECT(rows[0].row_number == 1U);
        PFL_EXPECT(rows[0].packet_index == 0U);
        PFL_EXPECT(!rows[0].reason_text.empty());
    }

    const auto packet = require_packet(session, 0U);
    const auto details = session.read_packet_details(packet);
    PFL_EXPECT(details.has_value());
    if (!details.has_value()) {
        return;
    }

    // Current baseline: outer Ethernet/VLAN may be visible, but MACsec itself
    // is not parsed yet and protected payload must not fabricate higher layers.
    PFL_EXPECT(details->has_ethernet);
    PFL_EXPECT(!details->has_pbb);
    PFL_EXPECT(!details->has_mpls);
    PFL_EXPECT(!details->has_pppoe);
    PFL_EXPECT(!details->has_llc);
    PFL_EXPECT(!details->has_snap);
    PFL_EXPECT(!details->has_arp);
    PFL_EXPECT(!details->has_ipv4);
    PFL_EXPECT(!details->has_ipv6);
    PFL_EXPECT(!details->has_tcp);
    PFL_EXPECT(!details->has_udp);
}

void expect_outer_vlan_envelope_only(
    CaptureSession& session,
    const std::filesystem::path& relative_path,
    const std::size_t expected_vlan_count
) {
    expect_conservative_no_flow_macsec_fixture(session, relative_path);

    const auto packet = require_packet(session, 0U);
    const auto details = session.read_packet_details(packet);
    PFL_EXPECT(details.has_value());
    if (!details.has_value()) {
        return;
    }

    PFL_EXPECT(details->has_vlan);
    PFL_EXPECT(details->vlan_tags.size() == expected_vlan_count);

    const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet);
    if (expected_vlan_count == 1U) {
        expect_layer_prefix(summary_layers, {"frame", "ethernet", "vlan"});
    } else {
        expect_layer_prefix(summary_layers, {"frame", "ethernet", "vlan", "vlan"});
    }

    for (std::size_t index = 0; index < expected_vlan_count; ++index) {
        const auto* vlan_layer = find_layer(summary_layers, "vlan", index);
        PFL_EXPECT(vlan_layer != nullptr);
    }
}

}  // namespace

void run_macsec_pcap_fixture_tests() {
    // 01-05: future MACsec SecTAG presentation candidates. Current baseline is
    // conservative no-flow / no protected-payload decode.
    {
        CaptureSession session {};
        expect_conservative_no_flow_macsec_fixture(session, "parsing/macsec/01_macsec_basic_no_sci.pcap");
    }

    {
        CaptureSession session {};
        expect_conservative_no_flow_macsec_fixture(session, "parsing/macsec/02_macsec_sci_present.pcap");
    }

    {
        CaptureSession session {};
        expect_conservative_no_flow_macsec_fixture(session, "parsing/macsec/03_macsec_an2_nonzero_pn_sci.pcap");
    }

    {
        CaptureSession session {};
        expect_conservative_no_flow_macsec_fixture(
            session,
            "parsing/macsec/04_macsec_integrity_only_cleartext_like_payload.pcap"
        );
    }

    {
        CaptureSession session {};
        expect_conservative_no_flow_macsec_fixture(session, "parsing/macsec/05_macsec_short_length_nonzero.pcap");
    }

    // 06-07: outer VLAN/QinQ envelope should remain visible before unknown 0x88e5.
    {
        CaptureSession session {};
        expect_outer_vlan_envelope_only(session, "parsing/macsec/06_vlan_macsec_sci.pcap", 1U);
    }

    {
        CaptureSession session {};
        expect_outer_vlan_envelope_only(session, "parsing/macsec/07_qinq_macsec_basic.pcap", 2U);
    }

    // 08-09: more TCI flag future-presentation candidates. Still conservative today.
    {
        CaptureSession session {};
        expect_conservative_no_flow_macsec_fixture(session, "parsing/macsec/08_macsec_scb_flag.pcap");
    }

    {
        CaptureSession session {};
        expect_conservative_no_flow_macsec_fixture(session, "parsing/macsec/09_macsec_es_flag.pcap");
    }

    // 10-13: malformed/truncated robustness fixtures. No crash, no flow, and
    // no accidental decode of the protected payload.
    {
        CaptureSession session {};
        expect_conservative_no_flow_macsec_fixture(session, "parsing/macsec/10_macsec_truncated_base_sectag.pcap");
    }

    {
        CaptureSession session {};
        expect_conservative_no_flow_macsec_fixture(session, "parsing/macsec/11_macsec_truncated_packet_number.pcap");
    }

    {
        CaptureSession session {};
        expect_conservative_no_flow_macsec_fixture(session, "parsing/macsec/12_macsec_truncated_sci.pcap");
    }

    {
        CaptureSession session {};
        expect_conservative_no_flow_macsec_fixture(
            session,
            "parsing/macsec/13_macsec_missing_icv_or_short_payload.pcap"
        );
    }

    // 14-15: metadata robustness and cleartext-looking protected payload that
    // must still not become fake IPv4/UDP flows.
    {
        CaptureSession session {};
        expect_conservative_no_flow_macsec_fixture(session, "parsing/macsec/14_macsec_zero_packet_number.pcap");
    }

    {
        CaptureSession session {};
        expect_conservative_no_flow_macsec_fixture(
            session,
            "parsing/macsec/15_macsec_protected_payload_ipv4_like_no_decode.pcap"
        );
    }
}

}  // namespace pfl::tests
