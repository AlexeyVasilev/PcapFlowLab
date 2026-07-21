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

UnrecognizedPacketRow expect_single_macsec_no_flow_packet(
    CaptureSession& session,
    const std::filesystem::path& relative_path,
    const std::string& expected_reason
) {
    const ScopedTestContext fixture_context {"fixture=" + relative_path.string()};
    PFL_EXPECT(session.open_capture(fixture_path(relative_path)));
    PFL_EXPECT(session.summary().packet_count == 0U);
    PFL_EXPECT(session.summary().flow_count == 0U);
    PFL_EXPECT(session.list_flows().empty());
    PFL_EXPECT(session.unrecognized_packet_count() == 1U);
    PFL_EXPECT(session.state().protocol_path_registry.size() == 0U);
    const auto storage = session.storage_summary();
    PFL_EXPECT(storage.recognized_packets == 0U);
    PFL_EXPECT(storage.unrecognized_packets == 1U);
    PFL_EXPECT(storage.total_packets_seen == 1U);

    const auto rows = session.list_unrecognized_packets(0U, 30U);
    PFL_REQUIRE(rows.size() == 1U);
    PFL_EXPECT(rows[0].row_number == 1U);
    PFL_EXPECT(rows[0].packet_index == 0U);
    PFL_EXPECT(rows[0].reason_text == expected_reason);
    return rows[0];
}

PacketDetails require_macsec_details(
    CaptureSession& session,
    const std::uint64_t packet_index
) {
    const auto packet = require_packet(session, packet_index);
    const auto details = session.read_packet_details(packet);
    PFL_REQUIRE(details.has_value());
    if (!details.has_value()) {
        return {};
    }
    PFL_EXPECT(details->has_ethernet);
    PFL_EXPECT(details->has_macsec);
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
    return *details;
}

void expect_macsec_protocol_text_contains(
    CaptureSession& session,
    const PacketRef& packet,
    std::initializer_list<const char*> fragments
) {
    const auto text = session.read_packet_protocol_details_text(packet);
    for (const auto* fragment : fragments) {
        PFL_EXPECT(text.find(fragment) != std::string::npos);
    }
}

void expect_complete_macsec_fixture(
    CaptureSession& session,
    const std::filesystem::path& relative_path,
    std::initializer_list<const char*> expected_layer_prefix,
    const bool expect_sc,
    const std::string& expected_packet_number_text,
    const bool expect_plain_ether_type = false
) {
    const auto row = expect_single_macsec_no_flow_packet(
        session,
        relative_path,
        "MACsec protected payload not decrypted"
    );
    const auto packet = require_packet(session, row.packet_index);
    const auto details = require_macsec_details(session, row.packet_index);
    PFL_EXPECT(details.macsec.present);
    PFL_EXPECT(!details.macsec.sectag_truncated);
    PFL_EXPECT(!details.macsec.packet_number_truncated);
    PFL_EXPECT(!details.macsec.sci_truncated);
    PFL_EXPECT(!details.macsec.icv_truncated);
    PFL_EXPECT(details.macsec.packet_number_present);
    PFL_EXPECT(details.macsec.sc == expect_sc);
    PFL_EXPECT(details.macsec.protected_payload_length > 0U);
    PFL_EXPECT(!details.macsec.protected_payload_preview.empty());
    PFL_EXPECT(details.macsec.icv_length == 16U);

    const auto summary_layers = session_detail::build_packet_summary_layers(details, packet);
    expect_layer_prefix(summary_layers, expected_layer_prefix);
    const auto* macsec_layer = find_layer(summary_layers, "macsec");
    PFL_REQUIRE(macsec_layer != nullptr);
    PFL_EXPECT(layer_has_field_containing(*macsec_layer, "Packet Number", expected_packet_number_text));
    const auto* payload_layer = find_layer(summary_layers, "macsec-payload");
    PFL_REQUIRE(payload_layer != nullptr);
    PFL_EXPECT(layer_has_field_containing(*payload_layer, "Length", "bytes"));
    PFL_EXPECT(layer_has_field_label(*payload_layer, "Raw"));
    PFL_EXPECT(layer_has_field_label(*payload_layer, "Plain EtherType") == expect_plain_ether_type);
    const auto* icv_layer = find_layer(summary_layers, "macsec-icv");
    PFL_REQUIRE(icv_layer != nullptr);
    PFL_EXPECT(layer_has_field_containing(*icv_layer, "Length", "16 bytes"));

    expect_macsec_protocol_text_contains(session, packet, {
        "Protocol: MACsec / IEEE 802.1AE",
        "Protected payload is not decrypted.",
    });
    const auto protocol_text = session.read_packet_protocol_details_text(packet);
    PFL_EXPECT((protocol_text.find("Plain EtherType:") != std::string::npos) == expect_plain_ether_type);
}

}  // namespace

void run_macsec_pcap_fixture_tests() {
    {
        CaptureSession session {};
        expect_complete_macsec_fixture(
            session,
            "parsing/macsec/01_macsec_basic_no_sci.pcap",
            {"frame", "ethernet", "macsec", "macsec-payload", "macsec-icv"},
            false,
            "0x01020304 (16909060)"
        );
        const auto details = require_macsec_details(session, 0U);
        PFL_EXPECT(details.macsec.available_base_bytes == 6U);
        PFL_EXPECT(details.macsec.version == 0U);
        PFL_EXPECT(!details.macsec.es);
        PFL_EXPECT(!details.macsec.sc);
        PFL_EXPECT(!details.macsec.scb);
        PFL_EXPECT(details.macsec.encrypted);
        PFL_EXPECT(details.macsec.changed);
        PFL_EXPECT(details.macsec.association_number == 0U);
        PFL_EXPECT(details.macsec.short_length == 0U);
        PFL_EXPECT(details.macsec.available_sci_bytes == 0U);
    }

    {
        CaptureSession session {};
        expect_complete_macsec_fixture(
            session,
            "parsing/macsec/02_macsec_sci_present.pcap",
            {"frame", "ethernet", "macsec", "macsec-payload", "macsec-icv"},
            true,
            "0x01020304 (16909060)"
        );
        const auto packet = require_packet(session, 0U);
        const auto details = require_macsec_details(session, 0U);
        PFL_EXPECT(details.macsec.available_sci_bytes == 8U);
        const auto summary_layers = session_detail::build_packet_summary_layers(details, packet);
        const auto* macsec_layer = find_layer(summary_layers, "macsec");
        PFL_REQUIRE(macsec_layer != nullptr);
        PFL_EXPECT(layer_has_field_containing(*macsec_layer, "SCI System ID", "02:00:00:00:71:01"));
        PFL_EXPECT(layer_has_field_containing(*macsec_layer, "SCI Port ID", "0x0001"));
    }

    {
        CaptureSession session {};
        expect_complete_macsec_fixture(
            session,
            "parsing/macsec/03_macsec_an2_nonzero_pn_sci.pcap",
            {"frame", "ethernet", "macsec", "macsec-payload", "macsec-icv"},
            true,
            "0x0a0b0c0d (168496141)"
        );
        const auto packet = require_packet(session, 0U);
        const auto details = require_macsec_details(session, 0U);
        PFL_EXPECT(details.macsec.association_number == 2U);
        const auto summary_layers = session_detail::build_packet_summary_layers(details, packet);
        const auto* macsec_layer = find_layer(summary_layers, "macsec");
        PFL_REQUIRE(macsec_layer != nullptr);
        PFL_EXPECT(layer_has_field_containing(*macsec_layer, "Association Number", "2"));
    }

    {
        CaptureSession session {};
        expect_complete_macsec_fixture(
            session,
            "parsing/macsec/04_macsec_integrity_only_cleartext_like_payload.pcap",
            {"frame", "ethernet", "macsec", "macsec-payload", "macsec-icv"},
            false,
            "0x01020304 (16909060)",
            true
        );
        const auto packet = require_packet(session, 0U);
        const auto details = require_macsec_details(session, 0U);
        PFL_EXPECT(!details.macsec.encrypted);
        PFL_EXPECT(!details.macsec.changed);
        const auto summary_layers = session_detail::build_packet_summary_layers(details, packet);
        const auto* macsec_layer = find_layer(summary_layers, "macsec");
        PFL_REQUIRE(macsec_layer != nullptr);
        PFL_EXPECT(layer_has_field_containing(*macsec_layer, "Encrypted (E)", "0"));
        PFL_EXPECT(layer_has_field_containing(*macsec_layer, "Changed (C)", "0"));
        const auto* payload_layer = find_layer(summary_layers, "macsec-payload");
        PFL_REQUIRE(payload_layer != nullptr);
        PFL_EXPECT(layer_has_field_containing(*payload_layer, "Plain EtherType", "0x4500"));
        PFL_EXPECT(layer_has_field_containing(*payload_layer, "Data Length", "33 bytes"));
        const auto protocol_text = session.read_packet_protocol_details_text(packet);
        PFL_EXPECT(protocol_text.find("Plain EtherType: 0x4500") != std::string::npos);
        PFL_EXPECT(protocol_text.find("Data Length: 33 bytes") != std::string::npos);
    }

    {
        CaptureSession session {};
        expect_complete_macsec_fixture(
            session,
            "parsing/macsec/05_macsec_short_length_nonzero.pcap",
            {"frame", "ethernet", "macsec", "macsec-payload", "macsec-icv"},
            false,
            "0x01020304 (16909060)"
        );
        const auto packet = require_packet(session, 0U);
        const auto details = require_macsec_details(session, 0U);
        PFL_EXPECT(details.macsec.short_length == 32U);
        const auto summary_layers = session_detail::build_packet_summary_layers(details, packet);
        const auto* macsec_layer = find_layer(summary_layers, "macsec");
        PFL_REQUIRE(macsec_layer != nullptr);
        PFL_EXPECT(layer_has_field_containing(*macsec_layer, "Short Length", "32"));
    }

    {
        CaptureSession session {};
        expect_complete_macsec_fixture(
            session,
            "parsing/macsec/06_vlan_macsec_sci.pcap",
            {"frame", "ethernet", "vlan", "macsec", "macsec-payload", "macsec-icv"},
            true,
            "0x01020304 (16909060)"
        );
        const auto details = require_macsec_details(session, 0U);
        PFL_EXPECT(details.has_vlan);
        PFL_EXPECT(details.vlan_tags.size() == 1U);
        PFL_EXPECT(details.vlan_tags[0].tpid == 0x8100U);
        PFL_EXPECT((details.vlan_tags[0].tci & 0x0FFFU) == 700U);
    }

    {
        CaptureSession session {};
        expect_complete_macsec_fixture(
            session,
            "parsing/macsec/07_qinq_macsec_basic.pcap",
            {"frame", "ethernet", "vlan", "vlan", "macsec", "macsec-payload", "macsec-icv"},
            false,
            "0x01020304 (16909060)"
        );
        const auto details = require_macsec_details(session, 0U);
        PFL_EXPECT(details.has_vlan);
        PFL_EXPECT(details.vlan_tags.size() == 2U);
        PFL_EXPECT(details.vlan_tags[0].tpid == 0x88a8U);
        PFL_EXPECT((details.vlan_tags[0].tci & 0x0FFFU) == 710U);
        PFL_EXPECT(details.vlan_tags[1].tpid == 0x8100U);
        PFL_EXPECT((details.vlan_tags[1].tci & 0x0FFFU) == 720U);
    }

    {
        CaptureSession session {};
        expect_complete_macsec_fixture(
            session,
            "parsing/macsec/08_macsec_scb_flag.pcap",
            {"frame", "ethernet", "macsec", "macsec-payload", "macsec-icv"},
            false,
            "0x01020304 (16909060)"
        );
        const auto packet = require_packet(session, 0U);
        const auto details = require_macsec_details(session, 0U);
        PFL_EXPECT(details.macsec.scb);
        const auto summary_layers = session_detail::build_packet_summary_layers(details, packet);
        const auto* macsec_layer = find_layer(summary_layers, "macsec");
        PFL_REQUIRE(macsec_layer != nullptr);
        PFL_EXPECT(layer_has_field_containing(*macsec_layer, "SCB", "1"));
    }

    {
        CaptureSession session {};
        expect_complete_macsec_fixture(
            session,
            "parsing/macsec/09_macsec_es_flag.pcap",
            {"frame", "ethernet", "macsec", "macsec-payload", "macsec-icv"},
            false,
            "0x01020304 (16909060)"
        );
        const auto packet = require_packet(session, 0U);
        const auto details = require_macsec_details(session, 0U);
        PFL_EXPECT(details.macsec.es);
        const auto summary_layers = session_detail::build_packet_summary_layers(details, packet);
        const auto* macsec_layer = find_layer(summary_layers, "macsec");
        PFL_REQUIRE(macsec_layer != nullptr);
        PFL_EXPECT(layer_has_field_containing(*macsec_layer, "ES", "1"));
    }

    {
        CaptureSession session {};
        const auto row = expect_single_macsec_no_flow_packet(
            session,
            "parsing/macsec/10_macsec_truncated_base_sectag.pcap",
            "MACsec SecTAG truncated"
        );
        const auto packet = require_packet(session, row.packet_index);
        const auto details = require_macsec_details(session, row.packet_index);
        PFL_EXPECT(details.macsec.sectag_truncated);
        PFL_EXPECT(!details.macsec.packet_number_present);
        const auto summary_layers = session_detail::build_packet_summary_layers(details, packet);
        const auto* macsec_layer = find_layer(summary_layers, "macsec");
        PFL_REQUIRE(macsec_layer != nullptr);
        PFL_EXPECT(!layer_has_field_label(*macsec_layer, "Packet Number"));
        PFL_EXPECT(layer_has_field_containing(*macsec_layer, "Warning", "SecTAG is truncated"));
    }

    {
        CaptureSession session {};
        const auto row = expect_single_macsec_no_flow_packet(
            session,
            "parsing/macsec/11_macsec_truncated_packet_number.pcap",
            "MACsec packet number truncated"
        );
        const auto packet = require_packet(session, row.packet_index);
        const auto details = require_macsec_details(session, row.packet_index);
        PFL_EXPECT(details.macsec.packet_number_truncated);
        PFL_EXPECT(!details.macsec.packet_number_present);
        const auto summary_layers = session_detail::build_packet_summary_layers(details, packet);
        const auto* macsec_layer = find_layer(summary_layers, "macsec");
        PFL_REQUIRE(macsec_layer != nullptr);
        PFL_EXPECT(layer_has_field_label(*macsec_layer, "Version"));
        PFL_EXPECT(layer_has_field_containing(*macsec_layer, "Short Length", "0"));
        PFL_EXPECT(!layer_has_field_label(*macsec_layer, "Packet Number"));
        PFL_EXPECT(layer_has_field_containing(*macsec_layer, "Warning", "packet number is truncated"));
    }

    {
        CaptureSession session {};
        const auto row = expect_single_macsec_no_flow_packet(
            session,
            "parsing/macsec/12_macsec_truncated_sci.pcap",
            "MACsec SCI truncated"
        );
        const auto packet = require_packet(session, row.packet_index);
        const auto details = require_macsec_details(session, row.packet_index);
        PFL_EXPECT(details.macsec.sci_truncated);
        PFL_EXPECT(details.macsec.packet_number_present);
        PFL_EXPECT(details.macsec.available_sci_bytes == 5U);
        const auto summary_layers = session_detail::build_packet_summary_layers(details, packet);
        const auto* macsec_layer = find_layer(summary_layers, "macsec");
        PFL_REQUIRE(macsec_layer != nullptr);
        PFL_EXPECT(layer_has_field_containing(*macsec_layer, "Packet Number", "0x01020304"));
        PFL_EXPECT(!layer_has_field_label(*macsec_layer, "SCI System ID"));
        PFL_EXPECT(!layer_has_field_label(*macsec_layer, "SCI Port ID"));
        PFL_EXPECT(layer_has_field_containing(*macsec_layer, "Warning", "SCI is truncated"));
    }

    {
        CaptureSession session {};
        const auto row = expect_single_macsec_no_flow_packet(
            session,
            "parsing/macsec/13_macsec_missing_icv_or_short_payload.pcap",
            "MACsec ICV truncated"
        );
        const auto packet = require_packet(session, row.packet_index);
        const auto details = require_macsec_details(session, row.packet_index);
        PFL_EXPECT(details.macsec.icv_truncated);
        PFL_EXPECT(details.macsec.icv_length == 0U);
        const auto summary_layers = session_detail::build_packet_summary_layers(details, packet);
        const auto* macsec_layer = find_layer(summary_layers, "macsec");
        PFL_REQUIRE(macsec_layer != nullptr);
        PFL_EXPECT(layer_has_field_containing(*macsec_layer, "Warning", "ICV is truncated"));
        PFL_EXPECT(find_layer(summary_layers, "macsec-icv") == nullptr);
    }

    {
        CaptureSession session {};
        expect_complete_macsec_fixture(
            session,
            "parsing/macsec/14_macsec_zero_packet_number.pcap",
            {"frame", "ethernet", "macsec", "macsec-payload", "macsec-icv"},
            false,
            "0x00000000 (0)"
        );
    }

    {
        CaptureSession session {};
        expect_complete_macsec_fixture(
            session,
            "parsing/macsec/15_macsec_protected_payload_ipv4_like_no_decode.pcap",
            {"frame", "ethernet", "macsec", "macsec-payload", "macsec-icv"},
            false,
            "0x01020304 (16909060)"
        );
        const auto details = require_macsec_details(session, 0U);
        PFL_EXPECT(!details.has_ipv4);
        PFL_EXPECT(!details.has_udp);
    }

    {
        CaptureSession session {};
        expect_complete_macsec_fixture(
            session,
            "parsing/macsec/16_macsec_legacy_vlan_9100.pcap",
            {"frame", "ethernet", "vlan", "macsec", "macsec-payload", "macsec-icv"},
            false,
            "0x01020304 (16909060)"
        );
        const auto details = require_macsec_details(session, 0U);
        PFL_EXPECT(details.has_vlan);
        PFL_EXPECT(details.vlan_tags.size() == 1U);
        PFL_EXPECT(details.vlan_tags[0].tpid == 0x9100U);
        PFL_EXPECT((details.vlan_tags[0].tci & 0x0FFFU) == 730U);
    }

    {
        CaptureSession session {};
        expect_complete_macsec_fixture(
            session,
            "parsing/macsec/17_macsec_version1_max_packet_number.pcap",
            {"frame", "ethernet", "macsec", "macsec-payload", "macsec-icv"},
            false,
            "0xffffffff (4294967295)"
        );
        const auto packet = require_packet(session, 0U);
        const auto details = require_macsec_details(session, 0U);
        PFL_EXPECT(details.macsec.version == 1U);
        PFL_EXPECT(details.macsec.association_number == 3U);
        PFL_EXPECT(details.macsec.packet_number == 0xFFFFFFFFU);
        const auto summary_layers = session_detail::build_packet_summary_layers(details, packet);
        const auto* macsec_layer = find_layer(summary_layers, "macsec");
        PFL_REQUIRE(macsec_layer != nullptr);
        PFL_EXPECT(layer_has_field_containing(*macsec_layer, "Version", "1"));
        PFL_EXPECT(layer_has_field_containing(*macsec_layer, "Association Number", "3"));
    }

    {
        CaptureSession session {};
        expect_complete_macsec_fixture(
            session,
            "parsing/macsec/18_macsec_short_length_ignored_for_bounds.pcap",
            {"frame", "ethernet", "macsec", "macsec-payload", "macsec-icv"},
            false,
            "0x01020304 (16909060)"
        );
        const auto packet = require_packet(session, 0U);
        const auto details = require_macsec_details(session, 0U);
        PFL_EXPECT(details.macsec.short_length == 4U);
        PFL_EXPECT(details.macsec.protected_payload_length == 12U);
        const std::vector<std::uint8_t> expected_payload {
            0xdeU, 0xadU, 0xbeU, 0xefU, 0xcaU, 0xfeU, 0xbaU, 0xbeU, 0x11U, 0x22U, 0x33U, 0x44U,
        };
        PFL_EXPECT(details.macsec.protected_payload_preview == expected_payload);
        const auto summary_layers = session_detail::build_packet_summary_layers(details, packet);
        const auto* payload_layer = find_layer(summary_layers, "macsec-payload");
        PFL_REQUIRE(payload_layer != nullptr);
        PFL_EXPECT(layer_has_field_containing(*payload_layer, "Length", "12 bytes"));
        PFL_EXPECT(layer_has_field_containing(*payload_layer, "Raw", "0xde, 0xad, 0xbe, 0xef"));
    }

    {
        CaptureSession session {};
        const auto row = expect_single_macsec_no_flow_packet(
            session,
            "parsing/macsec/19_macsec_caplen_lt_origlen_partial_icv.pcap",
            "MACsec ICV truncated"
        );
        const auto packet = require_packet(session, row.packet_index);
        const auto details = require_macsec_details(session, row.packet_index);
        PFL_EXPECT(packet.captured_length < packet.original_length);
        PFL_EXPECT(details.macsec.icv_truncated);
        PFL_EXPECT(details.macsec.protected_payload_length == 12U);
        PFL_EXPECT(details.macsec.icv_length == 0U);
        const std::vector<std::uint8_t> expected_payload {
            0x6dU, 0x61U, 0x63U, 0x73U, 0x65U, 0x63U, 0x2dU, 0x38U, 0xa0U, 0xa1U, 0xa2U, 0xa3U,
        };
        PFL_EXPECT(details.macsec.protected_payload_preview == expected_payload);
        const auto summary_layers = session_detail::build_packet_summary_layers(details, packet);
        const auto* payload_layer = find_layer(summary_layers, "macsec-payload");
        PFL_REQUIRE(payload_layer != nullptr);
        PFL_EXPECT(layer_has_field_containing(*payload_layer, "Length", "12 bytes"));
        PFL_EXPECT(layer_has_field_containing(*payload_layer, "Raw", "0x6d, 0x61, 0x63, 0x73"));
        PFL_EXPECT(find_layer(summary_layers, "macsec-icv") == nullptr);
    }

    {
        CaptureSession session {};
        expect_complete_macsec_fixture(
            session,
            "parsing/macsec/20_macsec_plain_ether_type_one_byte_only.pcap",
            {"frame", "ethernet", "macsec", "macsec-payload", "macsec-icv"},
            false,
            "0x01020304 (16909060)"
        );
        const auto packet = require_packet(session, 0U);
        const auto details = require_macsec_details(session, 0U);
        PFL_EXPECT(!details.macsec.encrypted);
        PFL_EXPECT(!details.macsec.changed);
        PFL_EXPECT(details.macsec.protected_payload_length == 1U);
        const auto summary_layers = session_detail::build_packet_summary_layers(details, packet);
        const auto* payload_layer = find_layer(summary_layers, "macsec-payload");
        PFL_REQUIRE(payload_layer != nullptr);
        PFL_EXPECT(layer_has_field_containing(*payload_layer, "Length", "1 bytes"));
        PFL_EXPECT(layer_has_field_containing(*payload_layer, "Raw", "45"));
        PFL_EXPECT(!layer_has_field_label(*payload_layer, "Plain EtherType"));
        PFL_EXPECT(!layer_has_field_label(*payload_layer, "Data Length"));
        const auto protocol_text = session.read_packet_protocol_details_text(packet);
        PFL_EXPECT(protocol_text.find("Plain EtherType:") == std::string::npos);
        PFL_EXPECT(protocol_text.find("Data Length:") == std::string::npos);
    }
}

}  // namespace pfl::tests
