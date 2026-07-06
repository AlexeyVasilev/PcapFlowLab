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

void expect_current_non_sctp_negative_behavior() {
    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(fixture_path("parsing/sctp/21_non_sctp_negative.pcap")));

    PFL_EXPECT(session.summary().packet_count == 1U);

    const auto rows = session.list_flows();
    PFL_EXPECT(rows.size() == 1U);

    const auto* udp_flow = find_flow_by_tuple(
        rows,
        FlowAddressFamily::ipv4,
        "UDP",
        "10.132.0.10",
        43000U,
        "10.132.0.20",
        43001U
    );
    PFL_REQUIRE(udp_flow != nullptr);
    PFL_EXPECT(udp_flow->packet_count == 1U);

    PFL_EXPECT(session.list_unrecognized_packets().empty());
}

void expect_sctp_flow_present(
    const std::filesystem::path& relative_path,
    const FlowAddressFamily family,
    const std::string& address_a,
    const std::uint16_t port_a,
    const std::string& address_b,
    const std::uint16_t port_b,
    const std::uint64_t expected_packet_count
) {
    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(fixture_path(relative_path)));

    const auto rows = session.list_flows();
    const auto* flow = find_flow_by_tuple(rows, family, "SCTP", address_a, port_a, address_b, port_b);
    PFL_EXPECT(flow != nullptr);
    if (flow == nullptr) {
        return;
    }

    PFL_EXPECT(rows.size() == 1U);
    PFL_EXPECT(flow->packet_count == expected_packet_count);
}

void expect_sctp_flow_absent(
    const std::filesystem::path& relative_path,
    const FlowAddressFamily family,
    const std::string& address_a,
    const std::uint16_t port_a,
    const std::string& address_b,
    const std::uint16_t port_b
) {
    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(fixture_path(relative_path)));

    const auto rows = session.list_flows();
    const auto* flow = find_flow_by_tuple(rows, family, "SCTP", address_a, port_a, address_b, port_b);
    PFL_EXPECT(flow == nullptr);
}

void expect_sctp_data_packet_details(
    const std::filesystem::path& relative_path,
    const std::string& expected_network_layer_id,
    const std::string& expected_source,
    const std::string& expected_destination,
    const std::string& expected_ppid_fragment,
    const std::string& expected_protocol_payload_name,
    const std::string& expected_summary_payload_layer_title = {}
) {
    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(fixture_path(relative_path)));

    const auto packet = session.find_packet(0U);
    PFL_REQUIRE(packet.has_value());
    const auto details = session.read_packet_details(*packet);
    PFL_REQUIRE(details.has_value());

    PFL_EXPECT(details->has_sctp);
    PFL_EXPECT(details->sctp.available_common_header_bytes == 12U);
    PFL_EXPECT(!details->sctp.common_header_truncated);
    PFL_EXPECT(details->sctp.first_chunk_present);
    PFL_EXPECT(details->sctp.first_chunk_type == 0U);
    PFL_EXPECT(details->sctp.data_metadata_present);
    PFL_EXPECT(details->sctp.data_metadata_available_bytes == 12U);
    PFL_EXPECT(!details->sctp.data_metadata_truncated);

    const auto summary_layers = session_detail::build_packet_summary_layers(*details, *packet);
    const auto* network_layer = find_top_level_layer(summary_layers, expected_network_layer_id);
    PFL_REQUIRE(network_layer != nullptr);
    PFL_EXPECT(title_contains_all(*network_layer, {expected_source, expected_destination}));

    const auto* sctp_layer = find_top_level_layer(summary_layers, "sctp");
    PFL_REQUIRE(sctp_layer != nullptr);
    PFL_EXPECT(title_contains_all(*sctp_layer, {"SCTP", "Src Port:", "Dst Port:"}));
    PFL_EXPECT(layer_has_field_containing(*sctp_layer, "Verification Tag", "0x10213243"));
    PFL_EXPECT(layer_has_field_containing(*sctp_layer, "Checksum", "0x00000000"));

    const auto* chunk_layer = find_top_level_layer(summary_layers, "sctp-chunk");
    PFL_REQUIRE(chunk_layer != nullptr);
    PFL_EXPECT(title_contains_all(*chunk_layer, {"SCTP DATA", expected_ppid_fragment}));
    PFL_EXPECT(layer_has_field_containing(*chunk_layer, "Chunk Type", "DATA"));
    PFL_EXPECT(layer_has_field_containing(*chunk_layer, "PPID", expected_ppid_fragment));
    PFL_EXPECT(!chunk_layer->warning);

    if (!expected_summary_payload_layer_title.empty()) {
        const auto* payload_layer = find_top_level_layer(summary_layers, "sctp-ppid");
        PFL_REQUIRE(payload_layer != nullptr);
        PFL_EXPECT(payload_layer->title == expected_summary_payload_layer_title);
    } else {
        PFL_EXPECT(find_top_level_layer(summary_layers, "sctp-ppid") == nullptr);
    }

    const auto protocol_text = session.read_packet_protocol_details_text(*packet);
    PFL_EXPECT(protocol_text.find("Protocol: SCTP") != std::string::npos);
    PFL_EXPECT(protocol_text.find("Source Port: 49132") != std::string::npos);
    PFL_EXPECT(protocol_text.find("Destination Port: 36412") != std::string::npos);
    PFL_EXPECT(protocol_text.find("Verification Tag: 0x10213243") != std::string::npos);
    PFL_EXPECT(protocol_text.find("First Chunk Type: DATA") != std::string::npos);
    PFL_EXPECT(protocol_text.find("PPID: " + expected_ppid_fragment) != std::string::npos);
    if (!expected_protocol_payload_name.empty()) {
        PFL_EXPECT(protocol_text.find("Recognized Payload: " + expected_protocol_payload_name) != std::string::npos);
    }
}

void expect_sctp_control_chunk_packet_details(
    const std::filesystem::path& relative_path,
    const std::string& expected_chunk_name
) {
    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(fixture_path(relative_path)));

    const auto packet = session.find_packet(0U);
    PFL_REQUIRE(packet.has_value());
    const auto details = session.read_packet_details(*packet);
    PFL_REQUIRE(details.has_value());

    PFL_EXPECT(details->has_sctp);
    PFL_EXPECT(!details->sctp.common_header_truncated);
    PFL_EXPECT(details->sctp.first_chunk_present);
    PFL_EXPECT(!details->sctp.first_chunk_header_truncated);
    PFL_EXPECT(!details->sctp.data_metadata_present);

    const auto summary_layers = session_detail::build_packet_summary_layers(*details, *packet);
    const auto* chunk_layer = find_top_level_layer(summary_layers, "sctp-chunk");
    PFL_REQUIRE(chunk_layer != nullptr);
    PFL_EXPECT(title_contains_all(*chunk_layer, {"SCTP", expected_chunk_name}));
    PFL_EXPECT(find_top_level_layer(summary_layers, "sctp-ppid") == nullptr);

    const auto protocol_text = session.read_packet_protocol_details_text(*packet);
    PFL_EXPECT(protocol_text.find("Protocol: SCTP") != std::string::npos);
    PFL_EXPECT(protocol_text.find("First Chunk Type: " + expected_chunk_name) != std::string::npos);
}

void expect_sctp_common_header_truncated_packet_details(const std::filesystem::path& relative_path) {
    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(fixture_path(relative_path)));

    const auto packet = session.find_packet(0U);
    PFL_REQUIRE(packet.has_value());
    const auto details = session.read_packet_details(*packet);
    PFL_REQUIRE(details.has_value());

    PFL_EXPECT(details->has_sctp);
    PFL_EXPECT(details->sctp.common_header_truncated);
    PFL_EXPECT(details->sctp.available_common_header_bytes < 12U);
    PFL_EXPECT(!details->sctp.first_chunk_present);

    const auto summary_layers = session_detail::build_packet_summary_layers(*details, *packet);
    const auto* sctp_layer = find_top_level_layer(summary_layers, "sctp");
    PFL_REQUIRE(sctp_layer != nullptr);
    PFL_EXPECT(title_contains_all(*sctp_layer, {"SCTP", "malformed"}));
    PFL_EXPECT(sctp_layer->warning);
    PFL_EXPECT(layer_has_field_containing(*sctp_layer, "Warning", "truncated"));
    PFL_EXPECT(find_top_level_layer(summary_layers, "sctp-chunk") == nullptr);

    const auto protocol_text = session.read_packet_protocol_details_text(*packet);
    PFL_EXPECT(protocol_text.find("Protocol: SCTP") != std::string::npos);
    PFL_EXPECT(protocol_text.find("Warning: SCTP common header is truncated.") != std::string::npos);
}

void expect_sctp_chunk_header_truncated_packet_details(const std::filesystem::path& relative_path) {
    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(fixture_path(relative_path)));

    const auto packet = session.find_packet(0U);
    PFL_REQUIRE(packet.has_value());
    const auto details = session.read_packet_details(*packet);
    PFL_REQUIRE(details.has_value());

    PFL_EXPECT(details->has_sctp);
    PFL_EXPECT(!details->sctp.common_header_truncated);
    PFL_EXPECT(details->sctp.first_chunk_present);
    PFL_EXPECT(details->sctp.first_chunk_header_truncated);
    PFL_EXPECT(!details->sctp.data_metadata_present);

    const auto summary_layers = session_detail::build_packet_summary_layers(*details, *packet);
    const auto* chunk_layer = find_top_level_layer(summary_layers, "sctp-chunk");
    PFL_REQUIRE(chunk_layer != nullptr);
    PFL_EXPECT(chunk_layer->warning);
    PFL_EXPECT(layer_has_field_containing(*chunk_layer, "Warning", "first chunk header is truncated"));
    PFL_EXPECT(find_top_level_layer(summary_layers, "sctp-ppid") == nullptr);

    const auto protocol_text = session.read_packet_protocol_details_text(*packet);
    PFL_EXPECT(protocol_text.find("Warning: SCTP first chunk header is truncated.") != std::string::npos);
}

void expect_sctp_data_metadata_truncated_packet_details(const std::filesystem::path& relative_path) {
    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(fixture_path(relative_path)));

    const auto packet = session.find_packet(0U);
    PFL_REQUIRE(packet.has_value());
    const auto details = session.read_packet_details(*packet);
    PFL_REQUIRE(details.has_value());

    PFL_EXPECT(details->has_sctp);
    PFL_EXPECT(!details->sctp.common_header_truncated);
    PFL_EXPECT(details->sctp.first_chunk_present);
    PFL_EXPECT(details->sctp.first_chunk_type == 0U);
    PFL_EXPECT(details->sctp.data_metadata_present);
    PFL_EXPECT(details->sctp.data_metadata_truncated);
    PFL_EXPECT(details->sctp.data_metadata_available_bytes < 12U);

    const auto summary_layers = session_detail::build_packet_summary_layers(*details, *packet);
    const auto* chunk_layer = find_top_level_layer(summary_layers, "sctp-chunk");
    PFL_REQUIRE(chunk_layer != nullptr);
    PFL_EXPECT(title_contains_all(*chunk_layer, {"SCTP DATA"}));
    PFL_EXPECT(chunk_layer->warning);
    PFL_EXPECT(layer_has_field_containing(*chunk_layer, "Warning", "DATA chunk metadata is truncated"));
    PFL_EXPECT(find_top_level_layer(summary_layers, "sctp-ppid") == nullptr);

    const auto protocol_text = session.read_packet_protocol_details_text(*packet);
    PFL_EXPECT(protocol_text.find("Warning: SCTP DATA chunk metadata is truncated.") != std::string::npos);
}

void run_default_outer_sctp_fixture_expectations() {
    constexpr std::uint16_t kSctpSourcePort = 49132U;
    constexpr std::uint16_t kSctpDestinationPort = 36412U;
    const auto expect_ipv4_single_packet = [&](const std::filesystem::path& relative_path) {
        expect_sctp_flow_present(
            relative_path,
            FlowAddressFamily::ipv4,
            "10.132.0.10",
            kSctpSourcePort,
            "10.132.0.20",
            kSctpDestinationPort,
            1U
        );
    };

    expect_sctp_flow_present(
        "parsing/sctp/01_sctp_ipv4_data_s1ap.pcap",
        FlowAddressFamily::ipv4,
        "10.132.0.10",
        kSctpSourcePort,
        "10.132.0.20",
        kSctpDestinationPort,
        1U
    );
    expect_sctp_flow_present(
        "parsing/sctp/02_sctp_ipv6_data_s1ap.pcap",
        FlowAddressFamily::ipv6,
        "2001:0db8:0132:0000:0000:0000:0000:0010",
        kSctpSourcePort,
        "2001:0db8:0132:0000:0000:0000:0000:0020",
        kSctpDestinationPort,
        1U
    );
    expect_ipv4_single_packet("parsing/sctp/03_sctp_ipv4_data_m3ua.pcap");
    expect_ipv4_single_packet("parsing/sctp/04_sctp_ipv4_data_dua.pcap");
    expect_ipv4_single_packet("parsing/sctp/05_sctp_ipv4_data_nbap.pcap");
    expect_ipv4_single_packet("parsing/sctp/06_sctp_ipv4_data_x2ap.pcap");
    expect_ipv4_single_packet("parsing/sctp/07_sctp_ipv4_data_diameter.pcap");
    expect_ipv4_single_packet("parsing/sctp/08_sctp_ipv4_data_ngap.pcap");
    expect_ipv4_single_packet("parsing/sctp/09_sctp_ipv4_data_unknown_ppid.pcap");
    expect_sctp_flow_present(
        "parsing/sctp/10_sctp_ipv4_init.pcap",
        FlowAddressFamily::ipv4,
        "10.132.0.10",
        kSctpSourcePort,
        "10.132.0.20",
        kSctpDestinationPort,
        1U
    );
    expect_sctp_flow_present(
        "parsing/sctp/11_sctp_ipv4_sack.pcap",
        FlowAddressFamily::ipv4,
        "10.132.0.10",
        kSctpSourcePort,
        "10.132.0.20",
        kSctpDestinationPort,
        1U
    );
    expect_sctp_flow_absent(
        "parsing/sctp/12_sctp_truncated_common_header.pcap",
        FlowAddressFamily::ipv4,
        "10.132.0.10",
        kSctpSourcePort,
        "10.132.0.20",
        kSctpDestinationPort
    );
    expect_sctp_flow_present(
        "parsing/sctp/13_sctp_truncated_data_chunk_header.pcap",
        FlowAddressFamily::ipv4,
        "10.132.0.10",
        kSctpSourcePort,
        "10.132.0.20",
        kSctpDestinationPort,
        1U
    );
    expect_sctp_flow_present(
        "parsing/sctp/14_sctp_truncated_data_chunk_ppid.pcap",
        FlowAddressFamily::ipv4,
        "10.132.0.10",
        kSctpSourcePort,
        "10.132.0.20",
        kSctpDestinationPort,
        1U
    );
    expect_sctp_flow_present(
        "parsing/sctp/15_sctp_ipv4_bidirectional_flow.pcap",
        FlowAddressFamily::ipv4,
        "10.132.0.10",
        kSctpSourcePort,
        "10.132.0.20",
        kSctpDestinationPort,
        2U
    );
    expect_sctp_flow_present(
        "parsing/sctp/16_sctp_vlan_ipv4_data_s1ap.pcap",
        FlowAddressFamily::ipv4,
        "10.132.0.10",
        kSctpSourcePort,
        "10.132.0.20",
        kSctpDestinationPort,
        1U
    );
    expect_sctp_flow_present(
        "parsing/sctp/17_sctp_mpls_ipv4_data_s1ap.pcap",
        FlowAddressFamily::ipv4,
        "10.132.0.10",
        kSctpSourcePort,
        "10.132.0.20",
        kSctpDestinationPort,
        1U
    );
    expect_ipv4_single_packet("parsing/sctp/22_sctp_ipv4_data_m2ap.pcap");
    expect_ipv4_single_packet("parsing/sctp/23_sctp_ipv4_data_m3ap.pcap");
    expect_ipv4_single_packet("parsing/sctp/24_sctp_ipv4_data_f1ap.pcap");

    expect_sctp_data_packet_details(
        "parsing/sctp/01_sctp_ipv4_data_s1ap.pcap",
        "ipv4",
        "10.132.0.10",
        "10.132.0.20",
        "S1AP (18)",
        "S1 Application Protocol",
        "S1 Application Protocol"
    );
    expect_sctp_data_packet_details(
        "parsing/sctp/02_sctp_ipv6_data_s1ap.pcap",
        "ipv6",
        "2001:0db8:0132:0000:0000:0000:0000:0010",
        "2001:0db8:0132:0000:0000:0000:0000:0020",
        "S1AP (18)",
        "S1 Application Protocol",
        "S1 Application Protocol"
    );
    expect_sctp_data_packet_details(
        "parsing/sctp/03_sctp_ipv4_data_m3ua.pcap",
        "ipv4",
        "10.132.0.10",
        "10.132.0.20",
        "M3UA (3)",
        "MTP 3 User Adaptation Layer",
        "MTP 3 User Adaptation Layer"
    );
    expect_sctp_data_packet_details(
        "parsing/sctp/04_sctp_ipv4_data_dua.pcap",
        "ipv4",
        "10.132.0.10",
        "10.132.0.20",
        "DUA (10)",
        "DUA",
        "DUA"
    );
    expect_sctp_data_packet_details(
        "parsing/sctp/05_sctp_ipv4_data_nbap.pcap",
        "ipv4",
        "10.132.0.10",
        "10.132.0.20",
        "NBAP (25)",
        "Node B Application Part",
        "Node B Application Part"
    );
    expect_sctp_data_packet_details(
        "parsing/sctp/06_sctp_ipv4_data_x2ap.pcap",
        "ipv4",
        "10.132.0.10",
        "10.132.0.20",
        "X2AP (27)",
        "X2 Application Protocol",
        "X2 Application Protocol"
    );
    expect_sctp_data_packet_details(
        "parsing/sctp/07_sctp_ipv4_data_diameter.pcap",
        "ipv4",
        "10.132.0.10",
        "10.132.0.20",
        "Diameter (46)",
        "Diameter",
        "Diameter"
    );
    expect_sctp_data_packet_details(
        "parsing/sctp/08_sctp_ipv4_data_ngap.pcap",
        "ipv4",
        "10.132.0.10",
        "10.132.0.20",
        "NGAP (60)",
        "NG Application Protocol",
        "NG Application Protocol"
    );
    expect_sctp_data_packet_details(
        "parsing/sctp/09_sctp_ipv4_data_unknown_ppid.pcap",
        "ipv4",
        "10.132.0.10",
        "10.132.0.20",
        "Unknown (0x12345678)",
        ""
    );
    expect_sctp_control_chunk_packet_details("parsing/sctp/10_sctp_ipv4_init.pcap", "INIT");
    expect_sctp_control_chunk_packet_details("parsing/sctp/11_sctp_ipv4_sack.pcap", "SACK");
    expect_sctp_common_header_truncated_packet_details("parsing/sctp/12_sctp_truncated_common_header.pcap");
    expect_sctp_chunk_header_truncated_packet_details("parsing/sctp/13_sctp_truncated_data_chunk_header.pcap");
    expect_sctp_data_metadata_truncated_packet_details("parsing/sctp/14_sctp_truncated_data_chunk_ppid.pcap");
    expect_sctp_data_packet_details(
        "parsing/sctp/22_sctp_ipv4_data_m2ap.pcap",
        "ipv4",
        "10.132.0.10",
        "10.132.0.20",
        "M2AP (43)",
        "M2 Application Protocol",
        "M2 Application Protocol"
    );
    expect_sctp_data_packet_details(
        "parsing/sctp/23_sctp_ipv4_data_m3ap.pcap",
        "ipv4",
        "10.132.0.10",
        "10.132.0.20",
        "M3AP (44)",
        "M3 Application Protocol",
        "M3 Application Protocol"
    );
    expect_sctp_data_packet_details(
        "parsing/sctp/24_sctp_ipv4_data_f1ap.pcap",
        "ipv4",
        "10.132.0.10",
        "10.132.0.20",
        "F1AP (62)",
        "F1 Application Protocol",
        "F1 Application Protocol"
    );
}

#if defined(PFL_ENABLE_PENDING_SCTP_TESTS)

void run_pending_future_sctp_fixture_expectations() {
    constexpr std::uint16_t kSctpSourcePort = 49132U;
    constexpr std::uint16_t kSctpDestinationPort = 36412U;

    const auto expect_ipv4_single_packet = [&](const std::filesystem::path& relative_path) {
        expect_sctp_flow_present(
            relative_path,
            FlowAddressFamily::ipv4,
            "10.132.0.10",
            kSctpSourcePort,
            "10.132.0.20",
            kSctpDestinationPort,
            1U
        );
    };

    expect_ipv4_single_packet("parsing/sctp/18_sctp_vxlan_inner_ipv4_data_s1ap.pcap");
    expect_ipv4_single_packet("parsing/sctp/19_sctp_geneve_inner_ipv4_data_m3ua.pcap");
    expect_ipv4_single_packet("parsing/sctp/20_sctp_gtpu_inner_ipv4_data_s1ap.pcap");
}

#endif

}  // namespace

void run_sctp_pcap_fixture_tests() {
    expect_current_non_sctp_negative_behavior();
    run_default_outer_sctp_fixture_expectations();

#if defined(PFL_ENABLE_PENDING_SCTP_TESTS)
    // Remaining pending expectations cover overlay-inner SCTP behind VXLAN / Geneve / GTP-U.
    run_pending_future_sctp_fixture_expectations();
#endif
}

}  // namespace pfl::tests
