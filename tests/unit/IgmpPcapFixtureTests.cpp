#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>

#include "TestSupport.h"
#include "app/session/CaptureSession.h"
#include "app/session/SessionFormatting.h"
#include "core/io/PcapReader.h"
#include "core/services/PacketDetailsService.h"

namespace pfl::tests {

namespace {

std::filesystem::path fixture_path(const std::filesystem::path& relative_path) {
    return std::filesystem::path(__FILE__).parent_path().parent_path() / "data" / relative_path;
}

PacketRef make_packet_ref(const RawPcapPacket& packet) {
    PacketRef ref {};
    ref.packet_index = packet.packet_index;
    ref.byte_offset = packet.data_offset;
    ref.data_link_type = packet.data_link_type;
    ref.captured_length = packet.captured_length;
    ref.original_length = packet.original_length;
    ref.ts_sec = packet.ts_sec;
    ref.ts_usec = packet.ts_usec;
    return ref;
}

PacketRef require_packet(CaptureSession& session, const std::uint64_t packet_index) {
    const auto packet = session.find_packet(packet_index);
    PFL_EXPECT(packet.has_value());
    return *packet;
}

RawPcapPacket require_raw_fixture_packet(const std::filesystem::path& relative_path) {
    PcapReader reader {};
    PFL_EXPECT(reader.open(fixture_path(relative_path)));
    const auto packet = reader.read_next();
    PFL_EXPECT(packet.has_value());
    PFL_EXPECT(!reader.read_next().has_value());
    return *packet;
}

std::optional<PacketDetails> decode_fixture_packet_details_best_effort(const RawPcapPacket& packet) {
    PacketDetailsService details_service {};
    return details_service.decode_best_effort(packet.bytes, make_packet_ref(packet));
}

std::vector<session_detail::PacketSummaryLayer> build_summary_layers(
    const PacketDetails& details,
    const PacketRef& packet,
    const std::string& protocol_details_text = {}
) {
    session_detail::PacketSummaryOptions options {};
    options.source_capture_accessible = true;
    options.protocol_details_text = protocol_details_text;
    return session_detail::build_packet_summary_layers(details, packet, options);
}

const session_detail::PacketSummaryLayer* find_layer(
    const std::vector<session_detail::PacketSummaryLayer>& layers,
    const std::string& id
) {
    const auto it = std::find_if(layers.begin(), layers.end(), [&](const session_detail::PacketSummaryLayer& layer) {
        return layer.id == id;
    });
    return it == layers.end() ? nullptr : &(*it);
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

void expect_single_igmp_flow(
    const std::filesystem::path& relative_path,
    const std::string& expected_hint,
    const std::string& expected_service,
    const std::string& expected_source,
    const std::string& expected_group
) {
    CaptureSession session {};
    PFL_EXPECT(session.open_capture(fixture_path(relative_path)));
    PFL_EXPECT(session.summary().packet_count == 1U);
    PFL_EXPECT(session.summary().flow_count == 1U);
    PFL_EXPECT(session.unrecognized_packet_count() == 0U);

    const auto rows = session.list_flows();
    PFL_EXPECT(rows.size() == 1U);
    PFL_EXPECT(rows[0].protocol_text == "IGMP");
    PFL_EXPECT(rows[0].protocol_hint == expected_hint);
    PFL_EXPECT(rows[0].service_hint == expected_service);
    PFL_EXPECT(rows[0].address_a == expected_source);
    PFL_EXPECT(rows[0].address_b == expected_group);
    PFL_EXPECT(rows[0].endpoint_a == expected_source);
    PFL_EXPECT(rows[0].endpoint_b == expected_group);
    PFL_EXPECT(rows[0].port_a == 0U);
    PFL_EXPECT(rows[0].port_b == 0U);
    PFL_EXPECT(rows[0].packet_count == 1U);
}

}  // namespace

void run_igmp_pcap_fixture_tests() {
    expect_single_igmp_flow(
        "parsing/igmp/01_igmpv1_membership_report_mdns_group.pcap",
        "igmpv1",
        "Membership Report 224.0.0.251",
        "192.0.2.10",
        "224.0.0.251");
    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/igmp/01_igmpv1_membership_report_mdns_group.pcap")));

        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_EXPECT(details.has_value());
        PFL_EXPECT(details->has_ipv4);
        PFL_EXPECT(details->has_igmp);

        const auto protocol_text = session.read_packet_protocol_details_text(packet);
        PFL_EXPECT(protocol_text.find("Protocol: IGMPv1 (Membership Report)") != std::string::npos);
        PFL_EXPECT(protocol_text.find("Type: Membership Report (0x12)") != std::string::npos);
        PFL_EXPECT(protocol_text.find("Group Address: 224.0.0.251") != std::string::npos);

        const auto layers = build_summary_layers(*details, packet, protocol_text);
        const auto* ipv4_layer = find_layer(layers, "ipv4");
        const auto* igmp_layer = find_layer(layers, "igmp");
        PFL_EXPECT(ipv4_layer != nullptr);
        PFL_EXPECT(igmp_layer != nullptr);
        PFL_EXPECT(igmp_layer->title == "IGMPv1, Membership Report 224.0.0.251");

        const auto* type_field = find_field(*igmp_layer, "Type");
        const auto* checksum_field = find_field(*igmp_layer, "Checksum");
        const auto* group_field = find_field(*igmp_layer, "Group Address");
        PFL_EXPECT(type_field != nullptr);
        PFL_EXPECT(checksum_field != nullptr);
        PFL_EXPECT(group_field != nullptr);
        PFL_EXPECT(type_field->value == "Membership Report (0x12)");
        PFL_EXPECT(!checksum_field->value.empty());
        PFL_EXPECT(group_field->value == "224.0.0.251");
    }
    expect_single_igmp_flow(
        "parsing/igmp/02_igmpv2_membership_report_mdns_group.pcap",
        "igmpv2",
        "Membership Report 224.0.0.251",
        "192.0.2.10",
        "224.0.0.251");
    expect_single_igmp_flow(
        "parsing/igmp/03_igmpv2_leave_group_mdns_group.pcap",
        "igmpv2",
        "Leave Group 224.0.0.251",
        "192.0.2.10",
        "224.0.0.251");
    expect_single_igmp_flow(
        "parsing/igmp/04_igmpv2_general_query.pcap",
        "igmpv2",
        "General Query",
        "192.0.2.1",
        "224.0.0.1");
    expect_single_igmp_flow(
        "parsing/igmp/05_igmpv2_group_specific_query.pcap",
        "igmpv2",
        "Group-Specific Query 239.1.2.3",
        "192.0.2.1",
        "239.1.2.3");

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/igmp/06_igmp_same_source_group_report_then_leave.pcap")));
        PFL_EXPECT(session.summary().packet_count == 2U);
        PFL_EXPECT(session.summary().flow_count == 1U);
        PFL_EXPECT(session.unrecognized_packet_count() == 0U);

        const auto rows = session.list_flows();
        PFL_EXPECT(rows.size() == 1U);
        PFL_EXPECT(rows[0].protocol_text == "IGMP");
        PFL_EXPECT(rows[0].protocol_hint == "igmpv2");
        PFL_EXPECT(rows[0].packet_count == 2U);
        PFL_EXPECT(rows[0].address_a == "192.0.2.10");
        PFL_EXPECT(rows[0].address_b == "224.0.0.251");
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/igmp/07_igmp_two_sources_same_group.pcap")));
        PFL_EXPECT(session.summary().packet_count == 2U);
        PFL_EXPECT(session.summary().flow_count == 2U);
        const auto rows = session.list_flows();
        PFL_EXPECT(rows.size() == 2U);
        PFL_EXPECT(rows[0].address_b == "224.0.0.251");
        PFL_EXPECT(rows[1].address_b == "224.0.0.251");
        PFL_EXPECT(rows[0].address_a != rows[1].address_a);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/igmp/08_igmp_same_source_two_groups.pcap")));
        PFL_EXPECT(session.summary().packet_count == 2U);
        PFL_EXPECT(session.summary().flow_count == 2U);
        const auto rows = session.list_flows();
        PFL_EXPECT(rows.size() == 2U);
        PFL_EXPECT(rows[0].address_a == "192.0.2.10");
        PFL_EXPECT(rows[1].address_a == "192.0.2.10");
        PFL_EXPECT(rows[0].address_b != rows[1].address_b);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/igmp/09_igmpv2_report_with_router_alert.pcap")));
        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_EXPECT(details.has_value());
        PFL_EXPECT(details->has_ipv4);
        PFL_EXPECT(details->has_igmp);

        const auto protocol_text = session.read_packet_protocol_details_text(packet);
        PFL_EXPECT(protocol_text.find("Protocol: IGMPv2 (Membership Report)") != std::string::npos);
        PFL_EXPECT(protocol_text.find("Group Address: 224.0.0.251") != std::string::npos);

        const auto layers = build_summary_layers(*details, packet, protocol_text);
        PFL_EXPECT(layers.size() >= 4U);
        PFL_EXPECT(layers[0].id == "frame");
        PFL_EXPECT(layers[1].id == "ethernet");
        PFL_EXPECT(layers[2].id == "ipv4");
        PFL_EXPECT(layers[3].id == "igmp");
        PFL_EXPECT(layers[3].title.find("IGMPv2, Membership Report 224.0.0.251") != std::string::npos);
        const auto* type_field = find_field(layers[3], "Type");
        PFL_EXPECT(type_field != nullptr);
        PFL_EXPECT(type_field->value.find("Membership Report") != std::string::npos);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/igmp/10_igmpv2_general_query_with_router_alert.pcap")));
        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_EXPECT(details.has_value());
        PFL_EXPECT(details->has_igmp);

        const auto protocol_text = session.read_packet_protocol_details_text(packet);
        PFL_EXPECT(protocol_text.find("Protocol: IGMPv2 (Membership Query)") != std::string::npos);

        const auto layers = build_summary_layers(*details, packet, protocol_text);
        const auto* igmp_layer = find_layer(layers, "igmp");
        PFL_EXPECT(igmp_layer != nullptr);
        PFL_EXPECT(igmp_layer->title.find("General Query") != std::string::npos);
        const auto* destination_field = find_field(*igmp_layer, "Destination");
        PFL_EXPECT(destination_field != nullptr);
        PFL_EXPECT(destination_field->value == "224.0.0.1");
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/igmp/11_igmp_unknown_type.pcap")));
        const auto rows = session.list_flows();
        PFL_EXPECT(rows.size() == 1U);
        PFL_EXPECT(rows[0].protocol_hint == "igmp");
        PFL_EXPECT(rows[0].service_hint == "Unknown IGMP Type 0x99");

        const auto packet = require_packet(session, 0U);
        const auto protocol_text = session.read_packet_protocol_details_text(packet);
        PFL_EXPECT(protocol_text.find("Protocol: IGMP") != std::string::npos);
        PFL_EXPECT(protocol_text.find("Type: Unknown Type (0x99)") != std::string::npos);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/igmp/12_igmpv3_membership_report_minimal.pcap")));
        PFL_EXPECT(session.summary().flow_count == 1U);
        const auto rows = session.list_flows();
        PFL_EXPECT(rows.size() == 1U);
        PFL_EXPECT(rows[0].protocol_hint == "igmpv3");
        PFL_EXPECT(rows[0].service_hint == "IGMPv3 Membership Report");
        PFL_EXPECT(rows[0].address_b == "239.1.2.3");

        const auto packet = require_packet(session, 0U);
        const auto protocol_text = session.read_packet_protocol_details_text(packet);
        PFL_EXPECT(protocol_text.find("Protocol: IGMPv3") != std::string::npos);
        PFL_EXPECT(protocol_text.find("Group Record Count: 0") != std::string::npos);
        PFL_EXPECT(protocol_text.find("Detailed IGMPv3 group-record parsing is deferred.") != std::string::npos);

        const auto details = session.read_packet_details(packet);
        PFL_EXPECT(details.has_value());
        const auto layers = build_summary_layers(*details, packet, protocol_text);
        const auto* igmp_layer = find_layer(layers, "igmp");
        PFL_EXPECT(igmp_layer != nullptr);
        const auto* record_count_field = find_field(*igmp_layer, "Group Record Count");
        PFL_EXPECT(record_count_field != nullptr);
        PFL_EXPECT(record_count_field->value == "0");
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/igmp/13_igmp_truncated_header.pcap")));
        PFL_EXPECT(session.summary().packet_count == 0U);
        PFL_EXPECT(session.summary().flow_count == 0U);
        PFL_EXPECT(session.unrecognized_packet_count() == 1U);

        const auto rows = session.list_unrecognized_packets();
        PFL_EXPECT(rows.size() == 1U);
        PFL_EXPECT(rows[0].reason_text == "IGMP header truncated");

        const auto packet = require_raw_fixture_packet("parsing/igmp/13_igmp_truncated_header.pcap");
        const auto details = decode_fixture_packet_details_best_effort(packet);
        PFL_EXPECT(details.has_value());
        PFL_EXPECT(details->has_ipv4);
        PFL_EXPECT(details->has_igmp);
        PFL_EXPECT(details->igmp.header_truncated);

        const auto protocol_text = session_detail::build_basic_protocol_details_text(*details);
        PFL_EXPECT(protocol_text.has_value());
        PFL_EXPECT(protocol_text->find("Warning: IGMP header is truncated.") != std::string::npos);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/igmp/14_igmp_snaplen_truncated_header.pcap")));
        PFL_EXPECT(session.summary().packet_count == 0U);
        PFL_EXPECT(session.summary().flow_count == 0U);
        PFL_EXPECT(session.unrecognized_packet_count() == 1U);

        const auto rows = session.list_unrecognized_packets();
        PFL_EXPECT(rows.size() == 1U);
        PFL_EXPECT(rows[0].reason_text == "IGMP header truncated");

        const auto packet = require_raw_fixture_packet("parsing/igmp/14_igmp_snaplen_truncated_header.pcap");
        PFL_EXPECT(packet.captured_length < packet.original_length);

        const auto details = decode_fixture_packet_details_best_effort(packet);
        PFL_EXPECT(details.has_value());
        PFL_EXPECT(details->has_igmp);
        PFL_EXPECT(details->igmp.header_truncated);

        const auto protocol_text = session_detail::build_basic_protocol_details_text(*details);
        PFL_EXPECT(protocol_text.has_value());
        const auto layers = build_summary_layers(*details, make_packet_ref(packet), *protocol_text);
        const auto* igmp_layer = find_layer(layers, "igmp");
        PFL_EXPECT(igmp_layer != nullptr);
        PFL_EXPECT(igmp_layer->warning);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/igmp/15_igmp_bad_checksum.pcap")));
        PFL_EXPECT(session.summary().packet_count == 1U);
        PFL_EXPECT(session.summary().flow_count == 1U);
        const auto rows = session.list_flows();
        PFL_EXPECT(rows.size() == 1U);
        PFL_EXPECT(rows[0].protocol_hint == "igmpv2");

        const auto packet = require_packet(session, 0U);
        const auto protocol_text = session.read_packet_protocol_details_text(packet);
        PFL_EXPECT(protocol_text.find("Protocol: IGMPv2 (Membership Report)") != std::string::npos);
        PFL_EXPECT(protocol_text.find("Checksum: 0x") != std::string::npos);

        const auto details = session.read_packet_details(packet);
        PFL_EXPECT(details.has_value());
        const auto layers = build_summary_layers(*details, packet, protocol_text);
        const auto* igmp_layer = find_layer(layers, "igmp");
        PFL_EXPECT(igmp_layer != nullptr);
        PFL_EXPECT(find_field(*igmp_layer, "Checksum") != nullptr);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/igmp/16_ipv4_protocol_igmp_no_payload.pcap")));
        PFL_EXPECT(session.summary().packet_count == 0U);
        PFL_EXPECT(session.summary().flow_count == 0U);
        PFL_EXPECT(session.unrecognized_packet_count() == 1U);

        const auto rows = session.list_unrecognized_packets();
        PFL_EXPECT(rows.size() == 1U);
        PFL_EXPECT(rows[0].reason_text == "Missing IGMP payload");

        const auto packet = require_raw_fixture_packet("parsing/igmp/16_ipv4_protocol_igmp_no_payload.pcap");
        const auto details = decode_fixture_packet_details_best_effort(packet);
        PFL_EXPECT(details.has_value());
        PFL_EXPECT(details->has_ipv4);
        PFL_EXPECT(!details->has_igmp);
    }
}

}  // namespace pfl::tests
