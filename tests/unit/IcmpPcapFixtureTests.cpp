#include <algorithm>
#include <array>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

#include "TestSupport.h"
#include "app/session/CaptureSession.h"
#include "app/session/SelectedPacketBytePresentation.h"
#include "app/session/SessionFormatting.h"
#include "core/domain/ProtocolPath.h"
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
    PFL_REQUIRE(packet.has_value());
    return *packet;
}

RawPcapPacket require_raw_fixture_packet(const std::filesystem::path& relative_path) {
    PcapReader reader {};
    PFL_EXPECT(reader.open(fixture_path(relative_path)));
    const auto packet = reader.read_next();
    PFL_REQUIRE(packet.has_value());
    PFL_EXPECT(!reader.read_next().has_value());
    return *packet;
}

std::optional<PacketDetails> decode_fixture_packet_details_best_effort(const RawPcapPacket& packet) {
    PacketDetailsService details_service {};
    return details_service.decode_best_effort(packet.bytes, make_packet_ref(packet));
}

std::vector<session_detail::PacketSummaryLayer> build_summary_layers(
    const PacketDetails& details,
    const PacketRef& packet
) {
    session_detail::PacketSummaryOptions options {};
    options.source_capture_accessible = true;
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

std::string require_protocol_path_text(const CaptureSession& session, const FlowRow& row) {
    PFL_REQUIRE(row.protocol_path_id != kInvalidProtocolPathId);
    const auto* path = session.state().protocol_path_registry.find(row.protocol_path_id);
    PFL_REQUIRE(path != nullptr);
    return format_protocol_path(*path);
}

std::vector<std::string> collect_labels(const session_detail::SelectedPacketBytePresentation& presentation) {
    const auto descriptors = session_detail::build_selected_packet_byte_view_descriptors(presentation);
    std::vector<std::string> labels {};
    labels.reserve(descriptors.size());
    for (const auto& descriptor : descriptors) {
        labels.push_back(descriptor.label);
    }
    return labels;
}

}  // namespace

void run_icmp_pcap_fixture_tests() {
    constexpr std::array<const char*, 16> kFixtureNames {{
        "01_icmp_echo_request.pcap",
        "02_icmp_echo_reply.pcap",
        "03_icmp_dest_unreachable_network.pcap",
        "04_icmp_dest_unreachable_host.pcap",
        "05_icmp_dest_unreachable_port.pcap",
        "06_icmp_dest_unreachable_frag_needed_mtu_1400.pcap",
        "07_icmp_time_exceeded_ttl.pcap",
        "08_icmp_time_exceeded_reassembly.pcap",
        "09_icmp_redirect_host_gateway.pcap",
        "10_icmp_parameter_problem_pointer_5.pcap",
        "11_icmp_unknown_type_99.pcap",
        "12_icmp_echo_request_unknown_code_7.pcap",
        "13_icmp_truncated_common_header_3_bytes.pcap",
        "14_icmp_truncated_echo_body.pcap",
        "15_icmp_truncated_error_quote.pcap",
        "16_icmp_same_endpoints_different_identifiers.pcap",
    }};

    for (const auto* fixture_name : kFixtureNames) {
        PFL_EXPECT(std::filesystem::exists(fixture_path(std::filesystem::path("parsing/icmp") / fixture_name)));

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path(std::filesystem::path("parsing/icmp") / fixture_name)));
    }

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/icmp/01_icmp_echo_request.pcap")));
        PFL_EXPECT(session.summary().packet_count == 1U);
        PFL_EXPECT(session.summary().flow_count == 1U);
        PFL_EXPECT(session.unrecognized_packet_count() == 0U);

        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 1U);
        PFL_EXPECT(rows[0].protocol_text == "ICMP");
        PFL_EXPECT(rows[0].address_a == "192.0.2.10");
        PFL_EXPECT(rows[0].address_b == "198.51.100.20");
        PFL_EXPECT(rows[0].port_a == 0U);
        PFL_EXPECT(rows[0].port_b == 0U);
        PFL_EXPECT(require_protocol_path_text(session, rows[0]) == "EthernetII -> IPv4");

        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->has_ipv4);
        PFL_EXPECT(details->has_icmp);
        PFL_EXPECT(details->icmp.type == 8U);
        PFL_EXPECT(details->icmp.code == 0U);

        const auto protocol_text = session.read_packet_protocol_details_text(packet);
        PFL_EXPECT(protocol_text.find("ICMP") != std::string::npos);
        PFL_EXPECT(protocol_text.find("Type: 8") != std::string::npos);
        PFL_EXPECT(protocol_text.find("Code: 0") != std::string::npos);
        PFL_EXPECT(protocol_text.find("Source: 192.0.2.10") != std::string::npos);
        PFL_EXPECT(protocol_text.find("Destination: 198.51.100.20") != std::string::npos);

        const auto layers = build_summary_layers(*details, packet);
        const auto* icmp_layer = find_layer(layers, "icmp");
        PFL_REQUIRE(icmp_layer != nullptr);
        PFL_EXPECT(icmp_layer->title == "Internet Control Message Protocol");
        PFL_REQUIRE(find_field(*icmp_layer, "Type") != nullptr);
        PFL_REQUIRE(find_field(*icmp_layer, "Code") != nullptr);
        PFL_REQUIRE(find_field(*icmp_layer, "Source") != nullptr);
        PFL_REQUIRE(find_field(*icmp_layer, "Destination") != nullptr);
        PFL_EXPECT(find_field(*icmp_layer, "Type")->value == "8");
        PFL_EXPECT(find_field(*icmp_layer, "Code")->value == "0");
        PFL_EXPECT(find_field(*icmp_layer, "Source")->value == "192.0.2.10");
        PFL_EXPECT(find_field(*icmp_layer, "Destination")->value == "198.51.100.20");

        const auto presentation = session.derive_selected_packet_byte_presentation(packet);
        PFL_REQUIRE(presentation.has_value());
        const std::vector<std::string> expected_labels {
            "Ethernet II Frame",
            "IPv4 Packet",
            "ICMP Message",
        };
        PFL_EXPECT(collect_labels(*presentation) == expected_labels);
    }

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/icmp/02_icmp_echo_reply.pcap")));
        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->has_icmp);
        PFL_EXPECT(details->icmp.type == 0U);
        PFL_EXPECT(details->icmp.code == 0U);
    }

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/icmp/06_icmp_dest_unreachable_frag_needed_mtu_1400.pcap")));
        PFL_EXPECT(session.summary().flow_count == 1U);
        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 1U);
        PFL_EXPECT(rows[0].protocol_text == "ICMP");
        PFL_EXPECT(require_protocol_path_text(session, rows[0]) == "EthernetII -> IPv4");

        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->has_icmp);
        PFL_EXPECT(details->icmp.type == 3U);
        PFL_EXPECT(details->icmp.code == 4U);
    }

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/icmp/11_icmp_unknown_type_99.pcap")));
        PFL_EXPECT(session.summary().flow_count == 1U);

        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->has_icmp);
        PFL_EXPECT(details->icmp.type == 99U);
        PFL_EXPECT(details->icmp.code == 1U);

        const auto layers = build_summary_layers(*details, packet);
        const auto* icmp_layer = find_layer(layers, "icmp");
        PFL_REQUIRE(icmp_layer != nullptr);
        PFL_EXPECT(find_field(*icmp_layer, "Type")->value == "99");
        PFL_EXPECT(find_field(*icmp_layer, "Code")->value == "1");
    }

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/icmp/13_icmp_truncated_common_header_3_bytes.pcap")));
        PFL_EXPECT(session.summary().packet_count == 0U);
        PFL_EXPECT(session.summary().flow_count == 0U);
        PFL_EXPECT(session.unrecognized_packet_count() == 1U);
        PFL_EXPECT(session.list_flows().empty());

        const auto packet = require_raw_fixture_packet("parsing/icmp/13_icmp_truncated_common_header_3_bytes.pcap");
        const auto details = decode_fixture_packet_details_best_effort(packet);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->has_ipv4);
        PFL_EXPECT(details->has_icmp);
        PFL_EXPECT(details->icmp.type == 8U);
        PFL_EXPECT(details->icmp.code == 0U);
    }

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/icmp/14_icmp_truncated_echo_body.pcap")));
        PFL_EXPECT(session.summary().packet_count == 1U);
        PFL_EXPECT(session.summary().flow_count == 1U);

        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->has_icmp);
        PFL_EXPECT(details->icmp.type == 8U);
        PFL_EXPECT(details->icmp.code == 0U);
    }

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/icmp/16_icmp_same_endpoints_different_identifiers.pcap")));
        PFL_EXPECT(session.summary().packet_count == 2U);
        PFL_EXPECT(session.summary().flow_count == 1U);
        PFL_EXPECT(session.unrecognized_packet_count() == 0U);

        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 1U);
        PFL_EXPECT(rows[0].protocol_text == "ICMP");
        PFL_EXPECT(rows[0].packet_count == 2U);
        PFL_EXPECT(rows[0].address_a == "192.0.2.10");
        PFL_EXPECT(rows[0].address_b == "198.51.100.20");
        PFL_EXPECT(rows[0].port_a == 0U);
        PFL_EXPECT(rows[0].port_b == 0U);
        PFL_EXPECT(require_protocol_path_text(session, rows[0]) == "EthernetII -> IPv4");

        const auto packet_rows = session.list_flow_packets(rows[0].index);
        PFL_EXPECT(packet_rows.size() == 2U);
    }
}

}  // namespace pfl::tests
