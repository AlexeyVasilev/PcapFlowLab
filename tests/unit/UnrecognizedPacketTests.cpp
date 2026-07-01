#include <algorithm>
#include <filesystem>
#include <string>

#include "TestSupport.h"
#include "PcapTestUtils.h"
#include "app/frontend/FrontendSessionAdapter.h"
#include "app/session/CaptureSession.h"
#include "app/session/SessionFormatting.h"

namespace pfl::tests {

namespace {

std::filesystem::path fixture_path(const std::filesystem::path& relative_path) {
    return std::filesystem::path(__FILE__).parent_path().parent_path() / "data" / relative_path;
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

}  // namespace

void run_unrecognized_packet_tests() {
    const auto truncated_tcp_fixture = fixture_path("parsing/tcp_options/19_tcp_syn_tcp_header_snaplen_truncated.pcap");
    const auto normal_tcp_fixture = fixture_path("parsing/tcp_options/01_tcp_syn_no_options.pcap");

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(truncated_tcp_fixture));
        PFL_EXPECT(session.summary().packet_count == 0U);
        PFL_EXPECT(session.list_flows().empty());
        PFL_EXPECT(session.unrecognized_packet_count() == 1U);

        const auto rows = session.list_unrecognized_packets(0U, 30U);
        PFL_REQUIRE(rows.size() == 1U);
        PFL_EXPECT(rows[0].row_number == 1U);
        PFL_EXPECT(rows[0].packet_index == 0U);
        PFL_EXPECT(rows[0].captured_length > 0U);
        PFL_EXPECT(rows[0].original_length >= rows[0].captured_length);
        PFL_EXPECT(rows[0].reason_text == "TCP header truncated");

        const auto packet = session.find_packet(rows[0].packet_index);
        PFL_REQUIRE(packet.has_value());

        const auto details = session.read_packet_details(*packet);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->has_ethernet);
        PFL_EXPECT(details->has_ipv4);
        PFL_EXPECT(!details->has_tcp);

        const auto summary_layers = session_detail::build_packet_summary_layers(*details, *packet, {
            .source_capture_accessible = true,
            .protocol_details_text = session_detail::build_basic_protocol_details_text(*details).value_or(std::string {}),
        });
        PFL_EXPECT(!summary_layers.empty());
        PFL_EXPECT(summary_layers.front().id == "warnings");
        PFL_EXPECT(!summary_layers.front().title.empty());
        const auto* frame_layer = find_layer(summary_layers, "frame");
        const auto* ethernet_layer = find_layer(summary_layers, "ethernet");
        const auto* ipv4_layer = find_layer(summary_layers, "ipv4");
        PFL_REQUIRE(frame_layer != nullptr);
        PFL_REQUIRE(ethernet_layer != nullptr);
        PFL_REQUIRE(ipv4_layer != nullptr);
        PFL_EXPECT(!frame_layer->title.empty());
        PFL_EXPECT(!ethernet_layer->title.empty());
        PFL_EXPECT(!ipv4_layer->title.empty());
        const auto* frame_number_in_file = find_field(*frame_layer, "Packet number in file");
        PFL_REQUIRE(frame_number_in_file != nullptr);
        PFL_EXPECT(frame_number_in_file->value == "1");
        PFL_REQUIRE(find_field(*ipv4_layer, "Source Address") != nullptr);

        const auto raw_dump = session.read_packet_hex_dump(*packet);
        PFL_EXPECT(!raw_dump.empty());
    }

    {
        FrontendSessionAdapter adapter {};
        const auto open_result = adapter.open_capture(truncated_tcp_fixture, FrontendOpenMode::fast);
        PFL_EXPECT(open_result.opened);

        const auto overview = adapter.get_overview();
        PFL_EXPECT(overview.has_capture);
        PFL_EXPECT(overview.unrecognized_packet_count == 1U);

        const auto packets = adapter.get_unrecognized_packets(0U, 30U);
        PFL_EXPECT(packets.has_capture);
        PFL_EXPECT(packets.total_count == 1U);
        PFL_REQUIRE(packets.packets.size() == 1U);
        PFL_EXPECT(packets.packets[0].row_number == 1U);
        PFL_EXPECT(packets.packets[0].reason_text == "TCP header truncated");

        const auto details = adapter.get_unrecognized_packet_details(packets.packets[0].packet_index);
        PFL_EXPECT(details.has_capture);
        PFL_EXPECT(details.packet_found);
        PFL_EXPECT(details.details_available);
        PFL_EXPECT(details.raw_preview_available);
        PFL_EXPECT(!details.summary_layers.empty());
        PFL_EXPECT(details.summary_layers.front().id == "warnings");
        PFL_EXPECT(!details.summary_layers.front().title.empty());
        const auto* frame_layer = find_layer(details.summary_layers, "frame");
        const auto* ethernet_layer = find_layer(details.summary_layers, "ethernet");
        const auto* ipv4_layer = find_layer(details.summary_layers, "ipv4");
        PFL_REQUIRE(frame_layer != nullptr);
        PFL_REQUIRE(ethernet_layer != nullptr);
        PFL_REQUIRE(ipv4_layer != nullptr);
        PFL_EXPECT(!frame_layer->title.empty());
        PFL_EXPECT(!ethernet_layer->title.empty());
        PFL_EXPECT(!ipv4_layer->title.empty());
        const auto* frame_number_in_file = find_field(*frame_layer, "Packet number in file");
        PFL_REQUIRE(frame_number_in_file != nullptr);
        PFL_EXPECT(frame_number_in_file->value == "1");
        PFL_REQUIRE(find_field(*ipv4_layer, "Source Address") != nullptr);
        PFL_EXPECT(find_layer(details.summary_layers, "tcp") == nullptr);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(normal_tcp_fixture));
        PFL_EXPECT(session.unrecognized_packet_count() == 0U);
        PFL_EXPECT(session.list_unrecognized_packets().empty());
        PFL_EXPECT(session.list_flows().size() == 1U);
    }

    {
        CaptureSession source_session {};
        PFL_EXPECT(source_session.open_capture(truncated_tcp_fixture));
        PFL_EXPECT(source_session.unrecognized_packet_count() == 1U);

        const auto index_path = std::filesystem::temp_directory_path() / "pfl_unrecognized_packets_roundtrip.idx";
        PFL_EXPECT(source_session.save_index(index_path));

        CaptureSession loaded_index_session {};
        PFL_EXPECT(loaded_index_session.load_index(index_path));
        PFL_EXPECT(loaded_index_session.unrecognized_packet_count() == 0U);
    }
}

}  // namespace pfl::tests
