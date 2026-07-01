#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <vector>

#include "TestSupport.h"
#include "app/session/SessionFormatting.h"
#include "app/session/CaptureSession.h"
#include "core/domain/PacketDetails.h"
#include "core/domain/PacketRef.h"
#include "core/services/HexDumpService.h"
#include "core/services/PacketDetailsService.h"
#include "PcapTestUtils.h"

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

const session_detail::PacketSummaryLayer* find_summary_layer(
    const std::vector<session_detail::PacketSummaryLayer>& layers,
    const std::string& id
) {
    const auto it = std::find_if(layers.begin(), layers.end(), [&](const session_detail::PacketSummaryLayer& layer) {
        return layer.id == id;
    });
    return it != layers.end() ? &(*it) : nullptr;
}

const session_detail::PacketSummaryField* find_summary_field(
    const session_detail::PacketSummaryLayer& layer,
    const std::string& label
) {
    const auto it = std::find_if(layer.fields.begin(), layer.fields.end(), [&](const session_detail::PacketSummaryField& field) {
        return field.label == label;
    });
    return it != layer.fields.end() ? &(*it) : nullptr;
}

const session_detail::PacketSummaryLayer* find_summary_child(
    const session_detail::PacketSummaryLayer& layer,
    const std::string& id,
    const std::size_t occurrence = 0U
) {
    std::size_t seen = 0U;
    for (const auto& child : layer.children) {
        if (child.id != id) {
            continue;
        }
        if (seen == occurrence) {
            return &child;
        }
        ++seen;
    }
    return nullptr;
}

std::vector<session_detail::PacketSummaryLayer> build_fixture_summary_layers(
    const std::filesystem::path& relative_fixture_path
) {
    CaptureSession session {};
    PFL_EXPECT(session.open_capture(fixture_path(relative_fixture_path), CaptureImportOptions {.mode = ImportMode::fast}));
    const auto packet = require_packet(session, 0U);
    const auto details = session.read_packet_details(packet);
    PFL_REQUIRE(details.has_value());
    return session_detail::build_packet_summary_layers(*details, packet, {
        .source_capture_accessible = true,
        .transport_payload_length = packet.payload_length,
        .original_transport_payload_length = packet.payload_length,
        .protocol_details_text = session.read_packet_protocol_details_text(packet),
    });
}

std::vector<std::uint8_t> make_ethernet_ipv4_tcp_syn_with_options_packet(
    const std::uint32_t src_addr,
    const std::uint32_t dst_addr,
    const std::uint16_t src_port,
    const std::uint16_t dst_port
) {
    auto bytes = make_ethernet_ipv4_tcp_packet(src_addr, dst_addr, src_port, dst_port);
    const std::array<std::uint8_t, 12> options {
        0x02U, 0x04U, 0x05U, 0xb4U,
        0x01U, 0x01U, 0x04U, 0x02U,
        0x01U, 0x03U, 0x03U, 0x07U
    };

    auto write_be16 = [](std::vector<std::uint8_t>& target, const std::size_t offset, const std::uint16_t value) {
        target[offset] = static_cast<std::uint8_t>((value >> 8U) & 0xFFU);
        target[offset + 1U] = static_cast<std::uint8_t>(value & 0xFFU);
    };
    auto write_be32 = [](std::vector<std::uint8_t>& target, const std::size_t offset, const std::uint32_t value) {
        target[offset] = static_cast<std::uint8_t>((value >> 24U) & 0xFFU);
        target[offset + 1U] = static_cast<std::uint8_t>((value >> 16U) & 0xFFU);
        target[offset + 2U] = static_cast<std::uint8_t>((value >> 8U) & 0xFFU);
        target[offset + 3U] = static_cast<std::uint8_t>(value & 0xFFU);
    };

    bytes.insert(bytes.end(), options.begin(), options.end());
    write_be16(bytes, 16U, 52U);
    write_be32(bytes, 38U, 1455851779U);
    write_be32(bytes, 42U, 0U);
    bytes[46] = 0x80U;
    bytes[47] = 0x02U;
    write_be16(bytes, 48U, 62420U);
    write_be16(bytes, 50U, 0x1d02U);
    write_be16(bytes, 52U, 0U);
    return bytes;
}

}  // namespace

void run_packet_details_tests() {
    const auto tcp_packet = make_ethernet_ipv4_tcp_packet(ipv4(10, 0, 0, 1), ipv4(10, 0, 0, 2), 12345, 443);
    const auto udp_packet = make_ethernet_ipv4_udp_packet(ipv4(10, 0, 0, 3), ipv4(10, 0, 0, 4), 5353, 53);

    {
        PacketDetailsService service {};
        const PacketRef packet_ref {
            .packet_index = 7,
            .byte_offset = 40,
            .captured_length = static_cast<std::uint32_t>(tcp_packet.size()),
            .original_length = static_cast<std::uint32_t>(tcp_packet.size()),
        };

        const auto details = service.decode(tcp_packet, packet_ref);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->has_ethernet);
        PFL_EXPECT(details->ethernet.dst_mac == (std::array<std::uint8_t, 6> {0x00U, 0x11U, 0x22U, 0x33U, 0x44U, 0x55U}));
        PFL_EXPECT(details->ethernet.src_mac == (std::array<std::uint8_t, 6> {0x66U, 0x77U, 0x88U, 0x99U, 0xaaU, 0xbbU}));
        PFL_EXPECT(details->ethernet.ether_type == 0x0800);
        PFL_EXPECT(details->has_ipv4);
        PFL_EXPECT(details->ipv4.src_addr == ipv4(10, 0, 0, 1));
        PFL_EXPECT(details->ipv4.dst_addr == ipv4(10, 0, 0, 2));
        PFL_EXPECT(details->ipv4.header_length_bytes == 20U);
        PFL_EXPECT(details->ipv4.differentiated_services_field == 0U);
        PFL_EXPECT(details->ipv4.protocol == 6);
        PFL_EXPECT(details->has_tcp);
        PFL_EXPECT(details->tcp.src_port == 12345);
        PFL_EXPECT(details->tcp.dst_port == 443);
        PFL_EXPECT(details->tcp.header_length_bytes == 20U);
        PFL_EXPECT(details->tcp.flags == 0x10);
        PFL_EXPECT(details->tcp.window == 0U);
        PFL_EXPECT(details->tcp.checksum == 0U);
        PFL_EXPECT(details->tcp.urgent_pointer == 0U);
        PFL_EXPECT(details->tcp.options_bytes.empty());

        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet_ref, {
            .flow_packet_index = 4U,
            .transport_payload_length = 0U,
            .original_transport_payload_length = 0U,
            .protocol_details_text = "No protocol-specific details available for this packet.",
        });
        PFL_REQUIRE(!summary_layers.empty());
        PFL_EXPECT(summary_layers.front().id == "frame");
        PFL_EXPECT(summary_layers.front().title == "Frame: Packet 4 in Flow, Packet 8 in file");
        PFL_EXPECT(!summary_layers.front().expanded_by_default);
        PFL_REQUIRE(summary_layers.size() >= 4U);
        PFL_EXPECT(summary_layers[1].id == "ethernet");
        PFL_EXPECT(!summary_layers[1].expanded_by_default);
        PFL_EXPECT(summary_layers[2].id == "ipv4");
        PFL_EXPECT(!summary_layers[2].expanded_by_default);
        PFL_EXPECT(summary_layers[3].id == "tcp");
        PFL_EXPECT(summary_layers[3].expanded_by_default);
        PFL_EXPECT(summary_layers[1].title == "Ethernet II, Src: 66:77:88:99:aa:bb, Dst: 00:11:22:33:44:55");
        PFL_EXPECT(summary_layers[2].title == "IPv4, Src: 10.0.0.1, Dst: 10.0.0.2");
        PFL_EXPECT(summary_layers[3].title == "TCP, Src Port: 12345, Dst Port: 443");
        PFL_EXPECT(summary_layers[3].title.find("Seq:") == std::string::npos);
        PFL_EXPECT(summary_layers[3].title.find("Ack:") == std::string::npos);
        PFL_EXPECT(summary_layers[3].title.find("Len:") == std::string::npos);
        PFL_EXPECT(summary_layers.size() == 4U);
        const auto* frame_layer = find_summary_layer(summary_layers, "frame");
        const auto* ethernet_layer = find_summary_layer(summary_layers, "ethernet");
        const auto* ipv4_layer = find_summary_layer(summary_layers, "ipv4");
        const auto* tcp_layer = find_summary_layer(summary_layers, "tcp");
        PFL_REQUIRE(frame_layer != nullptr);
        PFL_REQUIRE(ethernet_layer != nullptr);
        PFL_REQUIRE(ipv4_layer != nullptr);
        PFL_REQUIRE(tcp_layer != nullptr);
        const auto* frame_in_flow_field = find_summary_field(*frame_layer, "Packet number in flow");
        const auto* frame_in_file_field = find_summary_field(*frame_layer, "Packet number in file");
        const auto* frame_captured_length_field = find_summary_field(*frame_layer, "Captured Length");
        const auto* frame_original_length_field = find_summary_field(*frame_layer, "Original Length");
        const auto* ethernet_source_field = find_summary_field(*ethernet_layer, "Source");
        const auto* ethernet_destination_field = find_summary_field(*ethernet_layer, "Destination");
        const auto* ethernet_type_field = find_summary_field(*ethernet_layer, "Type");
        const auto* ipv4_ihl_field = find_summary_field(*ipv4_layer, "Internet Header Length");
        const auto* ipv4_ds_field = find_summary_field(*ipv4_layer, "Differentiated Services Field");
        const auto* ipv4_total_length_field = find_summary_field(*ipv4_layer, "Total Length");
        const auto* ipv4_identification_field = find_summary_field(*ipv4_layer, "Identification");
        const auto* ipv4_flags_field = find_summary_field(*ipv4_layer, "Flags");
        const auto* ipv4_fragment_offset_field = find_summary_field(*ipv4_layer, "Fragment Offset");
        const auto* ipv4_protocol_field = find_summary_field(*ipv4_layer, "Protocol");
        const auto* ipv4_checksum_field = find_summary_field(*ipv4_layer, "Header Checksum");
        const auto* ipv4_src_field = find_summary_field(*ipv4_layer, "Source Address");
        const auto* ipv4_dst_field = find_summary_field(*ipv4_layer, "Destination Address");
        const auto* tcp_source_port_field = find_summary_field(*tcp_layer, "Source Port");
        const auto* tcp_destination_port_field = find_summary_field(*tcp_layer, "Destination Port");
        const auto* tcp_sequence_field = find_summary_field(*tcp_layer, "Sequence Number (raw)");
        const auto* tcp_acknowledgment_field = find_summary_field(*tcp_layer, "Acknowledgment Number (raw)");
        const auto* tcp_header_length_field = find_summary_field(*tcp_layer, "Header Length");
        const auto* tcp_flags_field = find_summary_field(*tcp_layer, "Flags");
        const auto* tcp_window_field = find_summary_field(*tcp_layer, "Window");
        const auto* tcp_checksum_field = find_summary_field(*tcp_layer, "Checksum");
        const auto* tcp_urgent_pointer_field = find_summary_field(*tcp_layer, "Urgent Pointer");
        const auto* tcp_options_layer = find_summary_child(*tcp_layer, "tcp_options");
        PFL_REQUIRE(frame_in_flow_field != nullptr);
        PFL_REQUIRE(frame_in_file_field != nullptr);
        PFL_REQUIRE(frame_captured_length_field != nullptr);
        PFL_REQUIRE(frame_original_length_field != nullptr);
        PFL_REQUIRE(ethernet_source_field != nullptr);
        PFL_REQUIRE(ethernet_destination_field != nullptr);
        PFL_REQUIRE(ethernet_type_field != nullptr);
        PFL_REQUIRE(ipv4_ihl_field != nullptr);
        PFL_REQUIRE(ipv4_ds_field != nullptr);
        PFL_REQUIRE(ipv4_total_length_field != nullptr);
        PFL_REQUIRE(ipv4_identification_field != nullptr);
        PFL_REQUIRE(ipv4_flags_field != nullptr);
        PFL_REQUIRE(ipv4_fragment_offset_field != nullptr);
        PFL_REQUIRE(ipv4_protocol_field != nullptr);
        PFL_REQUIRE(ipv4_checksum_field != nullptr);
        PFL_REQUIRE(ipv4_src_field != nullptr);
        PFL_REQUIRE(ipv4_dst_field != nullptr);
        PFL_REQUIRE(tcp_source_port_field != nullptr);
        PFL_REQUIRE(tcp_destination_port_field != nullptr);
        PFL_REQUIRE(tcp_sequence_field != nullptr);
        PFL_REQUIRE(tcp_acknowledgment_field != nullptr);
        PFL_REQUIRE(tcp_header_length_field != nullptr);
        PFL_REQUIRE(tcp_flags_field != nullptr);
        PFL_REQUIRE(tcp_window_field != nullptr);
        PFL_REQUIRE(tcp_checksum_field != nullptr);
        PFL_REQUIRE(tcp_urgent_pointer_field != nullptr);
        PFL_EXPECT(tcp_options_layer == nullptr);
        PFL_EXPECT(frame_in_flow_field->value == "4");
        PFL_EXPECT(frame_in_file_field->value == "8");
        PFL_EXPECT(frame_captured_length_field->value == std::to_string(tcp_packet.size()) + " bytes");
        PFL_EXPECT(frame_original_length_field->value == std::to_string(tcp_packet.size()) + " bytes");
        PFL_EXPECT(ethernet_source_field->value == "66:77:88:99:aa:bb");
        PFL_EXPECT(ethernet_destination_field->value == "00:11:22:33:44:55");
        PFL_EXPECT(ethernet_type_field->value == "IPv4 (0x0800)");
        PFL_EXPECT(ipv4_ihl_field->value == "20 bytes (5)");
        PFL_EXPECT(ipv4_ds_field->value == "0x00");
        PFL_EXPECT(ipv4_total_length_field->value == std::to_string(tcp_packet.size() - 14U) + " bytes");
        PFL_EXPECT(ipv4_identification_field->value == "0x0000");
        PFL_EXPECT(ipv4_flags_field->value == "0x0");
        PFL_EXPECT(ipv4_fragment_offset_field->value == "0");
        PFL_EXPECT(ipv4_protocol_field->value == "TCP (6)");
        PFL_EXPECT(ipv4_checksum_field->value == "0x0000");
        PFL_EXPECT(ipv4_src_field->value == "10.0.0.1");
        PFL_EXPECT(ipv4_dst_field->value == "10.0.0.2");
        PFL_EXPECT(tcp_source_port_field->value == "12345");
        PFL_EXPECT(tcp_destination_port_field->value == "443");
        PFL_EXPECT(tcp_sequence_field->value == "0");
        PFL_EXPECT(tcp_acknowledgment_field->value == "0");
        PFL_EXPECT(tcp_header_length_field->value == "20 bytes (5)");
        PFL_EXPECT(tcp_flags_field->value == "ACK");
        PFL_EXPECT(tcp_window_field->value == "0");
        PFL_EXPECT(tcp_checksum_field->value == "0x0000");
        PFL_EXPECT(tcp_urgent_pointer_field->value == "0");
    }

    {
        PacketDetailsService service {};
        const PacketRef packet_ref {
            .packet_index = 8,
            .byte_offset = 80,
            .captured_length = static_cast<std::uint32_t>(udp_packet.size()),
            .original_length = static_cast<std::uint32_t>(udp_packet.size()),
        };

        const auto details = service.decode(udp_packet, packet_ref);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->has_ipv4);
        PFL_EXPECT(details->ipv4.protocol == 17);
        PFL_EXPECT(details->has_udp);
        PFL_EXPECT(details->udp.src_port == 5353);
        PFL_EXPECT(details->udp.dst_port == 53);
        PFL_EXPECT(details->udp.length == 8);
        PFL_EXPECT(details->udp.checksum == 0U);

        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet_ref, {
            .transport_payload_length = 0U,
            .original_transport_payload_length = 0U,
            .protocol_details_text = "No protocol-specific details available for this packet.",
        });
        PFL_REQUIRE(summary_layers.size() >= 4U);
        PFL_EXPECT(summary_layers[0].id == "frame");
        PFL_EXPECT(summary_layers[0].title == "Frame: Packet 9 in file");
        PFL_EXPECT(!summary_layers[0].expanded_by_default);
        PFL_EXPECT(summary_layers[1].id == "ethernet");
        PFL_EXPECT(!summary_layers[1].expanded_by_default);
        PFL_EXPECT(summary_layers[2].id == "ipv4");
        PFL_EXPECT(!summary_layers[2].expanded_by_default);
        PFL_EXPECT(summary_layers[3].id == "udp");
        PFL_EXPECT(summary_layers[3].expanded_by_default);
        PFL_EXPECT(summary_layers[3].title == "UDP, Src Port: 5353, Dst Port: 53");
        PFL_EXPECT(summary_layers.size() == 4U);
        const auto* udp_layer = find_summary_layer(summary_layers, "udp");
        PFL_REQUIRE(udp_layer != nullptr);
        const auto* udp_source_port_field = find_summary_field(*udp_layer, "Source Port");
        const auto* udp_destination_port_field = find_summary_field(*udp_layer, "Destination Port");
        const auto* udp_length_field = find_summary_field(*udp_layer, "Length");
        const auto* udp_checksum_field = find_summary_field(*udp_layer, "Checksum");
        const auto* udp_payload_length_field = find_summary_field(*udp_layer, "Payload Length");
        PFL_REQUIRE(udp_source_port_field != nullptr);
        PFL_REQUIRE(udp_destination_port_field != nullptr);
        PFL_REQUIRE(udp_length_field != nullptr);
        PFL_REQUIRE(udp_checksum_field != nullptr);
        PFL_REQUIRE(udp_payload_length_field != nullptr);
        PFL_EXPECT(udp_source_port_field->value == "5353");
        PFL_EXPECT(udp_destination_port_field->value == "53");
        PFL_EXPECT(udp_length_field->value == "8 bytes");
        PFL_EXPECT(udp_checksum_field->value == "0x0000");
        PFL_EXPECT(udp_payload_length_field->value == "0 bytes");
    }

    {
        PacketDetailsService service {};
        const auto syn_packet = make_ethernet_ipv4_tcp_syn_with_options_packet(
            ipv4(10, 0, 0, 11), ipv4(10, 0, 0, 12), 41580, 443);
        const PacketRef packet_ref {
            .packet_index = 9,
            .byte_offset = 120,
            .captured_length = static_cast<std::uint32_t>(syn_packet.size()),
            .original_length = static_cast<std::uint32_t>(syn_packet.size()),
        };

        const auto details = service.decode(syn_packet, packet_ref);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->has_tcp);
        PFL_EXPECT(details->tcp.src_port == 41580U);
        PFL_EXPECT(details->tcp.dst_port == 443U);
        PFL_EXPECT(details->tcp.seq_number == 1455851779U);
        PFL_EXPECT(details->tcp.ack_number == 0U);
        PFL_EXPECT(details->tcp.header_length_bytes == 32U);
        PFL_EXPECT(details->tcp.flags == 0x02U);
        PFL_EXPECT(details->tcp.window == 62420U);
        PFL_EXPECT(details->tcp.checksum == 0x1d02U);
        PFL_EXPECT(details->tcp.urgent_pointer == 0U);
        PFL_EXPECT(details->tcp.options_bytes.size() == 12U);

        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet_ref, {
            .transport_payload_length = 0U,
            .original_transport_payload_length = 0U,
            .protocol_details_text = "No protocol-specific details available for this packet.",
        });
        const auto* tcp_layer = find_summary_layer(summary_layers, "tcp");
        PFL_REQUIRE(tcp_layer != nullptr);
        PFL_EXPECT(tcp_layer->title == "TCP, Src Port: 41580, Dst Port: 443");
        PFL_EXPECT(tcp_layer->title.find("Seq:") == std::string::npos);
        PFL_EXPECT(tcp_layer->title.find("Ack:") == std::string::npos);
        PFL_EXPECT(tcp_layer->title.find("Len:") == std::string::npos);
        const auto* tcp_sequence_field = find_summary_field(*tcp_layer, "Sequence Number (raw)");
        const auto* tcp_acknowledgment_field = find_summary_field(*tcp_layer, "Acknowledgment Number (raw)");
        const auto* tcp_header_length_field = find_summary_field(*tcp_layer, "Header Length");
        const auto* tcp_flags_field = find_summary_field(*tcp_layer, "Flags");
        const auto* tcp_window_field = find_summary_field(*tcp_layer, "Window");
        const auto* tcp_checksum_field = find_summary_field(*tcp_layer, "Checksum");
        const auto* tcp_urgent_pointer_field = find_summary_field(*tcp_layer, "Urgent Pointer");
        const auto* tcp_options_layer = find_summary_child(*tcp_layer, "tcp_options");
        PFL_REQUIRE(tcp_sequence_field != nullptr);
        PFL_REQUIRE(tcp_acknowledgment_field != nullptr);
        PFL_REQUIRE(tcp_header_length_field != nullptr);
        PFL_REQUIRE(tcp_flags_field != nullptr);
        PFL_REQUIRE(tcp_window_field != nullptr);
        PFL_REQUIRE(tcp_checksum_field != nullptr);
        PFL_REQUIRE(tcp_urgent_pointer_field != nullptr);
        PFL_REQUIRE(tcp_options_layer != nullptr);
        PFL_EXPECT(tcp_sequence_field->value == "1455851779");
        PFL_EXPECT(tcp_acknowledgment_field->value == "0");
        PFL_EXPECT(tcp_header_length_field->value == "32 bytes (8)");
        PFL_EXPECT(tcp_flags_field->value == "SYN");
        PFL_EXPECT(tcp_window_field->value == "62420");
        PFL_EXPECT(tcp_checksum_field->value == "0x1d02");
        PFL_EXPECT(tcp_urgent_pointer_field->value == "0");
        PFL_EXPECT(tcp_options_layer->title == "TCP Options (12 bytes)");
        const auto* tcp_options_raw_field = find_summary_field(*tcp_options_layer, "Raw");
        const auto* tcp_mss_option = find_summary_child(*tcp_options_layer, "tcp_option_mss");
        const auto* tcp_nop_option0 = find_summary_child(*tcp_options_layer, "tcp_option_nop", 0U);
        const auto* tcp_nop_option1 = find_summary_child(*tcp_options_layer, "tcp_option_nop", 1U);
        const auto* tcp_sack_permitted_option = find_summary_child(*tcp_options_layer, "tcp_option_sack_permitted");
        const auto* tcp_window_scale_option = find_summary_child(*tcp_options_layer, "tcp_option_window_scale");
        PFL_REQUIRE(tcp_options_raw_field != nullptr);
        PFL_EXPECT(tcp_options_raw_field->value ==
            "0x02, 0x04, 0x05, 0xb4, 0x01, 0x01, 0x04, 0x02, 0x01, 0x03, 0x03, 0x07");
        PFL_REQUIRE(tcp_mss_option != nullptr);
        PFL_REQUIRE(tcp_nop_option0 != nullptr);
        PFL_REQUIRE(tcp_nop_option1 != nullptr);
        PFL_REQUIRE(tcp_sack_permitted_option != nullptr);
        PFL_REQUIRE(tcp_window_scale_option != nullptr);
        const auto* tcp_mss_value_field = find_summary_field(*tcp_mss_option, "MSS");
        const auto* tcp_window_scale_field = find_summary_field(*tcp_window_scale_option, "Shift Count");
        PFL_REQUIRE(tcp_mss_value_field != nullptr);
        PFL_REQUIRE(tcp_window_scale_field != nullptr);
        PFL_EXPECT(tcp_mss_value_field->value == "1460 bytes");
        PFL_EXPECT(tcp_window_scale_field->value == "7");
    }

    {
        const auto summary_layers = build_fixture_summary_layers("parsing/tcp_options/03_tcp_syn_mss.pcap");
        const auto* tcp_layer = find_summary_layer(summary_layers, "tcp");
        PFL_REQUIRE(tcp_layer != nullptr);
        const auto* tcp_options_layer = find_summary_child(*tcp_layer, "tcp_options");
        PFL_REQUIRE(tcp_options_layer != nullptr);
        PFL_EXPECT(tcp_options_layer->title == "TCP Options (4 bytes)");
        const auto* tcp_mss_option = find_summary_child(*tcp_options_layer, "tcp_option_mss");
        PFL_REQUIRE(tcp_mss_option != nullptr);
        const auto* tcp_mss_value = find_summary_field(*tcp_mss_option, "MSS");
        PFL_REQUIRE(tcp_mss_value != nullptr);
        PFL_EXPECT(tcp_mss_value->value == "1460 bytes");
    }

    {
        const auto summary_layers = build_fixture_summary_layers("parsing/tcp_options/04_tcp_syn_mss_window_scale_sack_timestamp.pcap");
        const auto* tcp_layer = find_summary_layer(summary_layers, "tcp");
        PFL_REQUIRE(tcp_layer != nullptr);
        const auto* tcp_options_layer = find_summary_child(*tcp_layer, "tcp_options");
        PFL_REQUIRE(tcp_options_layer != nullptr);
        PFL_REQUIRE(find_summary_child(*tcp_options_layer, "tcp_option_mss") != nullptr);
        PFL_REQUIRE(find_summary_child(*tcp_options_layer, "tcp_option_sack_permitted") != nullptr);
        PFL_REQUIRE(find_summary_child(*tcp_options_layer, "tcp_option_timestamp") != nullptr);
        PFL_REQUIRE(find_summary_child(*tcp_options_layer, "tcp_option_window_scale") != nullptr);
        PFL_REQUIRE(find_summary_child(*tcp_options_layer, "tcp_option_nop", 0U) != nullptr);
        const auto* timestamp_option = find_summary_child(*tcp_options_layer, "tcp_option_timestamp");
        PFL_REQUIRE(timestamp_option != nullptr);
        PFL_REQUIRE(find_summary_field(*timestamp_option, "Timestamp value") != nullptr);
        PFL_REQUIRE(find_summary_field(*timestamp_option, "Timestamp echo reply") != nullptr);
    }

    {
        const auto summary_layers = build_fixture_summary_layers("parsing/tcp_options/07_tcp_ack_sack_blocks.pcap");
        const auto* tcp_layer = find_summary_layer(summary_layers, "tcp");
        PFL_REQUIRE(tcp_layer != nullptr);
        const auto* tcp_options_layer = find_summary_child(*tcp_layer, "tcp_options");
        PFL_REQUIRE(tcp_options_layer != nullptr);
        const auto* sack_option = find_summary_child(*tcp_options_layer, "tcp_option_sack");
        PFL_REQUIRE(sack_option != nullptr);
        PFL_REQUIRE(find_summary_field(*sack_option, "Block 1 Left Edge") != nullptr);
        PFL_REQUIRE(find_summary_field(*sack_option, "Block 1 Right Edge") != nullptr);
        PFL_REQUIRE(find_summary_field(*sack_option, "Block 2 Left Edge") != nullptr);
        PFL_REQUIRE(find_summary_field(*sack_option, "Block 2 Right Edge") != nullptr);
    }

    {
        const auto summary_layers = build_fixture_summary_layers("parsing/tcp_options/08_tcp_ack_timestamp_only.pcap");
        const auto* tcp_layer = find_summary_layer(summary_layers, "tcp");
        PFL_REQUIRE(tcp_layer != nullptr);
        const auto* tcp_options_layer = find_summary_child(*tcp_layer, "tcp_options");
        PFL_REQUIRE(tcp_options_layer != nullptr);
        const auto* timestamp_option = find_summary_child(*tcp_options_layer, "tcp_option_timestamp");
        PFL_REQUIRE(timestamp_option != nullptr);
        PFL_REQUIRE(find_summary_field(*timestamp_option, "Timestamp value") != nullptr);
        PFL_REQUIRE(find_summary_field(*timestamp_option, "Timestamp echo reply") != nullptr);
    }

    {
        const auto summary_layers = build_fixture_summary_layers("parsing/tcp_options/09_tcp_syn_unknown_valid_option.pcap");
        const auto* tcp_layer = find_summary_layer(summary_layers, "tcp");
        PFL_REQUIRE(tcp_layer != nullptr);
        const auto* tcp_options_layer = find_summary_child(*tcp_layer, "tcp_options");
        PFL_REQUIRE(tcp_options_layer != nullptr);
        const auto* unknown_option = find_summary_child(*tcp_options_layer, "tcp_option_unknown");
        PFL_REQUIRE(unknown_option != nullptr);
        PFL_REQUIRE(find_summary_field(*unknown_option, "Kind") != nullptr);
        PFL_REQUIRE(find_summary_field(*unknown_option, "Raw") != nullptr);
    }

    {
        const auto summary_layers = build_fixture_summary_layers("parsing/tcp_options/13_tcp_option_length_zero_malformed.pcap");
        const auto* tcp_layer = find_summary_layer(summary_layers, "tcp");
        PFL_REQUIRE(tcp_layer != nullptr);
        const auto* tcp_options_layer = find_summary_child(*tcp_layer, "tcp_options");
        PFL_REQUIRE(tcp_options_layer != nullptr);
        const auto* malformed_option = find_summary_child(*tcp_options_layer, "tcp_option_malformed");
        PFL_REQUIRE(malformed_option != nullptr);
        PFL_EXPECT(malformed_option->warning);
        PFL_EXPECT(malformed_option->title.find("invalid length 0") != std::string::npos);
    }

    {
        const auto summary_layers = build_fixture_summary_layers("parsing/tcp_options/16_tcp_option_truncated_timestamp_malformed.pcap");
        const auto* tcp_layer = find_summary_layer(summary_layers, "tcp");
        PFL_REQUIRE(tcp_layer != nullptr);
        const auto* tcp_options_layer = find_summary_child(*tcp_layer, "tcp_options");
        PFL_REQUIRE(tcp_options_layer != nullptr);
        const auto* malformed_option = find_summary_child(*tcp_options_layer, "tcp_option_malformed");
        PFL_REQUIRE(malformed_option != nullptr);
        PFL_EXPECT(malformed_option->warning);
        PFL_EXPECT(malformed_option->title == "Malformed Timestamp Option");
    }

    {
        const auto summary_layers = build_fixture_summary_layers("parsing/tcp_options/17_tcp_option_eol_then_nonzero_padding.pcap");
        const auto* tcp_layer = find_summary_layer(summary_layers, "tcp");
        PFL_REQUIRE(tcp_layer != nullptr);
        const auto* tcp_options_layer = find_summary_child(*tcp_layer, "tcp_options");
        PFL_REQUIRE(tcp_options_layer != nullptr);
        PFL_REQUIRE(find_summary_child(*tcp_options_layer, "tcp_option_eol") != nullptr);
        const auto* malformed_option = find_summary_child(*tcp_options_layer, "tcp_option_malformed");
        PFL_REQUIRE(malformed_option != nullptr);
        PFL_EXPECT(malformed_option->title == "Non-zero padding after EOL");
    }

    {
        const auto summary_layers = build_fixture_summary_layers("parsing/tcp_options/20_tcp_syn_ipv4_options_and_tcp_options.pcap");
        const auto* ipv4_layer = find_summary_layer(summary_layers, "ipv4");
        const auto* tcp_layer = find_summary_layer(summary_layers, "tcp");
        PFL_REQUIRE(ipv4_layer != nullptr);
        PFL_REQUIRE(tcp_layer != nullptr);
        PFL_REQUIRE(find_summary_field(*ipv4_layer, "Internet Header Length") != nullptr);
        PFL_REQUIRE(find_summary_child(*tcp_layer, "tcp_options") != nullptr);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/dns/dns_request_1.pcap"), CaptureImportOptions {.mode = ImportMode::deep}));
        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet, {
            .transport_payload_length = packet.payload_length,
            .original_transport_payload_length = packet.payload_length,
            .protocol_details_text = session.read_packet_protocol_details_text(packet),
        });
        PFL_EXPECT(summary_layers.size() >= 5U);
        PFL_EXPECT(summary_layers[summary_layers.size() - 2U].id == "udp");
        PFL_EXPECT(!summary_layers[summary_layers.size() - 2U].expanded_by_default);
        PFL_EXPECT(summary_layers.back().id == "dns");
        PFL_EXPECT(summary_layers.back().expanded_by_default);
        PFL_EXPECT(summary_layers.back().title.find("Domain Name System") != std::string::npos);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/quic/quic_initial_ch_1.pcap"), CaptureImportOptions {.mode = ImportMode::fast}));
        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        const auto protocol_text = session.derive_quic_protocol_text_for_packet(0U, packet.packet_index)
            .value_or(session.read_packet_protocol_details_text(packet));
        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet, {
            .transport_payload_length = packet.payload_length,
            .original_transport_payload_length = packet.payload_length,
            .protocol_details_text = protocol_text,
        });
        PFL_EXPECT(summary_layers.size() >= 5U);
        PFL_EXPECT(summary_layers[summary_layers.size() - 2U].id == "udp");
        PFL_EXPECT(summary_layers.back().id == "quic");
        PFL_EXPECT(summary_layers.back().title.find("QUIC") != std::string::npos);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/tls/tls_client_hello_1.pcap"), CaptureImportOptions {.mode = ImportMode::deep}));
        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet, {
            .transport_payload_length = packet.payload_length,
            .original_transport_payload_length = packet.payload_length,
            .protocol_details_text = session.read_packet_protocol_details_text(packet),
        });
        PFL_EXPECT(summary_layers.size() >= 5U);
        PFL_EXPECT(summary_layers[summary_layers.size() - 2U].id == "tcp");
        PFL_EXPECT(!summary_layers[summary_layers.size() - 2U].expanded_by_default);
        PFL_EXPECT(summary_layers.back().id == "tls");
        PFL_EXPECT(summary_layers.back().expanded_by_default);
        PFL_EXPECT(summary_layers.back().title.find("Transport Layer Security") != std::string::npos);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/http/http_get_1.pcap"), CaptureImportOptions {.mode = ImportMode::deep}));
        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet, {
            .transport_payload_length = packet.payload_length,
            .original_transport_payload_length = packet.payload_length,
            .protocol_details_text = session.read_packet_protocol_details_text(packet),
        });
        PFL_EXPECT(summary_layers.size() >= 5U);
        PFL_EXPECT(summary_layers[summary_layers.size() - 2U].id == "tcp");
        PFL_EXPECT(summary_layers.back().id == "http");
        PFL_EXPECT(summary_layers.back().title.find("Hypertext Transfer Protocol") != std::string::npos);
    }

    {
        const auto full_udp_with_payload = make_ethernet_ipv4_udp_packet_with_payload(
            ipv4(10, 0, 0, 5), ipv4(10, 0, 0, 6), 54000, 443, 7);
        auto captured_udp_with_payload = full_udp_with_payload;
        captured_udp_with_payload.resize(full_udp_with_payload.size() - 3U);

        PacketDetailsService service {};
        const PacketRef packet_ref {
            .packet_index = 18,
            .byte_offset = 88,
            .captured_length = static_cast<std::uint32_t>(captured_udp_with_payload.size()),
            .original_length = static_cast<std::uint32_t>(full_udp_with_payload.size()),
        };

        const auto details = service.decode(captured_udp_with_payload, packet_ref);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->has_ipv4);
        PFL_EXPECT(details->ipv4.protocol == 17);
        PFL_EXPECT(details->has_udp);
        PFL_EXPECT(details->udp.src_port == 54000);
        PFL_EXPECT(details->udp.dst_port == 443);
        PFL_EXPECT(details->udp.length == 15);

        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet_ref, {
            .transport_payload_length = 4U,
            .original_transport_payload_length = 7U,
            .protocol_details_text = "No protocol-specific details available for this packet.",
        });
        const auto* udp_layer = find_summary_layer(summary_layers, "udp");
        PFL_REQUIRE(udp_layer != nullptr);
        const auto* udp_payload_length_field = find_summary_field(*udp_layer, "Payload Length");
        const auto* udp_captured_payload_length_field = find_summary_field(*udp_layer, "Captured Payload Length");
        const auto* udp_original_payload_length_field = find_summary_field(*udp_layer, "Original Payload Length");
        PFL_EXPECT(udp_payload_length_field == nullptr);
        PFL_REQUIRE(udp_captured_payload_length_field != nullptr);
        PFL_REQUIRE(udp_original_payload_length_field != nullptr);
        PFL_EXPECT(udp_captured_payload_length_field->value == "4 bytes");
        PFL_EXPECT(udp_original_payload_length_field->value == "7 bytes");
    }

    {
        const auto full_tcp_with_payload = make_ethernet_ipv4_tcp_packet_with_payload(
            ipv4(10, 0, 0, 7), ipv4(10, 0, 0, 8), 41000, 443, 7, 0x18);
        auto captured_tcp_with_payload = full_tcp_with_payload;
        captured_tcp_with_payload.resize(full_tcp_with_payload.size() - 3U);

        PacketDetailsService service {};
        const PacketRef packet_ref {
            .packet_index = 21,
            .byte_offset = 144,
            .captured_length = static_cast<std::uint32_t>(captured_tcp_with_payload.size()),
            .original_length = static_cast<std::uint32_t>(full_tcp_with_payload.size()),
        };

        const auto details = service.decode(captured_tcp_with_payload, packet_ref);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->has_tcp);

        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet_ref, {
            .transport_payload_length = 4U,
            .original_transport_payload_length = 7U,
            .protocol_details_text = "No protocol-specific details available for this packet.",
        });
        const auto* tcp_layer = find_summary_layer(summary_layers, "tcp");
        PFL_REQUIRE(tcp_layer != nullptr);
        const auto* tcp_payload_length_field = find_summary_field(*tcp_layer, "Payload Length");
        const auto* tcp_captured_payload_length_field = find_summary_field(*tcp_layer, "Captured Payload Length");
        const auto* tcp_original_payload_length_field = find_summary_field(*tcp_layer, "Original Payload Length");
        PFL_EXPECT(tcp_payload_length_field == nullptr);
        PFL_REQUIRE(tcp_captured_payload_length_field != nullptr);
        PFL_REQUIRE(tcp_original_payload_length_field != nullptr);
        PFL_EXPECT(tcp_captured_payload_length_field->value == "4 bytes");
        PFL_EXPECT(tcp_original_payload_length_field->value == "7 bytes");
    }

    {
        PacketDetailsService service {};
        const auto arp_packet = make_ethernet_arp_packet(ipv4(10, 10, 12, 2), ipv4(10, 10, 12, 1), 1U);
        const PacketRef packet_ref {
            .packet_index = 19,
            .byte_offset = 96,
            .captured_length = static_cast<std::uint32_t>(arp_packet.size()),
            .original_length = static_cast<std::uint32_t>(arp_packet.size()),
        };

        const auto details = service.decode(arp_packet, packet_ref);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->has_arp);
        PFL_EXPECT(details->arp.hardware_type == 1U);
        PFL_EXPECT(details->arp.protocol_type == 0x0800U);
        PFL_EXPECT(details->arp.hardware_size == 6U);
        PFL_EXPECT(details->arp.protocol_size == 4U);
        PFL_EXPECT(details->arp.opcode == 1U);
        PFL_EXPECT(details->arp.sender_hardware_address.size() == 6U);
        PFL_EXPECT(details->arp.sender_protocol_address.size() == 4U);
        PFL_EXPECT(details->arp.target_hardware_address.size() == 6U);
        PFL_EXPECT(details->arp.target_protocol_address.size() == 4U);
        const std::array<std::uint8_t, 4> expected_sender_ipv4 {10U, 10U, 12U, 2U};
        const std::array<std::uint8_t, 4> expected_target_ipv4 {10U, 10U, 12U, 1U};
        PFL_EXPECT(details->arp.sender_ipv4 == expected_sender_ipv4);
        PFL_EXPECT(details->arp.target_ipv4 == expected_target_ipv4);
        PFL_EXPECT(!details->arp.fixed_header_truncated);
        PFL_EXPECT(!details->arp.address_section_truncated);

        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet_ref, {
            .protocol_details_text = session_detail::build_basic_protocol_details_text(*details).value_or(std::string {}),
        });
        const auto arp_layer_it = std::find_if(summary_layers.begin(), summary_layers.end(), [](const session_detail::PacketSummaryLayer& layer) {
            return layer.id == "arp";
        });
        PFL_EXPECT(arp_layer_it != summary_layers.end());
        PFL_EXPECT(arp_layer_it->title.find("Address Resolution Protocol") != std::string::npos);
        PFL_EXPECT(static_cast<unsigned>(std::count_if(summary_layers.begin(), summary_layers.end(), [](const session_detail::PacketSummaryLayer& layer) {
            return layer.id == "arp";
        })) == 1U);
        const auto opcode_it = std::find_if(arp_layer_it->fields.begin(), arp_layer_it->fields.end(), [](const session_detail::PacketSummaryField& field) {
            return field.label == "Opcode" && field.value == "request (1)";
        });
        PFL_EXPECT(opcode_it != arp_layer_it->fields.end());
        const auto message_it = std::find_if(arp_layer_it->fields.begin(), arp_layer_it->fields.end(), [](const session_detail::PacketSummaryField& field) {
            return field.label == "Message" && field.value == "ARP Request";
        });
        PFL_EXPECT(message_it != arp_layer_it->fields.end());
        const auto detail_it = std::find_if(arp_layer_it->fields.begin(), arp_layer_it->fields.end(), [](const session_detail::PacketSummaryField& field) {
            return field.label.empty() && field.value == "Who has 10.10.12.1? Tell 10.10.12.2";
        });
        PFL_EXPECT(detail_it != arp_layer_it->fields.end());
    }

    {
        PacketDetailsService service {};
        auto padded_arp_packet = make_ethernet_arp_packet(ipv4(10, 10, 12, 1), ipv4(10, 10, 12, 2), 2U);
        padded_arp_packet.insert(padded_arp_packet.end(), {0x00U, 0x00U, 0x00U, 0x00U});
        const PacketRef packet_ref {
            .packet_index = 20,
            .byte_offset = 120,
            .captured_length = static_cast<std::uint32_t>(padded_arp_packet.size()),
            .original_length = static_cast<std::uint32_t>(padded_arp_packet.size()),
        };

        const auto details = service.decode(padded_arp_packet, packet_ref);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->has_arp);
        PFL_EXPECT(details->arp.sender_hardware_address.size() == 6U);
        PFL_EXPECT(details->arp.target_hardware_address.size() == 6U);
        PFL_EXPECT(!details->arp.address_section_truncated);
    }

    {
        PacketDetailsService service {};
        const auto vlan_arp_packet = add_vlan_tags(
            make_ethernet_arp_packet(ipv4(10, 10, 12, 3), ipv4(10, 10, 12, 4), 1U),
            {{0x8100U, 200U}}
        );
        const PacketRef packet_ref {
            .packet_index = 23,
            .byte_offset = 192,
            .captured_length = static_cast<std::uint32_t>(vlan_arp_packet.size()),
            .original_length = static_cast<std::uint32_t>(vlan_arp_packet.size()),
        };

        const auto details = service.decode(vlan_arp_packet, packet_ref);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->has_arp);
        PFL_EXPECT(details->has_vlan);
        const std::array<std::uint8_t, 4> expected_vlan_sender_ipv4 {10U, 10U, 12U, 3U};
        PFL_EXPECT(details->arp.sender_ipv4 == expected_vlan_sender_ipv4);

        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet_ref);
        PFL_EXPECT(summary_layers.size() >= 4U);
        PFL_EXPECT(summary_layers[0].id == "frame");
        PFL_EXPECT(summary_layers[1].id == "ethernet");
        PFL_EXPECT(summary_layers[2].id == "vlan");
        PFL_EXPECT(summary_layers[3].id == "arp");
        PFL_EXPECT(summary_layers[2].title.find("802.1Q Virtual LAN") != std::string::npos);
    }

    {
        PacketDetailsService service {};
        auto truncated_arp_packet = make_ethernet_arp_packet(ipv4(10, 10, 12, 2), ipv4(10, 10, 12, 1), 1U);
        truncated_arp_packet.resize(truncated_arp_packet.size() - 5U);
        const PacketRef packet_ref {
            .packet_index = 21,
            .byte_offset = 144,
            .captured_length = static_cast<std::uint32_t>(truncated_arp_packet.size()),
            .original_length = static_cast<std::uint32_t>(truncated_arp_packet.size() + 5U),
        };

        const auto details = service.decode(truncated_arp_packet, packet_ref);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->has_arp);
        PFL_EXPECT(!details->arp.fixed_header_truncated);
        PFL_EXPECT(details->arp.address_section_truncated);
        PFL_EXPECT(details->arp.target_protocol_address.size() < 4U);

        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet_ref);
        const auto warning_layer_it = std::find_if(summary_layers.begin(), summary_layers.end(), [](const session_detail::PacketSummaryLayer& layer) {
            return layer.id == "warnings";
        });
        PFL_EXPECT(warning_layer_it != summary_layers.end());
        PFL_EXPECT(summary_layers.size() >= 2U);
        PFL_EXPECT(summary_layers[0].id == "warnings");
        PFL_EXPECT(summary_layers[0].expanded_by_default);
        PFL_EXPECT(summary_layers[1].id == "frame");
        PFL_EXPECT(!summary_layers[1].expanded_by_default);
        const auto arp_layer_it = std::find_if(summary_layers.begin(), summary_layers.end(), [](const session_detail::PacketSummaryLayer& layer) {
            return layer.id == "arp";
        });
        PFL_EXPECT(arp_layer_it != summary_layers.end());
        PFL_EXPECT(arp_layer_it->warning);
        PFL_EXPECT(arp_layer_it->expanded_by_default);
    }

    {
        PacketDetailsService service {};
        auto short_arp_packet = make_ethernet_arp_packet(ipv4(10, 10, 12, 2), ipv4(10, 10, 12, 1), 1U);
        short_arp_packet.resize(14U + 6U);
        const PacketRef packet_ref {
            .packet_index = 22,
            .byte_offset = 168,
            .captured_length = static_cast<std::uint32_t>(short_arp_packet.size()),
            .original_length = static_cast<std::uint32_t>(short_arp_packet.size() + 8U),
        };

        const auto details = service.decode(short_arp_packet, packet_ref);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->has_arp);
        PFL_EXPECT(details->arp.fixed_header_truncated);
    }

    {
        PacketDetailsService service {};
        const auto icmp_packet = make_ethernet_ipv4_icmp_packet(ipv4(10, 0, 0, 10), ipv4(10, 0, 0, 20), 8U, 0U);
        const PacketRef packet_ref {
            .packet_index = 25,
            .byte_offset = 240,
            .captured_length = static_cast<std::uint32_t>(icmp_packet.size()),
            .original_length = static_cast<std::uint32_t>(icmp_packet.size()),
        };

        const auto details = service.decode(icmp_packet, packet_ref);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->has_icmp);
        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet_ref, {
            .protocol_details_text = session_detail::build_basic_protocol_details_text(*details).value_or(std::string {}),
        });
        PFL_EXPECT(summary_layers.size() >= 4U);
        PFL_EXPECT(summary_layers[summary_layers.size() - 2U].id == "ipv4");
        PFL_EXPECT(summary_layers.back().id == "icmp");
        PFL_EXPECT(summary_layers.back().title.find("Internet Control Message Protocol") != std::string::npos);
    }

    {
        PacketDetailsService service {};
        const auto ipv6_src = ipv6({0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01});
        const auto ipv6_dst = ipv6({0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02});
        const auto icmpv6_packet = make_ethernet_ipv6_icmpv6_with_hop_by_hop_packet(ipv6_src, ipv6_dst, 128U, 0U);
        const PacketRef packet_ref {
            .packet_index = 26,
            .byte_offset = 264,
            .captured_length = static_cast<std::uint32_t>(icmpv6_packet.size()),
            .original_length = static_cast<std::uint32_t>(icmpv6_packet.size()),
        };

        const auto details = service.decode(icmpv6_packet, packet_ref);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->has_icmpv6);
        PFL_EXPECT(details->ipv6.traffic_class == 0U);
        PFL_EXPECT(details->ipv6.flow_label == 0U);
        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet_ref, {
            .protocol_details_text = session_detail::build_basic_protocol_details_text(*details).value_or(std::string {}),
        });
        PFL_EXPECT(summary_layers.size() >= 4U);
        PFL_EXPECT(summary_layers[summary_layers.size() - 2U].id == "ipv6");
        PFL_EXPECT(summary_layers.back().id == "icmpv6");
        PFL_EXPECT(summary_layers[summary_layers.size() - 2U].title.find("IPv6, Src:") != std::string::npos);
        const auto* ipv6_layer = find_summary_layer(summary_layers, "ipv6");
        PFL_REQUIRE(ipv6_layer != nullptr);
        const auto* ipv6_traffic_class_field = find_summary_field(*ipv6_layer, "Traffic Class");
        const auto* ipv6_flow_label_field = find_summary_field(*ipv6_layer, "Flow Label");
        const auto* ipv6_payload_length_field = find_summary_field(*ipv6_layer, "Payload Length");
        const auto* ipv6_next_header_field = find_summary_field(*ipv6_layer, "Next Header");
        PFL_REQUIRE(ipv6_traffic_class_field != nullptr);
        PFL_REQUIRE(ipv6_flow_label_field != nullptr);
        PFL_REQUIRE(ipv6_payload_length_field != nullptr);
        PFL_REQUIRE(ipv6_next_header_field != nullptr);
        PFL_EXPECT(ipv6_traffic_class_field->value == "0x00");
        PFL_EXPECT(ipv6_flow_label_field->value == "0x0");
        PFL_EXPECT(ipv6_payload_length_field->value == "16 bytes");
        PFL_EXPECT(ipv6_next_header_field->value == "ICMPv6 (58)");
        PFL_EXPECT(summary_layers.back().title.find("Internet Control Message Protocol v6") != std::string::npos);
    }

    {
        PacketDetailsService service {};
        const auto custom_arp_packet = make_ethernet_arp_packet_with_fields(
            {0x01, 0x02, 0x03},
            {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
            {0x04, 0x05, 0x06},
            {0x11, 0x22, 0x33, 0x44, 0x55, 0x66},
            3U,
            7U,
            0x1234U
        );
        const PacketRef packet_ref {
            .packet_index = 24,
            .byte_offset = 216,
            .captured_length = static_cast<std::uint32_t>(custom_arp_packet.size()),
            .original_length = static_cast<std::uint32_t>(custom_arp_packet.size()),
        };

        const auto details = service.decode(custom_arp_packet, packet_ref);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->has_arp);
        PFL_EXPECT(details->arp.hardware_type == 7U);
        PFL_EXPECT(details->arp.protocol_type == 0x1234U);
        PFL_EXPECT(details->arp.hardware_size == 3U);
        PFL_EXPECT(details->arp.protocol_size == 6U);
        PFL_EXPECT(details->arp.opcode == 3U);
        PFL_EXPECT(details->arp.sender_hardware_address.size() == 3U);
        PFL_EXPECT(details->arp.sender_protocol_address.size() == 6U);
        PFL_EXPECT(details->arp.target_hardware_address.size() == 3U);
        PFL_EXPECT(details->arp.target_protocol_address.size() == 6U);
    }

    {
        const auto path = write_temp_pcap("pfl_packet_details_session.pcap", make_classic_pcap({{100, tcp_packet}}));
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(path));
        PFL_EXPECT(session.state().ipv4_connections.size() == 1);

        const auto key = make_connection_key(FlowKeyV4 {
            .src_addr = ipv4(10, 0, 0, 1),
            .dst_addr = ipv4(10, 0, 0, 2),
            .src_port = 12345,
            .dst_port = 443,
            .protocol = ProtocolId::tcp,
        });
        const auto* connection = session.state().ipv4_connections.find(key);
        PFL_REQUIRE(connection != nullptr);

        const auto details = session.read_packet_details(connection->flow_a.packets.front());
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->packet_index == 0);
        PFL_EXPECT(details->has_tcp);
        PFL_EXPECT(details->tcp.dst_port == 443);

        const auto hex_dump = session.read_packet_hex_dump(connection->flow_a.packets.front());
        PFL_EXPECT(!hex_dump.empty());
        PFL_EXPECT(hex_dump.find("00000000") != std::string::npos);
    }

    {
        HexDumpService service {};
        const std::vector<std::uint8_t> bytes {
            0x00, 0x01, 0x41, 0x42, 0x7f, 0x20, 0x10, 0x11,
            0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
            0x30, 0x31, 0x32, 0x33,
        };

        const auto dump = service.format(bytes);
        PFL_EXPECT(dump.find("00000000") != std::string::npos);
        PFL_EXPECT(dump.find("00000010") != std::string::npos);
        PFL_EXPECT(dump.find("00 01 41 42 7f 20") != std::string::npos);
        PFL_EXPECT(dump.find("|..AB.") != std::string::npos);
    }

    {
        PacketDetailsService service {};
        const std::vector<std::uint8_t> short_packet {0x00, 0x01, 0x02};
        const PacketRef packet_ref {
            .packet_index = 9,
            .byte_offset = 0,
            .captured_length = 3,
            .original_length = 3,
        };

        PFL_EXPECT(!service.decode(short_packet, packet_ref).has_value());

        HexDumpService hex_dump {};
        PFL_EXPECT(hex_dump.format(std::span<const std::uint8_t> {}).empty());
    }
}

}  // namespace pfl::tests
