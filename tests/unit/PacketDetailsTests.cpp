#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "TestSupport.h"
#include "app/session/SessionFormatting.h"
#include "app/session/CaptureSession.h"
#include "core/domain/PacketDetails.h"
#include "core/domain/PacketRef.h"
#include "core/services/HexDumpService.h"
#include "core/services/PacketDetailsService.h"
#include "core/services/PacketPayloadService.h"
#include "PcapTestUtils.h"

namespace pfl::tests {

namespace {

std::filesystem::path fixture_path(const std::filesystem::path& relative_path) {
    return std::filesystem::path(__FILE__).parent_path().parent_path() / "data" / relative_path;
}

void append_be16(std::vector<std::uint8_t>& bytes, const std::uint16_t value) {
    bytes.push_back(static_cast<std::uint8_t>((value >> 8U) & 0xFFU));
    bytes.push_back(static_cast<std::uint8_t>(value & 0xFFU));
}

void append_be24(std::vector<std::uint8_t>& bytes, const std::uint32_t value) {
    bytes.push_back(static_cast<std::uint8_t>((value >> 16U) & 0xFFU));
    bytes.push_back(static_cast<std::uint8_t>((value >> 8U) & 0xFFU));
    bytes.push_back(static_cast<std::uint8_t>(value & 0xFFU));
}

std::vector<std::uint8_t> make_zero_filled(const std::size_t count) {
    return std::vector<std::uint8_t>(count, 0x00U);
}

void append_extension(
    std::vector<std::uint8_t>& bytes,
    const std::uint16_t extension_type,
    const std::vector<std::uint8_t>& body
) {
    append_be16(bytes, extension_type);
    append_be16(bytes, static_cast<std::uint16_t>(body.size()));
    bytes.insert(bytes.end(), body.begin(), body.end());
}

std::vector<std::uint8_t> make_tls_record(
    const std::uint8_t content_type,
    const std::uint16_t version,
    const std::vector<std::uint8_t>& body
) {
    std::vector<std::uint8_t> record {};
    record.push_back(content_type);
    append_be16(record, version);
    append_be16(record, static_cast<std::uint16_t>(body.size()));
    record.insert(record.end(), body.begin(), body.end());
    return record;
}

std::vector<std::uint8_t> make_tls_handshake_record(
    const std::uint8_t handshake_type,
    const std::vector<std::uint8_t>& body
) {
    std::vector<std::uint8_t> handshake {};
    handshake.push_back(handshake_type);
    append_be24(handshake, static_cast<std::uint32_t>(body.size()));
    handshake.insert(handshake.end(), body.begin(), body.end());
    return make_tls_record(0x16U, 0x0303U, handshake);
}

std::vector<std::uint8_t> make_minimal_client_hello_body_with_extensions(
    const std::vector<std::uint8_t>& extensions
) {
    std::vector<std::uint8_t> body {};
    append_be16(body, 0x0303U);
    const auto random = make_zero_filled(32U);
    body.insert(body.end(), random.begin(), random.end());
    body.push_back(0x00U);
    append_be16(body, 0x0002U);
    append_be16(body, 0x1301U);
    body.push_back(0x01U);
    body.push_back(0x00U);
    append_be16(body, static_cast<std::uint16_t>(extensions.size()));
    body.insert(body.end(), extensions.begin(), extensions.end());
    return body;
}

std::vector<std::uint8_t> make_minimal_server_hello_body_with_extensions(
    const std::vector<std::uint8_t>& extensions
) {
    std::vector<std::uint8_t> body {};
    append_be16(body, 0x0303U);
    const auto random = make_zero_filled(32U);
    body.insert(body.end(), random.begin(), random.end());
    body.push_back(0x00U);
    append_be16(body, 0x1301U);
    body.push_back(0x00U);
    append_be16(body, static_cast<std::uint16_t>(extensions.size()));
    body.insert(body.end(), extensions.begin(), extensions.end());
    return body;
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

std::string require_summary_field_value(
    const session_detail::PacketSummaryLayer& layer,
    const std::string& label
) {
    const auto* field = find_summary_field(layer, label);
    PFL_REQUIRE(field != nullptr);
    return field->value;
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

const session_detail::PacketSummaryLayer* require_summary_child(
    const session_detail::PacketSummaryLayer& layer,
    const std::string& id,
    const std::size_t occurrence = 0U
) {
    const auto* child = find_summary_child(layer, id, occurrence);
    PFL_REQUIRE(child != nullptr);
    return child;
}

void expect_summary_child_titles(
    const session_detail::PacketSummaryLayer& layer,
    const std::vector<std::string>& expected_titles
) {
    PFL_EXPECT(layer.children.size() == expected_titles.size());
    if (layer.children.size() != expected_titles.size()) {
        return;
    }

    for (std::size_t index = 0U; index < expected_titles.size(); ++index) {
        PFL_EXPECT(layer.children[index].title == expected_titles[index]);
    }
}

void expect_indexed_summary_field_values(
    const session_detail::PacketSummaryLayer& layer,
    const std::vector<std::string>& expected_values
) {
    PFL_EXPECT(layer.fields.size() == expected_values.size());
    if (layer.fields.size() != expected_values.size()) {
        return;
    }

    for (std::size_t index = 0U; index < expected_values.size(); ++index) {
        PFL_EXPECT(require_summary_field_value(layer, "[" + std::to_string(index) + "]") == expected_values[index]);
    }
}

std::vector<const session_detail::PacketSummaryLayer*> find_summary_layers(
    const std::vector<session_detail::PacketSummaryLayer>& layers,
    const std::string& id
) {
    std::vector<const session_detail::PacketSummaryLayer*> matches {};
    for (const auto& layer : layers) {
        if (layer.id == id) {
            matches.push_back(&layer);
        }
    }
    return matches;
}

std::size_t count_hex_byte_tokens(const std::string_view value) {
    std::size_t count = 0U;
    std::size_t offset = 0U;
    while (offset < value.size()) {
        while (offset < value.size() && value[offset] == ' ') {
            ++offset;
        }
        if (offset >= value.size()) {
            break;
        }
        const auto next_space = value.find(' ', offset);
        ++count;
        if (next_space == std::string_view::npos) {
            break;
        }
        offset = next_space + 1U;
    }
    return count;
}

std::vector<session_detail::PacketSummaryLayer> build_fixture_summary_layers(
    const std::filesystem::path& relative_fixture_path
) {
    CaptureSession session {};
    PFL_EXPECT(session.open_capture(fixture_path(relative_fixture_path), CaptureImportOptions {}));
    const auto packet = require_packet(session, 0U);
    const auto details = session.read_packet_details(packet);
    PFL_REQUIRE(details.has_value());
    const auto packet_bytes = session.read_packet_data(packet);
    PacketPayloadService payload_service {};
    const auto transport_payload = payload_service.extract_transport_payload(packet_bytes, packet.data_link_type);
    return session_detail::build_packet_summary_layers(*details, packet, {
        .source_capture_accessible = true,
        .transport_payload_length = packet.payload_length,
        .original_transport_payload_length = packet.payload_length,
        .transport_payload_bytes = std::span<const std::uint8_t>(transport_payload.data(), transport_payload.size()),
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
        PFL_EXPECT(session.open_capture(fixture_path("parsing/dns/dns_request_1.pcap"), CaptureImportOptions {}));
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
        PFL_EXPECT(session.open_capture(fixture_path("parsing/quic/quic_initial_ch_1.pcap"), CaptureImportOptions {}));
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
        PFL_EXPECT(session.open_capture(fixture_path("parsing/tls/tls_client_hello_1.pcap"), CaptureImportOptions {}));
        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        const auto summary_layers = build_fixture_summary_layers("parsing/tls/tls_client_hello_1.pcap");
        PFL_EXPECT(summary_layers.size() >= 5U);
        PFL_EXPECT(summary_layers[summary_layers.size() - 2U].id == "tcp");
        PFL_EXPECT(!summary_layers[summary_layers.size() - 2U].expanded_by_default);
        const auto tls_layers = find_summary_layers(summary_layers, "tls");
        PFL_REQUIRE(tls_layers.size() == 1U);
        const auto* tls_layer = tls_layers[0];
        PFL_EXPECT(tls_layer->expanded_by_default);
        PFL_EXPECT(tls_layer->title.find("Transport Layer Security") != std::string::npos);
        PFL_EXPECT(tls_layer->title.find("ClientHello") != std::string::npos);
        const auto* handshake_type = find_summary_field(*tls_layer, "Handshake Type");
        const auto* record_type = find_summary_field(*tls_layer, "Record Type");
        const auto* record_version = find_summary_field(*tls_layer, "Record Legacy Version");
        const auto* record_length = find_summary_field(*tls_layer, "Record Length");
        const auto* total_record_size = find_summary_field(*tls_layer, "Total Record Size");
        const auto* handshake_length = find_summary_field(*tls_layer, "Handshake Length");
        const auto* hello_version = find_summary_field(*tls_layer, "ClientHello Legacy Version");
        const auto* session_id_length = find_summary_field(*tls_layer, "Session ID Length");
        const auto* session_id = find_summary_field(*tls_layer, "Session ID");
        const auto* cipher_suite_count = find_summary_field(*tls_layer, "Cipher Suite Count");
        const auto* compression_method_count = find_summary_field(*tls_layer, "Compression Method Count");
        const auto* extension_count = find_summary_field(*tls_layer, "Extension Count");
        const auto* sni = find_summary_field(*tls_layer, "SNI");
        const auto* alpn = find_summary_field(*tls_layer, "ALPN");
        const auto* supported_versions = find_summary_field(*tls_layer, "Supported TLS Versions");
        PFL_REQUIRE(handshake_type != nullptr);
        PFL_REQUIRE(record_type != nullptr);
        PFL_REQUIRE(record_version != nullptr);
        PFL_REQUIRE(record_length != nullptr);
        PFL_REQUIRE(total_record_size != nullptr);
        PFL_REQUIRE(handshake_length != nullptr);
        PFL_REQUIRE(hello_version != nullptr);
        PFL_REQUIRE(session_id_length != nullptr);
        PFL_REQUIRE(session_id != nullptr);
        PFL_REQUIRE(cipher_suite_count != nullptr);
        PFL_REQUIRE(compression_method_count != nullptr);
        PFL_REQUIRE(extension_count != nullptr);
        PFL_REQUIRE(sni != nullptr);
        PFL_REQUIRE(alpn != nullptr);
        PFL_REQUIRE(supported_versions != nullptr);
        PFL_EXPECT(handshake_type->value == "ClientHello");
        PFL_EXPECT(record_type->value == "Handshake");
        PFL_EXPECT(record_version->value == "TLS 1.0 (0x0301)");
        PFL_EXPECT(record_length->value == "512");
        PFL_EXPECT(total_record_size->value == "517 bytes");
        PFL_EXPECT(handshake_length->value == "508");
        PFL_EXPECT(hello_version->value == "TLS 1.2 (0x0303)");
        PFL_EXPECT(session_id_length->value == "32");
        PFL_EXPECT(count_hex_byte_tokens(session_id->value) == 32U);
        PFL_EXPECT(cipher_suite_count->value == "16");
        PFL_EXPECT(compression_method_count->value == "1");
        PFL_EXPECT(extension_count->value == "18");
        PFL_EXPECT(sni->value == "auth.split.io");
        PFL_EXPECT(alpn->value.find("h2") != std::string::npos);
        PFL_EXPECT(alpn->value.find("http/1.1") != std::string::npos);
        PFL_EXPECT(supported_versions->value.find("TLS 1.3 (0x0304)") != std::string::npos);
        PFL_EXPECT(supported_versions->value.find("TLS 1.2 (0x0303)") != std::string::npos);
        const auto* cipher_suites_group = require_summary_child(*tls_layer, "tls_cipher_suites");
        const auto* compression_methods_group = require_summary_child(*tls_layer, "tls_compression_methods");
        const auto* extensions_group = require_summary_child(*tls_layer, "tls_extensions");
        PFL_EXPECT(cipher_suites_group->title == "Cipher Suites (16)");
        PFL_EXPECT(cipher_suites_group->children.empty());
        expect_indexed_summary_field_values(*cipher_suites_group, {
            "GREASE (0x8a8a)",
            "TLS_AES_128_GCM_SHA256 (0x1301)",
            "TLS_AES_256_GCM_SHA384 (0x1302)",
            "TLS_CHACHA20_POLY1305_SHA256 (0x1303)",
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (0xc02b)",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xc02f)",
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 (0xc02c)",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (0xc030)",
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 (0xcca9)",
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (0xcca8)",
            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (0xc013)",
            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA (0xc014)",
            "TLS_RSA_WITH_AES_128_GCM_SHA256 (0x009c)",
            "TLS_RSA_WITH_AES_256_GCM_SHA384 (0x009d)",
            "TLS_RSA_WITH_AES_128_CBC_SHA (0x002f)",
            "TLS_RSA_WITH_AES_256_CBC_SHA (0x0035)",
        });
        PFL_EXPECT(compression_methods_group->title == "Compression Methods (1)");
        PFL_EXPECT(compression_methods_group->children.empty());
        expect_indexed_summary_field_values(*compression_methods_group, {"null (0)"});
        PFL_EXPECT(extensions_group->title == "Extensions (18)");
        expect_summary_child_titles(*extensions_group, {
            "[0] GREASE (0xfafa), 0 bytes",
            "[1] server_name (0x0000), 18 bytes - auth.split.io",
            "[2] extended_master_secret (0x0017), 0 bytes",
            "[3] renegotiation_info (0xff01), 1 byte",
            "[4] supported_groups (0x000a), 10 bytes - GREASE (0x5a5a), x25519, secp256r1, ...",
            "[5] ec_point_formats (0x000b), 2 bytes",
            "[6] session_ticket (0x0023), 138 bytes",
            "[7] application_layer_protocol_negotiation (0x0010), 14 bytes - h2, http/1.1",
            "[8] status_request (0x0005), 5 bytes - OCSP (1)",
            "[9] signature_algorithms (0x000d), 18 bytes - ecdsa_secp256r1_sha256, rsa_pss_rsae_sha256, ...",
            "[10] signed_certificate_timestamp (0x0012), 0 bytes",
            "[11] key_share (0x0033), 43 bytes - x25519, 32 bytes, ...",
            "[12] psk_key_exchange_modes (0x002d), 2 bytes - psk_dhe_ke",
            "[13] supported_versions (0x002b), 7 bytes - GREASE, TLS 1.3 (0x0304), TLS 1.2 (0x0303)",
            "[14] compress_certificate (0x001b), 3 bytes - brotli",
            "[15] Unknown Extension (0x4469), 5 bytes",
            "[16] GREASE (0x9a9a), 1 byte",
            "[17] padding (0x0015), 64 bytes - 64 bytes",
        });
        PFL_EXPECT(require_summary_field_value(extensions_group->children[0], "Type") == "64250 (0xfafa)");
        PFL_EXPECT(require_summary_field_value(extensions_group->children[0], "Length") == "0");
        PFL_EXPECT(require_summary_field_value(extensions_group->children[1], "Type") == "0 (0x0000)");
        PFL_EXPECT(require_summary_field_value(extensions_group->children[1], "Length") == "18");
        PFL_EXPECT(find_summary_child(extensions_group->children[1], "tls_server_names") == nullptr);
        PFL_EXPECT(find_summary_child(extensions_group->children[7], "tls_alpn_protocols") == nullptr);
        PFL_EXPECT(find_summary_child(extensions_group->children[13], "tls_supported_versions") == nullptr);
        PFL_EXPECT(require_summary_field_value(extensions_group->children[1], "Server Name [0]") == "auth.split.io");
        PFL_EXPECT(require_summary_field_value(extensions_group->children[7], "ALPN [0]") == "h2");
        PFL_EXPECT(require_summary_field_value(extensions_group->children[7], "ALPN [1]") == "http/1.1");
        PFL_EXPECT(require_summary_field_value(extensions_group->children[4], "Group [0]") == "GREASE (0x5a5a)");
        PFL_EXPECT(require_summary_field_value(extensions_group->children[4], "Group [1]") == "x25519 (0x001d)");
        PFL_EXPECT(require_summary_field_value(extensions_group->children[4], "Group [2]") == "secp256r1 (0x0017)");
        PFL_EXPECT(require_summary_field_value(extensions_group->children[4], "Group [3]") == "secp384r1 (0x0018)");
        PFL_EXPECT(require_summary_field_value(extensions_group->children[8], "Status Type") == "OCSP (1)");
        PFL_EXPECT(require_summary_field_value(extensions_group->children[8], "Responder ID List Length") == "0");
        PFL_EXPECT(require_summary_field_value(extensions_group->children[8], "Request Extensions Length") == "0");
        PFL_EXPECT(require_summary_field_value(extensions_group->children[9], "Signature Scheme [0]") == "ecdsa_secp256r1_sha256 (0x0403)");
        PFL_EXPECT(require_summary_field_value(extensions_group->children[9], "Signature Scheme [1]") == "rsa_pss_rsae_sha256 (0x0804)");
        PFL_EXPECT(require_summary_field_value(extensions_group->children[9], "Signature Scheme [2]") == "rsa_pkcs1_sha256 (0x0401)");
        PFL_EXPECT(require_summary_field_value(extensions_group->children[9], "Signature Scheme [3]") == "ecdsa_secp384r1_sha384 (0x0503)");
        PFL_EXPECT(require_summary_field_value(extensions_group->children[9], "Signature Scheme [4]") == "rsa_pss_rsae_sha384 (0x0805)");
        PFL_EXPECT(require_summary_field_value(extensions_group->children[9], "Signature Scheme [5]") == "rsa_pkcs1_sha384 (0x0501)");
        PFL_EXPECT(require_summary_field_value(extensions_group->children[9], "Signature Scheme [6]") == "rsa_pss_rsae_sha512 (0x0806)");
        PFL_EXPECT(require_summary_field_value(extensions_group->children[9], "Signature Scheme [7]") == "rsa_pkcs1_sha512 (0x0601)");
        const auto* key_share_entry0 = require_summary_child(extensions_group->children[11], "tls_key_share_entry", 0U);
        const auto* key_share_entry1 = require_summary_child(extensions_group->children[11], "tls_key_share_entry", 1U);
        PFL_EXPECT(key_share_entry0->title == "[0] GREASE (0x5a5a), 1 byte");
        PFL_EXPECT(key_share_entry1->title == "[1] x25519 (0x001d), 32 bytes");
        PFL_EXPECT(require_summary_field_value(*key_share_entry0, "Group") == "GREASE (0x5a5a)");
        PFL_EXPECT(require_summary_field_value(*key_share_entry0, "Key Exchange Length") == "1 byte");
        PFL_EXPECT(require_summary_field_value(*key_share_entry1, "Group") == "x25519 (0x001d)");
        PFL_EXPECT(require_summary_field_value(*key_share_entry1, "Key Exchange Length") == "32 bytes");
        PFL_EXPECT(require_summary_field_value(extensions_group->children[12], "Mode [0]") == "psk_dhe_ke (1)");
        PFL_EXPECT(require_summary_field_value(extensions_group->children[13], "Version [0]") == "GREASE (0x5a5a)");
        PFL_EXPECT(require_summary_field_value(extensions_group->children[13], "Version [1]") == "TLS 1.3 (0x0304)");
        PFL_EXPECT(require_summary_field_value(extensions_group->children[13], "Version [2]") == "TLS 1.2 (0x0303)");
        PFL_EXPECT(require_summary_field_value(extensions_group->children[14], "Algorithm [0]") == "brotli (2)");
        PFL_EXPECT(require_summary_field_value(extensions_group->children[16], "Type") == "39578 (0x9a9a)");
        PFL_EXPECT(require_summary_field_value(extensions_group->children[16], "Length") == "1");
        PFL_EXPECT(require_summary_field_value(extensions_group->children[17], "Padding Length") == "64 bytes");
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/tls/tls_1_3_client_hello_5.pcap"), CaptureImportOptions {}));
        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        const auto summary_layers = build_fixture_summary_layers("parsing/tls/tls_1_3_client_hello_5.pcap");
        const auto tls_layers = find_summary_layers(summary_layers, "tls");
        PFL_REQUIRE(tls_layers.size() == 1U);
        const auto* tls_layer = tls_layers[0];
        PFL_EXPECT(tls_layer->title.find("ClientHello") != std::string::npos);
        const auto* total_record_size = find_summary_field(*tls_layer, "Total Record Size");
        const auto* record_length = find_summary_field(*tls_layer, "Record Length");
        const auto* handshake_type = find_summary_field(*tls_layer, "Handshake Type");
        const auto* hello_version = find_summary_field(*tls_layer, "ClientHello Legacy Version");
        const auto* session_id_length = find_summary_field(*tls_layer, "Session ID Length");
        const auto* cipher_suite_count = find_summary_field(*tls_layer, "Cipher Suite Count");
        const auto* compression_method_count = find_summary_field(*tls_layer, "Compression Method Count");
        const auto* extension_count = find_summary_field(*tls_layer, "Extension Count");
        const auto* sni = find_summary_field(*tls_layer, "SNI");
        const auto* alpn = find_summary_field(*tls_layer, "ALPN");
        const auto* supported_versions = find_summary_field(*tls_layer, "Supported TLS Versions");
        PFL_REQUIRE(total_record_size != nullptr);
        PFL_REQUIRE(record_length != nullptr);
        PFL_REQUIRE(handshake_type != nullptr);
        PFL_REQUIRE(hello_version != nullptr);
        PFL_REQUIRE(session_id_length != nullptr);
        PFL_REQUIRE(cipher_suite_count != nullptr);
        PFL_REQUIRE(compression_method_count != nullptr);
        PFL_REQUIRE(extension_count != nullptr);
        PFL_REQUIRE(sni != nullptr);
        PFL_REQUIRE(alpn != nullptr);
        PFL_REQUIRE(supported_versions != nullptr);
        PFL_EXPECT(total_record_size->value == "517 bytes");
        PFL_EXPECT(record_length->value == "512");
        PFL_EXPECT(handshake_type->value == "ClientHello");
        PFL_EXPECT(hello_version->value == "TLS 1.2 (0x0303)");
        PFL_EXPECT(session_id_length->value == "32");
        PFL_EXPECT(cipher_suite_count->value == "21");
        PFL_EXPECT(compression_method_count->value == "1");
        PFL_EXPECT(extension_count->value == "16");
        PFL_EXPECT(sni->value == "p101-fmf.icloud.com");
        PFL_EXPECT(alpn->value.find("h2") != std::string::npos);
        PFL_EXPECT(alpn->value.find("http/1.1") != std::string::npos);
        PFL_EXPECT(supported_versions->value.find("TLS 1.3 (0x0304)") != std::string::npos);
        PFL_EXPECT(supported_versions->value.find("TLS 1.2 (0x0303)") != std::string::npos);
        PFL_EXPECT(supported_versions->value.find("TLS 1.1 (0x0302)") != std::string::npos);
        PFL_EXPECT(supported_versions->value.find("TLS 1.0 (0x0301)") != std::string::npos);
        const auto* cipher_suites_group = require_summary_child(*tls_layer, "tls_cipher_suites");
        const auto* compression_methods_group = require_summary_child(*tls_layer, "tls_compression_methods");
        const auto* extensions_group = require_summary_child(*tls_layer, "tls_extensions");
        PFL_EXPECT(cipher_suites_group->title == "Cipher Suites (21)");
        PFL_EXPECT(cipher_suites_group->children.empty());
        expect_indexed_summary_field_values(*cipher_suites_group, {
            "GREASE (0x8a8a)",
            "TLS_AES_128_GCM_SHA256 (0x1301)",
            "TLS_AES_256_GCM_SHA384 (0x1302)",
            "TLS_CHACHA20_POLY1305_SHA256 (0x1303)",
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 (0xc02c)",
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (0xc02b)",
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 (0xcca9)",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (0xc030)",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xc02f)",
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (0xcca8)",
            "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA (0xc00a)",
            "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA (0xc009)",
            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA (0xc014)",
            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (0xc013)",
            "TLS_RSA_WITH_AES_256_GCM_SHA384 (0x009d)",
            "TLS_RSA_WITH_AES_128_GCM_SHA256 (0x009c)",
            "TLS_RSA_WITH_AES_256_CBC_SHA (0x0035)",
            "TLS_RSA_WITH_AES_128_CBC_SHA (0x002f)",
            "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA (0xc008)",
            "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA (0xc012)",
            "TLS_RSA_WITH_3DES_EDE_CBC_SHA (0x000a)",
        });
        PFL_EXPECT(compression_methods_group->title == "Compression Methods (1)");
        PFL_EXPECT(compression_methods_group->children.empty());
        expect_indexed_summary_field_values(*compression_methods_group, {"null (0)"});
        PFL_EXPECT(extensions_group->title == "Extensions (16)");
        expect_summary_child_titles(*extensions_group, {
            "[0] GREASE (0x9a9a), 0 bytes",
            "[1] server_name (0x0000), 24 bytes - p101-fmf.icloud.com",
            "[2] extended_master_secret (0x0017), 0 bytes",
            "[3] renegotiation_info (0xff01), 1 byte",
            "[4] supported_groups (0x000a), 12 bytes - GREASE (0x4a4a), x25519, secp256r1, ...",
            "[5] ec_point_formats (0x000b), 2 bytes",
            "[6] application_layer_protocol_negotiation (0x0010), 14 bytes - h2, http/1.1",
            "[7] status_request (0x0005), 5 bytes - OCSP (1)",
            "[8] signature_algorithms (0x000d), 22 bytes - ecdsa_secp256r1_sha256, rsa_pss_rsae_sha256, ...",
            "[9] signed_certificate_timestamp (0x0012), 0 bytes",
            "[10] key_share (0x0033), 43 bytes - x25519, 32 bytes, ...",
            "[11] psk_key_exchange_modes (0x002d), 2 bytes - psk_dhe_ke",
            "[12] supported_versions (0x002b), 11 bytes - GREASE, TLS 1.3 (0x0304), TLS 1.2 (0x0303), ...",
            "[13] compress_certificate (0x001b), 3 bytes - zlib",
            "[14] GREASE (0x0a0a), 1 byte",
            "[15] padding (0x0015), 189 bytes - 189 bytes",
        });
        PFL_EXPECT(require_summary_field_value(extensions_group->children[0], "Type") == "39578 (0x9a9a)");
        PFL_EXPECT(require_summary_field_value(extensions_group->children[0], "Length") == "0");
        PFL_EXPECT(require_summary_field_value(extensions_group->children[1], "Type") == "0 (0x0000)");
        PFL_EXPECT(require_summary_field_value(extensions_group->children[1], "Length") == "24");
        PFL_EXPECT(find_summary_child(extensions_group->children[1], "tls_server_names") == nullptr);
        PFL_EXPECT(find_summary_child(extensions_group->children[6], "tls_alpn_protocols") == nullptr);
        PFL_EXPECT(find_summary_child(extensions_group->children[12], "tls_supported_versions") == nullptr);
        PFL_EXPECT(require_summary_field_value(extensions_group->children[1], "Server Name [0]") == "p101-fmf.icloud.com");
        PFL_EXPECT(require_summary_field_value(extensions_group->children[6], "ALPN [0]") == "h2");
        PFL_EXPECT(require_summary_field_value(extensions_group->children[6], "ALPN [1]") == "http/1.1");
        PFL_EXPECT(require_summary_field_value(extensions_group->children[4], "Group [0]") == "GREASE (0x4a4a)");
        PFL_EXPECT(require_summary_field_value(extensions_group->children[4], "Group [1]") == "x25519 (0x001d)");
        PFL_EXPECT(require_summary_field_value(extensions_group->children[4], "Group [2]") == "secp256r1 (0x0017)");
        PFL_EXPECT(require_summary_field_value(extensions_group->children[4], "Group [3]") == "secp384r1 (0x0018)");
        PFL_EXPECT(require_summary_field_value(extensions_group->children[4], "Group [4]") == "secp521r1 (0x0019)");
        PFL_EXPECT(require_summary_field_value(extensions_group->children[7], "Status Type") == "OCSP (1)");
        PFL_EXPECT(require_summary_field_value(extensions_group->children[7], "Responder ID List Length") == "0");
        PFL_EXPECT(require_summary_field_value(extensions_group->children[7], "Request Extensions Length") == "0");
        PFL_EXPECT(require_summary_field_value(extensions_group->children[8], "Signature Scheme [0]") == "ecdsa_secp256r1_sha256 (0x0403)");
        PFL_EXPECT(require_summary_field_value(extensions_group->children[8], "Signature Scheme [1]") == "rsa_pss_rsae_sha256 (0x0804)");
        PFL_EXPECT(require_summary_field_value(extensions_group->children[8], "Signature Scheme [2]") == "rsa_pkcs1_sha256 (0x0401)");
        PFL_EXPECT(require_summary_field_value(extensions_group->children[8], "Signature Scheme [3]") == "ecdsa_secp384r1_sha384 (0x0503)");
        PFL_EXPECT(require_summary_field_value(extensions_group->children[8], "Signature Scheme [4]") == "rsa_pss_rsae_sha384 (0x0805)");
        PFL_EXPECT(require_summary_field_value(extensions_group->children[8], "Signature Scheme [5]") == "rsa_pss_rsae_sha384 (0x0805)");
        PFL_EXPECT(require_summary_field_value(extensions_group->children[8], "Signature Scheme [6]") == "rsa_pkcs1_sha384 (0x0501)");
        PFL_EXPECT(require_summary_field_value(extensions_group->children[8], "Signature Scheme [7]") == "rsa_pss_rsae_sha512 (0x0806)");
        PFL_EXPECT(require_summary_field_value(extensions_group->children[8], "Signature Scheme [8]") == "rsa_pkcs1_sha512 (0x0601)");
        PFL_EXPECT(require_summary_field_value(extensions_group->children[8], "Signature Scheme [9]") == "rsa_pkcs1_sha1 (0x0201)");
        const auto* key_share_entry0 = require_summary_child(extensions_group->children[10], "tls_key_share_entry", 0U);
        const auto* key_share_entry1 = require_summary_child(extensions_group->children[10], "tls_key_share_entry", 1U);
        PFL_EXPECT(key_share_entry0->title == "[0] GREASE (0x4a4a), 1 byte");
        PFL_EXPECT(key_share_entry1->title == "[1] x25519 (0x001d), 32 bytes");
        PFL_EXPECT(require_summary_field_value(*key_share_entry0, "Group") == "GREASE (0x4a4a)");
        PFL_EXPECT(require_summary_field_value(*key_share_entry0, "Key Exchange Length") == "1 byte");
        PFL_EXPECT(require_summary_field_value(*key_share_entry1, "Group") == "x25519 (0x001d)");
        PFL_EXPECT(require_summary_field_value(*key_share_entry1, "Key Exchange Length") == "32 bytes");
        PFL_EXPECT(require_summary_field_value(extensions_group->children[11], "Mode [0]") == "psk_dhe_ke (1)");
        PFL_EXPECT(require_summary_field_value(extensions_group->children[12], "Version [0]") == "GREASE (0x3a3a)");
        PFL_EXPECT(require_summary_field_value(extensions_group->children[12], "Version [1]") == "TLS 1.3 (0x0304)");
        PFL_EXPECT(require_summary_field_value(extensions_group->children[12], "Version [2]") == "TLS 1.2 (0x0303)");
        PFL_EXPECT(require_summary_field_value(extensions_group->children[12], "Version [3]") == "TLS 1.1 (0x0302)");
        PFL_EXPECT(require_summary_field_value(extensions_group->children[12], "Version [4]") == "TLS 1.0 (0x0301)");
        PFL_EXPECT(require_summary_field_value(extensions_group->children[13], "Algorithm [0]") == "zlib (1)");
        PFL_EXPECT(require_summary_field_value(extensions_group->children[14], "Type") == "2570 (0x0a0a)");
        PFL_EXPECT(require_summary_field_value(extensions_group->children[14], "Length") == "1");
        PFL_EXPECT(require_summary_field_value(extensions_group->children[15], "Padding Length") == "189 bytes");
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/tls/tls_1_2_server_hello_4.pcap"), CaptureImportOptions {}));
        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        const auto summary_layers = build_fixture_summary_layers("parsing/tls/tls_1_2_server_hello_4.pcap");
        const auto tls_layers = find_summary_layers(summary_layers, "tls");
        PFL_REQUIRE(tls_layers.size() == 1U);
        const auto* tls_layer = tls_layers[0];
        PFL_EXPECT(tls_layer->title.find("ServerHello") != std::string::npos);
        const auto* handshake_type = find_summary_field(*tls_layer, "Handshake Type");
        const auto* record_type = find_summary_field(*tls_layer, "Record Type");
        const auto* record_version = find_summary_field(*tls_layer, "Record Legacy Version");
        const auto* total_record_size = find_summary_field(*tls_layer, "Total Record Size");
        const auto* record_length = find_summary_field(*tls_layer, "Record Length");
        const auto* handshake_length = find_summary_field(*tls_layer, "Handshake Length");
        const auto* hello_version = find_summary_field(*tls_layer, "ServerHello Legacy Version");
        const auto* selected_tls_version = find_summary_field(*tls_layer, "Selected TLS Version");
        const auto* selected_cipher_suite = find_summary_field(*tls_layer, "Selected Cipher Suite");
        const auto* session_id_length = find_summary_field(*tls_layer, "Session ID Length");
        const auto* compression_method = find_summary_field(*tls_layer, "Compression Method");
        const auto* extension_count = find_summary_field(*tls_layer, "Extension Count");
        PFL_REQUIRE(handshake_type != nullptr);
        PFL_REQUIRE(record_type != nullptr);
        PFL_REQUIRE(record_version != nullptr);
        PFL_REQUIRE(total_record_size != nullptr);
        PFL_REQUIRE(record_length != nullptr);
        PFL_REQUIRE(handshake_length != nullptr);
        PFL_REQUIRE(hello_version != nullptr);
        PFL_REQUIRE(selected_tls_version != nullptr);
        PFL_REQUIRE(selected_cipher_suite != nullptr);
        PFL_REQUIRE(session_id_length != nullptr);
        PFL_REQUIRE(compression_method != nullptr);
        PFL_REQUIRE(extension_count != nullptr);
        PFL_EXPECT(handshake_type->value == "ServerHello");
        PFL_EXPECT(record_type->value == "Handshake");
        PFL_EXPECT(record_version->value == "TLS 1.2 (0x0303)");
        PFL_EXPECT(total_record_size->value == "96 bytes");
        PFL_EXPECT(record_length->value == "91");
        PFL_EXPECT(handshake_length->value == "87");
        PFL_EXPECT(hello_version->value == "TLS 1.2 (0x0303)");
        PFL_EXPECT(selected_tls_version->value == "TLS 1.2 (0x0303)");
        PFL_EXPECT(selected_cipher_suite->value == "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xc02f)");
        PFL_EXPECT(session_id_length->value == "32");
        PFL_EXPECT(compression_method->value == "null (0)");
        PFL_EXPECT(extension_count->value == "3");
        const auto* extensions_group = require_summary_child(*tls_layer, "tls_extensions");
        PFL_EXPECT(extensions_group->title == "Extensions (3)");
        expect_summary_child_titles(*extensions_group, {
            "[0] ec_point_formats (0x000b), 2 bytes",
            "[1] renegotiation_info (0xff01), 1 byte",
            "[2] extended_master_secret (0x0017), 0 bytes",
        });
        PFL_EXPECT(require_summary_field_value(extensions_group->children[0], "Type") == "11 (0x000b)");
        PFL_EXPECT(require_summary_field_value(extensions_group->children[0], "Length") == "2");
        PFL_EXPECT(require_summary_field_value(extensions_group->children[1], "Type") == "65281 (0xff01)");
        PFL_EXPECT(require_summary_field_value(extensions_group->children[1], "Length") == "1");
        PFL_EXPECT(require_summary_field_value(extensions_group->children[2], "Type") == "23 (0x0017)");
        PFL_EXPECT(require_summary_field_value(extensions_group->children[2], "Length") == "0");
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/tls/tls_1_3_server_hello_6.pcap"), CaptureImportOptions {}));
        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        const auto summary_layers = build_fixture_summary_layers("parsing/tls/tls_1_3_server_hello_6.pcap");
        std::size_t tcp_index = summary_layers.size();
        for (std::size_t index = 0U; index < summary_layers.size(); ++index) {
            if (summary_layers[index].id == "tcp") {
                tcp_index = index;
                break;
            }
        }
        PFL_REQUIRE(tcp_index < summary_layers.size());
        PFL_REQUIRE(tcp_index + 3U < summary_layers.size());
        PFL_EXPECT(summary_layers[tcp_index + 1U].id == "tls");
        PFL_EXPECT(summary_layers[tcp_index + 2U].id == "tls");
        PFL_EXPECT(summary_layers[tcp_index + 3U].id == "tls");

        const auto& server_hello_layer = summary_layers[tcp_index + 1U];
        const auto& ccs_layer = summary_layers[tcp_index + 2U];
        const auto& partial_layer = summary_layers[tcp_index + 3U];

        PFL_EXPECT(server_hello_layer.title.find("ServerHello") != std::string::npos);
        PFL_EXPECT(ccs_layer.title.find("ChangeCipherSpec") != std::string::npos);
        PFL_EXPECT(partial_layer.title.find("TLS Record Fragment (partial)") != std::string::npos);

        const auto* server_hello_total_size = find_summary_field(server_hello_layer, "Total Record Size");
        const auto* server_hello_record_length = find_summary_field(server_hello_layer, "Record Length");
        const auto* server_hello_record_version = find_summary_field(server_hello_layer, "Record Legacy Version");
        const auto* server_hello_handshake_length = find_summary_field(server_hello_layer, "Handshake Length");
        const auto* server_hello_legacy_version = find_summary_field(server_hello_layer, "ServerHello Legacy Version");
        const auto* server_hello_selected_tls_version = find_summary_field(server_hello_layer, "Selected TLS Version");
        const auto* server_hello_selected_cipher_suite = find_summary_field(server_hello_layer, "Selected Cipher Suite");
        const auto* server_hello_session_id_length = find_summary_field(server_hello_layer, "Session ID Length");
        const auto* server_hello_compression_method = find_summary_field(server_hello_layer, "Compression Method");
        const auto* server_hello_extension_count = find_summary_field(server_hello_layer, "Extension Count");
        PFL_REQUIRE(server_hello_total_size != nullptr);
        PFL_REQUIRE(server_hello_record_length != nullptr);
        PFL_REQUIRE(server_hello_record_version != nullptr);
        PFL_REQUIRE(server_hello_handshake_length != nullptr);
        PFL_REQUIRE(server_hello_legacy_version != nullptr);
        PFL_REQUIRE(server_hello_selected_tls_version != nullptr);
        PFL_REQUIRE(server_hello_selected_cipher_suite != nullptr);
        PFL_REQUIRE(server_hello_session_id_length != nullptr);
        PFL_REQUIRE(server_hello_compression_method != nullptr);
        PFL_REQUIRE(server_hello_extension_count != nullptr);
        PFL_EXPECT(server_hello_total_size->value == "1215 bytes");
        PFL_EXPECT(server_hello_record_length->value == "1210");
        PFL_EXPECT(server_hello_record_version->value == "TLS 1.2 (0x0303)");
        PFL_EXPECT(server_hello_handshake_length->value == "1206");
        PFL_EXPECT(server_hello_legacy_version->value == "TLS 1.2 (0x0303)");
        PFL_EXPECT(server_hello_selected_tls_version->value == "TLS 1.3 (0x0304)");
        PFL_EXPECT(server_hello_selected_cipher_suite->value == "TLS_AES_128_GCM_SHA256 (0x1301)");
        PFL_EXPECT(server_hello_session_id_length->value == "32");
        PFL_EXPECT(server_hello_compression_method->value == "null (0)");
        PFL_EXPECT(server_hello_extension_count->value == "2");
        const auto* server_hello_extensions_group = require_summary_child(server_hello_layer, "tls_extensions");
        PFL_EXPECT(server_hello_extensions_group->title == "Extensions (2)");
        expect_summary_child_titles(*server_hello_extensions_group, {
            "[0] key_share (0x0033), 1124 bytes - X25519MLKEM768, 1120 bytes",
            "[1] supported_versions (0x002b), 2 bytes - TLS 1.3 (0x0304)",
        });
        PFL_EXPECT(require_summary_field_value(server_hello_extensions_group->children[0], "Type") == "51 (0x0033)");
        PFL_EXPECT(require_summary_field_value(server_hello_extensions_group->children[0], "Length") == "1124");
        PFL_EXPECT(require_summary_field_value(server_hello_extensions_group->children[1], "Type") == "43 (0x002b)");
        PFL_EXPECT(require_summary_field_value(server_hello_extensions_group->children[1], "Length") == "2");
        const auto* key_share_entry = require_summary_child(server_hello_extensions_group->children[0], "tls_key_share_entry");
        PFL_EXPECT(key_share_entry->title == "[0] X25519MLKEM768 (0x11ec), 1120 bytes");
        PFL_EXPECT(require_summary_field_value(*key_share_entry, "Group") == "X25519MLKEM768 (0x11ec)");
        PFL_EXPECT(require_summary_field_value(*key_share_entry, "Key Exchange Length") == "1120 bytes");
        PFL_EXPECT(find_summary_child(server_hello_extensions_group->children[1], "tls_supported_versions") == nullptr);
        PFL_EXPECT(require_summary_field_value(server_hello_extensions_group->children[1], "Version [0]") == "TLS 1.3 (0x0304)");

        const auto* ccs_total_size = find_summary_field(ccs_layer, "Total Record Size");
        const auto* ccs_record_length = find_summary_field(ccs_layer, "Record Length");
        const auto* ccs_record_version = find_summary_field(ccs_layer, "Record Legacy Version");
        const auto* ccs_handshake_type = find_summary_field(ccs_layer, "Handshake Type");
        PFL_REQUIRE(ccs_total_size != nullptr);
        PFL_REQUIRE(ccs_record_length != nullptr);
        PFL_REQUIRE(ccs_record_version != nullptr);
        PFL_EXPECT(ccs_total_size->value == "6 bytes");
        PFL_EXPECT(ccs_record_length->value == "1");
        PFL_EXPECT(ccs_record_version->value == "TLS 1.2 (0x0303)");
        PFL_EXPECT(ccs_handshake_type == nullptr);

        const auto* partial_status = find_summary_field(partial_layer, "Status");
        const auto* partial_available_bytes = find_summary_field(partial_layer, "Available Bytes");
        const auto* partial_handshake_type = find_summary_field(partial_layer, "Handshake Type");
        const auto* partial_selected_tls_version = find_summary_field(partial_layer, "Selected TLS Version");
        const auto* partial_selected_cipher_suite = find_summary_field(partial_layer, "Selected Cipher Suite");
        PFL_REQUIRE(partial_status != nullptr);
        PFL_REQUIRE(partial_available_bytes != nullptr);
        PFL_EXPECT(partial_status->value == "Incomplete record body");
        PFL_EXPECT(partial_available_bytes->value == "179");
        PFL_EXPECT(partial_handshake_type == nullptr);
        PFL_EXPECT(partial_selected_tls_version == nullptr);
        PFL_EXPECT(partial_selected_cipher_suite == nullptr);
    }

    {
        const auto summary_layers = build_fixture_summary_layers("parsing/tls/tls_1_2_app_data_3.pcap");
        const auto tls_layers = find_summary_layers(summary_layers, "tls");
        PFL_REQUIRE(tls_layers.size() == 1U);
        PFL_EXPECT(tls_layers[0]->title.find("ApplicationData") != std::string::npos);
        PFL_EXPECT(require_summary_field_value(*tls_layers[0], "Record Type") == "ApplicationData");
        PFL_EXPECT(require_summary_field_value(*tls_layers[0], "Record Legacy Version") == "TLS 1.2 (0x0303)");
        PFL_EXPECT(require_summary_field_value(*tls_layers[0], "Record Length") == "652");
        PFL_EXPECT(require_summary_field_value(*tls_layers[0], "Total Record Size") == "657 bytes");
        PFL_EXPECT(find_summary_field(*tls_layers[0], "Handshake Type") == nullptr);
    }

    {
        const auto summary_layers = build_fixture_summary_layers("parsing/tls/tls_1_3_app_data_7.pcap");
        const auto tls_layers = find_summary_layers(summary_layers, "tls");
        PFL_REQUIRE(tls_layers.size() == 2U);
        PFL_EXPECT(tls_layers[0]->title.find("ApplicationData") != std::string::npos);
        PFL_EXPECT(require_summary_field_value(*tls_layers[0], "Record Type") == "ApplicationData");
        PFL_EXPECT(require_summary_field_value(*tls_layers[0], "Record Legacy Version") == "TLS 1.2 (0x0303)");
        PFL_EXPECT(require_summary_field_value(*tls_layers[0], "Record Length") == "911");
        PFL_EXPECT(require_summary_field_value(*tls_layers[0], "Total Record Size") == "916 bytes");
        PFL_EXPECT(tls_layers[1]->title.find("ApplicationData") != std::string::npos);
        PFL_EXPECT(require_summary_field_value(*tls_layers[1], "Record Type") == "ApplicationData");
        PFL_EXPECT(require_summary_field_value(*tls_layers[1], "Record Legacy Version") == "TLS 1.2 (0x0303)");
        PFL_EXPECT(require_summary_field_value(*tls_layers[1], "Record Length") == "57");
        PFL_EXPECT(require_summary_field_value(*tls_layers[1], "Total Record Size") == "62 bytes");
    }

    {
        const auto summary_layers = build_fixture_summary_layers("parsing/tls/tls_1_2_change_cipher_spec_2.pcap");
        const auto tls_layers = find_summary_layers(summary_layers, "tls");
        PFL_REQUIRE(tls_layers.size() == 2U);
        PFL_EXPECT(tls_layers[0]->title.find("ChangeCipherSpec") != std::string::npos);
        PFL_EXPECT(require_summary_field_value(*tls_layers[0], "Record Type") == "ChangeCipherSpec");
        PFL_EXPECT(require_summary_field_value(*tls_layers[0], "Record Length") == "1");
        PFL_EXPECT(tls_layers[1]->title.find("Encrypted Handshake Message") != std::string::npos);
        PFL_EXPECT(require_summary_field_value(*tls_layers[1], "Record Type") == "Handshake");
        PFL_EXPECT(require_summary_field_value(*tls_layers[1], "Record Legacy Version") == "TLS 1.2 (0x0303)");
        PFL_EXPECT(require_summary_field_value(*tls_layers[1], "Record Length") == "40");
        PFL_EXPECT(require_summary_field_value(*tls_layers[1], "Total Record Size") == "45 bytes");
        PFL_EXPECT(require_summary_field_value(*tls_layers[1], "Payload Interpretation") == "Encrypted/opaque handshake payload");
        PFL_EXPECT(find_summary_field(*tls_layers[1], "Handshake Type") == nullptr);
        PFL_EXPECT(find_summary_field(*tls_layers[1], "Handshake Length") == nullptr);
    }

    {
        const auto summary_layers = build_fixture_summary_layers("parsing/tls/tls_1_3_change_cipher_spec_8.pcap");
        const auto tls_layers = find_summary_layers(summary_layers, "tls");
        PFL_REQUIRE(tls_layers.size() == 2U);
        PFL_EXPECT(tls_layers[0]->title.find("ChangeCipherSpec") != std::string::npos);
        PFL_EXPECT(require_summary_field_value(*tls_layers[0], "Record Type") == "ChangeCipherSpec");
        PFL_EXPECT(require_summary_field_value(*tls_layers[0], "Record Length") == "1");
        PFL_EXPECT(tls_layers[1]->title.find("ApplicationData") != std::string::npos);
        PFL_EXPECT(require_summary_field_value(*tls_layers[1], "Record Type") == "ApplicationData");
        PFL_EXPECT(require_summary_field_value(*tls_layers[1], "Record Legacy Version") == "TLS 1.2 (0x0303)");
        PFL_EXPECT(require_summary_field_value(*tls_layers[1], "Record Length") == "69");
        PFL_EXPECT(require_summary_field_value(*tls_layers[1], "Total Record Size") == "74 bytes");
    }

    {
        const auto summary_layers = build_fixture_summary_layers("parsing/tls/tls_1_2_new_session_ticket_9.pcap");
        const auto tls_layers = find_summary_layers(summary_layers, "tls");
        PFL_REQUIRE(tls_layers.size() == 3U);
        PFL_EXPECT(tls_layers[0]->title.find("NewSessionTicket") != std::string::npos);
        PFL_EXPECT(require_summary_field_value(*tls_layers[0], "Record Type") == "Handshake");
        PFL_EXPECT(require_summary_field_value(*tls_layers[0], "Record Legacy Version") == "TLS 1.2 (0x0303)");
        PFL_EXPECT(require_summary_field_value(*tls_layers[0], "Record Length") == "186");
        PFL_EXPECT(require_summary_field_value(*tls_layers[0], "Total Record Size") == "191 bytes");
        PFL_EXPECT(require_summary_field_value(*tls_layers[0], "Handshake Type") == "NewSessionTicket");
        PFL_EXPECT(require_summary_field_value(*tls_layers[0], "Handshake Length") == "182");
        PFL_EXPECT(require_summary_field_value(*tls_layers[0], "Session Ticket Lifetime Hint") == "7200 seconds");
        PFL_EXPECT(require_summary_field_value(*tls_layers[0], "Session Ticket Length") == "176 bytes");
        PFL_EXPECT(find_summary_field(*tls_layers[0], "Ticket Bytes") == nullptr);
        PFL_EXPECT(find_summary_field(*tls_layers[0], "Payload Interpretation") == nullptr);
        PFL_EXPECT(tls_layers[1]->title.find("ChangeCipherSpec") != std::string::npos);
        PFL_EXPECT(require_summary_field_value(*tls_layers[1], "Record Type") == "ChangeCipherSpec");
        PFL_EXPECT(require_summary_field_value(*tls_layers[1], "Record Length") == "1");
        PFL_EXPECT(tls_layers[2]->title.find("Encrypted Handshake Message") != std::string::npos);
        PFL_EXPECT(require_summary_field_value(*tls_layers[2], "Record Type") == "Handshake");
        PFL_EXPECT(require_summary_field_value(*tls_layers[2], "Record Legacy Version") == "TLS 1.2 (0x0303)");
        PFL_EXPECT(require_summary_field_value(*tls_layers[2], "Record Length") == "40");
        PFL_EXPECT(require_summary_field_value(*tls_layers[2], "Total Record Size") == "45 bytes");
        PFL_EXPECT(require_summary_field_value(*tls_layers[2], "Payload Interpretation") == "Encrypted/opaque handshake payload");
        PFL_EXPECT(find_summary_field(*tls_layers[2], "Handshake Type") == nullptr);
        PFL_EXPECT(find_summary_field(*tls_layers[2], "Handshake Length") == nullptr);
        PFL_EXPECT(find_summary_field(*tls_layers[2], "Session Ticket Lifetime Hint") == nullptr);
        PFL_EXPECT(find_summary_field(*tls_layers[2], "Session Ticket Length") == nullptr);
    }

    {
        std::vector<std::uint8_t> malformed_extensions {};
        append_extension(malformed_extensions, 0x000AU, {0x00U, 0x03U, 0x00U, 0x1DU, 0x00U});
        const auto malformed_summary_layers = session_detail::build_tls_summary_layers(
            make_tls_handshake_record(0x01U, make_minimal_client_hello_body_with_extensions(malformed_extensions))
        );
        const auto* malformed_tls_layer = find_summary_layer(malformed_summary_layers, "tls");
        PFL_REQUIRE(malformed_tls_layer != nullptr);
        const auto* malformed_extensions_group = require_summary_child(*malformed_tls_layer, "tls_extensions");
        PFL_REQUIRE(malformed_extensions_group->children.size() == 1U);
        PFL_EXPECT(malformed_extensions_group->children[0].title == "[0] supported_groups (0x000a), 5 bytes");
        PFL_EXPECT(require_summary_field_value(malformed_extensions_group->children[0], "Type") == "10 (0x000a)");
        PFL_EXPECT(require_summary_field_value(malformed_extensions_group->children[0], "Length") == "5");
        PFL_EXPECT(require_summary_field_value(malformed_extensions_group->children[0], "Structured Details") == "Malformed");
        PFL_EXPECT(find_summary_field(malformed_extensions_group->children[0], "Group [0]") == nullptr);
        PFL_EXPECT(find_summary_child(malformed_extensions_group->children[0], "tls_key_share_entry") == nullptr);

        std::vector<std::uint8_t> hrr_extensions {};
        append_extension(hrr_extensions, 0x0033U, {0x00U, 0x1DU});
        const auto hrr_summary_layers = session_detail::build_tls_summary_layers(
            make_tls_handshake_record(0x02U, make_minimal_server_hello_body_with_extensions(hrr_extensions))
        );
        const auto* hrr_tls_layer = find_summary_layer(hrr_summary_layers, "tls");
        PFL_REQUIRE(hrr_tls_layer != nullptr);
        const auto* hrr_extensions_group = require_summary_child(*hrr_tls_layer, "tls_extensions");
        PFL_REQUIRE(hrr_extensions_group->children.size() == 1U);
        PFL_EXPECT(hrr_extensions_group->children[0].title == "[0] key_share (0x0033), 2 bytes");
        PFL_EXPECT(require_summary_field_value(hrr_extensions_group->children[0], "Structured Details") == "Not decoded");
        PFL_EXPECT(find_summary_child(hrr_extensions_group->children[0], "tls_key_share_entry") == nullptr);
        PFL_EXPECT(find_summary_field(hrr_extensions_group->children[0], "Group [0]") == nullptr);
    }

    {
        PacketDetailsService service {};
        const auto non_tls_packet = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
            ipv4(10, 0, 0, 9), ipv4(10, 0, 0, 10), 41001, 443, {0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U}, 0x18);
        const PacketRef packet_ref {
            .packet_index = 27,
            .byte_offset = 320,
            .captured_length = static_cast<std::uint32_t>(non_tls_packet.size()),
            .original_length = static_cast<std::uint32_t>(non_tls_packet.size()),
        };
        const auto details = service.decode(non_tls_packet, packet_ref);
        PFL_REQUIRE(details.has_value());
        PacketPayloadService payload_service {};
        const auto transport_payload = payload_service.extract_transport_payload(non_tls_packet);
        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet_ref, {
            .transport_payload_length = static_cast<std::uint32_t>(transport_payload.size()),
            .original_transport_payload_length = static_cast<std::uint32_t>(transport_payload.size()),
            .transport_payload_bytes = std::span<const std::uint8_t>(transport_payload.data(), transport_payload.size()),
            .protocol_details_text = "No protocol-specific details available for this packet.",
        });
        PFL_EXPECT(find_summary_layer(summary_layers, "tls") == nullptr);
    }

    {
        PacketDetailsService service {};
        const auto short_tls_like_packet = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
            ipv4(10, 0, 0, 11), ipv4(10, 0, 0, 12), 41002, 443, {0x16U, 0x03U, 0x03U, 0x00U}, 0x18);
        const PacketRef packet_ref {
            .packet_index = 28,
            .byte_offset = 360,
            .captured_length = static_cast<std::uint32_t>(short_tls_like_packet.size()),
            .original_length = static_cast<std::uint32_t>(short_tls_like_packet.size()),
        };
        const auto details = service.decode(short_tls_like_packet, packet_ref);
        PFL_REQUIRE(details.has_value());
        PacketPayloadService payload_service {};
        const auto transport_payload = payload_service.extract_transport_payload(short_tls_like_packet);
        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet_ref, {
            .transport_payload_length = static_cast<std::uint32_t>(transport_payload.size()),
            .original_transport_payload_length = static_cast<std::uint32_t>(transport_payload.size()),
            .transport_payload_bytes = std::span<const std::uint8_t>(transport_payload.data(), transport_payload.size()),
            .protocol_details_text = "No protocol-specific details available for this packet.",
        });
        PFL_EXPECT(find_summary_layer(summary_layers, "tls") == nullptr);
    }

    {
        PacketDetailsService service {};
        const auto incomplete_tls_like_packet = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
            ipv4(10, 0, 0, 13), ipv4(10, 0, 0, 14), 41003, 443, {0x16U, 0x03U, 0x03U, 0x00U, 0x08U, 0x01U, 0x02U}, 0x18);
        const PacketRef packet_ref {
            .packet_index = 29,
            .byte_offset = 400,
            .captured_length = static_cast<std::uint32_t>(incomplete_tls_like_packet.size()),
            .original_length = static_cast<std::uint32_t>(incomplete_tls_like_packet.size()),
        };
        const auto details = service.decode(incomplete_tls_like_packet, packet_ref);
        PFL_REQUIRE(details.has_value());
        PacketPayloadService payload_service {};
        const auto transport_payload = payload_service.extract_transport_payload(incomplete_tls_like_packet);
        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet_ref, {
            .transport_payload_length = static_cast<std::uint32_t>(transport_payload.size()),
            .original_transport_payload_length = static_cast<std::uint32_t>(transport_payload.size()),
            .transport_payload_bytes = std::span<const std::uint8_t>(transport_payload.data(), transport_payload.size()),
            .protocol_details_text = "No protocol-specific details available for this packet.",
        });
        PFL_EXPECT(find_summary_layer(summary_layers, "tls") == nullptr);
    }

    {
        PacketDetailsService service {};
        const auto unknown_tls_type_packet = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
            ipv4(10, 0, 0, 15), ipv4(10, 0, 0, 16), 41004, 443, {0x99U, 0x03U, 0x03U, 0x00U, 0x02U, 0xAAU, 0xBBU}, 0x18);
        const PacketRef packet_ref {
            .packet_index = 30,
            .byte_offset = 440,
            .captured_length = static_cast<std::uint32_t>(unknown_tls_type_packet.size()),
            .original_length = static_cast<std::uint32_t>(unknown_tls_type_packet.size()),
        };
        const auto details = service.decode(unknown_tls_type_packet, packet_ref);
        PFL_REQUIRE(details.has_value());
        PacketPayloadService payload_service {};
        const auto transport_payload = payload_service.extract_transport_payload(unknown_tls_type_packet);
        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet_ref, {
            .transport_payload_length = static_cast<std::uint32_t>(transport_payload.size()),
            .original_transport_payload_length = static_cast<std::uint32_t>(transport_payload.size()),
            .transport_payload_bytes = std::span<const std::uint8_t>(transport_payload.data(), transport_payload.size()),
            .protocol_details_text = "No protocol-specific details available for this packet.",
        });
        PFL_EXPECT(find_summary_layer(summary_layers, "tls") == nullptr);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/http/http_get_1.pcap"), CaptureImportOptions {}));
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

        const auto connections = session.state().ipv4_connections.list();
        PFL_REQUIRE(connections.size() == 1U);
        const auto* connection = connections.front();
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

