#include <algorithm>
#include <array>
#include <cstdint>
#include <filesystem>
#include <iomanip>
#include <sstream>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "TestSupport.h"
#include "app/session/SelectedPacketSummaryPreparation.h"
#include "app/session/SelectedFlowPacketSemantics.h"
#include "app/session/SessionFormatting.h"
#include "app/session/CaptureSession.h"
#include "app/session/SessionTlsPresentation.h"
#include "core/domain/PacketDetails.h"
#include "core/domain/PacketRef.h"
#include "core/io/PcapReader.h"
#include "core/io/LinkType.h"
#include "core/services/HexDumpService.h"
#include "core/services/PacketDetailsService.h"
#include "core/services/PacketPayloadService.h"
#include "PcapTestUtils.h"

namespace pfl::tests {

namespace {

template <typename T>
concept has_selected_initial_plaintext_payload_member = requires(const T& value) {
    value.selected_initial_plaintext_payload;
};

static_assert(!has_selected_initial_plaintext_payload_member<session_detail::QuicStreamItemPresentation>);
static_assert(!has_selected_initial_plaintext_payload_member<StreamItemRow>);

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

RawPcapPacket require_first_raw_packet(const std::filesystem::path& capture_path) {
    PcapReader reader {};
    PFL_REQUIRE(reader.open(capture_path));
    const auto packet = reader.read_next();
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

const session_detail::PacketSummaryLayer* find_descendant_summary_layer(
    const session_detail::PacketSummaryLayer& layer,
    const std::string& id
) {
    for (const auto& child : layer.children) {
        if (child.id == id) {
            return &child;
        }
        if (const auto* descendant = find_descendant_summary_layer(child, id); descendant != nullptr) {
            return descendant;
        }
    }
    return nullptr;
}

const session_detail::PacketSummaryField* find_descendant_summary_field(
    const session_detail::PacketSummaryLayer& layer,
    const std::string& label
) {
    if (const auto* field = find_summary_field(layer, label); field != nullptr) {
        return field;
    }

    for (const auto& child : layer.children) {
        if (const auto* descendant = find_descendant_summary_field(child, label); descendant != nullptr) {
            return descendant;
        }
    }
    return nullptr;
}

const session_detail::PacketSummaryLayer* find_descendant_summary_layer_with_field_value(
    const session_detail::PacketSummaryLayer& layer,
    const std::string& label,
    const std::string& value
) {
    if (const auto* field = find_summary_field(layer, label); field != nullptr && field->value == value) {
        return &layer;
    }

    for (const auto& child : layer.children) {
        if (const auto* descendant = find_descendant_summary_layer_with_field_value(child, label, value);
            descendant != nullptr) {
            return descendant;
        }
    }
    return nullptr;
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

std::size_t find_summary_layer_index(
    const std::vector<session_detail::PacketSummaryLayer>& layers,
    const std::string& id,
    const std::size_t occurrence = 0U
) {
    std::size_t seen = 0U;
    for (std::size_t index = 0U; index < layers.size(); ++index) {
        if (layers[index].id != id) {
            continue;
        }
        if (seen == occurrence) {
            return index;
        }
        ++seen;
    }
    return layers.size();
}

struct SelectedPacketSummaryResult {
    std::vector<session_detail::PacketSummaryLayer> summary_layers {};
    std::vector<session_detail::TlsSelectedPacketRecordContext> reconstructed_tls_records {};
};

struct SelectedPacketTransportPayloadLengths {
    std::optional<std::uint32_t> captured_transport_payload_length {};
    std::optional<std::uint32_t> original_transport_payload_length {};
};

SelectedPacketTransportPayloadLengths resolve_selected_packet_transport_payload_lengths(
    CaptureSession& session,
    const PacketRef& packet
) {
    return SelectedPacketTransportPayloadLengths {
        .captured_transport_payload_length = std::optional<std::uint32_t> {packet.payload_length},
        .original_transport_payload_length =
            session_detail::derive_original_transport_payload_length_from_headers(session, packet),
    };
}

struct SelectedPacketFlowContext {
    std::optional<std::size_t> flow_index {};
    std::optional<std::uint64_t> flow_packet_index {};
    std::optional<std::size_t> loaded_packet_window_count {};
};

SelectedPacketFlowContext resolve_selected_packet_flow_context(
    CaptureSession& session,
    const PacketRef& packet
) {
    SelectedPacketFlowContext context {};
    const auto flow_rows = session.list_flows();
    for (const auto& flow_row : flow_rows) {
        const auto packet_rows = session.list_flow_packets(flow_row.index);
        const auto packet_it = std::find_if(packet_rows.begin(), packet_rows.end(), [&](const PacketRow& row) {
            return row.packet_index == packet.packet_index;
        });
        if (packet_it == packet_rows.end()) {
            continue;
        }

        context.flow_index = flow_row.index;
        PFL_REQUIRE(packet_it->row_number > 0U);
        context.flow_packet_index = packet_it->row_number - 1U;
        context.loaded_packet_window_count = packet_rows.size();
        break;
    }

    return context;
}

session_detail::SelectedPacketSummaryPreparation prepare_selected_packet_summary_with_production_lengths(
    CaptureSession& session,
    const PacketDetails& details,
    const PacketRef& packet,
    const std::optional<std::size_t> flow_index,
    const std::optional<std::uint64_t> flow_packet_index,
    const std::optional<std::size_t> loaded_packet_window_count
) {
    const auto payload_lengths = resolve_selected_packet_transport_payload_lengths(session, packet);
    return session_detail::prepare_selected_packet_summary(
        session,
        details,
        packet,
        flow_index,
        flow_packet_index,
        loaded_packet_window_count,
        payload_lengths.captured_transport_payload_length,
        payload_lengths.original_transport_payload_length
    );
}

SelectedPacketSummaryResult build_selected_packet_summary(
    CaptureSession& session,
    const std::size_t flow_index,
    const std::uint64_t packet_index,
    const std::uint64_t flow_packet_index,
    const std::size_t loaded_packet_window_count
) {
    const auto packet = require_packet(session, packet_index);
    const auto details = session.read_packet_details(packet);
    PFL_REQUIRE(details.has_value());
    auto packet_summary_preparation = prepare_selected_packet_summary_with_production_lengths(
        session,
        *details,
        packet,
        flow_index,
        flow_packet_index,
        loaded_packet_window_count
    );

    auto summary_layers = session_detail::build_packet_summary_layers(
        *details,
        packet,
        packet_summary_preparation.make_options()
    );
    auto reconstructed_tls_records = packet_summary_preparation.reconstructed_tls_records;
    return SelectedPacketSummaryResult {
        .summary_layers = std::move(summary_layers),
        .reconstructed_tls_records = std::move(reconstructed_tls_records),
    };
}

std::uint64_t require_flow_packet_index(
    CaptureSession& session,
    const std::size_t flow_index,
    const std::uint64_t packet_index
) {
    const auto rows = session.list_flow_packets(flow_index);
    const auto it = std::find_if(rows.begin(), rows.end(), [&](const PacketRow& row) {
        return row.packet_index == packet_index;
    });
    PFL_REQUIRE(it != rows.end());
    PFL_REQUIRE(it->row_number > 0U);
    return it->row_number - 1U;
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

std::string format_expected_hex_byte_list(std::span<const std::uint8_t> bytes) {
    std::ostringstream builder {};
    builder << std::hex << std::setfill('0');
    for (std::size_t index = 0U; index < bytes.size(); ++index) {
        if (index > 0U) {
            builder << ' ';
        }
        builder << std::setw(2) << static_cast<unsigned>(bytes[index]);
    }
    return builder.str();
}

std::string format_transport_port_prefix_hex(const std::uint16_t src_port, const std::uint16_t dst_port) {
    const std::array<std::uint8_t, 4> bytes {
        static_cast<std::uint8_t>((src_port >> 8U) & 0xFFU),
        static_cast<std::uint8_t>(src_port & 0xFFU),
        static_cast<std::uint8_t>((dst_port >> 8U) & 0xFFU),
        static_cast<std::uint8_t>(dst_port & 0xFFU),
    };
    return format_expected_hex_byte_list(bytes);
}

std::vector<session_detail::PacketSummaryLayer> build_fixture_summary_layers(
    const std::filesystem::path& relative_fixture_path,
    const CaptureImportOptions& options,
    const std::uint64_t packet_index
) {
    CaptureSession session {};
    PFL_EXPECT(session.open_capture(fixture_path(relative_fixture_path), options));
    const auto packet = require_packet(session, packet_index);
    const auto details = session.read_packet_details(packet);
    PFL_REQUIRE(details.has_value());
    const auto flow_context = resolve_selected_packet_flow_context(session, packet);
    auto packet_summary_preparation = prepare_selected_packet_summary_with_production_lengths(
        session,
        *details,
        packet,
        flow_context.flow_index,
        flow_context.flow_packet_index,
        flow_context.loaded_packet_window_count
    );
    return session_detail::build_packet_summary_layers(*details, packet, packet_summary_preparation.make_options());
}

std::vector<session_detail::PacketSummaryLayer> build_fixture_summary_layers(
    const std::filesystem::path& relative_fixture_path
) {
    return build_fixture_summary_layers(relative_fixture_path, CaptureImportOptions {}, 0U);
}

std::vector<session_detail::PacketSummaryLayer> build_capture_summary_layers(
    const std::filesystem::path& capture_path,
    const std::uint64_t packet_index = 0U
) {
    CaptureSession session {};
    PFL_EXPECT(session.open_capture(capture_path));
    const auto packet = require_packet(session, packet_index);
    const auto details = session.read_packet_details(packet);
    PFL_REQUIRE(details.has_value());
    const auto flow_context = resolve_selected_packet_flow_context(session, packet);
    auto packet_summary_preparation = prepare_selected_packet_summary_with_production_lengths(
        session,
        *details,
        packet,
        flow_context.flow_index,
        flow_context.flow_packet_index,
        flow_context.loaded_packet_window_count
    );
    return session_detail::build_packet_summary_layers(*details, packet, packet_summary_preparation.make_options());
}

std::vector<session_detail::PacketSummaryLayer> build_flow_packet_summary_layers(
    CaptureSession& session,
    const std::size_t flow_index,
    const std::uint64_t packet_index,
    const std::size_t loaded_packet_window_count = 64U
) {
    const auto packet = require_packet(session, packet_index);
    const auto details = session.read_packet_details(packet);
    PFL_REQUIRE(details.has_value());
    const auto flow_packet_number = session.selected_flow_exact_packet_number(flow_index, packet_index);
    PFL_REQUIRE(flow_packet_number.has_value());
    const auto internal_flow_packet_index = *flow_packet_number - 1U;
    auto packet_summary_preparation = prepare_selected_packet_summary_with_production_lengths(
        session,
        *details,
        packet,
        flow_index,
        internal_flow_packet_index,
        loaded_packet_window_count
    );
    return session_detail::build_packet_summary_layers(*details, packet, packet_summary_preparation.make_options());
}

std::vector<session_detail::PacketSummaryLayer> build_synthetic_tcp_flow_summary_layers(
    const std::string& file_name,
    const std::vector<std::vector<std::uint8_t>>& tcp_payloads,
    const std::uint64_t selected_packet_index
) {
    std::vector<std::pair<std::uint32_t, std::vector<std::uint8_t>>> packets {};
    packets.reserve(tcp_payloads.size());
    for (std::size_t index = 0U; index < tcp_payloads.size(); ++index) {
        packets.push_back({
            static_cast<std::uint32_t>(100U + index),
            make_ethernet_ipv4_tcp_packet_with_bytes_payload(
                ipv4(10, 10, 0, 1),
                ipv4(10, 10, 0, 2),
                41050,
                443,
                tcp_payloads[index],
                0x18)
        });
    }

    const auto capture_path = write_temp_pcap(file_name, make_classic_pcap(packets));
    CaptureSession session {};
    PFL_EXPECT(session.open_capture(capture_path, CaptureImportOptions {}));
    return build_flow_packet_summary_layers(
        session,
        0U,
        selected_packet_index,
        tcp_payloads.size()
    );
}

void expect_ecdhe_server_key_exchange_summary(
    const session_detail::PacketSummaryLayer& layer,
    const bool expect_explicit_signature_scheme
) {
    PFL_EXPECT(require_summary_field_value(layer, "Handshake Type") == "ServerKeyExchange");
    PFL_EXPECT(require_summary_field_value(layer, "Key Exchange") == "ECDHE");
    PFL_EXPECT(require_summary_field_value(layer, "Curve Type") == "Named Curve (3)");
    PFL_EXPECT(require_summary_field_value(layer, "Named Group") == "secp256r1 (0x0017)");
    PFL_EXPECT(require_summary_field_value(layer, "Public Key Length") == "65 bytes");
    PFL_EXPECT(require_summary_field_value(layer, "Public Key Available Length") == "65 bytes");
    PFL_EXPECT(require_summary_field_value(layer, "Public Key Status") == "Complete");
    PFL_EXPECT(require_summary_field_value(layer, "Signature Authentication") == "RSA");
    if (expect_explicit_signature_scheme) {
        PFL_EXPECT(require_summary_field_value(layer, "Signature Scheme") == "rsa_pkcs1_sha512 (0x0601)");
    } else {
        PFL_EXPECT(find_summary_field(layer, "Signature Scheme") == nullptr);
    }
    PFL_EXPECT(require_summary_field_value(layer, "Signature Length") == "256 bytes");
    PFL_EXPECT(require_summary_field_value(layer, "Signature Available Length") == "256 bytes");
    PFL_EXPECT(require_summary_field_value(layer, "Signature Status") == "Complete");
    PFL_EXPECT(require_summary_field_value(layer, "Status") == "Complete");
}

void expect_ecdhe_client_key_exchange_summary(const session_detail::PacketSummaryLayer& layer) {
    PFL_EXPECT(require_summary_field_value(layer, "Handshake Type") == "ClientKeyExchange");
    PFL_EXPECT(require_summary_field_value(layer, "Key Exchange") == "ECDHE");
    PFL_EXPECT(require_summary_field_value(layer, "Public Key Length") == "65 bytes");
    PFL_EXPECT(require_summary_field_value(layer, "Public Key Available Length") == "65 bytes");
    PFL_EXPECT(require_summary_field_value(layer, "Public Key Status") == "Complete");
    PFL_EXPECT(require_summary_field_value(layer, "Status") == "Complete");
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
            .flow_packet_index = 3U,
            .transport_payload_length = 0U,
            .original_transport_payload_length = 0U,
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
        const auto* frame_encapsulation_type_field = find_summary_field(*frame_layer, "Encapsulation Type");
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
        PFL_REQUIRE(frame_encapsulation_type_field != nullptr);
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
        PFL_EXPECT(frame_encapsulation_type_field->value == "Ethernet");
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
        PFL_EXPECT(details->has_dns);
        PFL_EXPECT(!details->has_http);
        PFL_EXPECT(!details->dns.is_response);
        PFL_EXPECT(details->dns.query_name == "gsp85-ssl.ls.apple.com");
        PFL_EXPECT(details->dns.query_type == 65U);
        const auto summary_layers = build_flow_packet_summary_layers(
            session,
            0U,
            0U,
            64U
        );
        PFL_EXPECT(summary_layers.size() >= 5U);
        PFL_EXPECT(summary_layers[summary_layers.size() - 2U].id == "udp");
        PFL_EXPECT(!summary_layers[summary_layers.size() - 2U].expanded_by_default);
        PFL_EXPECT(summary_layers.back().id == "dns");
        PFL_EXPECT(summary_layers.back().expanded_by_default);
        PFL_EXPECT(summary_layers.back().title.find("Domain Name System") != std::string::npos);
        PFL_EXPECT(require_summary_field_value(summary_layers.back(), "Message Type") == "Query");
        PFL_EXPECT(require_summary_field_value(summary_layers.back(), "QName") == "gsp85-ssl.ls.apple.com");
        PFL_EXPECT(require_summary_field_value(summary_layers.back(), "QType") == "HTTPS (65)");
        PFL_EXPECT(find_summary_layer(summary_layers, "data") == nullptr);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/quic/quic_initial_ch_1.pcap"), CaptureImportOptions {}));
        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 1U);
        PFL_EXPECT(rows[0].protocol_hint == "quic");
        const auto presentation = session.derive_quic_presentation_for_packet(0U, 0U);
        PFL_REQUIRE(presentation.has_value());
        PFL_REQUIRE(presentation->packets.size() == 1U);
        PFL_EXPECT(presentation->packets[0].shell_type == session_detail::QuicPresentationShellType::initial);
        PFL_EXPECT(!presentation->selected_initial_plaintext_payload.empty());
        PFL_EXPECT(std::any_of(
            presentation->packets[0].frames.begin(),
            presentation->packets[0].frames.end(),
            [](const session_detail::QuicPresentationFrame& frame) {
                return frame.type == session_detail::QuicPresentationFrameType::crypto;
            }
        ));
        PFL_REQUIRE(presentation->packets[0].tls_handshakes.size() == 1U);
        PFL_EXPECT(presentation->packets[0].tls_handshakes[0].kind == TlsHandshakeKind::client_hello);
        PFL_EXPECT(presentation->sni == std::optional<std::string> {"bag.itunes.apple.com"});
        const auto packet = require_packet(session, 0U);
        const auto packet_bytes = session.read_packet_data(packet);
        PacketPayloadService payload_service {};
        const auto udp_payload = payload_service.extract_transport_payload(packet_bytes, packet.data_link_type);
        PFL_EXPECT(presentation->selected_initial_plaintext_payload.size() <= udp_payload.size());
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/quic/quic_initial_ch_1.pcap"), CaptureImportOptions {}));
        const auto summary_layers = build_flow_packet_summary_layers(session, 0U, 0U, 64U);
        PFL_EXPECT(summary_layers.size() >= 5U);
        const auto* udp_layer = find_summary_layer(summary_layers, "udp");
        const auto quic_layers = find_summary_layers(summary_layers, "quic");
        const auto tls_layers = find_summary_layers(summary_layers, "tls");
        PFL_REQUIRE(udp_layer != nullptr);
        PFL_REQUIRE(quic_layers.size() == 1U);
        PFL_REQUIRE(tls_layers.size() == 1U);
        PFL_EXPECT(require_summary_field_value(*quic_layers[0], "Packet Type") == "Initial");
        PFL_EXPECT(require_summary_field_value(*quic_layers[0], "Frame Presence") == "CRYPTO");
        const auto* crypto_frame = find_summary_child(*quic_layers[0], "quic_frame");
        PFL_REQUIRE(crypto_frame != nullptr);
        PFL_EXPECT(require_summary_field_value(*crypto_frame, "Type") == "CRYPTO");
        PFL_EXPECT(require_summary_field_value(*tls_layers[0], "Handshake Type") == "ClientHello");
        PFL_EXPECT(require_summary_field_value(*tls_layers[0], "SNI") == "bag.itunes.apple.com");
        PFL_EXPECT(find_summary_layer(summary_layers, "data") == nullptr);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/quic/quic_example_1.pcap"), CaptureImportOptions {}));
        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 1U);
        PFL_EXPECT(rows[0].protocol_hint == "quic");
        const auto summary_layers = build_flow_packet_summary_layers(session, 0U, 14U);
        const auto quic_layers = find_summary_layers(summary_layers, "quic");
        const auto tls_layers = find_summary_layers(summary_layers, "tls");
        PFL_REQUIRE(quic_layers.size() == 2U);
        PFL_EXPECT(require_summary_field_value(*quic_layers[0], "Packet Type") == "Handshake");
        PFL_EXPECT(require_summary_field_value(*quic_layers[1], "Packet Type") == "Protected Payload");
        PFL_EXPECT(tls_layers.empty());
        PFL_EXPECT(find_summary_layer(summary_layers, "data") == nullptr);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/quic/quic_example_2.pcap"), CaptureImportOptions {}));
        const auto mixed_summary_layers = build_flow_packet_summary_layers(session, 0U, 2U);
        const auto mixed_quic_layers = find_summary_layers(mixed_summary_layers, "quic");
        const auto mixed_tls_layers = find_summary_layers(mixed_summary_layers, "tls");
        PFL_REQUIRE(mixed_quic_layers.size() == 2U);
        PFL_REQUIRE(mixed_tls_layers.size() == 1U);
        PFL_EXPECT(require_summary_field_value(*mixed_quic_layers[0], "Packet Type") == "Initial");
        PFL_EXPECT(require_summary_field_value(*mixed_quic_layers[0], "Frame Presence") == "CRYPTO");
        PFL_EXPECT(require_summary_field_value(*mixed_tls_layers[0], "Handshake Type") == "ClientHello");
        PFL_EXPECT(require_summary_field_value(*mixed_quic_layers[1], "Packet Type") == "0-RTT");
        PFL_EXPECT(find_summary_layer(mixed_summary_layers, "data") == nullptr);

        const auto server_hello_summary_layers = build_flow_packet_summary_layers(session, 0U, 12U);
        const auto server_hello_quic_layers = find_summary_layers(server_hello_summary_layers, "quic");
        const auto server_hello_tls_layers = find_summary_layers(server_hello_summary_layers, "tls");
        PFL_REQUIRE(server_hello_quic_layers.size() == 1U);
        PFL_REQUIRE(server_hello_tls_layers.size() == 1U);
        PFL_EXPECT(require_summary_field_value(*server_hello_quic_layers[0], "Packet Type") == "Initial");
        PFL_EXPECT(require_summary_field_value(*server_hello_quic_layers[0], "Frame Presence") == "CRYPTO, PADDING");
        PFL_EXPECT(require_summary_field_value(*server_hello_tls_layers[0], "Handshake Type") == "ServerHello");
        PFL_EXPECT(find_summary_field(*server_hello_tls_layers[0], "SNI") == nullptr);
        PFL_EXPECT(find_summary_layer(server_hello_summary_layers, "data") == nullptr);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/quic/quic_initial_sh_2.pcap"), CaptureImportOptions {}));
        const auto presentation = session.derive_quic_presentation_for_packet(0U, 0U);
        PFL_REQUIRE(presentation.has_value());
        PFL_REQUIRE(presentation->packets.size() == 1U);
        PFL_EXPECT(presentation->packets[0].shell_type == session_detail::QuicPresentationShellType::initial);
        PFL_EXPECT(std::any_of(
            presentation->packets[0].frames.begin(),
            presentation->packets[0].frames.end(),
            [](const session_detail::QuicPresentationFrame& frame) {
                return frame.type == session_detail::QuicPresentationFrameType::crypto;
            }
        ));
        PFL_REQUIRE(presentation->packets[0].tls_handshakes.size() == 1U);
        PFL_EXPECT(presentation->packets[0].tls_handshakes[0].kind == TlsHandshakeKind::server_hello);
        PFL_EXPECT(presentation->sni == std::nullopt);
    }

    {
        const auto summary_layers = build_fixture_summary_layers("parsing/quic/quic_initial_sh_2.pcap");
        const auto quic_layers = find_summary_layers(summary_layers, "quic");
        const auto tls_layers = find_summary_layers(summary_layers, "tls");
        PFL_REQUIRE(quic_layers.size() == 1U);
        PFL_REQUIRE(tls_layers.size() == 1U);
        PFL_EXPECT(require_summary_field_value(*quic_layers[0], "Header Form") == "Long");
        PFL_EXPECT(require_summary_field_value(*quic_layers[0], "Packet Type") == "Initial");
        PFL_EXPECT(require_summary_field_value(*quic_layers[0], "Frame Presence") == "CRYPTO");
        PFL_EXPECT(require_summary_field_value(*tls_layers[0], "Handshake Type") == "ServerHello");
        PFL_EXPECT(find_summary_field(*tls_layers[0], "SNI") == nullptr);
        PFL_EXPECT(find_summary_layer(summary_layers, "data") == nullptr);
    }

    {
        const auto summary_layers = build_fixture_summary_layers("parsing/quic/quic_handshake_3.pcap");
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/quic/quic_handshake_3.pcap"), CaptureImportOptions {}));
        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 1U);
        PFL_EXPECT(rows[0].protocol_hint == "quic");
        const auto quic_layers = find_summary_layers(summary_layers, "quic");
        const auto tls_layers = find_summary_layers(summary_layers, "tls");
        PFL_REQUIRE(quic_layers.size() == 1U);
        PFL_EXPECT(require_summary_field_value(*quic_layers[0], "Header Form") == "Long");
        PFL_EXPECT(require_summary_field_value(*quic_layers[0], "Packet Type") == "Handshake");
        PFL_EXPECT(tls_layers.empty());
        PFL_EXPECT(find_summary_layer(summary_layers, "data") == nullptr);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/quic/quic_protected_payload_4.pcap"), CaptureImportOptions {}));
        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 1U);
        PFL_EXPECT(rows[0].protocol_hint.empty());
        const auto presentation = session.derive_quic_presentation_for_packet(0U, 0U);
        PFL_REQUIRE(presentation.has_value());
        PFL_EXPECT(presentation->selected_initial_plaintext_payload.empty());
        const auto summary_layers = build_flow_packet_summary_layers(session, 0U, 0U);
        const auto quic_layers = find_summary_layers(summary_layers, "quic");
        const auto tls_layers = find_summary_layers(summary_layers, "tls");
        const auto data_layers = find_summary_layers(summary_layers, "data");
        PFL_EXPECT(quic_layers.empty());
        PFL_EXPECT(tls_layers.empty());
        PFL_REQUIRE(data_layers.size() == 1U);
        PFL_EXPECT(require_summary_field_value(*data_layers[0], "Transport") == "UDP");
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/quic/quic_initial_ack_decrypt_ok_1.pcap"), CaptureImportOptions {}));
        const auto summary_layers = build_flow_packet_summary_layers(session, 0U, 7U);
        const auto quic_layers = find_summary_layers(summary_layers, "quic");
        const auto tls_layers = find_summary_layers(summary_layers, "tls");
        PFL_REQUIRE(quic_layers.size() == 1U);
        PFL_EXPECT(require_summary_field_value(*quic_layers[0], "Packet Type") == "Initial");
        PFL_EXPECT(require_summary_field_value(*quic_layers[0], "Frame Presence") == "ACK");
        PFL_EXPECT(tls_layers.empty());
        PFL_EXPECT(find_summary_layer(summary_layers, "data") == nullptr);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/quic/quic_initial_ack_wrong_pkn_1.pcap"), CaptureImportOptions {}));
        const auto presentation = session.derive_quic_presentation_for_packet(0U, 7U);
        PFL_REQUIRE(presentation.has_value());
        PFL_EXPECT(presentation->selected_initial_plaintext_payload.empty());
        const auto summary_layers = build_flow_packet_summary_layers(session, 0U, 7U);
        const auto quic_layers = find_summary_layers(summary_layers, "quic");
        const auto tls_layers = find_summary_layers(summary_layers, "tls");
        PFL_REQUIRE(quic_layers.size() == 1U);
        PFL_EXPECT(require_summary_field_value(*quic_layers[0], "Packet Type") == "Initial");
        PFL_EXPECT(find_summary_field(*quic_layers[0], "Frame Presence") == nullptr);
        PFL_EXPECT(find_descendant_summary_layer(*quic_layers[0], "quic_frame") == nullptr);
        PFL_EXPECT(find_descendant_summary_layer_with_field_value(*quic_layers[0], "Type", "ACK") == nullptr);
        PFL_EXPECT(find_descendant_summary_layer_with_field_value(*quic_layers[0], "Type", "CRYPTO") == nullptr);
        PFL_EXPECT(find_descendant_summary_layer_with_field_value(*quic_layers[0], "Type", "PADDING") == nullptr);
        PFL_EXPECT(tls_layers.empty());
        PFL_EXPECT(find_descendant_summary_layer(*quic_layers[0], "tls") == nullptr);
        PFL_EXPECT(find_descendant_summary_field(*quic_layers[0], "Handshake Type") == nullptr);
        PFL_EXPECT(find_descendant_summary_layer_with_field_value(*quic_layers[0], "Handshake Type", "ClientHello") == nullptr);
        PFL_EXPECT(find_descendant_summary_layer_with_field_value(*quic_layers[0], "Handshake Type", "ServerHello") == nullptr);
        PFL_EXPECT(find_descendant_summary_field(*quic_layers[0], "SNI") == nullptr);
        PFL_EXPECT(find_summary_layer(summary_layers, "data") == nullptr);
    }

    {
        const auto udp_payload = std::vector<std::uint8_t> {
            0x53U, 0x45U, 0x41U, 0x52U, 0x43U, 0x48U, 0x20U, 0x42U,
            0x53U, 0x44U, 0x50U, 0x2fU, 0x30U, 0x2eU, 0x31U, 0x0aU,
        };
        const auto capture_path = write_temp_pcap(
            "pfl_packet_summary_possible_quic_ascii_search_bsdp.pcap",
            make_classic_pcap({{
                100U,
                make_ethernet_ipv4_udp_packet_with_bytes_payload(
                    ipv4(10, 0, 1, 20),
                    ipv4(10, 0, 1, 21),
                    54040,
                    443,
                    udp_payload)
            }})
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(capture_path, CaptureImportOptions {
            .settings = AnalysisSettings {.use_possible_tls_quic = true},
        }));
        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 1U);
        PFL_EXPECT(rows[0].protocol_hint == "possible_quic");
        const auto summary_layers = build_flow_packet_summary_layers(session, 0U, 0U);
        const auto data_layers = find_summary_layers(summary_layers, "data");
        PFL_EXPECT(find_summary_layer(summary_layers, "quic") == nullptr);
        PFL_EXPECT(find_summary_layer(summary_layers, "tls") == nullptr);
        PFL_REQUIRE(data_layers.size() == 1U);
        PFL_EXPECT(require_summary_field_value(*data_layers[0], "Transport") == "UDP");
        PFL_EXPECT(require_summary_field_value(*data_layers[0], "Preview") == format_expected_hex_byte_list(udp_payload));
    }

    {
        const auto short_header_like_payload = std::vector<std::uint8_t> {0x40U, 0xAAU, 0xBBU, 0xCCU, 0xDDU};
        const auto capture_path = write_temp_pcap(
            "pfl_packet_summary_possible_quic_short_header_only.pcap",
            make_classic_pcap({{
                100U,
                make_ethernet_ipv4_udp_packet_with_bytes_payload(
                    ipv4(10, 0, 1, 22),
                    ipv4(10, 0, 1, 23),
                    54041,
                    443,
                    short_header_like_payload)
            }})
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(capture_path, CaptureImportOptions {
            .settings = AnalysisSettings {.use_possible_tls_quic = true},
        }));
        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 1U);
        PFL_EXPECT(rows[0].protocol_hint == "possible_quic");
        const auto summary_layers = build_flow_packet_summary_layers(session, 0U, 0U);
        const auto data_layers = find_summary_layers(summary_layers, "data");
        PFL_EXPECT(find_summary_layer(summary_layers, "quic") == nullptr);
        PFL_EXPECT(find_summary_layer(summary_layers, "tls") == nullptr);
        PFL_REQUIRE(data_layers.size() == 1U);
        PFL_EXPECT(require_summary_field_value(*data_layers[0], "Transport") == "UDP");
        PFL_EXPECT(require_summary_field_value(*data_layers[0], "Preview") == format_expected_hex_byte_list(short_header_like_payload));
    }

    {
        const auto summary_layers = build_fixture_summary_layers("parsing/quic/ipv6_quic_constricted_1.pcap");
        const auto quic_layers = find_summary_layers(summary_layers, "quic");
        PFL_REQUIRE(!quic_layers.empty());
        PFL_EXPECT(require_summary_field_value(*quic_layers[0], "Header Form") == "Long");
        PFL_EXPECT(require_summary_field_value(*quic_layers[0], "Packet Type") == "Initial");
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/quic/quic_constricted_1.pcap"), CaptureImportOptions {}));
        const auto summary_layers = build_flow_packet_summary_layers(session, 0U, 0U, 30U);
        const auto quic_layers = find_summary_layers(summary_layers, "quic");
        PFL_REQUIRE(!quic_layers.empty());
        PFL_EXPECT(require_summary_field_value(*quic_layers[0], "Header Form") == "Long");
        PFL_EXPECT(require_summary_field_value(*quic_layers[0], "Packet Type") == "Initial");
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
        PFL_EXPECT(find_summary_layer(summary_layers, "data") == nullptr);
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
        const auto* alpn = find_summary_field(*tls_layer, "Offered Protocols");
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
        const auto* alpn = find_summary_field(*tls_layer, "Offered Protocols");
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
        PFL_EXPECT(find_summary_layer(summary_layers, "data") == nullptr);
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
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/tls/tls_1_3_split_client_hello_10.pcap"), CaptureImportOptions {}));

        const auto packet4 = require_packet(session, 3U);
        const auto details4 = session.read_packet_details(packet4);
        PFL_REQUIRE(details4.has_value());
        const auto packet4_bytes = session.read_packet_data(packet4);
        PacketPayloadService payload_service {};
        const auto transport_payload4 = payload_service.extract_transport_payload(packet4_bytes, packet4.data_link_type);
        PFL_EXPECT(transport_payload4.size() == 1412U);
        const auto reconstructed_tls_records4_incomplete =
            session_detail::build_selected_packet_tls_contexts(session, 0U, 3U, 4U);
        PFL_REQUIRE(reconstructed_tls_records4_incomplete.size() == 1U);
        PFL_EXPECT(reconstructed_tls_records4_incomplete[0].status == session_detail::TlsSelectedPacketStatus::incomplete_window);

        const auto reconstructed_tls_records4 =
            session_detail::build_selected_packet_tls_contexts(session, 0U, 3U, 5U);
        PFL_REQUIRE(reconstructed_tls_records4.size() == 1U);
        PFL_EXPECT(reconstructed_tls_records4[0].status == session_detail::TlsSelectedPacketStatus::complete);
        PFL_EXPECT(reconstructed_tls_records4[0].selected_contribution_flow_packet_index == std::optional<std::uint64_t> {3U});
        PFL_EXPECT(reconstructed_tls_records4[0].completion_flow_packet_index == std::optional<std::uint64_t> {4U});
        const auto summary_layers4 = session_detail::build_packet_summary_layers(*details4, packet4, {
            .flow_packet_index = 3U,
            .transport_payload_length = static_cast<std::uint32_t>(transport_payload4.size()),
            .original_transport_payload_length = static_cast<std::uint32_t>(transport_payload4.size()),
            .transport_payload_bytes = std::span<const std::uint8_t>(transport_payload4.data(), transport_payload4.size()),
            .reconstructed_tls_records = reconstructed_tls_records4,
        });

        std::size_t tcp_index4 = summary_layers4.size();
        for (std::size_t index = 0U; index < summary_layers4.size(); ++index) {
            if (summary_layers4[index].id == "tcp") {
                tcp_index4 = index;
                break;
            }
        }
        PFL_REQUIRE(tcp_index4 < summary_layers4.size());
        PFL_REQUIRE(tcp_index4 + 1U < summary_layers4.size());
        PFL_EXPECT(summary_layers4[tcp_index4 + 1U].id == "tls");

        const auto& tls_layer4 = summary_layers4[tcp_index4 + 1U];
        PFL_EXPECT(tls_layer4.title == "Transport Layer Security, ClientHello Fragment");
        PFL_EXPECT(tls_layer4.warning);
        PFL_EXPECT(tls_layer4.marker_text == "Warning");
        PFL_EXPECT(require_summary_field_value(tls_layer4, "Status") == "Incomplete record body");
        PFL_EXPECT(require_summary_field_value(tls_layer4, "Available Bytes") == "1412");
        PFL_EXPECT(require_summary_field_value(tls_layer4, "Record Type") == "Handshake");
        PFL_EXPECT(require_summary_field_value(tls_layer4, "Record Legacy Version") == "TLS 1.0 (0x0301)");
        PFL_EXPECT(require_summary_field_value(tls_layer4, "Declared Record Length") == "1893");
        PFL_EXPECT(require_summary_field_value(tls_layer4, "Handshake Type") == "ClientHello");
        PFL_EXPECT(require_summary_field_value(tls_layer4, "Handshake Length") == "1889");
        PFL_EXPECT(require_summary_field_value(tls_layer4, "Handshake Status") == "Incomplete body");
        PFL_EXPECT(require_summary_field_value(tls_layer4, "Available Handshake Bytes") == "1407");
        PFL_EXPECT(find_summary_field(tls_layer4, "SNI") == nullptr);
        PFL_EXPECT(find_summary_field(tls_layer4, "Offered Protocols") == nullptr);
        PFL_EXPECT(find_summary_field(tls_layer4, "Extension Count") == nullptr);
        PFL_EXPECT(find_summary_field(tls_layer4, "ClientHello Legacy Version") == nullptr);
        PFL_EXPECT(find_summary_field(tls_layer4, "Supported TLS Versions") == nullptr);
        PFL_EXPECT(find_summary_child(tls_layer4, "tls_cipher_suites") == nullptr);
        PFL_EXPECT(find_summary_child(tls_layer4, "tls_compression_methods") == nullptr);
        PFL_EXPECT(find_summary_child(tls_layer4, "tls_extensions") == nullptr);
        const auto reassembled_layers4 = find_summary_layers(summary_layers4, "tls_reassembled");
        PFL_REQUIRE(reassembled_layers4.size() == 1U);
        PFL_EXPECT(require_summary_field_value(*reassembled_layers4[0], "Status") == "Continues in a later loaded packet");
        PFL_EXPECT(require_summary_field_value(*reassembled_layers4[0], "Contributing Flow Packets") == "4, 5");
        PFL_EXPECT(require_summary_field_value(*reassembled_layers4[0], "Completion Flow Packet") == "5");
        const auto* packet4_selected_contribution = require_summary_child(*reassembled_layers4[0], "tls_reassembled_contribution", 0U);
        const auto* packet4_completion_contribution = require_summary_child(*reassembled_layers4[0], "tls_reassembled_contribution", 1U);
        PFL_EXPECT(packet4_selected_contribution->title == "Selected Packet Contribution");
        PFL_EXPECT(require_summary_field_value(*packet4_selected_contribution, "Flow Packet") == "4");
        PFL_EXPECT(require_summary_field_value(*packet4_selected_contribution, "Packet in File") == "4");
        PFL_EXPECT(require_summary_field_value(*packet4_selected_contribution, "Record Byte Range") == "1-1412");
        PFL_EXPECT(require_summary_field_value(*packet4_selected_contribution, "Captured Contribution") == "1412 bytes");
        PFL_EXPECT(packet4_completion_contribution->title == "Flow Packet 5 Contribution");
        PFL_EXPECT(require_summary_field_value(*packet4_completion_contribution, "Flow Packet") == "5");
        PFL_EXPECT(require_summary_field_value(*packet4_completion_contribution, "Packet in File") == "5");
        PFL_EXPECT(require_summary_field_value(*packet4_completion_contribution, "Record Byte Range") == "1413-1898");
        PFL_EXPECT(require_summary_field_value(*packet4_completion_contribution, "Captured Contribution") == "486 bytes");

        const auto packet5 = require_packet(session, 4U);
        const auto details5 = session.read_packet_details(packet5);
        PFL_REQUIRE(details5.has_value());
        const auto packet5_bytes = session.read_packet_data(packet5);
        const auto transport_payload5 = payload_service.extract_transport_payload(packet5_bytes, packet5.data_link_type);
        PFL_EXPECT(transport_payload5.size() == 486U);
        const auto reconstructed_tls_records5 =
            session_detail::build_selected_packet_tls_contexts(session, 0U, 4U, 5U);
        PFL_REQUIRE(reconstructed_tls_records5.size() == 1U);
        PFL_EXPECT(reconstructed_tls_records5[0].status == session_detail::TlsSelectedPacketStatus::complete);
        PFL_EXPECT(reconstructed_tls_records5[0].selected_contribution_flow_packet_index == std::optional<std::uint64_t> {4U});
        PFL_EXPECT(reconstructed_tls_records5[0].completion_flow_packet_index == std::optional<std::uint64_t> {4U});
        const auto summary_layers5 = session_detail::build_packet_summary_layers(*details5, packet5, {
            .flow_packet_index = 4U,
            .transport_payload_length = static_cast<std::uint32_t>(transport_payload5.size()),
            .original_transport_payload_length = static_cast<std::uint32_t>(transport_payload5.size()),
            .transport_payload_bytes = std::span<const std::uint8_t>(transport_payload5.data(), transport_payload5.size()),
            .reconstructed_tls_records = reconstructed_tls_records5,
        });
        const auto tls_layers5 = find_summary_layers(summary_layers5, "tls");
        PFL_REQUIRE(tls_layers5.size() == 1U);
        PFL_EXPECT(tls_layers5[0]->title.find("ClientHello") != std::string::npos);
        PFL_EXPECT(require_summary_field_value(*tls_layers5[0], "Record Type") == "Handshake");
        PFL_EXPECT(require_summary_field_value(*tls_layers5[0], "Handshake Type") == "ClientHello");
        PFL_EXPECT(require_summary_field_value(*tls_layers5[0], "Handshake Length") == "1889");
        PFL_EXPECT(require_summary_field_value(*tls_layers5[0], "SNI") == "www.youtube.com");
        PFL_EXPECT(find_summary_field(*tls_layers5[0], "Supported TLS Versions") != nullptr);
        const auto reassembled_layers5 = find_summary_layers(summary_layers5, "tls_reassembled");
        PFL_REQUIRE(reassembled_layers5.size() == 1U);
        PFL_EXPECT(require_summary_field_value(*reassembled_layers5[0], "Status") == "Reassembled in this packet");
        PFL_EXPECT(require_summary_field_value(*reassembled_layers5[0], "Contributing Flow Packets") == "4, 5");
        PFL_EXPECT(require_summary_field_value(*reassembled_layers5[0], "Completion Flow Packet") == "5");
        const auto* packet5_initial_contribution = require_summary_child(*reassembled_layers5[0], "tls_reassembled_contribution", 0U);
        const auto* packet5_selected_contribution = require_summary_child(*reassembled_layers5[0], "tls_reassembled_contribution", 1U);
        PFL_EXPECT(packet5_initial_contribution->title == "Flow Packet 4 Contribution");
        PFL_EXPECT(packet5_selected_contribution->title == "Selected Packet Contribution");
        PFL_EXPECT(require_summary_field_value(*packet5_selected_contribution, "Flow Packet") == "5");
        PFL_EXPECT(require_summary_field_value(*packet5_selected_contribution, "Packet in File") == "5");
        PFL_EXPECT(require_summary_field_value(*packet5_selected_contribution, "Record Byte Range") == "1413-1898");
        PFL_EXPECT(require_summary_field_value(*packet5_selected_contribution, "Captured Contribution") == "486 bytes");
    }

    {
        struct ServerKeyExchangePacketExpectation {
            const char* relative_path;
            bool expect_explicit_signature_scheme;
            std::uint16_t expected_negotiated_version;
        };

        const std::vector<ServerKeyExchangePacketExpectation> expectations {
            {
                .relative_path = "parsing/tls/tls_1_0_badssl_baseline_12.pcap",
                .expect_explicit_signature_scheme = false,
                .expected_negotiated_version = 0x0301U,
            },
            {
                .relative_path = "parsing/tls/tls_1_1_badssl_baseline_13.pcap",
                .expect_explicit_signature_scheme = false,
                .expected_negotiated_version = 0x0302U,
            },
            {
                .relative_path = "parsing/tls/tls_1_2_badssl_baseline_14.pcap",
                .expect_explicit_signature_scheme = true,
                .expected_negotiated_version = 0x0303U,
            },
        };

        for (const auto& expectation : expectations) {
            ScopedTestContext context {
                std::string {"fixture="} + expectation.relative_path +
                " | packet=12 | reassembled_server_key_exchange"
            };
            CaptureSession session {};
            PFL_EXPECT(session.open_capture(
                fixture_path(expectation.relative_path),
                CaptureImportOptions {}
            ));

            const auto loaded_packet_window_count = session.list_flow_packets(0).size();
            const auto flow_packet_index = require_flow_packet_index(session, 0U, 11U);
            const auto summary = build_selected_packet_summary(
                session,
                0U,
                11U,
                flow_packet_index,
                loaded_packet_window_count
            );

            PFL_REQUIRE(summary.reconstructed_tls_records.size() == 1U);
            PFL_EXPECT(summary.reconstructed_tls_records[0].status == session_detail::TlsSelectedPacketStatus::complete);
            PFL_EXPECT(summary.reconstructed_tls_records[0].selected_contribution_flow_packet_index == std::optional<std::uint64_t> {11U});
            PFL_EXPECT(summary.reconstructed_tls_records[0].completion_flow_packet_index == std::optional<std::uint64_t> {11U});
            PFL_EXPECT(
                summary.reconstructed_tls_records[0].initial_parser_context.negotiated_cipher_suite ==
                std::optional<std::uint16_t> {
                    expectation.expect_explicit_signature_scheme ? 0xC030U : 0xC014U
                }
            );
            PFL_EXPECT(
                summary.reconstructed_tls_records[0].initial_parser_context.negotiated_version ==
                std::optional<std::uint16_t> {expectation.expected_negotiated_version}
            );

            const auto reassembled_layers = find_summary_layers(summary.summary_layers, "tls_reassembled");
            const auto tls_layers = find_summary_layers(summary.summary_layers, "tls");
            PFL_REQUIRE(reassembled_layers.size() == 1U);
            PFL_REQUIRE(tls_layers.size() == 2U);

            PFL_EXPECT(require_summary_field_value(*reassembled_layers[0], "Status") == "Reassembled in this packet");
            PFL_EXPECT(require_summary_field_value(*reassembled_layers[0], "Contributing Flow Packets") == "10, 12");
            PFL_EXPECT(require_summary_field_value(*reassembled_layers[0], "Completion Flow Packet") == "12");
            const auto* selected_contribution = require_summary_child(*reassembled_layers[0], "tls_reassembled_contribution", 1U);
            PFL_EXPECT(require_summary_field_value(*selected_contribution, "Flow Packet") == "12");
            PFL_EXPECT(require_summary_field_value(*selected_contribution, "Packet in File") == "12");

            expect_ecdhe_server_key_exchange_summary(*tls_layers[0], expectation.expect_explicit_signature_scheme);
            PFL_EXPECT(require_summary_field_value(*tls_layers[1], "Handshake Type") == "ServerHelloDone");
            PFL_EXPECT(require_summary_field_value(*tls_layers[1], "Handshake Length") == "0");
        }
    }

    {
        ScopedTestContext context {"fixture=parsing/tls/tls_1_2_client_certificate_missing_18.pcap | packet=11 | reconstructed_tls_context"};
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(
            fixture_path("parsing/tls/tls_1_2_client_certificate_missing_18.pcap"),
            CaptureImportOptions {}
        ));

        const auto loaded_packet_window_count = session.list_flow_packets(0).size();
        const auto summary = build_selected_packet_summary(session, 0U, 10U, 10U, loaded_packet_window_count);

        PFL_REQUIRE(summary.reconstructed_tls_records.size() == 1U);
        PFL_EXPECT(summary.reconstructed_tls_records[0].status == session_detail::TlsSelectedPacketStatus::complete);
        PFL_EXPECT(summary.reconstructed_tls_records[0].selected_contribution_flow_packet_index == std::optional<std::uint64_t> {10U});
        PFL_EXPECT(summary.reconstructed_tls_records[0].completion_flow_packet_index == std::optional<std::uint64_t> {10U});
        PFL_EXPECT(
            summary.reconstructed_tls_records[0].initial_parser_context.negotiated_cipher_suite ==
            std::optional<std::uint16_t> {0xC02FU}
        );
        PFL_EXPECT(
            summary.reconstructed_tls_records[0].initial_parser_context.negotiated_version ==
            std::optional<std::uint16_t> {0x0303U}
        );

        const auto reassembled_layers = find_summary_layers(summary.summary_layers, "tls_reassembled");
        const auto tls_layers = find_summary_layers(summary.summary_layers, "tls");
        PFL_REQUIRE(reassembled_layers.size() == 1U);
        PFL_REQUIRE(tls_layers.size() == 2U);

        const auto reassembled_index = find_summary_layer_index(summary.summary_layers, "tls_reassembled");
        const auto first_tls_index = find_summary_layer_index(summary.summary_layers, "tls", 0U);
        const auto second_tls_index = find_summary_layer_index(summary.summary_layers, "tls", 1U);
        PFL_EXPECT(reassembled_index < first_tls_index);
        PFL_EXPECT(first_tls_index < second_tls_index);

        PFL_EXPECT(require_summary_field_value(*reassembled_layers[0], "Status") == "Reassembled in this packet");
        PFL_EXPECT(require_summary_field_value(*reassembled_layers[0], "Contributing Flow Packets") == "10, 11");
        PFL_EXPECT(require_summary_field_value(*reassembled_layers[0], "Completion Flow Packet") == "11");
        const auto* selected_contribution = require_summary_child(*reassembled_layers[0], "tls_reassembled_contribution", 1U);
        PFL_EXPECT(require_summary_field_value(*selected_contribution, "Flow Packet") == "11");
        PFL_EXPECT(require_summary_field_value(*selected_contribution, "Packet in File") == "11");

        expect_ecdhe_server_key_exchange_summary(*tls_layers[0], true);

        PFL_EXPECT(require_summary_field_value(*tls_layers[1], "Record Type") == "Handshake");
        PFL_EXPECT(require_summary_field_value(*tls_layers[1], "Handshake Count") == "2");
        const auto* certificate_request_handshake = require_summary_child(*tls_layers[1], "tls_handshake", 0U);
        PFL_EXPECT(require_summary_field_value(*certificate_request_handshake, "Handshake Type") == "CertificateRequest");
        PFL_EXPECT(require_summary_field_value(*certificate_request_handshake, "Handshake Length") == "179");
        PFL_EXPECT(require_summary_field_value(*certificate_request_handshake, "Certificate Type Count") == "3");
        PFL_EXPECT(require_summary_field_value(*certificate_request_handshake, "Signature/Hash Algorithm Count") == "15");
        PFL_EXPECT(require_summary_field_value(*certificate_request_handshake, "Certificate Authorities Length") == "141");
        PFL_EXPECT(require_summary_field_value(*certificate_request_handshake, "Authority Count") == "1");
        const auto* authorities_group = require_summary_child(*certificate_request_handshake, "tls_certificate_authorities");
        PFL_EXPECT(authorities_group->title == "Certificate Authorities (1)");

        const auto* server_hello_done_handshake = require_summary_child(*tls_layers[1], "tls_handshake", 1U);
        PFL_EXPECT(require_summary_field_value(*server_hello_done_handshake, "Handshake Type") == "ServerHelloDone");
        PFL_EXPECT(require_summary_field_value(*server_hello_done_handshake, "Handshake Length") == "0");
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(
            fixture_path("parsing/tls/tls_1_2_expired_certificate_alert_16.pcap"),
            CaptureImportOptions {}
        ));

        const auto loaded_packet_window_count = session.list_flow_packets(0).size();
        const auto summary = build_selected_packet_summary(session, 0U, 11U, 11U, loaded_packet_window_count);

        PFL_REQUIRE(summary.reconstructed_tls_records.size() == 1U);
        PFL_EXPECT(summary.reconstructed_tls_records[0].status == session_detail::TlsSelectedPacketStatus::complete);
        PFL_EXPECT(summary.reconstructed_tls_records[0].selected_contribution_flow_packet_index == std::optional<std::uint64_t> {11U});
        PFL_EXPECT(summary.reconstructed_tls_records[0].completion_flow_packet_index == std::optional<std::uint64_t> {11U});

        const auto reassembled_layers = find_summary_layers(summary.summary_layers, "tls_reassembled");
        const auto tls_layers = find_summary_layers(summary.summary_layers, "tls");
        PFL_REQUIRE(reassembled_layers.size() == 1U);
        PFL_REQUIRE(tls_layers.size() == 3U);

        const auto reassembled_index = find_summary_layer_index(summary.summary_layers, "tls_reassembled");
        const auto first_tls_index = find_summary_layer_index(summary.summary_layers, "tls", 0U);
        const auto second_tls_index = find_summary_layer_index(summary.summary_layers, "tls", 1U);
        const auto third_tls_index = find_summary_layer_index(summary.summary_layers, "tls", 2U);
        PFL_EXPECT(reassembled_index < first_tls_index);
        PFL_EXPECT(first_tls_index < second_tls_index);
        PFL_EXPECT(second_tls_index < third_tls_index);

        PFL_EXPECT(require_summary_field_value(*tls_layers[0], "Handshake Type") == "Certificate");
        PFL_EXPECT(require_summary_field_value(*tls_layers[0], "Certificate Count") == "3");
        expect_ecdhe_server_key_exchange_summary(*tls_layers[1], true);
        PFL_EXPECT(require_summary_field_value(*tls_layers[2], "Handshake Type") == "ServerHelloDone");
        PFL_EXPECT(require_summary_field_value(*tls_layers[2], "Handshake Length") == "0");
    }

    {
        struct ClientKeyExchangePacketExpectation {
            const char* relative_path;
        };

        const std::vector<ClientKeyExchangePacketExpectation> expectations {
            {.relative_path = "parsing/tls/tls_1_0_badssl_baseline_12.pcap"},
            {.relative_path = "parsing/tls/tls_1_1_badssl_baseline_13.pcap"},
            {.relative_path = "parsing/tls/tls_1_2_badssl_baseline_14.pcap"},
        };

        for (const auto& expectation : expectations) {
            CaptureSession session {};
            PFL_EXPECT(session.open_capture(
                fixture_path(expectation.relative_path),
                CaptureImportOptions {}
            ));

            const auto loaded_packet_window_count = session.list_flow_packets(0).size();
            const auto flow_packet_index = require_flow_packet_index(session, 0U, 13U);
            const auto summary = build_selected_packet_summary(
                session,
                0U,
                13U,
                flow_packet_index,
                loaded_packet_window_count
            );

            PFL_EXPECT(summary.reconstructed_tls_records.empty());

            const auto tls_layers = find_summary_layers(summary.summary_layers, "tls");
            PFL_REQUIRE(tls_layers.size() == 3U);
            expect_ecdhe_client_key_exchange_summary(*tls_layers[0]);
            PFL_EXPECT(require_summary_field_value(*tls_layers[1], "Record Type") == "ChangeCipherSpec");
            PFL_EXPECT(require_summary_field_value(*tls_layers[1], "Record Length") == "1");
            PFL_EXPECT(require_summary_field_value(*tls_layers[2], "Payload Interpretation") == "Encrypted/opaque handshake payload");
        }
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(
            fixture_path("parsing/tls/tls_1_2_client_certificate_missing_18.pcap"),
            CaptureImportOptions {}
        ));

        const auto loaded_packet_window_count = session.list_flow_packets(0).size();
        const auto flow_packet_index = require_flow_packet_index(session, 0U, 12U);
        const auto summary = build_selected_packet_summary(
            session,
            0U,
            12U,
            flow_packet_index,
            loaded_packet_window_count
        );

        PFL_EXPECT(summary.reconstructed_tls_records.empty());

        const auto tls_layers = find_summary_layers(summary.summary_layers, "tls");
        PFL_REQUIRE(tls_layers.size() == 4U);
        PFL_EXPECT(require_summary_field_value(*tls_layers[0], "Handshake Type") == "Certificate");
        PFL_EXPECT(require_summary_field_value(*tls_layers[0], "Certificate Count") == "0");
        expect_ecdhe_client_key_exchange_summary(*tls_layers[1]);
        PFL_EXPECT(require_summary_field_value(*tls_layers[2], "Record Type") == "ChangeCipherSpec");
        PFL_EXPECT(require_summary_field_value(*tls_layers[2], "Record Length") == "1");
        PFL_EXPECT(require_summary_field_value(*tls_layers[3], "Payload Interpretation") == "Encrypted/opaque handshake payload");
    }

    {
        const auto summary_layers = build_fixture_summary_layers("parsing/tls/tls_1_2_app_data_3.pcap");
        const auto tls_layers = find_summary_layers(summary_layers, "tls");
        PFL_REQUIRE(tls_layers.size() == 1U);
        PFL_EXPECT(find_summary_layer(summary_layers, "data") == nullptr);
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
        PFL_EXPECT(find_summary_layer(summary_layers, "data") == nullptr);
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
        PFL_EXPECT(find_summary_layer(summary_layers, "data") == nullptr);
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
        struct EncryptedAlertPacketExpectation {
            const char* relative_path;
            std::uint64_t packet_index;
        };

        const std::vector<EncryptedAlertPacketExpectation> expectations {
            {
                .relative_path = "parsing/tls/tls_1_0_badssl_baseline_12.pcap",
                .packet_index = 19U,
            },
            {
                .relative_path = "parsing/tls/tls_1_0_badssl_baseline_12.pcap",
                .packet_index = 22U,
            },
            {
                .relative_path = "parsing/tls/tls_1_1_badssl_baseline_13.pcap",
                .packet_index = 18U,
            },
            {
                .relative_path = "parsing/tls/tls_1_1_badssl_baseline_13.pcap",
                .packet_index = 20U,
            },
            {
                .relative_path = "parsing/tls/tls_1_2_badssl_baseline_14.pcap",
                .packet_index = 18U,
            },
            {
                .relative_path = "parsing/tls/tls_1_2_badssl_baseline_14.pcap",
                .packet_index = 20U,
            },
        };

        for (const auto& expectation : expectations) {
            ScopedTestContext context {
                std::string {"fixture="} + expectation.relative_path +
                " | packet=" + std::to_string(expectation.packet_index + 1U)
            };
            CaptureSession session {};
            PFL_EXPECT(session.open_capture(fixture_path(expectation.relative_path), CaptureImportOptions {}));

            const auto loaded_packet_window_count = session.list_flow_packets(0).size();
            const auto flow_packet_index = require_flow_packet_index(session, 0U, expectation.packet_index);
            const auto summary = build_selected_packet_summary(
                session,
                0U,
                expectation.packet_index,
                flow_packet_index,
                loaded_packet_window_count
            );
            const auto tls_layers = find_summary_layers(summary.summary_layers, "tls");
            PFL_REQUIRE(!tls_layers.empty());
            PFL_EXPECT(find_summary_layer(summary.summary_layers, "data") == nullptr);
            for (std::size_t index = 0U; index + 1U < tls_layers.size(); ++index) {
                PFL_EXPECT(tls_layers[index]->title.find("ApplicationData") != std::string::npos);
            }
            PFL_EXPECT(summary.reconstructed_tls_records.empty());
            const auto* alert_layer = tls_layers.back();
            PFL_EXPECT(alert_layer->title.find("Alert") != std::string::npos);
            PFL_EXPECT(require_summary_field_value(*alert_layer, "Record Type") == "Alert");
            const auto* payload_interpretation = find_summary_field(*alert_layer, "Payload Interpretation");
            if (payload_interpretation == nullptr) {
                std::ostringstream message {};
                message << "alert layer fields:";
                for (const auto& field : alert_layer->fields) {
                    message << " [" << field.label << '=' << field.value << ']';
                }
                record_failure_message(message.str());
            } else if (payload_interpretation->value != "Encrypted/opaque alert payload") {
                record_failure_message(
                    "alert payload interpretation=" + payload_interpretation->value
                );
            }
            PFL_EXPECT(require_summary_field_value(*alert_layer, "Payload Interpretation") ==
                "Encrypted/opaque alert payload");
            PFL_EXPECT(find_summary_field(*alert_layer, "Status") == nullptr);
            PFL_EXPECT(find_summary_field(*alert_layer, "Alert Count") == nullptr);
            PFL_EXPECT(find_summary_field(*alert_layer, "Alert Level [0]") == nullptr);
            PFL_EXPECT(find_summary_field(*alert_layer, "Alert Description [0]") == nullptr);
        }
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(
            fixture_path("parsing/tls/tls_1_2_self_signed_unknown_ca_17.pcap"),
            CaptureImportOptions {}
        ));

        const auto loaded_packet_window_count = session.list_flow_packets(0).size();
        const auto flow_packet_index = require_flow_packet_index(session, 0U, 7U);
        const auto summary = build_selected_packet_summary(session, 0U, 7U, flow_packet_index, loaded_packet_window_count);
        const auto tls_layers = find_summary_layers(summary.summary_layers, "tls");
        PFL_EXPECT(summary.reconstructed_tls_records.empty());
        PFL_REQUIRE(!tls_layers.empty());
        const auto* alert_layer = tls_layers.back();
        PFL_EXPECT(alert_layer->title.find("Alert") != std::string::npos);
        PFL_EXPECT(require_summary_field_value(*alert_layer, "Record Type") == "Alert");
        PFL_EXPECT(require_summary_field_value(*alert_layer, "Status") == "Plaintext alert payload parsed");
        PFL_EXPECT(require_summary_field_value(*alert_layer, "Alert Count") == "1");
        PFL_EXPECT(require_summary_field_value(*alert_layer, "Alert Level [0]") == "Fatal (2)");
        PFL_EXPECT(require_summary_field_value(*alert_layer, "Alert Description [0]") == "Unknown CA (48)");
        PFL_EXPECT(find_summary_field(*alert_layer, "Payload Interpretation") == nullptr);
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
        });
        const auto* tls_layer = find_summary_layer(summary_layers, "tls");
        PFL_REQUIRE(tls_layer != nullptr);
        PFL_EXPECT(tls_layer->warning);
        PFL_EXPECT(tls_layer->title == "Transport Layer Security, ClientHello Fragment");
        PFL_EXPECT(require_summary_field_value(*tls_layer, "Status") == "Incomplete record body");
        PFL_EXPECT(require_summary_field_value(*tls_layer, "Available Bytes") == "7");
        PFL_EXPECT(require_summary_field_value(*tls_layer, "Record Type") == "Handshake");
        PFL_EXPECT(require_summary_field_value(*tls_layer, "Record Legacy Version") == "TLS 1.2 (0x0303)");
        PFL_EXPECT(require_summary_field_value(*tls_layer, "Declared Record Length") == "8");
        PFL_EXPECT(require_summary_field_value(*tls_layer, "Handshake Type") == "ClientHello");
        PFL_EXPECT(find_summary_field(*tls_layer, "Handshake Length") == nullptr);
        PFL_EXPECT(require_summary_field_value(*tls_layer, "Handshake Status") == "Incomplete header");
        PFL_EXPECT(require_summary_field_value(*tls_layer, "Available Handshake Bytes") == "2");
        PFL_EXPECT(find_summary_field(*tls_layer, "ClientHello Legacy Version") == nullptr);
        PFL_EXPECT(find_summary_child(*tls_layer, "tls_extensions") == nullptr);
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
        });
        PFL_EXPECT(find_summary_layer(summary_layers, "tls") == nullptr);
    }

    {
        const auto payload = std::vector<std::uint8_t> {0x16U, 0x03U, 0x03U, 0x00U, 0x00U};
        const auto summary_layers = build_synthetic_tcp_flow_summary_layers(
            "pfl_packet_summary_tls_zero_length_handshake_like.pcap",
            {payload},
            0U
        );
        PFL_EXPECT(find_summary_layer(summary_layers, "tls") == nullptr);
        const auto data_layers = find_summary_layers(summary_layers, "data");
        PFL_REQUIRE(data_layers.size() == 1U);
        PFL_EXPECT(require_summary_field_value(*data_layers[0], "Transport") == "TCP");
        PFL_EXPECT(require_summary_field_value(*data_layers[0], "Data Length") == "5 bytes");
        PFL_EXPECT(require_summary_field_value(*data_layers[0], "Preview") == format_expected_hex_byte_list(payload));
    }

    {
        const auto payload = std::vector<std::uint8_t> {0x15U, 0x03U, 0x03U, 0x00U, 0x00U};
        const auto summary_layers = build_synthetic_tcp_flow_summary_layers(
            "pfl_packet_summary_tls_zero_length_alert_like.pcap",
            {payload},
            0U
        );
        PFL_EXPECT(find_summary_layer(summary_layers, "tls") == nullptr);
        const auto data_layers = find_summary_layers(summary_layers, "data");
        PFL_REQUIRE(data_layers.size() == 1U);
        PFL_EXPECT(require_summary_field_value(*data_layers[0], "Transport") == "TCP");
        PFL_EXPECT(require_summary_field_value(*data_layers[0], "Data Length") == "5 bytes");
        PFL_EXPECT(require_summary_field_value(*data_layers[0], "Preview") == format_expected_hex_byte_list(payload));
    }

    {
        const auto payload = std::vector<std::uint8_t> {0x14U, 0x03U, 0x03U, 0x00U, 0x00U};
        const auto summary_layers = build_synthetic_tcp_flow_summary_layers(
            "pfl_packet_summary_tls_zero_length_ccs_like.pcap",
            {payload},
            0U
        );
        PFL_EXPECT(find_summary_layer(summary_layers, "tls") == nullptr);
        const auto data_layers = find_summary_layers(summary_layers, "data");
        PFL_REQUIRE(data_layers.size() == 1U);
        PFL_EXPECT(require_summary_field_value(*data_layers[0], "Transport") == "TCP");
        PFL_EXPECT(require_summary_field_value(*data_layers[0], "Data Length") == "5 bytes");
        PFL_EXPECT(require_summary_field_value(*data_layers[0], "Preview") == format_expected_hex_byte_list(payload));
    }

    {
        const auto payload = std::vector<std::uint8_t> {0x16U, 0x03U, 0x03U, 0x00U, 0x20U};
        const auto summary_layers = build_synthetic_tcp_flow_summary_layers(
            "pfl_packet_summary_tls_partial_header_only_like.pcap",
            {payload},
            0U
        );
        PFL_EXPECT(find_summary_layer(summary_layers, "tls") == nullptr);
        const auto data_layers = find_summary_layers(summary_layers, "data");
        PFL_REQUIRE(data_layers.size() == 1U);
        PFL_EXPECT(require_summary_field_value(*data_layers[0], "Transport") == "TCP");
        PFL_EXPECT(require_summary_field_value(*data_layers[0], "Data Length") == "5 bytes");
        PFL_EXPECT(require_summary_field_value(*data_layers[0], "Preview") == format_expected_hex_byte_list(payload));
    }

    {
        const auto payload = std::vector<std::uint8_t> {0x16U, 0x03U, 0x03U, 0x00U, 0x08U, 0x01U, 0x02U};
        const auto summary_layers = build_synthetic_tcp_flow_summary_layers(
            "pfl_packet_summary_tls_partial_client_hello_like.pcap",
            {payload},
            0U
        );
        const auto* tls_layer = find_summary_layer(summary_layers, "tls");
        PFL_REQUIRE(tls_layer != nullptr);
        PFL_EXPECT(tls_layer->title == "Transport Layer Security, ClientHello Fragment");
        PFL_EXPECT(require_summary_field_value(*tls_layer, "Status") == "Incomplete record body");
        PFL_EXPECT(find_summary_layer(summary_layers, "data") == nullptr);
    }

    {
        const auto payload = std::vector<std::uint8_t> {0x16U, 0x03U, 0x03U, 0x40U, 0x01U};
        const auto summary_layers = build_synthetic_tcp_flow_summary_layers(
            "pfl_packet_summary_tls_invalid_record_length_like.pcap",
            {payload},
            0U
        );
        PFL_EXPECT(find_summary_layer(summary_layers, "tls") == nullptr);
        const auto data_layers = find_summary_layers(summary_layers, "data");
        PFL_REQUIRE(data_layers.size() == 1U);
        PFL_EXPECT(require_summary_field_value(*data_layers[0], "Transport") == "TCP");
        PFL_EXPECT(require_summary_field_value(*data_layers[0], "Data Length") == "5 bytes");
        PFL_EXPECT(require_summary_field_value(*data_layers[0], "Preview") == format_expected_hex_byte_list(payload));
    }

    {
        const auto payload = std::vector<std::uint8_t> {0x17U, 0x03U, 0x03U, 0x00U, 0x00U};
        const auto summary_layers = build_synthetic_tcp_flow_summary_layers(
            "pfl_packet_summary_tls_zero_length_app_data_without_context.pcap",
            {payload},
            0U
        );
        PFL_EXPECT(find_summary_layer(summary_layers, "tls") == nullptr);
        const auto data_layers = find_summary_layers(summary_layers, "data");
        PFL_REQUIRE(data_layers.size() == 1U);
        PFL_EXPECT(require_summary_field_value(*data_layers[0], "Transport") == "TCP");
        PFL_EXPECT(require_summary_field_value(*data_layers[0], "Data Length") == "5 bytes");
        PFL_EXPECT(require_summary_field_value(*data_layers[0], "Preview") == format_expected_hex_byte_list(payload));
    }

    {
        const auto summary_layers = build_synthetic_tcp_flow_summary_layers(
            "pfl_packet_summary_tls_zero_length_app_data_with_confirmed_context.pcap",
            {
                make_tls_record(0x14U, 0x0303U, {0x01U}),
                make_tls_record(0x17U, 0x0303U, {}),
            },
            1U
        );
        const auto tls_layers = find_summary_layers(summary_layers, "tls");
        PFL_REQUIRE(tls_layers.size() == 1U);
        PFL_EXPECT(require_summary_field_value(*tls_layers[0], "Record Type") == "ApplicationData");
        PFL_EXPECT(require_summary_field_value(*tls_layers[0], "Record Length") == "0");
        PFL_EXPECT(find_summary_layer(summary_layers, "data") == nullptr);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/http/http_get_1.pcap"), CaptureImportOptions {}));
        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->has_http);
        PFL_EXPECT(!details->has_dns);
        PFL_EXPECT(details->http.message_type == HttpMessageType::request);
        PFL_EXPECT(details->http.method == "GET");
        PFL_EXPECT(details->http.host == "www.kresla-darom.ru");
        const auto summary_layers = build_flow_packet_summary_layers(
            session,
            0U,
            0U,
            64U
        );
        PFL_EXPECT(summary_layers.size() >= 5U);
        PFL_EXPECT(summary_layers[summary_layers.size() - 2U].id == "tcp");
        PFL_EXPECT(summary_layers.back().id == "http");
        PFL_EXPECT(summary_layers.back().title.find("Hypertext Transfer Protocol") != std::string::npos);
        PFL_EXPECT(require_summary_field_value(summary_layers.back(), "Message Type") == "Request");
        PFL_EXPECT(require_summary_field_value(summary_layers.back(), "Method") == "GET");
        PFL_EXPECT(require_summary_field_value(summary_layers.back(), "Host") == "www.kresla-darom.ru");
        PFL_EXPECT(find_summary_layer(summary_layers, "data") == nullptr);
    }

    {
        const auto udp_payload = std::vector<std::uint8_t> {0xdeU, 0xadU, 0xbeU, 0xefU};
        const auto capture_path = write_temp_pcap(
            "pfl_packet_summary_unclaimed_udp_data.pcap",
            make_classic_pcap({{
                100U,
                make_ethernet_ipv4_udp_packet_with_bytes_payload(
                    ipv4(10, 0, 0, 20),
                    ipv4(10, 0, 0, 21),
                    54020,
                    40000,
                    udp_payload)
            }})
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(capture_path, CaptureImportOptions {}));
        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        PFL_REQUIRE(details->effective_transport_payload.has_value());
        PFL_EXPECT(details->effective_transport_payload->transport == EffectiveTransportKind::udp);
        PFL_EXPECT(details->effective_transport_payload->role == EffectiveTransportRole::top_level);
        PFL_EXPECT(details->effective_transport_payload->summary_placement ==
            EffectiveTransportSummaryPlacement::after_udp);
        PFL_EXPECT(details->effective_transport_payload->captured_payload_length == udp_payload.size());
        PFL_EXPECT(details->effective_transport_payload->declared_payload_length == udp_payload.size());
        const auto summary_layers = build_flow_packet_summary_layers(session, 0U, 0U);
        const auto data_layers = find_summary_layers(summary_layers, "data");
        PFL_REQUIRE(data_layers.size() == 1U);
        PFL_EXPECT(find_summary_layer(summary_layers, "dns") == nullptr);
        PFL_EXPECT(find_summary_layer(summary_layers, "http") == nullptr);
        PFL_EXPECT(find_summary_layer(summary_layers, "quic") == nullptr);
        PFL_EXPECT(find_summary_layer(summary_layers, "tls") == nullptr);
        PFL_EXPECT(find_summary_layer_index(summary_layers, "udp") < find_summary_layer_index(summary_layers, "data"));
        PFL_EXPECT(require_summary_field_value(*data_layers[0], "Role") == "Transport Payload");
        PFL_EXPECT(require_summary_field_value(*data_layers[0], "Transport") == "UDP");
        PFL_EXPECT(require_summary_field_value(*data_layers[0], "Data Length") == "4 bytes");
        PFL_EXPECT(require_summary_field_value(*data_layers[0], "Status") == "Complete");
        PFL_EXPECT(require_summary_field_value(*data_layers[0], "Preview") == format_expected_hex_byte_list(udp_payload));
        PFL_EXPECT(require_summary_field_value(*data_layers[0], "Displayed Bytes") == "4 bytes");
        PFL_EXPECT(require_summary_field_value(*data_layers[0], "Omitted Bytes") == "0 bytes");
        PFL_EXPECT(find_summary_field(*data_layers[0], "Declared Length") == nullptr);
        PFL_EXPECT(find_summary_field(*data_layers[0], "Captured Length") == nullptr);
    }

    {
        std::vector<std::uint8_t> tcp_payload {};
        tcp_payload.reserve(40U);
        for (std::uint8_t value = 0U; value < 40U; ++value) {
            tcp_payload.push_back(value);
        }

        const auto capture_path = write_temp_pcap(
            "pfl_packet_summary_unclaimed_tcp_data.pcap",
            make_classic_pcap({{
                100U,
                make_ethernet_ipv4_tcp_packet_with_bytes_payload(
                    ipv4(10, 0, 0, 22),
                    ipv4(10, 0, 0, 23),
                    41020,
                    40001,
                    tcp_payload)
            }})
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(capture_path, CaptureImportOptions {}));
        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        PFL_REQUIRE(details->effective_transport_payload.has_value());
        PFL_EXPECT(details->effective_transport_payload->transport == EffectiveTransportKind::tcp);
        PFL_EXPECT(details->effective_transport_payload->role == EffectiveTransportRole::top_level);
        PFL_EXPECT(details->effective_transport_payload->summary_placement ==
            EffectiveTransportSummaryPlacement::after_tcp);
        PFL_EXPECT(details->effective_transport_payload->captured_payload_length == tcp_payload.size());
        PFL_EXPECT(!details->effective_transport_payload->declared_payload_length.has_value());
        const auto summary_layers = build_flow_packet_summary_layers(session, 0U, 0U);
        const auto data_layers = find_summary_layers(summary_layers, "data");
        PFL_REQUIRE(data_layers.size() == 1U);
        PFL_EXPECT(find_summary_layer(summary_layers, "http") == nullptr);
        PFL_EXPECT(find_summary_layer(summary_layers, "tls") == nullptr);
        PFL_EXPECT(find_summary_layer(summary_layers, "quic") == nullptr);
        PFL_EXPECT(find_summary_layer_index(summary_layers, "tcp") < find_summary_layer_index(summary_layers, "data"));
        PFL_EXPECT(require_summary_field_value(*data_layers[0], "Role") == "Transport Payload");
        PFL_EXPECT(require_summary_field_value(*data_layers[0], "Transport") == "TCP");
        PFL_EXPECT(require_summary_field_value(*data_layers[0], "Data Length") == "40 bytes");
        PFL_EXPECT(find_summary_field(*data_layers[0], "Status") == nullptr);
        PFL_EXPECT(require_summary_field_value(*data_layers[0], "Preview") ==
            format_expected_hex_byte_list(std::span<const std::uint8_t>(tcp_payload.data(), 32U)));
        PFL_EXPECT(count_hex_byte_tokens(require_summary_field_value(*data_layers[0], "Preview")) == 32U);
        PFL_EXPECT(require_summary_field_value(*data_layers[0], "Displayed Bytes") == "32 bytes");
        PFL_EXPECT(require_summary_field_value(*data_layers[0], "Omitted Bytes") == "8 bytes");
        PFL_EXPECT(require_summary_field_value(*data_layers[0], "Preview").find("20 21 22") == std::string::npos);
    }

    {
        const auto tcp_capture_path = write_temp_pcap(
            "pfl_packet_summary_empty_tcp_payload.pcap",
            make_classic_pcap({{
                100U,
                make_ethernet_ipv4_tcp_packet(
                    ipv4(10, 0, 0, 24),
                    ipv4(10, 0, 0, 25),
                    41021,
                    40002)
            }})
        );
        CaptureSession tcp_session {};
        PFL_EXPECT(tcp_session.open_capture(tcp_capture_path, CaptureImportOptions {}));
        PFL_EXPECT(find_summary_layer(build_flow_packet_summary_layers(tcp_session, 0U, 0U), "data") == nullptr);

        const auto udp_capture_path = write_temp_pcap(
            "pfl_packet_summary_empty_udp_payload.pcap",
            make_classic_pcap({{
                100U,
                make_ethernet_ipv4_udp_packet(
                    ipv4(10, 0, 0, 26),
                    ipv4(10, 0, 0, 27),
                    54021,
                    40003)
            }})
        );
        CaptureSession udp_session {};
        PFL_EXPECT(udp_session.open_capture(udp_capture_path, CaptureImportOptions {}));
        PFL_EXPECT(find_summary_layer(build_flow_packet_summary_layers(udp_session, 0U, 0U), "data") == nullptr);
    }

    {
        const auto udp_payload = std::vector<std::uint8_t> {
            't', 'o', 'p', '-', 'l', 'e', 'v', 'e', 'l', '-',
            't', 'r', 'u', 'n', 'c', 'a', 't', 'e', 'd'
        };
        const auto full_udp_packet = make_ethernet_ipv4_udp_packet_with_bytes_payload(
            ipv4(10, 0, 0, 28),
            ipv4(10, 0, 0, 29),
            54022,
            40004,
            udp_payload
        );
        auto captured_udp_packet = full_udp_packet;
        captured_udp_packet.resize(captured_udp_packet.size() - 3U);

        const auto capture_path = write_temp_pcap(
            "pfl_packet_summary_top_level_udp_truncated.pcap",
            make_classic_pcap_with_captured_lengths(std::vector<ClassicPcapCapturedRecord> {
                ClassicPcapCapturedRecord {
                    .ts_usec = 100U,
                    .captured_bytes = captured_udp_packet,
                    .original_length = static_cast<std::uint32_t>(full_udp_packet.size()),
                },
            })
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(capture_path, CaptureImportOptions {}));
        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        PFL_REQUIRE(details->effective_transport_payload.has_value());
        PFL_EXPECT(details->effective_transport_payload->role == EffectiveTransportRole::top_level);
        PFL_EXPECT(details->effective_transport_payload->transport == EffectiveTransportKind::udp);

        const auto packet_summary_preparation = prepare_selected_packet_summary_with_production_lengths(
            session,
            *details,
            packet,
            0U,
            0U,
            1U
        );
        PFL_REQUIRE(packet_summary_preparation.packet_data.has_value());
        PFL_EXPECT(packet_summary_preparation.packet_data->disposition ==
            session_detail::TransportPayloadDisposition::unavailable_or_truncated);
        PFL_EXPECT(find_summary_layer(
            session_detail::build_packet_summary_layers(*details, packet, packet_summary_preparation.make_options()),
            "data"
        ) == nullptr);
    }

    {
        const std::string_view expected_udp_data_text = "INNER-UDP-DATA|0123456789|ABCDEFGHIJKLMNOPQRSTUV";
        const std::vector<std::uint8_t> expected_udp_data(
            expected_udp_data_text.begin(),
            expected_udp_data_text.end()
        );
        const auto summary_layers = build_fixture_summary_layers("parsing/gtpu/32_gtpu_inner_ipv4_udp_data.pcap");
        const auto data_layers = find_summary_layers(summary_layers, "data");
        PFL_REQUIRE(find_summary_layer(summary_layers, "udp") != nullptr);
        PFL_REQUIRE(find_summary_layer(summary_layers, "gtpu") != nullptr);
        PFL_REQUIRE(find_summary_layer(summary_layers, "ipv4-inner") != nullptr);
        const auto* inner_udp_layer = find_summary_layer(summary_layers, "udp-inner");
        PFL_REQUIRE(inner_udp_layer != nullptr);
        PFL_REQUIRE(data_layers.size() == 1U);
        PFL_EXPECT(find_summary_layer_index(summary_layers, "udp-inner") + 1U == find_summary_layer_index(summary_layers, "data"));
        PFL_EXPECT(require_summary_field_value(*inner_udp_layer, "Payload Length") == "48 bytes");
        PFL_EXPECT(require_summary_field_value(*data_layers[0], "Role") == "Transport Payload");
        PFL_EXPECT(require_summary_field_value(*data_layers[0], "Transport") == "UDP");
        PFL_EXPECT(require_summary_field_value(*data_layers[0], "Data Length") == "48 bytes");
        PFL_EXPECT(require_summary_field_value(*data_layers[0], "Status") == "Complete");
        PFL_EXPECT(require_summary_field_value(*data_layers[0], "Preview") ==
            format_expected_hex_byte_list(std::span<const std::uint8_t>(expected_udp_data.data(), 32U)));
        PFL_EXPECT(count_hex_byte_tokens(require_summary_field_value(*data_layers[0], "Preview")) == 32U);
        PFL_EXPECT(require_summary_field_value(*data_layers[0], "Displayed Bytes") == "32 bytes");
        PFL_EXPECT(require_summary_field_value(*data_layers[0], "Omitted Bytes") == "16 bytes");
        PFL_EXPECT(require_summary_field_value(*data_layers[0], "Preview").find("49 4e 4e 45 52 2d 55 44 50 2d 44 41 54 41") == 0U);

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/gtpu/32_gtpu_inner_ipv4_udp_data.pcap"), CaptureImportOptions {}));
        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        PFL_REQUIRE(details->effective_transport_payload.has_value());
        PFL_EXPECT(details->effective_transport_payload->transport == EffectiveTransportKind::udp);
        PFL_EXPECT(details->effective_transport_payload->role == EffectiveTransportRole::inner);
        PFL_EXPECT(details->effective_transport_payload->summary_placement ==
            EffectiveTransportSummaryPlacement::after_inner_udp);
        PFL_EXPECT(details->effective_transport_payload->captured_payload_length == expected_udp_data.size());
        PFL_EXPECT(details->effective_transport_payload->declared_payload_length == expected_udp_data.size());

        const auto flow_context = resolve_selected_packet_flow_context(session, packet);
        const auto packet_summary_preparation = prepare_selected_packet_summary_with_production_lengths(
            session,
            *details,
            packet,
            flow_context.flow_index,
            flow_context.flow_packet_index,
            flow_context.loaded_packet_window_count
        );
        PFL_REQUIRE(packet_summary_preparation.packet_data.has_value());
        PFL_EXPECT(packet_summary_preparation.packet_data->disposition ==
            session_detail::TransportPayloadDisposition::unclaimed_data);
        PFL_EXPECT(packet_summary_preparation.packet_data->placement ==
            session_detail::PacketDataPlacement::after_inner_udp);
        PFL_EXPECT(packet_summary_preparation.packet_data->captured_length == expected_udp_data.size());
        PFL_EXPECT(packet_summary_preparation.packet_data->declared_length == expected_udp_data.size());
        PFL_EXPECT(packet_summary_preparation.packet_data_preview.size() == 32U);
        PFL_EXPECT(packet_summary_preparation.packet_data_preview ==
            std::vector<std::uint8_t>(expected_udp_data.begin(), expected_udp_data.begin() + 32));
    }

    {
        const std::string_view expected_tcp_data_text = "INNER-TCP-DATA|0123456789|abcdefghijklmnopqrstuv";
        const std::vector<std::uint8_t> expected_tcp_data(
            expected_tcp_data_text.begin(),
            expected_tcp_data_text.end()
        );
        const auto summary_layers = build_fixture_summary_layers("parsing/gtpu/33_gtpu_inner_ipv4_tcp_data.pcap");
        const auto data_layers = find_summary_layers(summary_layers, "data");
        PFL_REQUIRE(find_summary_layer(summary_layers, "udp") != nullptr);
        PFL_REQUIRE(find_summary_layer(summary_layers, "gtpu") != nullptr);
        PFL_REQUIRE(find_summary_layer(summary_layers, "ipv4-inner") != nullptr);
        const auto* inner_tcp_layer = find_summary_layer(summary_layers, "tcp-inner");
        PFL_REQUIRE(inner_tcp_layer != nullptr);
        PFL_REQUIRE(data_layers.size() == 1U);
        PFL_EXPECT(find_summary_layer_index(summary_layers, "tcp-inner") + 1U == find_summary_layer_index(summary_layers, "data"));
        PFL_EXPECT(require_summary_field_value(*inner_tcp_layer, "Payload Length") == "48 bytes");
        PFL_EXPECT(require_summary_field_value(*data_layers[0], "Role") == "Transport Payload");
        PFL_EXPECT(require_summary_field_value(*data_layers[0], "Transport") == "TCP");
        PFL_EXPECT(require_summary_field_value(*data_layers[0], "Data Length") == "48 bytes");
        PFL_EXPECT(find_summary_field(*data_layers[0], "Status") == nullptr);
        PFL_EXPECT(require_summary_field_value(*data_layers[0], "Preview") ==
            format_expected_hex_byte_list(std::span<const std::uint8_t>(expected_tcp_data.data(), 32U)));
        PFL_EXPECT(count_hex_byte_tokens(require_summary_field_value(*data_layers[0], "Preview")) == 32U);
        PFL_EXPECT(require_summary_field_value(*data_layers[0], "Displayed Bytes") == "32 bytes");
        PFL_EXPECT(require_summary_field_value(*data_layers[0], "Omitted Bytes") == "16 bytes");
        PFL_EXPECT(require_summary_field_value(*data_layers[0], "Preview").find("49 4e 4e 45 52 2d 54 43 50 2d 44 41 54 41") == 0U);

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/gtpu/33_gtpu_inner_ipv4_tcp_data.pcap"), CaptureImportOptions {}));
        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        PFL_REQUIRE(details->effective_transport_payload.has_value());
        PFL_EXPECT(details->effective_transport_payload->transport == EffectiveTransportKind::tcp);
        PFL_EXPECT(details->effective_transport_payload->role == EffectiveTransportRole::inner);
        PFL_EXPECT(details->effective_transport_payload->summary_placement ==
            EffectiveTransportSummaryPlacement::after_inner_tcp);
        PFL_EXPECT(details->effective_transport_payload->captured_payload_length == expected_tcp_data.size());
        PFL_EXPECT(!details->effective_transport_payload->declared_payload_length.has_value());

        const auto flow_context = resolve_selected_packet_flow_context(session, packet);
        const auto packet_summary_preparation = prepare_selected_packet_summary_with_production_lengths(
            session,
            *details,
            packet,
            flow_context.flow_index,
            flow_context.flow_packet_index,
            flow_context.loaded_packet_window_count
        );
        PFL_REQUIRE(packet_summary_preparation.packet_data.has_value());
        PFL_EXPECT(packet_summary_preparation.packet_data->disposition ==
            session_detail::TransportPayloadDisposition::unclaimed_data);
        PFL_EXPECT(packet_summary_preparation.packet_data->placement ==
            session_detail::PacketDataPlacement::after_inner_tcp);
        PFL_EXPECT(packet_summary_preparation.packet_data->captured_length == expected_tcp_data.size());
    }

    {
        const auto summary_layers = build_fixture_summary_layers("parsing/gtpu/34_gtpu_inner_ipv4_tcp_ack_only.pcap");
        PFL_REQUIRE(find_summary_layer(summary_layers, "gtpu") != nullptr);
        const auto* inner_tcp_layer = find_summary_layer(summary_layers, "tcp-inner");
        PFL_REQUIRE(inner_tcp_layer != nullptr);
        PFL_EXPECT(require_summary_field_value(*inner_tcp_layer, "Flags") == "ACK");
        PFL_EXPECT(require_summary_field_value(*inner_tcp_layer, "Payload Length") == "0 bytes");
        PFL_EXPECT(find_summary_layer(summary_layers, "data") == nullptr);

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/gtpu/34_gtpu_inner_ipv4_tcp_ack_only.pcap"), CaptureImportOptions {}));
        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        PFL_REQUIRE(details->effective_transport_payload.has_value());
        PFL_EXPECT(details->effective_transport_payload->transport == EffectiveTransportKind::tcp);
        PFL_EXPECT(details->effective_transport_payload->role == EffectiveTransportRole::inner);
        PFL_EXPECT(details->effective_transport_payload->summary_placement ==
            EffectiveTransportSummaryPlacement::after_inner_tcp);
        PFL_EXPECT(details->effective_transport_payload->captured_payload_length == 0U);

        const auto flow_context = resolve_selected_packet_flow_context(session, packet);
        const auto packet_summary_preparation = prepare_selected_packet_summary_with_production_lengths(
            session,
            *details,
            packet,
            flow_context.flow_index,
            flow_context.flow_packet_index,
            flow_context.loaded_packet_window_count
        );
        PFL_REQUIRE(packet_summary_preparation.packet_data.has_value());
        PFL_EXPECT(packet_summary_preparation.packet_data->captured_length == 0U);
        PFL_EXPECT(find_summary_layer(
            session_detail::build_packet_summary_layers(*details, packet, packet_summary_preparation.make_options()),
            "data"
        ) == nullptr);
    }

    {
        const CaptureImportOptions gtpu_teid_agnostic_options {
            .settings = AnalysisSettings {
                .ignore_gtpu_teids_when_grouping_inner_flows = true,
            },
        };

        const auto first_summary_layers = build_fixture_summary_layers(
            "parsing/gtpu/35_gtpu_bidirectional_different_teids_same_inner_tcp.pcap",
            gtpu_teid_agnostic_options,
            0U
        );
        const auto* first_gtpu_layer = find_summary_layer(first_summary_layers, "gtpu");
        PFL_REQUIRE(first_gtpu_layer != nullptr);
        PFL_EXPECT(first_gtpu_layer->title.find("0x01020311") != std::string::npos);
        PFL_EXPECT(require_summary_field_value(*first_gtpu_layer, "TEID") == "0x01020311");

        const auto second_summary_layers = build_fixture_summary_layers(
            "parsing/gtpu/35_gtpu_bidirectional_different_teids_same_inner_tcp.pcap",
            gtpu_teid_agnostic_options,
            1U
        );
        const auto* second_gtpu_layer = find_summary_layer(second_summary_layers, "gtpu");
        PFL_REQUIRE(second_gtpu_layer != nullptr);
        PFL_EXPECT(second_gtpu_layer->title.find("0x02030412") != std::string::npos);
        PFL_EXPECT(require_summary_field_value(*second_gtpu_layer, "TEID") == "0x02030412");
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/gtpu/32_gtpu_inner_ipv4_udp_data.pcap"), CaptureImportOptions {}));
        const auto packet = require_packet(session, 0U);
        auto details = session.read_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        PFL_REQUIRE(details->effective_transport_payload.has_value());
        details->effective_transport_payload->payload_truncated = true;

        const auto flow_context = resolve_selected_packet_flow_context(session, packet);
        auto packet_summary_preparation = session_detail::prepare_selected_packet_summary(
            session,
            *details,
            packet,
            flow_context.flow_index,
            flow_context.flow_packet_index,
            flow_context.loaded_packet_window_count,
            std::optional<std::uint32_t> {packet.payload_length},
            std::optional<std::uint32_t> {packet.payload_length}
        );
        PFL_REQUIRE(packet_summary_preparation.packet_data.has_value());
        PFL_EXPECT(packet_summary_preparation.packet_data->disposition ==
            session_detail::TransportPayloadDisposition::unavailable_or_truncated);
        PFL_EXPECT(find_summary_layer(
            session_detail::build_packet_summary_layers(*details, packet, packet_summary_preparation.make_options()),
            "data"
        ) == nullptr);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/gre/15_gre_mpls_ipv4_udp.pcap"), CaptureImportOptions {}));
        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        PFL_REQUIRE(details->effective_transport_payload.has_value());
        PFL_EXPECT(details->effective_transport_payload->transport == EffectiveTransportKind::udp);
        PFL_EXPECT(details->effective_transport_payload->role == EffectiveTransportRole::inner);
        PFL_EXPECT(details->effective_transport_payload->summary_placement ==
            EffectiveTransportSummaryPlacement::after_inner_udp);

        const auto summary_layers = build_flow_packet_summary_layers(session, 0U, 0U);
        const auto data_layers = find_summary_layers(summary_layers, "data");
        const auto* gre_layer = find_summary_layer(summary_layers, "gre");
        const auto* mpls_layer = find_summary_layer(summary_layers, "mpls");
        const auto* inner_udp_layer = find_summary_layer(summary_layers, "udp-inner");
        PFL_REQUIRE(gre_layer != nullptr);
        PFL_REQUIRE(mpls_layer != nullptr);
        PFL_REQUIRE(inner_udp_layer != nullptr);
        PFL_REQUIRE(data_layers.size() == 1U);
        PFL_EXPECT(find_summary_layer(summary_layers, "udp") == nullptr);
        PFL_EXPECT(find_summary_layer_index(summary_layers, "udp-inner") + 1U == find_summary_layer_index(summary_layers, "data"));
        PFL_EXPECT(require_summary_field_value(*data_layers[0], "Transport") == "UDP");
        PFL_EXPECT(require_summary_field_value(*data_layers[0], "Data Length") ==
            require_summary_field_value(*inner_udp_layer, "Payload Length"));
        const auto preview = require_summary_field_value(*data_layers[0], "Preview");
        PFL_EXPECT(!preview.empty());
        PFL_EXPECT(preview.find("45 ") != 0U);
        const auto src_port = static_cast<std::uint16_t>(std::stoul(
            require_summary_field_value(*inner_udp_layer, "Source Port")
        ));
        const auto dst_port = static_cast<std::uint16_t>(std::stoul(
            require_summary_field_value(*inner_udp_layer, "Destination Port")
        ));
        PFL_EXPECT(preview.find(format_transport_port_prefix_hex(src_port, dst_port)) != 0U);
    }

    {
        const auto summary_layers = build_fixture_summary_layers("parsing/ah/12_ipv4_ah_inner_ipv4_udp.pcap");
        const auto data_layers = find_summary_layers(summary_layers, "data");
        const auto* ah_layer = find_summary_layer(summary_layers, "ah");
        const auto* inner_udp_layer = find_summary_layer(summary_layers, "udp-inner");
        PFL_REQUIRE(ah_layer != nullptr);
        PFL_REQUIRE(inner_udp_layer != nullptr);
        PFL_REQUIRE(data_layers.size() == 1U);
        PFL_EXPECT(find_summary_layer(summary_layers, "udp") == nullptr);
        PFL_EXPECT(find_summary_layer_index(summary_layers, "udp-inner") + 1U == find_summary_layer_index(summary_layers, "data"));
        PFL_EXPECT(require_summary_field_value(*data_layers[0], "Transport") == "UDP");
        PFL_EXPECT(require_summary_field_value(*data_layers[0], "Data Length") ==
            require_summary_field_value(*inner_udp_layer, "Payload Length"));
        const auto preview = require_summary_field_value(*data_layers[0], "Preview");
        PFL_EXPECT(!preview.empty());
        PFL_EXPECT(preview.find("45 ") != 0U);
        const auto src_port = static_cast<std::uint16_t>(std::stoul(
            require_summary_field_value(*inner_udp_layer, "Source Port")
        ));
        const auto dst_port = static_cast<std::uint16_t>(std::stoul(
            require_summary_field_value(*inner_udp_layer, "Destination Port")
        ));
        PFL_EXPECT(preview != format_transport_port_prefix_hex(src_port, dst_port));

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/ah/12_ipv4_ah_inner_ipv4_udp.pcap"), CaptureImportOptions {}));
        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        PFL_REQUIRE(details->effective_transport_payload.has_value());
        PFL_EXPECT(details->effective_transport_payload->transport == EffectiveTransportKind::udp);
        PFL_EXPECT(details->effective_transport_payload->role == EffectiveTransportRole::inner);
        PFL_EXPECT(details->effective_transport_payload->summary_placement ==
            EffectiveTransportSummaryPlacement::after_inner_udp);
        PFL_EXPECT(details->effective_transport_payload->captured_payload_length == 4U);
        PFL_EXPECT(details->effective_transport_payload->declared_payload_length == 4U);
    }

    {
        const auto summary_layers = build_fixture_summary_layers("parsing/ah/13_ipv4_ah_inner_ipv6_tcp.pcap");
        PFL_REQUIRE(find_summary_layer(summary_layers, "ah") != nullptr);
        const auto* inner_tcp_layer = find_summary_layer(summary_layers, "tcp-inner");
        PFL_REQUIRE(inner_tcp_layer != nullptr);
        PFL_EXPECT(require_summary_field_value(*inner_tcp_layer, "Payload Length") == "0 bytes");
        PFL_EXPECT(find_summary_layer(summary_layers, "data") == nullptr);

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/ah/13_ipv4_ah_inner_ipv6_tcp.pcap"), CaptureImportOptions {}));
        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        PFL_REQUIRE(details->effective_transport_payload.has_value());
        PFL_EXPECT(details->effective_transport_payload->transport == EffectiveTransportKind::tcp);
        PFL_EXPECT(details->effective_transport_payload->role == EffectiveTransportRole::inner);
        PFL_EXPECT(details->effective_transport_payload->summary_placement ==
            EffectiveTransportSummaryPlacement::after_inner_tcp);
        PFL_EXPECT(details->effective_transport_payload->captured_payload_length == 0U);
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
        const auto summary_layers = build_fixture_summary_layers("parsing/linux_cooked/01_sll_ipv4_tcp.pcap");
        PFL_EXPECT(summary_layers.size() >= 4U);
        PFL_EXPECT(find_summary_layer_index(summary_layers, "frame") == 0U);
        PFL_EXPECT(find_summary_layer_index(summary_layers, "linux-cooked") == 1U);
        PFL_EXPECT(find_summary_layer_index(summary_layers, "ipv4") == 2U);
        PFL_EXPECT(find_summary_layer_index(summary_layers, "tcp") == 3U);

        const auto* frame_layer = find_summary_layer(summary_layers, "frame");
        const auto* linux_sll_layer = find_summary_layer(summary_layers, "linux-cooked");
        PFL_REQUIRE(frame_layer != nullptr);
        PFL_REQUIRE(linux_sll_layer != nullptr);
        PFL_EXPECT(require_summary_field_value(*frame_layer, "Encapsulation Type") == "Linux cooked capture v1");
        PFL_EXPECT(linux_sll_layer->title == "Linux cooked capture v1");
        PFL_EXPECT(require_summary_field_value(*linux_sll_layer, "Packet Type") == "0x1234");
        PFL_EXPECT(require_summary_field_value(*linux_sll_layer, "Link-layer Address Type") == "0x3456");
        PFL_EXPECT(require_summary_field_value(*linux_sll_layer, "Link-layer Address Length") == "6");
        PFL_EXPECT(require_summary_field_value(*linux_sll_layer, "Link-layer Address") == "10:20:30:40:50:60");
        PFL_EXPECT(require_summary_field_value(*linux_sll_layer, "Protocol") == "IPv4 (0x0800)");
    }

    {
        const auto summary_layers = build_fixture_summary_layers("parsing/linux_cooked/05_sll2_ipv4_tcp.pcap");
        PFL_EXPECT(summary_layers.size() >= 4U);
        PFL_EXPECT(find_summary_layer_index(summary_layers, "frame") == 0U);
        PFL_EXPECT(find_summary_layer_index(summary_layers, "linux-cooked") == 1U);
        PFL_EXPECT(find_summary_layer_index(summary_layers, "ipv4") == 2U);
        PFL_EXPECT(find_summary_layer_index(summary_layers, "tcp") == 3U);

        const auto* frame_layer = find_summary_layer(summary_layers, "frame");
        const auto* linux_sll2_layer = find_summary_layer(summary_layers, "linux-cooked");
        PFL_REQUIRE(frame_layer != nullptr);
        PFL_REQUIRE(linux_sll2_layer != nullptr);
        PFL_EXPECT(require_summary_field_value(*frame_layer, "Encapsulation Type") == "Linux cooked capture v2");
        PFL_EXPECT(linux_sll2_layer->title == "Linux cooked capture v2");
        PFL_EXPECT(require_summary_field_value(*linux_sll2_layer, "Protocol") == "IPv4 (0x0800)");
        PFL_EXPECT(require_summary_field_value(*linux_sll2_layer, "Reserved") == "0x0000");
        PFL_EXPECT(require_summary_field_value(*linux_sll2_layer, "Interface Index") == "16909060");
        PFL_EXPECT(require_summary_field_value(*linux_sll2_layer, "Link-layer Address Type") == "0x0f0e");
        PFL_EXPECT(require_summary_field_value(*linux_sll2_layer, "Packet Type") == "0x007f");
        PFL_EXPECT(require_summary_field_value(*linux_sll2_layer, "Link-layer Address Length") == "6");
        PFL_EXPECT(require_summary_field_value(*linux_sll2_layer, "Link-layer Address") == "21:22:23:24:25:26");
    }

    {
        const auto summary_layers = build_fixture_summary_layers("parsing/linux_cooked/12_sll2_unknown_protocol.pcap");
        const auto* frame_layer = find_summary_layer(summary_layers, "frame");
        const auto* linux_sll2_layer = find_summary_layer(summary_layers, "linux-cooked");
        PFL_REQUIRE(frame_layer != nullptr);
        PFL_REQUIRE(linux_sll2_layer != nullptr);
        PFL_EXPECT(require_summary_field_value(*frame_layer, "Encapsulation Type") == "Linux cooked capture v2");
        PFL_EXPECT(linux_sll2_layer->title == "Linux cooked capture v2");
        PFL_EXPECT(require_summary_field_value(*linux_sll2_layer, "Protocol") == "0x4321");
    }

    {
        const auto summary_layers = build_fixture_summary_layers("parsing/linux_cooked/18_sll2_addrlen_12_ipv6_udp.pcap");
        const auto* linux_sll2_layer = find_summary_layer(summary_layers, "linux-cooked");
        PFL_REQUIRE(linux_sll2_layer != nullptr);
        PFL_EXPECT(require_summary_field_value(*linux_sll2_layer, "Link-layer Address Length") == "12");
        PFL_EXPECT(require_summary_field_value(*linux_sll2_layer, "Warning") ==
            "Declared link-layer address length exceeds the fixed 8-byte SLL2 address field");
    }

    {
        const auto summary_layers = build_fixture_summary_layers("parsing/linux_cooked/14_sll2_truncated_inner_ipv6.pcap");
        const auto* warning_layer = find_summary_layer(summary_layers, "warnings");
        const auto* linux_sll2_layer = find_summary_layer(summary_layers, "linux-cooked");
        PFL_REQUIRE(warning_layer != nullptr);
        PFL_REQUIRE(linux_sll2_layer != nullptr);
        PFL_EXPECT(linux_sll2_layer->title == "Linux cooked capture v2");
        PFL_EXPECT(require_summary_field_value(*linux_sll2_layer, "Protocol") == "IPv6 (0x86dd)");
        const auto has_truncation_warning = std::any_of(
            warning_layer->fields.begin(),
            warning_layer->fields.end(),
            [](const auto& field) {
                return field.value.find("IPv6 header truncated") != std::string::npos;
            }
        );
        PFL_EXPECT(has_truncation_warning);
    }

    {
        const auto summary_layers = build_fixture_summary_layers("parsing/linux_cooked/13_sll_truncated_inner_ipv4.pcap");
        const auto* warning_layer = find_summary_layer(summary_layers, "warnings");
        const auto* linux_sll_layer = find_summary_layer(summary_layers, "linux-cooked");
        PFL_REQUIRE(warning_layer != nullptr);
        PFL_REQUIRE(linux_sll_layer != nullptr);
        PFL_EXPECT(linux_sll_layer->title == "Linux cooked capture v1");
        PFL_EXPECT(require_summary_field_value(*linux_sll_layer, "Packet Type") == "0x0a0b");
        PFL_EXPECT(require_summary_field_value(*linux_sll_layer, "Link-layer Address Type") == "0x0c0d");
        PFL_EXPECT(require_summary_field_value(*linux_sll_layer, "Protocol") == "IPv4 (0x0800)");
        const auto has_truncation_warning = std::any_of(
            warning_layer->fields.begin(),
            warning_layer->fields.end(),
            [](const session_detail::PacketSummaryField& field) {
                return field.value == "Packet is truncated in capture";
            }
        );
        PFL_EXPECT(has_truncation_warning);
    }

    {
        const auto summary_layers = build_fixture_summary_layers("parsing/linux_cooked/16_sll_addrlen_12_ipv4_tcp.pcap");
        const auto* linux_sll_layer = find_summary_layer(summary_layers, "linux-cooked");
        PFL_REQUIRE(linux_sll_layer != nullptr);
        PFL_EXPECT(require_summary_field_value(*linux_sll_layer, "Link-layer Address Length") == "12");
        PFL_EXPECT(require_summary_field_value(*linux_sll_layer, "Warning") ==
            "Declared link-layer address length exceeds the fixed 8-byte SLL address field");
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
        PacketDetails details {
            .packet_index = 30U,
            .captured_length = 10U,
            .original_length = 10U,
        };
        const PacketRef packet_ref {
            .packet_index = 30U,
            .byte_offset = 300U,
            .data_link_type = 999U,
            .captured_length = 10U,
            .original_length = 10U,
        };

        const auto summary_layers = session_detail::build_packet_summary_layers(details, packet_ref);
        PFL_REQUIRE(summary_layers.size() == 1U);
        const auto* frame_layer = find_summary_layer(summary_layers, "frame");
        PFL_REQUIRE(frame_layer != nullptr);
        PFL_EXPECT(require_summary_field_value(*frame_layer, "Encapsulation Type") == "Unknown (999)");
    }

    {
        const auto ethernet_packet = make_ethernet_ipv4_tcp_packet(
            ipv4(10, 1, 0, 1),
            ipv4(10, 1, 0, 2),
            12345,
            443
        );
        const auto sll2_packet =
            require_first_raw_packet(fixture_path("parsing/linux_cooked/05_sll2_ipv4_tcp.pcap"));
        const auto pcapng_path = write_temp_pcap(
            "pfl_packet_details_multi_interface_encapsulation.pcapng",
            make_pcapng({
                make_pcapng_section_header_block(),
                make_pcapng_interface_description_block(static_cast<std::uint16_t>(kLinkTypeEthernet)),
                make_pcapng_interface_description_block(static_cast<std::uint16_t>(kLinkTypeLinuxSll2)),
                make_pcapng_enhanced_packet_block(0U, 1U, 100U, ethernet_packet),
                make_pcapng_enhanced_packet_block(1U, 1U, 200U, sll2_packet.bytes),
            })
        );

        const auto ethernet_summary_layers = build_capture_summary_layers(pcapng_path, 0U);
        const auto sll2_summary_layers = build_capture_summary_layers(pcapng_path, 1U);
        const auto* ethernet_frame_layer = find_summary_layer(ethernet_summary_layers, "frame");
        const auto* sll2_frame_layer = find_summary_layer(sll2_summary_layers, "frame");
        PFL_REQUIRE(ethernet_frame_layer != nullptr);
        PFL_REQUIRE(sll2_frame_layer != nullptr);
        PFL_EXPECT(require_summary_field_value(*ethernet_frame_layer, "Encapsulation Type") == "Ethernet");
        PFL_EXPECT(require_summary_field_value(*sll2_frame_layer, "Encapsulation Type") == "Linux cooked capture v2");
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

