#include <algorithm>
#include <array>
#include <cctype>
#include <cstddef>
#include <filesystem>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "TestSupport.h"
#include "PcapTestUtils.h"
#include "app/session/CaptureSession.h"
#include "app/session/SessionFormatting.h"
#include "app/session/SessionQuicPresentation.h"
#include "app/session/SessionTlsPresentation.h"
#include "core/services/HexDumpService.h"
#include "core/services/PacketPayloadService.h"

namespace pfl::tests {

namespace {

void append_be16(std::vector<std::uint8_t>& bytes, const std::uint16_t value) {
    bytes.push_back(static_cast<std::uint8_t>((value >> 8U) & 0xFFU));
    bytes.push_back(static_cast<std::uint8_t>(value & 0xFFU));
}

void append_be24(std::vector<std::uint8_t>& bytes, const std::uint32_t value) {
    bytes.push_back(static_cast<std::uint8_t>((value >> 16U) & 0xFFU));
    bytes.push_back(static_cast<std::uint8_t>((value >> 8U) & 0xFFU));
    bytes.push_back(static_cast<std::uint8_t>(value & 0xFFU));
}

std::vector<std::uint8_t> make_tls_record(
    const std::uint8_t content_type,
    const std::uint16_t version,
    const std::vector<std::uint8_t>& body
) {
    std::vector<std::uint8_t> record {};
    record.reserve(5U + body.size());
    record.push_back(content_type);
    append_be16(record, version);
    append_be16(record, static_cast<std::uint16_t>(body.size()));
    record.insert(record.end(), body.begin(), body.end());
    return record;
}

std::vector<std::uint8_t> make_tls_handshake_record(
    const std::uint8_t handshake_type,
    const std::vector<std::uint8_t>& body = {},
    const std::uint16_t version = 0x0303U
) {
    std::vector<std::uint8_t> handshake {};
    handshake.reserve(4U + body.size());
    handshake.push_back(handshake_type);
    append_be24(handshake, static_cast<std::uint32_t>(body.size()));
    handshake.insert(handshake.end(), body.begin(), body.end());
    return make_tls_record(0x16U, version, handshake);
}

std::vector<std::uint8_t> make_tls_change_cipher_spec_record(const std::uint16_t version = 0x0303U) {
    return make_tls_record(0x14U, version, std::vector<std::uint8_t> {0x01U});
}

std::vector<std::uint8_t> make_tls_alert_record(
    const std::uint8_t level = 0x01U,
    const std::uint8_t description = 0x00U,
    const std::uint16_t version = 0x0303U
) {
    return make_tls_record(0x15U, version, std::vector<std::uint8_t> {level, description});
}

std::vector<std::uint8_t> concat_bytes(
    const std::vector<std::uint8_t>& first,
    const std::vector<std::uint8_t>& second
) {
    std::vector<std::uint8_t> combined {};
    combined.reserve(first.size() + second.size());
    combined.insert(combined.end(), first.begin(), first.end());
    combined.insert(combined.end(), second.begin(), second.end());
    return combined;
}

std::vector<std::uint8_t> make_text_bytes(const std::string_view text) {
    return std::vector<std::uint8_t>(text.begin(), text.end());
}

void append_quic_varint(std::vector<std::uint8_t>& bytes, const std::uint64_t value) {
    if (value < 64U) {
        bytes.push_back(static_cast<std::uint8_t>(value));
        return;
    }

    PFL_EXPECT(value < 16384U);
    bytes.push_back(static_cast<std::uint8_t>(0x40U | ((value >> 8U) & 0x3FU)));
    bytes.push_back(static_cast<std::uint8_t>(value & 0xFFU));
}

std::vector<std::uint8_t> make_plaintext_quic_initial_payload(const std::vector<std::uint8_t>& frame_bytes) {
    std::vector<std::uint8_t> payload {
        0xC0U,
        0x00U, 0x00U, 0x00U, 0x01U,
        0x08U,
        0x11U, 0x22U, 0x33U, 0x44U, 0x55U, 0x66U, 0x77U, 0x88U,
        0x08U,
        0x99U, 0xAAU, 0xBBU, 0xCCU, 0xDDU, 0xEEU, 0xFFU, 0x00U,
        0x00U,
    };

    append_quic_varint(payload, frame_bytes.size() + 1U);
    payload.push_back(0x00U);
    payload.insert(payload.end(), frame_bytes.begin(), frame_bytes.end());
    return payload;
}

std::vector<std::uint8_t> make_quic_crypto_frame_bytes(const std::vector<std::uint8_t>& crypto_bytes) {
    std::vector<std::uint8_t> frame {0x06U, 0x00U};
    append_quic_varint(frame, crypto_bytes.size());
    frame.insert(frame.end(), crypto_bytes.begin(), crypto_bytes.end());
    return frame;
}

std::vector<std::uint8_t> make_quic_crypto_frame_bytes(
    const std::uint64_t crypto_offset,
    const std::vector<std::uint8_t>& crypto_bytes
) {
    std::vector<std::uint8_t> frame {0x06U};
    append_quic_varint(frame, crypto_offset);
    append_quic_varint(frame, crypto_bytes.size());
    frame.insert(frame.end(), crypto_bytes.begin(), crypto_bytes.end());
    return frame;
}

std::vector<std::uint8_t> make_quic_crypto_frame_bytes() {
    return make_quic_crypto_frame_bytes(std::vector<std::uint8_t> {'a', 'b', 'c'});
}

std::vector<std::uint8_t> make_tls_client_hello_handshake_bytes() {
    const std::vector<std::uint8_t> server_name {'s', 't', 'a', 'g', 'e', '1', '.', 'e', 'x', 'a', 'm', 'p', 'l', 'e'};

    std::vector<std::uint8_t> sni_extension_data {};
    append_be16(sni_extension_data, static_cast<std::uint16_t>(server_name.size() + 3U));
    sni_extension_data.push_back(0x00U);
    append_be16(sni_extension_data, static_cast<std::uint16_t>(server_name.size()));
    sni_extension_data.insert(sni_extension_data.end(), server_name.begin(), server_name.end());

    std::vector<std::uint8_t> supported_versions_extension_data {0x02U, 0x03U, 0x04U};

    std::vector<std::uint8_t> extensions {};
    append_be16(extensions, 0x0000U);
    append_be16(extensions, static_cast<std::uint16_t>(sni_extension_data.size()));
    extensions.insert(extensions.end(), sni_extension_data.begin(), sni_extension_data.end());
    append_be16(extensions, 0x002BU);
    append_be16(extensions, static_cast<std::uint16_t>(supported_versions_extension_data.size()));
    extensions.insert(extensions.end(), supported_versions_extension_data.begin(), supported_versions_extension_data.end());

    std::vector<std::uint8_t> body {};
    body.push_back(0x03U);
    body.push_back(0x03U);
    for (std::uint8_t index = 0U; index < 32U; ++index) {
        body.push_back(static_cast<std::uint8_t>(0x20U + index));
    }
    body.push_back(0x00U);
    append_be16(body, 0x0002U);
    append_be16(body, 0x1301U);
    body.push_back(0x01U);
    body.push_back(0x00U);
    append_be16(body, static_cast<std::uint16_t>(extensions.size()));
    body.insert(body.end(), extensions.begin(), extensions.end());

    std::vector<std::uint8_t> handshake {0x01U};
    append_be24(handshake, static_cast<std::uint32_t>(body.size()));
    handshake.insert(handshake.end(), body.begin(), body.end());
    return handshake;
}

std::vector<std::uint8_t> make_quic_ack_frame_bytes() {
    return {0x02U, 0x00U, 0x00U, 0x00U, 0x00U};
}

std::vector<std::uint8_t> make_quic_padding_frame_bytes(const std::size_t count = 1U) {
    return std::vector<std::uint8_t>(count, 0x00U);
}

std::vector<std::uint8_t> make_quic_ping_frame_bytes() {
    return {0x01U};
}

std::vector<std::uint8_t> make_quic_truncated_payload() {
    return {
        0xC0U,
        0x00U, 0x00U, 0x00U, 0x01U,
        0x08U,
        0x11U, 0x22U, 0x33U, 0x44U,
    };
}

std::vector<std::uint8_t> make_quic_short_header_like_payload(
    const std::vector<std::uint8_t>& payload = std::vector<std::uint8_t> {0x01U, 0x02U, 0x03U}
) {
    std::vector<std::uint8_t> bytes {0x40U};
    bytes.insert(bytes.end(), payload.begin(), payload.end());
    return bytes;
}

std::vector<std::uint8_t> make_quic_retry_like_payload() {
    std::vector<std::uint8_t> payload {
        0xF0U,
        0x00U, 0x00U, 0x00U, 0x01U,
        0x08U,
        0x11U, 0x22U, 0x33U, 0x44U, 0x55U, 0x66U, 0x77U, 0x88U,
        0x08U,
        0x99U, 0xAAU, 0xBBU, 0xCCU, 0xDDU, 0xEEU, 0xFFU, 0x00U,
    };
    payload.insert(payload.end(), 16U, 0xABU);
    return payload;
}

std::vector<std::uint8_t> make_tls_server_hello_handshake_bytes() {
    std::vector<std::uint8_t> body {};
    append_be16(body, 0x0303U);
    for (std::uint8_t index = 0U; index < 32U; ++index) {
        body.push_back(static_cast<std::uint8_t>(0xA0U + index));
    }
    body.push_back(0x00U);
    append_be16(body, 0x1301U);
    body.push_back(0x00U);

    std::vector<std::uint8_t> extensions {};
    append_be16(extensions, 0x002BU);
    append_be16(extensions, 0x0002U);
    extensions.push_back(0x03U);
    extensions.push_back(0x04U);

    append_be16(body, static_cast<std::uint16_t>(extensions.size()));
    body.insert(body.end(), extensions.begin(), extensions.end());

    std::vector<std::uint8_t> handshake {0x02U};
    append_be24(handshake, static_cast<std::uint32_t>(body.size()));
    handshake.insert(handshake.end(), body.begin(), body.end());
    return handshake;
}

std::string direction_for_packet(const std::vector<PacketRow>& packet_rows, const std::uint64_t packet_index) {
    for (const auto& row : packet_rows) {
        if (row.packet_index == packet_index) {
            return row.direction_text;
        }
    }

    PFL_EXPECT(false);
    return {};
}

std::filesystem::path fixture_path(const std::filesystem::path& relative_path) {
    return std::filesystem::path(__FILE__).parent_path().parent_path() / "data" / relative_path;
}

bool starts_with(const std::string_view value, const std::string_view prefix) {
    return value.rfind(prefix, 0U) == 0U;
}

std::string_view trim_ascii(std::string_view text) {
    while (!text.empty() && (text.front() == ' ' || text.front() == '\t' || text.front() == '\r')) {
        text.remove_prefix(1U);
    }
    while (!text.empty() && (text.back() == ' ' || text.back() == '\t' || text.back() == '\r')) {
        text.remove_suffix(1U);
    }
    return text;
}

std::optional<std::string_view> find_protocol_detail_value(
    const std::string_view protocol_text,
    const std::string_view label_with_colon
) {
    std::size_t line_start = 0U;
    while (line_start <= protocol_text.size()) {
        const auto line_end = protocol_text.find('\n', line_start);
        const auto raw_line = protocol_text.substr(
            line_start,
            line_end == std::string_view::npos ? protocol_text.size() - line_start : line_end - line_start
        );
        const auto line = trim_ascii(raw_line);
        if (line.starts_with(label_with_colon)) {
            return trim_ascii(line.substr(label_with_colon.size()));
        }
        if (line_end == std::string_view::npos) {
            break;
        }
        line_start = line_end + 1U;
    }
    return std::nullopt;
}

void expect_matching_protocol_detail(
    const std::string_view packet_protocol_text,
    const std::string_view stream_protocol_text,
    const std::string_view label_with_colon
) {
    const auto packet_value = find_protocol_detail_value(packet_protocol_text, label_with_colon);
    const auto stream_value = find_protocol_detail_value(stream_protocol_text, label_with_colon);
    PFL_REQUIRE(packet_value.has_value());
    PFL_REQUIRE(stream_value.has_value());
    PFL_EXPECT(*packet_value == *stream_value);
}

const StreamItemRow* find_stream_row_by_label(const std::vector<StreamItemRow>& rows, const std::string_view label) {
    const auto it = std::find_if(rows.begin(), rows.end(), [&](const StreamItemRow& row) {
        return row.label == label;
    });
    return it == rows.end() ? nullptr : &(*it);
}

void expect_matching_stream_row_prefix(
    const std::vector<StreamItemRow>& actual,
    const std::vector<StreamItemRow>& expected,
    const std::size_t count
) {
    PFL_EXPECT(actual.size() == count);
    PFL_EXPECT(expected.size() >= count);
    for (std::size_t index = 0U; index < count; ++index) {
        PFL_EXPECT(actual[index].stream_item_index == expected[index].stream_item_index);
        PFL_EXPECT(actual[index].direction_text == expected[index].direction_text);
        PFL_EXPECT(actual[index].label == expected[index].label);
        PFL_EXPECT(actual[index].byte_count == expected[index].byte_count);
        PFL_EXPECT(actual[index].packet_count == expected[index].packet_count);
        PFL_EXPECT(actual[index].packet_indices == expected[index].packet_indices);
        PFL_EXPECT(actual[index].has_constricted_contribution == expected[index].has_constricted_contribution);
        PFL_EXPECT(actual[index].constricted_contribution_notes == expected[index].constricted_contribution_notes);
        PFL_EXPECT(actual[index].constricted_packet_notes == expected[index].constricted_packet_notes);
        PFL_EXPECT(actual[index].summary_text == expected[index].summary_text);
        PFL_EXPECT(actual[index].payload_hex_text == expected[index].payload_hex_text);
        PFL_EXPECT(actual[index].protocol_text == expected[index].protocol_text);
        PFL_EXPECT(actual[index].tls_semantic_kind == expected[index].tls_semantic_kind);
    }
}

void expect_exact_stream_rows(
    const std::vector<StreamItemRow>& actual,
    const std::vector<StreamItemRow>& expected
) {
    PFL_EXPECT(actual.size() == expected.size());
    expect_matching_stream_row_prefix(actual, expected, expected.size());
}

std::vector<StreamItemRow> query_bounded_stream_rows_fresh(
    const std::filesystem::path& capture_path,
    const CaptureImportOptions& options,
    const std::size_t flow_index,
    const std::size_t packet_budget,
    const std::size_t item_limit
) {
    CaptureSession fresh_session {};
    PFL_EXPECT(fresh_session.open_capture(capture_path, options));
    return fresh_session.list_flow_stream_items_for_packet_prefix(flow_index, packet_budget, item_limit);
}

std::size_t count_stream_rows_by_label(const std::vector<StreamItemRow>& rows, const std::string_view label) {
    return static_cast<std::size_t>(std::count_if(rows.begin(), rows.end(), [&](const StreamItemRow& row) {
        return row.label == label;
    }));
}

std::map<std::uint64_t, std::uint64_t> build_flow_packet_numbers(const std::vector<PacketRow>& packet_rows) {
    std::map<std::uint64_t, std::uint64_t> flow_packet_numbers {};
    for (const auto& row : packet_rows) {
        flow_packet_numbers.emplace(row.packet_index, row.row_number);
    }
    return flow_packet_numbers;
}

std::string format_stream_source_packets_text_for_test(
    const StreamItemRow& row,
    const std::map<std::uint64_t, std::uint64_t>& flow_packet_numbers
) {
    std::vector<std::string> packet_numbers {};
    packet_numbers.reserve(row.packet_indices.size());
    bool used_flow_numbers = true;
    for (const auto packet_index : row.packet_indices) {
        const auto flow_it = flow_packet_numbers.find(packet_index);
        if (flow_it == flow_packet_numbers.end()) {
            used_flow_numbers = false;
            break;
        }
        packet_numbers.push_back("#" + std::to_string(flow_it->second));
    }

    if (!used_flow_numbers) {
        packet_numbers.clear();
        packet_numbers.reserve(row.packet_indices.size());
        for (const auto packet_index : row.packet_indices) {
            packet_numbers.push_back("#" + std::to_string(packet_index));
        }
    }

    if (packet_numbers.empty()) {
        return row.packet_count == 1U
            ? "1 packet"
            : std::to_string(row.packet_count) + " packets";
    }

    std::ostringstream out {};
    out << (packet_numbers.size() == 1U ? "packet " : "packets ");
    for (std::size_t index = 0U; index < packet_numbers.size(); ++index) {
        if (index != 0U) {
            out << ',';
        }
        out << packet_numbers[index];
    }
    return out.str();
}

bool stream_item_uses_packet_fallback_for_test(const StreamItemRow& row) {
    return row.payload_hex_text.empty() && row.protocol_text.empty() && row.packet_indices.size() == 1U;
}

std::string stream_item_frames_hint_text_for_test(const StreamItemRow& row) {
    if (row.protocol_text.empty()) {
        return {};
    }

    std::vector<std::string> hints {};
    const auto extract_line_value = [&](const std::string& marker) -> std::string {
        const auto marker_index = row.protocol_text.find(marker);
        if (marker_index == std::string::npos) {
            return {};
        }

        const auto line_start = marker_index + marker.size();
        const auto line_end = row.protocol_text.find('\n', line_start);
        auto value = row.protocol_text.substr(
            line_start,
            line_end == std::string::npos ? std::string::npos : (line_end - line_start)
        );
        while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front())) != 0) {
            value.erase(value.begin());
        }
        while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back())) != 0) {
            value.pop_back();
        }
        return value;
    };

    const auto append_normalized_values = [&](const std::string& value) {
        std::stringstream stream {value};
        std::string part {};
        while (std::getline(stream, part, ',')) {
            while (!part.empty() && std::isspace(static_cast<unsigned char>(part.front())) != 0) {
                part.erase(part.begin());
            }
            while (!part.empty() && std::isspace(static_cast<unsigned char>(part.back())) != 0) {
                part.pop_back();
            }
            if (part == "Protected Payload") {
                part = "Protected payload";
            }
            if (part.empty() || part == "Packet Type: Initial" || part == "Initial") {
                continue;
            }
            if (std::find(hints.begin(), hints.end(), part) == hints.end()) {
                hints.push_back(part);
            }
        }
    };

    append_normalized_values(extract_line_value("Frame Presence:"));
    append_normalized_values(extract_line_value("Packet Type:"));
    append_normalized_values(extract_line_value("Additional Packet Types:"));

    if (hints.empty()) {
        return {};
    }

    std::ostringstream out {};
    out << "Frames: ";
    for (std::size_t index = 0U; index < hints.size(); ++index) {
        if (index != 0U) {
            out << ", ";
        }
        out << hints[index];
    }
    return out.str();
}

std::vector<session_detail::PacketSummaryLayer> build_stream_summary_layers(
    const StreamItemRow& row,
    const std::vector<PacketRow>& packet_rows
) {
    return session_detail::build_stream_item_summary_layers(
        row,
        format_stream_source_packets_text_for_test(row, build_flow_packet_numbers(packet_rows)),
        stream_item_uses_packet_fallback_for_test(row) ? "Packet fallback" : "Stream item",
        stream_item_frames_hint_text_for_test(row)
    );
}

std::vector<session_detail::PacketSummaryLayer> build_packet_summary_layers_for_packet(
    CaptureSession& session,
    const PacketRef& packet
) {
    const auto details = session.read_packet_details(packet);
    PFL_REQUIRE(details.has_value());
    const auto packet_bytes = session.read_packet_data(packet);
    PacketPayloadService payload_service {};
    const auto transport_payload = payload_service.extract_transport_payload(packet_bytes, packet.data_link_type);
    return session_detail::build_packet_summary_layers(
        *details,
        packet,
        {
            .transport_payload_bytes = std::span<const std::uint8_t>(transport_payload.data(), transport_payload.size()),
        }
    );
}

const session_detail::PacketSummaryLayer* find_top_level_summary_layer(
    const std::vector<session_detail::PacketSummaryLayer>& layers,
    const std::string_view id,
    const std::size_t occurrence = 0U
) {
    std::size_t current = 0U;
    for (const auto& layer : layers) {
        if (layer.id != id) {
            continue;
        }
        if (current == occurrence) {
            return &layer;
        }
        ++current;
    }
    return nullptr;
}

std::vector<const session_detail::PacketSummaryLayer*> find_top_level_summary_layers(
    const std::vector<session_detail::PacketSummaryLayer>& layers,
    const std::string_view id
) {
    std::vector<const session_detail::PacketSummaryLayer*> matches {};
    for (const auto& layer : layers) {
        if (layer.id == id) {
            matches.push_back(&layer);
        }
    }
    return matches;
}

const session_detail::PacketSummaryField* find_summary_field(
    const session_detail::PacketSummaryLayer& layer,
    const std::string_view label
) {
    const auto it = std::find_if(layer.fields.begin(), layer.fields.end(), [&](const session_detail::PacketSummaryField& field) {
        return field.label == label;
    });
    return it == layer.fields.end() ? nullptr : &(*it);
}

std::string require_summary_field_value(
    const session_detail::PacketSummaryLayer& layer,
    const std::string_view label
) {
    const auto* field = find_summary_field(layer, label);
    PFL_REQUIRE(field != nullptr);
    return field->value;
}

const session_detail::PacketSummaryLayer* find_summary_child(
    const session_detail::PacketSummaryLayer& layer,
    const std::string_view id,
    const std::size_t occurrence = 0U
) {
    std::size_t current = 0U;
    for (const auto& child : layer.children) {
        if (child.id != id) {
            continue;
        }
        if (current == occurrence) {
            return &child;
        }
        ++current;
    }
    return nullptr;
}

const session_detail::PacketSummaryLayer* require_summary_child(
    const session_detail::PacketSummaryLayer& layer,
    const std::string_view id,
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

void expect_summary_layer_semantic_match(
    const session_detail::PacketSummaryLayer& actual,
    const session_detail::PacketSummaryLayer& expected
) {
    PFL_EXPECT(actual.id == expected.id);
    PFL_EXPECT(actual.title == expected.title);
    PFL_EXPECT(actual.fields.size() == expected.fields.size());
    if (actual.fields.size() == expected.fields.size()) {
        for (std::size_t index = 0U; index < actual.fields.size(); ++index) {
            PFL_EXPECT(actual.fields[index].label == expected.fields[index].label);
            PFL_EXPECT(actual.fields[index].value == expected.fields[index].value);
        }
    }

    PFL_EXPECT(actual.children.size() == expected.children.size());
    if (actual.children.size() == expected.children.size()) {
        for (std::size_t index = 0U; index < actual.children.size(); ++index) {
            expect_summary_layer_semantic_match(actual.children[index], expected.children[index]);
        }
    }
}

}  // namespace

void run_stream_query_tests() {
    const auto forward_payload = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
        ipv4(10, 40, 0, 1), ipv4(10, 40, 0, 2), 51000, 443, std::vector<std::uint8_t> {'A', 'B', 'C'}, 0x18);
    const auto reverse_ack = make_ethernet_ipv4_tcp_packet(
        ipv4(10, 40, 0, 2), ipv4(10, 40, 0, 1), 443, 51000);
    const auto reverse_payload = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
        ipv4(10, 40, 0, 2), ipv4(10, 40, 0, 1), 443, 51000, std::vector<std::uint8_t> {'O', 'K'}, 0x18);

    const auto path = write_temp_pcap(
        "pfl_stream_query.pcap",
        make_classic_pcap({
            {100, forward_payload},
            {200, reverse_ack},
            {300, reverse_payload},
        })
    );

    CaptureSession session {};
    PFL_EXPECT(session.open_capture(path));

    const auto packet_rows = session.list_flow_packets(0);
    PFL_EXPECT(packet_rows.size() == 3);

    const auto stream_rows = session.list_flow_stream_items(0);
    PFL_EXPECT(stream_rows.size() == 2);
    PFL_EXPECT(stream_rows[0].stream_item_index == 1);
    PFL_EXPECT(stream_rows[1].stream_item_index == 2);
    PFL_EXPECT(stream_rows[0].packet_indices == std::vector<std::uint64_t> {0});
    PFL_EXPECT(stream_rows[1].packet_indices == std::vector<std::uint64_t> {2});
    PFL_EXPECT(stream_rows[0].direction_text == direction_for_packet(packet_rows, 0));
    PFL_EXPECT(stream_rows[1].direction_text == direction_for_packet(packet_rows, 2));
    PFL_EXPECT(stream_rows[0].byte_count == 3);
    PFL_EXPECT(stream_rows[1].byte_count == 2);
    PFL_EXPECT(stream_rows[0].packet_count == 1);
    PFL_EXPECT(stream_rows[1].packet_count == 1);
    PFL_EXPECT(stream_rows[0].label == "TCP Payload");
    PFL_EXPECT(stream_rows[1].label == "TCP Payload");

    const auto duplicate_segment_packet_a = make_ethernet_ipv4_tcp_packet_with_bytes_payload_and_sequence(
        ipv4(10, 40, 1, 1), ipv4(10, 40, 1, 2), 51001, 443, std::vector<std::uint8_t> {'D', 'U', 'P'}, 1000U, 2000U, 0x18);
    const auto duplicate_segment_packet_b = make_ethernet_ipv4_tcp_packet_with_bytes_payload_and_sequence(
        ipv4(10, 40, 1, 1), ipv4(10, 40, 1, 2), 51001, 443, std::vector<std::uint8_t> {'D', 'U', 'P'}, 1000U, 2000U, 0x18);
    const auto duplicate_segment_path = write_temp_pcap(
        "pfl_stream_query_duplicate_segment.pcap",
        make_classic_pcap({
            {100, duplicate_segment_packet_a},
            {200, duplicate_segment_packet_b},
        })
    );

    CaptureSession duplicate_segment_session {};
    PFL_EXPECT(duplicate_segment_session.open_capture(duplicate_segment_path));
    const auto duplicate_packet_rows = duplicate_segment_session.list_flow_packets(0);
    PFL_EXPECT(duplicate_packet_rows.size() == 2U);
    const auto duplicate_suppressed_packet_indices = duplicate_segment_session.suspected_tcp_retransmission_packet_indices(0);
    PFL_EXPECT(duplicate_suppressed_packet_indices == std::vector<std::uint64_t> {1U});
    duplicate_segment_session.set_selected_flow_tcp_payload_suppression(0U, duplicate_suppressed_packet_indices);
    const auto duplicate_segment_rows = duplicate_segment_session.list_flow_stream_items(0);
    PFL_EXPECT(duplicate_segment_rows.size() == 1U);
    PFL_EXPECT(duplicate_segment_rows[0].label == "TCP Payload");
    PFL_EXPECT(duplicate_segment_rows[0].packet_count == 1U);
    PFL_EXPECT(duplicate_segment_rows[0].packet_indices == std::vector<std::uint64_t> {0U});

    const auto similar_segment_packet_a = make_ethernet_ipv4_tcp_packet_with_bytes_payload_and_sequence(
        ipv4(10, 40, 2, 1), ipv4(10, 40, 2, 2), 51002, 443, std::vector<std::uint8_t> {'A', 'A', 'A'}, 1000U, 2000U, 0x18);
    const auto similar_segment_packet_b = make_ethernet_ipv4_tcp_packet_with_bytes_payload_and_sequence(
        ipv4(10, 40, 2, 1), ipv4(10, 40, 2, 2), 51002, 443, std::vector<std::uint8_t> {'B', 'B', 'B'}, 1000U, 2000U, 0x18);
    const auto similar_segment_path = write_temp_pcap(
        "pfl_stream_query_similar_segment.pcap",
        make_classic_pcap({
            {100, similar_segment_packet_a},
            {200, similar_segment_packet_b},
        })
    );

    CaptureSession similar_segment_session {};
    PFL_EXPECT(similar_segment_session.open_capture(similar_segment_path));
    const auto similar_suppressed_packet_indices = similar_segment_session.suspected_tcp_retransmission_packet_indices(0);
    PFL_EXPECT(similar_suppressed_packet_indices.empty());
    similar_segment_session.set_selected_flow_tcp_payload_suppression(0U, similar_suppressed_packet_indices);
    const auto similar_segment_rows = similar_segment_session.list_flow_stream_items(0);
    PFL_EXPECT(similar_segment_rows.size() == 2U);
    PFL_EXPECT(similar_segment_rows[0].packet_indices == std::vector<std::uint64_t> {0U});
    PFL_EXPECT(similar_segment_rows[1].packet_indices == std::vector<std::uint64_t> {1U});

    const auto partial_overlap_packet_a = make_ethernet_ipv4_tcp_packet_with_bytes_payload_and_sequence(
        ipv4(10, 40, 3, 1), ipv4(10, 40, 3, 2), 51003, 443, std::vector<std::uint8_t> {'A', 'B', 'C', 'D', 'E'}, 1000U, 2000U, 0x18);
    const auto partial_overlap_packet_b = make_ethernet_ipv4_tcp_packet_with_bytes_payload_and_sequence(
        ipv4(10, 40, 3, 1), ipv4(10, 40, 3, 2), 51003, 443, std::vector<std::uint8_t> {'C', 'D', 'E', 'F', 'G'}, 1002U, 2000U, 0x18);
    const auto partial_overlap_path = write_temp_pcap(
        "pfl_stream_query_partial_overlap_segment.pcap",
        make_classic_pcap({
            {100, partial_overlap_packet_a},
            {200, partial_overlap_packet_b},
        })
    );

    CaptureSession partial_overlap_session {};
    PFL_EXPECT(partial_overlap_session.open_capture(partial_overlap_path));
    const auto partial_overlap_suppressed_packet_indices = partial_overlap_session.suspected_tcp_retransmission_packet_indices(0);
    PFL_EXPECT(partial_overlap_suppressed_packet_indices.empty());
    partial_overlap_session.set_selected_flow_tcp_payload_suppression(0U, partial_overlap_suppressed_packet_indices);
    const auto partial_overlap_rows = partial_overlap_session.list_flow_stream_items(0);
    PFL_EXPECT(partial_overlap_rows.size() == 2U);
    PFL_EXPECT(partial_overlap_rows[0].label == "TCP Payload");
    PFL_EXPECT(partial_overlap_rows[0].byte_count == 5U);
    PFL_EXPECT(partial_overlap_rows[0].packet_indices == std::vector<std::uint64_t> {0U});
    PFL_EXPECT(partial_overlap_rows[1].label == "TCP Payload");
    PFL_EXPECT(partial_overlap_rows[1].byte_count == 2U);
    PFL_EXPECT(partial_overlap_rows[1].packet_indices == std::vector<std::uint64_t> {1U});

    const auto dns_payload = std::vector<std::uint8_t> {
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x03, 'a', 'p', 'i',
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x00,
        0x00, 0x01, 0x00, 0x01,
    };
    const auto dns_packet = make_ethernet_ipv4_udp_packet_with_bytes_payload(
        ipv4(10, 41, 0, 1), ipv4(10, 41, 0, 2), 53000, 53, dns_payload);
    const auto dns_path = write_temp_pcap(
        "pfl_stream_query_dns.pcap",
        make_classic_pcap({{100, dns_packet}})
    );

    CaptureSession dns_session {};
    PFL_EXPECT(dns_session.open_capture(dns_path));
    const auto dns_rows = dns_session.list_flow_stream_items(0);
    PFL_EXPECT(dns_rows.size() == 1);
    PFL_EXPECT(dns_rows[0].label == "DNS Query");
    PFL_EXPECT(dns_rows[0].byte_count == dns_payload.size());

    const auto server_hello_record = make_tls_handshake_record(0x02U, {0xAA, 0xBB, 0xCC, 0xDD});
    const auto change_cipher_spec_record = make_tls_change_cipher_spec_record();
    const auto tls_multi_payload = concat_bytes(server_hello_record, change_cipher_spec_record);
    const auto tls_multi_packet = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
        ipv4(10, 42, 0, 1), ipv4(10, 42, 0, 2), 443, 52000, tls_multi_payload, 0x18);
    const auto tls_multi_path = write_temp_pcap(
        "pfl_stream_query_tls_multi.pcap",
        make_classic_pcap({{100, tls_multi_packet}})
    );

    CaptureSession tls_multi_session {};
    CaptureImportOptions fast_options {};

    constexpr std::string_view split_http_request_text =
        "GET /split HTTP/1.1\r\n"
        "Host: split.example\r\n"
        "User-Agent: test\r\n"
        "\r\n";
    const auto split_http_request = make_text_bytes(split_http_request_text);
    const auto split_http_request_a = std::vector<std::uint8_t>(
        split_http_request.begin(),
        split_http_request.begin() + 18
    );
    const auto split_http_request_b = std::vector<std::uint8_t>(
        split_http_request.begin() + 18,
        split_http_request.end()
    );
    const auto split_http_request_packet_a = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
        ipv4(10, 41, 1, 1), ipv4(10, 41, 1, 2), 53010, 80, split_http_request_a, 0x18);
    const auto split_http_request_packet_b = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
        ipv4(10, 41, 1, 1), ipv4(10, 41, 1, 2), 53010, 80, split_http_request_b, 0x18);
    const auto split_http_request_path = write_temp_pcap(
        "pfl_stream_query_http_split_request.pcap",
        make_classic_pcap({
            {100, split_http_request_packet_a},
            {200, split_http_request_packet_b},
        })
    );

    CaptureSession split_http_request_session {};
    PFL_EXPECT(split_http_request_session.open_capture(split_http_request_path, fast_options));
    const auto split_http_request_rows = split_http_request_session.list_flow_stream_items(0);
    PFL_EXPECT(split_http_request_rows.size() == 1);
    PFL_EXPECT(split_http_request_rows[0].label == "HTTP GET /split");
    PFL_EXPECT(split_http_request_rows[0].byte_count == split_http_request.size());
    PFL_EXPECT(split_http_request_rows[0].packet_count == 2);
    const auto expected_http_split_packet_indices = std::vector<std::uint64_t> {0, 1};
    PFL_EXPECT(split_http_request_rows[0].packet_indices == expected_http_split_packet_indices);
    PFL_EXPECT(split_http_request_rows[0].protocol_text.find("Method: GET") != std::string::npos);
    PFL_EXPECT(split_http_request_rows[0].protocol_text.find("Path: /split") != std::string::npos);
    PFL_EXPECT(split_http_request_rows[0].protocol_text.find("Host: split.example") != std::string::npos);

    constexpr std::string_view split_http_response_text =
        "HTTP/1.1 200 OK\r\n"
        "Server: test\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Length: 5\r\n"
        "\r\n";
    const auto split_http_response = make_text_bytes(split_http_response_text);
    const auto split_http_response_a = std::vector<std::uint8_t>(
        split_http_response.begin(),
        split_http_response.begin() + 12
    );
    const auto split_http_response_b = std::vector<std::uint8_t>(
        split_http_response.begin() + 12,
        split_http_response.end()
    );
    const auto split_http_response_packet_a = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
        ipv4(10, 41, 2, 2), ipv4(10, 41, 2, 1), 80, 53011, split_http_response_a, 0x18);
    const auto split_http_response_packet_b = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
        ipv4(10, 41, 2, 2), ipv4(10, 41, 2, 1), 80, 53011, split_http_response_b, 0x18);
    const auto split_http_response_path = write_temp_pcap(
        "pfl_stream_query_http_split_response.pcap",
        make_classic_pcap({
            {100, split_http_response_packet_a},
            {200, split_http_response_packet_b},
        })
    );

    CaptureSession split_http_response_session {};
    PFL_EXPECT(split_http_response_session.open_capture(split_http_response_path, fast_options));
    const auto split_http_response_rows = split_http_response_session.list_flow_stream_items(0);
    PFL_EXPECT(split_http_response_rows.size() == 1);
    PFL_EXPECT(split_http_response_rows[0].label == "HTTP 200 OK");
    PFL_EXPECT(split_http_response_rows[0].byte_count == split_http_response.size());
    PFL_EXPECT(split_http_response_rows[0].packet_count == 2);
    PFL_EXPECT(split_http_response_rows[0].packet_indices == expected_http_split_packet_indices);
    PFL_EXPECT(split_http_response_rows[0].protocol_text.find("Status Code: 200") != std::string::npos);
    PFL_EXPECT(split_http_response_rows[0].protocol_text.find("Reason: OK") != std::string::npos);
    PFL_EXPECT(split_http_response_rows[0].protocol_text.find("Content-Type: text/plain") != std::string::npos);
    PFL_EXPECT(split_http_response_rows[0].protocol_text.find("Content-Length: 5") != std::string::npos);

    constexpr std::string_view http_request_one_text =
        "GET /one HTTP/1.1\r\n"
        "Host: one.example\r\n"
        "\r\n";
    constexpr std::string_view http_request_two_text =
        "GET /two HTTP/1.1\r\n"
        "Host: two.example\r\n"
        "\r\n";
    const auto http_request_one = make_text_bytes(http_request_one_text);
    const auto http_request_two = make_text_bytes(http_request_two_text);
    const auto http_multi_payload = concat_bytes(http_request_one, http_request_two);
    const auto http_multi_split = static_cast<std::ptrdiff_t>(http_request_one.size() + 10U);
    const auto http_multi_payload_a = std::vector<std::uint8_t>(
        http_multi_payload.begin(),
        http_multi_payload.begin() + http_multi_split
    );
    const auto http_multi_payload_b = std::vector<std::uint8_t>(
        http_multi_payload.begin() + http_multi_split,
        http_multi_payload.end()
    );
    const auto http_multi_packet_a = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
        ipv4(10, 41, 3, 1), ipv4(10, 41, 3, 2), 53012, 80, http_multi_payload_a, 0x18);
    const auto http_multi_packet_b = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
        ipv4(10, 41, 3, 1), ipv4(10, 41, 3, 2), 53012, 80, http_multi_payload_b, 0x18);
    const auto http_multi_path = write_temp_pcap(
        "pfl_stream_query_http_multi_headers.pcap",
        make_classic_pcap({
            {100, http_multi_packet_a},
            {200, http_multi_packet_b},
        })
    );

    CaptureSession http_multi_session {};
    PFL_EXPECT(http_multi_session.open_capture(http_multi_path, fast_options));
    const auto http_multi_rows = http_multi_session.list_flow_stream_items(0);
    PFL_EXPECT(http_multi_rows.size() == 2);
    PFL_EXPECT(http_multi_rows[0].label == "HTTP GET /one");
    PFL_EXPECT(http_multi_rows[1].label == "HTTP GET /two");
    PFL_EXPECT(http_multi_rows[0].byte_count == http_request_one.size());
    PFL_EXPECT(http_multi_rows[1].byte_count == http_request_two.size());
    PFL_EXPECT(http_multi_rows[0].packet_indices == std::vector<std::uint64_t> {0});
    PFL_EXPECT(http_multi_rows[1].packet_indices == expected_http_split_packet_indices);
    PFL_EXPECT(http_multi_rows[0].protocol_text.find("Path: /one") != std::string::npos);
    PFL_EXPECT(http_multi_rows[1].protocol_text.find("Path: /two") != std::string::npos);

    constexpr std::string_view http_partial_request_text =
        "GET /ok HTTP/1.1\r\n"
        "Host: ok.example\r\n"
        "\r\n"
        "GET /partial HTTP/1.1\r\n"
        "Host: partial.example\r\n";
    const auto http_partial_payload = make_text_bytes(http_partial_request_text);
    const auto http_partial_split = static_cast<std::ptrdiff_t>(39);
    const auto http_partial_payload_a = std::vector<std::uint8_t>(
        http_partial_payload.begin(),
        http_partial_payload.begin() + http_partial_split
    );
    const auto http_partial_payload_b = std::vector<std::uint8_t>(
        http_partial_payload.begin() + http_partial_split,
        http_partial_payload.end()
    );
    const auto http_partial_packet_a = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
        ipv4(10, 41, 4, 1), ipv4(10, 41, 4, 2), 53013, 80, http_partial_payload_a, 0x18);
    const auto http_partial_packet_b = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
        ipv4(10, 41, 4, 1), ipv4(10, 41, 4, 2), 53013, 80, http_partial_payload_b, 0x18);
    const auto http_partial_path = write_temp_pcap(
        "pfl_stream_query_http_partial_headers.pcap",
        make_classic_pcap({
            {100, http_partial_packet_a},
            {200, http_partial_packet_b},
        })
    );

    CaptureSession http_partial_session {};
    PFL_EXPECT(http_partial_session.open_capture(http_partial_path, fast_options));
    const auto http_partial_rows = http_partial_session.list_flow_stream_items(0);
    PFL_EXPECT(http_partial_rows.size() == 2);
    PFL_EXPECT(http_partial_rows[0].label == "HTTP GET /ok");
    PFL_EXPECT(http_partial_rows[1].label == "HTTP Payload (partial)");
    PFL_EXPECT(http_partial_rows[1].packet_indices == expected_http_split_packet_indices);
    PFL_EXPECT(http_partial_rows[1].protocol_text.find("complete HTTP header block") != std::string::npos);
    PFL_EXPECT(http_partial_rows[1].protocol_text.find("Message Type: Request") == std::string::npos);

    PFL_EXPECT(tls_multi_session.open_capture(tls_multi_path, fast_options));
    const auto tls_multi_summary_before = tls_multi_session.summary();

    const auto tls_multi_rows = tls_multi_session.list_flow_stream_items(0);
    PFL_EXPECT(tls_multi_rows.size() == 2);
    PFL_EXPECT(tls_multi_rows[0].label == "TLS ServerHello");
    PFL_EXPECT(tls_multi_rows[1].label == "TLS ChangeCipherSpec");
    PFL_EXPECT(tls_multi_rows[0].byte_count == server_hello_record.size());
    PFL_EXPECT(tls_multi_rows[1].byte_count == change_cipher_spec_record.size());
    PFL_EXPECT(tls_multi_rows[0].packet_count == 1);
    PFL_EXPECT(tls_multi_rows[1].packet_count == 1);
    PFL_EXPECT(tls_multi_rows[0].packet_indices == std::vector<std::uint64_t> {0});
    PFL_EXPECT(tls_multi_rows[1].packet_indices == std::vector<std::uint64_t> {0});
    PFL_EXPECT(tls_multi_rows[0].protocol_text.find("Handshake Type: ServerHello") != std::string::npos);
    PFL_EXPECT(tls_multi_rows[1].protocol_text.find("Record Type: ChangeCipherSpec") != std::string::npos);
    PFL_EXPECT(!tls_multi_rows[0].payload_hex_text.empty());
    PFL_EXPECT(!tls_multi_rows[1].payload_hex_text.empty());
    PFL_EXPECT(tls_multi_session.summary().packet_count == tls_multi_summary_before.packet_count);
    PFL_EXPECT(tls_multi_session.summary().flow_count == tls_multi_summary_before.flow_count);
    PFL_EXPECT(tls_multi_session.summary().total_bytes == tls_multi_summary_before.total_bytes);

    const auto tls_ccs_packet = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
        ipv4(10, 43, 0, 1), ipv4(10, 43, 0, 2), 52001, 443, make_tls_change_cipher_spec_record(), 0x18);
    const auto tls_ccs_path = write_temp_pcap(
        "pfl_stream_query_tls_ccs.pcap",
        make_classic_pcap({{100, tls_ccs_packet}})
    );

    CaptureSession tls_ccs_session {};
    PFL_EXPECT(tls_ccs_session.open_capture(tls_ccs_path, fast_options));
    const auto tls_ccs_rows = tls_ccs_session.list_flow_stream_items(0);
    PFL_EXPECT(tls_ccs_rows.size() == 1);
    PFL_EXPECT(tls_ccs_rows[0].label == "TLS ChangeCipherSpec");
    PFL_EXPECT(tls_ccs_rows[0].protocol_text.find("ChangeCipherSpec") != std::string::npos);

    const auto tls_alert_packet = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
        ipv4(10, 43, 0, 3), ipv4(10, 43, 0, 4), 52003, 443, make_tls_alert_record(), 0x18);
    const auto tls_alert_path = write_temp_pcap(
        "pfl_stream_query_tls_alert.pcap",
        make_classic_pcap({{100, tls_alert_packet}})
    );

    CaptureSession tls_alert_session {};
    PFL_EXPECT(tls_alert_session.open_capture(tls_alert_path, fast_options));
    const auto tls_alert_rows = tls_alert_session.list_flow_stream_items(0);
    PFL_EXPECT(tls_alert_rows.size() == 1U);
    PFL_EXPECT(tls_alert_rows[0].label == "TLS Alert");
    PFL_EXPECT(tls_alert_rows[0].protocol_text.find("Record Type: Alert") != std::string::npos);
    PFL_EXPECT(tls_alert_rows[0].protocol_text.find("Alert Level: Warning") != std::string::npos);
    PFL_EXPECT(tls_alert_rows[0].protocol_text.find("Alert Description: Close Notify") != std::string::npos);

    std::vector<std::uint8_t> incomplete_tls_record {
        0x17U, 0x03U, 0x03U, 0x00U, 0x04U, 0xDEU, 0xADU,
    };
    const auto tls_partial_payload = concat_bytes(server_hello_record, incomplete_tls_record);
    const auto tls_partial_packet = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
        ipv4(10, 44, 0, 1), ipv4(10, 44, 0, 2), 52002, 443, tls_partial_payload, 0x18);
    const auto tls_partial_path = write_temp_pcap(
        "pfl_stream_query_tls_partial.pcap",
        make_classic_pcap({{100, tls_partial_packet}})
    );

    CaptureSession tls_partial_session {};
    PFL_EXPECT(tls_partial_session.open_capture(tls_partial_path, fast_options));
    const auto tls_partial_rows = tls_partial_session.list_flow_stream_items(0);
    PFL_EXPECT(tls_partial_rows.size() == 2);
    PFL_EXPECT(tls_partial_rows[0].label == "TLS ServerHello");
    PFL_EXPECT(tls_partial_rows[1].label == "TLS Record Fragment (partial)");
    PFL_EXPECT(tls_partial_rows[0].byte_count == server_hello_record.size());
    PFL_EXPECT(tls_partial_rows[1].byte_count == incomplete_tls_record.size());
    PFL_EXPECT(tls_partial_rows[1].protocol_text.find("complete TLS record") != std::string::npos);
    PFL_EXPECT(tls_partial_rows[1].protocol_text.find("ServerHello") == std::string::npos);

    const auto split_server_hello_record = make_tls_handshake_record(0x02U, {0x01, 0x02, 0x03, 0x04, 0x05, 0x06});
    const auto split_packet_payload_a = std::vector<std::uint8_t>(split_server_hello_record.begin(), split_server_hello_record.begin() + 7);
    const auto split_packet_payload_b = std::vector<std::uint8_t>(split_server_hello_record.begin() + 7, split_server_hello_record.end());
    const auto split_tls_packet_a = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
        ipv4(10, 45, 0, 1), ipv4(10, 45, 0, 2), 52003, 443, split_packet_payload_a, 0x18);
    const auto split_tls_packet_b = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
        ipv4(10, 45, 0, 1), ipv4(10, 45, 0, 2), 52003, 443, split_packet_payload_b, 0x18);
    const auto split_tls_path = write_temp_pcap(
        "pfl_stream_query_tls_split_record.pcap",
        make_classic_pcap({
            {100, split_tls_packet_a},
            {200, split_tls_packet_b},
        })
    );

    CaptureSession split_tls_session {};
    PFL_EXPECT(split_tls_session.open_capture(split_tls_path, fast_options));
    const auto split_tls_rows = split_tls_session.list_flow_stream_items(0);
    PFL_EXPECT(split_tls_rows.size() == 1);
    PFL_EXPECT(split_tls_rows[0].label == "TLS ServerHello");
    PFL_EXPECT(split_tls_rows[0].byte_count == split_server_hello_record.size());
    PFL_EXPECT(split_tls_rows[0].packet_count == 2);
    const auto expected_split_packet_indices = std::vector<std::uint64_t> {0, 1};
    PFL_EXPECT(split_tls_rows[0].packet_indices == expected_split_packet_indices);
    PFL_EXPECT(split_tls_rows[0].protocol_text.find("Handshake Type: ServerHello") != std::string::npos);
    PFL_EXPECT(!split_tls_rows[0].payload_hex_text.empty());

    const auto split_app_data_record = make_tls_record(0x17U, 0x0303U, {0xDEU, 0xADU, 0xBEU, 0xEFU, 0x11U, 0x22U});
    const auto split_app_payload_a = std::vector<std::uint8_t>(
        split_app_data_record.begin(),
        split_app_data_record.begin() + 6
    );
    const auto split_app_payload_b = std::vector<std::uint8_t>(
        split_app_data_record.begin() + 6,
        split_app_data_record.end()
    );
    const auto split_app_packet_a = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
        ipv4(10, 46, 0, 1), ipv4(10, 46, 0, 2), 52004, 443, split_app_payload_a, 0x18);
    const auto split_app_packet_b = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
        ipv4(10, 46, 0, 1), ipv4(10, 46, 0, 2), 52004, 443, split_app_payload_b, 0x18);
    const auto split_app_path = write_temp_pcap(
        "pfl_stream_query_tls_split_appdata.pcap",
        make_classic_pcap({
            {100, split_app_packet_a},
            {200, split_app_packet_b},
        })
    );

    CaptureSession split_app_session {};
    PFL_EXPECT(split_app_session.open_capture(split_app_path, fast_options));
    const auto split_app_rows = split_app_session.list_flow_stream_items(0);
    PFL_EXPECT(split_app_rows.size() == 1);
    PFL_EXPECT(split_app_rows[0].label == "TLS AppData");
    PFL_EXPECT(split_app_rows[0].byte_count == split_app_data_record.size());
    PFL_EXPECT(split_app_rows[0].packet_count == 2);
    PFL_EXPECT(split_app_rows[0].packet_indices == expected_split_packet_indices);
    PFL_EXPECT(split_app_rows[0].protocol_text.find("Record Type: ApplicationData") != std::string::npos);
    PFL_EXPECT(!split_app_rows[0].payload_hex_text.empty());

    const auto tls_gap_app_data = make_tls_record(0x17U, 0x0303U, {0xAAU, 0xBBU, 0xCCU, 0xDDU});
    const auto tls_gap_packet_a = make_ethernet_ipv4_tcp_packet_with_bytes_payload_and_sequence(
        ipv4(10, 46, 1, 1), ipv4(10, 46, 1, 2), 52014, 443, split_server_hello_record, 1000U, 0U, 0x18);
    const auto tls_gap_packet_b = make_ethernet_ipv4_tcp_packet_with_bytes_payload_and_sequence(
        ipv4(10, 46, 1, 1), ipv4(10, 46, 1, 2), 52014, 443, tls_gap_app_data, 1000U + static_cast<std::uint32_t>(split_server_hello_record.size()) + 9U, 0U, 0x18);
    const auto tls_gap_path = write_temp_pcap(
        "pfl_stream_query_tls_gap_stop.pcap",
        make_classic_pcap({
            {100, tls_gap_packet_a},
            {200, tls_gap_packet_b},
        })
    );

    CaptureSession tls_gap_session {};
    PFL_EXPECT(tls_gap_session.open_capture(tls_gap_path, fast_options));
    tls_gap_session.set_selected_flow_tcp_payload_suppression(0U, {}, 2U);
    const auto tls_gap_rows = tls_gap_session.list_flow_stream_items_for_packet_prefix(0U, 2U, 10U);
    PFL_EXPECT(tls_gap_rows.size() == 3U);
    PFL_EXPECT(tls_gap_rows[0].label == "TLS ServerHello");
    PFL_EXPECT(tls_gap_rows[1].label == "TLS Gap");
    PFL_EXPECT(tls_gap_rows[2].label == "TLS Payload");
    PFL_EXPECT(tls_gap_rows[1].protocol_text.find("Semantic parsing stopped for this direction") != std::string::npos);
    PFL_EXPECT(tls_gap_rows[2].protocol_text.find("Later bytes are shown conservatively") != std::string::npos);
    PFL_EXPECT(tls_gap_rows[2].packet_indices == std::vector<std::uint64_t> {1U});
    const auto tls_gap_info = tls_gap_session.selected_flow_stream_context_info();
    PFL_REQUIRE(tls_gap_info.has_value());
    PFL_EXPECT(tls_gap_info->committed_stable_row_count == tls_gap_rows.size());
    PFL_EXPECT(tls_gap_info->provisional_row_count == 0U);
    PFL_EXPECT(!tls_gap_info->has_window_incomplete_suffix);

    constexpr std::string_view http_gap_request_one =
        "GET /one HTTP/1.1\r\n"
        "Host: gap.example\r\n"
        "\r\n";
    constexpr std::string_view http_gap_request_two =
        "GET /two HTTP/1.1\r\n"
        "Host: gap.example\r\n"
        "\r\n";
    const auto http_gap_payload_a = make_text_bytes(http_gap_request_one);
    const auto http_gap_payload_b = make_text_bytes(http_gap_request_two);
    const auto http_gap_packet_a = make_ethernet_ipv4_tcp_packet_with_bytes_payload_and_sequence(
        ipv4(10, 46, 2, 1), ipv4(10, 46, 2, 2), 53024, 80, http_gap_payload_a, 4000U, 0U, 0x18);
    const auto http_gap_packet_b = make_ethernet_ipv4_tcp_packet_with_bytes_payload_and_sequence(
        ipv4(10, 46, 2, 1), ipv4(10, 46, 2, 2), 53024, 80, http_gap_payload_b, 4000U + static_cast<std::uint32_t>(http_gap_payload_a.size()) + 13U, 0U, 0x18);
    const auto http_gap_path = write_temp_pcap(
        "pfl_stream_query_http_gap_stop.pcap",
        make_classic_pcap({
            {100, http_gap_packet_a},
            {200, http_gap_packet_b},
        })
    );

    CaptureSession http_gap_session {};
    PFL_EXPECT(http_gap_session.open_capture(http_gap_path, fast_options));
    http_gap_session.set_selected_flow_tcp_payload_suppression(0U, {}, 2U);
    const auto http_gap_rows = http_gap_session.list_flow_stream_items_for_packet_prefix(0U, 2U, 10U);
    PFL_EXPECT(http_gap_rows.size() == 3U);
    PFL_EXPECT(http_gap_rows[0].label == "HTTP GET /one");
    PFL_EXPECT(http_gap_rows[1].label == "HTTP Gap");
    PFL_EXPECT(http_gap_rows[2].label == "HTTP Payload");
    PFL_EXPECT(http_gap_rows[1].protocol_text.find("Semantic parsing stopped for this direction") != std::string::npos);
    PFL_EXPECT(http_gap_rows[2].protocol_text.find("Later bytes are shown conservatively") != std::string::npos);
    PFL_EXPECT(http_gap_rows[2].packet_indices == std::vector<std::uint64_t> {1U});
    const auto http_gap_info = http_gap_session.selected_flow_stream_context_info();
    PFL_REQUIRE(http_gap_info.has_value());
    PFL_EXPECT(http_gap_info->committed_stable_row_count == http_gap_rows.size());
    PFL_EXPECT(http_gap_info->provisional_row_count == 0U);
    PFL_EXPECT(!http_gap_info->has_window_incomplete_suffix);

    const auto multi_record_server_hello = make_tls_handshake_record(0x02U, {0x10U, 0x11U, 0x12U, 0x13U});
    const auto multi_record_ccs = make_tls_change_cipher_spec_record();
    const auto multi_record_app_data = make_tls_record(0x17U, 0x0303U, {0x21U, 0x22U, 0x23U, 0x24U, 0x25U});
    const auto multi_record_payload = concat_bytes(
        concat_bytes(multi_record_server_hello, multi_record_ccs),
        multi_record_app_data
    );
    const auto multi_record_split = static_cast<std::ptrdiff_t>(multi_record_server_hello.size() + 2U);
    const auto multi_record_payload_a = std::vector<std::uint8_t>(
        multi_record_payload.begin(),
        multi_record_payload.begin() + multi_record_split
    );
    const auto multi_record_payload_b = std::vector<std::uint8_t>(
        multi_record_payload.begin() + multi_record_split,
        multi_record_payload.end()
    );
    const auto multi_record_packet_a = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
        ipv4(10, 47, 0, 1), ipv4(10, 47, 0, 2), 52005, 443, multi_record_payload_a, 0x18);
    const auto multi_record_packet_b = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
        ipv4(10, 47, 0, 1), ipv4(10, 47, 0, 2), 52005, 443, multi_record_payload_b, 0x18);
    const auto multi_record_path = write_temp_pcap(
        "pfl_stream_query_tls_reassembled_sequence.pcap",
        make_classic_pcap({
            {100, multi_record_packet_a},
            {200, multi_record_packet_b},
        })
    );

    CaptureSession multi_record_session {};
    PFL_EXPECT(multi_record_session.open_capture(multi_record_path, fast_options));
    const auto multi_record_rows = multi_record_session.list_flow_stream_items(0);
    PFL_EXPECT(multi_record_rows.size() == 3);
    PFL_EXPECT(multi_record_rows[0].label == "TLS ServerHello");
    PFL_EXPECT(multi_record_rows[1].label == "TLS ChangeCipherSpec");
    PFL_EXPECT(multi_record_rows[2].label == "TLS AppData");
    PFL_EXPECT(multi_record_rows[0].byte_count == multi_record_server_hello.size());
    PFL_EXPECT(multi_record_rows[1].byte_count == multi_record_ccs.size());
    PFL_EXPECT(multi_record_rows[2].byte_count == multi_record_app_data.size());
    PFL_EXPECT(multi_record_rows[0].packet_indices == std::vector<std::uint64_t> {0});
    PFL_EXPECT(multi_record_rows[1].packet_indices == expected_split_packet_indices);
    PFL_EXPECT(multi_record_rows[2].packet_indices == std::vector<std::uint64_t> {1});
    PFL_EXPECT(multi_record_rows[0].protocol_text.find("Handshake Type: ServerHello") != std::string::npos);
    PFL_EXPECT(multi_record_rows[1].protocol_text.find("Record Type: ChangeCipherSpec") != std::string::npos);
    PFL_EXPECT(multi_record_rows[2].protocol_text.find("Record Type: ApplicationData") != std::string::npos);

    const auto incomplete_reassembled_app_data = std::vector<std::uint8_t> {
        0x17U, 0x03U, 0x03U, 0x00U, 0x04U, 0xAAU, 0xBBU,
    };
    const auto reassembled_partial_payload = concat_bytes(server_hello_record, incomplete_reassembled_app_data);
    const auto reassembled_partial_split = static_cast<std::ptrdiff_t>(server_hello_record.size() + 2U);
    const auto reassembled_partial_payload_a = std::vector<std::uint8_t>(
        reassembled_partial_payload.begin(),
        reassembled_partial_payload.begin() + reassembled_partial_split
    );
    const auto reassembled_partial_payload_b = std::vector<std::uint8_t>(
        reassembled_partial_payload.begin() + reassembled_partial_split,
        reassembled_partial_payload.end()
    );
    const auto reassembled_partial_packet_a = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
        ipv4(10, 48, 0, 1), ipv4(10, 48, 0, 2), 52006, 443, reassembled_partial_payload_a, 0x18);
    const auto reassembled_partial_packet_b = make_ethernet_ipv4_tcp_packet_with_bytes_payload(
        ipv4(10, 48, 0, 1), ipv4(10, 48, 0, 2), 52006, 443, reassembled_partial_payload_b, 0x18);
    const auto reassembled_partial_path = write_temp_pcap(
        "pfl_stream_query_tls_reassembled_partial.pcap",
        make_classic_pcap({
            {100, reassembled_partial_packet_a},
            {200, reassembled_partial_packet_b},
        })
    );

    CaptureSession reassembled_partial_session {};
    PFL_EXPECT(reassembled_partial_session.open_capture(reassembled_partial_path, fast_options));
    const auto reassembled_partial_rows = reassembled_partial_session.list_flow_stream_items(0);
    PFL_EXPECT(reassembled_partial_rows.size() == 2);
    PFL_EXPECT(reassembled_partial_rows[0].label == "TLS ServerHello");
    PFL_EXPECT(reassembled_partial_rows[1].label == "TLS Record Fragment (partial)");
    PFL_EXPECT(reassembled_partial_rows[1].packet_indices == expected_split_packet_indices);
    PFL_EXPECT(reassembled_partial_rows[1].protocol_text.find("do not contain a complete TLS record") != std::string::npos);
    PFL_EXPECT(reassembled_partial_rows[1].protocol_text.find("ApplicationData") == std::string::npos);

    std::vector<std::pair<std::uint32_t, std::vector<std::uint8_t>>> bounded_stream_packets {};
    bounded_stream_packets.reserve(31);
    for (std::uint32_t index = 0; index < 31U; ++index) {
        bounded_stream_packets.push_back({
            1000U + index,
            make_ethernet_ipv4_tcp_packet_with_payload(ipv4(10, 60, 0, 1), ipv4(10, 60, 0, 2), 54000, 443, 6, 0x18)
        });
    }
    const auto split_http_request_prefix_rows = split_http_request_session.list_flow_stream_items_for_packet_prefix(0, 30U, 16U);
    PFL_EXPECT(split_http_request_prefix_rows.size() == 1U);
    PFL_EXPECT(split_http_request_prefix_rows[0].label == "HTTP GET /split");

    constexpr std::string_view bounded_prefix_http_text =
        "GET /bounded HTTP/1.1\r\n"
        "Host: bounded.example\r\n"
        "User-Agent: split-test\r\n"
        "Accept: */*\r\n"
        "Connection: keep-alive\r\n"
        "X-Debug: 1234567890\r\n"
        "\r\n";
    const auto bounded_prefix_http_bytes = make_text_bytes(bounded_prefix_http_text);
    std::vector<std::pair<std::uint32_t, std::vector<std::uint8_t>>> bounded_prefix_http_packets {};
    bounded_prefix_http_packets.reserve(40U);
    const auto chunk_size = (bounded_prefix_http_bytes.size() + 39U) / 40U;
    for (std::size_t packetIndex = 0; packetIndex < 40U; ++packetIndex) {
        const auto begin = std::min(packetIndex * chunk_size, bounded_prefix_http_bytes.size());
        const auto end = std::min(begin + chunk_size, bounded_prefix_http_bytes.size());
        const auto fragment = std::vector<std::uint8_t>(bounded_prefix_http_bytes.begin() + static_cast<std::ptrdiff_t>(begin), bounded_prefix_http_bytes.begin() + static_cast<std::ptrdiff_t>(end));
        bounded_prefix_http_packets.push_back({
            static_cast<std::uint32_t>(2000U + packetIndex),
            make_ethernet_ipv4_tcp_packet_with_bytes_payload(ipv4(10, 61, 0, 1), ipv4(10, 61, 0, 2), 54010, 80, fragment, 0x18)
        });
    }
    const auto bounded_prefix_http_path = write_temp_pcap(
        "pfl_stream_query_bounded_prefix_http.pcap",
        make_classic_pcap(bounded_prefix_http_packets)
    );

    CaptureSession bounded_prefix_http_session {};
    PFL_EXPECT(bounded_prefix_http_session.open_capture(bounded_prefix_http_path, fast_options));
    const auto bounded_prefix_rows = bounded_prefix_http_session.list_flow_stream_items_for_packet_prefix(0, 30U, 16U);
    const auto bounded_prefix_full_rows = bounded_prefix_http_session.list_flow_stream_items(0, 0U, 16U);
    PFL_EXPECT(!bounded_prefix_rows.empty());
    PFL_EXPECT(!bounded_prefix_full_rows.empty());
    PFL_EXPECT(bounded_prefix_rows.size() <= 16U);
    PFL_EXPECT(!bounded_prefix_rows.front().label.empty());
    PFL_EXPECT(!bounded_prefix_rows.front().direction_text.empty());
    for (const auto& row : bounded_prefix_rows) {
        for (const auto packet_index : row.packet_indices) {
            PFL_EXPECT(packet_index < 30U);
        }
    }
    bounded_prefix_http_session.prepare_selected_flow_packet_cache(0, 30U);
    auto bounded_prefix_cache = bounded_prefix_http_session.selected_flow_packet_cache_info();
    PFL_EXPECT(bounded_prefix_cache.has_value());
    PFL_EXPECT(bounded_prefix_cache->flow_index == 0U);
    PFL_EXPECT(bounded_prefix_cache->cached_packet_window_count == 30U);
    PFL_EXPECT(!bounded_prefix_cache->limit_reached);
    PFL_EXPECT(bounded_prefix_cache->window_fully_cached);

    bounded_prefix_http_session.prepare_selected_flow_packet_cache(0, 40U);
    bounded_prefix_cache = bounded_prefix_http_session.selected_flow_packet_cache_info();
    PFL_EXPECT(bounded_prefix_cache.has_value());
    PFL_EXPECT(bounded_prefix_cache->cached_packet_window_count == 40U);
    PFL_EXPECT(!bounded_prefix_cache->limit_reached);
    PFL_EXPECT(bounded_prefix_cache->window_fully_cached);

    const auto extended_prefix_rows = bounded_prefix_http_session.list_flow_stream_items_for_packet_prefix(0, 40U, 16U);
    PFL_EXPECT(!extended_prefix_rows.empty());
    PFL_EXPECT(extended_prefix_rows.size() <= 16U);
    const auto extended_comparable_row_count = std::min(extended_prefix_rows.size(), bounded_prefix_full_rows.size());
    for (std::size_t index = 0; index < extended_comparable_row_count; ++index) {
        PFL_EXPECT(extended_prefix_rows[index].label == bounded_prefix_full_rows[index].label);
        PFL_EXPECT(extended_prefix_rows[index].direction_text == bounded_prefix_full_rows[index].direction_text);
    }
    for (const auto& row : extended_prefix_rows) {
        for (const auto packet_index : row.packet_indices) {
            PFL_EXPECT(packet_index < 40U);
        }
    }

    std::vector<std::pair<std::uint32_t, std::vector<std::uint8_t>>> mixed_prefix_http_packets {};
    mixed_prefix_http_packets.reserve(80U);
    const auto mixed_chunk_size = (bounded_prefix_http_bytes.size() + 39U) / 40U;
    for (std::size_t packetIndex = 0; packetIndex < 40U; ++packetIndex) {
        const auto begin = std::min(packetIndex * mixed_chunk_size, bounded_prefix_http_bytes.size());
        const auto end = std::min(begin + mixed_chunk_size, bounded_prefix_http_bytes.size());
        const auto fragment = std::vector<std::uint8_t>(
            bounded_prefix_http_bytes.begin() + static_cast<std::ptrdiff_t>(begin),
            bounded_prefix_http_bytes.begin() + static_cast<std::ptrdiff_t>(end)
        );
        mixed_prefix_http_packets.push_back({
            static_cast<std::uint32_t>(3000U + (packetIndex * 2U)),
            make_ethernet_ipv4_tcp_packet_with_bytes_payload(ipv4(10, 62, 0, 1), ipv4(10, 62, 0, 2), 54020, 80, fragment, 0x18)
        });
        mixed_prefix_http_packets.push_back({
            static_cast<std::uint32_t>(3001U + (packetIndex * 2U)),
            make_ethernet_ipv4_tcp_packet(ipv4(10, 62, 0, 2), ipv4(10, 62, 0, 1), 80, 54020)
        });
    }
    const auto mixed_prefix_http_path = write_temp_pcap(
        "pfl_stream_query_bounded_prefix_http_mixed.pcap",
        make_classic_pcap(mixed_prefix_http_packets)
    );

    CaptureSession mixed_prefix_http_session {};
    PFL_EXPECT(mixed_prefix_http_session.open_capture(mixed_prefix_http_path, fast_options));
    const auto mixed_prefix_rows = mixed_prefix_http_session.list_flow_stream_items_for_packet_prefix(0, 30U, 16U);
    PFL_EXPECT(!mixed_prefix_rows.empty());
    for (const auto& row : mixed_prefix_rows) {
        for (const auto packet_index : row.packet_indices) {
            PFL_EXPECT(packet_index < 30U);
        }
    }

    {
        constexpr std::array<std::string_view, 6> kHttpPrefixMessages {
            "GET /prefix-1 HTTP/1.1\r\nHost: prefix.example\r\n\r\n",
            "GET /prefix-2 HTTP/1.1\r\nHost: prefix.example\r\n\r\n",
            "GET /prefix-3 HTTP/1.1\r\nHost: prefix.example\r\n\r\n",
            "GET /prefix-4 HTTP/1.1\r\nHost: prefix.example\r\n\r\n",
            "GET /prefix-5 HTTP/1.1\r\nHost: prefix.example\r\n\r\n",
            "GET /prefix-6 HTTP/1.1\r\nHost: prefix.example\r\n\r\n",
        };
        std::vector<std::pair<std::uint32_t, std::vector<std::uint8_t>>> http_prefix_packets {};
        http_prefix_packets.reserve(kHttpPrefixMessages.size());
        for (std::size_t index = 0U; index < kHttpPrefixMessages.size(); ++index) {
            http_prefix_packets.push_back({
                static_cast<std::uint32_t>(4000U + index),
                make_ethernet_ipv4_tcp_packet_with_bytes_payload(
                    ipv4(10, 63, 0, 1),
                    ipv4(10, 63, 0, 2),
                    54030,
                    80,
                    make_text_bytes(kHttpPrefixMessages[index]),
                    0x18
                )
            });
        }

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(
            write_temp_pcap("pfl_stream_query_http_visible_prefix_budget.pcap", make_classic_pcap(http_prefix_packets)),
            fast_options
        ));

        const auto full_rows = session.list_flow_stream_items(0);
        const auto bounded_rows = session.list_flow_stream_items_for_packet_prefix(0, 6U, 3U);
        PFL_EXPECT(full_rows.size() == 6U);
        PFL_EXPECT(bounded_rows.size() == 3U);
        for (std::size_t index = 0U; index < bounded_rows.size(); ++index) {
            PFL_EXPECT(bounded_rows[index].label == full_rows[index].label);
            PFL_EXPECT(bounded_rows[index].byte_count == full_rows[index].byte_count);
            PFL_EXPECT(bounded_rows[index].direction_text == full_rows[index].direction_text);
            PFL_EXPECT(bounded_rows[index].packet_indices == full_rows[index].packet_indices);
        }

        const auto repeated_rows = session.list_flow_stream_items_for_packet_prefix(0, 6U, 6U);
        PFL_EXPECT(repeated_rows.size() == full_rows.size());
        for (std::size_t index = 0U; index < repeated_rows.size(); ++index) {
            PFL_EXPECT(repeated_rows[index].stream_item_index == full_rows[index].stream_item_index);
            PFL_EXPECT(repeated_rows[index].label == full_rows[index].label);
            PFL_EXPECT(repeated_rows[index].direction_text == full_rows[index].direction_text);
            PFL_EXPECT(repeated_rows[index].byte_count == full_rows[index].byte_count);
            PFL_EXPECT(repeated_rows[index].packet_indices == full_rows[index].packet_indices);
            PFL_EXPECT(repeated_rows[index].payload_hex_text == full_rows[index].payload_hex_text);
            PFL_EXPECT(repeated_rows[index].protocol_text == full_rows[index].protocol_text);
        }

        const auto context_info_after_first = session.selected_flow_stream_context_info();
        PFL_REQUIRE(context_info_after_first.has_value());
        PFL_EXPECT(context_info_after_first->valid);
        PFL_EXPECT(context_info_after_first->materialized_packet_window_count == 6U);
        PFL_EXPECT(context_info_after_first->materialized_cumulative_item_limit == 6U);
        PFL_EXPECT(context_info_after_first->materialized_row_count == 6U);
        PFL_EXPECT(context_info_after_first->committed_stable_row_count == 6U);
        PFL_EXPECT(context_info_after_first->provisional_row_count == 0U);
        PFL_EXPECT(!context_info_after_first->has_window_incomplete_suffix);

        const auto smaller_projection_rows = session.list_flow_stream_items_for_packet_prefix(0, 6U, 3U);
        PFL_EXPECT(smaller_projection_rows.size() == 3U);
        for (std::size_t index = 0U; index < smaller_projection_rows.size(); ++index) {
            PFL_EXPECT(smaller_projection_rows[index].stream_item_index == full_rows[index].stream_item_index);
            PFL_EXPECT(smaller_projection_rows[index].label == full_rows[index].label);
            PFL_EXPECT(smaller_projection_rows[index].direction_text == full_rows[index].direction_text);
            PFL_EXPECT(smaller_projection_rows[index].byte_count == full_rows[index].byte_count);
            PFL_EXPECT(smaller_projection_rows[index].packet_indices == full_rows[index].packet_indices);
        }

        const auto context_info_after_smaller_projection = session.selected_flow_stream_context_info();
        PFL_REQUIRE(context_info_after_smaller_projection.has_value());
        PFL_EXPECT(context_info_after_smaller_projection->generation == context_info_after_first->generation);
        PFL_EXPECT(context_info_after_smaller_projection->materialized_cumulative_item_limit == 6U);
        PFL_EXPECT(context_info_after_smaller_projection->materialized_row_count == 6U);

        session.clear_selected_flow_packet_cache();
        PFL_EXPECT(!session.selected_flow_stream_context_info().has_value());
    }

    {
        std::vector<std::uint8_t> many_tls_records_payload {};
        for (std::size_t index = 0U; index < 45U; ++index) {
            const auto record = make_tls_alert_record(0x01U, static_cast<std::uint8_t>(0x20U + index));
            many_tls_records_payload.insert(many_tls_records_payload.end(), record.begin(), record.end());
        }
        const std::vector<std::pair<std::uint32_t, std::vector<std::uint8_t>>> many_tls_record_packets {
            {
                100U,
                make_ethernet_ipv4_tcp_packet_with_bytes_payload(
                    ipv4(10, 63, 1, 1),
                    ipv4(10, 63, 1, 2),
                    54443,
                    443,
                    many_tls_records_payload,
                    0x18)
            }
        };

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(
            write_temp_pcap(
                "pfl_stream_query_tls_item_budget_continuation.pcap",
                make_classic_pcap(many_tls_record_packets)),
            fast_options
        ));

        const auto full_rows = session.list_flow_stream_items(0);
        PFL_EXPECT(full_rows.size() == 45U);

        const auto first_page_rows = session.list_flow_stream_items_for_packet_prefix(0, 1U, 15U);
        expect_matching_stream_row_prefix(first_page_rows, full_rows, 15U);
        const auto first_page_info = session.selected_flow_stream_context_info();
        PFL_REQUIRE(first_page_info.has_value());
        PFL_EXPECT(first_page_info->generation != 0U);
        PFL_EXPECT(first_page_info->committed_stable_row_count == 15U);

        const auto repeated_first_page_rows = session.list_flow_stream_items_for_packet_prefix(0, 1U, 15U);
        expect_matching_stream_row_prefix(repeated_first_page_rows, full_rows, 15U);
        const auto repeated_first_page_info = session.selected_flow_stream_context_info();
        PFL_REQUIRE(repeated_first_page_info.has_value());
        PFL_EXPECT(repeated_first_page_info->generation == first_page_info->generation);

        const auto second_page_rows = session.list_flow_stream_items_for_packet_prefix(0, 1U, 30U);
        expect_matching_stream_row_prefix(second_page_rows, full_rows, 30U);
        const auto second_page_info = session.selected_flow_stream_context_info();
        PFL_REQUIRE(second_page_info.has_value());
        PFL_EXPECT(second_page_info->generation > first_page_info->generation);
        PFL_EXPECT(second_page_info->committed_stable_row_count == 30U);

        const auto third_page_rows = session.list_flow_stream_items_for_packet_prefix(0, 1U, 45U);
        expect_matching_stream_row_prefix(third_page_rows, full_rows, 45U);
        const auto third_page_info = session.selected_flow_stream_context_info();
        PFL_REQUIRE(third_page_info.has_value());
        PFL_EXPECT(third_page_info->generation > second_page_info->generation);
        PFL_EXPECT(third_page_info->committed_stable_row_count == 45U);
        PFL_EXPECT(third_page_info->provisional_row_count == 0U);

        const auto smaller_projection_rows = session.list_flow_stream_items_for_packet_prefix(0, 1U, 15U);
        expect_matching_stream_row_prefix(smaller_projection_rows, full_rows, 15U);
        const auto smaller_projection_info = session.selected_flow_stream_context_info();
        PFL_REQUIRE(smaller_projection_info.has_value());
        PFL_EXPECT(smaller_projection_info->generation == third_page_info->generation);
    }

    {
        const auto continuation_fixture_path = fixture_path("parsing/tls/tls_1_3_many_records_continuation_11.pcap");
        const std::array<std::pair<std::size_t, std::size_t>, 5> cumulative_requests {{
            {30U, 15U},
            {60U, 30U},
            {90U, 45U},
            {120U, 60U},
            {150U, 75U},
        }};

        const auto run_cumulative_oracle_sequence = [&](const std::optional<std::size_t> warmed_packet_cache) {
            CaptureSession session {};
            PFL_EXPECT(session.open_capture(continuation_fixture_path, fast_options));
            if (warmed_packet_cache.has_value()) {
                session.prepare_selected_flow_packet_cache(0U, *warmed_packet_cache);
            }

            std::optional<std::uint64_t> last_generation {};
            for (const auto& [packet_budget, item_limit] : cumulative_requests) {
                const auto actual_rows = session.list_flow_stream_items_for_packet_prefix(0U, packet_budget, item_limit);
                const auto expected_rows = query_bounded_stream_rows_fresh(
                    continuation_fixture_path,
                    fast_options,
                    0U,
                    packet_budget,
                    item_limit
                );
                expect_exact_stream_rows(actual_rows, expected_rows);
                PFL_EXPECT(actual_rows.size() <= item_limit);
                PFL_REQUIRE(actual_rows.size() >= 2U);
                PFL_EXPECT(actual_rows[0].label == "TLS ClientHello");
                PFL_EXPECT(actual_rows[1].label == "TLS ServerHello");

                const auto context_info = session.selected_flow_stream_context_info();
                PFL_REQUIRE(context_info.has_value());
                PFL_EXPECT(context_info->materialized_packet_window_count == packet_budget);
                PFL_EXPECT(context_info->materialized_cumulative_item_limit == item_limit);
                if (last_generation.has_value()) {
                    PFL_EXPECT(context_info->generation > *last_generation);
                }
                last_generation = context_info->generation;
            }

            const auto repeated_rows = session.list_flow_stream_items_for_packet_prefix(
                0U,
                cumulative_requests.back().first,
                cumulative_requests.back().second
            );
            const auto repeated_expected_rows = query_bounded_stream_rows_fresh(
                continuation_fixture_path,
                fast_options,
                0U,
                cumulative_requests.back().first,
                cumulative_requests.back().second
            );
            expect_exact_stream_rows(repeated_rows, repeated_expected_rows);
            const auto repeated_info = session.selected_flow_stream_context_info();
            PFL_REQUIRE(repeated_info.has_value());
            PFL_EXPECT(repeated_info->generation == *last_generation);

            const auto smaller_projection_rows = session.list_flow_stream_items_for_packet_prefix(0U, 60U, 30U);
            const auto smaller_projection_expected_rows = query_bounded_stream_rows_fresh(
                continuation_fixture_path,
                fast_options,
                0U,
                60U,
                30U
            );
            expect_exact_stream_rows(smaller_projection_rows, smaller_projection_expected_rows);
            const auto smaller_projection_info = session.selected_flow_stream_context_info();
            PFL_REQUIRE(smaller_projection_info.has_value());
            PFL_EXPECT(smaller_projection_info->generation == repeated_info->generation);
            PFL_EXPECT(smaller_projection_info->materialized_packet_window_count ==
                cumulative_requests.back().first);
            PFL_EXPECT(smaller_projection_info->materialized_cumulative_item_limit ==
                cumulative_requests.back().second);
        };

        run_cumulative_oracle_sequence(std::nullopt);
        run_cumulative_oracle_sequence(60U);
        run_cumulative_oracle_sequence(120U);
    }

    {
        std::vector<std::pair<std::uint32_t, std::vector<std::uint8_t>>> tls_window_packets {};
        tls_window_packets.reserve(31U);
        for (std::uint32_t index = 0U; index < 29U; ++index) {
            tls_window_packets.push_back({
                5000U + index,
                make_ethernet_ipv4_tcp_packet(ipv4(10, 64, 0, 1), ipv4(10, 64, 0, 2), 54040, 443)
            });
        }
        const auto split_tls_record = make_tls_handshake_record(0x01U, std::vector<std::uint8_t>(96U, 0x41U));
        const auto tls_split_offset = split_tls_record.size() / 2U;
        tls_window_packets.push_back({
            5029U,
            make_ethernet_ipv4_tcp_packet_with_bytes_payload(
                ipv4(10, 64, 0, 1), ipv4(10, 64, 0, 2), 54040, 443,
                std::vector<std::uint8_t>(
                    split_tls_record.begin(),
                    split_tls_record.begin() + static_cast<std::ptrdiff_t>(tls_split_offset)),
                0x18)
        });
        tls_window_packets.push_back({
            5030U,
            make_ethernet_ipv4_tcp_packet_with_bytes_payload(
                ipv4(10, 64, 0, 1), ipv4(10, 64, 0, 2), 54040, 443,
                std::vector<std::uint8_t>(
                    split_tls_record.begin() + static_cast<std::ptrdiff_t>(tls_split_offset),
                    split_tls_record.end()),
                0x18)
        });

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(
            write_temp_pcap("pfl_stream_query_tls_window_incomplete_suffix.pcap", make_classic_pcap(tls_window_packets)),
            fast_options
        ));

        const auto full_rows = session.list_flow_stream_items(0);
        PFL_EXPECT(full_rows.size() == 1U);

        const auto bounded_rows = session.list_flow_stream_items_for_packet_prefix(0, 30U, 8U);
        PFL_EXPECT(bounded_rows.size() == 1U);
        PFL_EXPECT(bounded_rows[0].label.find("(partial)") != std::string::npos);
        const auto bounded_info = session.selected_flow_stream_context_info();
        PFL_REQUIRE(bounded_info.has_value());
        PFL_EXPECT(bounded_info->committed_stable_row_count == 0U);
        PFL_EXPECT(bounded_info->provisional_row_count == 1U);
        PFL_EXPECT(bounded_info->provisional_suffix_begin_row_number == 1U);
        PFL_EXPECT(bounded_info->has_window_incomplete_suffix);

        const auto completed_rows = session.list_flow_stream_items_for_packet_prefix(0, 31U, 8U);
        PFL_EXPECT(completed_rows.size() == 1U);
        PFL_EXPECT(completed_rows[0].label.find("(partial)") == std::string::npos);
        PFL_EXPECT(completed_rows[0].packet_indices == std::vector<std::uint64_t>({29U, 30U}));
        expect_matching_stream_row_prefix(completed_rows, full_rows, 1U);
        const auto completed_info = session.selected_flow_stream_context_info();
        PFL_REQUIRE(completed_info.has_value());
        PFL_EXPECT(completed_info->generation > bounded_info->generation);
        PFL_EXPECT(completed_info->committed_stable_row_count == 1U);
        PFL_EXPECT(completed_info->provisional_row_count == 0U);
        PFL_EXPECT(!completed_info->has_window_incomplete_suffix);

        const auto repeated_completed_rows = session.list_flow_stream_items_for_packet_prefix(0, 31U, 8U);
        expect_matching_stream_row_prefix(repeated_completed_rows, full_rows, 1U);
        const auto repeated_completed_info = session.selected_flow_stream_context_info();
        PFL_REQUIRE(repeated_completed_info.has_value());
        PFL_EXPECT(repeated_completed_info->generation == completed_info->generation);
    }

    {
        std::vector<std::pair<std::uint32_t, std::vector<std::uint8_t>>> http_window_packets {};
        http_window_packets.reserve(31U);
        for (std::uint32_t index = 0U; index < 29U; ++index) {
            http_window_packets.push_back({
                5100U + index,
                make_ethernet_ipv4_tcp_packet(ipv4(10, 65, 0, 1), ipv4(10, 65, 0, 2), 54050, 80)
            });
        }
        const auto http_prefix_payload = concat_bytes(
            make_text_bytes("GET /one HTTP/1.1\r\nHost: suffix.example\r\n\r\n"),
            make_text_bytes("GET /two HTTP/1.1\r\nHost: suffix.example"));
        http_window_packets.push_back({
            5129U,
            make_ethernet_ipv4_tcp_packet_with_bytes_payload(
                ipv4(10, 65, 0, 1), ipv4(10, 65, 0, 2), 54050, 80, http_prefix_payload, 0x18)
        });
        http_window_packets.push_back({
            5130U,
            make_ethernet_ipv4_tcp_packet_with_bytes_payload(
                ipv4(10, 65, 0, 1), ipv4(10, 65, 0, 2), 54050, 80, make_text_bytes("\r\n\r\n"), 0x18)
        });

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(
            write_temp_pcap("pfl_stream_query_http_window_incomplete_suffix.pcap", make_classic_pcap(http_window_packets)),
            fast_options
        ));

        const auto bounded_rows = session.list_flow_stream_items_for_packet_prefix(0, 30U, 8U);
        PFL_EXPECT(bounded_rows.size() == 2U);
        PFL_EXPECT(bounded_rows[0].label == "HTTP GET /one");
        PFL_EXPECT(bounded_rows[1].label == "HTTP Payload (partial)");
        const auto bounded_info = session.selected_flow_stream_context_info();
        PFL_REQUIRE(bounded_info.has_value());
        PFL_EXPECT(bounded_info->committed_stable_row_count == 1U);
        PFL_EXPECT(bounded_info->provisional_row_count == 1U);
        PFL_EXPECT(bounded_info->provisional_suffix_begin_row_number == 2U);
        PFL_EXPECT(bounded_info->has_window_incomplete_suffix);

        const auto completed_rows = session.list_flow_stream_items_for_packet_prefix(0, 31U, 8U);
        PFL_EXPECT(completed_rows.size() == 2U);
        PFL_EXPECT(completed_rows[0].label == "HTTP GET /one");
        PFL_EXPECT(completed_rows[1].label == "HTTP GET /two");
        const auto completed_info = session.selected_flow_stream_context_info();
        PFL_REQUIRE(completed_info.has_value());
        PFL_EXPECT(completed_info->generation > bounded_info->generation);
        PFL_EXPECT(completed_info->committed_stable_row_count == 2U);
        PFL_EXPECT(completed_info->provisional_row_count == 0U);
        PFL_EXPECT(!completed_info->has_window_incomplete_suffix);
    }

    {
        const auto client_hello_record = make_tls_handshake_record(0x01U, std::vector<std::uint8_t>(96U, 0x31U));
        const auto split_offsets = std::array<std::size_t, 4U> {
            5U,
            9U,
            40U,
            client_hello_record.size() - 1U,
        };

        for (const auto split_offset : split_offsets) {
            const auto first_chunk = std::vector<std::uint8_t>(
                client_hello_record.begin(),
                client_hello_record.begin() + static_cast<std::ptrdiff_t>(split_offset)
            );
            const auto second_chunk = std::vector<std::uint8_t>(
                client_hello_record.begin() + static_cast<std::ptrdiff_t>(split_offset),
                client_hello_record.end()
            );

            auto one_shot_state = session_detail::make_tls_stream_scanner_state(Direction::a_to_b, true);
            const auto one_shot = session_detail::consume_tls_stream_scanner(
                one_shot_state,
                std::array<session_detail::TlsStreamScannerContribution, 2U> {{
                    {
                        .packet_index = 100U,
                        .flow_packet_index = 1U,
                        .captured_bytes = first_chunk,
                        .original_byte_count = first_chunk.size(),
                        .packet_captured_length = static_cast<std::uint32_t>(first_chunk.size()),
                        .packet_original_length = static_cast<std::uint32_t>(first_chunk.size()),
                    },
                    {
                        .packet_index = 101U,
                        .flow_packet_index = 2U,
                        .captured_bytes = second_chunk,
                        .original_byte_count = second_chunk.size(),
                        .packet_captured_length = static_cast<std::uint32_t>(second_chunk.size()),
                        .packet_original_length = static_cast<std::uint32_t>(second_chunk.size()),
                    },
                }},
                8U,
                session_detail::TlsStreamScannerFinishMode::flow_end
            );
            PFL_REQUIRE(one_shot.stable_rows.size() == 1U);
            PFL_EXPECT(!one_shot.provisional_row.has_value());

            auto split_state = session_detail::make_tls_stream_scanner_state(Direction::a_to_b, true);
            const auto first_pass = session_detail::consume_tls_stream_scanner(
                split_state,
                std::array<session_detail::TlsStreamScannerContribution, 1U> {{
                    {
                        .packet_index = 100U,
                        .flow_packet_index = 1U,
                        .captured_bytes = first_chunk,
                        .original_byte_count = first_chunk.size(),
                        .packet_captured_length = static_cast<std::uint32_t>(first_chunk.size()),
                        .packet_original_length = static_cast<std::uint32_t>(first_chunk.size()),
                    },
                }},
                8U,
                session_detail::TlsStreamScannerFinishMode::window_end
            );
            PFL_EXPECT(first_pass.stable_rows.empty());
            PFL_REQUIRE(first_pass.provisional_row.has_value());
            PFL_EXPECT(first_pass.provisional_row->item.label.find("(partial)") != std::string::npos);
            PFL_EXPECT(first_pass.provisional_row->item.stability == StreamMaterializationStability::window_incomplete);

            const auto second_pass = session_detail::consume_tls_stream_scanner(
                split_state,
                std::array<session_detail::TlsStreamScannerContribution, 1U> {{
                    {
                        .packet_index = 101U,
                        .flow_packet_index = 2U,
                        .captured_bytes = second_chunk,
                        .original_byte_count = second_chunk.size(),
                        .packet_captured_length = static_cast<std::uint32_t>(second_chunk.size()),
                        .packet_original_length = static_cast<std::uint32_t>(second_chunk.size()),
                    },
                }},
                8U,
                session_detail::TlsStreamScannerFinishMode::flow_end
            );
            PFL_REQUIRE(second_pass.stable_rows.size() == 1U);
            PFL_EXPECT(!second_pass.provisional_row.has_value());
            PFL_EXPECT(second_pass.stable_rows[0].item.label == one_shot.stable_rows[0].item.label);
            PFL_EXPECT(second_pass.stable_rows[0].item.byte_count == one_shot.stable_rows[0].item.byte_count);
            PFL_EXPECT(second_pass.stable_rows[0].item.packet_indices == one_shot.stable_rows[0].item.packet_indices);
            PFL_EXPECT(second_pass.stable_rows[0].item.payload_hex_text == one_shot.stable_rows[0].item.payload_hex_text);
            PFL_EXPECT(second_pass.stable_rows[0].item.protocol_text == one_shot.stable_rows[0].item.protocol_text);
            PFL_EXPECT(second_pass.stable_rows[0].item.semantic_kind == one_shot.stable_rows[0].item.semantic_kind);
        }
    }

    {
        const auto server_hello_record = make_tls_handshake_record(0x02U, {0x10U, 0x11U, 0x12U, 0x13U});
        const auto change_cipher_spec_record = make_tls_change_cipher_spec_record();
        const auto app_data_record = make_tls_record(0x17U, 0x0303U, {0x21U, 0x22U, 0x23U, 0x24U});
        const auto packet_payload = concat_bytes(concat_bytes(server_hello_record, change_cipher_spec_record), app_data_record);

        auto scanner_state = session_detail::make_tls_stream_scanner_state(Direction::a_to_b, true);
        const auto first_pass = session_detail::consume_tls_stream_scanner(
            scanner_state,
            std::array<session_detail::TlsStreamScannerContribution, 1U> {{
                {
                    .packet_index = 200U,
                    .flow_packet_index = 1U,
                    .captured_bytes = packet_payload,
                    .original_byte_count = packet_payload.size(),
                    .packet_captured_length = static_cast<std::uint32_t>(packet_payload.size()),
                    .packet_original_length = static_cast<std::uint32_t>(packet_payload.size()),
                },
            }},
            2U,
            session_detail::TlsStreamScannerFinishMode::none
        );
        PFL_REQUIRE(first_pass.stable_rows.size() == 2U);
        PFL_EXPECT(first_pass.budget_exhausted);
        PFL_EXPECT(first_pass.stable_rows[0].item.label == "TLS ServerHello");
        PFL_EXPECT(first_pass.stable_rows[1].item.label == "TLS ChangeCipherSpec");
        PFL_EXPECT(first_pass.stable_rows[0].intra_packet_ordinal == 0U);
        PFL_EXPECT(first_pass.stable_rows[1].intra_packet_ordinal == 1U);
        PFL_EXPECT(!first_pass.provisional_row.has_value());

        const auto second_pass = session_detail::consume_tls_stream_scanner(
            scanner_state,
            std::span<const session_detail::TlsStreamScannerContribution> {},
            4U,
            session_detail::TlsStreamScannerFinishMode::flow_end
        );
        PFL_REQUIRE(second_pass.stable_rows.size() == 1U);
        PFL_EXPECT(second_pass.stable_rows[0].item.label == "TLS AppData");
        PFL_EXPECT(second_pass.stable_rows[0].intra_packet_ordinal == 2U);
        PFL_EXPECT(!second_pass.provisional_row.has_value());
    }

    {
        const auto change_cipher_spec_record = make_tls_change_cipher_spec_record();
        const auto encrypted_handshake_record = make_tls_handshake_record(0x14U, {0xAAU, 0xBBU, 0xCCU});

        auto one_shot_state = session_detail::make_tls_stream_scanner_state(Direction::a_to_b, true);
        const auto one_shot = session_detail::consume_tls_stream_scanner(
            one_shot_state,
            std::array<session_detail::TlsStreamScannerContribution, 2U> {{
                {
                    .packet_index = 300U,
                    .flow_packet_index = 1U,
                    .captured_bytes = change_cipher_spec_record,
                    .original_byte_count = change_cipher_spec_record.size(),
                    .packet_captured_length = static_cast<std::uint32_t>(change_cipher_spec_record.size()),
                    .packet_original_length = static_cast<std::uint32_t>(change_cipher_spec_record.size()),
                },
                {
                    .packet_index = 301U,
                    .flow_packet_index = 2U,
                    .captured_bytes = encrypted_handshake_record,
                    .original_byte_count = encrypted_handshake_record.size(),
                    .packet_captured_length = static_cast<std::uint32_t>(encrypted_handshake_record.size()),
                    .packet_original_length = static_cast<std::uint32_t>(encrypted_handshake_record.size()),
                },
            }},
            8U,
            session_detail::TlsStreamScannerFinishMode::flow_end
        );
        PFL_REQUIRE(one_shot.stable_rows.size() == 2U);

        auto split_state = session_detail::make_tls_stream_scanner_state(Direction::a_to_b, true);
        const auto ccs_pass = session_detail::consume_tls_stream_scanner(
            split_state,
            std::array<session_detail::TlsStreamScannerContribution, 1U> {{
                {
                    .packet_index = 300U,
                    .flow_packet_index = 1U,
                    .captured_bytes = change_cipher_spec_record,
                    .original_byte_count = change_cipher_spec_record.size(),
                    .packet_captured_length = static_cast<std::uint32_t>(change_cipher_spec_record.size()),
                    .packet_original_length = static_cast<std::uint32_t>(change_cipher_spec_record.size()),
                },
            }},
            8U,
            session_detail::TlsStreamScannerFinishMode::window_end
        );
        PFL_REQUIRE(ccs_pass.stable_rows.size() == 1U);
        PFL_EXPECT(ccs_pass.stable_rows[0].item.label == "TLS ChangeCipherSpec");

        const auto encrypted_pass = session_detail::consume_tls_stream_scanner(
            split_state,
            std::array<session_detail::TlsStreamScannerContribution, 1U> {{
                {
                    .packet_index = 301U,
                    .flow_packet_index = 2U,
                    .captured_bytes = encrypted_handshake_record,
                    .original_byte_count = encrypted_handshake_record.size(),
                    .packet_captured_length = static_cast<std::uint32_t>(encrypted_handshake_record.size()),
                    .packet_original_length = static_cast<std::uint32_t>(encrypted_handshake_record.size()),
                },
            }},
            8U,
            session_detail::TlsStreamScannerFinishMode::flow_end
        );
        PFL_REQUIRE(encrypted_pass.stable_rows.size() == 1U);
        PFL_EXPECT(encrypted_pass.stable_rows[0].item.label == one_shot.stable_rows[1].item.label);
        PFL_EXPECT(encrypted_pass.stable_rows[0].item.protocol_text == one_shot.stable_rows[1].item.protocol_text);
        PFL_EXPECT(encrypted_pass.stable_rows[0].item.protocol_text.find("Encrypted/opaque handshake payload") != std::string::npos);
    }

    {
        const auto partial_record = make_tls_handshake_record(0x01U, std::vector<std::uint8_t>(48U, 0x44U));
        const auto split_offset = partial_record.size() / 2U;
        const auto partial_prefix = std::vector<std::uint8_t>(
            partial_record.begin(),
            partial_record.begin() + static_cast<std::ptrdiff_t>(split_offset)
        );

        auto window_state = session_detail::make_tls_stream_scanner_state(Direction::a_to_b, true);
        const auto window_result = session_detail::consume_tls_stream_scanner(
            window_state,
            std::array<session_detail::TlsStreamScannerContribution, 1U> {{
                {
                    .packet_index = 400U,
                    .flow_packet_index = 1U,
                    .captured_bytes = partial_prefix,
                    .original_byte_count = partial_prefix.size(),
                    .packet_captured_length = static_cast<std::uint32_t>(partial_prefix.size()),
                    .packet_original_length = static_cast<std::uint32_t>(partial_prefix.size()),
                },
            }},
            8U,
            session_detail::TlsStreamScannerFinishMode::window_end
        );
        PFL_EXPECT(window_result.stable_rows.empty());
        PFL_REQUIRE(window_result.provisional_row.has_value());
        PFL_EXPECT(window_result.provisional_row->item.stability == StreamMaterializationStability::window_incomplete);

        auto end_state = session_detail::make_tls_stream_scanner_state(Direction::a_to_b, true);
        const auto end_result = session_detail::consume_tls_stream_scanner(
            end_state,
            std::array<session_detail::TlsStreamScannerContribution, 1U> {{
                {
                    .packet_index = 400U,
                    .flow_packet_index = 1U,
                    .captured_bytes = partial_prefix,
                    .original_byte_count = partial_prefix.size(),
                    .packet_captured_length = static_cast<std::uint32_t>(partial_prefix.size()),
                    .packet_original_length = static_cast<std::uint32_t>(partial_prefix.size()),
                },
            }},
            8U,
            session_detail::TlsStreamScannerFinishMode::flow_end
        );
        PFL_REQUIRE(end_result.stable_rows.size() == 1U);
        PFL_EXPECT(!end_result.provisional_row.has_value());
        PFL_EXPECT(end_result.stable_rows[0].item.label.find("(partial)") != std::string::npos);
    }

    const auto bounded_stream_path = write_temp_pcap(
        "pfl_stream_query_bounded_rows.pcap",
        make_classic_pcap(bounded_stream_packets)
    );

    CaptureSession bounded_stream_session {};
    PFL_EXPECT(bounded_stream_session.open_capture(bounded_stream_path, fast_options));
    PFL_EXPECT(bounded_stream_session.flow_stream_item_count(0) == 31U);

    const auto initial_stream_rows = bounded_stream_session.list_flow_stream_items(0, 0U, 15U);
    PFL_EXPECT(initial_stream_rows.size() == 15U);
    PFL_EXPECT(initial_stream_rows.front().stream_item_index == 1U);
    PFL_EXPECT(initial_stream_rows.back().stream_item_index == 15U);
    PFL_EXPECT(initial_stream_rows.front().label == "TCP Payload");

    const auto next_stream_rows = bounded_stream_session.list_flow_stream_items(0, 15U, 15U);
    PFL_EXPECT(next_stream_rows.size() == 15U);
    PFL_EXPECT(next_stream_rows.front().stream_item_index == 16U);
    PFL_EXPECT(next_stream_rows.back().stream_item_index == 30U);

    const auto tail_stream_rows = bounded_stream_session.list_flow_stream_items(0, 30U, 15U);
    PFL_EXPECT(tail_stream_rows.size() == 1U);
    PFL_EXPECT(tail_stream_rows.front().stream_item_index == 31U);

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/tls/tls_normal_1.pcap"), fast_options));

        const auto rows = session.list_flow_stream_items(0);
        const auto bounded_rows = session.list_flow_stream_items_for_packet_prefix(0, 30U, 4U);
        PFL_EXPECT(!rows.empty());
        PFL_EXPECT(!bounded_rows.empty());
        PFL_EXPECT(bounded_rows.size() == 4U);
        for (std::size_t index = 0U; index < bounded_rows.size(); ++index) {
            PFL_EXPECT(bounded_rows[index].label == rows[index].label);
            PFL_EXPECT(bounded_rows[index].byte_count == rows[index].byte_count);
            PFL_EXPECT(bounded_rows[index].direction_text == rows[index].direction_text);
            PFL_EXPECT(bounded_rows[index].packet_indices == rows[index].packet_indices);
        }

        const auto* client_hello = find_stream_row_by_label(rows, "TLS ClientHello");
        const auto* server_hello = find_stream_row_by_label(rows, "TLS ServerHello");
        const auto* change_cipher_spec = find_stream_row_by_label(rows, "TLS ChangeCipherSpec");
        PFL_EXPECT(client_hello != nullptr);
        PFL_EXPECT(server_hello != nullptr);
        PFL_EXPECT(change_cipher_spec != nullptr);
        PFL_EXPECT(!client_hello->protocol_text.empty());
        PFL_EXPECT(!client_hello->payload_hex_text.empty());
        PFL_EXPECT(client_hello->protocol_text.find("Handshake Version:") != std::string::npos);
        PFL_EXPECT(client_hello->protocol_text.find("Cipher Suites:") != std::string::npos);
        PFL_EXPECT(client_hello->protocol_text.find("Extensions:") != std::string::npos);
        PFL_EXPECT(client_hello->protocol_text.find("SNI:") != std::string::npos);
        PFL_EXPECT(!server_hello->protocol_text.empty());
        PFL_EXPECT(!server_hello->payload_hex_text.empty());
        PFL_EXPECT(server_hello->protocol_text.find("Selected TLS Version:") != std::string::npos);
        PFL_EXPECT(server_hello->protocol_text.find("Selected Cipher Suite:") != std::string::npos);
        PFL_EXPECT(server_hello->protocol_text.find("Extensions:") != std::string::npos);
        PFL_EXPECT(!change_cipher_spec->protocol_text.empty());
        PFL_EXPECT(!change_cipher_spec->payload_hex_text.empty());
        PFL_EXPECT(std::none_of(bounded_rows.begin(), bounded_rows.end(), [](const StreamItemRow& row) {
            return starts_with(row.label, "HTTP");
        }));

        const auto data_like_it = std::find_if(rows.begin(), rows.end(), [](const StreamItemRow& row) {
            return row.label == "TLS AppData" || row.label == "TLS Payload";
        });
        PFL_EXPECT(data_like_it != rows.end());
        PFL_EXPECT(!data_like_it->protocol_text.empty());
        PFL_EXPECT(!data_like_it->payload_hex_text.empty());
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/tls/tls_client_hello_1.pcap"), fast_options));

        const auto packet_rows = session.list_flow_packets(0);
        PFL_EXPECT(packet_rows.size() == 1U);
        const auto rows = session.list_flow_stream_items(0);
        PFL_EXPECT(rows.size() == 1U);
        const auto packet = session.find_packet(0U);
        PFL_REQUIRE(packet.has_value());
        const auto packet_protocol_text = session.read_packet_protocol_details_text(*packet);

        PFL_EXPECT(rows[0].label == "TLS ClientHello");
        PFL_EXPECT(rows[0].byte_count == 517U);
        PFL_EXPECT(rows[0].packet_count == 1U);
        PFL_EXPECT(rows[0].packet_indices == std::vector<std::uint64_t> {0U});
        PFL_EXPECT(rows[0].direction_text == direction_for_packet(packet_rows, 0U));
        PFL_EXPECT(rows[0].tls_semantic_kind == TlsStreamItemSemanticKind::plaintext_handshake);
        PFL_EXPECT(!rows[0].payload_hex_text.empty());
        PFL_EXPECT(!rows[0].protocol_text.empty());
        const auto stream_summary_layers = build_stream_summary_layers(rows[0], packet_rows);
        const auto* stream_item_layer = find_top_level_summary_layer(stream_summary_layers, "stream_item");
        const auto* stream_tls_layer = find_top_level_summary_layer(stream_summary_layers, "tls");
        PFL_REQUIRE(stream_item_layer != nullptr);
        PFL_REQUIRE(stream_tls_layer != nullptr);
        PFL_EXPECT(require_summary_field_value(*stream_item_layer, "Label") == "TLS ClientHello");
        PFL_EXPECT(require_summary_field_value(*stream_item_layer, "Size") == "517 bytes");
        PFL_EXPECT(require_summary_field_value(*stream_item_layer, "Source packet") == "#1");
        PFL_EXPECT(require_summary_field_value(*stream_item_layer, "Details source") == "Stream item");
        PFL_EXPECT(require_summary_field_value(*stream_tls_layer, "Record Length") == "512");
        PFL_EXPECT(require_summary_field_value(*stream_tls_layer, "Total Record Size") == "517 bytes");
        PFL_EXPECT(require_summary_field_value(*stream_tls_layer, "Record Legacy Version") == "TLS 1.0 (0x0301)");
        PFL_EXPECT(require_summary_field_value(*stream_tls_layer, "Handshake Length") == "508");
        PFL_EXPECT(require_summary_field_value(*stream_tls_layer, "ClientHello Legacy Version") == "TLS 1.2 (0x0303)");
        PFL_EXPECT(require_summary_field_value(*stream_tls_layer, "Session ID Length") == "32");
        PFL_EXPECT(require_summary_field_value(*stream_tls_layer, "Cipher Suite Count") == "16");
        PFL_EXPECT(require_summary_field_value(*stream_tls_layer, "Compression Method Count") == "1");
        PFL_EXPECT(require_summary_field_value(*stream_tls_layer, "Extension Count") == "18");
        PFL_EXPECT(require_summary_field_value(*stream_tls_layer, "SNI") == "auth.split.io");
        PFL_EXPECT(require_summary_field_value(*stream_tls_layer, "ALPN") == "h2, http/1.1");
        PFL_EXPECT(require_summary_field_value(*stream_tls_layer, "Supported TLS Versions").find("TLS 1.3 (0x0304)") != std::string::npos);
        PFL_EXPECT(require_summary_field_value(*stream_tls_layer, "Supported TLS Versions").find("TLS 1.2 (0x0303)") != std::string::npos);
        const auto* stream_cipher_suites_group = require_summary_child(*stream_tls_layer, "tls_cipher_suites");
        const auto* stream_compression_methods_group = require_summary_child(*stream_tls_layer, "tls_compression_methods");
        const auto* stream_extensions_group = require_summary_child(*stream_tls_layer, "tls_extensions");
        PFL_EXPECT(stream_cipher_suites_group->title == "Cipher Suites (16)");
        PFL_EXPECT(stream_cipher_suites_group->children.empty());
        expect_indexed_summary_field_values(*stream_cipher_suites_group, {
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
        PFL_EXPECT(stream_compression_methods_group->title == "Compression Methods (1)");
        PFL_EXPECT(stream_compression_methods_group->children.empty());
        expect_indexed_summary_field_values(*stream_compression_methods_group, {"null (0)"});
        PFL_EXPECT(stream_extensions_group->title == "Extensions (18)");
        expect_summary_child_titles(*stream_extensions_group, {
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
        PFL_EXPECT(require_summary_field_value(stream_extensions_group->children[0], "Type") == "64250 (0xfafa)");
        PFL_EXPECT(require_summary_field_value(stream_extensions_group->children[16], "Type") == "39578 (0x9a9a)");
        PFL_EXPECT(find_summary_child(stream_extensions_group->children[1], "tls_server_names") == nullptr);
        PFL_EXPECT(find_summary_child(stream_extensions_group->children[7], "tls_alpn_protocols") == nullptr);
        PFL_EXPECT(find_summary_child(stream_extensions_group->children[13], "tls_supported_versions") == nullptr);
        PFL_EXPECT(require_summary_field_value(stream_extensions_group->children[1], "Server Name [0]") == "auth.split.io");
        PFL_EXPECT(require_summary_field_value(stream_extensions_group->children[7], "ALPN [0]") == "h2");
        PFL_EXPECT(require_summary_field_value(stream_extensions_group->children[7], "ALPN [1]") == "http/1.1");
        PFL_EXPECT(require_summary_field_value(stream_extensions_group->children[4], "Group [0]") == "GREASE (0x5a5a)");
        PFL_EXPECT(require_summary_field_value(stream_extensions_group->children[4], "Group [1]") == "x25519 (0x001d)");
        PFL_EXPECT(require_summary_field_value(stream_extensions_group->children[4], "Group [2]") == "secp256r1 (0x0017)");
        PFL_EXPECT(require_summary_field_value(stream_extensions_group->children[4], "Group [3]") == "secp384r1 (0x0018)");
        PFL_EXPECT(require_summary_field_value(stream_extensions_group->children[8], "Status Type") == "OCSP (1)");
        PFL_EXPECT(require_summary_field_value(stream_extensions_group->children[8], "Responder ID List Length") == "0");
        PFL_EXPECT(require_summary_field_value(stream_extensions_group->children[8], "Request Extensions Length") == "0");
        PFL_EXPECT(require_summary_field_value(stream_extensions_group->children[9], "Signature Scheme [0]") == "ecdsa_secp256r1_sha256 (0x0403)");
        PFL_EXPECT(require_summary_field_value(stream_extensions_group->children[9], "Signature Scheme [1]") == "rsa_pss_rsae_sha256 (0x0804)");
        PFL_EXPECT(require_summary_field_value(stream_extensions_group->children[9], "Signature Scheme [2]") == "rsa_pkcs1_sha256 (0x0401)");
        PFL_EXPECT(require_summary_field_value(stream_extensions_group->children[9], "Signature Scheme [3]") == "ecdsa_secp384r1_sha384 (0x0503)");
        PFL_EXPECT(require_summary_field_value(stream_extensions_group->children[9], "Signature Scheme [4]") == "rsa_pss_rsae_sha384 (0x0805)");
        PFL_EXPECT(require_summary_field_value(stream_extensions_group->children[9], "Signature Scheme [5]") == "rsa_pkcs1_sha384 (0x0501)");
        PFL_EXPECT(require_summary_field_value(stream_extensions_group->children[9], "Signature Scheme [6]") == "rsa_pss_rsae_sha512 (0x0806)");
        PFL_EXPECT(require_summary_field_value(stream_extensions_group->children[9], "Signature Scheme [7]") == "rsa_pkcs1_sha512 (0x0601)");
        const auto* key_share_entry0 = require_summary_child(stream_extensions_group->children[11], "tls_key_share_entry", 0U);
        const auto* key_share_entry1 = require_summary_child(stream_extensions_group->children[11], "tls_key_share_entry", 1U);
        PFL_EXPECT(key_share_entry0->title == "[0] GREASE (0x5a5a), 1 byte");
        PFL_EXPECT(key_share_entry1->title == "[1] x25519 (0x001d), 32 bytes");
        PFL_EXPECT(require_summary_field_value(*key_share_entry0, "Group") == "GREASE (0x5a5a)");
        PFL_EXPECT(require_summary_field_value(*key_share_entry0, "Key Exchange Length") == "1 byte");
        PFL_EXPECT(require_summary_field_value(*key_share_entry1, "Group") == "x25519 (0x001d)");
        PFL_EXPECT(require_summary_field_value(*key_share_entry1, "Key Exchange Length") == "32 bytes");
        PFL_EXPECT(require_summary_field_value(stream_extensions_group->children[12], "Mode [0]") == "psk_dhe_ke (1)");
        PFL_EXPECT(require_summary_field_value(stream_extensions_group->children[13], "Version [0]") == "GREASE (0x5a5a)");
        PFL_EXPECT(require_summary_field_value(stream_extensions_group->children[13], "Version [1]") == "TLS 1.3 (0x0304)");
        PFL_EXPECT(require_summary_field_value(stream_extensions_group->children[13], "Version [2]") == "TLS 1.2 (0x0303)");
        PFL_EXPECT(require_summary_field_value(stream_extensions_group->children[14], "Algorithm [0]") == "brotli (2)");
        PFL_EXPECT(require_summary_field_value(stream_extensions_group->children[17], "Padding Length") == "64 bytes");
        const auto packet_summary_layers = build_packet_summary_layers_for_packet(session, *packet);
        const auto* packet_tls_layer = find_top_level_summary_layer(packet_summary_layers, "tls");
        PFL_REQUIRE(packet_tls_layer != nullptr);
        PFL_EXPECT(require_summary_field_value(*stream_tls_layer, "Record Type") == require_summary_field_value(*packet_tls_layer, "Record Type"));
        PFL_EXPECT(require_summary_field_value(*stream_tls_layer, "Record Legacy Version") == require_summary_field_value(*packet_tls_layer, "Record Legacy Version"));
        PFL_EXPECT(require_summary_field_value(*stream_tls_layer, "Record Length") == require_summary_field_value(*packet_tls_layer, "Record Length"));
        PFL_EXPECT(require_summary_field_value(*stream_tls_layer, "Total Record Size") == require_summary_field_value(*packet_tls_layer, "Total Record Size"));
        PFL_EXPECT(require_summary_field_value(*stream_tls_layer, "Handshake Type") == require_summary_field_value(*packet_tls_layer, "Handshake Type"));
        PFL_EXPECT(require_summary_field_value(*stream_tls_layer, "Handshake Length") == require_summary_field_value(*packet_tls_layer, "Handshake Length"));
        PFL_EXPECT(require_summary_field_value(*stream_tls_layer, "SNI") == require_summary_field_value(*packet_tls_layer, "SNI"));
        PFL_EXPECT(require_summary_field_value(*stream_tls_layer, "Supported TLS Versions") == require_summary_field_value(*packet_tls_layer, "Supported TLS Versions"));
        expect_summary_layer_semantic_match(*stream_cipher_suites_group, *require_summary_child(*packet_tls_layer, "tls_cipher_suites"));
        expect_summary_layer_semantic_match(*stream_compression_methods_group, *require_summary_child(*packet_tls_layer, "tls_compression_methods"));
        expect_summary_layer_semantic_match(*stream_extensions_group, *require_summary_child(*packet_tls_layer, "tls_extensions"));
        expect_matching_protocol_detail(packet_protocol_text, rows[0].protocol_text, "Record Type:");
        expect_matching_protocol_detail(packet_protocol_text, rows[0].protocol_text, "Record Version:");
        expect_matching_protocol_detail(packet_protocol_text, rows[0].protocol_text, "Record Length:");
        expect_matching_protocol_detail(packet_protocol_text, rows[0].protocol_text, "Handshake Type:");
        expect_matching_protocol_detail(packet_protocol_text, rows[0].protocol_text, "Handshake Length:");
        expect_matching_protocol_detail(packet_protocol_text, rows[0].protocol_text, "Handshake Version:");
        expect_matching_protocol_detail(packet_protocol_text, rows[0].protocol_text, "SNI:");
        expect_matching_protocol_detail(packet_protocol_text, rows[0].protocol_text, "ALPN:");
        expect_matching_protocol_detail(packet_protocol_text, rows[0].protocol_text, "Supported Versions:");
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/tls/tls_1_3_client_hello_5.pcap"), fast_options));

        const auto packet_rows = session.list_flow_packets(0);
        PFL_EXPECT(packet_rows.size() == 1U);
        const auto rows = session.list_flow_stream_items(0);
        PFL_EXPECT(rows.size() == 1U);
        const auto packet = session.find_packet(0U);
        PFL_REQUIRE(packet.has_value());
        const auto packet_protocol_text = session.read_packet_protocol_details_text(*packet);

        PFL_EXPECT(rows[0].label == "TLS ClientHello");
        PFL_EXPECT(rows[0].byte_count == 517U);
        PFL_EXPECT(rows[0].packet_count == 1U);
        PFL_EXPECT(rows[0].packet_indices == std::vector<std::uint64_t> {0U});
        PFL_EXPECT(rows[0].direction_text == direction_for_packet(packet_rows, 0U));
        PFL_EXPECT(!rows[0].payload_hex_text.empty());
        PFL_EXPECT(!rows[0].protocol_text.empty());
        const auto stream_summary_layers = build_stream_summary_layers(rows[0], packet_rows);
        const auto* stream_tls_layer = find_top_level_summary_layer(stream_summary_layers, "tls");
        PFL_REQUIRE(stream_tls_layer != nullptr);
        PFL_EXPECT(require_summary_field_value(*stream_tls_layer, "Cipher Suite Count") == "21");
        PFL_EXPECT(require_summary_field_value(*stream_tls_layer, "Extension Count") == "16");
        PFL_EXPECT(require_summary_field_value(*stream_tls_layer, "SNI") == "p101-fmf.icloud.com");
        PFL_EXPECT(require_summary_field_value(*stream_tls_layer, "ALPN") == "h2, http/1.1");
        PFL_EXPECT(require_summary_field_value(*stream_tls_layer, "Supported TLS Versions").find("TLS 1.3 (0x0304)") != std::string::npos);
        PFL_EXPECT(require_summary_field_value(*stream_tls_layer, "Supported TLS Versions").find("TLS 1.0 (0x0301)") != std::string::npos);
        const auto* stream_cipher_suites_group = require_summary_child(*stream_tls_layer, "tls_cipher_suites");
        const auto* stream_compression_methods_group = require_summary_child(*stream_tls_layer, "tls_compression_methods");
        const auto* stream_extensions_group = require_summary_child(*stream_tls_layer, "tls_extensions");
        PFL_EXPECT(stream_cipher_suites_group->title == "Cipher Suites (21)");
        PFL_EXPECT(stream_cipher_suites_group->children.empty());
        expect_indexed_summary_field_values(*stream_cipher_suites_group, {
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
            "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA (0xc012)",
            "TLS_RSA_WITH_AES_128_GCM_SHA256 (0x009c)",
            "TLS_RSA_WITH_AES_256_GCM_SHA384 (0x009d)",
            "TLS_RSA_WITH_AES_128_CBC_SHA (0x002f)",
            "TLS_RSA_WITH_AES_256_CBC_SHA (0x0035)",
            "TLS_RSA_WITH_3DES_EDE_CBC_SHA (0x000a)",
            "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA (0xc009)",
            "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA (0xc00a)",
            "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA (0xc008)",
        });
        PFL_EXPECT(stream_compression_methods_group->title == "Compression Methods (1)");
        PFL_EXPECT(stream_compression_methods_group->children.empty());
        expect_indexed_summary_field_values(*stream_compression_methods_group, {"null (0)"});
        PFL_EXPECT(stream_extensions_group->title == "Extensions (16)");
        expect_summary_child_titles(*stream_extensions_group, {
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
        PFL_EXPECT(require_summary_field_value(stream_extensions_group->children[0], "Type") == "39578 (0x9a9a)");
        PFL_EXPECT(require_summary_field_value(stream_extensions_group->children[14], "Type") == "2570 (0x0a0a)");
        PFL_EXPECT(find_summary_child(stream_extensions_group->children[1], "tls_server_names") == nullptr);
        PFL_EXPECT(find_summary_child(stream_extensions_group->children[6], "tls_alpn_protocols") == nullptr);
        PFL_EXPECT(find_summary_child(stream_extensions_group->children[12], "tls_supported_versions") == nullptr);
        PFL_EXPECT(require_summary_field_value(stream_extensions_group->children[1], "Server Name [0]") == "p101-fmf.icloud.com");
        PFL_EXPECT(require_summary_field_value(stream_extensions_group->children[6], "ALPN [0]") == "h2");
        PFL_EXPECT(require_summary_field_value(stream_extensions_group->children[6], "ALPN [1]") == "http/1.1");
        PFL_EXPECT(require_summary_field_value(stream_extensions_group->children[4], "Group [0]") == "GREASE (0x4a4a)");
        PFL_EXPECT(require_summary_field_value(stream_extensions_group->children[4], "Group [1]") == "x25519 (0x001d)");
        PFL_EXPECT(require_summary_field_value(stream_extensions_group->children[4], "Group [2]") == "secp256r1 (0x0017)");
        PFL_EXPECT(require_summary_field_value(stream_extensions_group->children[4], "Group [3]") == "secp384r1 (0x0018)");
        PFL_EXPECT(require_summary_field_value(stream_extensions_group->children[4], "Group [4]") == "secp521r1 (0x0019)");
        PFL_EXPECT(require_summary_field_value(stream_extensions_group->children[7], "Status Type") == "OCSP (1)");
        PFL_EXPECT(require_summary_field_value(stream_extensions_group->children[7], "Responder ID List Length") == "0");
        PFL_EXPECT(require_summary_field_value(stream_extensions_group->children[7], "Request Extensions Length") == "0");
        PFL_EXPECT(require_summary_field_value(stream_extensions_group->children[8], "Signature Scheme [0]") == "ecdsa_secp256r1_sha256 (0x0403)");
        PFL_EXPECT(require_summary_field_value(stream_extensions_group->children[8], "Signature Scheme [1]") == "rsa_pss_rsae_sha256 (0x0804)");
        PFL_EXPECT(require_summary_field_value(stream_extensions_group->children[8], "Signature Scheme [2]") == "rsa_pkcs1_sha256 (0x0401)");
        PFL_EXPECT(require_summary_field_value(stream_extensions_group->children[8], "Signature Scheme [3]") == "ecdsa_secp384r1_sha384 (0x0503)");
        PFL_EXPECT(require_summary_field_value(stream_extensions_group->children[8], "Signature Scheme [4]") == "rsa_pss_rsae_sha384 (0x0805)");
        PFL_EXPECT(require_summary_field_value(stream_extensions_group->children[8], "Signature Scheme [5]") == "rsa_pss_rsae_sha384 (0x0805)");
        PFL_EXPECT(require_summary_field_value(stream_extensions_group->children[8], "Signature Scheme [6]") == "rsa_pkcs1_sha384 (0x0501)");
        PFL_EXPECT(require_summary_field_value(stream_extensions_group->children[8], "Signature Scheme [7]") == "rsa_pss_rsae_sha512 (0x0806)");
        PFL_EXPECT(require_summary_field_value(stream_extensions_group->children[8], "Signature Scheme [8]") == "rsa_pkcs1_sha512 (0x0601)");
        PFL_EXPECT(require_summary_field_value(stream_extensions_group->children[8], "Signature Scheme [9]") == "rsa_pkcs1_sha1 (0x0201)");
        const auto* key_share_entry0 = require_summary_child(stream_extensions_group->children[10], "tls_key_share_entry", 0U);
        const auto* key_share_entry1 = require_summary_child(stream_extensions_group->children[10], "tls_key_share_entry", 1U);
        PFL_EXPECT(key_share_entry0->title == "[0] GREASE (0x4a4a), 1 byte");
        PFL_EXPECT(key_share_entry1->title == "[1] x25519 (0x001d), 32 bytes");
        PFL_EXPECT(require_summary_field_value(*key_share_entry0, "Group") == "GREASE (0x4a4a)");
        PFL_EXPECT(require_summary_field_value(*key_share_entry0, "Key Exchange Length") == "1 byte");
        PFL_EXPECT(require_summary_field_value(*key_share_entry1, "Group") == "x25519 (0x001d)");
        PFL_EXPECT(require_summary_field_value(*key_share_entry1, "Key Exchange Length") == "32 bytes");
        PFL_EXPECT(require_summary_field_value(stream_extensions_group->children[11], "Mode [0]") == "psk_dhe_ke (1)");
        PFL_EXPECT(require_summary_field_value(stream_extensions_group->children[12], "Version [0]") == "GREASE (0x3a3a)");
        PFL_EXPECT(require_summary_field_value(stream_extensions_group->children[12], "Version [1]") == "TLS 1.3 (0x0304)");
        PFL_EXPECT(require_summary_field_value(stream_extensions_group->children[12], "Version [2]") == "TLS 1.2 (0x0303)");
        PFL_EXPECT(require_summary_field_value(stream_extensions_group->children[12], "Version [3]") == "TLS 1.1 (0x0302)");
        PFL_EXPECT(require_summary_field_value(stream_extensions_group->children[12], "Version [4]") == "TLS 1.0 (0x0301)");
        PFL_EXPECT(require_summary_field_value(stream_extensions_group->children[13], "Algorithm [0]") == "zlib (1)");
        PFL_EXPECT(require_summary_field_value(stream_extensions_group->children[15], "Padding Length") == "189 bytes");
        const auto packet_summary_layers = build_packet_summary_layers_for_packet(session, *packet);
        const auto* packet_tls_layer = find_top_level_summary_layer(packet_summary_layers, "tls");
        PFL_REQUIRE(packet_tls_layer != nullptr);
        PFL_EXPECT(require_summary_field_value(*stream_tls_layer, "SNI") == require_summary_field_value(*packet_tls_layer, "SNI"));
        PFL_EXPECT(require_summary_field_value(*stream_tls_layer, "ALPN") == require_summary_field_value(*packet_tls_layer, "ALPN"));
        PFL_EXPECT(require_summary_field_value(*stream_tls_layer, "Supported TLS Versions") ==
            require_summary_field_value(*packet_tls_layer, "Supported TLS Versions"));
        expect_summary_layer_semantic_match(*stream_cipher_suites_group, *require_summary_child(*packet_tls_layer, "tls_cipher_suites"));
        expect_summary_layer_semantic_match(
            *stream_compression_methods_group,
            *require_summary_child(*packet_tls_layer, "tls_compression_methods")
        );
        expect_summary_layer_semantic_match(*stream_extensions_group, *require_summary_child(*packet_tls_layer, "tls_extensions"));
        expect_matching_protocol_detail(packet_protocol_text, rows[0].protocol_text, "Record Type:");
        expect_matching_protocol_detail(packet_protocol_text, rows[0].protocol_text, "Record Version:");
        expect_matching_protocol_detail(packet_protocol_text, rows[0].protocol_text, "Record Length:");
        expect_matching_protocol_detail(packet_protocol_text, rows[0].protocol_text, "Handshake Type:");
        expect_matching_protocol_detail(packet_protocol_text, rows[0].protocol_text, "Handshake Length:");
        expect_matching_protocol_detail(packet_protocol_text, rows[0].protocol_text, "Handshake Version:");
        expect_matching_protocol_detail(packet_protocol_text, rows[0].protocol_text, "SNI:");
        expect_matching_protocol_detail(packet_protocol_text, rows[0].protocol_text, "ALPN:");
        expect_matching_protocol_detail(packet_protocol_text, rows[0].protocol_text, "Supported Versions:");
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/tls/tls_1_2_server_hello_4.pcap"), fast_options));

        const auto packet_rows = session.list_flow_packets(0);
        PFL_EXPECT(packet_rows.size() == 1U);
        const auto rows = session.list_flow_stream_items(0);
        PFL_EXPECT(rows.size() == 1U);
        const auto packet = session.find_packet(0U);
        PFL_REQUIRE(packet.has_value());
        const auto packet_protocol_text = session.read_packet_protocol_details_text(*packet);

        PFL_EXPECT(rows[0].label == "TLS ServerHello");
        PFL_EXPECT(rows[0].byte_count == 96U);
        PFL_EXPECT(rows[0].packet_count == 1U);
        PFL_EXPECT(rows[0].packet_indices == std::vector<std::uint64_t> {0U});
        PFL_EXPECT(rows[0].direction_text == direction_for_packet(packet_rows, 0U));
        PFL_EXPECT(rows[0].tls_semantic_kind == TlsStreamItemSemanticKind::plaintext_handshake);
        PFL_EXPECT(!rows[0].payload_hex_text.empty());
        PFL_EXPECT(!rows[0].protocol_text.empty());
        const auto stream_summary_layers = build_stream_summary_layers(rows[0], packet_rows);
        const auto* stream_tls_layer = find_top_level_summary_layer(stream_summary_layers, "tls");
        PFL_REQUIRE(stream_tls_layer != nullptr);
        PFL_EXPECT(require_summary_field_value(*stream_tls_layer, "Record Length") == "91");
        PFL_EXPECT(require_summary_field_value(*stream_tls_layer, "Total Record Size") == "96 bytes");
        PFL_EXPECT(require_summary_field_value(*stream_tls_layer, "Handshake Length") == "87");
        PFL_EXPECT(require_summary_field_value(*stream_tls_layer, "ServerHello Legacy Version") == "TLS 1.2 (0x0303)");
        PFL_EXPECT(require_summary_field_value(*stream_tls_layer, "Selected TLS Version") == "TLS 1.2 (0x0303)");
        PFL_EXPECT(require_summary_field_value(*stream_tls_layer, "Selected Cipher Suite") ==
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xc02f)");
        PFL_EXPECT(require_summary_field_value(*stream_tls_layer, "Session ID Length") == "32");
        PFL_EXPECT(require_summary_field_value(*stream_tls_layer, "Compression Method") == "null (0)");
        PFL_EXPECT(require_summary_field_value(*stream_tls_layer, "Extension Count") == "3");
        const auto* stream_extensions_group = require_summary_child(*stream_tls_layer, "tls_extensions");
        PFL_EXPECT(stream_extensions_group->title == "Extensions (3)");
        expect_summary_child_titles(*stream_extensions_group, {
            "[0] ec_point_formats (0x000b), 2 bytes",
            "[1] renegotiation_info (0xff01), 1 byte",
            "[2] extended_master_secret (0x0017), 0 bytes",
        });
        PFL_EXPECT(require_summary_field_value(stream_extensions_group->children[0], "Type") == "11 (0x000b)");
        PFL_EXPECT(require_summary_field_value(stream_extensions_group->children[0], "Length") == "2");
        PFL_EXPECT(require_summary_field_value(stream_extensions_group->children[1], "Type") == "65281 (0xff01)");
        PFL_EXPECT(require_summary_field_value(stream_extensions_group->children[1], "Length") == "1");
        PFL_EXPECT(require_summary_field_value(stream_extensions_group->children[2], "Type") == "23 (0x0017)");
        PFL_EXPECT(require_summary_field_value(stream_extensions_group->children[2], "Length") == "0");
        const auto packet_summary_layers = build_packet_summary_layers_for_packet(session, *packet);
        const auto* packet_tls_layer = find_top_level_summary_layer(packet_summary_layers, "tls");
        PFL_REQUIRE(packet_tls_layer != nullptr);
        PFL_EXPECT(require_summary_field_value(*stream_tls_layer, "Selected TLS Version") ==
            require_summary_field_value(*packet_tls_layer, "Selected TLS Version"));
        PFL_EXPECT(require_summary_field_value(*stream_tls_layer, "Selected Cipher Suite") ==
            require_summary_field_value(*packet_tls_layer, "Selected Cipher Suite"));
        expect_summary_layer_semantic_match(*stream_extensions_group, *require_summary_child(*packet_tls_layer, "tls_extensions"));
        expect_matching_protocol_detail(packet_protocol_text, rows[0].protocol_text, "Record Type:");
        expect_matching_protocol_detail(packet_protocol_text, rows[0].protocol_text, "Record Version:");
        expect_matching_protocol_detail(packet_protocol_text, rows[0].protocol_text, "Record Length:");
        expect_matching_protocol_detail(packet_protocol_text, rows[0].protocol_text, "Handshake Type:");
        expect_matching_protocol_detail(packet_protocol_text, rows[0].protocol_text, "Handshake Length:");
        expect_matching_protocol_detail(packet_protocol_text, rows[0].protocol_text, "Selected TLS Version:");
        expect_matching_protocol_detail(packet_protocol_text, rows[0].protocol_text, "Selected Cipher Suite:");
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/tls/tls_1_3_server_hello_6.pcap"), fast_options));

        const auto packet_rows = session.list_flow_packets(0);
        PFL_EXPECT(packet_rows.size() == 1U);
        const auto rows = session.list_flow_stream_items(0);
        PFL_EXPECT(rows.size() == 3U);
        const auto packet = session.find_packet(0U);
        PFL_REQUIRE(packet.has_value());
        const auto packet_protocol_text = session.read_packet_protocol_details_text(*packet);

        PFL_EXPECT(rows[0].label == "TLS ServerHello");
        PFL_EXPECT(rows[0].byte_count == 1215U);
        PFL_EXPECT(rows[0].packet_count == 1U);
        PFL_EXPECT(rows[0].packet_indices == std::vector<std::uint64_t> {0U});
        PFL_EXPECT(rows[0].direction_text == direction_for_packet(packet_rows, 0U));
        const auto server_hello_summary_layers = build_stream_summary_layers(rows[0], packet_rows);
        const auto* server_hello_stream_item_layer = find_top_level_summary_layer(server_hello_summary_layers, "stream_item");
        const auto* server_hello_tls_layer = find_top_level_summary_layer(server_hello_summary_layers, "tls");
        PFL_REQUIRE(server_hello_stream_item_layer != nullptr);
        PFL_REQUIRE(server_hello_tls_layer != nullptr);
        PFL_EXPECT(require_summary_field_value(*server_hello_stream_item_layer, "Label") == "TLS ServerHello");
        PFL_EXPECT(require_summary_field_value(*server_hello_stream_item_layer, "Size") == "1215 bytes");
        PFL_EXPECT(require_summary_field_value(*server_hello_stream_item_layer, "Source packet") == "#1");
        PFL_EXPECT(require_summary_field_value(*server_hello_tls_layer, "Record Length") == "1210");
        PFL_EXPECT(require_summary_field_value(*server_hello_tls_layer, "Total Record Size") == "1215 bytes");
        PFL_EXPECT(require_summary_field_value(*server_hello_tls_layer, "Handshake Length") == "1206");
        const auto* stream_extensions_group = require_summary_child(*server_hello_tls_layer, "tls_extensions");
        PFL_EXPECT(stream_extensions_group->title == "Extensions (2)");
        expect_summary_child_titles(*stream_extensions_group, {
            "[0] key_share (0x0033), 1124 bytes - X25519MLKEM768, 1120 bytes",
            "[1] supported_versions (0x002b), 2 bytes - TLS 1.3 (0x0304)",
        });
        PFL_EXPECT(require_summary_field_value(stream_extensions_group->children[0], "Type") == "51 (0x0033)");
        PFL_EXPECT(require_summary_field_value(stream_extensions_group->children[0], "Length") == "1124");
        PFL_EXPECT(require_summary_field_value(stream_extensions_group->children[1], "Type") == "43 (0x002b)");
        PFL_EXPECT(require_summary_field_value(stream_extensions_group->children[1], "Length") == "2");
        const auto* key_share_entry = require_summary_child(stream_extensions_group->children[0], "tls_key_share_entry");
        PFL_EXPECT(key_share_entry->title == "[0] X25519MLKEM768 (0x11ec), 1120 bytes");
        PFL_EXPECT(require_summary_field_value(*key_share_entry, "Group") == "X25519MLKEM768 (0x11ec)");
        PFL_EXPECT(require_summary_field_value(*key_share_entry, "Key Exchange Length") == "1120 bytes");
        PFL_EXPECT(find_summary_child(stream_extensions_group->children[1], "tls_supported_versions") == nullptr);
        PFL_EXPECT(require_summary_field_value(stream_extensions_group->children[1], "Version [0]") == "TLS 1.3 (0x0304)");
        const auto packet_summary_layers = build_packet_summary_layers_for_packet(session, *packet);
        const auto* packet_server_hello_tls_layer = find_top_level_summary_layer(packet_summary_layers, "tls");
        PFL_REQUIRE(packet_server_hello_tls_layer != nullptr);
        expect_summary_layer_semantic_match(*stream_extensions_group, *require_summary_child(*packet_server_hello_tls_layer, "tls_extensions"));
        expect_matching_protocol_detail(packet_protocol_text, rows[0].protocol_text, "Record Type:");
        expect_matching_protocol_detail(packet_protocol_text, rows[0].protocol_text, "Record Version:");
        expect_matching_protocol_detail(packet_protocol_text, rows[0].protocol_text, "Record Length:");
        expect_matching_protocol_detail(packet_protocol_text, rows[0].protocol_text, "Handshake Type:");
        expect_matching_protocol_detail(packet_protocol_text, rows[0].protocol_text, "Handshake Length:");
        expect_matching_protocol_detail(packet_protocol_text, rows[0].protocol_text, "Selected TLS Version:");
        expect_matching_protocol_detail(packet_protocol_text, rows[0].protocol_text, "Selected Cipher Suite:");

        PFL_EXPECT(rows[1].label == "TLS ChangeCipherSpec");
        PFL_EXPECT(rows[1].byte_count == 6U);
        PFL_EXPECT(rows[1].packet_count == 1U);
        PFL_EXPECT(rows[1].packet_indices == std::vector<std::uint64_t> {0U});
        PFL_EXPECT(rows[1].direction_text == direction_for_packet(packet_rows, 0U));
        PFL_EXPECT(rows[1].tls_semantic_kind == TlsStreamItemSemanticKind::change_cipher_spec);
        const auto ccs_summary_layers = build_stream_summary_layers(rows[1], packet_rows);
        const auto* ccs_tls_layer = find_top_level_summary_layer(ccs_summary_layers, "tls");
        PFL_REQUIRE(ccs_tls_layer != nullptr);
        PFL_EXPECT(require_summary_field_value(*ccs_tls_layer, "Record Type") == "ChangeCipherSpec");
        PFL_EXPECT(require_summary_field_value(*ccs_tls_layer, "Record Legacy Version") == "TLS 1.2 (0x0303)");
        PFL_EXPECT(require_summary_field_value(*ccs_tls_layer, "Record Length") == "1");
        PFL_EXPECT(find_summary_field(*ccs_tls_layer, "Handshake Type") == nullptr);
        PFL_EXPECT(find_protocol_detail_value(rows[1].protocol_text, "Record Type:").has_value());
        PFL_EXPECT(*find_protocol_detail_value(rows[1].protocol_text, "Record Type:") == "ChangeCipherSpec");
        PFL_EXPECT(find_protocol_detail_value(rows[1].protocol_text, "Record Version:").has_value());
        PFL_EXPECT(*find_protocol_detail_value(rows[1].protocol_text, "Record Version:") == "TLS 1.2 (0x0303)");
        PFL_EXPECT(find_protocol_detail_value(rows[1].protocol_text, "Record Length:").has_value());
        PFL_EXPECT(*find_protocol_detail_value(rows[1].protocol_text, "Record Length:") == "1");
        PFL_EXPECT(find_protocol_detail_value(rows[1].protocol_text, "Handshake Type:").has_value() == false);

        PFL_EXPECT(rows[2].label == "TLS Record Fragment (partial)");
        PFL_EXPECT(rows[2].byte_count == 179U);
        PFL_EXPECT(rows[2].packet_count == 1U);
        PFL_EXPECT(rows[2].packet_indices == std::vector<std::uint64_t> {0U});
        PFL_EXPECT(rows[2].direction_text == direction_for_packet(packet_rows, 0U));
        PFL_EXPECT(rows[2].tls_semantic_kind == TlsStreamItemSemanticKind::partial_record);
        const auto partial_summary_layers = build_stream_summary_layers(rows[2], packet_rows);
        const auto* partial_tls_layer = find_top_level_summary_layer(partial_summary_layers, "tls");
        PFL_REQUIRE(partial_tls_layer != nullptr);
        PFL_EXPECT(require_summary_field_value(*partial_tls_layer, "Status") == "Incomplete record body");
        PFL_EXPECT(require_summary_field_value(*partial_tls_layer, "Available Bytes") == "179");
        PFL_EXPECT(find_summary_field(*partial_tls_layer, "Handshake Type") == nullptr);
        PFL_EXPECT(find_summary_field(*partial_tls_layer, "Selected TLS Version") == nullptr);
        PFL_EXPECT(find_summary_field(*partial_tls_layer, "Selected Cipher Suite") == nullptr);
        PFL_EXPECT(rows[2].protocol_text.find("complete TLS record") != std::string::npos);
        PFL_EXPECT(find_protocol_detail_value(rows[2].protocol_text, "Record Type:").has_value() == false);
        PFL_EXPECT(find_protocol_detail_value(rows[2].protocol_text, "Handshake Type:").has_value() == false);
        PFL_EXPECT(find_protocol_detail_value(rows[2].protocol_text, "Selected TLS Version:").has_value() == false);
        PFL_EXPECT(find_protocol_detail_value(rows[2].protocol_text, "Selected Cipher Suite:").has_value() == false);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/tls/tls_1_2_app_data_3.pcap"), fast_options));

        const auto packet_rows = session.list_flow_packets(0);
        const auto rows = session.list_flow_stream_items(0);
        PFL_REQUIRE(rows.size() == 1U);
        PFL_EXPECT(rows[0].label == "TLS AppData");
        PFL_EXPECT(rows[0].byte_count == 657U);
        PFL_EXPECT(rows[0].packet_indices == std::vector<std::uint64_t> {0U});
        PFL_EXPECT(rows[0].direction_text == direction_for_packet(packet_rows, 0U));
        PFL_EXPECT(rows[0].tls_semantic_kind == TlsStreamItemSemanticKind::application_data);
        PFL_EXPECT(rows[0].protocol_text.find("Record Type: ApplicationData") != std::string::npos);
        PFL_EXPECT(rows[0].protocol_text.find("Record Version: TLS 1.2 (0x0303)") != std::string::npos);
        PFL_EXPECT(rows[0].protocol_text.find("Record Length: 652") != std::string::npos);
        PFL_EXPECT(find_protocol_detail_value(rows[0].protocol_text, "Handshake Type:").has_value() == false);
        const auto summary_layers = build_stream_summary_layers(rows[0], packet_rows);
        const auto* tls_layer = find_top_level_summary_layer(summary_layers, "tls");
        PFL_REQUIRE(tls_layer != nullptr);
        PFL_EXPECT(require_summary_field_value(*tls_layer, "Record Type") == "ApplicationData");
        PFL_EXPECT(require_summary_field_value(*tls_layer, "Record Legacy Version") == "TLS 1.2 (0x0303)");
        PFL_EXPECT(require_summary_field_value(*tls_layer, "Record Length") == "652");
        PFL_EXPECT(require_summary_field_value(*tls_layer, "Total Record Size") == "657 bytes");
        PFL_EXPECT(find_summary_field(*tls_layer, "Handshake Type") == nullptr);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/tls/tls_1_3_app_data_7.pcap"), fast_options));

        const auto packet_rows = session.list_flow_packets(0);
        const auto rows = session.list_flow_stream_items(0);
        PFL_REQUIRE(rows.size() == 2U);
        PFL_EXPECT(rows[0].label == "TLS AppData");
        PFL_EXPECT(rows[0].byte_count == 916U);
        PFL_EXPECT(rows[0].packet_indices == std::vector<std::uint64_t> {0U});
        PFL_EXPECT(rows[0].direction_text == direction_for_packet(packet_rows, 0U));
        PFL_EXPECT(rows[0].tls_semantic_kind == TlsStreamItemSemanticKind::application_data);
        PFL_EXPECT(rows[0].protocol_text.find("Record Type: ApplicationData") != std::string::npos);
        PFL_EXPECT(rows[0].protocol_text.find("Record Length: 911") != std::string::npos);
        PFL_EXPECT(rows[1].label == "TLS AppData");
        PFL_EXPECT(rows[1].byte_count == 62U);
        PFL_EXPECT(rows[1].packet_indices == std::vector<std::uint64_t> {0U});
        PFL_EXPECT(rows[1].tls_semantic_kind == TlsStreamItemSemanticKind::application_data);
        PFL_EXPECT(rows[1].protocol_text.find("Record Type: ApplicationData") != std::string::npos);
        PFL_EXPECT(rows[1].protocol_text.find("Record Length: 57") != std::string::npos);
        const auto first_summary_layers = build_stream_summary_layers(rows[0], packet_rows);
        const auto second_summary_layers = build_stream_summary_layers(rows[1], packet_rows);
        const auto* first_tls_layer = find_top_level_summary_layer(first_summary_layers, "tls");
        const auto* second_tls_layer = find_top_level_summary_layer(second_summary_layers, "tls");
        PFL_REQUIRE(first_tls_layer != nullptr);
        PFL_REQUIRE(second_tls_layer != nullptr);
        PFL_EXPECT(require_summary_field_value(*first_tls_layer, "Record Length") == "911");
        PFL_EXPECT(require_summary_field_value(*first_tls_layer, "Total Record Size") == "916 bytes");
        PFL_EXPECT(require_summary_field_value(*second_tls_layer, "Record Length") == "57");
        PFL_EXPECT(require_summary_field_value(*second_tls_layer, "Total Record Size") == "62 bytes");
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/tls/tls_1_2_change_cipher_spec_2.pcap"), fast_options));

        const auto packet_rows = session.list_flow_packets(0);
        const auto rows = session.list_flow_stream_items(0);
        PFL_REQUIRE(rows.size() == 2U);
        PFL_EXPECT(rows[0].label == "TLS ChangeCipherSpec");
        PFL_EXPECT(rows[0].byte_count == 6U);
        PFL_EXPECT(rows[0].tls_semantic_kind == TlsStreamItemSemanticKind::change_cipher_spec);
        PFL_EXPECT(rows[0].protocol_text.find("Record Type: ChangeCipherSpec") != std::string::npos);
        PFL_EXPECT(rows[1].label == "TLS Encrypted Handshake Message");
        PFL_EXPECT(rows[1].byte_count == 45U);
        PFL_EXPECT(rows[1].tls_semantic_kind == TlsStreamItemSemanticKind::encrypted_handshake);
        PFL_EXPECT(rows[1].protocol_text.find("Record Type: Handshake") != std::string::npos);
        PFL_EXPECT(rows[1].protocol_text.find("Record Version: TLS 1.2 (0x0303)") != std::string::npos);
        PFL_EXPECT(rows[1].protocol_text.find("Record Length: 40") != std::string::npos);
        PFL_EXPECT(rows[1].protocol_text.find("Payload Interpretation: Encrypted/opaque handshake payload") != std::string::npos);
        PFL_EXPECT(find_protocol_detail_value(rows[1].protocol_text, "Handshake Type:").has_value() == false);
        const auto encrypted_summary_layers = build_stream_summary_layers(rows[1], packet_rows);
        const auto* encrypted_tls_layer = find_top_level_summary_layer(encrypted_summary_layers, "tls");
        PFL_REQUIRE(encrypted_tls_layer != nullptr);
        PFL_EXPECT(encrypted_tls_layer->title.find("Encrypted Handshake Message") != std::string::npos);
        PFL_EXPECT(require_summary_field_value(*encrypted_tls_layer, "Record Type") == "Handshake");
        PFL_EXPECT(require_summary_field_value(*encrypted_tls_layer, "Record Legacy Version") == "TLS 1.2 (0x0303)");
        PFL_EXPECT(require_summary_field_value(*encrypted_tls_layer, "Record Length") == "40");
        PFL_EXPECT(require_summary_field_value(*encrypted_tls_layer, "Total Record Size") == "45 bytes");
        PFL_EXPECT(require_summary_field_value(*encrypted_tls_layer, "Payload Interpretation") == "Encrypted/opaque handshake payload");
        PFL_EXPECT(find_summary_field(*encrypted_tls_layer, "Handshake Type") == nullptr);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/tls/tls_1_3_change_cipher_spec_8.pcap"), fast_options));

        const auto packet_rows = session.list_flow_packets(0);
        const auto rows = session.list_flow_stream_items(0);
        PFL_REQUIRE(rows.size() == 2U);
        PFL_EXPECT(rows[0].label == "TLS ChangeCipherSpec");
        PFL_EXPECT(rows[0].byte_count == 6U);
        PFL_EXPECT(rows[0].tls_semantic_kind == TlsStreamItemSemanticKind::change_cipher_spec);
        PFL_EXPECT(rows[0].protocol_text.find("Record Type: ChangeCipherSpec") != std::string::npos);
        PFL_EXPECT(rows[1].label == "TLS AppData");
        PFL_EXPECT(rows[1].byte_count == 74U);
        PFL_EXPECT(rows[1].tls_semantic_kind == TlsStreamItemSemanticKind::application_data);
        PFL_EXPECT(rows[1].protocol_text.find("Record Type: ApplicationData") != std::string::npos);
        PFL_EXPECT(rows[1].protocol_text.find("Record Length: 69") != std::string::npos);
        const auto app_data_summary_layers = build_stream_summary_layers(rows[1], packet_rows);
        const auto* app_data_tls_layer = find_top_level_summary_layer(app_data_summary_layers, "tls");
        PFL_REQUIRE(app_data_tls_layer != nullptr);
        PFL_EXPECT(require_summary_field_value(*app_data_tls_layer, "Record Type") == "ApplicationData");
        PFL_EXPECT(require_summary_field_value(*app_data_tls_layer, "Record Legacy Version") == "TLS 1.2 (0x0303)");
        PFL_EXPECT(require_summary_field_value(*app_data_tls_layer, "Record Length") == "69");
        PFL_EXPECT(require_summary_field_value(*app_data_tls_layer, "Total Record Size") == "74 bytes");
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/tls/tls_1_2_new_session_ticket_9.pcap"), fast_options));

        const auto packet_rows = session.list_flow_packets(0);
        const auto rows = session.list_flow_stream_items(0);
        PFL_REQUIRE(rows.size() == 3U);
        PFL_EXPECT(rows[0].label == "TLS NewSessionTicket");
        PFL_EXPECT(rows[0].byte_count == 191U);
        PFL_EXPECT(rows[0].tls_semantic_kind == TlsStreamItemSemanticKind::plaintext_handshake);
        PFL_EXPECT(rows[0].protocol_text.find("Handshake Type: NewSessionTicket") != std::string::npos);
        PFL_EXPECT(rows[0].protocol_text.find("Handshake Length: 182") != std::string::npos);
        PFL_EXPECT(rows[1].label == "TLS ChangeCipherSpec");
        PFL_EXPECT(rows[1].byte_count == 6U);
        PFL_EXPECT(rows[1].tls_semantic_kind == TlsStreamItemSemanticKind::change_cipher_spec);
        PFL_EXPECT(rows[2].label == "TLS Encrypted Handshake Message");
        PFL_EXPECT(rows[2].byte_count == 45U);
        PFL_EXPECT(rows[2].tls_semantic_kind == TlsStreamItemSemanticKind::encrypted_handshake);
        PFL_EXPECT(rows[2].protocol_text.find("Record Type: Handshake") != std::string::npos);
        PFL_EXPECT(rows[2].protocol_text.find("Payload Interpretation: Encrypted/opaque handshake payload") != std::string::npos);
        PFL_EXPECT(find_protocol_detail_value(rows[2].protocol_text, "Handshake Type:").has_value() == false);
        const auto new_ticket_summary_layers = build_stream_summary_layers(rows[0], packet_rows);
        const auto* new_ticket_tls_layer = find_top_level_summary_layer(new_ticket_summary_layers, "tls");
        PFL_REQUIRE(new_ticket_tls_layer != nullptr);
        PFL_EXPECT(require_summary_field_value(*new_ticket_tls_layer, "Record Type") == "Handshake");
        PFL_EXPECT(require_summary_field_value(*new_ticket_tls_layer, "Record Legacy Version") == "TLS 1.2 (0x0303)");
        PFL_EXPECT(require_summary_field_value(*new_ticket_tls_layer, "Record Length") == "186");
        PFL_EXPECT(require_summary_field_value(*new_ticket_tls_layer, "Total Record Size") == "191 bytes");
        PFL_EXPECT(require_summary_field_value(*new_ticket_tls_layer, "Handshake Type") == "NewSessionTicket");
        PFL_EXPECT(require_summary_field_value(*new_ticket_tls_layer, "Handshake Length") == "182");
        PFL_EXPECT(require_summary_field_value(*new_ticket_tls_layer, "Session Ticket Lifetime Hint") == "7200 seconds");
        PFL_EXPECT(require_summary_field_value(*new_ticket_tls_layer, "Session Ticket Length") == "176 bytes");
        PFL_EXPECT(find_summary_field(*new_ticket_tls_layer, "Ticket Bytes") == nullptr);

        PFL_REQUIRE(!rows[0].packet_indices.empty());
        const auto packet = session.find_packet(rows[0].packet_indices[0]);
        PFL_REQUIRE(packet.has_value());
        const auto packet_summary_layers = build_packet_summary_layers_for_packet(session, *packet);
        const auto packet_tls_layers = find_top_level_summary_layers(packet_summary_layers, "tls");
        PFL_REQUIRE(packet_tls_layers.size() == 3U);
        PFL_EXPECT(require_summary_field_value(*new_ticket_tls_layer, "Handshake Type") == require_summary_field_value(*packet_tls_layers[0], "Handshake Type"));
        PFL_EXPECT(require_summary_field_value(*new_ticket_tls_layer, "Handshake Length") == require_summary_field_value(*packet_tls_layers[0], "Handshake Length"));
        PFL_EXPECT(require_summary_field_value(*new_ticket_tls_layer, "Session Ticket Lifetime Hint") == require_summary_field_value(*packet_tls_layers[0], "Session Ticket Lifetime Hint"));
        PFL_EXPECT(require_summary_field_value(*new_ticket_tls_layer, "Session Ticket Length") == require_summary_field_value(*packet_tls_layers[0], "Session Ticket Length"));

        const auto encrypted_summary_layers = build_stream_summary_layers(rows[2], packet_rows);
        const auto* encrypted_tls_layer = find_top_level_summary_layer(encrypted_summary_layers, "tls");
        PFL_REQUIRE(encrypted_tls_layer != nullptr);
        PFL_EXPECT(encrypted_tls_layer->title.find("Encrypted Handshake Message") != std::string::npos);
        PFL_EXPECT(require_summary_field_value(*encrypted_tls_layer, "Payload Interpretation") == "Encrypted/opaque handshake payload");
        PFL_EXPECT(find_summary_field(*encrypted_tls_layer, "Handshake Type") == nullptr);
        PFL_EXPECT(find_summary_field(*encrypted_tls_layer, "Handshake Length") == nullptr);
        PFL_EXPECT(find_summary_field(*encrypted_tls_layer, "Session Ticket Lifetime Hint") == nullptr);
        PFL_EXPECT(find_summary_field(*encrypted_tls_layer, "Session Ticket Length") == nullptr);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/udp/udp_generic_payload_2.pcap"), fast_options));

        const auto rows = session.list_flow_stream_items(0);
        PFL_EXPECT(!rows.empty());
        for (const auto& row : rows) {
            PFL_EXPECT(row.label == "UDP Payload");
            PFL_EXPECT(!starts_with(row.label, "DNS"));
            PFL_EXPECT(!starts_with(row.label, "QUIC"));
            PFL_EXPECT(row.tls_semantic_kind == TlsStreamItemSemanticKind::none);
            PFL_EXPECT(row.protocol_text.empty());
            PFL_EXPECT(row.payload_hex_text.empty());
        }
    }

    {
        HexDumpService hex_dump_service {};
        const auto payload = make_tls_handshake_record(0x02U, {0xAAU, 0xBBU, 0xCCU});
        const StreamItemRow row {
            .stream_item_index = 1U,
            .direction_text = "A -> B",
            .label = "synthetic-not-used-for-tls-semantics",
            .byte_count = static_cast<std::uint32_t>(payload.size()),
            .packet_count = 1U,
            .packet_indices = {0U},
            .payload_hex_text = hex_dump_service.format(payload),
            .protocol_text = "synthetic protocol text should not choose semantics",
            .tls_semantic_kind = TlsStreamItemSemanticKind::encrypted_handshake,
        };

        const auto summary_layers = session_detail::build_stream_item_summary_layers(
            row,
            "packet #1",
            "Stream item"
        );
        const auto* tls_layer = find_top_level_summary_layer(summary_layers, "tls");
        PFL_REQUIRE(tls_layer != nullptr);
        PFL_EXPECT(require_summary_field_value(*tls_layer, "Payload Interpretation") == "Encrypted/opaque handshake payload");
        PFL_EXPECT(find_summary_field(*tls_layer, "Handshake Type") == nullptr);
        PFL_EXPECT(find_summary_field(*tls_layer, "Handshake Length") == nullptr);
    }

    {
        const auto tls_like_udp_packet = make_ethernet_ipv4_udp_packet_with_bytes_payload(
            ipv4(10, 43, 0, 1), ipv4(10, 43, 0, 2), 54001, 443,
            make_tls_handshake_record(0x01U, {0xAAU, 0xBBU, 0xCCU})
        );
        const auto tls_like_udp_path = write_temp_pcap(
            "pfl_stream_query_udp_tls_like_payload.pcap",
            make_classic_pcap({{100, tls_like_udp_packet}})
        );

        CaptureSession tls_like_udp_session {};
        PFL_EXPECT(tls_like_udp_session.open_capture(tls_like_udp_path, fast_options));
        const auto tls_like_udp_rows = tls_like_udp_session.list_flow_stream_items(0);
        PFL_EXPECT(tls_like_udp_rows.size() == 1U);
        PFL_EXPECT(tls_like_udp_rows[0].label == "UDP Payload");
        PFL_EXPECT(!starts_with(tls_like_udp_rows[0].label, "TLS"));
        PFL_EXPECT(tls_like_udp_rows[0].protocol_text.empty());
        PFL_EXPECT(tls_like_udp_rows[0].payload_hex_text.empty());

        constexpr std::string_view http_like_udp_text =
            "GET /udp HTTP/1.1\r\n"
            "Host: udp.example\r\n"
            "\r\n";
        const auto http_like_udp_packet = make_ethernet_ipv4_udp_packet_with_bytes_payload(
            ipv4(10, 43, 0, 3), ipv4(10, 43, 0, 4), 54002, 80, make_text_bytes(http_like_udp_text)
        );
        const auto http_like_udp_path = write_temp_pcap(
            "pfl_stream_query_udp_http_like_payload.pcap",
            make_classic_pcap({{100, http_like_udp_packet}})
        );

        CaptureSession http_like_udp_session {};
        PFL_EXPECT(http_like_udp_session.open_capture(http_like_udp_path, fast_options));
        const auto http_like_udp_rows = http_like_udp_session.list_flow_stream_items(0);
        PFL_EXPECT(http_like_udp_rows.size() == 1U);
        PFL_EXPECT(http_like_udp_rows[0].label == "UDP Payload");
        PFL_EXPECT(!starts_with(http_like_udp_rows[0].label, "HTTP"));
        PFL_EXPECT(http_like_udp_rows[0].protocol_text.empty());
        PFL_EXPECT(http_like_udp_rows[0].payload_hex_text.empty());
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/quic/quic_initial_ch_1.pcap"), fast_options));

        const auto rows = session.list_flow_stream_items(0);
        const auto* quic_row = find_stream_row_by_label(rows, "QUIC Initial: CRYPTO");
        PFL_EXPECT(quic_row != nullptr);
        PFL_EXPECT(quic_row->protocol_text.find("TLS Handshake Type: ClientHello") != std::string::npos);
        PFL_EXPECT(quic_row->protocol_text.find("Cipher Suites:") != std::string::npos);
        PFL_EXPECT(quic_row->protocol_text.find("SNI:") != std::string::npos);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/quic/quic_test_1.pcap"), fast_options));

        const auto rows = session.list_flow_stream_items(0);
        PFL_EXPECT(!rows.empty());
        PFL_EXPECT(std::any_of(rows.begin(), rows.end(), [](const StreamItemRow& row) {
            return row.label == "QUIC Initial: ACK" || row.label == "QUIC Initial: CRYPTO" ||
                   starts_with(row.label, "QUIC ") || row.label == "Handshake" || row.label == "Protected payload" || row.label == "0-RTT";
        }));
        PFL_EXPECT(std::any_of(rows.begin(), rows.end(), [](const StreamItemRow& row) {
            return row.label == "QUIC Initial: CRYPTO";
        }));
        PFL_EXPECT(std::any_of(rows.begin(), rows.end(), [](const StreamItemRow& row) {
            return row.label != "UDP Payload" && !row.protocol_text.empty() && !row.payload_hex_text.empty();
        }));
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/quic/quic_handshake_3.pcap"), fast_options));

        const auto rows = session.list_flow_stream_items(0);
        PFL_EXPECT(rows.size() == 1U);
        PFL_EXPECT(rows[0].label == "Handshake");
        PFL_EXPECT(rows[0].protocol_text.find("Packet Type: Handshake") != std::string::npos);
        PFL_EXPECT(rows[0].protocol_text.find("Header Form: Long") != std::string::npos);
        PFL_EXPECT(!rows[0].payload_hex_text.empty());
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/quic/quic_protected_payload_4.pcap"), fast_options));

        const auto rows = session.list_flow_stream_items(0);
        PFL_EXPECT(rows.size() == 1U);
        PFL_EXPECT(rows[0].label == "UDP Payload");
        PFL_EXPECT(rows[0].protocol_text.empty());
        PFL_EXPECT(rows[0].payload_hex_text.empty());
    }

    {
        constexpr std::string_view ssdp_like_payload =
            "NOTIFY * HTTP/1.1\r\n"
            "HOST: 239.255.255.250:1900\r\n"
            "NTS: ssdp:alive\r\n"
            "\r\n";
        const auto packet = make_ethernet_ipv4_udp_packet_with_bytes_payload(
            ipv4(10, 41, 2, 10), ipv4(239, 255, 255, 250), 51515, 1900, make_text_bytes(ssdp_like_payload)
        );
        const auto path = write_temp_pcap(
            "pfl_stream_query_udp_ssdp_like_payload.pcap",
            make_classic_pcap({{100, packet}})
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(path, fast_options));
        const auto rows = session.list_flow_stream_items(0);
        PFL_EXPECT(rows.size() == 1U);
        PFL_EXPECT(rows[0].label == "UDP Payload");
        PFL_EXPECT(rows[0].protocol_text.empty());
        PFL_EXPECT(rows[0].payload_hex_text.empty());
    }

    {
        const auto packet = make_ethernet_ipv4_udp_packet_with_bytes_payload(
            ipv4(10, 41, 2, 11), ipv4(10, 41, 2, 12), 54011, 443, make_quic_short_header_like_payload()
        );
        const auto path = write_temp_pcap(
            "pfl_stream_query_quic_short_header_only_udp443.pcap",
            make_classic_pcap({{100, packet}})
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(path, fast_options));
        const auto rows = session.list_flow_stream_items(0);
        PFL_EXPECT(rows.size() == 1U);
        PFL_EXPECT(rows[0].label == "UDP Payload");
        PFL_EXPECT(rows[0].protocol_text.empty());
        PFL_EXPECT(rows[0].payload_hex_text.empty());
    }

    {
        const auto packet = make_ethernet_ipv4_udp_packet_with_bytes_payload(
            ipv4(10, 41, 2, 13), ipv4(10, 41, 2, 14), 54012, 137, make_quic_retry_like_payload()
        );
        const auto path = write_temp_pcap(
            "pfl_stream_query_quic_retry_like_udp137.pcap",
            make_classic_pcap({{100, packet}})
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(path, fast_options));
        const auto rows = session.list_flow_stream_items(0);
        PFL_EXPECT(rows.size() == 1U);
        PFL_EXPECT(rows[0].label == "UDP Payload");
        PFL_EXPECT(rows[0].protocol_text.empty());
        PFL_EXPECT(rows[0].payload_hex_text.empty());
    }

    {
        const auto crypto_packet = make_ethernet_ipv4_udp_packet_with_bytes_payload(
            ipv4(10, 41, 1, 1), ipv4(10, 41, 1, 2), 54000, 443, make_plaintext_quic_initial_payload(make_quic_crypto_frame_bytes()));
        const auto ack_packet = make_ethernet_ipv4_udp_packet_with_bytes_payload(
            ipv4(10, 41, 1, 1), ipv4(10, 41, 1, 2), 54000, 443, make_plaintext_quic_initial_payload(make_quic_ack_frame_bytes()));
        const auto path = write_temp_pcap(
            "pfl_stream_query_quic_plaintext_frames.pcap",
            make_classic_pcap({
                {100, crypto_packet},
                {200, ack_packet},
            })
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(path, fast_options));
        const auto rows = session.list_flow_stream_items(0);
        PFL_EXPECT(rows.size() == 2U);
        PFL_EXPECT(rows[0].label == "QUIC Initial: CRYPTO");
        PFL_EXPECT(rows[0].byte_count == make_quic_crypto_frame_bytes().size());
        PFL_EXPECT(rows[0].protocol_text.find("Frame Presence: CRYPTO") != std::string::npos);
        PFL_EXPECT(rows[1].label == "QUIC Initial: ACK");
        PFL_EXPECT(rows[1].byte_count == make_quic_ack_frame_bytes().size());
        PFL_EXPECT(rows[1].protocol_text.find("Frame Presence: ACK") != std::string::npos);
    }

    {
        std::vector<std::pair<std::uint32_t, std::vector<std::uint8_t>>> bounded_prefix_quic_packets {};
        bounded_prefix_quic_packets.reserve(40U);
        for (std::uint32_t packet_index = 0; packet_index < 30U; ++packet_index) {
            bounded_prefix_quic_packets.push_back({
                4000U + packet_index,
                make_ethernet_ipv4_udp_packet_with_bytes_payload(
                    ipv4(10, 41, 10, 1),
                    ipv4(10, 41, 10, 2),
                    54060,
                    443,
                    make_plaintext_quic_initial_payload(make_quic_ack_frame_bytes()))
            });
        }
        for (std::uint32_t packet_index = 30U; packet_index < 40U; ++packet_index) {
            bounded_prefix_quic_packets.push_back({
                4000U + packet_index,
                make_ethernet_ipv4_udp_packet_with_bytes_payload(
                    ipv4(10, 41, 10, 1),
                    ipv4(10, 41, 10, 2),
                    54060,
                    443,
                    make_plaintext_quic_initial_payload(make_quic_crypto_frame_bytes()))
            });
        }
        const auto path = write_temp_pcap(
            "pfl_stream_query_quic_bounded_prefix.pcap",
            make_classic_pcap(bounded_prefix_quic_packets)
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(path, fast_options));

        const auto bounded_prefix_packet_rows = session.list_flow_packets(0, 0U, 30U);
        std::vector<PacketRef> bounded_prefix_packet_refs {};
        bounded_prefix_packet_refs.reserve(bounded_prefix_packet_rows.size());
        for (const auto& row : bounded_prefix_packet_rows) {
            const auto packet = session.find_packet(row.packet_index);
            PFL_EXPECT(packet.has_value());
            bounded_prefix_packet_refs.push_back(*packet);
        }
        const auto bounded_prefix_dcid = session_detail::find_quic_client_initial_connection_id_for_packets(
            session,
            std::span<const PacketRef>(bounded_prefix_packet_refs.data(), bounded_prefix_packet_refs.size()),
            0U
        );
        PFL_EXPECT(bounded_prefix_dcid.has_value());
        PFL_EXPECT(!bounded_prefix_dcid->empty());

        const auto bounded_prefix_rows = session.list_flow_stream_items_for_packet_prefix(0, 30U, 16U);
        const auto extended_prefix_rows = session.list_flow_stream_items_for_packet_prefix(0, 40U, 40U);
        PFL_EXPECT(!bounded_prefix_rows.empty());
        PFL_EXPECT(!extended_prefix_rows.empty());
        for (const auto& row : bounded_prefix_rows) {
            for (const auto packet_index : row.packet_indices) {
                PFL_EXPECT(packet_index < 30U);
            }
            PFL_EXPECT(row.label != "QUIC Initial: CRYPTO");
        }
        PFL_EXPECT(std::any_of(extended_prefix_rows.begin(), extended_prefix_rows.end(), [](const StreamItemRow& row) {
            return row.label == "QUIC Initial: CRYPTO";
        }));
        for (const auto& row : extended_prefix_rows) {
            for (const auto packet_index : row.packet_indices) {
                PFL_EXPECT(packet_index < 40U);
            }
        }
    }

    {
        const auto crypto_with_padding_packet = make_ethernet_ipv4_udp_packet_with_bytes_payload(
            ipv4(10, 41, 1, 1),
            ipv4(10, 41, 1, 2),
            54000,
            443,
            make_plaintext_quic_initial_payload(concat_bytes(make_quic_crypto_frame_bytes(), make_quic_padding_frame_bytes(3U)))
        );
        const auto ack_with_padding_packet = make_ethernet_ipv4_udp_packet_with_bytes_payload(
            ipv4(10, 41, 1, 1),
            ipv4(10, 41, 1, 2),
            54000,
            443,
            make_plaintext_quic_initial_payload(concat_bytes(make_quic_ack_frame_bytes(), make_quic_padding_frame_bytes(2U)))
        );
        const auto padding_only_packet = make_ethernet_ipv4_udp_packet_with_bytes_payload(
            ipv4(10, 41, 1, 1),
            ipv4(10, 41, 1, 2),
            54000,
            443,
            make_plaintext_quic_initial_payload(make_quic_padding_frame_bytes(4U))
        );
        const auto ping_only_packet = make_ethernet_ipv4_udp_packet_with_bytes_payload(
            ipv4(10, 41, 1, 1),
            ipv4(10, 41, 1, 2),
            54000,
            443,
            make_plaintext_quic_initial_payload(make_quic_ping_frame_bytes())
        );
        const auto path = write_temp_pcap(
            "pfl_stream_query_quic_padding_ping_suppression.pcap",
            make_classic_pcap({
                {100, crypto_with_padding_packet},
                {200, ack_with_padding_packet},
                {300, padding_only_packet},
                {400, ping_only_packet},
            })
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(path, fast_options));
        const auto rows = session.list_flow_stream_items(0);
        PFL_EXPECT(rows.size() == 2U);
        PFL_EXPECT(rows[0].label == "QUIC Initial: CRYPTO");
        PFL_EXPECT(rows[0].protocol_text.find("Frame Presence: CRYPTO, PADDING") != std::string::npos);
        PFL_EXPECT(rows[1].label == "QUIC Initial: ACK");
        PFL_EXPECT(rows[1].protocol_text.find("Frame Presence: ACK, PADDING") != std::string::npos);
        PFL_EXPECT(std::none_of(rows.begin(), rows.end(), [](const StreamItemRow& row) {
            return row.label.find("PADDING") != std::string::npos || row.label.find("PING") != std::string::npos;
        }));
    }

    {
        const auto server_hello_packet = make_ethernet_ipv4_udp_packet_with_bytes_payload(
            ipv4(10, 41, 1, 3), ipv4(10, 41, 1, 4), 54000, 443,
            make_plaintext_quic_initial_payload(make_quic_crypto_frame_bytes(make_tls_server_hello_handshake_bytes())));
        const auto path = write_temp_pcap(
            "pfl_stream_query_quic_server_hello_plaintext.pcap",
            make_classic_pcap({{100, server_hello_packet}})
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(path, fast_options));
        const auto rows = session.list_flow_stream_items(0);
        PFL_EXPECT(rows.size() == 1U);
        PFL_EXPECT(rows[0].label == "QUIC Initial: CRYPTO");
        PFL_EXPECT(rows[0].protocol_text.find("TLS Handshake Type: ServerHello") != std::string::npos);
        PFL_EXPECT(rows[0].protocol_text.find("Selected TLS Version:") != std::string::npos);
        PFL_EXPECT(rows[0].protocol_text.find("Selected Cipher Suite:") != std::string::npos);
    }

    {
        const auto packet = make_ethernet_ipv4_udp_packet_with_bytes_payload(
            ipv4(10, 41, 2, 1), ipv4(10, 41, 2, 2), 54000, 443, make_quic_truncated_payload());
        const auto path = write_temp_pcap(
            "pfl_stream_query_quic_truncated.pcap",
            make_classic_pcap({{100, packet}})
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(path, fast_options));
        const auto rows = session.list_flow_stream_items(0);
        PFL_EXPECT(rows.size() == 1U);
        PFL_EXPECT(rows[0].label == "UDP Payload");
        PFL_EXPECT(rows[0].protocol_text.empty());
        PFL_EXPECT(rows[0].payload_hex_text.empty());
    }

    {
        const auto initial_packet = make_ethernet_ipv4_udp_packet_with_bytes_payload(
            ipv4(10, 41, 2, 21), ipv4(10, 41, 2, 22), 54021, 443, make_plaintext_quic_initial_payload(make_quic_crypto_frame_bytes())
        );
        const auto protected_packet = make_ethernet_ipv4_udp_packet_with_bytes_payload(
            ipv4(10, 41, 2, 22), ipv4(10, 41, 2, 21), 443, 54021, make_quic_short_header_like_payload({0xAAU, 0xBBU, 0xCCU, 0xDDU})
        );
        const auto path = write_temp_pcap(
            "pfl_stream_query_quic_confirmed_then_short_header.pcap",
            make_classic_pcap({
                {100, initial_packet},
                {200, protected_packet},
            })
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(path, fast_options));
        const auto rows = session.list_flow_stream_items(0);
        PFL_EXPECT(rows.size() == 2U);
        PFL_EXPECT(rows[0].label == "QUIC Initial: CRYPTO");
        PFL_EXPECT(rows[1].label == "Protected payload");
        PFL_EXPECT(rows[1].protocol_text.find("Packet Type: Protected Payload") != std::string::npos);
        PFL_EXPECT(rows[1].protocol_text.find("Header Form: Short") != std::string::npos);
        PFL_EXPECT(!rows[1].payload_hex_text.empty());
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/http/http_multi_message_3.pcap"), fast_options));

        const auto rows = session.list_flow_stream_items(0);
        PFL_EXPECT(!rows.empty());

        std::size_t request_count = 0U;
        std::size_t response_count = 0U;
        bool saw_multi_packet_http_response = false;
        for (const auto& row : rows) {
            if (starts_with(row.label, "HTTP GET")) {
                ++request_count;
                PFL_EXPECT(!row.protocol_text.empty());
                PFL_EXPECT(!row.payload_hex_text.empty());
            }
            if (starts_with(row.label, "HTTP 200")) {
                ++response_count;
                PFL_EXPECT(!row.protocol_text.empty());
                PFL_EXPECT(!row.payload_hex_text.empty());
                if (row.packet_count > 1U) {
                    saw_multi_packet_http_response = true;
                }
            }
        }

        PFL_EXPECT(request_count >= 3U);
        PFL_EXPECT(response_count >= 3U);
        PFL_EXPECT(saw_multi_packet_http_response);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/http/http_partial_response_4.pcap"), fast_options));

        const auto flows = session.list_flows();
        PFL_EXPECT(flows.size() == 1U);
        PFL_EXPECT(flows[0].packet_count == 8U);

        const auto rows = session.list_flow_stream_items(0);
        PFL_EXPECT(rows.size() == 3U);

        PFL_EXPECT(rows[0].label == "HTTP GET /");
        PFL_EXPECT(rows[1].label == "HTTP 200 OK");
        PFL_EXPECT(rows[2].label == "HTTP Payload (partial)");
        PFL_EXPECT(rows[2].protocol_text.find("complete HTTP header block") != std::string::npos);
    }

    {
        const auto client_hello_packet = make_ethernet_ipv4_udp_packet_with_bytes_payload(
            ipv4(10, 41, 3, 1), ipv4(10, 41, 3, 2), 54020, 443,
            make_plaintext_quic_initial_payload(make_quic_crypto_frame_bytes(make_tls_client_hello_handshake_bytes())));
        const auto server_hello_packet = make_ethernet_ipv4_udp_packet_with_bytes_payload(
            ipv4(10, 41, 3, 2), ipv4(10, 41, 3, 1), 443, 54020,
            make_plaintext_quic_initial_payload(make_quic_crypto_frame_bytes(make_tls_server_hello_handshake_bytes())));
        const auto server_ack_packet = make_ethernet_ipv4_udp_packet_with_bytes_payload(
            ipv4(10, 41, 3, 2), ipv4(10, 41, 3, 1), 443, 54020,
            make_plaintext_quic_initial_payload(make_quic_ack_frame_bytes()));
        const auto path = write_temp_pcap(
            "pfl_stream_query_quic_direction_ownership_stage1.pcap",
            make_classic_pcap(std::vector<std::pair<std::uint32_t, std::vector<std::uint8_t>>> {
                {100U, client_hello_packet},
                {200U, server_hello_packet},
                {300U, server_ack_packet},
            })
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(path, fast_options));

        const auto rows = session.list_flow_stream_items(0);
        const auto client_row = std::find_if(rows.begin(), rows.end(), [](const StreamItemRow& row) {
            return row.packet_indices == std::vector<std::uint64_t> {0U};
        });
        const auto server_row = std::find_if(rows.begin(), rows.end(), [](const StreamItemRow& row) {
            return row.packet_indices == std::vector<std::uint64_t> {1U};
        });
        const auto ack_row = std::find_if(rows.begin(), rows.end(), [](const StreamItemRow& row) {
            return row.packet_indices == std::vector<std::uint64_t> {2U};
        });

        PFL_EXPECT(client_row != rows.end());
        PFL_EXPECT(server_row != rows.end());
        PFL_EXPECT(ack_row != rows.end());

        const auto client_context = session.derive_quic_protocol_details_for_packet_context(0, client_row->packet_indices);
        PFL_EXPECT(client_context.has_value());
        PFL_EXPECT(client_context->find("TLS Handshake Type: ClientHello") != std::string::npos);
        PFL_EXPECT(client_context->find("ServerHello") == std::string::npos);

        const auto server_context = session.derive_quic_protocol_details_for_packet_context(0, server_row->packet_indices);
        PFL_EXPECT(server_context.has_value());
        PFL_EXPECT(server_context->find("TLS Handshake Type: ServerHello") != std::string::npos);
        PFL_EXPECT(server_context->find("ClientHello") == std::string::npos);
        PFL_EXPECT(server_context->find("SNI:") == std::string::npos);

        const auto ack_context = session.derive_quic_protocol_details_for_packet_context(0, ack_row->packet_indices);
        PFL_EXPECT(!ack_context.has_value());
    }

    {
        const auto server_hello_bytes = make_tls_server_hello_handshake_bytes();
        const auto split_offset = server_hello_bytes.size() / 2U;
        const std::vector<std::uint8_t> server_hello_prefix(server_hello_bytes.begin(), server_hello_bytes.begin() + static_cast<std::ptrdiff_t>(split_offset));
        const std::vector<std::uint8_t> server_hello_suffix(server_hello_bytes.begin() + static_cast<std::ptrdiff_t>(split_offset), server_hello_bytes.end());

        const auto client_hello_packet = make_ethernet_ipv4_udp_packet_with_bytes_payload(
            ipv4(10, 41, 4, 1), ipv4(10, 41, 4, 2), 54040, 443,
            make_plaintext_quic_initial_payload(make_quic_crypto_frame_bytes(make_tls_client_hello_handshake_bytes())));
        const auto server_hello_prefix_packet = make_ethernet_ipv4_udp_packet_with_bytes_payload(
            ipv4(10, 41, 4, 2), ipv4(10, 41, 4, 1), 443, 54040,
            make_plaintext_quic_initial_payload(make_quic_crypto_frame_bytes(server_hello_prefix)));
        const auto server_hello_suffix_packet = make_ethernet_ipv4_udp_packet_with_bytes_payload(
            ipv4(10, 41, 4, 2), ipv4(10, 41, 4, 1), 443, 54040,
            make_plaintext_quic_initial_payload(concat_bytes(
                make_quic_crypto_frame_bytes(static_cast<std::uint64_t>(split_offset), server_hello_suffix),
                make_quic_ack_frame_bytes()
            )));
        const auto path = write_temp_pcap(
            "pfl_stream_query_quic_server_hello_bounded_tail_attachment.pcap",
            make_classic_pcap(std::vector<std::pair<std::uint32_t, std::vector<std::uint8_t>>> {
                {100U, client_hello_packet},
                {200U, server_hello_prefix_packet},
                {300U, server_hello_suffix_packet},
            })
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(path, fast_options));

        const auto rows = session.list_flow_stream_items(0);
        const auto server_tail_row = std::find_if(rows.begin(), rows.end(), [](const StreamItemRow& row) {
            return row.packet_indices == std::vector<std::uint64_t> {2U};
        });
        PFL_EXPECT(server_tail_row != rows.end());
        PFL_EXPECT(
            starts_with(server_tail_row->label, "QUIC ") ||
            server_tail_row->label == "QUIC Initial: CRYPTO" ||
            server_tail_row->label == "QUIC Initial: ACK"
        );

        const auto server_tail_context = session.derive_quic_protocol_details_for_packet_context(0, server_tail_row->packet_indices);
        PFL_EXPECT(server_tail_context.has_value());
        PFL_EXPECT(server_tail_context->find("TLS Handshake Type: ServerHello") != std::string::npos);
        PFL_EXPECT(server_tail_context->find("Selected TLS Version:") != std::string::npos);
        PFL_EXPECT(server_tail_context->find("Selected Cipher Suite:") != std::string::npos);
        PFL_EXPECT(server_tail_context->find("ClientHello") == std::string::npos);
        PFL_EXPECT(server_tail_context->find("SNI:") == std::string::npos);
    }

    {
        const auto server_hello_bytes = make_tls_server_hello_handshake_bytes();
        const auto split_offset = server_hello_bytes.size() / 2U;
        const std::vector<std::uint8_t> server_hello_suffix(server_hello_bytes.begin() + static_cast<std::ptrdiff_t>(split_offset), server_hello_bytes.end());

        const auto client_hello_packet = make_ethernet_ipv4_udp_packet_with_bytes_payload(
            ipv4(10, 41, 5, 1), ipv4(10, 41, 5, 2), 54050, 443,
            make_plaintext_quic_initial_payload(make_quic_crypto_frame_bytes(make_tls_client_hello_handshake_bytes())));
        const auto server_hello_suffix_packet = make_ethernet_ipv4_udp_packet_with_bytes_payload(
            ipv4(10, 41, 5, 2), ipv4(10, 41, 5, 1), 443, 54050,
            make_plaintext_quic_initial_payload(make_quic_crypto_frame_bytes(static_cast<std::uint64_t>(split_offset), server_hello_suffix)));
        const auto path = write_temp_pcap(
            "pfl_stream_query_quic_server_hello_insufficient_tail_only.pcap",
            make_classic_pcap(std::vector<std::pair<std::uint32_t, std::vector<std::uint8_t>>> {
                {100U, client_hello_packet},
                {200U, server_hello_suffix_packet},
            })
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(path, fast_options));

        const auto rows = session.list_flow_stream_items(0);
        const auto server_tail_row = std::find_if(rows.begin(), rows.end(), [](const StreamItemRow& row) {
            return row.packet_indices == std::vector<std::uint64_t> {1U};
        });
        PFL_EXPECT(server_tail_row != rows.end());

        const auto server_tail_context = session.derive_quic_protocol_details_for_packet_context(0, server_tail_row->packet_indices);
        PFL_EXPECT(!server_tail_context.has_value());
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/tls/tls_partial_tail_5.pcap"), fast_options));

        const auto rows = session.list_flow_stream_items(0);
        PFL_EXPECT(!rows.empty());
        PFL_EXPECT(find_stream_row_by_label(rows, "TLS ClientHello") != nullptr);
        PFL_EXPECT(find_stream_row_by_label(rows, "TLS ServerHello") != nullptr);
        PFL_EXPECT(find_stream_row_by_label(rows, "TLS ChangeCipherSpec") != nullptr);
        PFL_EXPECT(rows.back().label == "TLS Payload (partial)" || rows.back().label == "TLS Record Fragment (partial)");
        PFL_EXPECT(!rows.front().protocol_text.empty());
        if (rows.back().label == "TLS Record Fragment (partial)") {
            PFL_EXPECT(rows.back().protocol_text.find("complete TLS record") != std::string::npos);
        }
        PFL_EXPECT(rows.back().protocol_text.find("Cipher Suites:") == std::string::npos);
        PFL_EXPECT(rows.back().protocol_text.find("Subject:") == std::string::npos);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/tls/tls_1_3_split_client_hello_10.pcap"), fast_options));

        const auto full_rows = session.list_flow_stream_items(0);
        const auto bounded_rows = session.list_flow_stream_items_for_packet_prefix(0, 5U, 16U);
        const auto* full_client_hello = find_stream_row_by_label(full_rows, "TLS ClientHello");
        const auto* bounded_client_hello = find_stream_row_by_label(bounded_rows, "TLS ClientHello");
        PFL_REQUIRE(full_client_hello != nullptr);
        PFL_REQUIRE(bounded_client_hello != nullptr);
        PFL_EXPECT(bounded_client_hello->label == full_client_hello->label);
        PFL_EXPECT(bounded_client_hello->byte_count == full_client_hello->byte_count);
        PFL_EXPECT(bounded_client_hello->packet_indices == full_client_hello->packet_indices);
        const auto full_summary_layers = build_stream_summary_layers(*full_client_hello, session.list_flow_packets(0));
        const auto bounded_summary_layers = build_stream_summary_layers(*bounded_client_hello, session.list_flow_packets(0, 0U, 5U));
        const auto* full_tls_layer = find_top_level_summary_layer(full_summary_layers, "tls");
        const auto* bounded_tls_layer = find_top_level_summary_layer(bounded_summary_layers, "tls");
        PFL_REQUIRE(full_tls_layer != nullptr);
        PFL_REQUIRE(bounded_tls_layer != nullptr);
        PFL_EXPECT(require_summary_field_value(*bounded_tls_layer, "Handshake Type") ==
            require_summary_field_value(*full_tls_layer, "Handshake Type"));
        PFL_EXPECT(require_summary_field_value(*bounded_tls_layer, "SNI") ==
            require_summary_field_value(*full_tls_layer, "SNI"));
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/tls/ipv4_tls_constricted_1.pcap"), fast_options));
        CaptureSession moved_session {std::move(session)};
        moved_session.clear_runtime_caches_after_transfer();
        const auto moved_packet_rows = moved_session.list_flow_packets(0U, 0U, 32U);
        const auto rows = moved_session.list_flow_stream_items(0);
        PFL_REQUIRE(moved_packet_rows.size() == 14U);
        PFL_REQUIRE(rows.size() == 10U);
        PFL_EXPECT(rows[0].label == "TLS ClientHello");
        PFL_EXPECT(rows[0].byte_count == 666U);
        PFL_EXPECT(rows[0].packet_indices == std::vector<std::uint64_t> {3U});
        PFL_EXPECT(rows[1].label == "TLS ServerHello");
        PFL_EXPECT(rows[1].byte_count == 127U);
        PFL_EXPECT(rows[1].packet_indices == std::vector<std::uint64_t> {5U});
        PFL_EXPECT(rows[2].label == "TLS ChangeCipherSpec");
        PFL_EXPECT(rows[2].byte_count == 6U);
        PFL_EXPECT(rows[2].packet_indices == std::vector<std::uint64_t> {5U});
        PFL_EXPECT(rows[3].label == "TLS AppData");
        PFL_EXPECT(rows[3].byte_count == 3061U);
        PFL_EXPECT(rows[3].packet_indices == std::vector<std::uint64_t>({5U, 6U}));
        PFL_EXPECT(rows[3].has_constricted_contribution);
        PFL_EXPECT(rows[3].constricted_contribution_notes == std::vector<std::string>({
            "#6 contributed 8 / 2787 bytes",
            "#7 contributed 8 / 274 bytes",
        }));
        PFL_EXPECT(rows[3].constricted_packet_notes == std::vector<std::string>({
            "  Constricted packet #6: captured 199 / original 2978 bytes.",
            "  Constricted packet #7: captured 66 / original 332 bytes.",
        }));
        PFL_EXPECT(rows[3].protocol_text.find("Record Type: ApplicationData") != std::string::npos);
        PFL_EXPECT(rows[3].protocol_text.find("Record Length: 3056") != std::string::npos);
        PFL_EXPECT(rows[3].protocol_text.find("Constricted packet #6: captured 199 / original 2978 bytes.") == std::string::npos);
        PFL_EXPECT(rows[3].protocol_text.find("Constricted packet #7: captured 66 / original 332 bytes.") == std::string::npos);
        const auto app_data_summary_layers = build_stream_summary_layers(rows[3], moved_packet_rows);
        const auto* app_data_item_layer = find_top_level_summary_layer(app_data_summary_layers, "stream_item");
        const auto* app_data_tls_layer = find_top_level_summary_layer(app_data_summary_layers, "tls");
        PFL_REQUIRE(app_data_item_layer != nullptr);
        PFL_REQUIRE(app_data_tls_layer != nullptr);
        PFL_EXPECT(require_summary_field_value(*app_data_item_layer, "Source packets") == "#6,#7");
        PFL_EXPECT(find_top_level_summary_layer(app_data_summary_layers, "stream_item_constricted_contributions") != nullptr);
        PFL_EXPECT(find_top_level_summary_layer(app_data_summary_layers, "stream_item_constricted_packets") != nullptr);
        PFL_EXPECT(require_summary_field_value(*app_data_tls_layer, "Status") == "Constricted item");
        PFL_EXPECT(require_summary_field_value(*app_data_tls_layer, "Available Bytes") == "3061");
        PFL_EXPECT(find_summary_field(*app_data_tls_layer, "Record Type") == nullptr);
        PFL_EXPECT(find_summary_field(*app_data_tls_layer, "Record Length") == nullptr);
        PFL_EXPECT(rows[4].label == "TLS ChangeCipherSpec");
        PFL_EXPECT(rows[4].byte_count == 6U);
        PFL_EXPECT(rows[4].packet_indices == std::vector<std::uint64_t> {8U});
        PFL_EXPECT(rows[5].label == "TLS AppData");
        PFL_EXPECT(rows[5].byte_count == 58U);
        PFL_EXPECT(rows[5].packet_indices == std::vector<std::uint64_t> {8U});
        PFL_EXPECT(rows[6].label == "TLS AppData");
        PFL_EXPECT(rows[6].byte_count == 1007U);
        PFL_EXPECT(rows[6].packet_indices == std::vector<std::uint64_t> {9U});
        PFL_EXPECT(rows[6].has_constricted_contribution);
        PFL_EXPECT(rows[6].constricted_contribution_notes == std::vector<std::string>({
            "#10 contributed 8 / 1007 bytes",
        }));
        PFL_EXPECT(rows[7].label == "TLS AppData");
        PFL_EXPECT(rows[7].byte_count == 450U);
        PFL_EXPECT(rows[7].packet_indices == std::vector<std::uint64_t> {11U});
        PFL_EXPECT(rows[8].label == "TLS AppData");
        PFL_EXPECT(rows[8].byte_count == 478U);
        PFL_EXPECT(rows[8].packet_indices == std::vector<std::uint64_t> {11U});
        PFL_EXPECT(rows[9].label == "TLS AppData");
        PFL_EXPECT(rows[9].byte_count == 87U);
        PFL_EXPECT(rows[9].packet_indices == std::vector<std::uint64_t> {13U});
        PFL_EXPECT(std::none_of(rows.begin(), rows.end(), [](const StreamItemRow& row) {
            return row.label == "TLS Gap";
        }));
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/tls/ipv6_tls_constricted_1.pcap"), fast_options));

        const auto flows = session.list_flows();
        PFL_EXPECT(flows.size() == 1U);
        PFL_EXPECT(flows[0].protocol_hint == "tls");
        PFL_EXPECT(flows[0].service_hint == "www.youtube.com");
        PFL_EXPECT(flows[0].packet_count == 19U);

        const auto rows = session.list_flow_stream_items(0);
        PFL_EXPECT(rows.size() == 9U);
        PFL_EXPECT(rows[0].label == "TLS ClientHello");
        PFL_EXPECT(rows[0].byte_count == 1890U);
        PFL_EXPECT(rows[0].packet_indices == std::vector<std::uint64_t> {3U});
        PFL_EXPECT(rows[1].label == "TLS ServerHello");
        PFL_EXPECT(rows[1].byte_count == 1215U);
        PFL_EXPECT(rows[1].packet_indices == std::vector<std::uint64_t>({5U, 7U}));
        PFL_EXPECT(rows[2].label == "TLS ChangeCipherSpec");
        PFL_EXPECT(rows[2].byte_count == 6U);
        PFL_EXPECT(rows[2].packet_indices == std::vector<std::uint64_t> {7U});
        PFL_EXPECT(rows[3].label == "TLS AppData");
        PFL_EXPECT(rows[3].byte_count == 6485U);
        PFL_EXPECT(rows[3].packet_indices == std::vector<std::uint64_t>({7U, 8U, 9U, 13U}));
        PFL_EXPECT(!rows[3].has_constricted_contribution);
        PFL_EXPECT(rows[4].label == "TLS ChangeCipherSpec");
        PFL_EXPECT(rows[4].byte_count == 6U);
        PFL_EXPECT(rows[4].packet_indices == std::vector<std::uint64_t> {15U});
        PFL_EXPECT(!rows[4].has_constricted_contribution);
        PFL_EXPECT(rows[5].label == "TLS AppData");
        PFL_EXPECT(rows[5].byte_count == 58U);
        PFL_EXPECT(rows[5].packet_indices == std::vector<std::uint64_t> {15U});
        PFL_EXPECT(rows[5].has_constricted_contribution);
        PFL_EXPECT(rows[5].constricted_contribution_notes == std::vector<std::string>({
            "#16 contributed 8 / 58 bytes",
        }));
        PFL_EXPECT(rows[6].label == "TLS AppData");
        PFL_EXPECT(rows[6].byte_count == 92U);
        PFL_EXPECT(rows[6].packet_indices == std::vector<std::uint64_t> {16U});
        PFL_EXPECT(rows[6].has_constricted_contribution);
        PFL_EXPECT(rows[6].constricted_contribution_notes == std::vector<std::string>({
            "#17 contributed 8 / 92 bytes",
        }));
        PFL_EXPECT(rows[7].label == "TLS AppData");
        PFL_EXPECT(rows[7].byte_count == 362U);
        PFL_EXPECT(rows[7].packet_indices == std::vector<std::uint64_t> {17U});
        PFL_EXPECT(rows[7].has_constricted_contribution);
        PFL_EXPECT(rows[7].constricted_contribution_notes == std::vector<std::string>({
            "#18 contributed 8 / 362 bytes",
        }));
        PFL_EXPECT(rows[8].label == "TLS AppData");
        PFL_EXPECT(rows[8].byte_count == 62U);
        PFL_EXPECT(rows[8].packet_indices == std::vector<std::uint64_t> {18U});
        PFL_EXPECT(rows[8].has_constricted_contribution);
        PFL_EXPECT(rows[8].constricted_contribution_notes == std::vector<std::string>({
            "#19 contributed 8 / 62 bytes",
        }));
        PFL_EXPECT(std::none_of(rows.begin(), rows.end(), [](const StreamItemRow& row) {
            return row.label == "TLS Gap" || row.label == "TCP Payload";
        }));
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/tls/ipv6_tls_strong_constrict_1.pcap"), fast_options));

        const auto flows = session.list_flows();
        PFL_EXPECT(flows.size() == 1U);
        PFL_EXPECT(flows[0].protocol_hint == "tls");
        PFL_EXPECT(flows[0].service_hint == "www.youtube.com");
        PFL_EXPECT(flows[0].packet_count == 19U);

        const auto rows = session.list_flow_stream_items(0);
        PFL_EXPECT(rows.size() == 9U);
        PFL_EXPECT(rows[0].label == "TLS ClientHello");
        PFL_EXPECT(rows[0].byte_count == 1890U);
        PFL_EXPECT(rows[0].packet_indices == std::vector<std::uint64_t> {3U});
        PFL_EXPECT(rows[1].label == "TLS ServerHello");
        PFL_EXPECT(rows[1].byte_count == 1215U);
        PFL_EXPECT(rows[1].packet_indices == std::vector<std::uint64_t>({5U, 7U}));
        PFL_EXPECT(!rows[1].has_constricted_contribution);
        PFL_EXPECT(rows[2].label == "TLS ChangeCipherSpec");
        PFL_EXPECT(rows[2].byte_count == 6U);
        PFL_EXPECT(rows[2].packet_indices == std::vector<std::uint64_t> {7U});
        PFL_EXPECT(!rows[2].has_constricted_contribution);
        PFL_EXPECT(rows[3].label == "TLS AppData");
        PFL_EXPECT(rows[3].byte_count == 6485U);
        PFL_EXPECT(rows[3].packet_indices == std::vector<std::uint64_t>({7U, 8U, 9U, 13U}));
        PFL_EXPECT(rows[3].has_constricted_contribution);
        PFL_EXPECT(rows[3].constricted_contribution_notes == std::vector<std::string>({
            "#8 contributed 8 / 1195 bytes",
            "#9 contributed 8 / 2416 bytes",
            "#10 contributed 8 / 2416 bytes",
            "#14 contributed 8 / 458 bytes",
        }));
        PFL_EXPECT(rows[3].protocol_text.find("Record Type: ApplicationData") != std::string::npos);
        PFL_EXPECT(rows[3].protocol_text.find("Record Length: 6480") != std::string::npos);
        PFL_EXPECT(rows[4].label == "TLS ChangeCipherSpec");
        PFL_EXPECT(rows[4].byte_count == 6U);
        PFL_EXPECT(rows[4].packet_indices == std::vector<std::uint64_t> {15U});
        PFL_EXPECT(!rows[4].has_constricted_contribution);
        PFL_EXPECT(rows[5].label == "TLS AppData");
        PFL_EXPECT(rows[5].byte_count == 58U);
        PFL_EXPECT(rows[5].packet_indices == std::vector<std::uint64_t> {15U});
        PFL_EXPECT(rows[5].has_constricted_contribution);
        PFL_EXPECT(rows[5].constricted_contribution_notes == std::vector<std::string>({
            "#16 contributed 8 / 58 bytes",
        }));
        PFL_EXPECT(rows[6].label == "TLS AppData");
        PFL_EXPECT(rows[6].byte_count == 92U);
        PFL_EXPECT(rows[6].packet_indices == std::vector<std::uint64_t> {16U});
        PFL_EXPECT(rows[6].has_constricted_contribution);
        PFL_EXPECT(rows[6].constricted_contribution_notes == std::vector<std::string>({
            "#17 contributed 8 / 92 bytes",
        }));
        PFL_EXPECT(rows[7].label == "TLS AppData");
        PFL_EXPECT(rows[7].byte_count == 362U);
        PFL_EXPECT(rows[7].packet_indices == std::vector<std::uint64_t> {17U});
        PFL_EXPECT(rows[7].has_constricted_contribution);
        PFL_EXPECT(rows[7].constricted_contribution_notes == std::vector<std::string>({
            "#18 contributed 8 / 362 bytes",
        }));
        PFL_EXPECT(rows[8].label == "TLS AppData");
        PFL_EXPECT(rows[8].byte_count == 62U);
        PFL_EXPECT(rows[8].packet_indices == std::vector<std::uint64_t> {18U});
        PFL_EXPECT(rows[8].has_constricted_contribution);
        PFL_EXPECT(rows[8].constricted_contribution_notes == std::vector<std::string>({
            "#19 contributed 8 / 62 bytes",
        }));
        PFL_EXPECT(std::none_of(rows.begin(), rows.end(), [](const StreamItemRow& row) {
            return row.label == "TLS Gap" || row.label == "TCP Payload";
        }));
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/quic/quic_constricted_1.pcap"), fast_options));
        CaptureSession moved_session {std::move(session)};
        moved_session.clear_runtime_caches_after_transfer();
        const auto moved_packet_rows = moved_session.list_flow_packets(0U, 0U, 32U);
        const auto rows = moved_session.list_flow_stream_items(0);
        PFL_REQUIRE(moved_packet_rows.size() == 18U);
        PFL_REQUIRE(rows.size() == 21U);

        PFL_EXPECT(rows.size() > 20U);
        PFL_EXPECT(rows[0].label == "QUIC Initial: CRYPTO");
        PFL_EXPECT(rows[0].byte_count == 855U);
        PFL_EXPECT(rows[0].packet_indices == std::vector<std::uint64_t>({0U}));
        PFL_EXPECT(!rows[0].has_constricted_contribution);
        PFL_EXPECT(rows[1].label == "QUIC Initial: CRYPTO");
        PFL_EXPECT(rows[1].byte_count == 99U);
        PFL_EXPECT(rows[1].packet_indices == std::vector<std::uint64_t>({0U}));
        PFL_EXPECT(!rows[1].has_constricted_contribution);
        PFL_EXPECT(rows[2].label == "QUIC Initial: CRYPTO");
        PFL_EXPECT(rows[2].byte_count == 950U);
        PFL_EXPECT(rows[2].packet_indices == std::vector<std::uint64_t>({1U}));
        PFL_EXPECT(!rows[2].has_constricted_contribution);
        PFL_EXPECT(rows[3].label == "QUIC Initial: ACK");
        PFL_EXPECT(rows[3].byte_count == 6U);
        PFL_EXPECT(rows[3].packet_indices == std::vector<std::uint64_t>({2U}));
        PFL_EXPECT(!rows[3].has_constricted_contribution);
        PFL_EXPECT(rows[4].label == "QUIC Initial: ACK");
        PFL_EXPECT(rows[4].byte_count == 6U);
        PFL_EXPECT(rows[4].packet_indices == std::vector<std::uint64_t>({3U}));
        PFL_EXPECT(!rows[4].has_constricted_contribution);
        PFL_EXPECT(rows[5].label == "QUIC Initial: CRYPTO");
        PFL_EXPECT(rows[5].byte_count == 1170U);
        PFL_EXPECT(rows[5].packet_indices == std::vector<std::uint64_t>({4U}));
        PFL_EXPECT(!rows[5].has_constricted_contribution);
        PFL_EXPECT(rows[6].label == "QUIC Initial: CRYPTO");
        PFL_EXPECT(rows[6].byte_count == 5U);
        PFL_EXPECT(rows[6].packet_indices == std::vector<std::uint64_t>({5U}));
        PFL_EXPECT(!rows[6].has_constricted_contribution);
        PFL_EXPECT(rows[7].label == "QUIC Initial: CRYPTO");
        PFL_EXPECT(rows[7].byte_count == 15U);
        PFL_EXPECT(rows[7].packet_indices == std::vector<std::uint64_t>({6U}));
        PFL_EXPECT(!rows[7].has_constricted_contribution);
        PFL_EXPECT(rows[8].label == "QUIC Initial: ACK");
        PFL_EXPECT(rows[8].byte_count == 6U);
        PFL_EXPECT(rows[8].packet_indices == std::vector<std::uint64_t>({7U}));
        PFL_EXPECT(!rows[8].has_constricted_contribution);
        PFL_EXPECT(rows[9].label == "Handshake");
        PFL_EXPECT(rows[9].byte_count == 1252U);
        PFL_EXPECT(rows[9].packet_indices == std::vector<std::uint64_t>({8U}));
        PFL_EXPECT(!rows[9].has_constricted_contribution);
        PFL_EXPECT(rows[10].label == "Handshake");
        PFL_EXPECT(rows[10].byte_count == 1252U);
        PFL_EXPECT(rows[10].packet_indices == std::vector<std::uint64_t>({9U}));
        PFL_EXPECT(!rows[10].has_constricted_contribution);
        PFL_EXPECT(rows[11].label == "Handshake");
        PFL_EXPECT(rows[11].byte_count == 42U);
        PFL_EXPECT(rows[11].packet_indices == std::vector<std::uint64_t>({10U}));
        PFL_EXPECT(!rows[11].has_constricted_contribution);
        PFL_EXPECT(rows[12].label == "Handshake");
        PFL_EXPECT(rows[12].byte_count == 1252U);
        PFL_EXPECT(rows[12].packet_indices == std::vector<std::uint64_t>({11U}));
        PFL_EXPECT(!rows[12].has_constricted_contribution);
        PFL_EXPECT(rows[13].label == "Handshake");
        PFL_EXPECT(rows[13].byte_count == 608U);
        PFL_EXPECT(rows[13].packet_indices == std::vector<std::uint64_t>({12U}));
        PFL_EXPECT(!rows[13].has_constricted_contribution);
        PFL_EXPECT(rows[14].label == "Protected payload");
        PFL_EXPECT(rows[14].byte_count == 69U);
        PFL_EXPECT(rows[14].packet_indices == std::vector<std::uint64_t>({12U}));
        PFL_EXPECT(rows[14].has_constricted_contribution);
        PFL_EXPECT(rows[15].label == "Handshake");
        PFL_EXPECT(rows[15].byte_count == 43U);
        PFL_EXPECT(rows[15].packet_indices == std::vector<std::uint64_t>({13U}));
        PFL_EXPECT(!rows[15].has_constricted_contribution);
        PFL_EXPECT(rows[16].label == "Handshake");
        PFL_EXPECT(rows[16].byte_count == 76U);
        PFL_EXPECT(rows[16].packet_indices == std::vector<std::uint64_t>({14U}));
        PFL_EXPECT(!rows[16].has_constricted_contribution);
        PFL_EXPECT(rows[17].label == "Protected payload");
        PFL_EXPECT(rows[17].byte_count == 55U);
        PFL_EXPECT(rows[17].packet_indices == std::vector<std::uint64_t>({14U}));
        PFL_EXPECT(rows[17].has_constricted_contribution);
        PFL_EXPECT(rows[18].label == "Protected payload");
        PFL_EXPECT(rows[18].byte_count == 78U);
        PFL_EXPECT(rows[18].packet_indices == std::vector<std::uint64_t>({15U}));
        PFL_EXPECT(rows[18].has_constricted_contribution);
        PFL_EXPECT(rows[19].label == "Protected payload");
        PFL_EXPECT(rows[19].byte_count == 766U);
        PFL_EXPECT(rows[19].packet_indices == std::vector<std::uint64_t>({16U}));
        PFL_EXPECT(rows[19].has_constricted_contribution);
        PFL_EXPECT(rows[20].label == "Protected payload");
        PFL_EXPECT(rows[20].byte_count == 736U);
        PFL_EXPECT(rows[20].packet_indices == std::vector<std::uint64_t>({17U}));
        PFL_EXPECT(rows[20].has_constricted_contribution);

        PFL_EXPECT(rows[14].constricted_contribution_notes == std::vector<std::string>({
            "#13 contributed 32 / 69 bytes",
        }));
        PFL_EXPECT(rows[17].constricted_contribution_notes == std::vector<std::string>({
            "#15 contributed 32 / 55 bytes",
        }));
        PFL_EXPECT(rows[18].constricted_contribution_notes == std::vector<std::string>({
            "#16 contributed 32 / 78 bytes",
        }));
        PFL_EXPECT(rows[19].constricted_contribution_notes == std::vector<std::string>({
            "#17 contributed 32 / 766 bytes",
        }));
        PFL_EXPECT(rows[20].constricted_contribution_notes == std::vector<std::string>({
            "#18 contributed 32 / 736 bytes",
        }));
        PFL_EXPECT(std::none_of(rows.begin(), rows.end(), [](const StreamItemRow& row) {
            return row.label == "QUIC Initial";
        }));
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/quic/ipv6_quic_constricted_1.pcap"), fast_options));

        const auto flows = session.list_flows();
        PFL_EXPECT(flows.size() == 1U);
        PFL_EXPECT(flows[0].protocol_hint == "quic");
        PFL_EXPECT(flows[0].service_hint == "www.instagram.com");
        PFL_EXPECT(flows[0].packet_count == 16U);

        const auto rows = session.list_flow_stream_items(0);
        PFL_EXPECT(rows.size() == 27U);

        PFL_EXPECT(rows[0].label == "QUIC Initial: CRYPTO");
        PFL_EXPECT(rows[0].byte_count == 820U);
        PFL_EXPECT(rows[0].packet_indices == std::vector<std::uint64_t>({0U}));
        PFL_EXPECT(!rows[0].has_constricted_contribution);
        PFL_EXPECT(rows[1].label == "QUIC Initial: CRYPTO");
        PFL_EXPECT(rows[1].byte_count == 111U);
        PFL_EXPECT(rows[1].packet_indices == std::vector<std::uint64_t>({0U}));
        PFL_EXPECT(!rows[1].has_constricted_contribution);
        PFL_EXPECT(rows[2].label == "QUIC Initial: CRYPTO");
        PFL_EXPECT(rows[2].byte_count == 928U);
        PFL_EXPECT(rows[2].packet_indices == std::vector<std::uint64_t>({1U}));
        PFL_EXPECT(!rows[2].has_constricted_contribution);
        PFL_EXPECT(rows[3].label == "QUIC Initial: CRYPTO");
        PFL_EXPECT(rows[3].byte_count == 820U);
        PFL_EXPECT(rows[3].packet_indices == std::vector<std::uint64_t>({2U}));
        PFL_EXPECT(!rows[3].has_constricted_contribution);
        PFL_EXPECT(rows[4].label == "QUIC Initial: CRYPTO");
        PFL_EXPECT(rows[4].byte_count == 111U);
        PFL_EXPECT(rows[4].packet_indices == std::vector<std::uint64_t>({2U}));
        PFL_EXPECT(!rows[4].has_constricted_contribution);
        PFL_EXPECT(rows[5].label == "QUIC Initial: CRYPTO");
        PFL_EXPECT(rows[5].byte_count == 928U);
        PFL_EXPECT(rows[5].packet_indices == std::vector<std::uint64_t>({3U}));
        PFL_EXPECT(!rows[5].has_constricted_contribution);
        PFL_EXPECT(rows[6].label == "QUIC Initial: CRYPTO");
        PFL_EXPECT(rows[6].byte_count == 1182U);
        PFL_EXPECT(rows[6].packet_indices == std::vector<std::uint64_t>({4U}));
        PFL_EXPECT(!rows[6].has_constricted_contribution);
        PFL_EXPECT(rows[7].label == "QUIC Initial: ACK");
        PFL_EXPECT(rows[7].byte_count == 6U);
        PFL_EXPECT(rows[7].packet_indices == std::vector<std::uint64_t>({4U}));
        PFL_EXPECT(!rows[7].has_constricted_contribution);
        PFL_EXPECT(rows[8].label == "QUIC Initial: ACK");
        PFL_EXPECT(rows[8].byte_count == 9U);
        PFL_EXPECT(rows[8].packet_indices == std::vector<std::uint64_t>({5U}));
        PFL_EXPECT(!rows[8].has_constricted_contribution);
        PFL_EXPECT(rows[9].label == "Handshake");
        PFL_EXPECT(rows[9].byte_count == 1232U);
        PFL_EXPECT(rows[9].packet_indices == std::vector<std::uint64_t>({6U}));
        PFL_EXPECT(!rows[9].has_constricted_contribution);
        PFL_EXPECT(rows[10].label == "Handshake");
        PFL_EXPECT(rows[10].byte_count == 1232U);
        PFL_EXPECT(rows[10].packet_indices == std::vector<std::uint64_t>({6U}));
        PFL_EXPECT(!rows[10].has_constricted_contribution);
        PFL_EXPECT(rows[11].label == "Handshake");
        PFL_EXPECT(rows[11].byte_count == 1232U);
        PFL_EXPECT(rows[11].packet_indices == std::vector<std::uint64_t>({6U}));
        PFL_EXPECT(!rows[11].has_constricted_contribution);
        PFL_EXPECT(rows[12].label == "Handshake");
        PFL_EXPECT(rows[12].byte_count == 661U);
        PFL_EXPECT(rows[12].packet_indices == std::vector<std::uint64_t>({6U}));
        PFL_EXPECT(!rows[12].has_constricted_contribution);
        PFL_EXPECT(rows[13].label == "Protected payload");
        PFL_EXPECT(rows[13].byte_count == 80U);
        PFL_EXPECT(rows[13].packet_indices == std::vector<std::uint64_t>({7U}));
        PFL_EXPECT(rows[13].has_constricted_contribution);
        PFL_EXPECT(rows[14].label == "Handshake");
        PFL_EXPECT(rows[14].byte_count == 46U);
        PFL_EXPECT(rows[14].packet_indices == std::vector<std::uint64_t>({8U}));
        PFL_EXPECT(!rows[14].has_constricted_contribution);
        PFL_EXPECT(rows[15].label == "Handshake");
        PFL_EXPECT(rows[15].byte_count == 76U);
        PFL_EXPECT(rows[15].packet_indices == std::vector<std::uint64_t>({9U}));
        PFL_EXPECT(!rows[15].has_constricted_contribution);
        PFL_EXPECT(rows[16].label == "Protected payload");
        PFL_EXPECT(rows[16].byte_count == 127U);
        PFL_EXPECT(rows[16].packet_indices == std::vector<std::uint64_t>({9U}));
        PFL_EXPECT(rows[16].has_constricted_contribution);
        PFL_EXPECT(rows[17].label == "Protected payload");
        PFL_EXPECT(rows[17].byte_count == 64U);
        PFL_EXPECT(rows[17].packet_indices == std::vector<std::uint64_t>({10U}));
        PFL_EXPECT(rows[17].has_constricted_contribution);
        PFL_EXPECT(rows[18].label == "Protected payload");
        PFL_EXPECT(rows[18].byte_count == 348U);
        PFL_EXPECT(rows[18].packet_indices == std::vector<std::uint64_t>({11U}));
        PFL_EXPECT(rows[18].has_constricted_contribution);
        PFL_EXPECT(rows[19].label == "QUIC Initial: ACK");
        PFL_EXPECT(rows[19].byte_count == 6U);
        PFL_EXPECT(rows[19].packet_indices == std::vector<std::uint64_t>({12U}));
        PFL_EXPECT(!rows[19].has_constricted_contribution);
        PFL_EXPECT(rows[20].label == "Handshake");
        PFL_EXPECT(rows[20].byte_count == 1232U);
        PFL_EXPECT(rows[20].packet_indices == std::vector<std::uint64_t>({12U}));
        PFL_EXPECT(!rows[20].has_constricted_contribution);
        PFL_EXPECT(rows[21].label == "Handshake");
        PFL_EXPECT(rows[21].byte_count == 1232U);
        PFL_EXPECT(rows[21].packet_indices == std::vector<std::uint64_t>({12U}));
        PFL_EXPECT(!rows[21].has_constricted_contribution);
        PFL_EXPECT(rows[22].label == "Protected payload");
        PFL_EXPECT(rows[22].byte_count == 59U);
        PFL_EXPECT(rows[22].packet_indices == std::vector<std::uint64_t>({12U}));
        PFL_EXPECT(rows[22].has_constricted_contribution);
        PFL_EXPECT(rows[23].label == "Handshake");
        PFL_EXPECT(rows[23].byte_count == 86U);
        PFL_EXPECT(rows[23].packet_indices == std::vector<std::uint64_t>({13U}));
        PFL_EXPECT(!rows[23].has_constricted_contribution);
        PFL_EXPECT(rows[24].label == "Protected payload");
        PFL_EXPECT(rows[24].byte_count == 36U);
        PFL_EXPECT(rows[24].packet_indices == std::vector<std::uint64_t>({13U}));
        PFL_EXPECT(!rows[24].has_constricted_contribution);
        PFL_EXPECT(rows[25].label == "Handshake");
        PFL_EXPECT(rows[25].byte_count == 42U);
        PFL_EXPECT(rows[25].packet_indices == std::vector<std::uint64_t>({14U}));
        PFL_EXPECT(!rows[25].has_constricted_contribution);
        PFL_EXPECT(rows[26].label == "Protected payload");
        PFL_EXPECT(rows[26].byte_count == 160U);
        PFL_EXPECT(rows[26].packet_indices == std::vector<std::uint64_t>({15U}));
        PFL_EXPECT(rows[26].has_constricted_contribution);

        PFL_EXPECT(rows[13].constricted_contribution_notes == std::vector<std::string>({
            "#8 contributed 32 / 80 bytes",
        }));
        PFL_EXPECT(rows[16].constricted_contribution_notes == std::vector<std::string>({
            "#10 contributed 32 / 127 bytes",
        }));
        PFL_EXPECT(rows[17].constricted_contribution_notes == std::vector<std::string>({
            "#11 contributed 32 / 64 bytes",
        }));
        PFL_EXPECT(rows[18].constricted_contribution_notes == std::vector<std::string>({
            "#12 contributed 32 / 348 bytes",
        }));
        PFL_EXPECT(rows[22].constricted_contribution_notes == std::vector<std::string>({
            "#13 contributed 32 / 59 bytes",
        }));
        PFL_EXPECT(rows[26].constricted_contribution_notes == std::vector<std::string>({
            "#16 contributed 32 / 160 bytes",
        }));
        PFL_EXPECT(std::none_of(rows.begin(), rows.end(), [](const StreamItemRow& row) {
            return row.label.find("PADDING") != std::string::npos || row.label == "QUIC Initial";
        }));
    }

    {
        // Correct packet-number handling lets packet #8 decrypt and expose its ACK frame.
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/quic/quic_initial_ack_decrypt_ok_1.pcap"), fast_options));

        const auto flows = session.list_flows();
        PFL_EXPECT(flows.size() == 1U);
        PFL_EXPECT(flows[0].protocol_hint == "quic");
        PFL_EXPECT(flows[0].packet_count == 8U);

        const auto rows = session.list_flow_stream_items(0);
        const auto packet_eight_row = std::find_if(rows.begin(), rows.end(), [](const StreamItemRow& row) {
            return row.packet_indices == std::vector<std::uint64_t> {7U};
        });
        PFL_EXPECT(packet_eight_row != rows.end());
        PFL_EXPECT(packet_eight_row->label == "QUIC Initial: ACK");
        PFL_EXPECT(packet_eight_row->label != "QUIC Initial");
        PFL_EXPECT(packet_eight_row->protocol_text.find("Frame Presence: ACK") != std::string::npos);
    }

    {
        // This fixture intentionally uses the wrong packet number, so packet #8 must fall back.
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/quic/quic_initial_ack_wrong_pkn_1.pcap"), fast_options));

        const auto flows = session.list_flows();
        PFL_EXPECT(flows.size() == 1U);
        PFL_EXPECT(flows[0].protocol_hint == "quic");
        PFL_EXPECT(flows[0].packet_count == 8U);

        const auto rows = session.list_flow_stream_items(0);
        const auto packet_eight_row = std::find_if(rows.begin(), rows.end(), [](const StreamItemRow& row) {
            return row.packet_indices == std::vector<std::uint64_t> {7U};
        });
        PFL_EXPECT(packet_eight_row != rows.end());
        PFL_EXPECT(packet_eight_row->label == "QUIC Initial");
        PFL_EXPECT(packet_eight_row->label != "QUIC Initial: ACK");
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/tls/tls_server_handshake_retransmit_6.pcap"), fast_options));

        const auto rows = session.list_flow_stream_items(0);
        PFL_EXPECT(!rows.empty());
        PFL_EXPECT(find_stream_row_by_label(rows, "TLS ClientHello") != nullptr);
        PFL_EXPECT(find_stream_row_by_label(rows, "TLS ServerHello") != nullptr);
        PFL_EXPECT(find_stream_row_by_label(rows, "TLS Certificate") != nullptr);
        PFL_EXPECT(find_stream_row_by_label(rows, "TLS ServerKeyExchange") != nullptr);
        PFL_EXPECT(find_stream_row_by_label(rows, "TLS ServerHelloDone") != nullptr);
        PFL_EXPECT(count_stream_rows_by_label(rows, "TLS ServerHello") == 1U);
        PFL_EXPECT(count_stream_rows_by_label(rows, "TLS Certificate") == 1U);
        PFL_EXPECT(count_stream_rows_by_label(rows, "TLS ServerKeyExchange") == 1U);
        PFL_EXPECT(count_stream_rows_by_label(rows, "TLS ServerHelloDone") == 1U);
        const auto* certificate = find_stream_row_by_label(rows, "TLS Certificate");
        PFL_EXPECT(certificate != nullptr);
        PFL_EXPECT(certificate->protocol_text.find("Certificate Entries:") != std::string::npos);
        PFL_EXPECT(certificate->protocol_text.find("Leaf Certificate Size:") != std::string::npos);
        const auto packet_rows = session.list_flow_packets(0);
        const auto multi_packet_handshake = std::find_if(rows.begin(), rows.end(), [](const StreamItemRow& row) {
            return (row.label == "TLS Certificate" || row.label == "TLS ServerKeyExchange" || row.label == "TLS ServerHelloDone")
                && row.packet_count > 1U;
        });
        PFL_REQUIRE(multi_packet_handshake != rows.end());
        const auto multi_packet_summary_layers = build_stream_summary_layers(*multi_packet_handshake, packet_rows);
        const auto* multi_packet_item_layer = find_top_level_summary_layer(multi_packet_summary_layers, "stream_item");
        const auto* multi_packet_tls_layer = find_top_level_summary_layer(multi_packet_summary_layers, "tls");
        PFL_REQUIRE(multi_packet_item_layer != nullptr);
        PFL_REQUIRE(multi_packet_tls_layer != nullptr);
        PFL_EXPECT(require_summary_field_value(*multi_packet_item_layer, "Details source") == "Stream item");
        PFL_EXPECT(require_summary_field_value(*multi_packet_item_layer, "Source packets").find('#') != std::string::npos);
        PFL_EXPECT(find_summary_field(*multi_packet_tls_layer, "Record Type") != nullptr);
        PFL_EXPECT(std::any_of(rows.begin(), rows.end(), [](const StreamItemRow& row) {
            return (row.label == "TLS Certificate" || row.label == "TLS ServerKeyExchange" || row.label == "TLS ServerHelloDone")
                && row.packet_count > 1U
                && !row.protocol_text.empty();
        }));
        PFL_EXPECT(std::any_of(rows.begin(), rows.end(), [](const StreamItemRow& row) {
            return starts_with(row.label, "TLS ") && row.label != "TCP Payload";
        }));
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/tcp/tcp_generic_payload_7.pcap"), fast_options));

        const auto rows = session.list_flow_stream_items(0);
        const auto bounded_rows = session.list_flow_stream_items_for_packet_prefix(0, 30U, 32U);
        PFL_EXPECT(!rows.empty());
        PFL_EXPECT(!bounded_rows.empty());
        for (const auto& row : rows) {
            PFL_EXPECT(row.label == "TCP Payload");
            PFL_EXPECT(!starts_with(row.label, "HTTP"));
            PFL_EXPECT(!starts_with(row.label, "TLS"));
            PFL_EXPECT(row.protocol_text.empty());
            PFL_EXPECT(row.payload_hex_text.empty());
        }
        for (const auto& row : bounded_rows) {
            PFL_EXPECT(row.label == "TCP Payload");
            PFL_EXPECT(!starts_with(row.label, "HTTP"));
            PFL_EXPECT(!starts_with(row.label, "TLS"));
        }
    }

    {
        const auto retransmit_capture_path = write_temp_pcap(
            "pfl_stream_query_retransmit_budget_parity.pcap",
            make_classic_pcap({
                {100U, make_ethernet_ipv4_tcp_packet_with_bytes_payload_and_sequence(
                    ipv4(10, 22, 0, 1), ipv4(10, 22, 0, 2), 44000, 80, make_text_bytes("alpha"), 1000U, 2000U, 0x18)},
                {200U, make_ethernet_ipv4_tcp_packet_with_bytes_payload_and_sequence(
                    ipv4(10, 22, 0, 1), ipv4(10, 22, 0, 2), 44000, 80, make_text_bytes("alpha"), 1000U, 2000U, 0x18)},
                {300U, make_ethernet_ipv4_tcp_packet_with_bytes_payload_and_sequence(
                    ipv4(10, 22, 1, 1), ipv4(10, 22, 1, 2), 44001, 80, make_text_bytes("clean"), 3000U, 4000U, 0x18)},
                {400U, make_ethernet_ipv4_tcp_packet_with_bytes_payload_and_sequence(
                    ipv4(10, 22, 1, 1), ipv4(10, 22, 1, 2), 44001, 80, make_text_bytes("other"), 3000U, 4000U, 0x18)},
            })
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(retransmit_capture_path, fast_options));

        const auto duplicated_full_rows = session.list_flow_stream_items(0U);
        const auto duplicated_bounded_rows = session.list_flow_stream_items_for_packet_prefix(0U, 2U, 2U);
        PFL_EXPECT(duplicated_full_rows.size() == 1U);
        expect_exact_stream_rows(duplicated_bounded_rows, duplicated_full_rows);

        const auto clean_full_rows = session.list_flow_stream_items(1U);
        const auto clean_bounded_rows = session.list_flow_stream_items_for_packet_prefix(1U, 2U, 3U);
        PFL_EXPECT(clean_full_rows.size() == 2U);
        expect_exact_stream_rows(clean_bounded_rows, clean_full_rows);
        PFL_EXPECT(clean_bounded_rows[0].label == "TCP Payload");
        PFL_EXPECT(clean_bounded_rows[1].label == "TCP Payload");
        PFL_EXPECT(clean_bounded_rows[0].packet_indices == std::vector<std::uint64_t>({2U}));
        PFL_EXPECT(clean_bounded_rows[1].packet_indices == std::vector<std::uint64_t>({3U}));
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/arp/01_arp_request_ipv4.pcap"), fast_options));

        const auto rows = session.list_flow_stream_items(0);
        PFL_EXPECT(rows.size() == 1U);
        PFL_EXPECT(rows[0].label.find("Who has 10.10.12.1? Tell 10.10.12.2") != std::string::npos);
        PFL_EXPECT(!rows[0].direction_text.empty());
        PFL_EXPECT(rows[0].packet_indices == std::vector<std::uint64_t>({0U}));
        PFL_EXPECT(rows[0].summary_text.find("Message: ARP Request") != std::string::npos);
        PFL_EXPECT(rows[0].payload_hex_text.find("00 01 08 00 06 04 00 01") != std::string::npos);
        PFL_EXPECT(rows[0].protocol_text.find("Protocol: ARP (Address Resolution Protocol)") != std::string::npos);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/arp/02_arp_reply_ipv4.pcap"), fast_options));

        const auto rows = session.list_flow_stream_items(0);
        PFL_EXPECT(rows.size() == 1U);
        PFL_EXPECT(rows[0].label.find("10.10.12.1 is at 02:00:00:00:00:01") != std::string::npos);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/arp/03_arp_request_reply_ipv4.pcap"), fast_options));

        const auto rows = session.list_flow_stream_items(0);
        PFL_EXPECT(rows.size() == 2U);
        PFL_EXPECT(rows[0].label.find("Who has 10.10.12.1? Tell 10.10.12.2") != std::string::npos);
        PFL_EXPECT(rows[1].label.find("10.10.12.1 is at 02:00:00:00:00:01") != std::string::npos);
        PFL_EXPECT(rows[0].packet_indices == std::vector<std::uint64_t>({0U}));
        PFL_EXPECT(rows[1].packet_indices == std::vector<std::uint64_t>({1U}));
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/arp/04_gratuitous_arp_request_ipv4.pcap"), fast_options));

        const auto rows = session.list_flow_stream_items(0);
        PFL_EXPECT(rows.size() == 1U);
        PFL_EXPECT(rows[0].label.find("Gratuitous ARP") != std::string::npos);
        PFL_EXPECT(rows[0].label.find("10.10.12.1") != std::string::npos);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/arp/06_arp_probe_ipv4.pcap"), fast_options));

        const auto rows = session.list_flow_stream_items(0);
        PFL_EXPECT(rows.size() == 1U);
        PFL_EXPECT(rows[0].label.find("ARP probe") != std::string::npos);
        PFL_EXPECT(rows[0].label.find("10.10.12.3") != std::string::npos);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/arp/08_arp_request_with_ethernet_padding.pcap"), fast_options));

        const auto rows = session.list_flow_stream_items(0);
        PFL_EXPECT(rows.size() == 1U);
        PFL_EXPECT(rows[0].payload_hex_text.find("00 01 08 00 06 04 00 01") != std::string::npos);
        PFL_EXPECT(rows[0].payload_hex_text.find("00000020") == std::string::npos);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/arp/09_truncated_arp_fixed_header.pcap"), fast_options));

        const auto rows = session.list_flow_stream_items(0);
        PFL_EXPECT(rows.size() == 1U);
        PFL_EXPECT(rows[0].label.find("Truncated ARP header") != std::string::npos);
        PFL_EXPECT(rows[0].protocol_text.find("Warning: ARP fixed header is truncated.") != std::string::npos);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/arp/11_snaplen_truncated_arp_request.pcap"), fast_options));

        const auto rows = session.list_flow_stream_items(0);
        PFL_EXPECT(rows.size() == 1U);
        PFL_EXPECT(rows[0].protocol_text.find("Warning: ARP address section is truncated.") != std::string::npos);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/arp/14_unknown_opcode.pcap"), fast_options));

        const auto rows = session.list_flow_stream_items(0);
        PFL_EXPECT(rows.size() == 1U);
        PFL_EXPECT(rows[0].label.find("ARP opcode 42") != std::string::npos);
    }
}

}  // namespace pfl::tests

