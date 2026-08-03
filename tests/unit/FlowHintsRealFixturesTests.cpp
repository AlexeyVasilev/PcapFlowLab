#include <algorithm>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

#include "TestSupport.h"
#include "app/frontend/FrontendSessionAdapter.h"
#include "app/session/CaptureSession.h"
#include "app/session/SessionTlsPresentation.h"

namespace pfl::tests {

namespace {

/*
 * Regression fixtures ported from the old project.
 * The capture files are reused as fixture data only; assertions target the
 * current Pcap Flow Lab API and current bounded QUIC Initial SNI extraction.
 */

struct FixtureExpectation {
    std::filesystem::path relative_path {};
    std::string expected_protocol_hint {};
    std::optional<std::string> expected_service_hint {};
};

struct QuicSniFixtureExpectation {
    std::filesystem::path relative_path {};
    std::optional<std::string> expected_sni {};
};

std::filesystem::path fixture_path(const std::filesystem::path& relative_path) {
    return std::filesystem::path(__FILE__).parent_path().parent_path() / "data" / relative_path;
}

bool has_matching_flow(const std::vector<FlowRow>& rows,
                       const std::string& protocol_hint,
                       const std::optional<std::string>& service_hint) {
    for (const auto& row : rows) {
        if (row.protocol_hint != protocol_hint) {
            continue;
        }

        if (service_hint.has_value() && row.service_hint != *service_hint) {
            continue;
        }

        return true;
    }

    return false;
}

std::optional<std::size_t> find_flow_index_with_protocol_hint(const std::vector<FlowRow>& rows,
                                                              const std::string& protocol_hint) {
    for (std::size_t index = 0U; index < rows.size(); ++index) {
        if (rows[index].protocol_hint == protocol_hint) {
            return index;
        }
    }

    return std::nullopt;
}

const session_detail::PacketSummaryLayer* find_summary_layer(
    const std::vector<session_detail::PacketSummaryLayer>& layers,
    const std::string& id,
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

std::vector<std::string> packet_byte_view_labels(const FrontendPacketDetailsDto& details) {
    std::vector<std::string> labels {};
    labels.reserve(details.byte_view_descriptors.size());
    for (const auto& descriptor : details.byte_view_descriptors) {
        labels.push_back(descriptor.label);
    }
    return labels;
}

const FrontendPacketDetailsDto::PacketByteViewDescriptor* find_packet_byte_view_descriptor(
    const FrontendPacketDetailsDto& details,
    const std::string& stable_id
) {
    const auto it = std::find_if(
        details.byte_view_descriptors.begin(),
        details.byte_view_descriptors.end(),
        [&](const FrontendPacketDetailsDto::PacketByteViewDescriptor& descriptor) {
            return descriptor.stable_id == stable_id;
        }
    );
    return it == details.byte_view_descriptors.end() ? nullptr : &(*it);
}

const session_detail::PacketSummaryField* find_summary_field(
    const session_detail::PacketSummaryLayer& layer,
    const std::string& label
) {
    const auto it = std::find_if(layer.fields.begin(), layer.fields.end(), [&](const session_detail::PacketSummaryField& field) {
        return field.label == label;
    });
    return it == layer.fields.end() ? nullptr : &(*it);
}

std::string require_summary_field_value(
    const session_detail::PacketSummaryLayer& layer,
    const std::string& label
) {
    const auto* field = find_summary_field(layer, label);
    PFL_REQUIRE(field != nullptr);
    return field->value;
}

void expect_fixture(const FixtureExpectation& expectation) {
    CaptureSession session {};
    PFL_EXPECT(session.open_capture(fixture_path(expectation.relative_path)));
    PFL_EXPECT(session.summary().packet_count > 0);

    const auto rows = session.list_flows();
    PFL_EXPECT(!rows.empty());

    if (expectation.expected_protocol_hint.empty()) {
        return;
    }

    PFL_EXPECT(has_matching_flow(rows, expectation.expected_protocol_hint, expectation.expected_service_hint));
}

void expect_quic_sni_fixture(const QuicSniFixtureExpectation& expectation) {
    CaptureSession deep_session {};
    PFL_EXPECT(deep_session.open_capture(fixture_path(expectation.relative_path)));
    const auto deep_rows = deep_session.list_flows();
    PFL_EXPECT(!deep_rows.empty());

    const auto deep_quic_flow_index = find_flow_index_with_protocol_hint(deep_rows, "quic");
    PFL_REQUIRE(deep_quic_flow_index.has_value());

    const auto& deep_quic_row = deep_rows[*deep_quic_flow_index];
    const auto deep_sni = deep_quic_row.service_hint.empty()
        ? std::optional<std::string> {}
        : std::optional<std::string> {deep_quic_row.service_hint};

    if (expectation.expected_sni.has_value()) {
        PFL_REQUIRE(deep_sni.has_value());
        PFL_EXPECT(*deep_sni == *expectation.expected_sni);
    } else {
        PFL_EXPECT(!deep_sni.has_value());
    }

    CaptureSession fast_session {};
    PFL_EXPECT(fast_session.open_capture(fixture_path(expectation.relative_path)));
    const auto fast_rows = fast_session.list_flows();
    PFL_EXPECT(!fast_rows.empty());

    const auto fast_quic_flow_index = find_flow_index_with_protocol_hint(fast_rows, "quic");
    PFL_REQUIRE(fast_quic_flow_index.has_value());

    const auto fast_sni = fast_session.derive_quic_service_hint_for_flow(*fast_quic_flow_index);
    if (expectation.expected_sni.has_value()) {
        PFL_REQUIRE(fast_sni.has_value());
        PFL_EXPECT(*fast_sni == *expectation.expected_sni);
    } else {
        PFL_EXPECT(!fast_sni.has_value());
    }

    PFL_EXPECT(fast_sni == deep_sni);
}

void expect_flow_row_accessor_matches_list_flows(const std::filesystem::path& relative_path) {
    CaptureSession session {};
    PFL_EXPECT(session.open_capture(fixture_path(relative_path)));

    const auto rows = session.list_flows();
    PFL_EXPECT(!rows.empty());

    const auto quic_flow_index = find_flow_index_with_protocol_hint(rows, "quic");
    PFL_REQUIRE(quic_flow_index.has_value());

    const auto row = session.flow_row(*quic_flow_index);
    PFL_REQUIRE(row.has_value());
    PFL_EXPECT(row->index == rows[*quic_flow_index].index);
    PFL_EXPECT(row->protocol_hint == rows[*quic_flow_index].protocol_hint);
    PFL_EXPECT(row->service_hint == rows[*quic_flow_index].service_hint);
    PFL_EXPECT(row->packet_count == rows[*quic_flow_index].packet_count);
    PFL_EXPECT(row->total_bytes == rows[*quic_flow_index].total_bytes);
}

void expect_frontend_adapter_quic_service_hint_refresh(
    const std::filesystem::path& relative_path,
    const std::string& expected_sni
) {
    FrontendSessionAdapter adapter {};
    const auto open_result = adapter.open_capture(fixture_path(relative_path));
    PFL_EXPECT(open_result.opened);

    const auto flows = adapter.get_flows();
    PFL_EXPECT(!flows.empty());

    const auto flow_it = std::find_if(flows.begin(), flows.end(), [](const FrontendFlowDto& flow) {
        return flow.protocol_hint == "quic";
    });
    PFL_EXPECT(flow_it != flows.end());
    PFL_EXPECT(flow_it->service_hint == expected_sni);

    const auto selection = adapter.select_flow(flow_it->flow_index);
    PFL_EXPECT(selection.selected);
    if (selection.updated_flow.has_value()) {
        PFL_EXPECT(selection.updated_flow->flow_index == flow_it->flow_index);
        PFL_EXPECT(selection.updated_flow->service_hint == expected_sni);
    }
}

void expect_frontend_adapter_selected_flow_packet_details_rejects_mismatched_packet(
    const std::filesystem::path& relative_path
) {
    FrontendSessionAdapter adapter {};
    const auto open_result = adapter.open_capture(fixture_path(relative_path));
    PFL_EXPECT(open_result.opened);

    const auto flows = adapter.get_flows();
    PFL_EXPECT(!flows.empty());

    const auto selection = adapter.select_flow(flows[0].flow_index);
    PFL_EXPECT(selection.selected);

    const auto selected_packets = adapter.get_selected_flow_packets(0U, 4U);
    PFL_EXPECT(selected_packets.packets.size() >= 2U);

    const auto mismatched_details = adapter.get_selected_flow_packet_details(
        selected_packets.packets[1].packet_index,
        selected_packets.packets[0].row_number
    );
    PFL_EXPECT(mismatched_details.error_text == "The selected packet is unavailable.");
}

void expect_frontend_adapter_stream_source_packets_use_bounded_flow_numbers(
    const std::filesystem::path& relative_path
) {
    FrontendSessionAdapter adapter {};
    const auto open_result = adapter.open_capture(fixture_path(relative_path));
    PFL_EXPECT(open_result.opened);

    const auto flows = adapter.get_flows();
    PFL_EXPECT(flows.size() == 1U);

    const auto selection = adapter.select_flow(flows[0].flow_index);
    PFL_EXPECT(selection.selected);

    const auto stream = adapter.get_selected_flow_stream(8U, 8U);
    PFL_EXPECT(stream.stream_available);
    PFL_EXPECT(stream.items.size() >= 2U);
    PFL_EXPECT(stream.items[0].source_packets_text == "packet #1");
    PFL_EXPECT(stream.items[1].source_packets_text == "packet #2");
}

void expect_frontend_adapter_selected_flow_packet_details_use_bounded_tls_window(
    const std::filesystem::path& relative_path
) {
    FrontendSessionAdapter adapter {};
    const auto open_result = adapter.open_capture(fixture_path(relative_path));
    PFL_EXPECT(open_result.opened);

    const auto flows = adapter.get_flows();
    PFL_REQUIRE(flows.size() == 1U);

    const auto selection = adapter.select_flow(flows[0].flow_index);
    PFL_EXPECT(selection.selected);

    const auto packets = adapter.get_selected_flow_packets(0U, 5U);
    PFL_REQUIRE(packets.packets.size() >= 5U);

    const auto& packet4 = packets.packets[3];
    const auto& packet5 = packets.packets[4];

    const auto details4_incomplete = adapter.get_selected_flow_packet_details(
        packet4.packet_index,
        packet4.row_number,
        4U
    );
    PFL_EXPECT(details4_incomplete.error_text.empty());
    const auto* packet4_incomplete_reassembled = find_summary_layer(details4_incomplete.summary_layers, "tls_reassembled");
    PFL_REQUIRE(packet4_incomplete_reassembled != nullptr);
    PFL_EXPECT(require_summary_field_value(*packet4_incomplete_reassembled, "Status") == "Incomplete in loaded packet window");

    const auto details4_loaded = adapter.get_selected_flow_packet_details(
        packet4.packet_index,
        packet4.row_number,
        5U
    );
    PFL_EXPECT(details4_loaded.error_text.empty());
    const auto* packet4_loaded_tls = find_summary_layer(details4_loaded.summary_layers, "tls");
    const auto* packet4_loaded_reassembled = find_summary_layer(details4_loaded.summary_layers, "tls_reassembled");
    PFL_REQUIRE(packet4_loaded_tls != nullptr);
    PFL_REQUIRE(packet4_loaded_reassembled != nullptr);
    PFL_EXPECT(require_summary_field_value(*packet4_loaded_reassembled, "Status") == "Continues in a later loaded packet");
    PFL_EXPECT(require_summary_field_value(*packet4_loaded_reassembled, "Contributing Flow Packets") == "4, 5");

    const auto details5_loaded = adapter.get_selected_flow_packet_details(
        packet5.packet_index,
        packet5.row_number,
        5U
    );
    PFL_EXPECT(details5_loaded.error_text.empty());
    const auto* packet5_loaded_tls = find_summary_layer(details5_loaded.summary_layers, "tls");
    const auto* packet5_loaded_reassembled = find_summary_layer(details5_loaded.summary_layers, "tls_reassembled");
    PFL_REQUIRE(packet5_loaded_tls != nullptr);
    PFL_REQUIRE(packet5_loaded_reassembled != nullptr);
    PFL_EXPECT(require_summary_field_value(*packet5_loaded_reassembled, "Status") == "Reassembled in this packet");
    PFL_EXPECT(require_summary_field_value(*packet5_loaded_reassembled, "Completion Flow Packet") == "5");
    PFL_EXPECT(require_summary_field_value(*packet5_loaded_tls, "Handshake Type") == "ClientHello");
    PFL_EXPECT(require_summary_field_value(*packet5_loaded_tls, "SNI") == "www.youtube.com");

    const auto packet3_details = adapter.get_selected_flow_packet_details(
        packets.packets[2].packet_index,
        packets.packets[2].row_number,
        5U
    );
    PFL_EXPECT(packet3_details.error_text.empty());
    const auto packet3_labels = packet_byte_view_labels(packet3_details);
    const auto packet4_labels = packet_byte_view_labels(details4_loaded);
    const auto packet5_labels = packet_byte_view_labels(details5_loaded);
    PFL_EXPECT(std::find(
        packet3_labels.begin(),
        packet3_labels.end(),
        "TLS Handshake Record (Reassembled)") == packet3_labels.end());
    PFL_EXPECT(std::find(
        packet4_labels.begin(),
        packet4_labels.end(),
        "TLS Handshake Record (Reassembled)") != packet4_labels.end());
    PFL_EXPECT(std::find(
        packet5_labels.begin(),
        packet5_labels.end(),
        "TLS Handshake Message, ClientHello (Reassembled)") != packet5_labels.end());

    const auto* packet4_record_descriptor = find_packet_byte_view_descriptor(details4_loaded, "tls_record:0:0");
    const auto* packet5_handshake_descriptor = find_packet_byte_view_descriptor(details5_loaded, "tls_handshake:0:0");
    PFL_REQUIRE(packet4_record_descriptor != nullptr);
    PFL_REQUIRE(packet5_handshake_descriptor != nullptr);
    PFL_EXPECT(packet4_record_descriptor->owner_kind == "tls_reconstructed_record");
    PFL_EXPECT(packet4_record_descriptor->assembly_kind == "reassembled");
    PFL_EXPECT(packet4_record_descriptor->contributing_unit_count == std::optional<std::uint32_t> {2U});
    PFL_EXPECT(packet4_record_descriptor->contributing_unit_kind == std::optional<std::string> {"tcp_segment"});
    PFL_EXPECT(packet5_handshake_descriptor->owner_kind == "tls_reconstructed_record");
    PFL_EXPECT(packet5_handshake_descriptor->assembly_kind == "reassembled");
    PFL_EXPECT(packet5_handshake_descriptor->contributing_unit_count == std::optional<std::uint32_t> {2U});
    PFL_EXPECT(packet5_handshake_descriptor->contributing_unit_kind == std::optional<std::string> {"tcp_segment"});

    const auto packet5_handshake_content = adapter.get_selected_flow_packet_byte_view_content(
        packet5.packet_index,
        "tls_handshake:0:0",
        packet5.row_number,
        5U
    );
    PFL_EXPECT(packet5_handshake_content.available);
    PFL_EXPECT(packet5_handshake_content.assembly_kind == "reassembled");
    PFL_EXPECT(packet5_handshake_content.contributing_unit_count == std::optional<std::uint32_t> {2U});
    PFL_EXPECT(packet5_handshake_content.contributing_unit_kind == std::optional<std::string> {"tcp_segment"});
    PFL_EXPECT(packet5_handshake_content.status_text.find("Reassembled from 2 TCP segments") != std::string::npos);
}

void expect_frontend_adapter_selected_flow_quic_reassembled_tls_byte_views() {
    FrontendSessionAdapter adapter {};
    const auto open_result = adapter.open_capture(fixture_path("parsing/quic/quic_example_2.pcap"));
    PFL_EXPECT(open_result.opened);

    const auto flows = adapter.get_flows();
    PFL_REQUIRE(flows.size() == 1U);
    const auto selection = adapter.select_flow(flows[0].flow_index);
    PFL_EXPECT(selection.selected);

    const auto packets = adapter.get_selected_flow_packets(0U, 3U);
    PFL_REQUIRE(packets.packets.size() >= 3U);
    const auto& packet3 = packets.packets[2];

    const auto details = adapter.get_selected_flow_packet_details(packet3.packet_index, packet3.row_number, 3U);
    PFL_EXPECT(details.error_text.empty());
    const auto labels = packet_byte_view_labels(details);
    PFL_EXPECT(std::find(labels.begin(), labels.end(), "QUIC Initial Decrypted Payload") != labels.end());
    PFL_EXPECT(std::find(labels.begin(), labels.end(), "CRYPTO Frame") != labels.end());
    PFL_EXPECT(std::find(labels.begin(), labels.end(), "CRYPTO Frame Data") != labels.end());
    PFL_EXPECT(std::find(labels.begin(), labels.end(), "QUIC CRYPTO Stream (Reassembled)") != labels.end());
    PFL_EXPECT(std::find(labels.begin(), labels.end(), "TLS Handshake Message, ClientHello (Reassembled)") != labels.end());
    PFL_EXPECT(std::find(labels.begin(), labels.end(), "TLS Handshake Record") == labels.end());

    const auto* crypto_stream_descriptor = find_packet_byte_view_descriptor(details, "quic_crypto_stream:0:0");
    const auto* tls_handshake_descriptor = find_packet_byte_view_descriptor(details, "tls_handshake:0:0");
    PFL_REQUIRE(crypto_stream_descriptor != nullptr);
    PFL_REQUIRE(tls_handshake_descriptor != nullptr);
    PFL_EXPECT(crypto_stream_descriptor->owner_kind == "quic_crypto_prefix");
    PFL_EXPECT(crypto_stream_descriptor->assembly_kind == "reassembled");
    PFL_EXPECT(crypto_stream_descriptor->contributing_unit_count == std::optional<std::uint32_t> {2U});
    PFL_EXPECT(crypto_stream_descriptor->contributing_unit_kind == std::optional<std::string> {"quic_crypto_frame"});
    PFL_EXPECT(crypto_stream_descriptor->parent_stable_id == std::optional<std::string> {"quic_initial_plaintext:0:0"});
    PFL_EXPECT(tls_handshake_descriptor->owner_kind == "quic_crypto_prefix");
    PFL_EXPECT(tls_handshake_descriptor->assembly_kind == "reassembled");
    PFL_EXPECT(tls_handshake_descriptor->contributing_unit_count == std::optional<std::uint32_t> {2U});
    PFL_EXPECT(tls_handshake_descriptor->contributing_unit_kind == std::optional<std::string> {"quic_crypto_frame"});
    PFL_EXPECT(tls_handshake_descriptor->parent_stable_id == std::optional<std::string> {"quic_crypto_stream:0:0"});

    const auto handshake_content = adapter.get_selected_flow_packet_byte_view_content(
        packet3.packet_index,
        "tls_handshake:0:0",
        packet3.row_number,
        3U
    );
    PFL_EXPECT(handshake_content.available);
    PFL_EXPECT(handshake_content.assembly_kind == "reassembled");
    PFL_EXPECT(handshake_content.contributing_unit_count == std::optional<std::uint32_t> {2U});
    PFL_EXPECT(handshake_content.contributing_unit_kind == std::optional<std::string> {"quic_crypto_frame"});
    PFL_EXPECT(handshake_content.status_text.find("Reassembled from 2 CRYPTO frames") != std::string::npos);
    PFL_EXPECT(handshake_content.formatted_text.find("01 00") != std::string::npos);
}

void expect_frontend_adapter_selected_flow_quic_early_reassembled_tls_byte_views() {
    FrontendSessionAdapter adapter {};
    const auto open_result = adapter.open_capture(fixture_path("parsing/quic/quic_example_2.pcap"));
    PFL_EXPECT(open_result.opened);

    const auto flows = adapter.get_flows();
    PFL_REQUIRE(flows.size() == 1U);
    const auto selection = adapter.select_flow(flows[0].flow_index);
    PFL_EXPECT(selection.selected);

    const auto packets = adapter.get_selected_flow_packets(0U, 3U);
    PFL_REQUIRE(packets.packets.size() >= 1U);
    const auto& packet1 = packets.packets[0];

    const auto details = adapter.get_selected_flow_packet_details(packet1.packet_index, packet1.row_number, 3U);
    PFL_EXPECT(details.error_text.empty());
    const auto* tls_layer = find_summary_layer(details.summary_layers, "tls");
    PFL_REQUIRE(tls_layer != nullptr);
    PFL_EXPECT(require_summary_field_value(*tls_layer, "Handshake Type") == "ClientHello");

    const auto labels = packet_byte_view_labels(details);
    PFL_EXPECT(std::find(labels.begin(), labels.end(), "QUIC Initial Decrypted Payload") != labels.end());
    PFL_EXPECT(std::find(labels.begin(), labels.end(), "CRYPTO Frame") != labels.end());
    PFL_EXPECT(std::find(labels.begin(), labels.end(), "CRYPTO Frame Data") != labels.end());
    PFL_EXPECT(std::find(labels.begin(), labels.end(), "QUIC CRYPTO Stream (Reassembled)") != labels.end());
    PFL_EXPECT(std::find(labels.begin(), labels.end(), "TLS Handshake Message, ClientHello (Reassembled)") != labels.end());
    PFL_EXPECT(std::find(labels.begin(), labels.end(), "TLS Handshake Record") == labels.end());

    const auto* crypto_stream_descriptor = find_packet_byte_view_descriptor(details, "quic_crypto_stream:0:0");
    const auto* tls_handshake_descriptor = find_packet_byte_view_descriptor(details, "tls_handshake:0:0");
    PFL_REQUIRE(crypto_stream_descriptor != nullptr);
    PFL_REQUIRE(tls_handshake_descriptor != nullptr);
    PFL_EXPECT(crypto_stream_descriptor->owner_kind == "quic_crypto_prefix");
    PFL_EXPECT(crypto_stream_descriptor->assembly_kind == "reassembled");
    PFL_EXPECT(crypto_stream_descriptor->contributing_unit_count == std::optional<std::uint32_t> {4U});
    PFL_EXPECT(crypto_stream_descriptor->contributing_unit_kind == std::optional<std::string> {"quic_crypto_frame"});
    PFL_EXPECT(crypto_stream_descriptor->parent_stable_id == std::optional<std::string> {"quic_initial_packet:0:0"});
    PFL_EXPECT(tls_handshake_descriptor->owner_kind == "quic_crypto_prefix");
    PFL_EXPECT(tls_handshake_descriptor->assembly_kind == "reassembled");
    PFL_EXPECT(tls_handshake_descriptor->contributing_unit_count == std::optional<std::uint32_t> {4U});
    PFL_EXPECT(tls_handshake_descriptor->contributing_unit_kind == std::optional<std::string> {"quic_crypto_frame"});
    PFL_EXPECT(tls_handshake_descriptor->parent_stable_id == std::optional<std::string> {"quic_crypto_stream:0:0"});

    const auto handshake_content = adapter.get_selected_flow_packet_byte_view_content(
        packet1.packet_index,
        "tls_handshake:0:0",
        packet1.row_number,
        3U
    );
    PFL_EXPECT(handshake_content.available);
    PFL_EXPECT(handshake_content.assembly_kind == "reassembled");
    PFL_EXPECT(handshake_content.contributing_unit_count == std::optional<std::uint32_t> {4U});
    PFL_EXPECT(handshake_content.contributing_unit_kind == std::optional<std::string> {"quic_crypto_frame"});
    PFL_EXPECT(handshake_content.status_text.find("Reassembled from 4 CRYPTO frames") != std::string::npos);
    PFL_EXPECT(handshake_content.formatted_text.find("01 00") != std::string::npos);
}

void expect_frontend_adapter_selected_flow_packet_byte_views() {
    FrontendSessionAdapter adapter {};
    const auto open_result = adapter.open_capture(fixture_path("parsing/http/http_get_1.pcap"));
    PFL_REQUIRE(open_result.opened);

    const auto flows = adapter.get_flows();
    PFL_REQUIRE(flows.size() == 1U);
    PFL_EXPECT(adapter.select_flow(flows[0].flow_index).selected);

    const auto packets = adapter.get_selected_flow_packets(0U, 4U);
    PFL_REQUIRE(packets.packets.size() == 1U);

    const auto& packet = packets.packets[0];
    const auto details = adapter.get_selected_flow_packet_details(packet.packet_index, packet.row_number, 1U);
    PFL_EXPECT(details.error_text.empty());
    PFL_EXPECT(details.packet_found);
    PFL_EXPECT(details.details_available);
    PFL_EXPECT(details.selected_byte_view.available);
    PFL_EXPECT(details.selected_byte_view.stable_id == "frame:0:0");
    PFL_EXPECT(details.selected_byte_view.label == "Frame");
    PFL_EXPECT(details.selected_byte_view.mode == "whole_unit");
    PFL_EXPECT(details.selected_byte_view.formatted_text.find("00000000") != std::string::npos);

    const std::vector<std::string> expected_labels {
        "Frame",
        "Ethernet II Frame",
        "IPv4 Packet",
        "TCP Segment",
    };
    PFL_EXPECT(packet_byte_view_labels(details) == expected_labels);
    PFL_REQUIRE(details.byte_view_descriptors.size() == 4U);
    PFL_EXPECT(details.byte_view_descriptors[0].stable_id == "frame:0:0");
    PFL_EXPECT(details.byte_view_descriptors[1].stable_id == "ethernet:0:0");
    PFL_EXPECT(details.byte_view_descriptors[2].stable_id == "ipv4:0:0");
    PFL_EXPECT(details.byte_view_descriptors[3].stable_id == "tcp:0:0");
    PFL_EXPECT(!details.byte_view_descriptors[0].parent_stable_id.has_value());
    PFL_EXPECT(details.byte_view_descriptors[1].parent_stable_id == std::optional<std::string> {"frame:0:0"});
    PFL_EXPECT(details.byte_view_descriptors[2].parent_stable_id == std::optional<std::string> {"ethernet:0:0"});
    PFL_EXPECT(details.byte_view_descriptors[3].parent_stable_id == std::optional<std::string> {"ipv4:0:0"});
    PFL_EXPECT(details.byte_view_descriptors[0].owner_kind == "captured_packet");
    PFL_EXPECT(details.byte_view_descriptors[3].owner_kind == "captured_packet");
    PFL_EXPECT(details.byte_view_descriptors[0].role == "protocol_unit");
    PFL_EXPECT(details.byte_view_descriptors[1].role == "protocol_unit");
    PFL_EXPECT(details.byte_view_descriptors[2].role == "protocol_unit");
    PFL_EXPECT(details.byte_view_descriptors[3].role == "protocol_unit");
    PFL_EXPECT(!details.byte_view_descriptors[0].supports_payload_only);
    PFL_EXPECT(details.byte_view_descriptors[1].supports_payload_only);
    PFL_EXPECT(details.byte_view_descriptors[2].supports_payload_only);
    PFL_EXPECT(details.byte_view_descriptors[3].supports_payload_only);
    PFL_REQUIRE(details.byte_view_descriptors[3].payload_available_length.has_value());

    const auto tcp_payload = adapter.get_selected_flow_packet_byte_view_content(
        packet.packet_index,
        "tcp:0:0",
        packet.row_number,
        1U
    );
    PFL_EXPECT(tcp_payload.available);
    PFL_EXPECT(tcp_payload.stable_id == "tcp:0:0");
    PFL_EXPECT(tcp_payload.mode == "whole_unit");
    PFL_EXPECT(tcp_payload.formatted_text.find("47 45 54 20 2f") != std::string::npos);
    PFL_EXPECT(tcp_payload.status_text.find("Available:") != std::string::npos);
}

void expect_bounded_tls_selected_flow_service_hint_query() {
    CaptureSession session {};
    PFL_EXPECT(session.open_capture(fixture_path("parsing/tls/tls_1_3_split_client_hello_10.pcap")));

    const auto rows = session.list_flows();
    PFL_REQUIRE(rows.size() == 1U);
    PFL_EXPECT(rows[0].protocol_hint == "tls");
    PFL_EXPECT(rows[0].service_hint == "www.youtube.com");

    PFL_EXPECT(!session_detail::derive_tls_service_hint_for_loaded_flow_prefix(session, 0U, 4U).has_value());

    session.prepare_selected_flow_packet_cache(0U, 5U);
    PFL_EXPECT(!session_detail::derive_tls_service_hint_for_loaded_flow_prefix(session, 0U, 4U).has_value());

    const auto loaded_hint = session_detail::derive_tls_service_hint_for_loaded_flow_prefix(session, 0U, 5U);
    PFL_REQUIRE(loaded_hint.has_value());
    PFL_EXPECT(*loaded_hint == "www.youtube.com");
}

void expect_non_client_hello_tls_selected_flow_service_hint_queries_return_empty() {
    constexpr const char* fixtures[] {
        "parsing/tls/tls_1_3_server_hello_6.pcap",
        "parsing/tls/tls_1_3_change_cipher_spec_8.pcap",
        "parsing/tls/tls_1_3_app_data_7.pcap",
    };

    for (const auto* fixture : fixtures) {
        ScopedTestContext context {std::string {"fixture="} + fixture};
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path(fixture)));
        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 1U);
        PFL_EXPECT(!session_detail::derive_tls_service_hint_for_loaded_flow_prefix(
            session,
            0U,
            session.flow_packet_count(0U)
        ).has_value());
    }
}

void expect_frontend_adapter_selected_flow_tls_service_hint_enrichment_uses_explicit_window() {
    FrontendSessionAdapter adapter {};
    const auto open_result = adapter.open_capture(fixture_path("parsing/tls/tls_1_3_split_client_hello_10.pcap"));
    PFL_EXPECT(open_result.opened);

    auto flows = adapter.get_flows();
    PFL_REQUIRE(flows.size() == 1U);
    PFL_EXPECT(flows[0].protocol_hint == "tls");
    PFL_EXPECT(flows[0].service_hint == "www.youtube.com");

    const auto selection = adapter.select_flow(flows[0].flow_index);
    PFL_EXPECT(selection.selected);
    PFL_EXPECT(!selection.updated_flow.has_value());

    const auto first_window = adapter.get_selected_flow_packets(0U, 4U);
    PFL_REQUIRE(first_window.packets.size() == 4U);
    PFL_EXPECT(!first_window.updated_flow.has_value());
    flows = adapter.get_flows();
    PFL_REQUIRE(flows.size() == 1U);
    PFL_EXPECT(flows[0].service_hint == "www.youtube.com");

    const auto second_window = adapter.get_selected_flow_packets(0U, 5U);
    PFL_REQUIRE(second_window.packets.size() == 5U);
    PFL_EXPECT(!second_window.updated_flow.has_value());
    flows = adapter.get_flows();
    PFL_REQUIRE(flows.size() == 1U);
    PFL_EXPECT(flows[0].service_hint == "www.youtube.com");

    const auto analysis = adapter.get_selected_flow_analysis();
    PFL_EXPECT(analysis.analysis_available);
    PFL_EXPECT(analysis.service_hint_text == "www.youtube.com");
}

void expect_frontend_adapter_selected_flow_tls_service_hint_preserves_existing_value() {
    FrontendSessionAdapter adapter {};
    const auto open_result = adapter.open_capture(fixture_path("parsing/tls/tls_client_hello_1.pcap"));
    PFL_EXPECT(open_result.opened);

    auto flows = adapter.get_flows();
    PFL_REQUIRE(flows.size() == 1U);
    PFL_EXPECT(flows[0].service_hint == "auth.split.io");

    const auto selection = adapter.select_flow(flows[0].flow_index);
    PFL_EXPECT(selection.selected);

    const auto packets = adapter.get_selected_flow_packets(0U, 1U);
    PFL_REQUIRE(packets.packets.size() == 1U);
    PFL_EXPECT(!packets.updated_flow.has_value());

    flows = adapter.get_flows();
    PFL_REQUIRE(flows.size() == 1U);
    PFL_EXPECT(flows[0].service_hint == "auth.split.io");
}

void expect_frontend_adapter_selected_flow_packet_details_require_explicit_tls_window() {
    FrontendSessionAdapter adapter {};
    const auto open_result = adapter.open_capture(fixture_path("parsing/tls/tls_1_3_split_client_hello_10.pcap"));
    PFL_EXPECT(open_result.opened);

    const auto flows = adapter.get_flows();
    PFL_REQUIRE(flows.size() == 1U);
    const auto selection = adapter.select_flow(flows[0].flow_index);
    PFL_EXPECT(selection.selected);

    const auto packets = adapter.get_selected_flow_packets(0U, 5U);
    PFL_REQUIRE(packets.packets.size() >= 5U);

    const auto& packet4 = packets.packets[3];
    const auto& packet5 = packets.packets[4];

    const auto details4_zero_window = adapter.get_selected_flow_packet_details(
        packet4.packet_index,
        packet4.row_number,
        0U
    );
    PFL_EXPECT(details4_zero_window.error_text.empty());
    PFL_EXPECT(find_summary_layer(details4_zero_window.summary_layers, "tls") != nullptr);
    PFL_EXPECT(find_summary_layer(details4_zero_window.summary_layers, "tls_reassembled") == nullptr);

    const auto details5_zero_window = adapter.get_selected_flow_packet_details(
        packet5.packet_index,
        packet5.row_number,
        0U
    );
    PFL_EXPECT(details5_zero_window.error_text.empty());
    PFL_EXPECT(find_summary_layer(details5_zero_window.summary_layers, "tls") == nullptr);
    PFL_EXPECT(find_summary_layer(details5_zero_window.summary_layers, "tls_reassembled") == nullptr);
}

}  // namespace

void run_flow_hints_real_fixtures_tests() {
    const std::vector<FixtureExpectation> fixtures {
        {.relative_path = "parsing/http/http_get_1.pcap", .expected_protocol_hint = "http", .expected_service_hint = "www.kresla-darom.ru"},
        {.relative_path = "parsing/http/http_answer_2.pcap", .expected_protocol_hint = "http"},
        {.relative_path = "parsing/dns/dns_request_1.pcap", .expected_protocol_hint = "dns", .expected_service_hint = "gsp85-ssl.ls.apple.com"},
        {.relative_path = "parsing/dns/dns_response_2.pcap", .expected_protocol_hint = "dns", .expected_service_hint = "_dns.resolver.arpa"},
        {.relative_path = "parsing/tls/tls_client_hello_1.pcap", .expected_protocol_hint = "tls", .expected_service_hint = "auth.split.io"},
        {.relative_path = "parsing/tls/tls_1_2_change_cipher_spec_2.pcap", .expected_protocol_hint = "tls"},
        {.relative_path = "parsing/tls/tls_1_2_app_data_3.pcap", .expected_protocol_hint = "tls"},
        {.relative_path = "parsing/tls/tls_1_2_server_hello_4.pcap", .expected_protocol_hint = "tls"},
        {.relative_path = "parsing/tls/tls_1_2_new_session_ticket_9.pcap", .expected_protocol_hint = "tls"},
        {.relative_path = "parsing/tls/tls_1_0_badssl_baseline_12.pcap", .expected_protocol_hint = "tls", .expected_service_hint = "tls-v1-0.badssl.com"},
        {.relative_path = "parsing/tls/tls_1_1_badssl_baseline_13.pcap", .expected_protocol_hint = "tls", .expected_service_hint = "tls-v1-1.badssl.com"},
        {.relative_path = "parsing/tls/tls_1_2_badssl_baseline_14.pcap", .expected_protocol_hint = "tls", .expected_service_hint = "tls-v1-2.badssl.com"},
        {.relative_path = "parsing/tls/tls_1_2_client_to_tls_1_0_protocol_version_15.pcap", .expected_protocol_hint = "tls", .expected_service_hint = "tls-v1-0.badssl.com"},
        {.relative_path = "parsing/tls/tls_1_2_expired_certificate_alert_16.pcap", .expected_protocol_hint = "tls", .expected_service_hint = "expired.badssl.com"},
        {.relative_path = "parsing/tls/tls_1_2_self_signed_unknown_ca_17.pcap", .expected_protocol_hint = "tls", .expected_service_hint = "self-signed.badssl.com"},
        {.relative_path = "parsing/tls/tls_1_2_client_certificate_missing_18.pcap", .expected_protocol_hint = "tls", .expected_service_hint = "client-cert-missing.badssl.com"},
        {.relative_path = "parsing/tls/tls_1_2_status_request_alpn_19.pcap", .expected_protocol_hint = "tls", .expected_service_hint = "tls-v1-2.badssl.com"},
        {.relative_path = "parsing/tls/tls_1_3_client_hello_5.pcap", .expected_protocol_hint = "tls", .expected_service_hint = "p101-fmf.icloud.com"},
        {.relative_path = "parsing/tls/tls_1_3_server_hello_6.pcap", .expected_protocol_hint = "tls"},
        {.relative_path = "parsing/tls/tls_1_3_app_data_7.pcap", .expected_protocol_hint = "tls"},
        {.relative_path = "parsing/tls/tls_1_3_change_cipher_spec_8.pcap", .expected_protocol_hint = "tls"},
        {.relative_path = "parsing/tls/tls_1_3_split_client_hello_10.pcap", .expected_protocol_hint = "tls", .expected_service_hint = "www.youtube.com"},
        {.relative_path = "parsing/tls/ipv6_tls_constricted_1.pcap", .expected_protocol_hint = "tls", .expected_service_hint = "www.youtube.com"},
        {.relative_path = "parsing/tls/ipv6_tls_strong_constrict_1.pcap", .expected_protocol_hint = "tls", .expected_service_hint = "www.youtube.com"},
        {.relative_path = "parsing/quic/quic_initial_ch_1.pcap", .expected_protocol_hint = "quic"},
        {.relative_path = "parsing/quic/quic_initial_sh_2.pcap", .expected_protocol_hint = "quic"},
        {.relative_path = "parsing/quic/quic_handshake_3.pcap", .expected_protocol_hint = "quic"},
        {.relative_path = "parsing/quic/ipv6_quic_constricted_1.pcap", .expected_protocol_hint = "quic"},
        {.relative_path = "parsing/quic/quic_protected_payload_4.pcap", .expected_protocol_hint = ""},
        {.relative_path = "parsing/quic/quic_test_3.pcap", .expected_protocol_hint = "quic"},
    };

    for (const auto& fixture : fixtures) {
        expect_fixture(fixture);
    }

    const std::vector<QuicSniFixtureExpectation> quic_sni_fixtures {
        {.relative_path = "parsing/quic/quic_test_1.pcap", .expected_sni = std::optional<std::string> {"rr1---sn-ug5on-unxs.googlevideo.com"}},
        {.relative_path = "parsing/quic/quic_test_2.pcap", .expected_sni = std::optional<std::string> {"www.youtube.com"}},
        {.relative_path = "parsing/quic/quic_test_3.pcap", .expected_sni = std::optional<std::string> {"log22-normal-useast1a.tiktokv.com"}},
        {.relative_path = "parsing/quic/quic_test_4.pcap", .expected_sni = std::nullopt},
        {.relative_path = "parsing/quic/quic_test_5.pcap", .expected_sni = std::nullopt},
    };

    for (const auto& fixture : quic_sni_fixtures) {
        expect_quic_sni_fixture(fixture);
    }

    expect_frontend_adapter_quic_service_hint_refresh(
        "parsing/quic/quic_test_1.pcap",
        "rr1---sn-ug5on-unxs.googlevideo.com");
    expect_frontend_adapter_selected_flow_packet_details_rejects_mismatched_packet("parsing/quic/quic_test_1.pcap");
    expect_frontend_adapter_selected_flow_packet_byte_views();
    expect_frontend_adapter_selected_flow_packet_details_use_bounded_tls_window("parsing/tls/tls_1_3_split_client_hello_10.pcap");
    expect_frontend_adapter_selected_flow_quic_early_reassembled_tls_byte_views();
    expect_frontend_adapter_selected_flow_quic_reassembled_tls_byte_views();
    expect_bounded_tls_selected_flow_service_hint_query();
    expect_non_client_hello_tls_selected_flow_service_hint_queries_return_empty();
    expect_frontend_adapter_selected_flow_tls_service_hint_enrichment_uses_explicit_window();
    expect_frontend_adapter_selected_flow_tls_service_hint_preserves_existing_value();
    expect_frontend_adapter_selected_flow_packet_details_require_explicit_tls_window();
    expect_frontend_adapter_stream_source_packets_use_bounded_flow_numbers("parsing/arp/03_arp_request_reply_ipv4.pcap");
    expect_flow_row_accessor_matches_list_flows("parsing/quic/quic_test_1.pcap");
}

}  // namespace pfl::tests

