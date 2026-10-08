#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "TestSupport.h"
#include "app/session/CaptureSession.h"
#include "app/session/SelectedFlowPacketSemantics.h"
#include "app/session/SelectedPacketBytePresentation.h"
#include "app/session/SelectedPacketSummaryPreparation.h"
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

bool contains_text(const std::string& text, const std::string_view expected) {
    return text.find(std::string {expected}) != std::string::npos;
}

struct ExpectedFlowShape {
    std::uint64_t capture_packet_count {0};
    std::uint64_t capture_flow_count {0};
    std::uint64_t flow_packet_count {0};
    std::string address_a {};
    std::uint16_t port_a {0};
    std::string address_b {};
    std::uint16_t port_b {0};
};

FlowRow require_single_udp_flow(const std::filesystem::path& relative_path, const ExpectedFlowShape& expected) {
    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(fixture_path(relative_path)));
    PFL_EXPECT(session.summary().packet_count == expected.capture_packet_count);
    PFL_EXPECT(session.summary().flow_count == expected.capture_flow_count);

    const auto rows = session.list_flows();
    PFL_REQUIRE(rows.size() == 1U);
    const auto& row = rows[0];
    PFL_EXPECT(row.protocol_text == "UDP");
    PFL_EXPECT(row.packet_count == expected.flow_packet_count);
    PFL_EXPECT(row.address_a == expected.address_a);
    PFL_EXPECT(row.port_a == expected.port_a);
    PFL_EXPECT(row.address_b == expected.address_b);
    PFL_EXPECT(row.port_b == expected.port_b);
    return row;
}

void expect_no_detected_application_protocol(const std::filesystem::path& relative_path, const ExpectedFlowShape& expected) {
    const auto row = require_single_udp_flow(relative_path, expected);
    PFL_EXPECT(row.protocol_hint.empty());
    PFL_EXPECT(row.service_hint.empty());
}

void expect_detected_ntp_protocol(const std::filesystem::path& relative_path, const ExpectedFlowShape& expected) {
    const auto row = require_single_udp_flow(relative_path, expected);
    PFL_EXPECT(row.protocol_hint == "ntp");
    PFL_EXPECT(row.service_hint.empty());
}

ExpectedFlowShape client_to_server_one_packet(const std::uint16_t server_port) {
    return ExpectedFlowShape {
        .capture_packet_count = 1U,
        .capture_flow_count = 1U,
        .flow_packet_count = 1U,
        .address_a = "192.0.2.170",
        .port_a = 59000U,
        .address_b = "192.0.2.180",
        .port_b = server_port,
    };
}

ExpectedFlowShape server_to_client_one_packet() {
    return ExpectedFlowShape {
        .capture_packet_count = 1U,
        .capture_flow_count = 1U,
        .flow_packet_count = 1U,
        .address_a = "192.0.2.180",
        .port_a = 123U,
        .address_b = "192.0.2.170",
        .port_b = 59000U,
    };
}

ExpectedFlowShape client_server_exchange_two_packets() {
    return ExpectedFlowShape {
        .capture_packet_count = 2U,
        .capture_flow_count = 1U,
        .flow_packet_count = 2U,
        .address_a = "192.0.2.170",
        .port_a = 59000U,
        .address_b = "192.0.2.180",
        .port_b = 123U,
    };
}

struct SelectedPacketTransportPayloadLengths {
    std::optional<std::uint32_t> captured_transport_payload_length {};
    std::optional<std::uint32_t> original_transport_payload_length {};
};

SelectedPacketTransportPayloadLengths resolve_selected_packet_transport_payload_lengths(
    CaptureSession& session,
    const PacketRef& packet
) {
    return SelectedPacketTransportPayloadLengths {
        .captured_transport_payload_length =
            session_detail::derive_captured_transport_payload_length_from_headers(session, packet),
        .original_transport_payload_length =
            session_detail::derive_original_transport_payload_length_from_headers(session, packet),
    };
}

struct SelectedPacketFlowContext {
    std::optional<std::size_t> flow_index {};
    std::optional<std::uint64_t> flow_packet_index {};
    std::optional<std::size_t> loaded_packet_window_count {};
};

SelectedPacketFlowContext resolve_selected_packet_flow_context(CaptureSession& session, const PacketRef& packet) {
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

std::vector<session_detail::PacketSummaryLayer> build_fixture_summary_layers(
    const std::filesystem::path& relative_fixture_path,
    const std::uint64_t packet_index = 0U
) {
    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(fixture_path(relative_fixture_path)));
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

const session_detail::PacketSummaryLayer* expect_ntp_summary_layer(
    const std::vector<session_detail::PacketSummaryLayer>& layers
) {
    const auto* ntp_layer = find_summary_layer(layers, "ntp");
    PFL_EXPECT(ntp_layer != nullptr);
    return ntp_layer;
}

void expect_summary_field_equals(
    const session_detail::PacketSummaryLayer& layer,
    const std::string& label,
    const std::string& expected
) {
    const auto* field = find_summary_field(layer, label);
    PFL_EXPECT(field != nullptr);
    if (field != nullptr) {
        PFL_EXPECT(field->value == expected);
    }
}

void expect_summary_field_contains(
    const session_detail::PacketSummaryLayer& layer,
    const std::string& label,
    const std::string_view expected
) {
    const auto* field = find_summary_field(layer, label);
    PFL_EXPECT(field != nullptr);
    if (field != nullptr) {
        PFL_EXPECT(contains_text(field->value, expected));
    }
}

void expect_summary_field_present(const session_detail::PacketSummaryLayer& layer, const std::string& label) {
    PFL_EXPECT(find_summary_field(layer, label) != nullptr);
}

const session_detail::SelectedPacketByteViewPresentationDescriptor* find_byte_view_descriptor_by_label(
    const std::vector<session_detail::SelectedPacketByteViewPresentationDescriptor>& descriptors,
    const std::string& label
) {
    const auto it = std::find_if(descriptors.begin(), descriptors.end(), [&](const auto& descriptor) {
        return descriptor.label == label;
    });
    return it != descriptors.end() ? &(*it) : nullptr;
}

void expect_target_positive_detection() {
    // Target: NTPv4 mode-3 client request, ephemeral -> UDP/123.
    expect_detected_ntp_protocol(
        "parsing/ntp/01_ntpv4_client_request_port123.pcap",
        client_to_server_one_packet(123U));

    // Target: NTPv4 mode-4 server response, UDP/123 -> ephemeral.
    expect_detected_ntp_protocol(
        "parsing/ntp/02_ntpv4_server_response_port123.pcap",
        server_to_client_one_packet());

    // Target: NTPv3 mode-3 client request.
    expect_detected_ntp_protocol(
        "parsing/ntp/03_ntpv3_client_request_port123.pcap",
        client_to_server_one_packet(123U));

    // Target: NTPv3 mode-4 server response.
    expect_detected_ntp_protocol(
        "parsing/ntp/04_ntpv3_server_response_port123.pcap",
        server_to_client_one_packet());

    // Target: NTPv4 mode-4 stratum-0 KoD-style RATE response.
    expect_detected_ntp_protocol(
        "parsing/ntp/05_ntpv4_kod_rate_response.pcap",
        server_to_client_one_packet());
}

void expect_structured_fixture_shapes_and_detection() {
    expect_detected_ntp_protocol(
        "parsing/ntp/11_ntpv4_structured_exchange.pcap",
        client_server_exchange_two_packets());

    expect_detected_ntp_protocol(
        "parsing/ntp/12_ntpv3_structured_server_response.pcap",
        server_to_client_one_packet());

    expect_detected_ntp_protocol(
        "parsing/ntp/13_ntpv4_unsynchronized_stratum16.pcap",
        server_to_client_one_packet());

    expect_detected_ntp_protocol(
        "parsing/ntp/14_ntpv4_large_root_delay.pcap",
        server_to_client_one_packet());

    expect_detected_ntp_protocol(
        "parsing/ntp/15_ntpv4_era0_last_second.pcap",
        server_to_client_one_packet());

    expect_detected_ntp_protocol(
        "parsing/ntp/16_ntpv3_signed_root_delay.pcap",
        server_to_client_one_packet());
}

void expect_permanent_negative_or_unsupported_baseline() {
    // Invariant: UDP/123 alone must not imply NTP.
    expect_no_detected_application_protocol(
        "parsing/ntp/06_ntp_garbage_port123.pcap",
        client_to_server_one_packet(123U));

    // Invariant: valid-looking NTP content on non-NTP ports is insufficient.
    expect_no_detected_application_protocol(
        "parsing/ntp/07_ntpv4_client_wrong_ports.pcap",
        client_to_server_one_packet(30123U));

    // First PFL support intentionally excludes NTPv2; this is not malformed NTP.
    expect_no_detected_application_protocol(
        "parsing/ntp/08_ntpv2_client_port123.pcap",
        client_to_server_one_packet(123U));

    // First PFL support intentionally excludes broadcast mode 5; this may be valid-family NTP.
    expect_no_detected_application_protocol(
        "parsing/ntp/09_ntpv4_broadcast_mode5.pcap",
        server_to_client_one_packet());

    // Invariant: an incomplete 47-byte basic header must not detect as NTP.
    expect_no_detected_application_protocol(
        "parsing/ntp/10_ntpv4_truncated_47_byte_header.pcap",
        client_to_server_one_packet(123U));
}

void expect_future_ntp_summary_for_structured_v4_client_packet() {
    const auto summary_layers = build_fixture_summary_layers("parsing/ntp/11_ntpv4_structured_exchange.pcap", 0U);
    const auto* ntp_layer = expect_ntp_summary_layer(summary_layers);
    if (ntp_layer == nullptr) {
        return;
    }

    PFL_EXPECT(ntp_layer->title == "Network Time Protocol");
    expect_summary_field_equals(*ntp_layer, "Version", "4");
    expect_summary_field_contains(*ntp_layer, "Mode", "Client");
    expect_summary_field_contains(*ntp_layer, "Mode", "3");
    expect_summary_field_contains(*ntp_layer, "Leap Indicator", "0");
    expect_summary_field_contains(*ntp_layer, "Leap Indicator", "No");
    expect_summary_field_equals(*ntp_layer, "Stratum", "Unspecified or invalid (0)");
    expect_summary_field_contains(*ntp_layer, "Poll", "6");
    expect_summary_field_contains(*ntp_layer, "Poll", "64");
    expect_summary_field_contains(*ntp_layer, "Precision", "-20");
    expect_summary_field_contains(*ntp_layer, "Root Delay", "0");
    expect_summary_field_contains(*ntp_layer, "Root Dispersion", "0");
    expect_summary_field_equals(*ntp_layer, "Reference Timestamp", "Unspecified");
    expect_summary_field_equals(*ntp_layer, "Originate Timestamp", "Unspecified");
    expect_summary_field_equals(*ntp_layer, "Receive Timestamp", "Unspecified");
    expect_summary_field_equals(*ntp_layer, "Transmit Timestamp", "2026-01-02 03:04:05.250000 UTC");
}

void expect_future_ntp_summary_for_structured_v4_server_packet() {
    const auto summary_layers = build_fixture_summary_layers("parsing/ntp/11_ntpv4_structured_exchange.pcap", 1U);
    const auto* ntp_layer = expect_ntp_summary_layer(summary_layers);
    if (ntp_layer == nullptr) {
        return;
    }

    expect_summary_field_equals(*ntp_layer, "Version", "4");
    expect_summary_field_contains(*ntp_layer, "Mode", "Server");
    expect_summary_field_contains(*ntp_layer, "Mode", "4");
    expect_summary_field_equals(*ntp_layer, "Stratum", "Secondary reference (2)");
    expect_summary_field_contains(*ntp_layer, "Poll", "6");
    expect_summary_field_contains(*ntp_layer, "Precision", "-20");
    expect_summary_field_contains(*ntp_layer, "Root Delay", "0.125");
    expect_summary_field_contains(*ntp_layer, "Root Delay", "s");
    expect_summary_field_contains(*ntp_layer, "Root Dispersion", "0.25");
    expect_summary_field_contains(*ntp_layer, "Root Dispersion", "s");
    expect_summary_field_equals(*ntp_layer, "Reference ID", "192.0.2.1");
    expect_summary_field_equals(*ntp_layer, "Reference Timestamp", "2026-01-02 03:00:00.500000 UTC");
    expect_summary_field_equals(*ntp_layer, "Originate Timestamp", "2026-01-02 03:04:05.250000 UTC");
    expect_summary_field_equals(*ntp_layer, "Receive Timestamp", "2026-01-02 03:04:05.375000 UTC");
    expect_summary_field_equals(*ntp_layer, "Transmit Timestamp", "2026-01-02 03:04:05.500000 UTC");
}

void expect_future_ntp_summary_for_structured_v3_server_packet() {
    const auto summary_layers = build_fixture_summary_layers("parsing/ntp/12_ntpv3_structured_server_response.pcap");
    const auto* ntp_layer = expect_ntp_summary_layer(summary_layers);
    if (ntp_layer == nullptr) {
        return;
    }

    expect_summary_field_equals(*ntp_layer, "Version", "3");
    expect_summary_field_contains(*ntp_layer, "Mode", "Server");
    expect_summary_field_contains(*ntp_layer, "Mode", "4");
    expect_summary_field_equals(*ntp_layer, "Stratum", "Primary reference (1)");
    expect_summary_field_contains(*ntp_layer, "Poll", "4");
    expect_summary_field_contains(*ntp_layer, "Precision", "-18");
    expect_summary_field_contains(*ntp_layer, "Reference ID", "GPS");
    expect_summary_field_contains(*ntp_layer, "Reference Timestamp", "2026-01-03 04:00:00.250000 UTC");
    expect_summary_field_contains(*ntp_layer, "Transmit Timestamp", "2026-01-03 04:00:03.250000 UTC");
    expect_summary_field_present(*ntp_layer, "Originate Timestamp");
    expect_summary_field_present(*ntp_layer, "Receive Timestamp");
}

void expect_future_ntp_summary_for_unsynchronized_boundary_packet() {
    const auto summary_layers = build_fixture_summary_layers("parsing/ntp/13_ntpv4_unsynchronized_stratum16.pcap");
    const auto* ntp_layer = expect_ntp_summary_layer(summary_layers);
    if (ntp_layer == nullptr) {
        return;
    }

    expect_summary_field_contains(*ntp_layer, "Leap Indicator", "3");
    expect_summary_field_contains(*ntp_layer, "Leap Indicator", "Unsynchronized");
    expect_summary_field_equals(*ntp_layer, "Stratum", "Unsynchronized (16)");
    expect_summary_field_equals(*ntp_layer, "Reference ID", "83.84.69.80");
}

void expect_future_ntp_summary_for_v4_large_unsigned_fixed_point_packet() {
    const auto summary_layers = build_fixture_summary_layers("parsing/ntp/14_ntpv4_large_root_delay.pcap");
    const auto* ntp_layer = expect_ntp_summary_layer(summary_layers);
    if (ntp_layer == nullptr) {
        return;
    }

    expect_summary_field_equals(*ntp_layer, "Version", "4");
    expect_summary_field_contains(*ntp_layer, "Precision", "-30");
    expect_summary_field_equals(*ntp_layer, "Root Delay", "65535.5 s");
    expect_summary_field_equals(*ntp_layer, "Root Dispersion", "1.5 s");
    expect_summary_field_equals(*ntp_layer, "Transmit Timestamp", "2026-01-05 06:00:03.500000 UTC");
}

void expect_future_ntp_summary_for_v3_signed_fixed_point_packet() {
    const auto summary_layers = build_fixture_summary_layers("parsing/ntp/16_ntpv3_signed_root_delay.pcap");
    const auto* ntp_layer = expect_ntp_summary_layer(summary_layers);
    if (ntp_layer == nullptr) {
        return;
    }

    expect_summary_field_equals(*ntp_layer, "Version", "3");
    expect_summary_field_contains(*ntp_layer, "Precision", "-30");
    expect_summary_field_equals(*ntp_layer, "Root Delay", "-0.5 s");
    expect_summary_field_equals(*ntp_layer, "Root Dispersion", "1.5 s");
    expect_summary_field_equals(*ntp_layer, "Stratum", "Secondary reference (2)");
}

void expect_future_ntp_summary_for_era0_boundary_packet() {
    const auto summary_layers = build_fixture_summary_layers("parsing/ntp/15_ntpv4_era0_last_second.pcap");
    const auto* ntp_layer = expect_ntp_summary_layer(summary_layers);
    if (ntp_layer == nullptr) {
        return;
    }

    expect_summary_field_equals(*ntp_layer, "Transmit Timestamp", "2036-02-07 06:28:15.500000 UTC");
}

void expect_future_ntp_summary_for_kod_rate_packet() {
    const auto summary_layers = build_fixture_summary_layers("parsing/ntp/05_ntpv4_kod_rate_response.pcap");
    const auto* ntp_layer = expect_ntp_summary_layer(summary_layers);
    if (ntp_layer == nullptr) {
        return;
    }

    expect_summary_field_equals(*ntp_layer, "Stratum", "Unspecified or invalid (0)");
    expect_summary_field_equals(*ntp_layer, "Reference ID", "RATE");
    expect_summary_field_equals(*ntp_layer, "Kiss Code", "RATE");
}

void expect_truncated_header_has_no_future_ntp_summary() {
    const auto summary_layers = build_fixture_summary_layers("parsing/ntp/10_ntpv4_truncated_47_byte_header.pcap");
    PFL_EXPECT(find_summary_layer(summary_layers, "ntp") == nullptr);
}

void expect_future_ntp_message_byte_view() {
    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(fixture_path("parsing/ntp/11_ntpv4_structured_exchange.pcap")));
    const auto packet = require_packet(session, 1U);
    const auto presentation = session.derive_selected_packet_byte_presentation(packet);
    PFL_REQUIRE(presentation.has_value());

    const auto descriptors = session_detail::build_selected_packet_byte_view_descriptors(*presentation);
    PFL_EXPECT(find_byte_view_descriptor_by_label(descriptors, "UDP Datagram") != nullptr);

    const auto* ntp_descriptor = find_byte_view_descriptor_by_label(descriptors, "NTP Message");
    PFL_EXPECT(ntp_descriptor != nullptr);
    if (ntp_descriptor == nullptr) {
        return;
    }

    PFL_EXPECT(ntp_descriptor->owner_kind == "captured_packet");
    PFL_EXPECT(ntp_descriptor->role == "protocol_unit");
    PFL_EXPECT(ntp_descriptor->assembly_kind == "packet_local");
    PFL_EXPECT(ntp_descriptor->available_length == 48U);
    PFL_EXPECT(ntp_descriptor->declared_length == std::optional<std::uint32_t> {48U});
    PFL_EXPECT(ntp_descriptor->state == "complete");

    const auto ntp_view_id = session_detail::parse_selected_packet_byte_view_stable_id(ntp_descriptor->stable_id);
    PFL_EXPECT(ntp_view_id.has_value());
    if (!ntp_view_id.has_value()) {
        return;
    }

    const auto* ntp_view = presentation->find_view(*ntp_view_id);
    PFL_EXPECT(ntp_view != nullptr);
    if (ntp_view == nullptr) {
        return;
    }

    PFL_EXPECT(ntp_view->offset == 42U);
    PFL_EXPECT(ntp_view->captured_length == 48U);
    PFL_EXPECT(ntp_view->declared_length == std::optional<std::uint32_t> {48U});
    PFL_EXPECT(!ntp_view->truncated);
}

}  // namespace

void run_ntp_pcap_fixture_tests() {
    expect_target_positive_detection();
    expect_structured_fixture_shapes_and_detection();
    expect_permanent_negative_or_unsupported_baseline();
    expect_future_ntp_summary_for_structured_v4_client_packet();
    expect_future_ntp_summary_for_structured_v4_server_packet();
    expect_future_ntp_summary_for_structured_v3_server_packet();
    expect_future_ntp_summary_for_unsynchronized_boundary_packet();
    expect_future_ntp_summary_for_v4_large_unsigned_fixed_point_packet();
    expect_future_ntp_summary_for_v3_signed_fixed_point_packet();
    expect_future_ntp_summary_for_era0_boundary_packet();
    expect_future_ntp_summary_for_kod_rate_packet();
    expect_truncated_header_has_no_future_ntp_summary();
    expect_future_ntp_message_byte_view();
}

}  // namespace pfl::tests
