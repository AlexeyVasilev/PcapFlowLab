#include <algorithm>
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

void expect_stun_flow(const std::filesystem::path& relative_path, const ExpectedFlowShape& expected) {
    const auto row = require_single_udp_flow(relative_path, expected);
    PFL_EXPECT(row.protocol_hint == "stun");
    PFL_EXPECT(row.service_hint.empty());
}

void expect_not_stun_flow(const std::filesystem::path& relative_path, const ExpectedFlowShape& expected) {
    const auto row = require_single_udp_flow(relative_path, expected);
    PFL_EXPECT(row.protocol_hint != "stun");
    PFL_EXPECT(row.service_hint.empty());
}

ExpectedFlowShape stun_ipv4_client_to_server_one_packet(const std::uint16_t server_port = 3478U) {
    return ExpectedFlowShape {
        .capture_packet_count = 1U,
        .capture_flow_count = 1U,
        .flow_packet_count = 1U,
        .address_a = "192.0.2.30",
        .port_a = 51000U,
        .address_b = "192.0.2.40",
        .port_b = server_port,
    };
}

ExpectedFlowShape stun_ipv4_server_to_client_one_packet() {
    return ExpectedFlowShape {
        .capture_packet_count = 1U,
        .capture_flow_count = 1U,
        .flow_packet_count = 1U,
        .address_a = "192.0.2.40",
        .port_a = 3478U,
        .address_b = "192.0.2.30",
        .port_b = 51000U,
    };
}

ExpectedFlowShape stun_ipv4_exchange_two_packets() {
    return ExpectedFlowShape {
        .capture_packet_count = 2U,
        .capture_flow_count = 1U,
        .flow_packet_count = 2U,
        .address_a = "192.0.2.30",
        .port_a = 51000U,
        .address_b = "192.0.2.40",
        .port_b = 3478U,
    };
}

ExpectedFlowShape stun_ipv6_server_to_client_one_packet() {
    return ExpectedFlowShape {
        .capture_packet_count = 1U,
        .capture_flow_count = 1U,
        .flow_packet_count = 1U,
        .address_a = "2001:0db8:0001:0000:0000:0000:0000:0040",
        .port_a = 3478U,
        .address_b = "2001:0db8:0001:0000:0000:0000:0000:0030",
        .port_b = 51000U,
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
    const auto it = std::find_if(layers.begin(), layers.end(), [&](const auto& layer) {
        return layer.id == id;
    });
    return it != layers.end() ? &(*it) : nullptr;
}

const session_detail::PacketSummaryField* find_summary_field(
    const session_detail::PacketSummaryLayer& layer,
    const std::string& label
) {
    const auto it = std::find_if(layer.fields.begin(), layer.fields.end(), [&](const auto& field) {
        return field.label == label;
    });
    return it != layer.fields.end() ? &(*it) : nullptr;
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

const session_detail::PacketSummaryLayer* expect_stun_summary_layer(
    const std::vector<session_detail::PacketSummaryLayer>& layers
) {
    const auto* stun_layer = find_summary_layer(layers, "stun");
    PFL_EXPECT(stun_layer != nullptr);
    return stun_layer;
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

void expect_descendant_summary_field_equals(
    const session_detail::PacketSummaryLayer& layer,
    const std::string& label,
    const std::string& expected
) {
    const auto* field = find_descendant_summary_field(layer, label);
    PFL_EXPECT(field != nullptr);
    if (field != nullptr) {
        PFL_EXPECT(field->value == expected);
    }
}

void expect_descendant_summary_field_contains(
    const session_detail::PacketSummaryLayer& layer,
    const std::string& label,
    const std::string_view expected
) {
    const auto* field = find_descendant_summary_field(layer, label);
    PFL_EXPECT(field != nullptr);
    if (field != nullptr) {
        PFL_EXPECT(contains_text(field->value, expected));
    }
}

const session_detail::PacketSummaryLayer* expect_attribute_child(
    const session_detail::PacketSummaryLayer& stun_layer,
    const std::size_t index,
    const std::string_view expected_title
) {
    PFL_EXPECT(stun_layer.children.size() > index);
    if (stun_layer.children.size() <= index) {
        return nullptr;
    }

    const auto& child = stun_layer.children[index];
    PFL_EXPECT(contains_text(child.title, expected_title));
    return &child;
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

void expect_structured_fixture_shapes_and_detection() {
    expect_stun_flow("parsing/stun/07_stun_binding_ice_exchange.pcap", stun_ipv4_exchange_two_packets());
    expect_stun_flow("parsing/stun/08_stun_binding_success_xor_mapped_ipv6.pcap", stun_ipv6_server_to_client_one_packet());
    expect_stun_flow("parsing/stun/09_stun_binding_error_response.pcap", stun_ipv4_server_to_client_one_packet());
    expect_stun_flow("parsing/stun/10_stun_attribute_padding_and_unknown.pcap", stun_ipv4_client_to_server_one_packet());
    expect_stun_flow("parsing/stun/11_stun_malformed_attribute_length.pcap", stun_ipv4_client_to_server_one_packet());
}

void expect_stun_header_contract(
    const session_detail::PacketSummaryLayer& stun_layer,
    const std::string& message_type,
    const std::string& method,
    const std::string& message_class,
    const std::string& message_length,
    const std::string& transaction_id
) {
    expect_summary_field_equals(stun_layer, "Message Type", message_type);
    expect_summary_field_equals(stun_layer, "Method", method);
    expect_summary_field_equals(stun_layer, "Class", message_class);
    expect_summary_field_equals(stun_layer, "Message Length", message_length);
    expect_summary_field_equals(stun_layer, "Magic Cookie", "0x2112A442");
    expect_summary_field_equals(stun_layer, "Transaction ID", transaction_id);
}

void expect_future_stun_summary_for_fixture_07_request() {
    const auto summary_layers = build_fixture_summary_layers("parsing/stun/07_stun_binding_ice_exchange.pcap", 0U);
    const auto* stun_layer = expect_stun_summary_layer(summary_layers);
    if (stun_layer == nullptr) {
        return;
    }

    PFL_EXPECT(stun_layer->title == "Session Traversal Utilities for NAT (STUN)" || stun_layer->title == "STUN");
    expect_stun_header_contract(*stun_layer, "0x0001", "Binding (0x001)", "Request", "72", "0x070707070707070707070707");

    const auto* username = expect_attribute_child(*stun_layer, 0U, "USERNAME");
    const auto* priority = expect_attribute_child(*stun_layer, 1U, "PRIORITY");
    const auto* ice_controlling = expect_attribute_child(*stun_layer, 2U, "ICE-CONTROLLING");
    const auto* use_candidate = expect_attribute_child(*stun_layer, 3U, "USE-CANDIDATE");
    const auto* message_integrity = expect_attribute_child(*stun_layer, 4U, "MESSAGE-INTEGRITY");
    const auto* fingerprint = expect_attribute_child(*stun_layer, 5U, "FINGERPRINT");

    if (username != nullptr) {
        expect_descendant_summary_field_equals(*username, "Value", "remote:local");
    }
    if (priority != nullptr) {
        expect_descendant_summary_field_equals(*priority, "Priority", "1845501695");
    }
    if (ice_controlling != nullptr) {
        expect_descendant_summary_field_equals(*ice_controlling, "Tie Breaker", "0x1122334455667788");
    }
    if (use_candidate != nullptr) {
        expect_descendant_summary_field_equals(*use_candidate, "Length", "0");
        expect_descendant_summary_field_contains(*use_candidate, "Value", "flag");
    }
    if (message_integrity != nullptr) {
        expect_descendant_summary_field_equals(*message_integrity, "Length", "20");
        expect_descendant_summary_field_contains(*message_integrity, "Validation", "Not performed");
    }
    if (fingerprint != nullptr) {
        expect_descendant_summary_field_equals(*fingerprint, "Length", "4");
        expect_descendant_summary_field_contains(*fingerprint, "Value", "0x");
    }
}

void expect_future_stun_summary_for_fixture_07_response() {
    const auto summary_layers = build_fixture_summary_layers("parsing/stun/07_stun_binding_ice_exchange.pcap", 1U);
    const auto* stun_layer = expect_stun_summary_layer(summary_layers);
    if (stun_layer == nullptr) {
        return;
    }

    expect_stun_header_contract(*stun_layer, "0x0101", "Binding (0x001)", "Success Response", "76", "0x070707070707070707070707");

    const auto* xor_mapped = expect_attribute_child(*stun_layer, 0U, "XOR-MAPPED-ADDRESS");
    const auto* software = expect_attribute_child(*stun_layer, 1U, "SOFTWARE");
    const auto* message_integrity = expect_attribute_child(*stun_layer, 2U, "MESSAGE-INTEGRITY-SHA256");
    const auto* fingerprint = expect_attribute_child(*stun_layer, 3U, "FINGERPRINT");

    if (xor_mapped != nullptr) {
        expect_descendant_summary_field_equals(*xor_mapped, "Family", "IPv4");
        expect_descendant_summary_field_equals(*xor_mapped, "Address", "203.0.113.25");
        expect_descendant_summary_field_equals(*xor_mapped, "Port", "54321");
    }
    if (software != nullptr) {
        expect_descendant_summary_field_equals(*software, "Value", "PFL STUN fixture");
    }
    if (message_integrity != nullptr) {
        expect_descendant_summary_field_equals(*message_integrity, "Length", "32");
        expect_descendant_summary_field_contains(*message_integrity, "Validation", "Not performed");
    }
    if (fingerprint != nullptr) {
        expect_descendant_summary_field_contains(*fingerprint, "Value", "0x");
    }
}

void expect_future_stun_summary_for_fixture_08_ipv6_addresses() {
    const auto summary_layers = build_fixture_summary_layers("parsing/stun/08_stun_binding_success_xor_mapped_ipv6.pcap");
    const auto* stun_layer = expect_stun_summary_layer(summary_layers);
    if (stun_layer == nullptr) {
        return;
    }

    expect_stun_header_contract(*stun_layer, "0x0101", "Binding (0x001)", "Success Response", "48", "0x080808080808080808080808");

    const auto* xor_mapped = expect_attribute_child(*stun_layer, 0U, "XOR-MAPPED-ADDRESS");
    const auto* mapped = expect_attribute_child(*stun_layer, 1U, "MAPPED-ADDRESS");

    if (xor_mapped != nullptr) {
        expect_descendant_summary_field_equals(*xor_mapped, "Family", "IPv6");
        expect_descendant_summary_field_equals(*xor_mapped, "Address", "2001:db8:ffff::25");
        expect_descendant_summary_field_equals(*xor_mapped, "Port", "54321");
    }
    if (mapped != nullptr) {
        expect_descendant_summary_field_equals(*mapped, "Family", "IPv6");
        expect_descendant_summary_field_equals(*mapped, "Address", "2001:db8:ffff::26");
        expect_descendant_summary_field_equals(*mapped, "Port", "54322");
    }
}

void expect_future_stun_summary_for_fixture_09_error_response() {
    const auto summary_layers = build_fixture_summary_layers("parsing/stun/09_stun_binding_error_response.pcap");
    const auto* stun_layer = expect_stun_summary_layer(summary_layers);
    if (stun_layer == nullptr) {
        return;
    }

    expect_stun_header_contract(*stun_layer, "0x0111", "Binding (0x001)", "Error Response", "80", "0x090909090909090909090909");

    const auto* error_code = expect_attribute_child(*stun_layer, 0U, "ERROR-CODE");
    const auto* realm = expect_attribute_child(*stun_layer, 1U, "REALM");
    const auto* nonce = expect_attribute_child(*stun_layer, 2U, "NONCE");
    const auto* software = expect_attribute_child(*stun_layer, 3U, "SOFTWARE");

    if (error_code != nullptr) {
        expect_descendant_summary_field_equals(*error_code, "Code", "401");
        expect_descendant_summary_field_equals(*error_code, "Reason", "Unauthorized");
    }
    if (realm != nullptr) {
        expect_descendant_summary_field_equals(*realm, "Value", "example.org");
    }
    if (nonce != nullptr) {
        expect_descendant_summary_field_equals(*nonce, "Value", "pfl-stun-nonce-0001");
    }
    if (software != nullptr) {
        expect_descendant_summary_field_equals(*software, "Value", "PFL STUN fixture");
    }
}

void expect_future_stun_summary_for_fixture_10_padding_and_unknown_attributes() {
    const auto summary_layers = build_fixture_summary_layers("parsing/stun/10_stun_attribute_padding_and_unknown.pcap");
    const auto* stun_layer = expect_stun_summary_layer(summary_layers);
    if (stun_layer == nullptr) {
        return;
    }

    expect_stun_header_contract(*stun_layer, "0x0001", "Binding (0x001)", "Request", "44", "0x101010101010101010101010");

    const auto* username = expect_attribute_child(*stun_layer, 0U, "USERNAME");
    const auto* ice_controlled = expect_attribute_child(*stun_layer, 1U, "ICE-CONTROLLED");
    const auto* unknown_required = expect_attribute_child(*stun_layer, 2U, "0x1234");
    const auto* unknown_optional = expect_attribute_child(*stun_layer, 3U, "0x8123");

    if (username != nullptr) {
        expect_descendant_summary_field_equals(*username, "Length", "9");
        expect_descendant_summary_field_equals(*username, "Value", "pad-nine!");
    }
    if (ice_controlled != nullptr) {
        expect_descendant_summary_field_equals(*ice_controlled, "Tie Breaker", "0x8877665544332211");
    }
    if (unknown_required != nullptr) {
        expect_descendant_summary_field_equals(*unknown_required, "Type", "0x1234");
        expect_descendant_summary_field_contains(*unknown_required, "Comprehension", "required");
        expect_descendant_summary_field_contains(*unknown_required, "Value", "12");
    }
    if (unknown_optional != nullptr) {
        expect_descendant_summary_field_equals(*unknown_optional, "Type", "0x8123");
        expect_descendant_summary_field_contains(*unknown_optional, "Comprehension", "optional");
        expect_descendant_summary_field_contains(*unknown_optional, "Value", "81");
    }
}

void expect_future_stun_summary_for_fixture_11_malformed_attribute() {
    const auto summary_layers = build_fixture_summary_layers("parsing/stun/11_stun_malformed_attribute_length.pcap");
    const auto* stun_layer = expect_stun_summary_layer(summary_layers);
    if (stun_layer == nullptr) {
        return;
    }

    expect_stun_header_contract(*stun_layer, "0x0001", "Binding (0x001)", "Request", "8", "0x111111111111111111111111");
    const auto* username = expect_attribute_child(*stun_layer, 0U, "USERNAME");
    if (username != nullptr) {
        expect_descendant_summary_field_equals(*username, "Length", "8");
        expect_descendant_summary_field_contains(*username, "Status", "malformed");
        expect_descendant_summary_field_contains(*username, "Warning", "extends beyond");
    }
    PFL_EXPECT(stun_layer->children.size() == 1U);
}

void expect_future_stun_message_byte_view() {
    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(fixture_path("parsing/stun/07_stun_binding_ice_exchange.pcap")));
    const auto packet = require_packet(session, 0U);
    const auto presentation = session.derive_selected_packet_byte_presentation(packet);
    PFL_REQUIRE(presentation.has_value());

    const auto descriptors = session_detail::build_selected_packet_byte_view_descriptors(*presentation);
    PFL_EXPECT(find_byte_view_descriptor_by_label(descriptors, "UDP Datagram") != nullptr);

    const auto* stun_descriptor = find_byte_view_descriptor_by_label(descriptors, "STUN Message");
    PFL_EXPECT(stun_descriptor != nullptr);
    if (stun_descriptor == nullptr) {
        return;
    }

    PFL_EXPECT(stun_descriptor->owner_kind == "captured_packet");
    PFL_EXPECT(stun_descriptor->role == "protocol_unit");
    PFL_EXPECT(stun_descriptor->assembly_kind == "packet_local");
    PFL_EXPECT(stun_descriptor->available_length == 92U);
    PFL_EXPECT(stun_descriptor->declared_length == std::optional<std::uint32_t> {92U});
    PFL_EXPECT(stun_descriptor->state == "complete");

    const auto stun_view_id = session_detail::parse_selected_packet_byte_view_stable_id(stun_descriptor->stable_id);
    PFL_EXPECT(stun_view_id.has_value());
    if (!stun_view_id.has_value()) {
        return;
    }

    const auto* stun_view = presentation->find_view(*stun_view_id);
    PFL_EXPECT(stun_view != nullptr);
    if (stun_view == nullptr) {
        return;
    }

    PFL_EXPECT(stun_view->offset == 42U);
    PFL_EXPECT(stun_view->captured_length == 92U);
    PFL_EXPECT(stun_view->declared_length == std::optional<std::uint32_t> {92U});
    PFL_EXPECT(!stun_view->truncated);
}

}  // namespace

void run_stun_pcap_fixture_tests() {
    expect_stun_flow(
        "parsing/stun/01_stun_binding_request_3478.pcap",
        ExpectedFlowShape {
            .capture_packet_count = 1U,
            .capture_flow_count = 1U,
            .flow_packet_count = 1U,
            .address_a = "192.0.2.30",
            .port_a = 51000U,
            .address_b = "192.0.2.40",
            .port_b = 3478U,
        });

    expect_stun_flow(
        "parsing/stun/02_stun_binding_request_response.pcap",
        ExpectedFlowShape {
            .capture_packet_count = 2U,
            .capture_flow_count = 1U,
            .flow_packet_count = 2U,
            .address_a = "192.0.2.30",
            .port_a = 51000U,
            .address_b = "192.0.2.40",
            .port_b = 3478U,
        });

    expect_stun_flow(
        "parsing/stun/03_stun_binding_request_nonstandard_port.pcap",
        ExpectedFlowShape {
            .capture_packet_count = 1U,
            .capture_flow_count = 1U,
            .flow_packet_count = 1U,
            .address_a = "192.0.2.30",
            .port_a = 51000U,
            .address_b = "192.0.2.40",
            .port_b = 45678U,
        });

    expect_not_stun_flow(
        "parsing/stun/04_stun_bad_magic_cookie.pcap",
        ExpectedFlowShape {
            .capture_packet_count = 1U,
            .capture_flow_count = 1U,
            .flow_packet_count = 1U,
            .address_a = "192.0.2.30",
            .port_a = 51000U,
            .address_b = "192.0.2.40",
            .port_b = 3478U,
        });

    expect_not_stun_flow(
        "parsing/stun/05_stun_invalid_top_bits.pcap",
        ExpectedFlowShape {
            .capture_packet_count = 1U,
            .capture_flow_count = 1U,
            .flow_packet_count = 1U,
            .address_a = "192.0.2.30",
            .port_a = 51000U,
            .address_b = "192.0.2.40",
            .port_b = 3478U,
        });

    expect_not_stun_flow(
        "parsing/stun/06_stun_declared_length_mismatch.pcap",
        ExpectedFlowShape {
            .capture_packet_count = 1U,
            .capture_flow_count = 1U,
            .flow_packet_count = 1U,
            .address_a = "192.0.2.30",
            .port_a = 51000U,
            .address_b = "192.0.2.40",
            .port_b = 3478U,
        });

    expect_structured_fixture_shapes_and_detection();
    expect_future_stun_summary_for_fixture_07_request();
    expect_future_stun_summary_for_fixture_07_response();
    expect_future_stun_summary_for_fixture_08_ipv6_addresses();
    expect_future_stun_summary_for_fixture_09_error_response();
    expect_future_stun_summary_for_fixture_10_padding_and_unknown_attributes();
    expect_future_stun_summary_for_fixture_11_malformed_attribute();
    expect_future_stun_message_byte_view();
}

}  // namespace pfl::tests
