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

FlowRow require_single_flow(const std::filesystem::path& relative_path, const ExpectedFlowShape& expected) {
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

void expect_dhcp_flow(const std::filesystem::path& relative_path, const ExpectedFlowShape& expected) {
    const auto row = require_single_flow(relative_path, expected);
    PFL_EXPECT(row.protocol_hint == "dhcp");
    PFL_EXPECT(row.service_hint.empty());
}

void expect_not_dhcp_flow(const std::filesystem::path& relative_path, const ExpectedFlowShape& expected) {
    const auto row = require_single_flow(relative_path, expected);
    PFL_EXPECT(row.protocol_hint != "dhcp");
    PFL_EXPECT(row.service_hint.empty());
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

const session_detail::PacketSummaryLayer* find_descendant_layer_title_contains(
    const session_detail::PacketSummaryLayer& layer,
    const std::string_view title_fragment
) {
    for (const auto& child : layer.children) {
        if (contains_text(child.title, title_fragment)) {
            return &child;
        }
        if (const auto* descendant = find_descendant_layer_title_contains(child, title_fragment); descendant != nullptr) {
            return descendant;
        }
    }
    return nullptr;
}

std::string flatten_summary_layer_text(const session_detail::PacketSummaryLayer& layer) {
    std::string text = layer.id + "\n" + layer.title + "\n" + layer.marker_text + "\n";
    for (const auto& field : layer.fields) {
        text += field.label + "\n" + field.value + "\n";
    }
    for (const auto& child : layer.children) {
        text += flatten_summary_layer_text(child);
    }
    return text;
}

const session_detail::PacketSummaryLayer* expect_dhcp_summary_layer(
    const std::vector<session_detail::PacketSummaryLayer>& layers
) {
    const auto* dhcp_layer = find_summary_layer(layers, "dhcp");
    PFL_EXPECT(dhcp_layer != nullptr);
    return dhcp_layer;
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

const session_detail::PacketSummaryLayer* expect_child_title_contains(
    const session_detail::PacketSummaryLayer& layer,
    const std::size_t index,
    const std::string_view expected_title
) {
    PFL_EXPECT(layer.children.size() > index);
    if (layer.children.size() <= index) {
        return nullptr;
    }

    const auto& child = layer.children[index];
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
    expect_dhcp_flow(
        "parsing/dhcp/07_dhcp_structured_discover.pcap",
        ExpectedFlowShape {
            .capture_packet_count = 1U,
            .capture_flow_count = 1U,
            .flow_packet_count = 1U,
            .address_a = "0.0.0.0",
            .port_a = 68U,
            .address_b = "255.255.255.255",
            .port_b = 67U,
        });

    expect_dhcp_flow(
        "parsing/dhcp/08_dhcp_structured_offer.pcap",
        ExpectedFlowShape {
            .capture_packet_count = 1U,
            .capture_flow_count = 1U,
            .flow_packet_count = 1U,
            .address_a = "192.0.2.1",
            .port_a = 67U,
            .address_b = "255.255.255.255",
            .port_b = 68U,
        });

    expect_dhcp_flow(
        "parsing/dhcp/09_dhcp_option_overload.pcap",
        ExpectedFlowShape {
            .capture_packet_count = 1U,
            .capture_flow_count = 1U,
            .flow_packet_count = 1U,
            .address_a = "192.0.2.1",
            .port_a = 67U,
            .address_b = "192.0.2.100",
            .port_b = 68U,
        });

    expect_dhcp_flow(
        "parsing/dhcp/10_dhcp_padding_unknown_end.pcap",
        ExpectedFlowShape {
            .capture_packet_count = 1U,
            .capture_flow_count = 1U,
            .flow_packet_count = 1U,
            .address_a = "192.0.2.100",
            .port_a = 68U,
            .address_b = "192.0.2.1",
            .port_b = 67U,
        });

    expect_dhcp_flow(
        "parsing/dhcp/11_dhcp_malformed_option_length.pcap",
        ExpectedFlowShape {
            .capture_packet_count = 1U,
            .capture_flow_count = 1U,
            .flow_packet_count = 1U,
            .address_a = "0.0.0.0",
            .port_a = 68U,
            .address_b = "255.255.255.255",
            .port_b = 67U,
        });
}

void expect_common_dhcp_request_header_contract(
    const session_detail::PacketSummaryLayer& dhcp_layer,
    const std::string& transaction_id
) {
    expect_descendant_summary_field_contains(dhcp_layer, "Operation", "BOOTREQUEST");
    expect_descendant_summary_field_contains(dhcp_layer, "Operation", "1");
    expect_descendant_summary_field_contains(dhcp_layer, "Hardware Type", "Ethernet");
    expect_descendant_summary_field_contains(dhcp_layer, "Hardware Type", "1");
    expect_descendant_summary_field_equals(dhcp_layer, "Hardware Address Length", "6");
    expect_descendant_summary_field_equals(dhcp_layer, "Hops", "0");
    expect_descendant_summary_field_equals(dhcp_layer, "Transaction ID", transaction_id);
    expect_descendant_summary_field_contains(dhcp_layer, "Flags", "Broadcast");
    expect_descendant_summary_field_contains(dhcp_layer, "Broadcast", "Yes");
    expect_descendant_summary_field_equals(dhcp_layer, "Client IP Address", "0.0.0.0");
    expect_descendant_summary_field_equals(dhcp_layer, "Your IP Address", "0.0.0.0");
    expect_descendant_summary_field_equals(dhcp_layer, "Next Server IP Address", "0.0.0.0");
    expect_descendant_summary_field_equals(dhcp_layer, "Relay Agent IP Address", "0.0.0.0");
    expect_descendant_summary_field_equals(dhcp_layer, "Client Hardware Address", "02:00:00:00:40:01");
    expect_descendant_summary_field_equals(dhcp_layer, "DHCP Magic Cookie", "0x63825363");
}

void expect_future_dhcp_summary_for_fixture_07_discover() {
    const auto summary_layers = build_fixture_summary_layers("parsing/dhcp/07_dhcp_structured_discover.pcap");
    const auto* dhcp_layer = expect_dhcp_summary_layer(summary_layers);
    if (dhcp_layer == nullptr) {
        return;
    }

    PFL_EXPECT(dhcp_layer->title == "Dynamic Host Configuration Protocol (DHCPv4)" || contains_text(dhcp_layer->title, "DHCP"));
    expect_common_dhcp_request_header_contract(*dhcp_layer, "0x3903F327");
    expect_descendant_summary_field_equals(*dhcp_layer, "Seconds Elapsed", "7");

    const auto* options = find_descendant_layer_title_contains(*dhcp_layer, "Options");
    PFL_EXPECT(options != nullptr);
    if (options == nullptr) {
        return;
    }

    const auto* message_type = expect_child_title_contains(*options, 0U, "DHCP Message Type");
    const auto* host_name = expect_child_title_contains(*options, 1U, "Host Name");
    const auto* requested_ip = expect_child_title_contains(*options, 2U, "Requested IP Address");
    const auto* prl = expect_child_title_contains(*options, 3U, "Parameter Request List");
    const auto* client_id = expect_child_title_contains(*options, 4U, "Client Identifier");
    const auto* maximum_message_size = expect_child_title_contains(*options, 5U, "Maximum DHCP Message Size");
    const auto* vendor_class = expect_child_title_contains(*options, 6U, "Vendor Class Identifier");
    expect_child_title_contains(*options, 7U, "End");

    if (message_type != nullptr) {
        expect_descendant_summary_field_contains(*message_type, "Value", "Discover");
        expect_descendant_summary_field_contains(*message_type, "Value", "1");
    }
    if (host_name != nullptr) {
        expect_descendant_summary_field_equals(*host_name, "Value", "pfl-client");
    }
    if (requested_ip != nullptr) {
        expect_descendant_summary_field_equals(*requested_ip, "Address", "192.0.2.100");
    }
    if (prl != nullptr) {
        const auto prl_text = flatten_summary_layer_text(*prl);
        PFL_EXPECT(contains_text(prl_text, "1"));
        PFL_EXPECT(contains_text(prl_text, "3"));
        PFL_EXPECT(contains_text(prl_text, "6"));
        PFL_EXPECT(contains_text(prl_text, "15"));
        PFL_EXPECT(contains_text(prl_text, "28"));
        PFL_EXPECT(contains_text(prl_text, "51"));
        PFL_EXPECT(contains_text(prl_text, "54"));
        PFL_EXPECT(contains_text(prl_text, "58"));
        PFL_EXPECT(contains_text(prl_text, "59"));
    }
    if (client_id != nullptr) {
        expect_descendant_summary_field_contains(*client_id, "Hardware Type", "Ethernet");
        expect_descendant_summary_field_contains(*client_id, "Hardware Type", "1");
        expect_descendant_summary_field_equals(*client_id, "Client Hardware Address", "02:00:00:00:40:01");
    }
    if (maximum_message_size != nullptr) {
        expect_descendant_summary_field_contains(*maximum_message_size, "Value", "1500");
    }
    if (vendor_class != nullptr) {
        expect_descendant_summary_field_equals(*vendor_class, "Value", "PFL-DHCP-Client");
    }
}

void expect_future_dhcp_summary_for_fixture_08_offer() {
    const auto summary_layers = build_fixture_summary_layers("parsing/dhcp/08_dhcp_structured_offer.pcap");
    const auto* dhcp_layer = expect_dhcp_summary_layer(summary_layers);
    if (dhcp_layer == nullptr) {
        return;
    }

    expect_descendant_summary_field_contains(*dhcp_layer, "Operation", "BOOTREPLY");
    expect_descendant_summary_field_contains(*dhcp_layer, "Operation", "2");
    expect_descendant_summary_field_equals(*dhcp_layer, "Transaction ID", "0x3903F327");
    expect_descendant_summary_field_equals(*dhcp_layer, "Your IP Address", "192.0.2.100");
    expect_descendant_summary_field_equals(*dhcp_layer, "Next Server IP Address", "192.0.2.1");
    expect_descendant_summary_field_equals(*dhcp_layer, "Relay Agent IP Address", "0.0.0.0");
    expect_descendant_summary_field_equals(*dhcp_layer, "Client Hardware Address", "02:00:00:00:40:01");
    expect_descendant_summary_field_equals(*dhcp_layer, "Server Host Name", "dhcp-server");
    expect_descendant_summary_field_equals(*dhcp_layer, "Boot File Name", "pxelinux.0");

    const auto* options = find_descendant_layer_title_contains(*dhcp_layer, "Options");
    PFL_EXPECT(options != nullptr);
    if (options == nullptr) {
        return;
    }

    const auto* message_type = expect_child_title_contains(*options, 0U, "DHCP Message Type");
    const auto* subnet = expect_child_title_contains(*options, 1U, "Subnet Mask");
    const auto* router = expect_child_title_contains(*options, 2U, "Router");
    const auto* dns = expect_child_title_contains(*options, 3U, "Domain Name Server");
    const auto* domain = expect_child_title_contains(*options, 4U, "Domain Name");
    const auto* broadcast = expect_child_title_contains(*options, 5U, "Broadcast Address");
    const auto* lease = expect_child_title_contains(*options, 6U, "IP Address Lease Time");
    const auto* renewal = expect_child_title_contains(*options, 7U, "Renewal Time Value");
    const auto* rebinding = expect_child_title_contains(*options, 8U, "Rebinding Time Value");
    const auto* server_id = expect_child_title_contains(*options, 9U, "Server Identifier");
    const auto* message = expect_child_title_contains(*options, 10U, "Message");

    if (message_type != nullptr) {
        expect_descendant_summary_field_contains(*message_type, "Value", "Offer");
        expect_descendant_summary_field_contains(*message_type, "Value", "2");
    }
    if (subnet != nullptr) {
        expect_descendant_summary_field_equals(*subnet, "Address", "255.255.255.0");
    }
    if (router != nullptr) {
        const auto router_text = flatten_summary_layer_text(*router);
        PFL_EXPECT(contains_text(router_text, "192.0.2.1"));
        PFL_EXPECT(contains_text(router_text, "192.0.2.254"));
    }
    if (dns != nullptr) {
        const auto dns_text = flatten_summary_layer_text(*dns);
        PFL_EXPECT(contains_text(dns_text, "192.0.2.53"));
        PFL_EXPECT(contains_text(dns_text, "192.0.2.54"));
    }
    if (domain != nullptr) {
        expect_descendant_summary_field_equals(*domain, "Value", "example.test");
    }
    if (broadcast != nullptr) {
        expect_descendant_summary_field_equals(*broadcast, "Address", "192.0.2.255");
    }
    if (lease != nullptr) {
        expect_descendant_summary_field_contains(*lease, "Value", "3600");
    }
    if (renewal != nullptr) {
        expect_descendant_summary_field_contains(*renewal, "Value", "1800");
    }
    if (rebinding != nullptr) {
        expect_descendant_summary_field_contains(*rebinding, "Value", "3150");
    }
    if (server_id != nullptr) {
        expect_descendant_summary_field_equals(*server_id, "Address", "192.0.2.1");
    }
    if (message != nullptr) {
        expect_descendant_summary_field_equals(*message, "Value", "PFL offer");
    }
}

void expect_future_dhcp_summary_for_fixture_09_option_overload() {
    const auto summary_layers = build_fixture_summary_layers("parsing/dhcp/09_dhcp_option_overload.pcap");
    const auto* dhcp_layer = expect_dhcp_summary_layer(summary_layers);
    if (dhcp_layer == nullptr) {
        return;
    }

    const auto* options = find_descendant_layer_title_contains(*dhcp_layer, "Options");
    PFL_EXPECT(options != nullptr);
    if (options == nullptr) {
        return;
    }

    const auto* message_type = expect_child_title_contains(*options, 0U, "DHCP Message Type");
    const auto* overload = expect_child_title_contains(*options, 1U, "Option Overload");
    const auto* server_id = expect_child_title_contains(*options, 2U, "Server Identifier");
    expect_child_title_contains(*options, 3U, "End");

    if (message_type != nullptr) {
        expect_descendant_summary_field_contains(*message_type, "Value", "ACK");
        expect_descendant_summary_field_contains(*message_type, "Value", "5");
    }
    if (overload != nullptr) {
        const auto overload_text = flatten_summary_layer_text(*overload);
        PFL_EXPECT(contains_text(overload_text, "3"));
        PFL_EXPECT(contains_text(overload_text, "file"));
        PFL_EXPECT(
            contains_text(overload_text, "sname") ||
            contains_text(overload_text, "Server Name") ||
            contains_text(overload_text, "server name")
        );
    }
    if (server_id != nullptr) {
        expect_descendant_summary_field_equals(*server_id, "Address", "192.0.2.1");
    }

    PFL_EXPECT(find_summary_field(*dhcp_layer, "Boot File Name") == nullptr);
    PFL_EXPECT(find_summary_field(*dhcp_layer, "Server Host Name") == nullptr);

    const auto* file_options = find_descendant_layer_title_contains(*dhcp_layer, "Overloaded File Options");
    PFL_EXPECT(file_options != nullptr);
    if (file_options != nullptr) {
        const auto* bootfile = expect_child_title_contains(*file_options, 0U, "Bootfile Name");
        expect_child_title_contains(*file_options, 1U, "End");
        if (bootfile != nullptr) {
            expect_descendant_summary_field_equals(*bootfile, "Value", "bootx64.efi");
        }
    }

    const auto* sname_options = find_descendant_layer_title_contains(*dhcp_layer, "Overloaded Server Name Options");
    PFL_EXPECT(sname_options != nullptr);
    if (sname_options != nullptr) {
        const auto* tftp = expect_child_title_contains(*sname_options, 0U, "TFTP Server Name");
        expect_child_title_contains(*sname_options, 1U, "End");
        if (tftp != nullptr) {
            expect_descendant_summary_field_equals(*tftp, "Value", "tftp.example.test");
        }
    }
}

void expect_future_dhcp_summary_for_fixture_10_padding_unknown_and_end() {
    const auto summary_layers = build_fixture_summary_layers("parsing/dhcp/10_dhcp_padding_unknown_end.pcap");
    const auto* dhcp_layer = expect_dhcp_summary_layer(summary_layers);
    if (dhcp_layer == nullptr) {
        return;
    }

    const auto* options = find_descendant_layer_title_contains(*dhcp_layer, "Options");
    PFL_EXPECT(options != nullptr);
    if (options == nullptr) {
        return;
    }

    const auto* message_type = expect_child_title_contains(*options, 0U, "DHCP Message Type");
    const auto* unknown = find_descendant_layer_title_contains(*options, "200");
    const auto* host_name = find_descendant_layer_title_contains(*options, "Host Name");

    if (message_type != nullptr) {
        expect_descendant_summary_field_contains(*message_type, "Value", "Request");
        expect_descendant_summary_field_contains(*message_type, "Value", "3");
    }
    PFL_EXPECT(unknown != nullptr);
    if (unknown != nullptr) {
        expect_descendant_summary_field_contains(*unknown, "Code", "200");
        expect_descendant_summary_field_equals(*unknown, "Length", "3");
        expect_descendant_summary_field_contains(*unknown, "Value", "12");
        expect_descendant_summary_field_contains(*unknown, "Value", "34");
        expect_descendant_summary_field_contains(*unknown, "Value", "56");
    }
    PFL_EXPECT(host_name != nullptr);
    if (host_name != nullptr) {
        expect_descendant_summary_field_equals(*host_name, "Value", "pad-client");
    }

    const auto dhcp_text = flatten_summary_layer_text(*dhcp_layer);
    PFL_EXPECT(!contains_text(dhcp_text, "ignored-tail"));
    PFL_EXPECT(!contains_text(dhcp_text, "ACK (5)"));
}

void expect_future_dhcp_summary_for_fixture_11_malformed_option() {
    const auto summary_layers = build_fixture_summary_layers("parsing/dhcp/11_dhcp_malformed_option_length.pcap");
    const auto* dhcp_layer = expect_dhcp_summary_layer(summary_layers);
    if (dhcp_layer == nullptr) {
        return;
    }

    expect_common_dhcp_request_header_contract(*dhcp_layer, "0x3903F32B");

    const auto* options = find_descendant_layer_title_contains(*dhcp_layer, "Options");
    PFL_EXPECT(options != nullptr);
    if (options == nullptr) {
        return;
    }

    const auto* message_type = expect_child_title_contains(*options, 0U, "DHCP Message Type");
    const auto* host_name = expect_child_title_contains(*options, 1U, "Host Name");
    if (message_type != nullptr) {
        expect_descendant_summary_field_contains(*message_type, "Value", "Discover");
        expect_descendant_summary_field_contains(*message_type, "Value", "1");
    }
    if (host_name != nullptr) {
        expect_descendant_summary_field_equals(*host_name, "Code", "12");
        expect_descendant_summary_field_equals(*host_name, "Declared Length", "10");
        expect_descendant_summary_field_equals(*host_name, "Available Value Length", "3");
        expect_descendant_summary_field_contains(*host_name, "Value", "bad");
        expect_descendant_summary_field_contains(*host_name, "Status", "malformed");
        expect_descendant_summary_field_contains(*host_name, "Warning", "extends beyond");
    }

    const auto dhcp_text = flatten_summary_layer_text(*dhcp_layer);
    PFL_EXPECT(!contains_text(dhcp_text, "End"));
}

void expect_negative_gate_has_no_future_dhcp_summary() {
    for (const auto* fixture : {
             "parsing/dhcp/04_dhcp_bad_magic_cookie.pcap",
             "parsing/dhcp/05_dhcp_valid_payload_wrong_ports.pcap",
             "parsing/dhcp/06_dhcp_truncated_before_magic_cookie.pcap",
         }) {
        const auto summary_layers = build_fixture_summary_layers(fixture);
        PFL_EXPECT(find_summary_layer(summary_layers, "dhcp") == nullptr);
    }
}

void expect_future_dhcp_message_byte_view() {
    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(fixture_path("parsing/dhcp/07_dhcp_structured_discover.pcap")));
    const auto packet = require_packet(session, 0U);
    const auto presentation = session.derive_selected_packet_byte_presentation(packet);
    PFL_REQUIRE(presentation.has_value());

    const auto descriptors = session_detail::build_selected_packet_byte_view_descriptors(*presentation);
    PFL_EXPECT(find_byte_view_descriptor_by_label(descriptors, "UDP Datagram") != nullptr);

    const auto* dhcp_descriptor = find_byte_view_descriptor_by_label(descriptors, "DHCP Message");
    PFL_EXPECT(dhcp_descriptor != nullptr);
    if (dhcp_descriptor == nullptr) {
        return;
    }

    PFL_EXPECT(dhcp_descriptor->owner_kind == "captured_packet");
    PFL_EXPECT(dhcp_descriptor->role == "protocol_unit");
    PFL_EXPECT(dhcp_descriptor->assembly_kind == "packet_local");
    PFL_EXPECT(dhcp_descriptor->available_length == 303U);
    PFL_EXPECT(dhcp_descriptor->declared_length == std::optional<std::uint32_t> {303U});
    PFL_EXPECT(dhcp_descriptor->state == "complete");

    const auto dhcp_view_id = session_detail::parse_selected_packet_byte_view_stable_id(dhcp_descriptor->stable_id);
    PFL_EXPECT(dhcp_view_id.has_value());
    if (!dhcp_view_id.has_value()) {
        return;
    }

    const auto* dhcp_view = presentation->find_view(*dhcp_view_id);
    PFL_EXPECT(dhcp_view != nullptr);
    if (dhcp_view == nullptr) {
        return;
    }

    PFL_EXPECT(dhcp_view->offset == 42U);
    PFL_EXPECT(dhcp_view->captured_length == 303U);
    PFL_EXPECT(dhcp_view->declared_length == std::optional<std::uint32_t> {303U});
    PFL_EXPECT(!dhcp_view->truncated);
}

void expect_future_dhcp_message_byte_view_for_malformed_options() {
    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(fixture_path("parsing/dhcp/11_dhcp_malformed_option_length.pcap")));
    const auto packet = require_packet(session, 0U);
    const auto presentation = session.derive_selected_packet_byte_presentation(packet);
    PFL_REQUIRE(presentation.has_value());

    const auto descriptors = session_detail::build_selected_packet_byte_view_descriptors(*presentation);
    const auto* dhcp_descriptor = find_byte_view_descriptor_by_label(descriptors, "DHCP Message");
    PFL_EXPECT(dhcp_descriptor != nullptr);
    if (dhcp_descriptor == nullptr) {
        return;
    }

    PFL_EXPECT(dhcp_descriptor->available_length == 248U);
    PFL_EXPECT(dhcp_descriptor->declared_length == std::optional<std::uint32_t> {248U});
    PFL_EXPECT(dhcp_descriptor->state == "complete");
}

}  // namespace

void run_dhcp_pcap_fixture_tests() {
    expect_dhcp_flow(
        "parsing/dhcp/01_dhcp_discover_broadcast.pcap",
        ExpectedFlowShape {
            .capture_packet_count = 1U,
            .capture_flow_count = 1U,
            .flow_packet_count = 1U,
            .address_a = "0.0.0.0",
            .port_a = 68U,
            .address_b = "255.255.255.255",
            .port_b = 67U,
        });

    expect_dhcp_flow(
        "parsing/dhcp/02_dhcp_offer_broadcast.pcap",
        ExpectedFlowShape {
            .capture_packet_count = 1U,
            .capture_flow_count = 1U,
            .flow_packet_count = 1U,
            .address_a = "192.0.2.1",
            .port_a = 67U,
            .address_b = "255.255.255.255",
            .port_b = 68U,
        });

    expect_dhcp_flow(
        "parsing/dhcp/03_dhcp_request_ack_bidirectional.pcap",
        ExpectedFlowShape {
            .capture_packet_count = 2U,
            .capture_flow_count = 1U,
            .flow_packet_count = 2U,
            .address_a = "192.0.2.100",
            .port_a = 68U,
            .address_b = "192.0.2.1",
            .port_b = 67U,
        });

    expect_not_dhcp_flow(
        "parsing/dhcp/04_dhcp_bad_magic_cookie.pcap",
        ExpectedFlowShape {
            .capture_packet_count = 1U,
            .capture_flow_count = 1U,
            .flow_packet_count = 1U,
            .address_a = "0.0.0.0",
            .port_a = 68U,
            .address_b = "255.255.255.255",
            .port_b = 67U,
        });

    expect_not_dhcp_flow(
        "parsing/dhcp/05_dhcp_valid_payload_wrong_ports.pcap",
        ExpectedFlowShape {
            .capture_packet_count = 1U,
            .capture_flow_count = 1U,
            .flow_packet_count = 1U,
            .address_a = "0.0.0.0",
            .port_a = 1068U,
            .address_b = "255.255.255.255",
            .port_b = 1067U,
        });

    expect_not_dhcp_flow(
        "parsing/dhcp/06_dhcp_truncated_before_magic_cookie.pcap",
        ExpectedFlowShape {
            .capture_packet_count = 1U,
            .capture_flow_count = 1U,
            .flow_packet_count = 1U,
            .address_a = "0.0.0.0",
            .port_a = 68U,
            .address_b = "255.255.255.255",
            .port_b = 67U,
        });

    expect_structured_fixture_shapes_and_detection();
    expect_future_dhcp_summary_for_fixture_07_discover();
    expect_future_dhcp_summary_for_fixture_08_offer();
    expect_future_dhcp_summary_for_fixture_09_option_overload();
    expect_future_dhcp_summary_for_fixture_10_padding_unknown_and_end();
    expect_future_dhcp_summary_for_fixture_11_malformed_option();
    expect_negative_gate_has_no_future_dhcp_summary();
    expect_future_dhcp_message_byte_view();
    expect_future_dhcp_message_byte_view_for_malformed_options();
}

}  // namespace pfl::tests
