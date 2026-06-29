#include <algorithm>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

#include "TestSupport.h"
#include "app/session/CaptureSession.h"
#include "app/session/FlowRows.h"
#include "app/session/SessionFormatting.h"

namespace pfl::tests {

namespace {

std::filesystem::path fixture_path(const std::filesystem::path& relative_path) {
    return std::filesystem::path(__FILE__).parent_path().parent_path() / "data" / relative_path;
}

PacketRef require_packet(CaptureSession& session, const std::uint64_t packet_index) {
    const auto packet = session.find_packet(packet_index);
    PFL_EXPECT(packet.has_value());
    return *packet;
}

const session_detail::PacketSummaryLayer* find_layer(
    const std::vector<session_detail::PacketSummaryLayer>& layers,
    const std::string& id,
    const std::size_t occurrence = 0U
) {
    std::size_t seen = 0U;
    for (const auto& layer : layers) {
        if (layer.id != id) {
            continue;
        }
        if (seen == occurrence) {
            return &layer;
        }
        ++seen;
    }
    return nullptr;
}

bool layer_has_field_containing(
    const session_detail::PacketSummaryLayer& layer,
    const std::string& label,
    const std::string& expected_fragment
) {
    return std::any_of(layer.fields.begin(), layer.fields.end(), [&](const session_detail::PacketSummaryField& field) {
        return field.label == label && field.value.find(expected_fragment) != std::string::npos;
    });
}

UnrecognizedPacketRow expect_single_unrecognized_packet(
    CaptureSession& session,
    const std::filesystem::path& relative_path,
    const std::optional<std::string>& expected_reason = std::nullopt
) {
    PFL_EXPECT(session.open_capture(fixture_path(relative_path)));
    PFL_EXPECT(session.summary().packet_count == 0U);
    PFL_EXPECT(session.list_flows().empty());
    PFL_EXPECT(session.unrecognized_packet_count() == 1U);

    const auto rows = session.list_unrecognized_packets(0U, 30U);
    PFL_EXPECT(rows.size() == 1U);
    PFL_EXPECT(rows[0].row_number == 1U);
    PFL_EXPECT(rows[0].packet_index == 0U);
    PFL_EXPECT(!rows[0].reason_text.empty());
    if (expected_reason.has_value()) {
        PFL_EXPECT(rows[0].reason_text == *expected_reason);
    }
    PFL_EXPECT(rows[0].captured_length > 0U);
    PFL_EXPECT(rows[0].original_length >= rows[0].captured_length);
    return rows[0];
}

void expect_pppoe_discovery_unrecognized(
    CaptureSession& session,
    const std::filesystem::path& relative_path,
    const std::string& expected_code_fragment,
    const std::vector<std::string>& expected_tag_names = {}
) {
    const auto row = expect_single_unrecognized_packet(session, relative_path);
    const auto packet = require_packet(session, row.packet_index);
    const auto details = session.read_packet_details(packet);
    PFL_EXPECT(details.has_value());
    PFL_EXPECT(details->has_ethernet);
    PFL_EXPECT(details->has_pppoe);
    PFL_EXPECT(details->pppoe.is_discovery);
    PFL_EXPECT(details->pppoe.version == 1U);
    PFL_EXPECT(details->pppoe.type == 1U);
    PFL_EXPECT(!details->has_ipv4);
    PFL_EXPECT(!details->has_ipv6);
    PFL_EXPECT(!details->has_tcp);
    PFL_EXPECT(!details->has_udp);

    const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet);
    PFL_EXPECT(find_layer(summary_layers, "frame") != nullptr);
    PFL_EXPECT(find_layer(summary_layers, "ethernet") != nullptr);
    const auto* pppoe_layer = find_layer(summary_layers, "pppoe");
    PFL_EXPECT(pppoe_layer != nullptr);
    PFL_EXPECT(pppoe_layer->title.find("PPPoE Discovery") != std::string::npos);
    PFL_EXPECT(layer_has_field_containing(*pppoe_layer, "Code", expected_code_fragment));
    PFL_EXPECT(layer_has_field_containing(*pppoe_layer, "Session ID", "0x"));
    PFL_EXPECT(layer_has_field_containing(*pppoe_layer, "Length", "bytes"));
    PFL_EXPECT(find_layer(summary_layers, "ppp") == nullptr);

    for (const auto& tag_name : expected_tag_names) {
        PFL_EXPECT(std::any_of(
            pppoe_layer->fields.begin(),
            pppoe_layer->fields.end(),
            [&](const session_detail::PacketSummaryField& field) {
                return field.label.find(tag_name) != std::string::npos;
            }
        ));
    }
}

void expect_pppoe_control_unrecognized(
    CaptureSession& session,
    const std::filesystem::path& relative_path,
    const std::uint16_t expected_ppp_protocol,
    const std::string& expected_code_fragment,
    const std::vector<std::string>& expected_option_names = {}
) {
    const auto row = expect_single_unrecognized_packet(session, relative_path);
    const auto packet = require_packet(session, row.packet_index);
    const auto details = session.read_packet_details(packet);
    PFL_EXPECT(details.has_value());
    PFL_EXPECT(details->has_ethernet);
    PFL_EXPECT(details->has_pppoe);
    PFL_EXPECT(!details->pppoe.is_discovery);
    PFL_EXPECT(details->pppoe.ppp_protocol == expected_ppp_protocol);
    PFL_EXPECT(details->pppoe.control.present);
    PFL_EXPECT(!details->has_ipv4);
    PFL_EXPECT(!details->has_ipv6);

    const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet);
    PFL_EXPECT(find_layer(summary_layers, "frame") != nullptr);
    PFL_EXPECT(find_layer(summary_layers, "ethernet") != nullptr);
    const auto* pppoe_layer = find_layer(summary_layers, "pppoe");
    PFL_EXPECT(pppoe_layer != nullptr);
    PFL_EXPECT(pppoe_layer->title.find("PPPoE Session") != std::string::npos);
    PFL_EXPECT(layer_has_field_containing(*pppoe_layer, "PPP Protocol", expected_ppp_protocol == 0xc021U
        ? "LCP"
        : expected_ppp_protocol == 0x8021U
            ? "IPCP"
            : "IPv6CP"));

    const auto* ppp_layer = find_layer(summary_layers, "ppp");
    PFL_EXPECT(ppp_layer != nullptr);
    PFL_EXPECT(!ppp_layer->children.empty());
    const auto& control_layer = ppp_layer->children.front();
    PFL_EXPECT(control_layer.id == "ppp-control");
    PFL_EXPECT(layer_has_field_containing(control_layer, "Code", expected_code_fragment));
    PFL_EXPECT(layer_has_field_containing(control_layer, "Identifier", ""));
    PFL_EXPECT(layer_has_field_containing(control_layer, "Length", "bytes"));
    PFL_EXPECT(!control_layer.children.empty());
    const auto& options_layer = control_layer.children.front();
    PFL_EXPECT(options_layer.id == "ppp-control-options");

    for (const auto& option_name : expected_option_names) {
        PFL_EXPECT(std::any_of(
            options_layer.children.begin(),
            options_layer.children.end(),
            [&](const session_detail::PacketSummaryLayer& child) {
                return child.title.find(option_name) != std::string::npos;
            }
        ));
    }
}

void expect_single_session_flow(
    CaptureSession& session,
    const std::filesystem::path& relative_path,
    const FlowAddressFamily expected_family,
    const std::string& expected_protocol,
    const std::uint16_t expected_ppp_protocol,
    const std::initializer_list<const char*> expected_layer_prefix,
    const std::size_t expected_vlan_count = 0U
) {
    PFL_EXPECT(session.open_capture(fixture_path(relative_path)));
    const auto rows = session.list_flows();
    PFL_EXPECT(rows.size() == 1U);
    PFL_EXPECT(rows[0].family == expected_family);
    PFL_EXPECT(rows[0].protocol_text == expected_protocol);
    PFL_EXPECT(rows[0].packet_count == 1U);
    PFL_EXPECT(session.unrecognized_packet_count() == 0U);

    const auto packet = require_packet(session, 0U);
    const auto details = session.read_packet_details(packet);
    PFL_EXPECT(details.has_value());
    PFL_EXPECT(details->has_ethernet);
    PFL_EXPECT(details->has_pppoe);
    PFL_EXPECT(details->pppoe.version == 1U);
    PFL_EXPECT(details->pppoe.type == 1U);
    PFL_EXPECT(details->pppoe.code == 0U);
    PFL_EXPECT(details->pppoe.ppp_protocol == expected_ppp_protocol);
    PFL_EXPECT(!details->pppoe.header_truncated);
    PFL_EXPECT(!details->pppoe.protocol_field_truncated);
    PFL_EXPECT(!details->pppoe.payload_length_mismatch);
    PFL_EXPECT(details->vlan_tags.size() == expected_vlan_count);

    const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet);
    PFL_EXPECT(summary_layers.size() >= expected_layer_prefix.size());
    std::size_t index = 0U;
    for (const auto* expected_id : expected_layer_prefix) {
        PFL_EXPECT(summary_layers[index].id == expected_id);
        ++index;
    }

    const auto* pppoe_layer = find_layer(summary_layers, "pppoe");
    PFL_EXPECT(pppoe_layer != nullptr);
    PFL_EXPECT(pppoe_layer->title.find("PPPoE Session") != std::string::npos);
    PFL_EXPECT(std::any_of(
        pppoe_layer->fields.begin(),
        pppoe_layer->fields.end(),
        [expected_ppp_protocol](const session_detail::PacketSummaryField& field) {
            return field.label == "PPP Protocol" &&
                field.value.find(expected_ppp_protocol == 0x0021U ? "IPv4" : "IPv6") != std::string::npos;
        }
    ));

    const auto* ppp_layer = find_layer(summary_layers, "ppp");
    PFL_EXPECT(ppp_layer != nullptr);
    PFL_EXPECT(!ppp_layer->fields.empty());
    PFL_EXPECT(ppp_layer->fields.front().label == "Protocol");
}

}  // namespace

void run_pppoe_pcap_fixture_tests() {
    {
        CaptureSession session {};
        expect_single_session_flow(
            session,
            "parsing/pppoe/01_pppoe_session_ipv4_tcp.pcap",
            FlowAddressFamily::ipv4,
            "TCP",
            0x0021U,
            {"frame", "ethernet", "pppoe", "ppp", "ipv4", "tcp"}
        );
    }

    {
        CaptureSession session {};
        expect_single_session_flow(
            session,
            "parsing/pppoe/02_pppoe_session_ipv4_udp.pcap",
            FlowAddressFamily::ipv4,
            "UDP",
            0x0021U,
            {"frame", "ethernet", "pppoe", "ppp", "ipv4", "udp"}
        );
    }

    {
        CaptureSession session {};
        expect_single_session_flow(
            session,
            "parsing/pppoe/03_pppoe_session_ipv6_tcp.pcap",
            FlowAddressFamily::ipv6,
            "TCP",
            0x0057U,
            {"frame", "ethernet", "pppoe", "ppp", "ipv6", "tcp"}
        );
    }

    {
        CaptureSession session {};
        expect_single_session_flow(
            session,
            "parsing/pppoe/04_pppoe_session_ipv6_udp.pcap",
            FlowAddressFamily::ipv6,
            "UDP",
            0x0057U,
            {"frame", "ethernet", "pppoe", "ppp", "ipv6", "udp"}
        );
    }

    {
        CaptureSession session {};
        expect_pppoe_control_unrecognized(
            session,
            "parsing/pppoe/05_pppoe_session_lcp_config_request.pcap",
            0xc021U,
            "Configure-Request",
            {"MRU", "Magic Number"}
        );
    }

    {
        CaptureSession session {};
        expect_pppoe_control_unrecognized(
            session,
            "parsing/pppoe/06_pppoe_session_ipcp_config_request.pcap",
            0x8021U,
            "Configure-Request",
            {"IP-Address"}
        );
    }

    {
        CaptureSession session {};
        expect_pppoe_control_unrecognized(
            session,
            "parsing/pppoe/07_pppoe_session_ipv6cp_config_request.pcap",
            0x8057U,
            "Configure-Request",
            {"Interface-Identifier"}
        );
    }

    {
        CaptureSession session {};
        expect_pppoe_discovery_unrecognized(
            session,
            "parsing/pppoe/08_pppoe_discovery_padi.pcap",
            "PADI"
        );
    }

    {
        CaptureSession session {};
        expect_pppoe_discovery_unrecognized(
            session,
            "parsing/pppoe/09_pppoe_discovery_pado.pcap",
            "PADO",
            {"Service-Name", "AC-Name", "AC-Cookie"}
        );
    }

    {
        CaptureSession session {};
        expect_pppoe_discovery_unrecognized(
            session,
            "parsing/pppoe/10_pppoe_discovery_padr.pcap",
            "PADR",
            {"Service-Name"}
        );
    }

    {
        CaptureSession session {};
        expect_pppoe_discovery_unrecognized(
            session,
            "parsing/pppoe/11_pppoe_discovery_pads.pcap",
            "PADS",
            {"Service-Name"}
        );
    }

    {
        CaptureSession session {};
        expect_pppoe_discovery_unrecognized(
            session,
            "parsing/pppoe/12_pppoe_discovery_padt.pcap",
            "PADT"
        );
    }

    {
        CaptureSession session {};
        expect_single_session_flow(
            session,
            "parsing/pppoe/13_vlan_pppoe_session_ipv4_tcp.pcap",
            FlowAddressFamily::ipv4,
            "TCP",
            0x0021U,
            {"frame", "ethernet", "vlan", "pppoe", "ppp", "ipv4", "tcp"},
            1U
        );
    }

    {
        CaptureSession session {};
        expect_single_session_flow(
            session,
            "parsing/pppoe/14_qinq_pppoe_session_ipv4_udp.pcap",
            FlowAddressFamily::ipv4,
            "UDP",
            0x0021U,
            {"frame", "ethernet", "vlan", "vlan", "pppoe", "ppp", "ipv4", "udp"},
            2U
        );
    }

    for (const auto* relative_path : {
             "parsing/pppoe/15_pppoe_session_unknown_ppp_protocol.pcap",
             "parsing/pppoe/19_pppoe_bad_length_short_payload.pcap",
         }) {
        CaptureSession session {};
        const auto row = expect_single_unrecognized_packet(session, relative_path);
        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_EXPECT(details.has_value());
        PFL_EXPECT(details->has_ethernet);
        PFL_EXPECT(details->has_pppoe);
        PFL_EXPECT(!details->has_ipv4);
        PFL_EXPECT(!details->has_ipv6);
        PFL_EXPECT(row.reason_text == "Unsupported or malformed packet");
    }

    {
        CaptureSession session {};
        const auto row = expect_single_unrecognized_packet(session, "parsing/pppoe/20_pppoe_bad_length_extra_payload.pcap");
        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_EXPECT(details.has_value());
        PFL_EXPECT(details->has_ethernet);
        PFL_EXPECT(details->has_pppoe);
        PFL_EXPECT(details->has_ipv4);
        PFL_EXPECT(!details->has_ipv6);
        PFL_EXPECT(row.reason_text == "Unsupported or malformed packet");
    }

    {
        CaptureSession session {};
        const auto row = expect_single_unrecognized_packet(session, "parsing/pppoe/16_pppoe_truncated_header.pcap");
        const auto packet = require_packet(session, row.packet_index);
        const auto details = session.read_packet_details(packet);
        PFL_EXPECT(details.has_value());
        PFL_EXPECT(details->has_ethernet);
        PFL_EXPECT(details->has_pppoe);
        PFL_EXPECT(details->pppoe.header_truncated);
    }

    {
        CaptureSession session {};
        const auto row = expect_single_unrecognized_packet(session, "parsing/pppoe/17_pppoe_truncated_ppp_protocol.pcap");
        const auto packet = require_packet(session, row.packet_index);
        const auto details = session.read_packet_details(packet);
        PFL_EXPECT(details.has_value());
        PFL_EXPECT(details->has_ethernet);
        PFL_EXPECT(details->has_pppoe);
        PFL_EXPECT(details->pppoe.protocol_field_truncated);
    }

    {
        CaptureSession session {};
        const auto row = expect_single_unrecognized_packet(session, "parsing/pppoe/18_pppoe_truncated_inner_ipv4.pcap");
        PFL_EXPECT(
            row.reason_text == "IPv4 header truncated" ||
            row.reason_text == "Unsupported or malformed packet"
        );
        const auto packet = require_packet(session, row.packet_index);
        const auto details = session.read_packet_details(packet);
        PFL_EXPECT(details.has_value());
        PFL_EXPECT(details->has_ethernet);
        PFL_EXPECT(details->has_pppoe);
        PFL_EXPECT(!details->has_ipv4);
    }
}

}  // namespace pfl::tests
