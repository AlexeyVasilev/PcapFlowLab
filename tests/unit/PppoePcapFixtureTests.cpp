#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <variant>
#include <vector>

#include "TestSupport.h"
#include "app/session/CaptureSession.h"
#include "app/session/FlowRows.h"
#include "app/session/SessionFormatting.h"
#include "core/domain/ProtocolPath.h"

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

ProtocolId flow_protocol_id(const FlowRow& row) {
    if (const auto* key = std::get_if<ConnectionKeyV4>(&row.key)) {
        return key->protocol;
    }

    const auto* key = std::get_if<ConnectionKeyV6>(&row.key);
    PFL_REQUIRE(key != nullptr);
    return key->protocol;
}

const ProtocolPath* require_protocol_path(const CaptureSession& session, const ProtocolPathId protocol_path_id) {
    PFL_REQUIRE(protocol_path_id != kInvalidProtocolPathId);
    const auto* path = session.state().protocol_path_registry.find(protocol_path_id);
    PFL_REQUIRE(path != nullptr);
    return path;
}

std::string require_flow_protocol_path_text(const CaptureSession& session, const FlowRow& row) {
    return format_protocol_path(*require_protocol_path(session, row.protocol_path_id));
}

const ProtocolPathStatisticsRow* find_protocol_path_stats_row(
    const CaptureProtocolPathSummary& summary,
    const std::string& path_text
) {
    const auto found = std::find_if(summary.rows.begin(), summary.rows.end(), [&](const ProtocolPathStatisticsRow& row) {
        return row.path_text == path_text;
    });
    return found == summary.rows.end() ? nullptr : &*found;
}

void expect_protocol_path_stats_row(
    const CaptureProtocolPathSummary& summary,
    const std::string& path_text,
    const std::uint64_t expected_flow_count,
    const std::uint64_t expected_packet_count
) {
    const auto* row = find_protocol_path_stats_row(summary, path_text);
    PFL_REQUIRE(row != nullptr);
    PFL_EXPECT(row->flow_count == expected_flow_count);
    PFL_EXPECT(row->packet_count == expected_packet_count);
}

void expect_no_protocol_paths(const CaptureSession& session) {
    PFL_EXPECT(session.state().protocol_path_registry.size() == 0U);
    PFL_EXPECT(session.protocol_path_summary().rows.empty());
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

bool layer_has_field_label(
    const session_detail::PacketSummaryLayer& layer,
    const std::string& label
) {
    return std::any_of(layer.fields.begin(), layer.fields.end(), [&](const session_detail::PacketSummaryField& field) {
        return field.label == label;
    });
}

UnrecognizedPacketRow expect_single_unrecognized_packet(
    CaptureSession& session,
    const std::filesystem::path& relative_path,
    const std::optional<std::string>& expected_reason = std::nullopt
) {
    const ScopedTestContext fixture_context {"fixture=" + relative_path.generic_string()};
    PFL_EXPECT(session.open_capture(fixture_path(relative_path)));
    PFL_EXPECT(session.summary().packet_count == 0U);
    PFL_EXPECT(session.list_flows().empty());
    PFL_EXPECT(session.unrecognized_packet_count() == 1U);
    expect_no_protocol_paths(session);

    const auto rows = session.list_unrecognized_packets(0U, 30U);
    PFL_REQUIRE(rows.size() == 1U);
    PFL_EXPECT(rows[0].row_number == 1U);
    PFL_EXPECT(rows[0].packet_index == 0U);
    PFL_EXPECT(!rows[0].reason_text.empty());
    if (expected_reason.has_value()) {
        PFL_EXPECT(rows[0].reason_text.find(*expected_reason) != std::string::npos);
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
    const auto row = expect_single_unrecognized_packet(
        session,
        relative_path,
        "PPPoE Discovery " + expected_code_fragment
    );
    const auto packet = require_packet(session, row.packet_index);
    const auto details = session.read_packet_details(packet);
    PFL_REQUIRE(details.has_value());
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
    PFL_REQUIRE(pppoe_layer != nullptr);
    PFL_EXPECT(pppoe_layer->title.find("PPPoE Discovery") != std::string::npos);
    PFL_EXPECT(layer_has_field_containing(*pppoe_layer, "Code", expected_code_fragment));
    PFL_EXPECT(layer_has_field_containing(*pppoe_layer, "Session ID", "0x"));
    PFL_EXPECT(layer_has_field_containing(*pppoe_layer, "Payload Length", "bytes"));
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
    const auto row = expect_single_unrecognized_packet(
        session,
        relative_path,
        expected_ppp_protocol == 0xc021U
            ? std::optional<std::string> {"PPP LCP control packet"}
            : expected_ppp_protocol == 0x8021U
                ? std::optional<std::string> {"PPP IPCP control packet"}
                : std::optional<std::string> {"PPP IPv6CP control packet"}
    );
    const auto packet = require_packet(session, row.packet_index);
    const auto details = session.read_packet_details(packet);
    PFL_REQUIRE(details.has_value());
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
    PFL_REQUIRE(pppoe_layer != nullptr);
    PFL_EXPECT(pppoe_layer->title.find("PPPoE Session") != std::string::npos);
    PFL_EXPECT(layer_has_field_containing(*pppoe_layer, "Payload Length", "bytes"));
    PFL_EXPECT(!layer_has_field_label(*pppoe_layer, "PPP Protocol"));

    const auto* ppp_layer = find_layer(summary_layers, "ppp");
    PFL_REQUIRE(ppp_layer != nullptr);
    PFL_EXPECT(layer_has_field_containing(*ppp_layer, "Protocol", expected_ppp_protocol == 0xc021U
        ? "LCP"
        : expected_ppp_protocol == 0x8021U
            ? "IPCP"
            : "IPv6CP"));
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

void expect_session_flow_contract(
    CaptureSession& session,
    const std::filesystem::path& relative_path,
    const FlowAddressFamily expected_family,
    const ProtocolId expected_protocol_id,
    const std::string& expected_protocol_text,
    const std::uint16_t expected_ppp_protocol,
    const std::string& expected_protocol_path,
    const std::initializer_list<const char*> expected_layer_prefix,
    const std::uint32_t expected_payload_length,
    const std::uint16_t expected_session_id = 0x1234U,
    const std::vector<std::uint16_t>& expected_vlan_tpids = {},
    const std::optional<std::string>& expected_kind_overview_path = std::nullopt
) {
    const ScopedTestContext fixture_context {"fixture=" + relative_path.generic_string()};
    PFL_EXPECT(session.open_capture(fixture_path(relative_path)));
    const auto rows = session.list_flows();
    PFL_REQUIRE(rows.size() == 1U);
    PFL_EXPECT(rows[0].family == expected_family);
    PFL_EXPECT(rows[0].protocol_text == expected_protocol_text);
    PFL_EXPECT(flow_protocol_id(rows[0]) == expected_protocol_id);
    PFL_EXPECT(rows[0].packet_count == 1U);
    PFL_EXPECT(session.unrecognized_packet_count() == 0U);
    PFL_EXPECT(session.state().protocol_path_registry.size() == 1U);
    PFL_EXPECT(require_flow_protocol_path_text(session, rows[0]) == expected_protocol_path);

    const auto path_summary = session.protocol_path_summary();
    expect_protocol_path_stats_row(
        path_summary,
        expected_kind_overview_path.value_or(expected_protocol_path),
        1U,
        1U);

    const auto packet_rows = session.list_flow_packets(0U);
    PFL_REQUIRE(packet_rows.size() == 1U);
    PFL_EXPECT(packet_rows[0].payload_length == expected_payload_length);

    const auto packet = require_packet(session, packet_rows[0].packet_index);
    const auto details = session.read_packet_details(packet);
    PFL_REQUIRE(details.has_value());
    PFL_EXPECT(details->has_ethernet);
    PFL_EXPECT(details->has_pppoe);
    PFL_EXPECT(details->pppoe.version == 1U);
    PFL_EXPECT(details->pppoe.type == 1U);
    PFL_EXPECT(details->pppoe.code == 0U);
    PFL_EXPECT(details->pppoe.session_id == expected_session_id);
    PFL_EXPECT(details->pppoe.ppp_protocol == expected_ppp_protocol);
    PFL_EXPECT(!details->pppoe.header_truncated);
    PFL_EXPECT(!details->pppoe.protocol_field_truncated);
    PFL_EXPECT(!details->pppoe.payload_length_mismatch);
    PFL_EXPECT(details->vlan_tags.size() == expected_vlan_tpids.size());
    for (std::size_t index = 0; index < expected_vlan_tpids.size(); ++index) {
        PFL_EXPECT(details->vlan_tags[index].tpid == expected_vlan_tpids[index]);
    }

    const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet);
    PFL_REQUIRE(summary_layers.size() >= expected_layer_prefix.size());
    std::size_t index = 0U;
    for (const auto* expected_id : expected_layer_prefix) {
        PFL_EXPECT(summary_layers[index].id == expected_id);
        ++index;
    }

    const auto* pppoe_layer = find_layer(summary_layers, "pppoe");
    PFL_REQUIRE(pppoe_layer != nullptr);
    PFL_EXPECT(pppoe_layer->title.find("PPPoE Session") != std::string::npos);
    PFL_EXPECT(layer_has_field_containing(*pppoe_layer, "Session ID", "0x"));
    PFL_EXPECT(layer_has_field_containing(*pppoe_layer, "Payload Length", "bytes"));
    PFL_EXPECT(!layer_has_field_label(*pppoe_layer, "PPP Protocol"));

    const auto* ppp_layer = find_layer(summary_layers, "ppp");
    PFL_REQUIRE(ppp_layer != nullptr);
    PFL_EXPECT(!ppp_layer->fields.empty());
    PFL_EXPECT(ppp_layer->fields.front().label == "Protocol");
    PFL_EXPECT(ppp_layer->fields.front().value.find(expected_ppp_protocol == 0x0021U ? "IPv4" : "IPv6") != std::string::npos);
}

void expect_multi_packet_session_flow_contract(
    CaptureSession& session,
    const std::filesystem::path& relative_path,
    const std::string& expected_protocol_path,
    const ProtocolId expected_protocol_id,
    const std::string& expected_protocol_text,
    const std::vector<std::uint16_t>& expected_session_ids,
    const std::uint32_t expected_payload_length,
    const std::optional<std::string>& expected_kind_overview_path = std::nullopt
) {
    const ScopedTestContext fixture_context {"fixture=" + relative_path.generic_string()};
    PFL_EXPECT(session.open_capture(fixture_path(relative_path)));
    const auto rows = session.list_flows();
    PFL_REQUIRE(rows.size() == 1U);
    PFL_EXPECT(rows[0].packet_count == expected_session_ids.size());
    PFL_EXPECT(rows[0].protocol_text == expected_protocol_text);
    PFL_EXPECT(flow_protocol_id(rows[0]) == expected_protocol_id);
    PFL_EXPECT(session.unrecognized_packet_count() == 0U);
    PFL_EXPECT(session.state().protocol_path_registry.size() == 1U);
    PFL_EXPECT(require_flow_protocol_path_text(session, rows[0]) == expected_protocol_path);

    const auto path_summary = session.protocol_path_summary();
    expect_protocol_path_stats_row(
        path_summary,
        expected_kind_overview_path.value_or(expected_protocol_path),
        1U,
        static_cast<std::uint64_t>(expected_session_ids.size()));

    const auto packet_rows = session.list_flow_packets(0U);
    PFL_REQUIRE(packet_rows.size() == expected_session_ids.size());
    for (std::size_t index = 0; index < packet_rows.size(); ++index) {
        PFL_EXPECT(packet_rows[index].payload_length == expected_payload_length);
        const auto packet = require_packet(session, packet_rows[index].packet_index);
        const auto details = session.read_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->has_pppoe);
        PFL_EXPECT(details->pppoe.session_id == expected_session_ids[index]);
        PFL_EXPECT(details->pppoe.code == 0U);
    }
}

void expect_unsupported_session_variant_unrecognized(
    CaptureSession& session,
    const std::filesystem::path& relative_path,
    const std::uint8_t expected_version,
    const std::uint8_t expected_type,
    const std::uint8_t expected_code
) {
    const auto row = expect_single_unrecognized_packet(
        session,
        relative_path,
        "Unsupported or malformed packet"
    );
    const auto packet = require_packet(session, row.packet_index);
    const auto details = session.read_packet_details(packet);
    PFL_REQUIRE(details.has_value());
    PFL_EXPECT(details->has_ethernet);
    PFL_EXPECT(details->has_pppoe);
    PFL_EXPECT(!details->pppoe.is_discovery);
    PFL_EXPECT(details->pppoe.version == expected_version);
    PFL_EXPECT(details->pppoe.type == expected_type);
    PFL_EXPECT(details->pppoe.code == expected_code);
    PFL_EXPECT(details->pppoe.ppp_protocol == 0x0021U);
    PFL_EXPECT(!details->has_ipv4);
    PFL_EXPECT(!details->has_ipv6);
    PFL_EXPECT(!details->has_tcp);
    PFL_EXPECT(!details->has_udp);

    const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet);
    PFL_REQUIRE(find_layer(summary_layers, "pppoe") != nullptr);
    PFL_REQUIRE(find_layer(summary_layers, "ppp") != nullptr);
    PFL_EXPECT(find_layer(summary_layers, "ipv4") == nullptr);
    PFL_EXPECT(find_layer(summary_layers, "ipv6") == nullptr);
}

}  // namespace

void run_pppoe_pcap_fixture_tests() {
    {
        CaptureSession session {};
        expect_session_flow_contract(
            session,
            "parsing/pppoe/01_pppoe_session_ipv4_tcp.pcap",
            FlowAddressFamily::ipv4,
            ProtocolId::tcp,
            "TCP",
            0x0021U,
            "EthernetII -> PPPoE -> PPP -> IPv4 -> TCP",
            {"frame", "ethernet", "pppoe", "ppp", "ipv4", "tcp"},
            9U
        );
    }

    {
        CaptureSession session {};
        expect_session_flow_contract(
            session,
            "parsing/pppoe/02_pppoe_session_ipv4_udp.pcap",
            FlowAddressFamily::ipv4,
            ProtocolId::udp,
            "UDP",
            0x0021U,
            "EthernetII -> PPPoE -> PPP -> IPv4 -> UDP",
            {"frame", "ethernet", "pppoe", "ppp", "ipv4", "udp"},
            9U
        );
    }

    {
        CaptureSession session {};
        expect_session_flow_contract(
            session,
            "parsing/pppoe/03_pppoe_session_ipv6_tcp.pcap",
            FlowAddressFamily::ipv6,
            ProtocolId::tcp,
            "TCP",
            0x0057U,
            "EthernetII -> PPPoE -> PPP -> IPv6 -> TCP",
            {"frame", "ethernet", "pppoe", "ppp", "ipv6", "tcp"},
            9U
        );
    }

    {
        CaptureSession session {};
        expect_session_flow_contract(
            session,
            "parsing/pppoe/04_pppoe_session_ipv6_udp.pcap",
            FlowAddressFamily::ipv6,
            ProtocolId::udp,
            "UDP",
            0x0057U,
            "EthernetII -> PPPoE -> PPP -> IPv6 -> UDP",
            {"frame", "ethernet", "pppoe", "ppp", "ipv6", "udp"},
            9U
        );
    }

    {
        CaptureSession session {};
        expect_pppoe_control_unrecognized(
            session,
            "parsing/pppoe/05_pppoe_session_lcp_config_request.pcap",
            0xc021U,
            "Configure-Request",
            {"Maximum Receive Unit", "Magic Number"}
        );
    }

    {
        CaptureSession session {};
        expect_pppoe_control_unrecognized(
            session,
            "parsing/pppoe/06_pppoe_session_ipcp_config_request.pcap",
            0x8021U,
            "Configure-Request",
            {"IP Address"}
        );
    }

    {
        CaptureSession session {};
        expect_pppoe_control_unrecognized(
            session,
            "parsing/pppoe/07_pppoe_session_ipv6cp_config_request.pcap",
            0x8057U,
            "Configure-Request",
            {"Interface Identifier"}
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
        expect_session_flow_contract(
            session,
            "parsing/pppoe/13_vlan_pppoe_session_ipv4_tcp.pcap",
            FlowAddressFamily::ipv4,
            ProtocolId::tcp,
            "TCP",
            0x0021U,
            "EthernetII -> VLAN(vid=130) -> PPPoE -> PPP -> IPv4 -> TCP",
            {"frame", "ethernet", "vlan", "pppoe", "ppp", "ipv4", "tcp"},
            9U,
            0x1234U,
            {0x8100U},
            "EthernetII -> VLAN -> PPPoE -> PPP -> IPv4 -> TCP"
        );
    }

    {
        CaptureSession session {};
        expect_session_flow_contract(
            session,
            "parsing/pppoe/14_qinq_pppoe_session_ipv4_udp.pcap",
            FlowAddressFamily::ipv4,
            ProtocolId::udp,
            "UDP",
            0x0021U,
            "EthernetII -> VLAN(vid=230) -> VLAN(vid=231) -> PPPoE -> PPP -> IPv4 -> UDP",
            {"frame", "ethernet", "vlan", "vlan", "pppoe", "ppp", "ipv4", "udp"},
            9U,
            0x1234U,
            {0x88A8U, 0x8100U},
            "EthernetII -> VLAN -> VLAN -> PPPoE -> PPP -> IPv4 -> UDP"
        );
    }

    {
        CaptureSession session {};
        const auto row = expect_single_unrecognized_packet(
            session,
            "parsing/pppoe/15_pppoe_session_unknown_ppp_protocol.pcap",
            "Unknown PPP protocol"
        );
        const auto packet = require_packet(session, row.packet_index);
        const auto details = session.read_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->has_ethernet);
        PFL_EXPECT(details->has_pppoe);
        PFL_EXPECT(!details->pppoe.is_discovery);
        PFL_EXPECT(details->pppoe.ppp_protocol == 0x1235U);
        PFL_EXPECT(!details->pppoe.control.present);
        PFL_EXPECT(details->pppoe.unknown_ppp_payload_length > 0U);
        PFL_EXPECT(!details->pppoe.unknown_ppp_payload_preview.empty());
        PFL_EXPECT(!details->has_ipv4);
        PFL_EXPECT(!details->has_ipv6);
        PFL_EXPECT(row.reason_text == "Unknown PPP protocol");

        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet);
        const auto* pppoe_layer = find_layer(summary_layers, "pppoe");
        PFL_REQUIRE(pppoe_layer != nullptr);
        const auto* ppp_layer = find_layer(summary_layers, "ppp");
        PFL_REQUIRE(ppp_layer != nullptr);
        PFL_EXPECT(layer_has_field_containing(*ppp_layer, "Protocol", "0x"));
        PFL_EXPECT(!ppp_layer->children.empty());
        const auto* payload_layer = find_layer(ppp_layer->children, "ppp-payload");
        PFL_REQUIRE(payload_layer != nullptr);
        PFL_EXPECT(payload_layer->title == "Data");
        PFL_EXPECT(layer_has_field_containing(*payload_layer, "Length", "bytes"));
        PFL_EXPECT(layer_has_field_label(*payload_layer, "Raw"));
        if (details->pppoe.unknown_ppp_payload_preview_truncated) {
            PFL_EXPECT(layer_has_field_containing(*payload_layer, "Preview truncated", "Yes"));
        }
    }

    {
        CaptureSession session {};
        const auto row = expect_single_unrecognized_packet(
            session,
            "parsing/pppoe/16_pppoe_truncated_header.pcap",
            "PPPoE Session header truncated"
        );
        const auto packet = require_packet(session, row.packet_index);
        const auto details = session.read_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->has_ethernet);
        PFL_EXPECT(details->has_pppoe);
        PFL_EXPECT(details->pppoe.header_truncated);
    }

    {
        CaptureSession session {};
        const auto row = expect_single_unrecognized_packet(
            session,
            "parsing/pppoe/17_pppoe_truncated_ppp_protocol.pcap",
            "PPP protocol field truncated"
        );
        const auto packet = require_packet(session, row.packet_index);
        const auto details = session.read_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->has_ethernet);
        PFL_EXPECT(details->has_pppoe);
        PFL_EXPECT(details->pppoe.protocol_field_truncated);
        PFL_EXPECT(details->pppoe.declared_payload_exceeds_captured);
    }

    {
        CaptureSession session {};
        const auto row = expect_single_unrecognized_packet(
            session,
            "parsing/pppoe/18_pppoe_truncated_inner_ipv4.pcap"
        );
        const auto packet = require_packet(session, row.packet_index);
        const auto details = session.read_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->has_ethernet);
        PFL_EXPECT(details->has_pppoe);
        PFL_EXPECT(details->has_ipv4);
        PFL_EXPECT(details->ipv4.header_truncated);
        PFL_EXPECT(details->ipv4.available_header_bytes > 0U);
        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet);
        const auto* ppp_layer = find_layer(summary_layers, "ppp");
        PFL_REQUIRE(ppp_layer != nullptr);
        const auto* ipv4_layer = find_layer(summary_layers, "ipv4");
        PFL_REQUIRE(ipv4_layer != nullptr);
        PFL_EXPECT(layer_has_field_containing(*ipv4_layer, "Warning", "IPv4 header is truncated"));
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/pppoe/19_pppoe_bad_length_short_payload.pcap")));
        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 1U);
        PFL_EXPECT(rows[0].family == FlowAddressFamily::ipv4);
        PFL_EXPECT(rows[0].protocol_text == "UDP");
        PFL_EXPECT(flow_protocol_id(rows[0]) == ProtocolId::udp);
        PFL_EXPECT(require_flow_protocol_path_text(session, rows[0]) == "EthernetII -> PPPoE -> PPP -> IPv4 -> UDP");
        PFL_EXPECT(session.unrecognized_packet_count() == 0U);

        const auto packet_rows = session.list_flow_packets(0U);
        PFL_REQUIRE(packet_rows.size() == 1U);
        PFL_EXPECT(packet_rows[0].payload_length == 9U);
        const auto packet = require_packet(session, packet_rows[0].packet_index);
        const auto details = session.read_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->has_ethernet);
        PFL_EXPECT(details->has_pppoe);
        PFL_EXPECT(details->has_ipv4);
        PFL_EXPECT(details->has_udp);
        PFL_EXPECT(details->pppoe.declared_payload_exceeds_captured);
        PFL_EXPECT(details->pppoe.payload_length_mismatch);
        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet);
        const auto* pppoe_layer = find_layer(summary_layers, "pppoe");
        PFL_REQUIRE(pppoe_layer != nullptr);
        PFL_EXPECT(layer_has_field_containing(*pppoe_layer, "Warning", "exceeds captured payload bytes"));
    }

    {
        CaptureSession session {};
        const auto row = expect_single_unrecognized_packet(
            session,
            "parsing/pppoe/20_pppoe_bad_length_extra_payload.pcap",
            "Unsupported or malformed packet"
        );
        const auto packet = require_packet(session, row.packet_index);
        const auto details = session.read_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->has_ethernet);
        PFL_EXPECT(details->has_pppoe);
        PFL_EXPECT(details->pppoe.captured_payload_exceeds_declared);
        PFL_EXPECT(details->pppoe.payload_length_mismatch);
        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet);
        const auto* pppoe_layer = find_layer(summary_layers, "pppoe");
        PFL_REQUIRE(pppoe_layer != nullptr);
        PFL_EXPECT(layer_has_field_containing(*pppoe_layer, "Warning", "trailing bytes ignored"));
    }

    {
        CaptureSession session {};
        expect_multi_packet_session_flow_contract(
            session,
            "parsing/pppoe/21_pppoe_session_same_tuple_same_session_id.pcap",
            "EthernetII -> PPPoE -> PPP -> IPv4 -> UDP",
            ProtocolId::udp,
            "UDP",
            {0x3333U, 0x3333U},
            9U
        );
    }

    {
        CaptureSession session {};
        expect_multi_packet_session_flow_contract(
            session,
            "parsing/pppoe/22_pppoe_session_same_tuple_different_session_id.pcap",
            "EthernetII -> PPPoE -> PPP -> IPv4 -> UDP",
            ProtocolId::udp,
            "UDP",
            {0x3333U, 0x4444U},
            9U
        );
    }

    {
        CaptureSession session {};
        expect_session_flow_contract(
            session,
            "parsing/pppoe/23_pppoe_session_zero_session_id_ipv4_udp.pcap",
            FlowAddressFamily::ipv4,
            ProtocolId::udp,
            "UDP",
            0x0021U,
            "EthernetII -> PPPoE -> PPP -> IPv4 -> UDP",
            {"frame", "ethernet", "pppoe", "ppp", "ipv4", "udp"},
            9U,
            0x0000U
        );
    }

    {
        CaptureSession session {};
        expect_session_flow_contract(
            session,
            "parsing/pppoe/24_qinq_pppoe_session_ipv6_tcp.pcap",
            FlowAddressFamily::ipv6,
            ProtocolId::tcp,
            "TCP",
            0x0057U,
            "EthernetII -> VLAN(vid=232) -> VLAN(vid=233) -> PPPoE -> PPP -> IPv6 -> TCP",
            {"frame", "ethernet", "vlan", "vlan", "pppoe", "ppp", "ipv6", "tcp"},
            9U,
            0x1234U,
            {0x88A8U, 0x8100U},
            "EthernetII -> VLAN -> VLAN -> PPPoE -> PPP -> IPv6 -> TCP"
        );
    }

    {
        CaptureSession session {};
        expect_session_flow_contract(
            session,
            "parsing/pppoe/25_legacy_9100_vlan_pppoe_session_ipv4_udp.pcap",
            FlowAddressFamily::ipv4,
            ProtocolId::udp,
            "UDP",
            0x0021U,
            "EthernetII -> VLAN(vid=330) -> PPPoE -> PPP -> IPv4 -> UDP",
            {"frame", "ethernet", "vlan", "pppoe", "ppp", "ipv4", "udp"},
            9U,
            0x1234U,
            {0x9100U},
            "EthernetII -> VLAN -> PPPoE -> PPP -> IPv4 -> UDP"
        );
    }

    {
        CaptureSession session {};
        const auto row = expect_single_unrecognized_packet(
            session,
            "parsing/pppoe/26_pppoe_session_declared_too_short_for_ppp_protocol_with_valid_trailer.pcap",
            "PPP protocol field truncated"
        );
        const auto packet = require_packet(session, row.packet_index);
        const auto details = session.read_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->has_pppoe);
        PFL_EXPECT(details->pppoe.protocol_field_truncated);
        PFL_EXPECT(details->pppoe.captured_payload_exceeds_declared);
        PFL_EXPECT(details->pppoe.payload_length_mismatch);
        PFL_EXPECT(!details->has_ipv4);
        PFL_EXPECT(!details->has_ipv6);
        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet);
        PFL_EXPECT(find_layer(summary_layers, "ppp") == nullptr);
    }

    {
        CaptureSession session {};
        const auto row = expect_single_unrecognized_packet(
            session,
            "parsing/pppoe/27_pppoe_session_capture_truncated_ipv4_udp_caplen_lt_origlen.pcap"
        );
        PFL_EXPECT(row.original_length > row.captured_length);
        const auto packet = require_packet(session, row.packet_index);
        const auto details = session.read_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->has_pppoe);
        PFL_EXPECT(details->pppoe.declared_payload_exceeds_captured);
        PFL_EXPECT(details->pppoe.payload_length_mismatch);
        PFL_EXPECT(details->has_ipv4);
        PFL_EXPECT(!details->has_udp);
    }

    {
        CaptureSession session {};
        expect_unsupported_session_variant_unrecognized(
            session,
            "parsing/pppoe/28_pppoe_session_unsupported_version_with_ipv4_trailer.pcap",
            2U,
            1U,
            0U
        );
    }

    {
        CaptureSession session {};
        expect_unsupported_session_variant_unrecognized(
            session,
            "parsing/pppoe/29_pppoe_session_unsupported_type_with_ipv4_trailer.pcap",
            1U,
            2U,
            0U
        );
    }

    {
        CaptureSession session {};
        expect_unsupported_session_variant_unrecognized(
            session,
            "parsing/pppoe/30_pppoe_session_unsupported_code_with_ipv4_trailer.pcap",
            1U,
            1U,
            1U
        );
    }

    {
        CaptureSession session {};
        const auto row = expect_single_unrecognized_packet(
            session,
            "parsing/pppoe/31_pppoe_session_zero_length_payload.pcap",
            "PPP protocol field truncated"
        );
        const auto packet = require_packet(session, row.packet_index);
        const auto details = session.read_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->has_pppoe);
        PFL_EXPECT(details->pppoe.payload_length == 0U);
        PFL_EXPECT(details->pppoe.protocol_field_truncated);
        PFL_EXPECT(!details->has_ipv4);
        PFL_EXPECT(!details->has_ipv6);
    }

    {
        CaptureSession session {};
        const auto row = expect_single_unrecognized_packet(
            session,
            "parsing/pppoe/32_pppoe_session_truncated_inner_ipv6.pcap"
        );
        const auto packet = require_packet(session, row.packet_index);
        const auto details = session.read_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->has_pppoe);
        PFL_EXPECT(!details->has_ipv6);
        PFL_EXPECT(!details->has_tcp);
        PFL_EXPECT(!details->has_udp);
        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet);
        PFL_REQUIRE(find_layer(summary_layers, "ppp") != nullptr);
        PFL_EXPECT(find_layer(summary_layers, "ipv6") == nullptr);
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/pppoe/33_pppoe_same_session_id_supported_and_unsupported_code.pcap")));
        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 1U);
        PFL_EXPECT(rows[0].packet_count == 1U);
        PFL_EXPECT(rows[0].protocol_text == "UDP");
        PFL_EXPECT(flow_protocol_id(rows[0]) == ProtocolId::udp);
        PFL_EXPECT(require_flow_protocol_path_text(session, rows[0]) == "EthernetII -> PPPoE -> PPP -> IPv4 -> UDP");
        PFL_EXPECT(session.unrecognized_packet_count() == 1U);
        PFL_EXPECT(session.state().protocol_path_registry.size() == 1U);

        const auto path_summary = session.protocol_path_summary();
        expect_protocol_path_stats_row(path_summary, "EthernetII -> PPPoE -> PPP -> IPv4 -> UDP", 1U, 1U);

        const auto unrecognized_rows = session.list_unrecognized_packets(0U, 30U);
        PFL_REQUIRE(unrecognized_rows.size() == 1U);
        PFL_EXPECT(unrecognized_rows[0].reason_text.find("Unsupported or malformed packet") != std::string::npos);
        const auto unrecognized_packet = require_packet(session, unrecognized_rows[0].packet_index);
        const auto details = session.read_packet_details(unrecognized_packet);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->has_pppoe);
        PFL_EXPECT(details->pppoe.session_id == 0x5555U);
        PFL_EXPECT(details->pppoe.code == 1U);
        PFL_EXPECT(!details->has_ipv4);
    }
}

}  // namespace pfl::tests
