#include <algorithm>
#include <filesystem>
#include <iomanip>
#include <initializer_list>
#include <sstream>
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

const ProtocolPath* require_protocol_path(const CaptureSession& session, const ProtocolPathId protocol_path_id) {
    PFL_REQUIRE(protocol_path_id != kInvalidProtocolPathId);
    const auto* path = session.state().protocol_path_registry.find(protocol_path_id);
    PFL_REQUIRE(path != nullptr);
    return path;
}

std::string require_flow_protocol_path_text(const CaptureSession& session, const FlowRow& row) {
    return format_protocol_path(*require_protocol_path(session, row.protocol_path_id));
}

PacketRef require_packet(CaptureSession& session, const std::uint64_t packet_index) {
    const auto packet = session.find_packet(packet_index);
    PFL_REQUIRE(packet.has_value());
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

bool layer_title_contains(
    const session_detail::PacketSummaryLayer& layer,
    const std::string& expected_fragment
) {
    return layer.title.find(expected_fragment) != std::string::npos;
}

std::size_t count_layers(
    const std::vector<session_detail::PacketSummaryLayer>& layers,
    const std::string& id
) {
    return static_cast<std::size_t>(std::count_if(layers.begin(), layers.end(), [&](const session_detail::PacketSummaryLayer& layer) {
        return layer.id == id;
    }));
}

std::string ascii_to_hex_fragment(const std::string& text) {
    std::ostringstream builder {};
    for (std::size_t index = 0; index < text.size(); ++index) {
        if (index > 0U) {
            builder << ' ';
        }
        builder << std::hex << std::nouppercase << std::setw(2) << std::setfill('0')
                << static_cast<unsigned>(static_cast<unsigned char>(text[index]));
    }
    return builder.str();
}

void expect_hex_dump_contains_payload_text(
    const std::string& hex_dump,
    const std::string& text
) {
    constexpr std::size_t kHexDumpLinePayloadBytes = 16U;
    for (std::size_t offset = 0U; offset < text.size(); offset += kHexDumpLinePayloadBytes) {
        const auto chunk = text.substr(offset, std::min(kHexDumpLinePayloadBytes, text.size() - offset));
        PFL_EXPECT(hex_dump.find(ascii_to_hex_fragment(chunk)) != std::string::npos);
    }
}

void expect_layer_prefix(
    const std::vector<session_detail::PacketSummaryLayer>& layers,
    std::initializer_list<const char*> expected_ids
) {
    PFL_EXPECT(layers.size() >= expected_ids.size());
    if (layers.size() < expected_ids.size()) {
        return;
    }
    std::size_t search_index = 0U;
    for (const auto* expected_id : expected_ids) {
        const auto found = std::find_if(
            layers.begin() + static_cast<std::ptrdiff_t>(search_index),
            layers.end(),
            [&](const session_detail::PacketSummaryLayer& layer) {
                return layer.id == expected_id;
            }
        );
        PFL_EXPECT(found != layers.end());
        if (found == layers.end()) {
            return;
        }
        search_index = static_cast<std::size_t>(std::distance(layers.begin(), found)) + 1U;
    }
}

void expect_pbb_metadata(
    const PacketDetails& details,
    const session_detail::PacketSummaryLayer& pbb_layer,
    const std::uint8_t expected_pcp,
    const bool expected_dei,
    const bool expected_nca,
    const std::uint32_t expected_isid
) {
    PFL_EXPECT(details.has_pbb);
    PFL_EXPECT(details.pbb.present);
    PFL_EXPECT(!details.pbb.itag_truncated);
    PFL_EXPECT(details.pbb.available_bytes == 4U);
    PFL_EXPECT(details.pbb.pcp == expected_pcp);
    PFL_EXPECT(details.pbb.dei == expected_dei);
    PFL_EXPECT(details.pbb.nca == expected_nca);
    PFL_EXPECT(details.pbb.isid == expected_isid);
    PFL_EXPECT(layer_has_field_containing(pbb_layer, "Priority", std::to_string(expected_pcp)));
    PFL_EXPECT(layer_has_field_containing(pbb_layer, "Drop Eligible", expected_dei ? "1" : "0"));
    PFL_EXPECT(layer_has_field_containing(pbb_layer, "NCA", expected_nca ? "1" : "0"));
    PFL_EXPECT(layer_has_field_containing(pbb_layer, "Reserved 1", "0"));
    PFL_EXPECT(layer_has_field_containing(pbb_layer, "Reserved 2", "0"));

    std::ostringstream isid_builder {};
    isid_builder << "0x" << std::hex << std::nouppercase << std::setw(6) << std::setfill('0') << expected_isid;
    const auto expected_hex = isid_builder.str();
    PFL_EXPECT(layer_has_field_containing(pbb_layer, "I-SID", expected_hex));
    PFL_EXPECT(layer_has_field_containing(pbb_layer, "I-SID", std::to_string(expected_isid)));
}

void expect_single_ip_pbb_flow(
    CaptureSession& session,
    const std::filesystem::path& relative_path,
    const FlowAddressFamily expected_family,
    const std::string& expected_protocol,
    const std::string& expected_address_a,
    const std::uint16_t expected_port_a,
    const std::string& expected_address_b,
    const std::uint16_t expected_port_b,
    std::initializer_list<const char*> expected_layer_prefix,
    const std::size_t expected_outer_vlan_count = 0U,
    const std::size_t expected_inner_vlan_count = 0U,
    const bool expect_snap = false,
    const std::uint8_t expected_pcp = 0U,
    const bool expected_dei = false,
    const bool expected_nca = false,
    const std::uint32_t expected_isid = 0x123456U,
    const std::string& expected_protocol_path = {},
    const std::string& expected_transport_payload = {}
) {
    const ScopedTestContext fixture_context {"fixture=" + relative_path.string()};
    PFL_EXPECT(session.open_capture(fixture_path(relative_path)));
    PFL_EXPECT(session.summary().packet_count == 1U);
    const auto rows = session.list_flows();
    PFL_REQUIRE(rows.size() == 1U);
    PFL_EXPECT(rows[0].family == expected_family);
    PFL_EXPECT(rows[0].protocol_text == expected_protocol);
    PFL_EXPECT(rows[0].packet_count == 1U);
    PFL_EXPECT(session.unrecognized_packet_count() == 0U);
    PFL_REQUIRE(rows[0].protocol_path_id != kInvalidProtocolPathId);
    if (!expected_protocol_path.empty()) {
        PFL_EXPECT(require_flow_protocol_path_text(session, rows[0]) == expected_protocol_path);
    }
    PFL_EXPECT(session.state().protocol_path_registry.size() == 1U);

    const auto packet = require_packet(session, 0U);
    const auto details = session.read_packet_details(packet);
    PFL_REQUIRE(details.has_value());
    PFL_EXPECT(details->has_ethernet);
    PFL_EXPECT(details->has_pbb);
    PFL_EXPECT(details->has_inner_ethernet);
    PFL_EXPECT(!details->inner_ethernet.header_truncated);
    PFL_EXPECT(details->encapsulating_vlan_tags.size() == expected_outer_vlan_count);
    PFL_EXPECT(details->vlan_tags.size() == expected_inner_vlan_count);
    PFL_EXPECT(details->has_snap == expect_snap);

    if (expected_family == FlowAddressFamily::ipv4) {
        PFL_EXPECT(details->has_ipv4);
        PFL_EXPECT(!details->has_ipv6);
        PFL_EXPECT(session_detail::format_ipv4_address(details->ipv4.src_addr) == expected_address_a);
        PFL_EXPECT(session_detail::format_ipv4_address(details->ipv4.dst_addr) == expected_address_b);
    } else {
        PFL_EXPECT(!details->has_ipv4);
        PFL_EXPECT(details->has_ipv6);
        PFL_EXPECT(session_detail::format_ipv6_address(details->ipv6.src_addr) == expected_address_a);
        PFL_EXPECT(session_detail::format_ipv6_address(details->ipv6.dst_addr) == expected_address_b);
    }

    if (expected_protocol == "TCP") {
        PFL_EXPECT(details->has_tcp);
        PFL_EXPECT(!details->has_udp);
        PFL_EXPECT(details->tcp.src_port == expected_port_a);
        PFL_EXPECT(details->tcp.dst_port == expected_port_b);
    } else {
        PFL_EXPECT(!details->has_tcp);
        PFL_EXPECT(details->has_udp);
        PFL_EXPECT(details->udp.src_port == expected_port_a);
        PFL_EXPECT(details->udp.dst_port == expected_port_b);
    }

    const bool forward_match =
        rows[0].address_a == expected_address_a &&
        rows[0].port_a == expected_port_a &&
        rows[0].address_b == expected_address_b &&
        rows[0].port_b == expected_port_b;
    const bool reverse_match =
        rows[0].address_a == expected_address_b &&
        rows[0].port_a == expected_port_b &&
        rows[0].address_b == expected_address_a &&
        rows[0].port_b == expected_port_a;
    PFL_EXPECT(forward_match || reverse_match);

    if (!expected_transport_payload.empty()) {
        PFL_EXPECT(packet.payload_length == expected_transport_payload.size());
        const auto payload_dump = session.read_packet_payload_hex_dump(packet);
        expect_hex_dump_contains_payload_text(payload_dump, expected_transport_payload);
    }

    const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet);
    expect_layer_prefix(summary_layers, expected_layer_prefix);
    PFL_EXPECT(count_layers(summary_layers, "vlan") == expected_outer_vlan_count + expected_inner_vlan_count);

    const auto* pbb_layer = find_layer(summary_layers, "pbb");
    PFL_REQUIRE(pbb_layer != nullptr);
    if (pbb_layer == nullptr) {
        return;
    }
    expect_pbb_metadata(*details, *pbb_layer, expected_pcp, expected_dei, expected_nca, expected_isid);

    const auto* inner_ethernet_layer = find_layer(summary_layers, "ethernet-inner");
    PFL_REQUIRE(inner_ethernet_layer != nullptr);
    if (inner_ethernet_layer != nullptr) {
        PFL_EXPECT(layer_title_contains(*inner_ethernet_layer, "Src: 02:00:00:00:61:01"));
        PFL_EXPECT(layer_title_contains(*inner_ethernet_layer, "Dst: 02:00:00:00:61:02"));
    }
}

void expect_single_pbb_arp_packet(CaptureSession& session, const std::filesystem::path& relative_path) {
    const ScopedTestContext fixture_context {"fixture=" + relative_path.string()};
    PFL_EXPECT(session.open_capture(fixture_path(relative_path)));
    PFL_EXPECT(session.summary().packet_count == 1U);
    PFL_EXPECT(session.summary().flow_count == 1U);
    PFL_EXPECT(session.unrecognized_packet_count() == 0U);

    const auto rows = session.list_flows();
    PFL_REQUIRE(rows.size() == 1U);
    PFL_EXPECT(rows[0].packet_count == 1U);
    PFL_REQUIRE(rows[0].protocol_path_id != kInvalidProtocolPathId);
    PFL_EXPECT(
        require_flow_protocol_path_text(session, rows[0]) ==
        "EthernetII -> PBB(isid=0x123456) -> EthernetII"
    );
    PFL_EXPECT(session.state().protocol_path_registry.size() == 1U);

    const auto packet = require_packet(session, 0U);
    const auto details = session.read_packet_details(packet);
    PFL_REQUIRE(details.has_value());
    PFL_EXPECT(details->has_pbb);
    PFL_EXPECT(details->has_inner_ethernet);
    PFL_EXPECT(details->has_arp);
    PFL_EXPECT(!details->has_tcp);
    PFL_EXPECT(!details->has_udp);
    PFL_EXPECT(details->encapsulating_vlan_tags.empty());
    PFL_EXPECT(details->vlan_tags.empty());

    const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet);
    expect_layer_prefix(summary_layers, {"frame", "ethernet", "pbb", "ethernet-inner", "arp"});
    const auto* pbb_layer = find_layer(summary_layers, "pbb");
    PFL_REQUIRE(pbb_layer != nullptr);
    if (pbb_layer == nullptr) {
        return;
    }
    expect_pbb_metadata(*details, *pbb_layer, 0U, false, false, 0x123456U);
}

void expect_single_unrecognized_pbb_packet(
    CaptureSession& session,
    const std::filesystem::path& relative_path,
    const std::string& expected_reason
) {
    const ScopedTestContext fixture_context {"fixture=" + relative_path.string()};
    PFL_EXPECT(session.open_capture(fixture_path(relative_path)));
    PFL_EXPECT(session.list_flows().empty());
    PFL_EXPECT(session.unrecognized_packet_count() == 1U);
    PFL_EXPECT(session.state().protocol_path_registry.size() == 0U);
    const auto rows = session.list_unrecognized_packets(0U, 30U);
    PFL_REQUIRE(rows.size() == 1U);
    PFL_EXPECT(rows[0].row_number == 1U);
    PFL_EXPECT(rows[0].packet_index == 0U);
    PFL_EXPECT(rows[0].reason_text == expected_reason);
}

}  // namespace

void run_pbb_pcap_fixture_tests() {
    {
        CaptureSession session {};
        expect_single_ip_pbb_flow(
            session,
            "parsing/pbb/01_pbb_ipv4_tcp.pcap",
            FlowAddressFamily::ipv4,
            "TCP",
            "192.0.2.60",
            49190U,
            "198.51.100.60",
            443U,
            {"frame", "ethernet", "pbb", "ethernet-inner", "ipv4", "tcp"},
            0U,
            0U,
            false,
            0U,
            false,
            false,
            0x123456U,
            "EthernetII -> PBB(isid=0x123456) -> EthernetII -> IPv4 -> TCP",
            "pbb-ipv4-tcp"
        );
    }

    {
        CaptureSession session {};
        expect_single_ip_pbb_flow(
            session,
            "parsing/pbb/02_pbb_ipv4_udp.pcap",
            FlowAddressFamily::ipv4,
            "UDP",
            "192.0.2.60",
            53570U,
            "198.51.100.60",
            443U,
            {"frame", "ethernet", "pbb", "ethernet-inner", "ipv4", "udp"},
            0U,
            0U,
            false,
            0U,
            false,
            false,
            0x123456U,
            "EthernetII -> PBB(isid=0x123456) -> EthernetII -> IPv4 -> UDP",
            "pbb-ipv4-udp"
        );
    }

    {
        CaptureSession session {};
        expect_single_ip_pbb_flow(
            session,
            "parsing/pbb/03_pbb_ipv6_tcp.pcap",
            FlowAddressFamily::ipv6,
            "TCP",
            "2001:0db8:0060:0000:0000:0000:0000:0010",
            49190U,
            "2001:0db8:0060:0000:0000:0000:0000:0020",
            443U,
            {"frame", "ethernet", "pbb", "ethernet-inner", "ipv6", "tcp"},
            0U,
            0U,
            false,
            0U,
            false,
            false,
            0x123456U,
            "EthernetII -> PBB(isid=0x123456) -> EthernetII -> IPv6 -> TCP",
            "pbb-ipv6-tcp"
        );
    }

    {
        CaptureSession session {};
        expect_single_ip_pbb_flow(
            session,
            "parsing/pbb/04_pbb_ipv6_udp.pcap",
            FlowAddressFamily::ipv6,
            "UDP",
            "2001:0db8:0060:0000:0000:0000:0000:0010",
            53570U,
            "2001:0db8:0060:0000:0000:0000:0000:0020",
            443U,
            {"frame", "ethernet", "pbb", "ethernet-inner", "ipv6", "udp"},
            0U,
            0U,
            false,
            0U,
            false,
            false,
            0x123456U,
            "EthernetII -> PBB(isid=0x123456) -> EthernetII -> IPv6 -> UDP",
            "pbb-ipv6-udp"
        );
    }

    {
        CaptureSession session {};
        expect_single_pbb_arp_packet(session, "parsing/pbb/05_pbb_arp.pcap");
    }

    {
        CaptureSession session {};
        expect_single_ip_pbb_flow(
            session,
            "parsing/pbb/06_pbb_inner_vlan_ipv4_tcp.pcap",
            FlowAddressFamily::ipv4,
            "TCP",
            "192.0.2.60",
            49190U,
            "198.51.100.60",
            443U,
            {"frame", "ethernet", "pbb", "ethernet-inner", "vlan", "ipv4", "tcp"},
            0U,
            1U,
            false,
            0U,
            false,
            false,
            0x123456U,
            "EthernetII -> PBB(isid=0x123456) -> EthernetII -> VLAN(vid=610) -> IPv4 -> TCP",
            "pbb-ipv4-tcp"
        );
    }

    {
        CaptureSession session {};
        expect_single_ip_pbb_flow(
            session,
            "parsing/pbb/07_pbb_inner_qinq_ipv4_udp.pcap",
            FlowAddressFamily::ipv4,
            "UDP",
            "192.0.2.60",
            53570U,
            "198.51.100.60",
            443U,
            {"frame", "ethernet", "pbb", "ethernet-inner", "vlan", "vlan", "ipv4", "udp"},
            0U,
            2U,
            false,
            0U,
            false,
            false,
            0x123456U,
            "EthernetII -> PBB(isid=0x123456) -> EthernetII -> VLAN(vid=620) -> VLAN(vid=610) -> IPv4 -> UDP",
            "pbb-ipv4-udp"
        );
    }

    {
        CaptureSession session {};
        expect_single_ip_pbb_flow(
            session,
            "parsing/pbb/08_pbb_inner_llc_snap_ipv4_udp.pcap",
            FlowAddressFamily::ipv4,
            "UDP",
            "192.0.2.60",
            53570U,
            "198.51.100.60",
            443U,
            {"frame", "ethernet", "pbb", "ethernet-inner", "llc", "snap", "ipv4", "udp"},
            0U,
            0U,
            true,
            0U,
            false,
            false,
            0x123456U,
            "EthernetII -> PBB(isid=0x123456) -> IEEE 802.3 -> LLC/SNAP -> IPv4 -> UDP",
            "pbb-ipv4-udp"
        );

        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->has_inner_ethernet);
        PFL_EXPECT(details->inner_ethernet.uses_length_field);
        PFL_EXPECT(details->inner_ethernet.ether_type == 48U);

        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet);
        const auto* inner_ethernet_layer = find_layer(summary_layers, "ethernet-inner");
        PFL_REQUIRE(inner_ethernet_layer != nullptr);
        if (inner_ethernet_layer != nullptr) {
            PFL_EXPECT(layer_title_contains(*inner_ethernet_layer, "Inner IEEE 802.3"));
            PFL_EXPECT(layer_title_contains(*inner_ethernet_layer, "Src: 02:00:00:00:61:01"));
            PFL_EXPECT(layer_title_contains(*inner_ethernet_layer, "Dst: 02:00:00:00:61:02"));
            PFL_EXPECT(layer_has_field_containing(*inner_ethernet_layer, "Length", "48 bytes"));
        }
    }

    {
        CaptureSession session {};
        expect_single_ip_pbb_flow(
            session,
            "parsing/pbb/09_pbb_outer_btag_ipv4_udp.pcap",
            FlowAddressFamily::ipv4,
            "UDP",
            "192.0.2.60",
            53570U,
            "198.51.100.60",
            443U,
            {"frame", "ethernet", "vlan", "pbb", "ethernet-inner", "ipv4", "udp"},
            1U,
            0U,
            false,
            0U,
            false,
            false,
            0x123456U,
            "EthernetII -> VLAN(vid=600) -> PBB(isid=0x123456) -> EthernetII -> IPv4 -> UDP",
            "pbb-ipv4-udp"
        );

        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->encapsulating_vlan_tags.size() == 1U);
        PFL_EXPECT(details->vlan_tags.empty());
        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet);
        const auto* outer_vlan_layer = find_layer(summary_layers, "vlan");
        PFL_REQUIRE(outer_vlan_layer != nullptr);
        if (outer_vlan_layer == nullptr) {
            return;
        }
        PFL_EXPECT(layer_title_contains(*outer_vlan_layer, "802.1ad B-TAG"));
        PFL_EXPECT(layer_has_field_containing(*outer_vlan_layer, "Encapsulated EtherType", "PBB I-TAG"));
        const auto* inner_ethernet_layer = find_layer(summary_layers, "ethernet-inner");
        PFL_REQUIRE(inner_ethernet_layer != nullptr);
        if (inner_ethernet_layer != nullptr) {
            PFL_EXPECT(layer_title_contains(*inner_ethernet_layer, "Src: 02:00:00:00:61:01"));
            PFL_EXPECT(layer_title_contains(*inner_ethernet_layer, "Dst: 02:00:00:00:61:02"));
        }
    }

    {
        CaptureSession session {};
        expect_single_ip_pbb_flow(
            session,
            "parsing/pbb/10_pbb_outer_btag_inner_vlan_ipv4_tcp.pcap",
            FlowAddressFamily::ipv4,
            "TCP",
            "192.0.2.60",
            49190U,
            "198.51.100.60",
            443U,
            {"frame", "ethernet", "vlan", "pbb", "ethernet-inner", "vlan", "ipv4", "tcp"},
            1U,
            1U,
            false,
            0U,
            false,
            false,
            0x123456U,
            "EthernetII -> VLAN(vid=600) -> PBB(isid=0x123456) -> EthernetII -> VLAN(vid=610) -> IPv4 -> TCP",
            "pbb-ipv4-tcp"
        );

        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->encapsulating_vlan_tags.size() == 1U);
        PFL_EXPECT(details->vlan_tags.size() == 1U);
    }

    {
        CaptureSession session {};
        expect_single_unrecognized_pbb_packet(
            session,
            "parsing/pbb/11_pbb_unknown_inner_ethertype.pcap",
            "Unknown PBB inner EtherType"
        );

        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->has_pbb);
        PFL_EXPECT(details->has_inner_ethernet);
        PFL_EXPECT(details->has_unknown_inner_ethernet_payload);
        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet);
        expect_layer_prefix(summary_layers, {"frame", "ethernet", "pbb", "ethernet-inner", "inner-payload"});
        const auto* pbb_layer = find_layer(summary_layers, "pbb");
        PFL_REQUIRE(pbb_layer != nullptr);
        if (pbb_layer != nullptr) {
            PFL_EXPECT(layer_has_field_containing(*pbb_layer, "Priority", "0"));
            PFL_EXPECT(layer_has_field_containing(*pbb_layer, "Drop Eligible", "0"));
            PFL_EXPECT(layer_has_field_containing(*pbb_layer, "NCA", "0"));
            PFL_EXPECT(layer_has_field_containing(*pbb_layer, "I-SID", "0x123456"));
            PFL_EXPECT(layer_has_field_containing(*pbb_layer, "I-SID", "1193046"));
        }
        const auto protocol_text = session.read_packet_protocol_details_text(packet);
        PFL_EXPECT(protocol_text.find("Protocol: PBB I-TAG") != std::string::npos);
        PFL_EXPECT(protocol_text.find("Priority: 0") != std::string::npos);
        PFL_EXPECT(protocol_text.find("Drop Eligible: 0") != std::string::npos);
        PFL_EXPECT(protocol_text.find("NCA: 0") != std::string::npos);
        PFL_EXPECT(protocol_text.find("I-SID: 0x123456 (1193046)") != std::string::npos);
        PFL_EXPECT(protocol_text.find("Inner EtherType:") != std::string::npos);
    }

    {
        CaptureSession session {};
        expect_single_unrecognized_pbb_packet(
            session,
            "parsing/pbb/12_pbb_truncated_itag.pcap",
            "PBB I-TAG truncated"
        );

        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->has_pbb);
        PFL_EXPECT(details->pbb.itag_truncated);
        PFL_EXPECT(!details->has_inner_ethernet);
        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet);
        const auto* pbb_layer = find_layer(summary_layers, "pbb");
        PFL_REQUIRE(pbb_layer != nullptr);
        if (pbb_layer == nullptr) {
            return;
        }
        PFL_EXPECT(details->pbb.available_bytes == 2U);
        PFL_EXPECT(layer_has_field_containing(*pbb_layer, "Priority", "0"));
        PFL_EXPECT(layer_has_field_containing(*pbb_layer, "Drop Eligible", "1"));
        PFL_EXPECT(layer_has_field_containing(*pbb_layer, "NCA", "0"));
        PFL_EXPECT(layer_has_field_containing(*pbb_layer, "Reserved 1", "0"));
        PFL_EXPECT(layer_has_field_containing(*pbb_layer, "Reserved 2", "2"));
        PFL_EXPECT(layer_has_field_containing(*pbb_layer, "Available Bytes", "2 of 4"));
        PFL_EXPECT(!layer_has_field_containing(*pbb_layer, "I-SID", "0x"));
        PFL_EXPECT(layer_has_field_containing(*pbb_layer, "Warning", "PBB I-TAG is truncated"));
        const auto protocol_text = session.read_packet_protocol_details_text(packet);
        PFL_EXPECT(protocol_text.find("Protocol: PBB I-TAG") != std::string::npos);
        PFL_EXPECT(protocol_text.find("Priority: 0") != std::string::npos);
        PFL_EXPECT(protocol_text.find("Drop Eligible: 1") != std::string::npos);
        PFL_EXPECT(protocol_text.find("NCA: 0") != std::string::npos);
        PFL_EXPECT(protocol_text.find("Reserved 1: 0") != std::string::npos);
        PFL_EXPECT(protocol_text.find("Reserved 2: 2") != std::string::npos);
        PFL_EXPECT(protocol_text.find("Available Bytes: 2 of 4") != std::string::npos);
        PFL_EXPECT(protocol_text.find("Warning: PBB I-TAG is truncated.") != std::string::npos);
    }

    {
        CaptureSession session {};
        expect_single_unrecognized_pbb_packet(
            session,
            "parsing/pbb/13_pbb_truncated_inner_ethernet.pcap",
            "Inner Ethernet header truncated"
        );

        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->has_pbb);
        PFL_EXPECT(details->has_inner_ethernet);
        PFL_EXPECT(details->inner_ethernet.header_truncated);
        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet);
        expect_layer_prefix(summary_layers, {"frame", "ethernet", "pbb", "ethernet-inner"});
        const auto* inner_ethernet_layer = find_layer(summary_layers, "ethernet-inner");
        PFL_REQUIRE(inner_ethernet_layer != nullptr);
        if (inner_ethernet_layer == nullptr) {
            return;
        }
        PFL_EXPECT(!layer_title_contains(*inner_ethernet_layer, "Src:"));
        PFL_EXPECT(!layer_title_contains(*inner_ethernet_layer, "Dst:"));
        PFL_EXPECT(layer_has_field_containing(*inner_ethernet_layer, "Warning", "Inner Ethernet header is truncated"));
        const auto protocol_text = session.read_packet_protocol_details_text(packet);
        PFL_EXPECT(protocol_text.find("Protocol: PBB I-TAG") != std::string::npos);
        PFL_EXPECT(protocol_text.find("Priority: 0") != std::string::npos);
        PFL_EXPECT(protocol_text.find("Drop Eligible: 0") != std::string::npos);
        PFL_EXPECT(protocol_text.find("NCA: 0") != std::string::npos);
        PFL_EXPECT(protocol_text.find("I-SID: 0x123456 (1193046)") != std::string::npos);
        PFL_EXPECT(protocol_text.find("Warning: Inner Ethernet header is truncated.") != std::string::npos);
    }

    {
        CaptureSession session {};
        expect_single_unrecognized_pbb_packet(
            session,
            "parsing/pbb/14_pbb_truncated_inner_ipv4.pcap",
            "IPv4 header truncated"
        );

        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->has_pbb);
        PFL_EXPECT(details->has_inner_ethernet);
        PFL_EXPECT(details->has_ipv4);
        PFL_EXPECT(details->ipv4.header_truncated);
        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet);
        expect_layer_prefix(summary_layers, {"warnings", "frame", "ethernet", "pbb", "ethernet-inner", "ipv4"});
        const auto* ipv4_layer = find_layer(summary_layers, "ipv4");
        PFL_REQUIRE(ipv4_layer != nullptr);
        if (ipv4_layer == nullptr) {
            return;
        }
        PFL_EXPECT(layer_has_field_containing(*ipv4_layer, "Version", "4"));
        PFL_EXPECT(layer_has_field_containing(*ipv4_layer, "Internet Header Length", "20 bytes"));
        PFL_EXPECT(layer_has_field_containing(*ipv4_layer, "Warning", "IPv4 header is truncated"));
    }

    {
        CaptureSession session {};
        expect_single_ip_pbb_flow(
            session,
            "parsing/pbb/15_pbb_metadata_nondefault_itag.pcap",
            FlowAddressFamily::ipv4,
            "UDP",
            "192.0.2.60",
            53570U,
            "198.51.100.60",
            443U,
            {"frame", "ethernet", "pbb", "ethernet-inner", "ipv4", "udp"},
            0U,
            0U,
            false,
            5U,
            true,
            true,
            0x654321U,
            "EthernetII -> PBB(isid=0x654321) -> EthernetII -> IPv4 -> UDP",
            "pbb-ipv4-udp"
        );
    }

    {
        CaptureSession session {};
        const ScopedTestContext fixture_context {"fixture=parsing/pbb/16_pbb_same_isid_same_inner_tuple_metadata_variation.pcap"};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/pbb/16_pbb_same_isid_same_inner_tuple_metadata_variation.pcap")));
        PFL_EXPECT(session.summary().packet_count == 2U);
        PFL_EXPECT(session.summary().flow_count == 1U);
        PFL_EXPECT(session.unrecognized_packet_count() == 0U);
        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 1U);
        PFL_EXPECT(rows[0].packet_count == 2U);
        PFL_EXPECT(require_flow_protocol_path_text(session, rows[0]) == "EthernetII -> PBB(isid=0x123456) -> EthernetII -> IPv4 -> UDP");
        PFL_EXPECT(session.state().protocol_path_registry.size() == 1U);

        const auto first_packet = require_packet(session, 0U);
        const auto second_packet = require_packet(session, 1U);
        const auto first_details = session.read_packet_details(first_packet);
        const auto second_details = session.read_packet_details(second_packet);
        PFL_REQUIRE(first_details.has_value());
        PFL_REQUIRE(second_details.has_value());
        PFL_EXPECT(first_details->pbb.isid == 0x123456U);
        PFL_EXPECT(second_details->pbb.isid == 0x123456U);
        PFL_EXPECT(first_details->pbb.pcp == 0U);
        PFL_EXPECT(!first_details->pbb.dei);
        PFL_EXPECT(!first_details->pbb.nca);
        PFL_EXPECT(second_details->pbb.pcp == 7U);
        PFL_EXPECT(second_details->pbb.dei);
        PFL_EXPECT(second_details->pbb.nca);
        PFL_EXPECT(second_details->pbb.reserved == 5U);
    }

    {
        CaptureSession session {};
        const ScopedTestContext fixture_context {"fixture=parsing/pbb/17_pbb_different_isid_same_inner_tuple.pcap"};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/pbb/17_pbb_different_isid_same_inner_tuple.pcap")));
        PFL_EXPECT(session.summary().packet_count == 2U);
        PFL_EXPECT(session.summary().flow_count == 2U);
        PFL_EXPECT(session.unrecognized_packet_count() == 0U);
        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 2U);
        PFL_EXPECT(rows[0].protocol_path_id != rows[1].protocol_path_id);
        const auto first_path = require_flow_protocol_path_text(session, rows[0]);
        const auto second_path = require_flow_protocol_path_text(session, rows[1]);
        PFL_EXPECT(
            (first_path == "EthernetII -> PBB(isid=0x123456) -> EthernetII -> IPv4 -> UDP" &&
             second_path == "EthernetII -> PBB(isid=0x123457) -> EthernetII -> IPv4 -> UDP") ||
            (first_path == "EthernetII -> PBB(isid=0x123457) -> EthernetII -> IPv4 -> UDP" &&
             second_path == "EthernetII -> PBB(isid=0x123456) -> EthernetII -> IPv4 -> UDP")
        );
        PFL_EXPECT(session.state().protocol_path_registry.size() == 2U);
    }

    {
        CaptureSession session {};
        expect_single_ip_pbb_flow(
            session,
            "parsing/pbb/18_pbb_zero_isid_ipv4_udp.pcap",
            FlowAddressFamily::ipv4,
            "UDP",
            "192.0.2.60",
            53570U,
            "198.51.100.60",
            443U,
            {"frame", "ethernet", "pbb", "ethernet-inner", "ipv4", "udp"},
            0U,
            0U,
            false,
            0U,
            false,
            false,
            0x000000U,
            "EthernetII -> PBB(isid=0x000000) -> EthernetII -> IPv4 -> UDP",
            "pbb-contract-udp"
        );
    }

    {
        CaptureSession session {};
        expect_single_ip_pbb_flow(
            session,
            "parsing/pbb/19_pbb_max_isid_ipv4_udp.pcap",
            FlowAddressFamily::ipv4,
            "UDP",
            "192.0.2.60",
            53570U,
            "198.51.100.60",
            443U,
            {"frame", "ethernet", "pbb", "ethernet-inner", "ipv4", "udp"},
            0U,
            0U,
            false,
            0U,
            false,
            false,
            0xFFFFFFU,
            "EthernetII -> PBB(isid=0xffffff) -> EthernetII -> IPv4 -> UDP",
            "pbb-contract-udp"
        );
    }

    {
        CaptureSession session {};
        expect_single_ip_pbb_flow(
            session,
            "parsing/pbb/20_pbb_outer_qinq_ipv6_udp.pcap",
            FlowAddressFamily::ipv6,
            "UDP",
            "2001:0db8:0060:0000:0000:0000:0000:0010",
            53570U,
            "2001:0db8:0060:0000:0000:0000:0000:0020",
            443U,
            {"frame", "ethernet", "vlan", "vlan", "pbb", "ethernet-inner", "ipv6", "udp"},
            2U,
            0U,
            false,
            0U,
            false,
            false,
            0x123456U,
            "EthernetII -> VLAN(vid=701) -> VLAN(vid=702) -> PBB(isid=0x123456) -> EthernetII -> IPv6 -> UDP",
            "pbb-contract-ipv6"
        );
    }

    {
        CaptureSession session {};
        expect_single_ip_pbb_flow(
            session,
            "parsing/pbb/21_pbb_outer_legacy_vlan_ipv4_udp.pcap",
            FlowAddressFamily::ipv4,
            "UDP",
            "192.0.2.60",
            53570U,
            "198.51.100.60",
            443U,
            {"frame", "ethernet", "vlan", "pbb", "ethernet-inner", "ipv4", "udp"},
            1U,
            0U,
            false,
            0U,
            false,
            false,
            0x123456U,
            "EthernetII -> VLAN(vid=703) -> PBB(isid=0x123456) -> EthernetII -> IPv4 -> UDP",
            "pbb-contract-udp"
        );
    }

    {
        CaptureSession session {};
        expect_single_unrecognized_pbb_packet(
            session,
            "parsing/pbb/22_pbb_capture_truncated_inner_ipv4_caplen_lt_origlen.pcap",
            "IPv4 header truncated"
        );

        const auto packet = require_packet(session, 0U);
        PFL_EXPECT(packet.captured_length < packet.original_length);
        const auto details = session.read_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->has_pbb);
        PFL_EXPECT(details->has_inner_ethernet);
        PFL_EXPECT(details->has_ipv4);
        PFL_EXPECT(details->ipv4.header_truncated);
    }

    {
        CaptureSession session {};
        expect_single_unrecognized_pbb_packet(
            session,
            "parsing/pbb/23_pbb_complete_itag_no_inner_ethernet.pcap",
            "Inner Ethernet header truncated"
        );

        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->has_pbb);
        PFL_EXPECT(details->has_inner_ethernet);
        PFL_EXPECT(details->inner_ethernet.header_truncated);
        PFL_EXPECT(details->inner_ethernet.available_header_bytes == 0U);
        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet);
        expect_layer_prefix(summary_layers, {"frame", "ethernet", "pbb", "ethernet-inner"});
    }

    {
        CaptureSession session {};
        expect_single_unrecognized_pbb_packet(
            session,
            "parsing/pbb/24_pbb_truncated_inner_ipv6.pcap",
            "IPv6 header truncated"
        );

        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->has_pbb);
        PFL_EXPECT(details->has_inner_ethernet);
        PFL_EXPECT(!details->has_ipv6);
        PFL_EXPECT(!details->has_udp);
        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet);
        expect_layer_prefix(summary_layers, {"frame", "ethernet", "pbb", "ethernet-inner"});
        PFL_EXPECT(find_layer(summary_layers, "ipv6") == nullptr);
        PFL_EXPECT(find_layer(summary_layers, "udp") == nullptr);
    }

    {
        CaptureSession session {};
        const ScopedTestContext fixture_context {"fixture=parsing/pbb/25_pbb_truncated_inner_arp.pcap"};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/pbb/25_pbb_truncated_inner_arp.pcap")));

        const auto rows = session.list_unrecognized_packets(0U, 30U);
        if (!rows.empty()) {
            PFL_EXPECT(rows[0].reason_text == "ARP header truncated");
        }

        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->has_pbb);
        PFL_EXPECT(details->has_inner_ethernet);
        PFL_EXPECT(details->has_arp);
        PFL_EXPECT(!details->arp.fixed_header_truncated);
        PFL_EXPECT(details->arp.address_section_truncated);
        PFL_EXPECT(details->arp.hardware_type == 1U);
        PFL_EXPECT(details->arp.protocol_type == 0x0800U);
        PFL_EXPECT(!details->has_ipv4);
        PFL_EXPECT(!details->has_ipv6);

        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet);
        expect_layer_prefix(summary_layers, {"frame", "ethernet", "pbb", "ethernet-inner"});
        PFL_EXPECT(find_layer(summary_layers, "arp") != nullptr);
    }

    {
        CaptureSession session {};
        expect_single_unrecognized_pbb_packet(
            session,
            "parsing/pbb/26_pbb_inner_pppoe_session_unsupported.pcap",
            "Unsupported or malformed packet"
        );

        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->has_pbb);
        PFL_EXPECT(details->has_inner_ethernet);
        PFL_EXPECT(!details->has_ipv4);
        PFL_EXPECT(!details->has_ipv6);
        PFL_EXPECT(!details->has_arp);
        PFL_EXPECT(!details->has_tcp);
        PFL_EXPECT(!details->has_udp);
    }

    {
        CaptureSession session {};
        expect_single_ip_pbb_flow(
            session,
            "parsing/pbb/27_pbb_extra_captured_tail_ipv4_udp.pcap",
            FlowAddressFamily::ipv4,
            "UDP",
            "192.0.2.60",
            53570U,
            "198.51.100.60",
            443U,
            {"frame", "ethernet", "pbb", "ethernet-inner", "ipv4", "udp"},
            0U,
            0U,
            false,
            0U,
            false,
            false,
            0x123456U,
            "EthernetII -> PBB(isid=0x123456) -> EthernetII -> IPv4 -> UDP",
            "pbb-tail-ok"
        );

        const auto packet = require_packet(session, 0U);
        PFL_EXPECT(packet.captured_length == packet.original_length);
        PFL_EXPECT(packet.original_length == 77U);
        const auto payload_dump = session.read_packet_payload_hex_dump(packet);
        PFL_EXPECT(payload_dump.find("de ad be ef a5 5a") == std::string::npos);
    }
}

}  // namespace pfl::tests
