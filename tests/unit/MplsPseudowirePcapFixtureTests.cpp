#include <algorithm>
#include <array>
#include <filesystem>
#include <initializer_list>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "PcapTestUtils.h"
#include "TestSupport.h"
#include "app/session/CaptureSession.h"
#include "app/session/FlowRows.h"
#include "app/session/SessionFormatting.h"
#include "core/domain/ProtocolPath.h"
#include "core/services/PacketPayloadService.h"

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

std::string require_protocol_path_text(const CaptureSession& session, const ProtocolPathId id) {
    PFL_REQUIRE(id != kInvalidProtocolPathId);
    const auto* path = session.state().protocol_path_registry.find(id);
    PFL_REQUIRE(path != nullptr);
    return format_protocol_path(*path);
}

std::string require_flow_protocol_path_text(const CaptureSession& session, const FlowRow& row) {
    return require_protocol_path_text(session, row.protocol_path_id);
}

struct MplsLabelSpec {
    std::uint32_t label {0};
    std::uint8_t traffic_class {0};
    bool bottom_of_stack {false};
    std::uint8_t ttl {64};
};

std::vector<std::uint8_t> make_ethernet_frame_with_payload(
    const std::uint16_t ether_type,
    const std::vector<std::uint8_t>& payload
) {
    std::vector<std::uint8_t> bytes {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
    };
    append_be16(bytes, ether_type);
    bytes.insert(bytes.end(), payload.begin(), payload.end());
    return bytes;
}

void append_mpls_label(
    std::vector<std::uint8_t>& bytes,
    const std::uint32_t label,
    const bool bottom_of_stack,
    const std::uint8_t ttl = 64U,
    const std::uint8_t traffic_class = 0U
) {
    const auto entry = (label << 12U) |
        (static_cast<std::uint32_t>(traffic_class & 0x7U) << 9U) |
        (static_cast<std::uint32_t>(bottom_of_stack ? 1U : 0U) << 8U) |
        static_cast<std::uint32_t>(ttl);
    append_be32(bytes, entry);
}

std::vector<std::uint8_t> make_inner_ethernet_frame_with_payload(
    const std::array<std::uint8_t, 6>& dst_mac,
    const std::array<std::uint8_t, 6>& src_mac,
    const std::uint16_t ether_type,
    const std::vector<std::uint8_t>& payload
) {
    std::vector<std::uint8_t> bytes {};
    bytes.insert(bytes.end(), dst_mac.begin(), dst_mac.end());
    bytes.insert(bytes.end(), src_mac.begin(), src_mac.end());
    append_be16(bytes, ether_type);
    bytes.insert(bytes.end(), payload.begin(), payload.end());
    return bytes;
}

std::vector<std::uint8_t> wrap_mpls_pseudowire_payload(
    const std::vector<MplsLabelSpec>& labels,
    const std::vector<std::uint8_t>& inner_payload,
    const std::optional<std::pair<std::uint16_t, std::uint16_t>>& control_word = std::nullopt
) {
    std::vector<std::uint8_t> bytes {};
    for (const auto& label : labels) {
        append_mpls_label(bytes, label.label, label.bottom_of_stack, label.ttl, label.traffic_class);
    }
    if (control_word.has_value()) {
        append_be16(bytes, control_word->first);
        append_be16(bytes, control_word->second);
    }
    bytes.insert(bytes.end(), inner_payload.begin(), inner_payload.end());
    return bytes;
}

std::vector<std::uint8_t> make_mpls_pseudowire_frame(
    const std::vector<MplsLabelSpec>& labels,
    const std::vector<std::uint8_t>& inner_payload,
    const std::optional<std::pair<std::uint16_t, std::uint16_t>>& control_word = std::nullopt,
    const std::vector<std::pair<std::uint16_t, std::uint16_t>>& outer_vlan_tags = {}
) {
    auto frame = make_ethernet_frame_with_payload(
        0x8847U,
        wrap_mpls_pseudowire_payload(labels, inner_payload, control_word)
    );
    if (!outer_vlan_tags.empty()) {
        frame = add_vlan_tags(frame, outer_vlan_tags);
    }
    return frame;
}

std::vector<std::uint8_t> make_default_inner_ipv4_udp_frame() {
    const auto packet = make_ethernet_ipv4_udp_packet(
        ipv4(192, 0, 2, 50),
        ipv4(198, 51, 100, 50),
        53560U,
        443U
    );
    return make_inner_ethernet_frame_with_payload(
        {0x02, 0x00, 0x00, 0x00, 0x51, 0x02},
        {0x02, 0x00, 0x00, 0x00, 0x51, 0x01},
        0x0800U,
        std::vector<std::uint8_t>(packet.begin() + 14, packet.end())
    );
}

void expect_single_ip_flow(
    CaptureSession& session,
    const std::filesystem::path& relative_path,
    const FlowAddressFamily expected_family,
    const std::string& expected_protocol,
    const std::string& expected_address_a,
    const std::uint16_t expected_port_a,
    const std::string& expected_address_b,
    const std::uint16_t expected_port_b,
    std::initializer_list<const char*> expected_layer_prefix,
    const bool expect_control_word,
    const std::size_t expected_vlan_count = 0U,
    const bool expect_snap = false,
    const bool expect_payload_extraction = true
) {
    PFL_EXPECT(session.open_capture(fixture_path(relative_path)));
    const auto rows = session.list_flows();
    PFL_REQUIRE(rows.size() == 1U);
    PFL_EXPECT(rows[0].family == expected_family);
    PFL_EXPECT(rows[0].protocol_text == expected_protocol);
    PFL_EXPECT(rows[0].packet_count == 1U);
    PFL_EXPECT(session.unrecognized_packet_count() == 0U);

    const auto packet = require_packet(session, 0U);
    const auto details = session.read_packet_details(packet);
    PFL_REQUIRE(details.has_value());
    PFL_EXPECT(details->has_ethernet);
    PFL_EXPECT(details->has_mpls);
    PFL_EXPECT(details->mpls_labels.size() == 2U);
    PFL_EXPECT(details->has_inner_ethernet);
    PFL_EXPECT(!details->inner_ethernet.header_truncated);
    PFL_EXPECT(details->has_mpls_pseudowire_control_word == expect_control_word);
    PFL_EXPECT(details->vlan_tags.size() == expected_vlan_count);
    PFL_EXPECT(details->has_snap == expect_snap);

    if (expected_family == FlowAddressFamily::ipv4) {
        PFL_EXPECT(details->has_ipv4);
        PFL_EXPECT(!details->has_ipv6);
        PFL_EXPECT(session_detail::format_ipv4_address(details->ipv4.src_addr) == expected_address_a);
        PFL_EXPECT(session_detail::format_ipv4_address(details->ipv4.dst_addr) == expected_address_b);
    } else {
        PFL_EXPECT(!details->has_ipv4);
        PFL_EXPECT(details->has_ipv6);
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

    std::string canonical_address_a {};
    std::string canonical_address_b {};
    if (details->has_ipv4) {
        canonical_address_a = session_detail::format_ipv4_address(details->ipv4.src_addr);
        canonical_address_b = session_detail::format_ipv4_address(details->ipv4.dst_addr);
    } else {
        canonical_address_a = session_detail::format_ipv6_address(details->ipv6.src_addr);
        canonical_address_b = session_detail::format_ipv6_address(details->ipv6.dst_addr);
    }

    const auto canonical_port_a = expected_protocol == "TCP" ? details->tcp.src_port : details->udp.src_port;
    const auto canonical_port_b = expected_protocol == "TCP" ? details->tcp.dst_port : details->udp.dst_port;
    const bool forward_match =
        rows[0].address_a == canonical_address_a &&
        rows[0].port_a == canonical_port_a &&
        rows[0].address_b == canonical_address_b &&
        rows[0].port_b == canonical_port_b;
    const bool reverse_match =
        rows[0].address_a == canonical_address_b &&
        rows[0].port_a == canonical_port_b &&
        rows[0].address_b == canonical_address_a &&
        rows[0].port_b == canonical_port_a;
    PFL_EXPECT(forward_match || reverse_match);

    const auto packet_bytes = session.read_packet_data(packet);
    PacketPayloadService payload_service {};
    const auto transport_payload = payload_service.extract_transport_payload(packet_bytes, packet.data_link_type);
    if (expect_payload_extraction) {
        PFL_EXPECT(!transport_payload.empty());
        PFL_EXPECT(static_cast<std::uint32_t>(transport_payload.size()) == packet.payload_length);
        PFL_EXPECT(!session.read_packet_payload_hex_dump(packet).empty());
    } else {
        PFL_EXPECT(transport_payload.empty());
        PFL_EXPECT(session.read_packet_payload_hex_dump(packet).empty());
    }

    const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet);
    expect_layer_prefix(summary_layers, expected_layer_prefix);
    PFL_EXPECT(count_layers(summary_layers, "mpls") == 2U);
    const auto* inner_ethernet_layer = find_layer(summary_layers, "ethernet-inner");
    PFL_REQUIRE(inner_ethernet_layer != nullptr);
    if (inner_ethernet_layer != nullptr) {
        PFL_EXPECT(layer_title_contains(*inner_ethernet_layer, "Src: 02:00:00:00:51:01"));
        PFL_EXPECT(layer_title_contains(*inner_ethernet_layer, "Dst: 02:00:00:00:51:02"));
    }
    if (expect_control_word) {
        const auto* control_word_layer = find_layer(summary_layers, "mpls-pw-control-word");
        PFL_REQUIRE(control_word_layer != nullptr);
        PFL_EXPECT(layer_has_field_containing(*control_word_layer, "Flags", "0x0000"));
        PFL_EXPECT(!layer_has_field_label(*control_word_layer, "Truncated"));
    } else {
        PFL_EXPECT(find_layer(summary_layers, "mpls-pw-control-word") == nullptr);
    }
}

void expect_single_unrecognized_mpls_pw_packet(
    CaptureSession& session,
    const std::filesystem::path& relative_path,
    const std::string& expected_reason
) {
    PFL_EXPECT(session.open_capture(fixture_path(relative_path)));
    PFL_EXPECT(session.list_flows().empty());
    PFL_EXPECT(session.unrecognized_packet_count() == 1U);
    const auto rows = session.list_unrecognized_packets(0U, 30U);
    PFL_REQUIRE(rows.size() == 1U);
    PFL_EXPECT(rows[0].reason_text == expected_reason);
}

}  // namespace

void run_mpls_pseudowire_pcap_fixture_tests() {
    {
        CaptureSession session {};
        expect_single_ip_flow(
            session,
            "parsing/mpls_pw/01_mpls_pw_eth_ipv4_tcp_no_cw.pcap",
            FlowAddressFamily::ipv4,
            "TCP",
            "192.0.2.50",
            49180U,
            "198.51.100.50",
            443U,
            {"frame", "ethernet", "mpls", "mpls", "ethernet-inner", "ipv4", "tcp"},
            false
        );
    }

    {
        CaptureSession session {};
        expect_single_ip_flow(
            session,
            "parsing/mpls_pw/02_mpls_pw_eth_ipv4_udp_no_cw.pcap",
            FlowAddressFamily::ipv4,
            "UDP",
            "192.0.2.50",
            53560U,
            "198.51.100.50",
            443U,
            {"frame", "ethernet", "mpls", "mpls", "ethernet-inner", "ipv4", "udp"},
            false
        );
    }

    {
        CaptureSession session {};
        expect_single_ip_flow(
            session,
            "parsing/mpls_pw/03_mpls_pw_eth_ipv6_tcp_cw.pcap",
            FlowAddressFamily::ipv6,
            "TCP",
            "2001:db8:50::10",
            49180U,
            "2001:db8:50::20",
            443U,
            {"frame", "ethernet", "mpls", "mpls", "mpls-pw-control-word", "ethernet-inner", "ipv6", "tcp"},
            true
        );
    }

    {
        CaptureSession session {};
        expect_single_ip_flow(
            session,
            "parsing/mpls_pw/04_mpls_pw_eth_ipv6_udp_cw.pcap",
            FlowAddressFamily::ipv6,
            "UDP",
            "2001:db8:50::10",
            53560U,
            "2001:db8:50::20",
            443U,
            {"frame", "ethernet", "mpls", "mpls", "mpls-pw-control-word", "ethernet-inner", "ipv6", "udp"},
            true
        );
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/mpls_pw/05_mpls_pw_eth_arp_cw.pcap")));
        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 1U);
        PFL_EXPECT(rows[0].protocol_text == "ARP");
        PFL_EXPECT(rows[0].packet_count == 1U);
        PFL_EXPECT(session.unrecognized_packet_count() == 0U);

        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->has_mpls);
        PFL_EXPECT(details->has_mpls_pseudowire_control_word);
        PFL_EXPECT(details->has_inner_ethernet);
        PFL_EXPECT(details->has_arp);
        PFL_EXPECT(!details->has_tcp);
        PFL_EXPECT(!details->has_udp);

        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet);
        expect_layer_prefix(summary_layers, {"frame", "ethernet", "mpls", "mpls", "mpls-pw-control-word", "ethernet-inner", "arp"});
    }

    {
        CaptureSession session {};
        expect_single_ip_flow(
            session,
            "parsing/mpls_pw/06_mpls_pw_eth_vlan_ipv4_tcp_cw.pcap",
            FlowAddressFamily::ipv4,
            "TCP",
            "192.0.2.50",
            49180U,
            "198.51.100.50",
            443U,
            {"frame", "ethernet", "mpls", "mpls", "mpls-pw-control-word", "ethernet-inner", "vlan", "ipv4", "tcp"},
            true,
            1U
        );
    }

    {
        CaptureSession session {};
        expect_single_ip_flow(
            session,
            "parsing/mpls_pw/07_mpls_pw_eth_qinq_ipv4_udp_cw.pcap",
            FlowAddressFamily::ipv4,
            "UDP",
            "192.0.2.50",
            53560U,
            "198.51.100.50",
            443U,
            {"frame", "ethernet", "mpls", "mpls", "mpls-pw-control-word", "ethernet-inner", "vlan", "vlan", "ipv4", "udp"},
            true,
            2U
        );
    }

    {
        ScopedTestContext fixture_context {"fixture=parsing/mpls_pw/16_mpls_pw_outer_vlan_inner_qinq_ipv4_udp_cw.pcap"};
        CaptureSession session {};
        expect_single_ip_flow(
            session,
            "parsing/mpls_pw/16_mpls_pw_outer_vlan_inner_qinq_ipv4_udp_cw.pcap",
            FlowAddressFamily::ipv4,
            "UDP",
            "192.0.2.50",
            53560U,
            "198.51.100.50",
            443U,
            {"frame", "ethernet", "vlan", "mpls", "mpls", "mpls-pw-control-word", "ethernet-inner", "vlan", "vlan", "ipv4", "udp"},
            true,
            2U,
            false,
            false
        );

        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 1U);
        PFL_EXPECT(
            require_flow_protocol_path_text(session, rows[0]) ==
            "EthernetII -> VLAN(vid=300) -> MPLS(label=24050) -> MPLS(label=16050) -> MPLS PW -> EthernetII -> VLAN(vid=100) -> VLAN(vid=200) -> IPv4 -> UDP"
        );

        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        PFL_REQUIRE(details->encapsulating_vlan_tags.size() == 1U);
        PFL_REQUIRE(details->vlan_tags.size() == 2U);
        PFL_EXPECT(details->encapsulating_vlan_tags[0].tci == 300U);
        PFL_EXPECT(details->vlan_tags[0].tci == 100U);
        PFL_EXPECT(details->vlan_tags[1].tci == 200U);
    }

    {
        CaptureSession session {};
        expect_single_ip_flow(
            session,
            "parsing/mpls_pw/08_mpls_pw_eth_llc_snap_ipv4_udp_cw.pcap",
            FlowAddressFamily::ipv4,
            "UDP",
            "192.0.2.50",
            53560U,
            "198.51.100.50",
            443U,
            {"frame", "ethernet", "mpls", "mpls", "mpls-pw-control-word", "ethernet-inner", "llc", "snap", "ipv4", "udp"},
            true,
            0U,
            true
        );
    }

    {
        CaptureSession session {};
        expect_single_unrecognized_mpls_pw_packet(
            session,
            "parsing/mpls_pw/09_mpls_pw_unknown_inner_ethertype_cw.pcap",
            "Unknown MPLS pseudowire inner EtherType"
        );

        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->has_mpls);
        PFL_EXPECT(details->has_mpls_pseudowire_control_word);
        PFL_EXPECT(details->has_inner_ethernet);
        PFL_EXPECT(details->has_unknown_inner_ethernet_payload);
        PFL_EXPECT(!details->has_ipv4);
        PFL_EXPECT(!details->has_ipv6);
        PFL_EXPECT(!details->has_arp);

        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet);
        expect_layer_prefix(summary_layers, {"frame", "ethernet", "mpls", "mpls", "mpls-pw-control-word", "ethernet-inner", "inner-payload"});
    }

    {
        CaptureSession session {};
        expect_single_unrecognized_mpls_pw_packet(
            session,
            "parsing/mpls_pw/10_mpls_pw_truncated_label_stack.pcap",
            "MPLS label header truncated"
        );

        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->has_mpls);
        PFL_EXPECT(details->mpls_labels.empty());
    }

    {
        CaptureSession session {};
        expect_single_unrecognized_mpls_pw_packet(
            session,
            "parsing/mpls_pw/11_mpls_pw_truncated_control_word.pcap",
            "MPLS pseudowire control word truncated"
        );

        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->has_mpls);
        PFL_EXPECT(details->has_mpls_pseudowire_control_word);
        PFL_EXPECT(details->mpls_pseudowire_control_word.truncated);
        PFL_EXPECT(details->mpls_pseudowire_control_word.available_bytes == 2U);

        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet);
        const auto* control_word_layer = find_layer(summary_layers, "mpls-pw-control-word");
        PFL_REQUIRE(control_word_layer != nullptr);
        PFL_EXPECT(layer_has_field_containing(*control_word_layer, "Flags", "0x0000"));
        PFL_EXPECT(!layer_has_field_label(*control_word_layer, "Sequence"));
        PFL_EXPECT(layer_has_field_containing(*control_word_layer, "Warning", "MPLS pseudowire control word is truncated"));
        PFL_EXPECT(!layer_has_field_label(*control_word_layer, "Truncated"));
    }

    {
        CaptureSession session {};
        expect_single_unrecognized_mpls_pw_packet(
            session,
            "parsing/mpls_pw/12_mpls_pw_truncated_inner_ethernet.pcap",
            "Inner Ethernet header truncated"
        );

        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->has_mpls);
        PFL_EXPECT(details->has_mpls_pseudowire_control_word);
        PFL_EXPECT(details->has_inner_ethernet);
        PFL_EXPECT(details->inner_ethernet.header_truncated);

        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet);
        const auto* inner_ethernet_layer = find_layer(summary_layers, "ethernet-inner");
        PFL_REQUIRE(inner_ethernet_layer != nullptr);
        if (inner_ethernet_layer != nullptr) {
            PFL_EXPECT(!layer_title_contains(*inner_ethernet_layer, "Src:"));
            PFL_EXPECT(!layer_title_contains(*inner_ethernet_layer, "Dst:"));
            PFL_EXPECT(layer_has_field_containing(*inner_ethernet_layer, "Warning", "truncated"));
        }
    }

    {
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/mpls_pw/13_mpls_pw_truncated_inner_ipv4.pcap")));
        PFL_EXPECT(session.list_flows().empty());
        PFL_EXPECT(session.unrecognized_packet_count() == 1U);
        const auto rows = session.list_unrecognized_packets(0U, 30U);
        PFL_REQUIRE(rows.size() == 1U);
        PFL_EXPECT(
            rows[0].reason_text == "Inner IPv4 header truncated" ||
            rows[0].reason_text == "IPv4 header truncated"
        );

        const auto packet = require_packet(session, rows[0].packet_index);
        const auto details = session.read_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->has_mpls);
        PFL_EXPECT(details->has_mpls_pseudowire_control_word);
        PFL_EXPECT(details->has_inner_ethernet);
        PFL_EXPECT(details->has_ipv4);
        PFL_EXPECT(details->ipv4.header_truncated);
        PFL_EXPECT(!details->has_udp);

        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet);
        expect_layer_prefix(summary_layers, {"warnings", "frame", "ethernet", "mpls", "mpls", "mpls-pw-control-word", "ethernet-inner", "ipv4"});
    }

    {
        CaptureSession session {};
        expect_single_ip_flow(
            session,
            "parsing/mpls_pw/14_mpls_pw_control_word_with_sequence.pcap",
            FlowAddressFamily::ipv4,
            "UDP",
            "192.0.2.50",
            53560U,
            "198.51.100.50",
            443U,
            {"frame", "ethernet", "mpls", "mpls", "mpls-pw-control-word", "ethernet-inner", "ipv4", "udp"},
            true
        );

        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->mpls_pseudowire_control_word.sequence == 0x1234U);
        const auto summary_layers = session_detail::build_packet_summary_layers(*details, packet);
        const auto* control_word_layer = find_layer(summary_layers, "mpls-pw-control-word");
        PFL_REQUIRE(control_word_layer != nullptr);
        PFL_EXPECT(layer_has_field_containing(*control_word_layer, "Sequence", "4660"));
        PFL_EXPECT(!layer_has_field_label(*control_word_layer, "Truncated"));
    }

    {
        CaptureSession session {};
        expect_single_ip_flow(
            session,
            "parsing/mpls_pw/15_mpls_pw_ambiguous_no_cw_inner_ethernet.pcap",
            FlowAddressFamily::ipv4,
            "UDP",
            "192.0.2.50",
            53560U,
            "198.51.100.50",
            443U,
            {"frame", "ethernet", "mpls", "mpls", "ethernet-inner", "ipv4", "udp"},
            false
        );

        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->has_inner_ethernet);
        PFL_EXPECT(!details->has_mpls_pseudowire_control_word);
        PFL_EXPECT(details->has_ipv4);
        PFL_EXPECT(details->has_udp);
    }

    {
        ScopedTestContext fixture_context {"fixture=parsing/mpls_pw/17_mpls_pw_outer_qinq_inner_ipv4_udp_cw.pcap"};
        CaptureSession session {};
        expect_single_ip_flow(
            session,
            "parsing/mpls_pw/17_mpls_pw_outer_qinq_inner_ipv4_udp_cw.pcap",
            FlowAddressFamily::ipv4,
            "UDP",
            "192.0.2.50",
            53560U,
            "198.51.100.50",
            443U,
            {"frame", "ethernet", "vlan", "vlan", "mpls", "mpls", "mpls-pw-control-word", "ethernet-inner", "ipv4", "udp"},
            true,
            0U,
            false,
            false
        );

        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 1U);
        PFL_EXPECT(
            require_flow_protocol_path_text(session, rows[0]) ==
            "EthernetII -> VLAN(vid=310) -> VLAN(vid=311) -> MPLS(label=24050) -> MPLS(label=16050) -> MPLS PW -> EthernetII -> IPv4 -> UDP"
        );
    }

    {
        ScopedTestContext fixture_context {"fixture=parsing/mpls_pw/18_mpls_pw_outer_legacy_vlan_ipv4_tcp_cw.pcap"};
        CaptureSession session {};
        expect_single_ip_flow(
            session,
            "parsing/mpls_pw/18_mpls_pw_outer_legacy_vlan_ipv4_tcp_cw.pcap",
            FlowAddressFamily::ipv4,
            "TCP",
            "192.0.2.50",
            49180U,
            "198.51.100.50",
            443U,
            {"frame", "ethernet", "vlan", "mpls", "mpls", "mpls-pw-control-word", "ethernet-inner", "ipv4", "tcp"},
            true,
            0U,
            false,
            false
        );

        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 1U);
        PFL_EXPECT(
            require_flow_protocol_path_text(session, rows[0]) ==
            "EthernetII -> VLAN(vid=320) -> MPLS(label=24050) -> MPLS(label=16050) -> MPLS PW -> EthernetII -> IPv4 -> TCP"
        );
    }

    {
        ScopedTestContext fixture_context {"fixture=parsing/mpls_pw/19_mpls_pw_ambiguous_no_cw_mac_starts_with_4.pcap"};
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/mpls_pw/19_mpls_pw_ambiguous_no_cw_mac_starts_with_4.pcap")));
        PFL_EXPECT(session.list_flows().empty());
        PFL_EXPECT(session.unrecognized_packet_count() == 1U);
        PFL_EXPECT(session.state().protocol_path_registry.size() == 0U);
        const auto rows = session.list_unrecognized_packets(0U, 30U);
        PFL_REQUIRE(rows.size() == 1U);
        PFL_EXPECT(!rows[0].reason_text.empty());
    }

    {
        ScopedTestContext fixture_context {"fixture=parsing/mpls_pw/20_mpls_pw_ambiguous_no_cw_mac_starts_with_6.pcap"};
        CaptureSession session {};
        PFL_EXPECT(session.open_capture(fixture_path("parsing/mpls_pw/20_mpls_pw_ambiguous_no_cw_mac_starts_with_6.pcap")));
        PFL_EXPECT(session.list_flows().empty());
        PFL_EXPECT(session.unrecognized_packet_count() == 1U);
        PFL_EXPECT(session.state().protocol_path_registry.size() == 0U);
        const auto rows = session.list_unrecognized_packets(0U, 30U);
        PFL_REQUIRE(rows.size() == 1U);
        PFL_EXPECT(!rows[0].reason_text.empty());
    }

    {
        ScopedTestContext fixture_context {"fixture=parsing/mpls_pw/21_mpls_pw_inner_pppoe_session_no_cw.pcap"};
        CaptureSession session {};
        expect_single_unrecognized_mpls_pw_packet(
            session,
            "parsing/mpls_pw/21_mpls_pw_inner_pppoe_session_no_cw.pcap",
            "Unknown MPLS payload"
        );

        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->has_mpls);
        PFL_EXPECT(details->has_inner_ethernet);
        PFL_EXPECT(!details->has_mpls_pseudowire_control_word);
        PFL_EXPECT(!details->has_ipv4);
        PFL_EXPECT(!details->has_ipv6);
    }

    {
        ScopedTestContext fixture_context {"fixture=parsing/mpls_pw/22_mpls_pw_inner_mpls_no_cw.pcap"};
        CaptureSession session {};
        expect_single_unrecognized_mpls_pw_packet(
            session,
            "parsing/mpls_pw/22_mpls_pw_inner_mpls_no_cw.pcap",
            "Unknown MPLS pseudowire inner EtherType"
        );

        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->has_mpls);
        PFL_EXPECT(details->has_inner_ethernet);
        PFL_EXPECT(details->has_unknown_inner_ethernet_payload);
        PFL_EXPECT(!details->has_mpls_pseudowire_control_word);
    }

    {
        ScopedTestContext fixture_context {"fixture=parsing/mpls_pw/23_mpls_pw_nonzero_cw_flags_not_recognized.pcap"};
        CaptureSession session {};
        expect_single_unrecognized_mpls_pw_packet(
            session,
            "parsing/mpls_pw/23_mpls_pw_nonzero_cw_flags_not_recognized.pcap",
            "Inner Ethernet header truncated"
        );

        const auto packet = require_packet(session, 0U);
        const auto details = session.read_packet_details(packet);
        PFL_REQUIRE(details.has_value());
        PFL_EXPECT(details->has_mpls);
        PFL_EXPECT(!details->has_mpls_pseudowire_control_word);
        PFL_EXPECT(details->has_inner_ethernet);
        PFL_EXPECT(details->inner_ethernet.header_truncated);
    }

    {
        ScopedTestContext fixture_context {"fixture=temp_mpls_pw_identity_same_tuple_different_labels"};
        const std::vector<MplsLabelSpec> base_labels {
            {.label = 24050U, .bottom_of_stack = false},
            {.label = 16050U, .bottom_of_stack = true},
        };
        const auto inner_frame = make_default_inner_ipv4_udp_frame();
        const auto capture_path = write_temp_pcap(
            "pfl_mpls_pw_same_tuple_different_labels.pcap",
            make_classic_pcap({
                {100U, make_mpls_pseudowire_frame(base_labels, inner_frame)},
                {200U, make_mpls_pseudowire_frame(
                    {
                        {.label = 24051U, .bottom_of_stack = false},
                        {.label = 16050U, .bottom_of_stack = true},
                    },
                    inner_frame
                )},
                {300U, make_mpls_pseudowire_frame(
                    {
                        {.label = 24050U, .bottom_of_stack = false},
                        {.label = 16051U, .bottom_of_stack = true},
                    },
                    inner_frame
                )},
            })
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(capture_path));
        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 3U);
        PFL_EXPECT(session.state().protocol_path_registry.size() == 3U);
    }

    {
        ScopedTestContext fixture_context {"fixture=temp_mpls_pw_identity_non_identity_fields_do_not_split"};
        const auto inner_frame = make_default_inner_ipv4_udp_frame();
        const auto capture_path = write_temp_pcap(
            "pfl_mpls_pw_non_identity_fields.pcap",
            make_classic_pcap({
                {100U, make_mpls_pseudowire_frame(
                    {
                        {.label = 24050U, .bottom_of_stack = false, .ttl = 64U},
                        {.label = 16050U, .bottom_of_stack = true, .ttl = 63U},
                    },
                    inner_frame,
                    std::pair<std::uint16_t, std::uint16_t> {0x0000U, 0x0000U}
                )},
                {200U, make_mpls_pseudowire_frame(
                    {
                        {.label = 24050U, .traffic_class = 7U, .bottom_of_stack = false, .ttl = 64U},
                        {.label = 16050U, .bottom_of_stack = true, .ttl = 63U},
                    },
                    inner_frame,
                    std::pair<std::uint16_t, std::uint16_t> {0x0000U, 0x1234U}
                )},
                {300U, make_mpls_pseudowire_frame(
                    {
                        {.label = 24050U, .bottom_of_stack = false, .ttl = 1U},
                        {.label = 16050U, .bottom_of_stack = true, .ttl = 255U},
                    },
                    inner_frame,
                    std::pair<std::uint16_t, std::uint16_t> {0x0000U, 0x4321U}
                )},
            })
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(capture_path));
        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 1U);
        PFL_EXPECT(rows[0].packet_count == 3U);
        PFL_EXPECT(session.state().protocol_path_registry.size() == 1U);
        PFL_EXPECT(
            require_flow_protocol_path_text(session, rows[0]) ==
            "EthernetII -> MPLS(label=24050) -> MPLS(label=16050) -> MPLS PW -> EthernetII -> IPv4 -> UDP"
        );
    }

    {
        ScopedTestContext fixture_context {"fixture=temp_mpls_pw_identity_control_word_presence_does_not_split"};
        const auto inner_frame = make_default_inner_ipv4_udp_frame();
        const auto labels = std::vector<MplsLabelSpec> {
            {.label = 24050U, .bottom_of_stack = false},
            {.label = 16050U, .bottom_of_stack = true},
        };
        const auto capture_path = write_temp_pcap(
            "pfl_mpls_pw_control_word_presence.pcap",
            make_classic_pcap({
                {100U, make_mpls_pseudowire_frame(labels, inner_frame)},
                {200U, make_mpls_pseudowire_frame(labels, inner_frame, std::pair<std::uint16_t, std::uint16_t> {0x0000U, 0x2222U})},
            })
        );

        CaptureSession session {};
        PFL_EXPECT(session.open_capture(capture_path));
        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 1U);
        PFL_EXPECT(rows[0].packet_count == 2U);
        PFL_EXPECT(session.state().protocol_path_registry.size() == 1U);
    }
}

}  // namespace pfl::tests
