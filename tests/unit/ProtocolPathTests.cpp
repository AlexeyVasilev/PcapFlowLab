#include <filesystem>
#include <functional>
#include <map>
#include <set>
#include <sstream>
#include <string>

#include "TestSupport.h"
#include "app/frontend/FrontendSessionAdapter.h"
#include "app/session/CaptureSession.h"
#include "app/session/FlowRows.h"
#include "app/session/ProtocolPathPresentation.h"
#include "PcapTestUtils.h"
#include "core/domain/ProtocolPath.h"
#include "core/services/CaptureImporter.h"

namespace pfl::tests {

namespace {

std::filesystem::path fixture_path(const std::filesystem::path& relative_path) {
    return std::filesystem::path(__FILE__).parent_path().parent_path() / "data" / relative_path;
}

CaptureState require_imported_capture_state(const std::filesystem::path& path) {
    CaptureImporter importer {};
    CaptureState state {};
    PFL_REQUIRE(importer.import_capture(path, state));
    return state;
}

const PacketRef* find_packet_ref(const CaptureState& state, const std::uint64_t packet_index) {
    for (const auto* connection : state.ipv4_connections.list()) {
        for (const auto& packet : connection->flow_a.packets) {
            if (packet.packet_index == packet_index) {
                return &packet;
            }
        }
        for (const auto& packet : connection->flow_b.packets) {
            if (packet.packet_index == packet_index) {
                return &packet;
            }
        }
    }

    for (const auto* connection : state.ipv6_connections.list()) {
        for (const auto& packet : connection->flow_a.packets) {
            if (packet.packet_index == packet_index) {
                return &packet;
            }
        }
        for (const auto& packet : connection->flow_b.packets) {
            if (packet.packet_index == packet_index) {
                return &packet;
            }
        }
    }

    for (const auto& record : state.unrecognized_packets) {
        if (record.packet.packet_index == packet_index) {
            return &record.packet;
        }
    }

    return nullptr;
}

std::string require_packet_protocol_path_text(const CaptureState& state, const std::uint64_t packet_index) {
    const auto* packet = find_packet_ref(state, packet_index);
    PFL_REQUIRE(packet != nullptr);
    PFL_REQUIRE(packet->protocol_path_id != kInvalidProtocolPathId);
    const auto* path = state.protocol_path_registry.find(packet->protocol_path_id);
    PFL_REQUIRE(path != nullptr);
    return format_protocol_path(*path);
}

CaptureImportOptions fast_import_options() {
    CaptureImportOptions options {};
    options.mode = ImportMode::fast;
    return options;
}

ProtocolPathId flow_protocol_path_id(const FlowRow& row) {
    if (std::holds_alternative<ConnectionKeyV4>(row.key)) {
        return std::get<ConnectionKeyV4>(row.key).protocol_path_id;
    }

    return std::get<ConnectionKeyV6>(row.key).protocol_path_id;
}

std::string protocol_path_text_or_invalid(const CaptureState& state, const ProtocolPathId id) {
    if (id == kInvalidProtocolPathId) {
        return "invalid";
    }

    const auto* path = state.protocol_path_registry.find(id);
    if (path == nullptr) {
        return "missing";
    }

    return format_protocol_path(*path);
}

std::string normalized_protocol_path_text_for_flow_identity(const CaptureState& state, const ProtocolPathId id) {
    if (id == kInvalidProtocolPathId) {
        return "invalid";
    }

    const auto* path = state.protocol_path_registry.find(id);
    if (path == nullptr) {
        return "missing";
    }

    std::vector<LayerKey> normalized_layers {};
    normalized_layers.reserve(path->size());
    for (const auto& layer : path->layers()) {
        const bool omit_priority_tag =
            layer.kind == ProtocolLayerKind::vlan &&
            layer.identifier.kind == ProtocolLayerIdentifierKind::vlan_vid &&
            layer.identifier.value == 0U;
        if (!omit_priority_tag) {
            normalized_layers.push_back(layer);
        }
    }

    return format_protocol_path(ProtocolPath {std::move(normalized_layers)});
}

std::string join_packet_indices(const std::vector<PacketRef>& packets) {
    std::ostringstream builder {};
    for (std::size_t index = 0; index < packets.size(); ++index) {
        if (index != 0U) {
            builder << ',';
        }
        builder << packets[index].packet_index;
    }
    return builder.str();
}

std::string join_packet_numbers(const std::vector<PacketRef>& packets) {
    std::ostringstream builder {};
    for (std::size_t index = 0; index < packets.size(); ++index) {
        if (index != 0U) {
            builder << ',';
        }
        builder << '#' << (packets[index].packet_index + 1U);
    }
    return builder.str();
}

std::string summarize_packet_path_ids(const CaptureState& state, const std::vector<PacketRef>& packets) {
    std::map<ProtocolPathId, std::vector<std::uint64_t>> packets_by_path {};
    for (const auto& packet : packets) {
        packets_by_path[packet.protocol_path_id].push_back(packet.packet_index);
    }

    std::ostringstream builder {};
    bool first_entry = true;
    for (const auto& [path_id, packet_indices] : packets_by_path) {
        if (!first_entry) {
            builder << "; ";
        }
        first_entry = false;

        builder << "id=" << path_id
                << " [" << protocol_path_text_or_invalid(state, path_id) << "] packets=";
        for (std::size_t index = 0; index < packet_indices.size(); ++index) {
            if (index != 0U) {
                builder << ',';
            }
            builder << packet_indices[index];
        }
    }
    return builder.str();
}

std::vector<std::string> badge_short_labels(const std::vector<ProtocolPathBadgeRow>& badges) {
    std::vector<std::string> labels {};
    labels.reserve(badges.size());
    for (const auto& badge : badges) {
        labels.push_back(badge.short_label);
    }
    return labels;
}

std::string format_fixture_flow_diagnostics(
    const std::filesystem::path& relative_path,
    const CaptureSession& session
) {
    const auto& state = session.state();
    const auto rows = session.list_flows();

    std::ostringstream builder {};
    builder << "Protocol-path diagnostics for " << relative_path.generic_string() << '\n';
    builder << "flow_count=" << rows.size() << '\n';

    for (std::size_t flow_index = 0U; flow_index < rows.size(); ++flow_index) {
        const auto& row = rows[flow_index];
        const auto packets = session.flow_packets(flow_index);
        const auto packet_rows = session.list_flow_packets(flow_index);
        builder << "  flow[" << flow_index << "]: protocol=" << row.protocol_text
                << " tuple=" << row.endpoint_a << " <-> " << row.endpoint_b
                << " packet_count=" << row.packet_count
                << " flow_protocol_path_id=" << flow_protocol_path_id(row)
                << " flow_protocol_path=" << protocol_path_text_or_invalid(state, flow_protocol_path_id(row))
                << '\n';
        builder << "    packet_rows.count=" << packet_rows.size();
        if (!packet_rows.empty()) {
            builder << " first_row={row=" << packet_rows.front().row_number
                    << ",packet_index=" << packet_rows.front().packet_index
                    << ",payload_length=" << packet_rows.front().payload_length
                    << "} last_row={row=" << packet_rows.back().row_number
                    << ",packet_index=" << packet_rows.back().packet_index
                    << ",payload_length=" << packet_rows.back().payload_length
                    << "}";
        }
        builder << '\n';
        if (!packets.has_value()) {
            builder << "    packets: unavailable\n";
            continue;
        }

        builder << "    packet_indices=[" << join_packet_indices(*packets) << "]\n";
        builder << "    packet_numbers=[" << join_packet_numbers(*packets) << "]\n";
        builder << "    packet_paths=" << summarize_packet_path_ids(state, *packets) << '\n';
    }

    return builder.str();
}

void expect_layer_key_equality() {
    PFL_EXPECT(LayerKey::ipv4() == LayerKey::ipv4());
    PFL_EXPECT(LayerKey::ipv4() != LayerKey::ipv6());
    PFL_EXPECT(LayerKey::vlan(100U) == LayerKey::vlan(100U));
    PFL_EXPECT(LayerKey::vlan(100U) != LayerKey::vlan(200U));
    PFL_EXPECT(LayerKey::vxlan(100U) != LayerKey::geneve(100U));
    PFL_EXPECT(LayerKey::mpls(102U) != LayerKey::vlan(102U));

    const auto ipv4_hash_1 = std::hash<LayerKey> {}(LayerKey::ipv4());
    const auto ipv4_hash_2 = std::hash<LayerKey> {}(LayerKey::ipv4());
    const auto vlan_hash_1 = std::hash<LayerKey> {}(LayerKey::vlan(100U));
    const auto vlan_hash_2 = std::hash<LayerKey> {}(LayerKey::vlan(100U));

    PFL_EXPECT(ipv4_hash_1 == ipv4_hash_2);
    PFL_EXPECT(vlan_hash_1 == vlan_hash_2);
}

void expect_protocol_path_ordered_equality() {
    const ProtocolPath direct_a {
        LayerKey::ethernet_ii(),
        LayerKey::ipv4(),
        LayerKey::tcp(),
    };
    const ProtocolPath direct_b {
        LayerKey::ethernet_ii(),
        LayerKey::ipv4(),
        LayerKey::tcp(),
    };
    const ProtocolPath udp_path {
        LayerKey::ethernet_ii(),
        LayerKey::ipv4(),
        LayerKey::udp(),
    };
    const ProtocolPath shim_path_a {
        LayerKey::ethernet_ii(),
        LayerKey::mpls(102U),
        LayerKey::vlan(200U),
        LayerKey::ipv4(),
        LayerKey::tcp(),
    };
    const ProtocolPath shim_path_b {
        LayerKey::ethernet_ii(),
        LayerKey::vlan(200U),
        LayerKey::mpls(102U),
        LayerKey::ipv4(),
        LayerKey::tcp(),
    };

    PFL_EXPECT(direct_a == direct_b);
    PFL_EXPECT(direct_a != udp_path);
    PFL_EXPECT(shim_path_a != shim_path_b);

    const auto direct_hash_1 = std::hash<ProtocolPath> {}(direct_a);
    const auto direct_hash_2 = std::hash<ProtocolPath> {}(direct_b);
    PFL_EXPECT(direct_hash_1 == direct_hash_2);
}

void expect_identifier_differences() {
    const ProtocolPath vxlan_100 {
        LayerKey::ethernet_ii(),
        LayerKey::ipv4(),
        LayerKey::udp(),
        LayerKey::vxlan(100U),
        LayerKey::ethernet_ii(),
        LayerKey::ipv4(),
        LayerKey::tcp(),
    };
    const ProtocolPath vxlan_200 {
        LayerKey::ethernet_ii(),
        LayerKey::ipv4(),
        LayerKey::udp(),
        LayerKey::vxlan(200U),
        LayerKey::ethernet_ii(),
        LayerKey::ipv4(),
        LayerKey::tcp(),
    };
    const ProtocolPath gtpu_a {
        LayerKey::ethernet_ii(),
        LayerKey::ipv4(),
        LayerKey::udp(),
        LayerKey::gtpu(0x01020384U),
        LayerKey::ipv4(),
        LayerKey::sctp(),
    };
    const ProtocolPath gtpu_b {
        LayerKey::ethernet_ii(),
        LayerKey::ipv4(),
        LayerKey::udp(),
        LayerKey::gtpu(0x01020385U),
        LayerKey::ipv4(),
        LayerKey::sctp(),
    };
    const ProtocolPath mpls_ab {
        LayerKey::ethernet_ii(),
        LayerKey::mpls(100U),
        LayerKey::mpls(200U),
        LayerKey::ipv4(),
        LayerKey::tcp(),
    };
    const ProtocolPath mpls_ba {
        LayerKey::ethernet_ii(),
        LayerKey::mpls(200U),
        LayerKey::mpls(100U),
        LayerKey::ipv4(),
        LayerKey::tcp(),
    };

    PFL_EXPECT(vxlan_100 != vxlan_200);
    PFL_EXPECT(gtpu_a != gtpu_b);
    PFL_EXPECT(mpls_ab != mpls_ba);
}

void expect_registry_interning() {
    ProtocolPathRegistry registry {};

    const ProtocolPath direct {
        LayerKey::ethernet_ii(),
        LayerKey::ipv4(),
        LayerKey::tcp(),
    };
    const ProtocolPath direct_copy {
        LayerKey::ethernet_ii(),
        LayerKey::ipv4(),
        LayerKey::tcp(),
    };
    const ProtocolPath shim {
        LayerKey::ethernet_ii(),
        LayerKey::mpls(102U),
        LayerKey::vlan(200U),
        LayerKey::ipv4(),
        LayerKey::tcp(),
    };

    PFL_EXPECT(registry.size() == 0U);
    PFL_EXPECT(registry.find(kInvalidProtocolPathId) == nullptr);
    PFL_EXPECT(registry.find(999U) == nullptr);

    const auto direct_id = registry.intern(direct);
    const auto direct_copy_id = registry.intern(direct_copy);
    const auto shim_id = registry.intern(shim);

    PFL_EXPECT(direct_id == 1U);
    PFL_EXPECT(direct_id != kInvalidProtocolPathId);
    PFL_EXPECT(direct_id == direct_copy_id);
    PFL_EXPECT(shim_id == 2U);
    PFL_EXPECT(shim_id != kInvalidProtocolPathId);
    PFL_EXPECT(shim_id != direct_id);
    PFL_EXPECT(registry.size() == 2U);

    const auto* stored_direct = registry.find(direct_id);
    const auto* stored_shim = registry.find(shim_id);
    PFL_REQUIRE(stored_direct != nullptr);
    PFL_REQUIRE(stored_shim != nullptr);
    PFL_EXPECT(*stored_direct == direct);
    PFL_EXPECT(*stored_shim == shim);
}

void expect_formatting() {
    const ProtocolPath direct {
        LayerKey::ethernet_ii(),
        LayerKey::ipv4(),
        LayerKey::tcp(),
    };
    const ProtocolPath shim {
        LayerKey::ethernet_ii(),
        LayerKey::mpls(102U),
        LayerKey::vlan(200U),
        LayerKey::ipv4(),
        LayerKey::tcp(),
    };
    const ProtocolPath vxlan {
        LayerKey::ethernet_ii(),
        LayerKey::ipv4(),
        LayerKey::udp(),
        LayerKey::vxlan(100U),
        LayerKey::ethernet_ii(),
        LayerKey::ipv4(),
        LayerKey::tcp(),
    };
    const ProtocolPath gtpu {
        LayerKey::ethernet_ii(),
        LayerKey::ipv4(),
        LayerKey::udp(),
        LayerKey::gtpu(0x01020384U),
        LayerKey::ipv4(),
        LayerKey::sctp(),
    };

    PFL_EXPECT(format_protocol_layer_key(LayerKey::ethernet_ii()) == "EthernetII");
    PFL_EXPECT(format_protocol_layer_key(LayerKey::ipv4()) == "IPv4");
    PFL_EXPECT(format_protocol_layer_key(LayerKey::tcp()) == "TCP");
    PFL_EXPECT(format_protocol_layer_key(LayerKey::vlan(200U)) == "VLAN(vid=200)");
    PFL_EXPECT(format_protocol_layer_key(LayerKey::mpls(102U)) == "MPLS(label=102)");
    PFL_EXPECT(format_protocol_layer_key(LayerKey::vxlan(100U)) == "VXLAN(vni=100)");
    PFL_EXPECT(format_protocol_layer_key(LayerKey::geneve(200U)) == "Geneve(vni=200)");
    PFL_EXPECT(format_protocol_layer_key(LayerKey::gtpu(0x01020384U)) == "GTP-U(teid=0x01020384)");

    PFL_EXPECT(format_protocol_path(direct) == "EthernetII -> IPv4 -> TCP");
    PFL_EXPECT(format_protocol_path(shim) == "EthernetII -> MPLS(label=102) -> VLAN(vid=200) -> IPv4 -> TCP");
    PFL_EXPECT(format_protocol_path(vxlan) == "EthernetII -> IPv4 -> UDP -> VXLAN(vni=100) -> EthernetII -> IPv4 -> TCP");
    PFL_EXPECT(format_protocol_path(gtpu) == "EthernetII -> IPv4 -> UDP -> GTP-U(teid=0x01020384) -> IPv4 -> SCTP");
}

void expect_protocol_path_presentation_mapping() {
    const ProtocolPath direct {
        LayerKey::ethernet_ii(),
        LayerKey::ipv4(),
        LayerKey::tcp(),
    };
    const ProtocolPath vxlan {
        LayerKey::ethernet_ii(),
        LayerKey::ipv4(),
        LayerKey::udp(),
        LayerKey::vxlan(100U),
        LayerKey::ethernet_ii(),
        LayerKey::ipv4(),
        LayerKey::tcp(),
    };
    const ProtocolPath gtpu {
        LayerKey::ethernet_ii(),
        LayerKey::ipv4(),
        LayerKey::udp(),
        LayerKey::gtpu(0x01020384U),
        LayerKey::ipv4(),
        LayerKey::sctp(),
    };
    const ProtocolPath mpls {
        LayerKey::ethernet_ii(),
        LayerKey::mpls(100U),
        LayerKey::mpls(200U),
        LayerKey::ipv4(),
        LayerKey::tcp(),
    };

    const auto direct_presentation = session_detail::build_protocol_path_presentation(&direct);
    PFL_EXPECT(direct_presentation.full_text == "EthernetII -> IPv4 -> TCP");
    PFL_EXPECT(direct_presentation.compact_text == "EII|Ip4|TCP");
    PFL_EXPECT(badge_short_labels(direct_presentation.badges) == std::vector<std::string>({"EII", "Ip4", "TCP"}));
    PFL_EXPECT(direct_presentation.badges[0].full_name == "Ethernet II");
    PFL_EXPECT(direct_presentation.badges[0].color_key == "link");

    const auto vxlan_presentation = session_detail::build_protocol_path_presentation(&vxlan);
    PFL_EXPECT(vxlan_presentation.compact_text == "EII|Ip4|UDP|Vx|EII|Ip4|TCP");
    PFL_EXPECT(vxlan_presentation.badges[3].tooltip == "VXLAN\nVNI: 100");
    PFL_EXPECT(vxlan_presentation.badges[3].color_key == "overlay");

    const auto gtpu_presentation = session_detail::build_protocol_path_presentation(&gtpu);
    PFL_EXPECT(gtpu_presentation.badges[3].short_label == "GTP-U");
    PFL_EXPECT(gtpu_presentation.badges[3].tooltip == "GTP-U\nTEID: 0x01020384");
    PFL_EXPECT(gtpu_presentation.badges.back().short_label == "SCTP");

    const auto mpls_presentation = session_detail::build_protocol_path_presentation(&mpls);
    PFL_EXPECT(badge_short_labels(mpls_presentation.badges) == std::vector<std::string>({"EII", "M", "M", "Ip4", "TCP"}));
    PFL_EXPECT(mpls_presentation.badges[1].tooltip == "MPLS\nLabel: 100");
    PFL_EXPECT(mpls_presentation.badges[2].tooltip == "MPLS\nLabel: 200");

    const auto unknown_presentation = session_detail::build_protocol_path_presentation(nullptr);
    PFL_EXPECT(unknown_presentation.full_text == "Unknown protocol path");
    PFL_EXPECT(unknown_presentation.compact_text == "?");
    PFL_REQUIRE(unknown_presentation.badges.size() == 1U);
    PFL_EXPECT(unknown_presentation.badges[0].short_label == "?");

    const auto legend = session_detail::protocol_path_legend_entries();
    PFL_EXPECT(legend.size() == 19U);
    PFL_EXPECT(legend.front().short_label == "EII");
    PFL_EXPECT(legend.back().short_label == "?");
    PFL_EXPECT(legend.back().full_name == "Unknown");
}

void expect_flow_rows_expose_protocol_path_presentation() {
    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/vxlan/01_vxlan_inner_ipv4_tcp.pcap")));
        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 1U);
        PFL_EXPECT(rows[0].protocol_path_text == "EthernetII -> IPv4 -> UDP -> VXLAN(vni=100) -> EthernetII -> IPv4 -> TCP");
        PFL_EXPECT(rows[0].protocol_path_compact_text == "EII|Ip4|UDP|Vx|EII|Ip4|TCP");
        PFL_REQUIRE(rows[0].protocol_path_badges.size() == 7U);
        PFL_EXPECT(rows[0].protocol_path_badges[3].tooltip == "VXLAN\nVNI: 100");
    }

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/gtpu/01_gtpu_inner_ipv4_tcp.pcap")));
        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 1U);
        PFL_EXPECT(rows[0].protocol_path_text == "EthernetII -> IPv4 -> UDP -> GTP-U(teid=0x01020304) -> IPv4 -> TCP");
        PFL_EXPECT(rows[0].protocol_path_compact_text == "EII|Ip4|UDP|GTP-U|Ip4|TCP");
        PFL_REQUIRE(rows[0].protocol_path_badges.size() == 6U);
        PFL_EXPECT(rows[0].protocol_path_badges[3].tooltip == "GTP-U\nTEID: 0x01020304");
    }
}

void expect_frontend_flows_expose_protocol_path_presentation() {
    FrontendSessionAdapter adapter {};
    PFL_REQUIRE(adapter.open_capture(fixture_path("parsing/vxlan/01_vxlan_inner_ipv4_tcp.pcap"), FrontendOpenMode::fast).opened);

    const auto flows = adapter.get_flows();
    PFL_REQUIRE(flows.size() == 1U);
    PFL_EXPECT(flows[0].protocol_path_text == "EthernetII -> IPv4 -> UDP -> VXLAN(vni=100) -> EthernetII -> IPv4 -> TCP");
    PFL_EXPECT(flows[0].protocol_path_compact_text == "EII|Ip4|UDP|Vx|EII|Ip4|TCP");
    PFL_REQUIRE(flows[0].protocol_path_badges.size() == 7U);
    PFL_EXPECT(flows[0].protocol_path_badges[3].short_label == "Vx");
    PFL_EXPECT(flows[0].protocol_path_badges[3].tooltip == "VXLAN\nVNI: 100");
}

void expect_builder_empty_state() {
    ProtocolPathBuilder builder {};

    PFL_EXPECT(builder.empty());
    PFL_EXPECT(builder.size() == 0U);
    PFL_EXPECT(!builder.full());
    PFL_EXPECT(!builder.overflowed());

    const auto path = builder.to_path();
    PFL_EXPECT(path.empty());
}

void expect_builder_push_order() {
    ProtocolPathBuilder builder {};

    PFL_EXPECT(builder.push(LayerKey::ethernet_ii()));
    PFL_EXPECT(builder.push(LayerKey::ipv4()));
    PFL_EXPECT(builder.push(LayerKey::tcp()));
    PFL_EXPECT(builder.size() == 3U);
    PFL_EXPECT(!builder.empty());
    PFL_EXPECT(builder[0] == LayerKey::ethernet_ii());
    PFL_EXPECT(builder[1] == LayerKey::ipv4());
    PFL_EXPECT(builder[2] == LayerKey::tcp());

    const auto path = builder.to_path();
    PFL_EXPECT(path.size() == 3U);
    PFL_EXPECT(format_protocol_path(path) == "EthernetII -> IPv4 -> TCP");
}

void expect_builder_identifier_layers() {
    ProtocolPathBuilder builder {};
    PFL_EXPECT(builder.push(LayerKey::ethernet_ii()));
    PFL_EXPECT(builder.push(LayerKey::mpls(102U)));
    PFL_EXPECT(builder.push(LayerKey::vlan(200U)));
    PFL_EXPECT(builder.push(LayerKey::ipv4()));
    PFL_EXPECT(builder.push(LayerKey::tcp()));

    const auto path = builder.to_path();
    const ProtocolPath expected {
        LayerKey::ethernet_ii(),
        LayerKey::mpls(102U),
        LayerKey::vlan(200U),
        LayerKey::ipv4(),
        LayerKey::tcp(),
    };
    PFL_EXPECT(path == expected);
}

void expect_builder_clear_and_reuse() {
    ProtocolPathBuilder builder {};
    PFL_EXPECT(builder.push(LayerKey::ethernet_ii()));
    PFL_EXPECT(builder.push(LayerKey::ipv4()));
    PFL_EXPECT(builder.push(LayerKey::tcp()));
    PFL_EXPECT(builder.size() == 3U);

    builder.clear();
    PFL_EXPECT(builder.empty());
    PFL_EXPECT(builder.size() == 0U);
    PFL_EXPECT(!builder.full());
    PFL_EXPECT(!builder.overflowed());

    PFL_EXPECT(builder.push(LayerKey::ethernet_ii()));
    PFL_EXPECT(builder.push(LayerKey::ipv6()));
    PFL_EXPECT(builder.push(LayerKey::udp()));

    const auto path = builder.to_path();
    PFL_EXPECT(format_protocol_path(path) == "EthernetII -> IPv6 -> UDP");
}

void expect_builder_capacity_and_overflow() {
    ProtocolPathBuilder builder {};

    for (std::size_t index = 0U; index < kMaxProtocolPathLayers; ++index) {
        const auto layer = (index % 2U) == 0U ? LayerKey::ethernet_ii() : LayerKey::ipv4();
        PFL_EXPECT(builder.push(layer));
    }

    PFL_EXPECT(builder.size() == kMaxProtocolPathLayers);
    PFL_EXPECT(builder.full());
    PFL_EXPECT(!builder.overflowed());

    const auto prefix_path = builder.to_path();
    PFL_EXPECT(prefix_path.size() == kMaxProtocolPathLayers);

    PFL_EXPECT(!builder.push(LayerKey::tcp()));
    PFL_EXPECT(builder.overflowed());
    PFL_EXPECT(builder.full());
    PFL_EXPECT(builder.size() == kMaxProtocolPathLayers);
    PFL_EXPECT(builder.to_path() == prefix_path);

    PFL_EXPECT(!builder.push(LayerKey::udp()));
    PFL_EXPECT(builder.overflowed());
    PFL_EXPECT(builder.size() == kMaxProtocolPathLayers);
    PFL_EXPECT(builder.to_path() == prefix_path);
}

void expect_decode_attaches_direct_and_shim_protocol_paths() {
    {
        const auto packet = make_ethernet_ipv4_tcp_packet(ipv4(192, 0, 2, 10), ipv4(198, 51, 100, 20), 49152, 443);
        const auto capture_path = write_temp_pcap(
            "pfl_protocol_path_direct_ipv4_tcp.pcap",
            make_classic_pcap({{100U, packet}})
        );
        const auto state = require_imported_capture_state(capture_path);
        PFL_EXPECT(require_packet_protocol_path_text(state, 0U) == "EthernetII -> IPv4 -> TCP");
    }

    {
        const auto state = require_imported_capture_state(fixture_path("parsing/sctp/16_sctp_vlan_ipv4_data_s1ap.pcap"));
        PFL_EXPECT(require_packet_protocol_path_text(state, 0U) == "EthernetII -> VLAN(vid=132) -> IPv4 -> SCTP");
    }

    {
        const auto state = require_imported_capture_state(fixture_path("parsing/mpls/01_mpls_ipv4_tcp_single_label.pcap"));
        PFL_EXPECT(require_packet_protocol_path_text(state, 0U) == "EthernetII -> MPLS(label=100) -> IPv4 -> TCP");
    }
}

void expect_decode_attaches_overlay_protocol_paths() {
    {
        const auto state = require_imported_capture_state(fixture_path("parsing/sctp/18_sctp_vxlan_inner_ipv4_data_s1ap.pcap"));
        PFL_EXPECT(
            require_packet_protocol_path_text(state, 0U) ==
            "EthernetII -> IPv4 -> UDP -> VXLAN(vni=132) -> EthernetII -> IPv4 -> SCTP");
    }

    {
        const auto state = require_imported_capture_state(fixture_path("parsing/sctp/19_sctp_geneve_inner_ipv4_data_m3ua.pcap"));
        PFL_EXPECT(
            require_packet_protocol_path_text(state, 0U) ==
            "EthernetII -> IPv4 -> UDP -> Geneve(vni=132) -> EthernetII -> IPv4 -> SCTP");
    }

    {
        const auto state = require_imported_capture_state(fixture_path("parsing/sctp/20_sctp_gtpu_inner_ipv4_data_s1ap.pcap"));
        PFL_EXPECT(
            require_packet_protocol_path_text(state, 0U) ==
            "EthernetII -> IPv4 -> UDP -> GTP-U(teid=0x01020384) -> IPv4 -> SCTP");
    }
}

void expect_same_inner_tuple_different_vni_splits_into_two_flows() {
    const auto state = require_imported_capture_state(fixture_path("parsing/vxlan/10_vxlan_same_inner_tuple_different_vni.pcap"));

    const auto connections = state.ipv4_connections.list();
    PFL_REQUIRE(connections.size() == 2U);

    const auto* first_packet = find_packet_ref(state, 0U);
    const auto* second_packet = find_packet_ref(state, 1U);
    PFL_REQUIRE(first_packet != nullptr);
    PFL_REQUIRE(second_packet != nullptr);
    PFL_REQUIRE(first_packet->protocol_path_id != kInvalidProtocolPathId);
    PFL_REQUIRE(second_packet->protocol_path_id != kInvalidProtocolPathId);
    PFL_EXPECT(first_packet->protocol_path_id != second_packet->protocol_path_id);

    const auto* first_path = state.protocol_path_registry.find(first_packet->protocol_path_id);
    const auto* second_path = state.protocol_path_registry.find(second_packet->protocol_path_id);
    PFL_REQUIRE(first_path != nullptr);
    PFL_REQUIRE(second_path != nullptr);
    PFL_EXPECT(format_protocol_path(*first_path) == "EthernetII -> IPv4 -> UDP -> VXLAN(vni=100) -> EthernetII -> IPv4 -> TCP");
    PFL_EXPECT(format_protocol_path(*second_path) == "EthernetII -> IPv4 -> UDP -> VXLAN(vni=200) -> EthernetII -> IPv4 -> TCP");
}

void expect_gtpu_same_inner_tuple_different_teid_splits_into_two_flows() {
    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(fixture_path("parsing/gtpu/21_gtpu_same_inner_tuple_different_teid.pcap")));
    PFL_EXPECT(session.list_flows().size() == 2U);

    const auto& state = session.state();
    const auto* first_packet = find_packet_ref(state, 0U);
    const auto* second_packet = find_packet_ref(state, 1U);
    PFL_REQUIRE(first_packet != nullptr);
    PFL_REQUIRE(second_packet != nullptr);
    PFL_REQUIRE(first_packet->protocol_path_id != kInvalidProtocolPathId);
    PFL_REQUIRE(second_packet->protocol_path_id != kInvalidProtocolPathId);
    PFL_EXPECT(first_packet->protocol_path_id != second_packet->protocol_path_id);
    PFL_EXPECT(
        require_packet_protocol_path_text(state, 0U) ==
        "EthernetII -> IPv4 -> UDP -> GTP-U(teid=0x01020304) -> IPv4 -> TCP");
    PFL_EXPECT(
        require_packet_protocol_path_text(state, 1U) ==
        "EthernetII -> IPv4 -> UDP -> GTP-U(teid=0x11223344) -> IPv4 -> TCP");
}

void expect_mpls_same_inner_tuple_different_labels_splits_into_two_flows() {
    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(fixture_path("parsing/mpls/23_mpls_same_inner_flow_different_labels.pcap")));
    PFL_EXPECT(session.list_flows().size() == 2U);

    const auto& state = session.state();
    const auto* first_packet = find_packet_ref(state, 0U);
    const auto* second_packet = find_packet_ref(state, 1U);
    PFL_REQUIRE(first_packet != nullptr);
    PFL_REQUIRE(second_packet != nullptr);
    PFL_REQUIRE(first_packet->protocol_path_id != kInvalidProtocolPathId);
    PFL_REQUIRE(second_packet->protocol_path_id != kInvalidProtocolPathId);
    PFL_EXPECT(first_packet->protocol_path_id != second_packet->protocol_path_id);
    PFL_EXPECT(require_packet_protocol_path_text(state, 0U) == "EthernetII -> MPLS(label=1100) -> IPv4 -> TCP");
    PFL_EXPECT(require_packet_protocol_path_text(state, 1U) == "EthernetII -> MPLS(label=1200) -> IPv4 -> TCP");
}

void expect_same_exact_path_reverse_tuple_stays_bidirectional() {
    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(fixture_path("parsing/vxlan/11_vxlan_inner_ipv4_tcp_bidirectional.pcap")));
    const auto rows = session.list_flows();
    PFL_REQUIRE(rows.size() == 1U);
    PFL_EXPECT(rows[0].packet_count == 2U);

    const auto& state = session.state();
    const auto* first_packet = find_packet_ref(state, 0U);
    const auto* second_packet = find_packet_ref(state, 1U);
    PFL_REQUIRE(first_packet != nullptr);
    PFL_REQUIRE(second_packet != nullptr);
    PFL_REQUIRE(first_packet->protocol_path_id != kInvalidProtocolPathId);
    PFL_REQUIRE(second_packet->protocol_path_id != kInvalidProtocolPathId);
    PFL_EXPECT(first_packet->protocol_path_id == second_packet->protocol_path_id);
    PFL_EXPECT(
        require_packet_protocol_path_text(state, 0U) ==
        "EthernetII -> IPv4 -> UDP -> VXLAN(vni=100) -> EthernetII -> IPv4 -> TCP");
    PFL_EXPECT(
        require_packet_protocol_path_text(state, 1U) ==
        "EthernetII -> IPv4 -> UDP -> VXLAN(vni=100) -> EthernetII -> IPv4 -> TCP");
}

void expect_tls_quic_constricted_fixtures_do_not_split_into_multiple_protocol_paths() {
    struct FixtureExpectation {
        std::filesystem::path relative_path {};
        std::uint64_t expected_packet_count {0};
    };

    const std::vector<FixtureExpectation> fixtures {
        {.relative_path = "parsing/tls/ipv4_tls_constricted_1.pcap", .expected_packet_count = 14U},
        {.relative_path = "parsing/tls/ipv6_tls_constricted_1.pcap", .expected_packet_count = 19U},
        {.relative_path = "parsing/tls/ipv6_tls_strong_constrict_1.pcap", .expected_packet_count = 19U},
        {.relative_path = "parsing/quic/quic_constricted_1.pcap", .expected_packet_count = 18U},
        {.relative_path = "parsing/quic/ipv6_quic_constricted_1.pcap", .expected_packet_count = 16U},
        {.relative_path = "parsing/quic/quic_initial_ack_decrypt_ok_1.pcap", .expected_packet_count = 8U},
        {.relative_path = "parsing/quic/quic_initial_ack_wrong_pkn_1.pcap", .expected_packet_count = 8U},
    };

    const auto fast_options = fast_import_options();

    for (const auto& fixture : fixtures) {
        CaptureSession session {};
        const auto full_path = fixture_path(fixture.relative_path);
        PFL_REQUIRE(session.open_capture(full_path, fast_options));

        const auto rows = session.list_flows();
        const auto diagnostics = format_fixture_flow_diagnostics(fixture.relative_path, session);
        if (rows.size() != 1U) {
            record_failure_message(diagnostics);
        }
        PFL_EXPECT(rows.size() == 1U);

        std::map<std::string, std::set<std::string>> tuple_path_ids {};
        std::map<std::string, std::set<std::string>> payloadless_tuple_path_ids {};
        std::map<std::string, std::set<std::string>> payloadbearing_tuple_path_ids {};
        bool saw_invalid_protocol_path_id = false;

        for (std::size_t flow_index = 0U; flow_index < rows.size(); ++flow_index) {
            const auto packets = session.flow_packets(flow_index);
            const auto packet_rows = session.list_flow_packets(flow_index);
            PFL_REQUIRE(packets.has_value());

            const auto& row = rows[flow_index];
            const auto tuple_text = row.endpoint_a + " <-> " + row.endpoint_b + " [" + row.protocol_text + "]";

            if (row.packet_count != fixture.expected_packet_count) {
                record_failure_message(diagnostics);
            }
            PFL_EXPECT(row.packet_count == fixture.expected_packet_count);
            if (packet_rows.size() != static_cast<std::size_t>(fixture.expected_packet_count)) {
                record_failure_message(diagnostics);
            }
            PFL_EXPECT(packet_rows.size() == static_cast<std::size_t>(fixture.expected_packet_count));
            if (!packet_rows.empty()) {
                PFL_EXPECT(packet_rows.front().row_number == 1U);
                PFL_EXPECT(packet_rows.back().row_number == fixture.expected_packet_count);
            }

            for (const auto& packet : *packets) {
                if (packet.protocol_path_id == kInvalidProtocolPathId) {
                    saw_invalid_protocol_path_id = true;
                }

                const auto normalized_path_text =
                    normalized_protocol_path_text_for_flow_identity(session.state(), packet.protocol_path_id);
                tuple_path_ids[tuple_text].insert(normalized_path_text);
                if (packet.payload_length == 0U) {
                    payloadless_tuple_path_ids[tuple_text].insert(normalized_path_text);
                } else {
                    payloadbearing_tuple_path_ids[tuple_text].insert(normalized_path_text);
                }
            }
        }

        bool same_tuple_split_across_protocol_paths = false;
        bool payloadless_packets_use_distinct_protocol_paths = false;
        for (const auto& [tuple_text, path_ids] : tuple_path_ids) {
            if (path_ids.size() > 1U) {
                same_tuple_split_across_protocol_paths = true;
            }

            const auto payloadless = payloadless_tuple_path_ids.find(tuple_text);
            const auto payloadbearing = payloadbearing_tuple_path_ids.find(tuple_text);
            if (payloadless != payloadless_tuple_path_ids.end() &&
                payloadbearing != payloadbearing_tuple_path_ids.end() &&
                payloadless->second != payloadbearing->second) {
                payloadless_packets_use_distinct_protocol_paths = true;
            }
        }

        if (saw_invalid_protocol_path_id ||
            same_tuple_split_across_protocol_paths ||
            payloadless_packets_use_distinct_protocol_paths) {
            record_failure_message(diagnostics);
        }

        PFL_EXPECT(!saw_invalid_protocol_path_id);
        PFL_EXPECT(!same_tuple_split_across_protocol_paths);
        PFL_EXPECT(!payloadless_packets_use_distinct_protocol_paths);
    }
}

}  // namespace

void run_protocol_path_tests() {
    expect_layer_key_equality();
    expect_protocol_path_ordered_equality();
    expect_identifier_differences();
    expect_registry_interning();
    expect_formatting();
    expect_protocol_path_presentation_mapping();
    expect_flow_rows_expose_protocol_path_presentation();
    expect_frontend_flows_expose_protocol_path_presentation();
    expect_builder_empty_state();
    expect_builder_push_order();
    expect_builder_identifier_layers();
    expect_builder_clear_and_reuse();
    expect_builder_capacity_and_overflow();
    expect_decode_attaches_direct_and_shim_protocol_paths();
    expect_decode_attaches_overlay_protocol_paths();
    expect_same_inner_tuple_different_vni_splits_into_two_flows();
    expect_gtpu_same_inner_tuple_different_teid_splits_into_two_flows();
    expect_mpls_same_inner_tuple_different_labels_splits_into_two_flows();
    expect_same_exact_path_reverse_tuple_stays_bidirectional();
    expect_tls_quic_constricted_fixtures_do_not_split_into_multiple_protocol_paths();
}

}  // namespace pfl::tests
