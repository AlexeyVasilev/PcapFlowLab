#include <algorithm>
#include <array>
#include <filesystem>
#include <functional>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <utility>

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

std::optional<ProtocolPathId> find_packet_flow_protocol_path_id(const CaptureState& state, const std::uint64_t packet_index) {
    for (const auto* connection : state.ipv4_connections.list()) {
        for (const auto& packet : connection->flow_a.packets) {
            if (packet.packet_index == packet_index) {
                return connection->key.protocol_path_id;
            }
        }
        for (const auto& packet : connection->flow_b.packets) {
            if (packet.packet_index == packet_index) {
                return connection->key.protocol_path_id;
            }
        }
    }

    for (const auto* connection : state.ipv6_connections.list()) {
        for (const auto& packet : connection->flow_a.packets) {
            if (packet.packet_index == packet_index) {
                return connection->key.protocol_path_id;
            }
        }
        for (const auto& packet : connection->flow_b.packets) {
            if (packet.packet_index == packet_index) {
                return connection->key.protocol_path_id;
            }
        }
    }

    return std::nullopt;
}

ProtocolPathId require_packet_flow_protocol_path_id(const CaptureState& state, const std::uint64_t packet_index) {
    const auto path_id = find_packet_flow_protocol_path_id(state, packet_index);
    PFL_REQUIRE(path_id.has_value());
    PFL_REQUIRE(*path_id != kInvalidProtocolPathId);
    return *path_id;
}

std::string require_packet_protocol_path_text(const CaptureState& state, const std::uint64_t packet_index) {
    const auto path_id = require_packet_flow_protocol_path_id(state, packet_index);
    const auto* path = state.protocol_path_registry.find(path_id);
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

const FrontendProtocolPathPresentationDto* find_frontend_protocol_path_presentation(
    const std::vector<FrontendProtocolPathPresentationDto>& presentations,
    const ProtocolPathId protocol_path_id
) {
    const auto found = std::find_if(presentations.begin(), presentations.end(), [protocol_path_id](const auto& row) {
        return row.protocol_path_id == protocol_path_id;
    });
    return found == presentations.end() ? nullptr : &*found;
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
        const auto path_id = find_packet_flow_protocol_path_id(state, packet.packet_index).value_or(kInvalidProtocolPathId);
        packets_by_path[path_id].push_back(packet.packet_index);
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

const ProtocolPathStatisticsRow* find_protocol_path_stats_row(
    const CaptureProtocolPathSummary& summary,
    const std::string& path_text
) {
    const auto found = std::find_if(summary.rows.begin(), summary.rows.end(), [&](const auto& row) {
        return row.path_text == path_text;
    });
    return found == summary.rows.end() ? nullptr : &(*found);
}

const ProtocolPathStatisticsRow* find_protocol_path_stats_row_by_node_id(
    const CaptureProtocolPathSummary& summary,
    const std::uint64_t node_id
) {
    const auto found = std::find_if(summary.rows.begin(), summary.rows.end(), [&](const auto& row) {
        return row.node_id == node_id;
    });
    return found == summary.rows.end() ? nullptr : &(*found);
}

void expect_protocol_path_stats_membership(
    const CaptureSession& session,
    const CaptureProtocolPathSummary& summary,
    const ProtocolPathStatisticsMode mode,
    const std::string& path_text,
    const std::vector<FlowIndex>& expected_flow_indices
) {
    const auto* row = find_protocol_path_stats_row(summary, path_text);
    PFL_REQUIRE(row != nullptr);
    const auto actual_flow_indices = session.protocol_path_summary_flow_indices(mode, row->node_id);
    PFL_EXPECT(actual_flow_indices == expected_flow_indices);
    PFL_EXPECT(actual_flow_indices.size() == row->flow_count);
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

void expect_protocol_path_stats_layer_text(
    const CaptureProtocolPathSummary& summary,
    const std::string& path_text,
    const std::string& expected_layer_text
) {
    const auto* row = find_protocol_path_stats_row(summary, path_text);
    PFL_REQUIRE(row != nullptr);
    PFL_EXPECT(row->layer_text == expected_layer_text);
}

void expect_no_protocol_path_stats_row(
    const CaptureProtocolPathSummary& summary,
    const std::string& path_text
) {
    PFL_EXPECT(find_protocol_path_stats_row(summary, path_text) == nullptr);
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
    ProtocolPathBuilder empty_builder {};
    const ProtocolPath empty_path {};

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
    PFL_EXPECT(registry.intern(empty_builder.view()) == kInvalidProtocolPathId);
    PFL_EXPECT(registry.size() == 0U);
    PFL_EXPECT(registry.intern(empty_path) == kInvalidProtocolPathId);
    PFL_EXPECT(registry.size() == 0U);
    PFL_EXPECT(registry.intern(ProtocolPath {}) == kInvalidProtocolPathId);
    PFL_EXPECT(registry.size() == 0U);

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
    PFL_EXPECT(registry.intern(ProtocolPath {}) == kInvalidProtocolPathId);
    PFL_EXPECT(registry.size() == 2U);

    const auto* stored_direct = registry.find(direct_id);
    const auto* stored_shim = registry.find(shim_id);
    PFL_REQUIRE(stored_direct != nullptr);
    PFL_REQUIRE(stored_shim != nullptr);
    PFL_EXPECT(*stored_direct == direct);
    PFL_EXPECT(*stored_shim == shim);
}

void expect_registry_view_interning() {
    ProtocolPathRegistry registry {};
    ProtocolPathBuilder empty_builder {};

    ProtocolPathBuilder direct_builder {};
    PFL_EXPECT(direct_builder.push(LayerKey::ethernet_ii()));
    PFL_EXPECT(direct_builder.push(LayerKey::ipv4()));
    PFL_EXPECT(direct_builder.push(LayerKey::tcp()));

    ProtocolPathBuilder direct_copy_builder {};
    PFL_EXPECT(direct_copy_builder.push(LayerKey::ethernet_ii()));
    PFL_EXPECT(direct_copy_builder.push(LayerKey::ipv4()));
    PFL_EXPECT(direct_copy_builder.push(LayerKey::tcp()));

    ProtocolPathBuilder shim_builder {};
    PFL_EXPECT(shim_builder.push(LayerKey::ethernet_ii()));
    PFL_EXPECT(shim_builder.push(LayerKey::mpls(102U)));
    PFL_EXPECT(shim_builder.push(LayerKey::vlan(200U)));
    PFL_EXPECT(shim_builder.push(LayerKey::ipv4()));
    PFL_EXPECT(shim_builder.push(LayerKey::tcp()));

    PFL_EXPECT(registry.intern(empty_builder.view()) == kInvalidProtocolPathId);
    PFL_EXPECT(registry.size() == 0U);

    const auto direct_id = registry.intern(direct_builder.view());
    const auto direct_copy_id = registry.intern(direct_copy_builder.view());
    const auto shim_id = registry.intern(shim_builder.view());

    PFL_EXPECT(direct_id == 1U);
    PFL_EXPECT(direct_copy_id == direct_id);
    PFL_EXPECT(shim_id == 2U);
    PFL_EXPECT(registry.size() == 2U);
    PFL_EXPECT(registry.intern(empty_builder.view()) == kInvalidProtocolPathId);
    PFL_EXPECT(registry.size() == 2U);

    const auto* stored_direct = registry.find(direct_id);
    const auto* stored_shim = registry.find(shim_id);
    PFL_REQUIRE(stored_direct != nullptr);
    PFL_REQUIRE(stored_shim != nullptr);
    PFL_EXPECT(format_protocol_path(*stored_direct) == "EthernetII -> IPv4 -> TCP");
    PFL_EXPECT(format_protocol_path(*stored_shim) == "EthernetII -> MPLS(label=102) -> VLAN(vid=200) -> IPv4 -> TCP");
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
    const ProtocolPath llc_snap {
        LayerKey::ieee8023(),
        LayerKey::llc_snap(),
        LayerKey::ipv4(),
        LayerKey::tcp(),
    };
    const ProtocolPath mpls_pw {
        LayerKey::ethernet_ii(),
        LayerKey::mpls(24050U),
        LayerKey::mpls(16050U),
        LayerKey::mpls_pw(),
        LayerKey::ethernet_ii(),
        LayerKey::ipv4(),
        LayerKey::tcp(),
    };
    const ProtocolPath pbb {
        LayerKey::ethernet_ii(),
        LayerKey::pbb(0x123456U),
        LayerKey::ethernet_ii(),
        LayerKey::ipv4(),
        LayerKey::tcp(),
    };
    const ProtocolPath pppoe {
        LayerKey::ethernet_ii(),
        LayerKey::pppoe(),
        LayerKey::ppp(),
        LayerKey::ipv4(),
        LayerKey::tcp(),
    };
    const ProtocolPath macsec {
        LayerKey::ethernet_ii(),
        LayerKey::macsec(),
    };

    PFL_EXPECT(format_protocol_layer_key(LayerKey::ethernet_ii()) == "EthernetII");
    PFL_EXPECT(format_protocol_layer_key(LayerKey::ieee8023()) == "IEEE 802.3");
    PFL_EXPECT(format_protocol_layer_key(LayerKey::llc_snap()) == "LLC/SNAP");
    PFL_EXPECT(format_protocol_layer_key(LayerKey::ipv4()) == "IPv4");
    PFL_EXPECT(format_protocol_layer_key(LayerKey::tcp()) == "TCP");
    PFL_EXPECT(format_protocol_layer_key(LayerKey::vlan(200U)) == "VLAN(vid=200)");
    PFL_EXPECT(format_protocol_layer_key(LayerKey::mpls(102U)) == "MPLS(label=102)");
    PFL_EXPECT(format_protocol_layer_key(LayerKey::mpls_pw()) == "MPLS PW");
    PFL_EXPECT(format_protocol_layer_key(LayerKey::pbb(0x123456U)) == "PBB(isid=0x123456)");
    PFL_EXPECT(format_protocol_layer_key(LayerKey::pppoe()) == "PPPoE");
    PFL_EXPECT(format_protocol_layer_key(LayerKey::ppp()) == "PPP");
    PFL_EXPECT(format_protocol_layer_key(LayerKey::macsec()) == "MACsec");
    PFL_EXPECT(format_protocol_layer_key(LayerKey::vxlan(100U)) == "VXLAN(vni=100)");
    PFL_EXPECT(format_protocol_layer_key(LayerKey::geneve(200U)) == "Geneve(vni=200)");
    PFL_EXPECT(format_protocol_layer_key(LayerKey::gtpu(0x01020384U)) == "GTP-U(teid=0x01020384)");

    PFL_EXPECT(format_protocol_path(direct) == "EthernetII -> IPv4 -> TCP");
    PFL_EXPECT(format_protocol_path(shim) == "EthernetII -> MPLS(label=102) -> VLAN(vid=200) -> IPv4 -> TCP");
    PFL_EXPECT(format_protocol_path(vxlan) == "EthernetII -> IPv4 -> UDP -> VXLAN(vni=100) -> EthernetII -> IPv4 -> TCP");
    PFL_EXPECT(format_protocol_path(gtpu) == "EthernetII -> IPv4 -> UDP -> GTP-U(teid=0x01020384) -> IPv4 -> SCTP");
    PFL_EXPECT(format_protocol_path(llc_snap) == "IEEE 802.3 -> LLC/SNAP -> IPv4 -> TCP");
    PFL_EXPECT(format_protocol_path(mpls_pw)
        == "EthernetII -> MPLS(label=24050) -> MPLS(label=16050) -> MPLS PW -> EthernetII -> IPv4 -> TCP");
    PFL_EXPECT(format_protocol_path(pbb) == "EthernetII -> PBB(isid=0x123456) -> EthernetII -> IPv4 -> TCP");
    PFL_EXPECT(format_protocol_path(pppoe) == "EthernetII -> PPPoE -> PPP -> IPv4 -> TCP");
    PFL_EXPECT(format_protocol_path(macsec) == "EthernetII -> MACsec");
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
    const ProtocolPath llc_snap {
        LayerKey::ieee8023(),
        LayerKey::llc_snap(),
        LayerKey::ipv4(),
        LayerKey::tcp(),
    };
    const ProtocolPath pbb {
        LayerKey::ethernet_ii(),
        LayerKey::pbb(0x123456U),
        LayerKey::ieee8023(),
        LayerKey::llc_snap(),
        LayerKey::ipv4(),
        LayerKey::udp(),
    };
    const ProtocolPath pppoe {
        LayerKey::ethernet_ii(),
        LayerKey::pppoe(),
        LayerKey::ppp(),
        LayerKey::ipv4(),
        LayerKey::tcp(),
    };
    const ProtocolPath macsec {
        LayerKey::ethernet_ii(),
        LayerKey::macsec(),
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

    const auto llc_presentation = session_detail::build_protocol_path_presentation(&llc_snap);
    PFL_EXPECT(llc_presentation.compact_text == "802.3|LLC|Ip4|TCP");
    PFL_EXPECT(llc_presentation.badges[1].full_name == "LLC/SNAP");
    PFL_EXPECT(llc_presentation.badges[1].color_key == "shim");

    const auto pbb_presentation = session_detail::build_protocol_path_presentation(&pbb);
    PFL_EXPECT(pbb_presentation.badges[1].short_label == "PBB");
    PFL_EXPECT(pbb_presentation.badges[1].tooltip == "PBB\nI-SID: 0x123456");
    PFL_EXPECT(pbb_presentation.badges[2].short_label == "802.3");
    PFL_EXPECT(pbb_presentation.badges[3].short_label == "LLC");

    const auto pppoe_presentation = session_detail::build_protocol_path_presentation(&pppoe);
    PFL_EXPECT(pppoe_presentation.compact_text == "EII|PPPoE|PPP|Ip4|TCP");
    PFL_EXPECT(pppoe_presentation.badges[1].full_name == "PPPoE");
    PFL_EXPECT(pppoe_presentation.badges[2].full_name == "PPP");

    const auto macsec_presentation = session_detail::build_protocol_path_presentation(&macsec);
    PFL_EXPECT(macsec_presentation.compact_text == "EII|MS");
    PFL_EXPECT(macsec_presentation.badges[1].full_name == "MACsec");
    PFL_EXPECT(macsec_presentation.badges[1].color_key == "security");

    const auto unknown_presentation = session_detail::build_protocol_path_presentation(nullptr);
    PFL_EXPECT(unknown_presentation.full_text == "Unknown protocol path");
    PFL_EXPECT(unknown_presentation.compact_text == "?");
    PFL_REQUIRE(unknown_presentation.badges.size() == 1U);
    PFL_EXPECT(unknown_presentation.badges[0].short_label == "?");

    const auto legend = session_detail::protocol_path_legend_entries();
    PFL_EXPECT(legend.size() == 22U);
    PFL_EXPECT(legend.front().short_label == "EII");
    PFL_REQUIRE(legend.size() >= 6U);
    PFL_EXPECT(legend[1].short_label == "802.3");
    PFL_EXPECT(legend[2].short_label == "SLL");
    PFL_EXPECT(legend[3].short_label == "SLL2");
    PFL_EXPECT(legend[4].short_label == "LLC");
    PFL_EXPECT(legend[5].short_label == "Vl");
    PFL_EXPECT(legend.back().short_label == "?");
    PFL_EXPECT(legend.back().full_name == "Unknown");
    PFL_EXPECT(std::any_of(legend.begin(), legend.end(), [](const auto& entry) { return entry.short_label == "LLC"; }));
    PFL_EXPECT(std::any_of(legend.begin(), legend.end(), [](const auto& entry) { return entry.short_label == "PW"; }));
    PFL_EXPECT(std::any_of(legend.begin(), legend.end(), [](const auto& entry) { return entry.short_label == "PBB"; }));
    PFL_EXPECT(std::any_of(legend.begin(), legend.end(), [](const auto& entry) { return entry.short_label == "PPPoE"; }));
    PFL_EXPECT(std::any_of(legend.begin(), legend.end(), [](const auto& entry) { return entry.short_label == "PPP"; }));
    PFL_EXPECT(std::any_of(legend.begin(), legend.end(), [](const auto& entry) { return entry.short_label == "MS"; }));
    PFL_EXPECT(!std::any_of(legend.begin(), legend.end(), [](const auto& entry) { return entry.short_label == "ARP"; }));
    PFL_EXPECT(!std::any_of(legend.begin(), legend.end(), [](const auto& entry) { return entry.short_label == "ICMP"; }));
    PFL_EXPECT(!std::any_of(legend.begin(), legend.end(), [](const auto& entry) { return entry.short_label == "ICMP6"; }));

    PFL_EXPECT(session_detail::format_protocol_path_layer_display_text(LayerKey::ethernet_ii()) == "Ethernet II");
    PFL_EXPECT(session_detail::format_protocol_path_layer_display_text(LayerKey::ieee8023()) == "IEEE 802.3");
    PFL_EXPECT(session_detail::format_protocol_path_layer_display_text(LayerKey::llc_snap()) == "LLC/SNAP");
    PFL_EXPECT(session_detail::format_protocol_path_layer_display_text(LayerKey::ipv4()) == "IPv4");
    PFL_EXPECT(session_detail::format_protocol_path_layer_display_text(LayerKey::vlan(200U)) == "VLAN (VID 200)");
    PFL_EXPECT(session_detail::format_protocol_path_layer_display_text(LayerKey::mpls(102U)) == "MPLS (label 102)");
    PFL_EXPECT(session_detail::format_protocol_path_layer_display_text(LayerKey::mpls_pw()) == "MPLS PW");
    PFL_EXPECT(session_detail::format_protocol_path_layer_display_text(LayerKey::pbb(0x123456U)) == "PBB (I-SID 0x123456)");
    PFL_EXPECT(session_detail::format_protocol_path_layer_display_text(LayerKey::pppoe()) == "PPPoE");
    PFL_EXPECT(session_detail::format_protocol_path_layer_display_text(LayerKey::ppp()) == "PPP");
    PFL_EXPECT(session_detail::format_protocol_path_layer_display_text(LayerKey::macsec()) == "MACsec");
    PFL_EXPECT(session_detail::format_protocol_path_layer_display_text(LayerKey::vxlan(100U)) == "VXLAN (VNI 100)");
    PFL_EXPECT(session_detail::format_protocol_path_layer_display_text(LayerKey::geneve(100U)) == "Geneve (VNI 100)");
    PFL_EXPECT(session_detail::format_protocol_path_layer_display_text(LayerKey::gtpu(0x01020384U)) == "GTP-U (TEID 0x01020384)");
}

void expect_flow_rows_expose_protocol_path_presentation() {
    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/vxlan/01_vxlan_inner_ipv4_tcp.pcap")));
        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 1U);
        PFL_REQUIRE(rows[0].protocol_path_id != kInvalidProtocolPathId);
        const auto presentation = session_detail::build_protocol_path_presentation(
            session.state().protocol_path_registry,
            rows[0].protocol_path_id
        );
        PFL_EXPECT(presentation.full_text == "EthernetII -> IPv4 -> UDP -> VXLAN(vni=100) -> EthernetII -> IPv4 -> TCP");
        PFL_EXPECT(presentation.compact_text == "EII|Ip4|UDP|Vx|EII|Ip4|TCP");
        PFL_REQUIRE(presentation.badges.size() == 7U);
        PFL_EXPECT(presentation.badges[3].tooltip == "VXLAN\nVNI: 100");
    }

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/gtpu/01_gtpu_inner_ipv4_tcp.pcap")));
        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 1U);
        PFL_REQUIRE(rows[0].protocol_path_id != kInvalidProtocolPathId);
        const auto presentation = session_detail::build_protocol_path_presentation(
            session.state().protocol_path_registry,
            rows[0].protocol_path_id
        );
        PFL_EXPECT(presentation.full_text == "EthernetII -> IPv4 -> UDP -> GTP-U(teid=0x01020304) -> IPv4 -> TCP");
        PFL_EXPECT(presentation.compact_text == "EII|Ip4|UDP|GTP-U|Ip4|TCP");
        PFL_REQUIRE(presentation.badges.size() == 6U);
        PFL_EXPECT(presentation.badges[3].tooltip == "GTP-U\nTEID: 0x01020304");
    }
}

void expect_frontend_flows_expose_protocol_path_presentation() {
    FrontendSessionAdapter adapter {};
    PFL_REQUIRE(adapter.open_capture(fixture_path("parsing/vxlan/01_vxlan_inner_ipv4_tcp.pcap"), FrontendOpenMode::fast).opened);

    const auto flows = adapter.get_flows();
    const auto overview = adapter.get_overview();
    PFL_REQUIRE(flows.size() == 1U);
    PFL_REQUIRE(flows[0].protocol_path_id != kInvalidProtocolPathId);
    const auto* presentation = find_frontend_protocol_path_presentation(
        overview.protocol_path_presentations,
        flows[0].protocol_path_id
    );
    PFL_REQUIRE(presentation != nullptr);
    PFL_EXPECT(presentation->path_text == "EthernetII -> IPv4 -> UDP -> VXLAN(vni=100) -> EthernetII -> IPv4 -> TCP");
    PFL_EXPECT(presentation->compact_text == "EII|Ip4|UDP|Vx|EII|Ip4|TCP");
    PFL_REQUIRE(presentation->badges.size() == 7U);
    PFL_EXPECT(presentation->badges[3].short_label == "Vx");
    PFL_EXPECT(presentation->badges[3].tooltip == "VXLAN\nVNI: 100");
}

void expect_frontend_protocol_path_legend_exposure() {
    FrontendSessionAdapter adapter {};
    const auto legend = adapter.get_protocol_path_legend();

    PFL_REQUIRE(legend.size() == 22U);
    PFL_EXPECT(legend.front().short_label == "EII");
    PFL_REQUIRE(legend.size() >= 6U);
    PFL_EXPECT(legend[1].short_label == "802.3");
    PFL_EXPECT(legend[2].short_label == "SLL");
    PFL_EXPECT(legend[3].short_label == "SLL2");
    PFL_EXPECT(legend[4].short_label == "LLC");
    PFL_EXPECT(legend[5].short_label == "Vl");
    PFL_EXPECT(legend.back().short_label == "?");
    PFL_EXPECT(legend.back().full_name == "Unknown");

    const auto contains_short_label = [&](const std::string& short_label) {
        return std::any_of(legend.begin(), legend.end(), [&](const auto& entry) {
            return entry.short_label == short_label;
        });
    };

    PFL_EXPECT(contains_short_label("EII"));
    PFL_EXPECT(contains_short_label("LLC"));
    PFL_EXPECT(contains_short_label("Vl"));
    PFL_EXPECT(contains_short_label("M"));
    PFL_EXPECT(contains_short_label("PW"));
    PFL_EXPECT(contains_short_label("PBB"));
    PFL_EXPECT(contains_short_label("PPPoE"));
    PFL_EXPECT(contains_short_label("PPP"));
    PFL_EXPECT(contains_short_label("MS"));
    PFL_EXPECT(contains_short_label("Ip4"));
    PFL_EXPECT(contains_short_label("UDP"));
    PFL_EXPECT(contains_short_label("Vx"));
    PFL_EXPECT(contains_short_label("GTP-U"));
    PFL_EXPECT(contains_short_label("?"));
    PFL_EXPECT(!contains_short_label("ARP"));
    PFL_EXPECT(!contains_short_label("ICMP"));
    PFL_EXPECT(!contains_short_label("ICMP6"));
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

    {
        const auto state = require_imported_capture_state(fixture_path("parsing/mpls/13_vlan_mpls_ipv4_tcp.pcap"));
        PFL_EXPECT(require_packet_protocol_path_text(state, 0U) == "EthernetII -> VLAN(vid=100) -> MPLS(label=500) -> IPv4 -> TCP");
    }

    {
        const auto state = require_imported_capture_state(fixture_path("parsing/mpls/14_qinq_mpls_ipv4_udp.pcap"));
        PFL_EXPECT(
            require_packet_protocol_path_text(state, 0U) ==
            "EthernetII -> VLAN(vid=100) -> VLAN(vid=200) -> MPLS(label=501) -> IPv4 -> UDP");
    }

    {
        const auto state = require_imported_capture_state(fixture_path("parsing/llc_snap/01_llc_snap_ipv4_tcp.pcap"));
        PFL_EXPECT(require_packet_protocol_path_text(state, 0U) == "IEEE 802.3 -> LLC/SNAP -> IPv4 -> TCP");
    }

    {
        const auto state = require_imported_capture_state(fixture_path("parsing/pppoe/01_pppoe_session_ipv4_tcp.pcap"));
        PFL_EXPECT(require_packet_protocol_path_text(state, 0U) == "EthernetII -> PPPoE -> PPP -> IPv4 -> TCP");
    }

    {
        const auto state = require_imported_capture_state(fixture_path("parsing/pbb/01_pbb_ipv4_tcp.pcap"));
        PFL_EXPECT(require_packet_protocol_path_text(state, 0U) == "EthernetII -> PBB(isid=0x123456) -> EthernetII -> IPv4 -> TCP");
    }

    {
        const auto state = require_imported_capture_state(fixture_path("parsing/pbb/08_pbb_inner_llc_snap_ipv4_udp.pcap"));
        PFL_EXPECT(
            require_packet_protocol_path_text(state, 0U) ==
            "EthernetII -> PBB(isid=0x123456) -> IEEE 802.3 -> LLC/SNAP -> IPv4 -> UDP");
    }

    {
        const auto state = require_imported_capture_state(fixture_path("parsing/mpls_pw/01_mpls_pw_eth_ipv4_tcp_no_cw.pcap"));
        PFL_EXPECT(
            require_packet_protocol_path_text(state, 0U) ==
            "EthernetII -> MPLS(label=24050) -> MPLS(label=16050) -> MPLS PW -> EthernetII -> IPv4 -> TCP");
    }

    {
        const auto state = require_imported_capture_state(fixture_path("parsing/mpls_pw/08_mpls_pw_eth_llc_snap_ipv4_udp_cw.pcap"));
        PFL_EXPECT(
            require_packet_protocol_path_text(state, 0U) ==
            "EthernetII -> MPLS(label=24050) -> MPLS(label=16050) -> MPLS PW -> IEEE 802.3 -> LLC/SNAP -> IPv4 -> UDP");
    }
}

void expect_terminal_control_protocols_do_not_appear_in_protocol_paths() {
    {
        const auto capture_path = write_temp_pcap(
            "pfl_protocol_path_arp_cleanup.pcap",
            make_classic_pcap({{100U, make_ethernet_arp_packet(ipv4(192, 168, 1, 10), ipv4(192, 168, 1, 1), 1U)}})
        );
        const auto state = require_imported_capture_state(capture_path);
        PFL_EXPECT(require_packet_protocol_path_text(state, 0U) == "EthernetII");
    }

    {
        const auto capture_path = write_temp_pcap(
            "pfl_protocol_path_icmp_cleanup.pcap",
            make_classic_pcap({{100U, make_ethernet_ipv4_icmp_packet(ipv4(10, 0, 0, 10), ipv4(10, 0, 0, 20), 8U, 0U)}})
        );
        const auto state = require_imported_capture_state(capture_path);
        PFL_EXPECT(require_packet_protocol_path_text(state, 0U) == "EthernetII -> IPv4");
    }

    {
        const auto ipv6_src = ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10});
        const auto ipv6_dst = ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x20});
        const auto capture_path = write_temp_pcap(
            "pfl_protocol_path_icmpv6_cleanup.pcap",
            make_classic_pcap({{100U, make_ethernet_ipv6_icmpv6_with_hop_by_hop_packet(ipv6_src, ipv6_dst, 128U, 0U)}})
        );
        const auto state = require_imported_capture_state(capture_path);
        PFL_EXPECT(require_packet_protocol_path_text(state, 0U) == "EthernetII -> IPv6");
    }
}

void expect_common_case_packets_resolve_to_owning_flow_protocol_path() {
    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/vxlan/01_vxlan_inner_ipv4_tcp.pcap")));
        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 1U);
        const auto packets = session.flow_packets(0U);
        PFL_REQUIRE(packets.has_value());
        PFL_REQUIRE(!packets->empty());
        PFL_REQUIRE(rows[0].protocol_path_id != kInvalidProtocolPathId);
        PFL_EXPECT(require_packet_flow_protocol_path_id(session.state(), (*packets)[0].packet_index) == rows[0].protocol_path_id);
    }

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/sctp/16_sctp_vlan_ipv4_data_s1ap.pcap")));
        const auto rows = session.list_flows();
        PFL_REQUIRE(rows.size() == 1U);
        const auto packets = session.flow_packets(0U);
        PFL_REQUIRE(packets.has_value());
        PFL_REQUIRE(!packets->empty());
        PFL_REQUIRE(rows[0].protocol_path_id != kInvalidProtocolPathId);
        PFL_EXPECT(require_packet_flow_protocol_path_id(session.state(), (*packets)[0].packet_index) == rows[0].protocol_path_id);
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
    const auto first_path_id = require_packet_flow_protocol_path_id(state, 0U);
    const auto second_path_id = require_packet_flow_protocol_path_id(state, 1U);
    PFL_EXPECT(first_path_id != second_path_id);

    const auto* first_path = state.protocol_path_registry.find(first_path_id);
    const auto* second_path = state.protocol_path_registry.find(second_path_id);
    PFL_REQUIRE(first_path != nullptr);
    PFL_REQUIRE(second_path != nullptr);
    PFL_EXPECT(format_protocol_path(*first_path) == "EthernetII -> IPv4 -> UDP -> VXLAN(vni=100) -> EthernetII -> IPv4 -> TCP");
    PFL_EXPECT(format_protocol_path(*second_path) == "EthernetII -> IPv4 -> UDP -> VXLAN(vni=200) -> EthernetII -> IPv4 -> TCP");
}

void expect_protocol_path_statistics_direct_tcp_prefixes() {
    const auto packet = make_ethernet_ipv4_tcp_packet(ipv4(192, 0, 2, 10), ipv4(198, 51, 100, 20), 49152, 443);
    const auto capture_path = write_temp_pcap(
        "pfl_protocol_path_stats_direct_ipv4_tcp.pcap",
        make_classic_pcap({{100U, packet}})
    );

    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(capture_path));

    const auto summary = session.protocol_path_summary();
    PFL_EXPECT(summary.total_original_byte_count > 0U);
    expect_protocol_path_stats_row(summary, "EthernetII", 1U, 1U);
    expect_protocol_path_stats_row(summary, "EthernetII -> IPv4", 1U, 1U);
    expect_protocol_path_stats_row(summary, "EthernetII -> IPv4 -> TCP", 1U, 1U);
    expect_protocol_path_stats_layer_text(summary, "EthernetII", "Ethernet II");
    expect_protocol_path_stats_layer_text(summary, "EthernetII -> IPv4", "IPv4");
    expect_protocol_path_stats_layer_text(summary, "EthernetII -> IPv4 -> TCP", "TCP");
    const auto* terminal_row = find_protocol_path_stats_row(summary, "EthernetII -> IPv4 -> TCP");
    PFL_REQUIRE(terminal_row != nullptr);
    PFL_EXPECT(terminal_row->flow_count_text.find('%') != std::string::npos);
    PFL_EXPECT(terminal_row->packet_count_text.find('%') != std::string::npos);
    PFL_EXPECT(terminal_row->original_byte_count > 0U);
    PFL_EXPECT(terminal_row->original_byte_count_text.find('B') != std::string::npos);
    PFL_EXPECT(terminal_row->original_byte_count_text.find('%') != std::string::npos);
    PFL_EXPECT(terminal_row->flow_percent == 100.0);
    PFL_EXPECT(terminal_row->packet_percent == 100.0);
    PFL_EXPECT(terminal_row->original_byte_percent == 100.0);
}

void expect_protocol_path_statistics_kind_overview_merge_vxlan_vnis() {
    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(fixture_path("parsing/vxlan/10_vxlan_same_inner_tuple_different_vni.pcap")));

    const auto summary = session.protocol_path_summary();
    expect_protocol_path_stats_row(summary, "EthernetII", 2U, 2U);
    expect_protocol_path_stats_row(summary, "EthernetII -> IPv4 -> UDP", 2U, 2U);
    expect_protocol_path_stats_row(
        summary,
        "EthernetII -> IPv4 -> UDP -> VXLAN",
        2U,
        2U
    );
    expect_protocol_path_stats_layer_text(summary, "EthernetII -> IPv4 -> UDP -> VXLAN", "VXLAN");
    expect_protocol_path_stats_row(summary, "EthernetII -> IPv4 -> UDP -> VXLAN -> EthernetII -> IPv4 -> TCP", 2U, 2U);
    expect_protocol_path_stats_membership(
        session,
        summary,
        ProtocolPathStatisticsMode::kind_overview,
        "EthernetII -> IPv4 -> UDP -> VXLAN",
        {0U, 1U}
    );
    expect_no_protocol_path_stats_row(summary, "EthernetII -> IPv4 -> UDP -> VXLAN(vni=100)");
    expect_no_protocol_path_stats_row(summary, "EthernetII -> IPv4 -> UDP -> VXLAN(vni=200)");
}

void expect_protocol_path_statistics_identity_tree_distinguish_vxlan_vnis() {
    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(fixture_path("parsing/vxlan/10_vxlan_same_inner_tuple_different_vni.pcap")));

    const auto summary = session.protocol_path_summary(ProtocolPathStatisticsMode::identity_tree);
    expect_protocol_path_stats_row(summary, "EthernetII", 2U, 2U);
    expect_protocol_path_stats_row(summary, "EthernetII -> IPv4 -> UDP", 2U, 2U);
    expect_protocol_path_stats_row(summary, "EthernetII -> IPv4 -> UDP -> VXLAN(vni=100)", 1U, 1U);
    expect_protocol_path_stats_row(summary, "EthernetII -> IPv4 -> UDP -> VXLAN(vni=200)", 1U, 1U);
    expect_protocol_path_stats_layer_text(summary, "EthernetII -> IPv4 -> UDP -> VXLAN(vni=100)", "VXLAN (VNI 100)");
    expect_protocol_path_stats_layer_text(summary, "EthernetII -> IPv4 -> UDP -> VXLAN(vni=200)", "VXLAN (VNI 200)");
    expect_protocol_path_stats_membership(
        session,
        summary,
        ProtocolPathStatisticsMode::identity_tree,
        "EthernetII -> IPv4 -> UDP -> VXLAN(vni=100)",
        {0U}
    );
    expect_protocol_path_stats_membership(
        session,
        summary,
        ProtocolPathStatisticsMode::identity_tree,
        "EthernetII -> IPv4 -> UDP -> VXLAN(vni=200)",
        {1U}
    );
}

void expect_protocol_path_statistics_kind_overview_merge_gtpu_teids() {
    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(fixture_path("parsing/gtpu/21_gtpu_same_inner_tuple_different_teid.pcap")));

    const auto summary = session.protocol_path_summary();
    expect_protocol_path_stats_row(summary, "EthernetII", 2U, 2U);
    expect_protocol_path_stats_row(summary, "EthernetII -> IPv4 -> UDP", 2U, 2U);
    expect_protocol_path_stats_row(summary, "EthernetII -> IPv4 -> UDP -> GTP-U", 2U, 2U);
    expect_protocol_path_stats_layer_text(summary, "EthernetII -> IPv4 -> UDP -> GTP-U", "GTP-U");
    expect_protocol_path_stats_membership(
        session,
        summary,
        ProtocolPathStatisticsMode::kind_overview,
        "EthernetII -> IPv4 -> UDP -> GTP-U",
        {0U, 1U}
    );
    expect_no_protocol_path_stats_row(summary, "EthernetII -> IPv4 -> UDP -> GTP-U(teid=0x01020304)");
    expect_no_protocol_path_stats_row(summary, "EthernetII -> IPv4 -> UDP -> GTP-U(teid=0x11223344)");
}

void expect_protocol_path_statistics_identity_tree_distinguish_gtpu_teids() {
    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(fixture_path("parsing/gtpu/21_gtpu_same_inner_tuple_different_teid.pcap")));

    const auto summary = session.protocol_path_summary(ProtocolPathStatisticsMode::identity_tree);
    expect_protocol_path_stats_row(summary, "EthernetII -> IPv4 -> UDP -> GTP-U(teid=0x01020304)", 1U, 1U);
    expect_protocol_path_stats_row(summary, "EthernetII -> IPv4 -> UDP -> GTP-U(teid=0x11223344)", 1U, 1U);
    expect_protocol_path_stats_layer_text(summary, "EthernetII -> IPv4 -> UDP -> GTP-U(teid=0x01020304)", "GTP-U (TEID 0x01020304)");
    expect_protocol_path_stats_layer_text(summary, "EthernetII -> IPv4 -> UDP -> GTP-U(teid=0x11223344)", "GTP-U (TEID 0x11223344)");
    expect_protocol_path_stats_membership(
        session,
        summary,
        ProtocolPathStatisticsMode::identity_tree,
        "EthernetII -> IPv4 -> UDP -> GTP-U(teid=0x01020304)",
        {0U}
    );
    expect_protocol_path_stats_membership(
        session,
        summary,
        ProtocolPathStatisticsMode::identity_tree,
        "EthernetII -> IPv4 -> UDP -> GTP-U(teid=0x11223344)",
        {1U}
    );
}

void expect_protocol_path_statistics_preserve_nested_mpls_prefixes_in_kind_overview() {
    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(fixture_path("parsing/mpls/05_mpls_ipv4_tcp_two_labels.pcap")));

    const auto summary = session.protocol_path_summary();
    expect_protocol_path_stats_row(summary, "EthernetII", 1U, 1U);
    expect_protocol_path_stats_row(summary, "EthernetII -> MPLS", 1U, 1U);
    expect_protocol_path_stats_row(summary, "EthernetII -> MPLS -> MPLS", 1U, 1U);
    expect_protocol_path_stats_row(summary, "EthernetII -> MPLS -> MPLS -> IPv4", 1U, 1U);
    expect_protocol_path_stats_row(summary, "EthernetII -> MPLS -> MPLS -> IPv4 -> TCP", 1U, 1U);
    expect_protocol_path_stats_layer_text(summary, "EthernetII -> MPLS", "MPLS");
    expect_protocol_path_stats_layer_text(summary, "EthernetII -> MPLS -> MPLS", "MPLS");
    expect_protocol_path_stats_membership(
        session,
        summary,
        ProtocolPathStatisticsMode::kind_overview,
        "EthernetII -> MPLS -> MPLS",
        {0U}
    );
}

void expect_protocol_path_statistics_cover_new_shim_layers() {
    const auto one_flow = std::vector<FlowIndex> {0U};

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/llc_snap/01_llc_snap_ipv4_tcp.pcap")));
        const auto summary = session.protocol_path_summary();
        expect_protocol_path_stats_row(summary, "IEEE 802.3 -> LLC/SNAP -> IPv4 -> TCP", 1U, 1U);
        expect_protocol_path_stats_layer_text(summary, "IEEE 802.3 -> LLC/SNAP", "LLC/SNAP");
        expect_protocol_path_stats_membership(
            session,
            summary,
            ProtocolPathStatisticsMode::kind_overview,
            "IEEE 802.3 -> LLC/SNAP",
            one_flow
        );
    }

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/pppoe/01_pppoe_session_ipv4_tcp.pcap")));
        const auto summary = session.protocol_path_summary();
        expect_protocol_path_stats_row(summary, "EthernetII -> PPPoE -> PPP -> IPv4 -> TCP", 1U, 1U);
        expect_protocol_path_stats_layer_text(summary, "EthernetII -> PPPoE", "PPPoE");
        expect_protocol_path_stats_layer_text(summary, "EthernetII -> PPPoE -> PPP", "PPP");
        expect_protocol_path_stats_membership(
            session,
            summary,
            ProtocolPathStatisticsMode::kind_overview,
            "EthernetII -> PPPoE -> PPP",
            one_flow
        );
    }

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/pbb/01_pbb_ipv4_tcp.pcap")));
        const auto kind_summary = session.protocol_path_summary();
        const auto identity_summary = session.protocol_path_summary(ProtocolPathStatisticsMode::identity_tree);
        expect_protocol_path_stats_row(kind_summary, "EthernetII -> PBB -> EthernetII -> IPv4 -> TCP", 1U, 1U);
        expect_protocol_path_stats_layer_text(kind_summary, "EthernetII -> PBB", "PBB");
        expect_protocol_path_stats_membership(
            session,
            kind_summary,
            ProtocolPathStatisticsMode::kind_overview,
            "EthernetII -> PBB",
            one_flow
        );
        expect_protocol_path_stats_row(identity_summary, "EthernetII -> PBB(isid=0x123456) -> EthernetII -> IPv4 -> TCP", 1U, 1U);
        expect_protocol_path_stats_layer_text(identity_summary, "EthernetII -> PBB(isid=0x123456)", "PBB (I-SID 0x123456)");
        expect_protocol_path_stats_membership(
            session,
            identity_summary,
            ProtocolPathStatisticsMode::identity_tree,
            "EthernetII -> PBB(isid=0x123456)",
            one_flow
        );
    }

    {
        CaptureSession session {};
        PFL_REQUIRE(session.open_capture(fixture_path("parsing/mpls_pw/01_mpls_pw_eth_ipv4_tcp_no_cw.pcap")));
        const auto summary = session.protocol_path_summary();
        expect_protocol_path_stats_row(summary, "EthernetII -> MPLS -> MPLS -> MPLS PW -> EthernetII -> IPv4 -> TCP", 1U, 1U);
        expect_protocol_path_stats_layer_text(summary, "EthernetII -> MPLS -> MPLS -> MPLS PW", "MPLS PW");
        expect_protocol_path_stats_membership(
            session,
            summary,
            ProtocolPathStatisticsMode::kind_overview,
            "EthernetII -> MPLS -> MPLS -> MPLS PW",
            one_flow
        );
    }
}

void expect_macsec_does_not_fabricate_flow_paths() {
    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(fixture_path("parsing/macsec/01_macsec_basic_no_sci.pcap")));
    PFL_EXPECT(session.list_flows().empty());
    PFL_EXPECT(session.unrecognized_packet_count() == 1U);
    PFL_EXPECT(session.protocol_path_summary().rows.empty());
}

void expect_protocol_path_statistics_terminal_paths_only() {
    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(fixture_path("parsing/vxlan/10_vxlan_same_inner_tuple_different_vni.pcap")));

    const auto summary = session.protocol_path_summary(ProtocolPathStatisticsMode::terminal_paths);
    PFL_EXPECT(summary.rows.size() == 2U);
    expect_no_protocol_path_stats_row(summary, "EthernetII");
    expect_no_protocol_path_stats_row(summary, "EthernetII -> IPv4 -> UDP");

    const auto* first_terminal = find_protocol_path_stats_row(
        summary,
        "EthernetII -> IPv4 -> UDP -> VXLAN(vni=100) -> EthernetII -> IPv4 -> TCP"
    );
    const auto* second_terminal = find_protocol_path_stats_row(
        summary,
        "EthernetII -> IPv4 -> UDP -> VXLAN(vni=200) -> EthernetII -> IPv4 -> TCP"
    );
    PFL_REQUIRE(first_terminal != nullptr);
    PFL_REQUIRE(second_terminal != nullptr);
    PFL_EXPECT(first_terminal->depth == 0U);
    PFL_EXPECT(second_terminal->depth == 0U);
    PFL_EXPECT(first_terminal->layer_text == first_terminal->path_text);
    PFL_EXPECT(second_terminal->layer_text == second_terminal->path_text);
    const auto first_terminal_flow = std::vector<FlowIndex> {0U};
    const auto second_terminal_flow = std::vector<FlowIndex> {1U};
    PFL_EXPECT(session.protocol_path_summary_flow_indices(ProtocolPathStatisticsMode::terminal_paths, first_terminal->node_id)
        == first_terminal_flow);
    PFL_EXPECT(session.protocol_path_summary_flow_indices(ProtocolPathStatisticsMode::terminal_paths, second_terminal->node_id)
        == second_terminal_flow);
}

void expect_protocol_path_statistics_tree_metadata() {
    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(fixture_path("parsing/vxlan/10_vxlan_same_inner_tuple_different_vni.pcap")));

    for (const auto mode : {ProtocolPathStatisticsMode::kind_overview, ProtocolPathStatisticsMode::identity_tree}) {
        const auto summary = session.protocol_path_summary(mode);
        std::set<std::uint64_t> seen_node_ids {};
        for (const auto& row : summary.rows) {
            PFL_EXPECT(row.node_id != kInvalidProtocolPathStatisticsNodeId);
            PFL_EXPECT(seen_node_ids.insert(row.node_id).second);
            if (row.parent_node_id != kInvalidProtocolPathStatisticsNodeId) {
                const auto* parent = find_protocol_path_stats_row_by_node_id(summary, row.parent_node_id);
                PFL_REQUIRE(parent != nullptr);
                PFL_EXPECT(parent->depth + 1U == row.depth);
                PFL_EXPECT(parent->path.size() + 1U == row.path.size());
                PFL_EXPECT(parent->has_children);
            } else {
                PFL_EXPECT(row.depth == 0U);
            }
        }

        const auto* root = find_protocol_path_stats_row(summary, "EthernetII");
        PFL_REQUIRE(root != nullptr);
        PFL_EXPECT(root->parent_node_id == kInvalidProtocolPathStatisticsNodeId);
        PFL_EXPECT(root->has_children);

        const auto* ipv4 = find_protocol_path_stats_row(summary, "EthernetII -> IPv4");
        PFL_REQUIRE(ipv4 != nullptr);
        PFL_EXPECT(ipv4->parent_node_id == root->node_id);
        PFL_EXPECT(ipv4->has_children);
    }
}

void expect_protocol_path_statistics_terminal_metadata_is_flat() {
    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(fixture_path("parsing/vxlan/10_vxlan_same_inner_tuple_different_vni.pcap")));

    const auto summary = session.protocol_path_summary(ProtocolPathStatisticsMode::terminal_paths);
    for (const auto& row : summary.rows) {
        PFL_EXPECT(row.node_id != kInvalidProtocolPathStatisticsNodeId);
        PFL_EXPECT(row.parent_node_id == kInvalidProtocolPathStatisticsNodeId);
        PFL_EXPECT(!row.has_children);
        PFL_EXPECT(row.depth == 0U);
    }
}

void expect_protocol_path_statistics_survive_index_roundtrip() {
    const auto capture_path = fixture_path("parsing/vxlan/10_vxlan_same_inner_tuple_different_vni.pcap");
    const auto index_path = std::filesystem::temp_directory_path() / "pfl_protocol_path_stats_roundtrip.idx";
    std::filesystem::remove(index_path);

    CaptureSession imported_session {};
    PFL_REQUIRE(imported_session.open_capture(capture_path));
    const auto imported_kind_summary = imported_session.protocol_path_summary(ProtocolPathStatisticsMode::kind_overview);
    const auto imported_identity_summary = imported_session.protocol_path_summary(ProtocolPathStatisticsMode::identity_tree);
    const auto imported_terminal_summary = imported_session.protocol_path_summary(ProtocolPathStatisticsMode::terminal_paths);
    PFL_REQUIRE(imported_session.save_index(index_path));

    CaptureSession loaded_session {};
    PFL_REQUIRE(loaded_session.load_index(index_path));
    const auto loaded_kind_summary = loaded_session.protocol_path_summary(ProtocolPathStatisticsMode::kind_overview);
    const auto loaded_identity_summary = loaded_session.protocol_path_summary(ProtocolPathStatisticsMode::identity_tree);
    const auto loaded_terminal_summary = loaded_session.protocol_path_summary(ProtocolPathStatisticsMode::terminal_paths);

    const std::array summaries {
        std::pair {std::cref(imported_kind_summary), std::cref(loaded_kind_summary)},
        std::pair {std::cref(imported_identity_summary), std::cref(loaded_identity_summary)},
        std::pair {std::cref(imported_terminal_summary), std::cref(loaded_terminal_summary)},
    };

    for (const auto& [imported_summary, loaded_summary] : summaries) {
        PFL_EXPECT(imported_summary.get().mode == loaded_summary.get().mode);
        PFL_EXPECT(imported_summary.get().total_flow_count == loaded_summary.get().total_flow_count);
        PFL_EXPECT(imported_summary.get().total_packet_count == loaded_summary.get().total_packet_count);
        PFL_EXPECT(imported_summary.get().total_original_byte_count == loaded_summary.get().total_original_byte_count);
        PFL_EXPECT(imported_summary.get().rows.size() == loaded_summary.get().rows.size());
        for (const auto& row : imported_summary.get().rows) {
            const auto* loaded_row = find_protocol_path_stats_row(loaded_summary.get(), row.path_text);
            PFL_REQUIRE(loaded_row != nullptr);
            PFL_EXPECT(loaded_row->node_id == row.node_id);
            PFL_EXPECT(loaded_row->parent_node_id == row.parent_node_id);
            PFL_EXPECT(loaded_row->depth == row.depth);
            PFL_EXPECT(loaded_row->layer_text == row.layer_text);
            PFL_EXPECT(loaded_row->has_children == row.has_children);
            PFL_EXPECT(loaded_row->flow_count == row.flow_count);
            PFL_EXPECT(loaded_row->packet_count == row.packet_count);
            PFL_EXPECT(loaded_row->original_byte_count == row.original_byte_count);
            PFL_EXPECT(loaded_row->is_terminal == row.is_terminal);
            PFL_EXPECT(loaded_row->compact_text == row.compact_text);
            PFL_EXPECT(loaded_row->flow_count_text == row.flow_count_text);
            PFL_EXPECT(loaded_row->packet_count_text == row.packet_count_text);
            PFL_EXPECT(loaded_row->original_byte_percent == row.original_byte_percent);
            PFL_EXPECT(loaded_row->original_byte_count_text == row.original_byte_count_text);
            PFL_EXPECT(
                loaded_session.protocol_path_summary_flow_indices(loaded_summary.get().mode, loaded_row->node_id) ==
                imported_session.protocol_path_summary_flow_indices(imported_summary.get().mode, row.node_id)
            );
        }
    }
}

void expect_protocol_path_statistics_flow_membership_lookup() {
    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(fixture_path("parsing/vxlan/10_vxlan_same_inner_tuple_different_vni.pcap")));

    const auto kind_summary = session.protocol_path_summary(ProtocolPathStatisticsMode::kind_overview);
    const auto identity_summary = session.protocol_path_summary(ProtocolPathStatisticsMode::identity_tree);
    const auto terminal_summary = session.protocol_path_summary(ProtocolPathStatisticsMode::terminal_paths);

    const auto* kind_row = find_protocol_path_stats_row(kind_summary, "EthernetII -> IPv4 -> UDP -> VXLAN");
    const auto* identity_prefix_row = find_protocol_path_stats_row(identity_summary, "EthernetII -> IPv4 -> UDP");
    const auto* identity_vni_100 = find_protocol_path_stats_row(identity_summary, "EthernetII -> IPv4 -> UDP -> VXLAN(vni=100)");
    const auto* identity_vni_200 = find_protocol_path_stats_row(identity_summary, "EthernetII -> IPv4 -> UDP -> VXLAN(vni=200)");
    const auto* terminal_vni_100 = find_protocol_path_stats_row(
        terminal_summary,
        "EthernetII -> IPv4 -> UDP -> VXLAN(vni=100) -> EthernetII -> IPv4 -> TCP"
    );

    PFL_REQUIRE(kind_row != nullptr);
    PFL_REQUIRE(identity_prefix_row != nullptr);
    PFL_REQUIRE(identity_vni_100 != nullptr);
    PFL_REQUIRE(identity_vni_200 != nullptr);
    PFL_REQUIRE(terminal_vni_100 != nullptr);

    const auto both_flows = std::vector<FlowIndex> {0U, 1U};
    const auto first_flow = std::vector<FlowIndex> {0U};
    const auto second_flow = std::vector<FlowIndex> {1U};
    PFL_EXPECT(session.protocol_path_summary_flow_indices(ProtocolPathStatisticsMode::kind_overview, kind_row->node_id)
        == both_flows);
    PFL_EXPECT(session.protocol_path_summary_flow_indices(ProtocolPathStatisticsMode::identity_tree, identity_prefix_row->node_id)
        == both_flows);
    PFL_EXPECT(session.protocol_path_summary_flow_indices(ProtocolPathStatisticsMode::identity_tree, identity_vni_100->node_id)
        == first_flow);
    PFL_EXPECT(session.protocol_path_summary_flow_indices(ProtocolPathStatisticsMode::identity_tree, identity_vni_200->node_id)
        == second_flow);
    PFL_EXPECT(session.protocol_path_summary_flow_indices(ProtocolPathStatisticsMode::terminal_paths, terminal_vni_100->node_id)
        == first_flow);
    PFL_EXPECT(session.protocol_path_summary_flow_indices(ProtocolPathStatisticsMode::terminal_paths, kind_row->node_id).empty());
    PFL_EXPECT(session.protocol_path_summary_flow_indices(
        ProtocolPathStatisticsMode::kind_overview,
        kInvalidProtocolPathStatisticsNodeId
    ).empty());
    PFL_EXPECT(session.protocol_path_summary_flow_indices(
        ProtocolPathStatisticsMode::kind_overview,
        std::numeric_limits<std::uint64_t>::max()
    ).empty());
}

void expect_frontend_protocol_path_statistics_are_loaded_by_mode() {
    FrontendSessionAdapter adapter {};
    PFL_REQUIRE(adapter.open_capture(fixture_path("parsing/vxlan/10_vxlan_same_inner_tuple_different_vni.pcap"), FrontendOpenMode::fast).opened);

    const auto overview = adapter.get_overview();
    PFL_EXPECT(overview.protocol_path_statistics_default_mode == ProtocolPathStatisticsMode::kind_overview);
    PFL_EXPECT(!overview.protocol_path_presentations.empty());

    const auto kind_overview_rows = adapter.get_protocol_path_statistics(ProtocolPathStatisticsMode::kind_overview);
    const auto identity_tree_rows = adapter.get_protocol_path_statistics(ProtocolPathStatisticsMode::identity_tree);
    const auto terminal_path_rows = adapter.get_protocol_path_statistics(ProtocolPathStatisticsMode::terminal_paths);
    PFL_EXPECT(!kind_overview_rows.empty());
    PFL_EXPECT(!identity_tree_rows.empty());
    PFL_EXPECT(!terminal_path_rows.empty());

    const auto found = std::find_if(
        kind_overview_rows.begin(),
        kind_overview_rows.end(),
        [](const auto& row) {
            return row.path_text == "EthernetII -> IPv4 -> UDP -> VXLAN";
        }
    );
    PFL_REQUIRE(found != kind_overview_rows.end());
    PFL_EXPECT(found->node_id != kInvalidProtocolPathStatisticsNodeId);
    PFL_EXPECT(found->parent_node_id != kInvalidProtocolPathStatisticsNodeId);
    PFL_EXPECT(found->has_children);
    PFL_EXPECT(found->layer_text == "VXLAN");
    PFL_EXPECT(found->flow_count == 2U);
    PFL_EXPECT(found->packet_count == 2U);
    PFL_EXPECT(found->original_byte_count > 0U);
    PFL_EXPECT(found->original_byte_count_text.find('B') != std::string::npos);
    PFL_EXPECT(found->original_byte_count_text.find('%') != std::string::npos);

    const auto identity_found = std::find_if(
        identity_tree_rows.begin(),
        identity_tree_rows.end(),
        [](const auto& row) {
            return row.path_text == "EthernetII -> IPv4 -> UDP -> VXLAN(vni=100)";
        }
    );
    PFL_REQUIRE(identity_found != identity_tree_rows.end());
    PFL_EXPECT(identity_found->node_id != kInvalidProtocolPathStatisticsNodeId);
    PFL_EXPECT(identity_found->has_children);
    PFL_EXPECT(identity_found->layer_text == "VXLAN (VNI 100)");
    PFL_EXPECT(identity_found->flow_count_text.find('%') != std::string::npos);
    PFL_EXPECT(identity_found->original_byte_count_text.find('B') != std::string::npos);
    PFL_EXPECT(identity_found->original_byte_count_text.find('%') != std::string::npos);

    const auto terminal_found = std::find_if(
        terminal_path_rows.begin(),
        terminal_path_rows.end(),
        [](const auto& row) {
            return row.path_text == "EthernetII -> IPv4 -> UDP -> VXLAN(vni=100) -> EthernetII -> IPv4 -> TCP";
        }
    );
    PFL_REQUIRE(terminal_found != terminal_path_rows.end());
    PFL_EXPECT(terminal_found->parent_node_id == kInvalidProtocolPathStatisticsNodeId);
    PFL_EXPECT(!terminal_found->has_children);
    PFL_EXPECT(terminal_found->is_terminal);
    PFL_EXPECT(terminal_found->original_byte_count > 0U);
    PFL_EXPECT(terminal_found->original_byte_count_text.find('B') != std::string::npos);
}

void expect_storage_summary_counts_recognized_packets_and_protocol_paths() {
    CaptureSession session {};
    PFL_REQUIRE(session.open_capture(fixture_path("parsing/vxlan/10_vxlan_same_inner_tuple_different_vni.pcap")));

    const auto summary = session.storage_summary();
    PFL_EXPECT(summary.unrecognized_packets == 0U);
    PFL_EXPECT(summary.recognized_packets == session.summary().packet_count);
    PFL_EXPECT(summary.total_packets_seen == summary.recognized_packets + summary.unrecognized_packets);
    PFL_EXPECT(summary.connection_packet_refs == summary.recognized_packets);
    PFL_EXPECT(summary.flow_count == session.summary().flow_count);
    PFL_EXPECT(summary.ipv4_connection_count + summary.ipv6_connection_count == summary.flow_count);
    PFL_EXPECT(summary.unique_protocol_paths >= 2U);
    PFL_EXPECT(summary.protocol_path_layers_total >= summary.unique_protocol_paths);
    PFL_EXPECT(summary.protocol_path_max_depth > 0U);
    PFL_EXPECT(summary.sizeof_packet_ref == sizeof(PacketRef));
    PFL_EXPECT(summary.sizeof_unrecognized_packet_record == sizeof(UnrecognizedPacketRecord));
    PFL_EXPECT(summary.sizeof_layer_key == sizeof(LayerKey));
    PFL_EXPECT(summary.approx_connection_packet_ref_bytes == summary.connection_packet_refs * sizeof(PacketRef));
    PFL_EXPECT(summary.approx_protocol_path_layer_payload_bytes ==
        summary.protocol_path_layers_total * sizeof(LayerKey) * 2U);
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
    PFL_EXPECT(require_packet_flow_protocol_path_id(state, 0U) != require_packet_flow_protocol_path_id(state, 1U));
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
    PFL_EXPECT(require_packet_flow_protocol_path_id(state, 0U) != require_packet_flow_protocol_path_id(state, 1U));
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
    PFL_EXPECT(require_packet_flow_protocol_path_id(state, 0U) == require_packet_flow_protocol_path_id(state, 1U));
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
                const auto packet_path_id = find_packet_flow_protocol_path_id(session.state(), packet.packet_index);
                if (!packet_path_id.has_value() || *packet_path_id == kInvalidProtocolPathId) {
                    saw_invalid_protocol_path_id = true;
                }

                const auto normalized_path_text =
                    normalized_protocol_path_text_for_flow_identity(session.state(), packet_path_id.value_or(kInvalidProtocolPathId));
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
    expect_registry_view_interning();
    expect_formatting();
    expect_protocol_path_presentation_mapping();
    expect_flow_rows_expose_protocol_path_presentation();
    expect_frontend_flows_expose_protocol_path_presentation();
    expect_frontend_protocol_path_legend_exposure();
    expect_builder_empty_state();
    expect_builder_push_order();
    expect_builder_identifier_layers();
    expect_builder_clear_and_reuse();
    expect_builder_capacity_and_overflow();
    expect_decode_attaches_direct_and_shim_protocol_paths();
    expect_decode_attaches_overlay_protocol_paths();
    expect_same_inner_tuple_different_vni_splits_into_two_flows();
    expect_protocol_path_statistics_direct_tcp_prefixes();
    expect_protocol_path_statistics_kind_overview_merge_vxlan_vnis();
    expect_protocol_path_statistics_identity_tree_distinguish_vxlan_vnis();
    expect_protocol_path_statistics_kind_overview_merge_gtpu_teids();
    expect_protocol_path_statistics_identity_tree_distinguish_gtpu_teids();
    expect_protocol_path_statistics_preserve_nested_mpls_prefixes_in_kind_overview();
    expect_protocol_path_statistics_tree_metadata();
    expect_protocol_path_statistics_terminal_paths_only();
    expect_protocol_path_statistics_terminal_metadata_is_flat();
    expect_protocol_path_statistics_flow_membership_lookup();
    expect_protocol_path_statistics_survive_index_roundtrip();
    expect_storage_summary_counts_recognized_packets_and_protocol_paths();
    expect_frontend_protocol_path_statistics_are_loaded_by_mode();
    expect_gtpu_same_inner_tuple_different_teid_splits_into_two_flows();
    expect_mpls_same_inner_tuple_different_labels_splits_into_two_flows();
    expect_same_exact_path_reverse_tuple_stays_bidirectional();
    expect_tls_quic_constricted_fixtures_do_not_split_into_multiple_protocol_paths();
    expect_terminal_control_protocols_do_not_appear_in_protocol_paths();
    expect_common_case_packets_resolve_to_owning_flow_protocol_path();
    expect_protocol_path_statistics_cover_new_shim_layers();
    expect_macsec_does_not_fabricate_flow_paths();
}

}  // namespace pfl::tests
