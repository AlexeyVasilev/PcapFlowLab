#include <filesystem>
#include <functional>
#include <string>

#include "TestSupport.h"
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

void expect_same_inner_tuple_different_vni_keeps_grouping_but_changes_path_id() {
    const auto state = require_imported_capture_state(fixture_path("parsing/vxlan/10_vxlan_same_inner_tuple_different_vni.pcap"));

    const auto connections = state.ipv4_connections.list();
    PFL_REQUIRE(connections.size() == 1U);
    PFL_EXPECT(connections[0]->has_flow_a);
    PFL_EXPECT(connections[0]->flow_a.packet_count == 2U);

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

}  // namespace

void run_protocol_path_tests() {
    expect_layer_key_equality();
    expect_protocol_path_ordered_equality();
    expect_identifier_differences();
    expect_registry_interning();
    expect_formatting();
    expect_builder_empty_state();
    expect_builder_push_order();
    expect_builder_identifier_layers();
    expect_builder_clear_and_reuse();
    expect_builder_capacity_and_overflow();
    expect_decode_attaches_direct_and_shim_protocol_paths();
    expect_decode_attaches_overlay_protocol_paths();
    expect_same_inner_tuple_different_vni_keeps_grouping_but_changes_path_id();
}

}  // namespace pfl::tests
