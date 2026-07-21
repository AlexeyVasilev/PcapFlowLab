#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <utility>
#include <variant>
#include <vector>

#include "TestSupport.h"
#include "PcapTestUtils.h"
#include "core/decode/PacketDecodeSupport.h"
#include "core/decode/PacketDecoder.h"
#include "core/dissection/CommonDirectDissection.h"
#include "core/dissection/PacketSlice.h"
#include "core/dissection/modules/CommonDirectModules.h"
#include "core/domain/ProtocolPath.h"
#include "core/io/PcapReader.h"
#include "core/io/LinkType.h"

namespace pfl::tests {

namespace {

using namespace dissection;

struct LegacyDirectFacts {
    bool recognized_flow {false};
    ProtocolId protocol {ProtocolId::unknown};
    DissectionAddressFamily family {DissectionAddressFamily::unknown};
    bool has_addresses {false};
    std::uint32_t src_addr_v4 {0U};
    std::uint32_t dst_addr_v4 {0U};
    std::array<std::uint8_t, 16> src_addr_v6 {};
    std::array<std::uint8_t, 16> dst_addr_v6 {};
    bool has_ports {false};
    std::uint16_t src_port {0U};
    std::uint16_t dst_port {0U};
    bool has_payload_length {false};
    std::uint32_t captured_payload_length {0U};
    bool has_tcp_flags {false};
    std::uint8_t tcp_flags {0U};
    bool is_ip_fragmented {false};
    ProtocolPath path {};
};

RawPcapPacket make_raw_packet(
    const std::vector<std::uint8_t>& captured_bytes,
    const std::uint32_t original_length = 0U,
    const std::uint32_t data_link_type = kLinkTypeEthernet,
    const std::uint64_t packet_index = 0U
) {
    return RawPcapPacket {
        .packet_index = packet_index,
        .ts_sec = 1U,
        .ts_usec = 1U,
        .captured_length = static_cast<std::uint32_t>(captured_bytes.size()),
        .original_length = original_length == 0U ? static_cast<std::uint32_t>(captured_bytes.size()) : original_length,
        .data_offset = 64U,
        .data_link_type = data_link_type,
        .bytes = captured_bytes,
    };
}

std::filesystem::path fixture_path(const std::filesystem::path& relative_path) {
    return std::filesystem::path(__FILE__).parent_path().parent_path() / "data" / relative_path;
}

RawPcapPacket require_raw_fixture_packet(const std::filesystem::path& relative_path) {
    PcapReader reader {};
    PFL_EXPECT(reader.open(fixture_path(relative_path)));
    const auto packet = reader.read_next();
    PFL_REQUIRE(packet.has_value());
    PFL_EXPECT(!reader.read_next().has_value());
    return *packet;
}

std::vector<RawPcapPacket> require_raw_fixture_packets(const std::filesystem::path& relative_path) {
    PcapReader reader {};
    PFL_EXPECT(reader.open(fixture_path(relative_path)));

    std::vector<RawPcapPacket> packets {};
    while (const auto packet = reader.read_next()) {
        packets.push_back(*packet);
    }

    PFL_EXPECT(!packets.empty());
    return packets;
}

PacketSlice make_root_slice(const RawPcapPacket& packet) {
    return make_root_packet_slice(
        ByteSourceId::captured_frame(static_cast<std::uint32_t>(packet.packet_index)),
        packet.bytes,
        packet.captured_length,
        packet.original_length
    );
}

PacketSlice make_declared_root_slice(const std::vector<std::uint8_t>& bytes, const std::size_t declared_length) {
    return make_root_packet_slice(
        ByteSourceId::captured_frame(),
        bytes,
        bytes.size(),
        declared_length
    );
}

PacketSlice require_child_slice(
    const PacketSlice& parent,
    const std::size_t payload_offset,
    const std::size_t declared_payload_length
) {
    const auto child = make_child_slice(parent, payload_offset, declared_payload_length);
    PFL_REQUIRE(child.has_slice());
    return *child.slice;
}

ByteRange require_range(const std::size_t begin, const std::size_t end) {
    const auto range = ByteRange::from_begin_end(begin, end);
    PFL_REQUIRE(range.has_value());
    return *range;
}

std::string format_builder_path(const ProtocolPathBuilder& builder) {
    PFL_EXPECT(!builder.overflowed());
    return format_protocol_path(builder.to_path());
}

std::string format_shadow_path(const ImportDissectionFacts& facts) {
    return format_builder_path(facts.physical_path);
}

ProtocolPath shadow_path(const ImportDissectionFacts& facts) {
    PFL_EXPECT(!facts.physical_path.overflowed());
    return facts.physical_path.to_path();
}

bool protocol_uses_ports(const ProtocolId protocol) {
    return protocol == ProtocolId::tcp ||
           protocol == ProtocolId::udp ||
           protocol == ProtocolId::sctp;
}

LegacyDirectFacts decode_legacy_direct(const RawPcapPacket& packet) {
    PacketDecoder decoder {};
    const auto decoded = decoder.decode(packet);

    LegacyDirectFacts facts {};
    if (!decoded.has_value()) {
        return facts;
    }

    facts.recognized_flow = true;
    facts.path = decoded.protocol_path_builder.to_path();

    if (decoded.ipv4.has_value()) {
        facts.family = DissectionAddressFamily::ipv4;
        facts.protocol = decoded.ipv4->flow_key.protocol;
        facts.has_addresses = true;
        facts.src_addr_v4 = decoded.ipv4->flow_key.src_addr;
        facts.dst_addr_v4 = decoded.ipv4->flow_key.dst_addr;
        facts.is_ip_fragmented = decoded.ipv4->packet_ref.is_ip_fragmented;
        facts.has_ports = !facts.is_ip_fragmented && protocol_uses_ports(facts.protocol);
        facts.src_port = decoded.ipv4->flow_key.src_port;
        facts.dst_port = decoded.ipv4->flow_key.dst_port;
        facts.has_payload_length = !facts.is_ip_fragmented || decoded.ipv4->packet_ref.payload_length != 0U;
        facts.captured_payload_length = decoded.ipv4->packet_ref.payload_length;
        facts.has_tcp_flags = facts.protocol == ProtocolId::tcp && !facts.is_ip_fragmented;
        facts.tcp_flags = decoded.ipv4->packet_ref.tcp_flags;
    } else if (decoded.ipv6.has_value()) {
        facts.family = DissectionAddressFamily::ipv6;
        facts.protocol = decoded.ipv6->flow_key.protocol;
        facts.has_addresses = true;
        facts.src_addr_v6 = decoded.ipv6->flow_key.src_addr;
        facts.dst_addr_v6 = decoded.ipv6->flow_key.dst_addr;
        facts.is_ip_fragmented = decoded.ipv6->packet_ref.is_ip_fragmented;
        facts.has_ports = !facts.is_ip_fragmented && protocol_uses_ports(facts.protocol);
        facts.src_port = decoded.ipv6->flow_key.src_port;
        facts.dst_port = decoded.ipv6->flow_key.dst_port;
        facts.has_payload_length = !facts.is_ip_fragmented || decoded.ipv6->packet_ref.payload_length != 0U;
        facts.captured_payload_length = decoded.ipv6->packet_ref.payload_length;
        facts.has_tcp_flags = facts.protocol == ProtocolId::tcp && !facts.is_ip_fragmented;
        facts.tcp_flags = decoded.ipv6->packet_ref.tcp_flags;
    }

    return facts;
}

ImportDissectionFacts run_shadow(const RawPcapPacket& packet, const DissectionRegistry& registry) {
    ImportDissectionCollector collector {};
    const DissectionEngine engine {};
    const auto result = engine.run(
        registry,
        make_link_type_selector(packet.data_link_type),
        make_root_slice(packet),
        collector.consumer()
    );
    collector.finish(result);
    return collector.facts();
}

std::vector<DissectionStep> collect_shadow_steps(const RawPcapPacket& packet, const DissectionRegistry& registry) {
    struct StepRecorder {
        std::vector<DissectionStep> steps {};
    };

    auto record_step = [](void* context, const DissectionStep& step) {
        auto* recorder = static_cast<StepRecorder*>(context);
        recorder->steps.push_back(step);
    };

    StepRecorder recorder {};
    const DissectionEngine engine {};
    static_cast<void>(engine.run(
        registry,
        make_link_type_selector(packet.data_link_type),
        make_root_slice(packet),
        DissectionConsumer {
            .on_step = record_step,
            .context = &recorder,
        }
    ));
    return recorder.steps;
}

const PppoeFacts* find_pppoe_facts(const std::vector<DissectionStep>& steps) {
    for (const auto& step : steps) {
        if (step.layer != DissectionLayerKind::pppoe) {
            continue;
        }

        const auto* facts = std::get_if<PppoeFacts>(&step.facts);
        if (facts != nullptr) {
            return facts;
        }
    }

    return nullptr;
}

const PbbFacts* find_pbb_facts(const std::vector<DissectionStep>& steps) {
    for (const auto& step : steps) {
        if (step.layer != DissectionLayerKind::pbb) {
            continue;
        }

        const auto* facts = std::get_if<PbbFacts>(&step.facts);
        if (facts != nullptr) {
            return facts;
        }
    }

    return nullptr;
}

const MacsecFacts* find_macsec_facts(const std::vector<DissectionStep>& steps) {
    for (const auto& step : steps) {
        if (step.layer != DissectionLayerKind::macsec) {
            continue;
        }

        const auto* facts = std::get_if<MacsecFacts>(&step.facts);
        if (facts != nullptr) {
            return facts;
        }
    }

    return nullptr;
}

std::vector<DissectionLayerKind> collect_step_kinds(const std::vector<DissectionStep>& steps) {
    std::vector<DissectionLayerKind> kinds {};
    kinds.reserve(steps.size());
    for (const auto& step : steps) {
        kinds.push_back(step.layer);
    }
    return kinds;
}

void expect_shadow_matches_legacy_flow(
    const DissectionRegistry& registry,
    const RawPcapPacket& packet,
    const std::string& expected_path,
    const StopReason expected_stop_reason
) {
    const auto legacy = decode_legacy_direct(packet);
    const auto shadow = run_shadow(packet, registry);

    PFL_REQUIRE(legacy.recognized_flow);
    PFL_EXPECT(shadow.outcome == ImportDissectionOutcome::recognized_flow);
    PFL_EXPECT(shadow.stop_reason == expected_stop_reason);
    PFL_EXPECT(shadow_path(shadow) == legacy.path);
    PFL_EXPECT(format_shadow_path(shadow) == expected_path);
    PFL_EXPECT(format_protocol_path(legacy.path) == expected_path);
    PFL_EXPECT(shadow.terminal_protocol == legacy.protocol);
    PFL_EXPECT(shadow.family == legacy.family);
    PFL_EXPECT(shadow.has_flow_addresses == legacy.has_addresses);
    if (legacy.family == DissectionAddressFamily::ipv4) {
        PFL_EXPECT(shadow.src_addr_v4 == legacy.src_addr_v4);
        PFL_EXPECT(shadow.dst_addr_v4 == legacy.dst_addr_v4);
        PFL_EXPECT(shadow.has_ipv4_fragmentation);
        PFL_EXPECT(shadow.ipv4_fragmentation.is_fragmented == legacy.is_ip_fragmented);
    } else if (legacy.family == DissectionAddressFamily::ipv6) {
        PFL_EXPECT(shadow.src_addr_v6 == legacy.src_addr_v6);
        PFL_EXPECT(shadow.dst_addr_v6 == legacy.dst_addr_v6);
        PFL_EXPECT(shadow.has_ipv6_fragmentation);
        PFL_EXPECT(shadow.ipv6_fragmentation.has_fragment_header == legacy.is_ip_fragmented);
    }
    PFL_EXPECT(shadow.has_ports == legacy.has_ports);
    PFL_EXPECT(shadow.src_port == legacy.src_port);
    PFL_EXPECT(shadow.dst_port == legacy.dst_port);
    PFL_EXPECT(shadow.has_transport_payload_length == legacy.has_payload_length);
    PFL_EXPECT(shadow.captured_transport_payload_length == legacy.captured_payload_length);
    PFL_EXPECT(shadow.has_tcp_flags == legacy.has_tcp_flags);
    PFL_EXPECT(shadow.tcp_flags == legacy.tcp_flags);
}

void expect_shadow_matches_legacy_portless_flow(
    const DissectionRegistry& registry,
    const RawPcapPacket& packet,
    const std::string& expected_shadow_path,
    const std::string& expected_legacy_path,
    const StopReason expected_stop_reason
) {
    const auto legacy = decode_legacy_direct(packet);
    const auto shadow = run_shadow(packet, registry);

    PFL_REQUIRE(legacy.recognized_flow);
    PFL_EXPECT(shadow.outcome == ImportDissectionOutcome::recognized_flow);
    PFL_EXPECT(shadow.stop_reason == expected_stop_reason);
    PFL_EXPECT(format_shadow_path(shadow) == expected_shadow_path);
    PFL_EXPECT(format_protocol_path(legacy.path) == expected_legacy_path);
    PFL_EXPECT(shadow.terminal_protocol == legacy.protocol);
    PFL_EXPECT(shadow.family == legacy.family);
    PFL_EXPECT(shadow.has_flow_addresses == legacy.has_addresses);
    if (legacy.family == DissectionAddressFamily::ipv4) {
        PFL_EXPECT(shadow.src_addr_v4 == legacy.src_addr_v4);
        PFL_EXPECT(shadow.dst_addr_v4 == legacy.dst_addr_v4);
        PFL_EXPECT(shadow.has_ipv4_fragmentation);
        PFL_EXPECT(shadow.ipv4_fragmentation.is_fragmented == legacy.is_ip_fragmented);
    } else if (legacy.family == DissectionAddressFamily::ipv6) {
        PFL_EXPECT(shadow.src_addr_v6 == legacy.src_addr_v6);
        PFL_EXPECT(shadow.dst_addr_v6 == legacy.dst_addr_v6);
        PFL_EXPECT(shadow.has_ipv6_fragmentation);
        PFL_EXPECT(shadow.ipv6_fragmentation.has_fragment_header == legacy.is_ip_fragmented);
    }
    PFL_EXPECT(legacy.src_port == 0U);
    PFL_EXPECT(legacy.dst_port == 0U);
    PFL_EXPECT(!shadow.has_ports);
    PFL_EXPECT(shadow.src_port == 0U);
    PFL_EXPECT(shadow.dst_port == 0U);
    PFL_EXPECT(!shadow.has_transport_payload_length);
    PFL_EXPECT(shadow.captured_transport_payload_length == 0U);
    PFL_EXPECT(!shadow.has_tcp_flags);
    PFL_EXPECT(shadow.tcp_flags == 0U);
}

void expect_shadow_matches_legacy_recognized_non_flow(
    const DissectionRegistry& registry,
    const RawPcapPacket& packet,
    const std::string& expected_shadow_path,
    const std::string& expected_legacy_path,
    const StopReason expected_stop_reason
) {
    const auto legacy = decode_legacy_direct(packet);
    const auto shadow = run_shadow(packet, registry);

    PFL_REQUIRE(legacy.recognized_flow);
    PFL_EXPECT(legacy.protocol == ProtocolId::arp);
    PFL_EXPECT(format_protocol_path(legacy.path) == expected_legacy_path);

    PFL_EXPECT(shadow.outcome == ImportDissectionOutcome::recognized_non_flow);
    PFL_EXPECT(shadow.stop_reason == expected_stop_reason);
    PFL_EXPECT(shadow.terminal_protocol == ProtocolId::arp);
    PFL_EXPECT(shadow.family == DissectionAddressFamily::ipv4);
    PFL_EXPECT(shadow.has_arp_addresses);
    PFL_EXPECT(format_shadow_path(shadow) == expected_shadow_path);
    PFL_EXPECT(!shadow.has_ports);
    PFL_EXPECT(shadow.src_port == 0U);
    PFL_EXPECT(shadow.dst_port == 0U);
    PFL_EXPECT(!shadow.has_transport_payload_length);
    PFL_EXPECT(!shadow.has_tcp_flags);
}

void expect_import_dissection_collector_uses_explicit_path_commit_policies() {
    const auto make_result = [](const StopReason stop_reason, const std::size_t step_count) {
        return DissectionEngineResult {
            .stop_reason = stop_reason,
            .step_count = step_count,
            .traversed_depth = step_count,
        };
    };
    const std::array all_policies {
        PathCommitPolicy::immediate,
        PathCommitPolicy::recognized_flow,
        PathCommitPolicy::recognized_flow_or_recognized_non_flow,
    };

    for (const auto lhs : all_policies) {
        for (const auto rhs : all_policies) {
            const auto combined = combine_path_commit_policies(lhs, rhs);
            PFL_EXPECT(combined == combine_path_commit_policies(rhs, lhs));
            PFL_EXPECT(path_commit_policy_strength(combined) >= path_commit_policy_strength(lhs));
            PFL_EXPECT(path_commit_policy_strength(combined) >= path_commit_policy_strength(rhs));
        }
        PFL_EXPECT(combine_path_commit_policies(lhs, lhs) == lhs);
    }

    for (const auto lhs : all_policies) {
        for (const auto middle : all_policies) {
            for (const auto rhs : all_policies) {
                PFL_EXPECT(
                    combine_path_commit_policies(
                        combine_path_commit_policies(lhs, middle),
                        rhs)
                    == combine_path_commit_policies(
                        lhs,
                        combine_path_commit_policies(middle, rhs))
                );
            }
        }
    }

    {
        ImportDissectionCollector collector {};
        collector.consume(DissectionStep {
            .layer = DissectionLayerKind::ethernet_ii,
            .path_contribution = LayerKey::ethernet_ii(),
            .status = ParseStatus::complete,
            .stop_reason = StopReason::none,
        });
        collector.finish(make_result(StopReason::unknown_next_protocol, 1U));

        PFL_EXPECT(collector.facts().outcome == ImportDissectionOutcome::unrecognized);
        PFL_EXPECT(format_shadow_path(collector.facts()) == "EthernetII");
    }

    {
        ImportDissectionCollector collector {};
        collector.consume(DissectionStep {
            .layer = DissectionLayerKind::ethernet_ii,
            .path_contribution = LayerKey::ethernet_ii(),
            .status = ParseStatus::complete,
            .stop_reason = StopReason::none,
        });
        collector.consume(DissectionStep {
            .layer = DissectionLayerKind::pppoe,
            .path_contribution = LayerKey::pppoe(),
            .path_commit_policy = PathCommitPolicy::recognized_flow,
            .status = ParseStatus::complete,
            .stop_reason = StopReason::none,
        });
        collector.finish(make_result(StopReason::unsupported_variant, 2U));

        PFL_EXPECT(collector.facts().outcome == ImportDissectionOutcome::unrecognized);
        PFL_EXPECT(format_shadow_path(collector.facts()) == "EthernetII");
    }

    {
        ImportDissectionCollector collector {};
        collector.consume(DissectionStep {
            .layer = DissectionLayerKind::ieee8023,
            .path_contribution = LayerKey::ieee8023(),
            .path_contribution_deferrable_by_child = true,
            .status = ParseStatus::complete,
            .stop_reason = StopReason::none,
        });
        collector.consume(DissectionStep {
            .layer = DissectionLayerKind::llc_snap,
            .path_contribution = LayerKey::llc_snap(),
            .path_commit_policy = PathCommitPolicy::recognized_flow_or_recognized_non_flow,
            .defer_last_deferrable_path_contribution = true,
            .status = ParseStatus::complete,
            .stop_reason = StopReason::none,
        });
        collector.finish(make_result(StopReason::truncated, 2U));

        PFL_EXPECT(collector.facts().outcome == ImportDissectionOutcome::unrecognized);
        PFL_EXPECT(format_shadow_path(collector.facts()).empty());
    }

    {
        ImportDissectionCollector collector {};
        collector.consume(DissectionStep {
            .layer = DissectionLayerKind::ieee8023,
            .path_contribution = LayerKey::ieee8023(),
            .path_contribution_deferrable_by_child = true,
            .status = ParseStatus::complete,
            .stop_reason = StopReason::none,
        });
        collector.consume(DissectionStep {
            .layer = DissectionLayerKind::llc_snap,
            .path_contribution = LayerKey::llc_snap(),
            .path_commit_policy = PathCommitPolicy::recognized_flow_or_recognized_non_flow,
            .defer_last_deferrable_path_contribution = true,
            .status = ParseStatus::complete,
            .stop_reason = StopReason::none,
        });
        collector.consume(DissectionStep {
            .layer = DissectionLayerKind::arp,
            .facts = ArpFacts {
                .has_sender_ipv4 = true,
                .has_target_ipv4 = true,
                .sender_ipv4 = ipv4(192, 0, 2, 10),
                .target_ipv4 = ipv4(192, 0, 2, 1),
            },
            .terminal_disposition = TerminalDisposition::recognized_non_flow,
            .status = ParseStatus::complete,
            .stop_reason = StopReason::terminal_protocol,
        });
        collector.finish(make_result(StopReason::terminal_protocol, 3U));

        PFL_EXPECT(collector.facts().outcome == ImportDissectionOutcome::recognized_non_flow);
        PFL_EXPECT(format_shadow_path(collector.facts()) == "IEEE 802.3 -> LLC/SNAP");
    }

    {
        ImportDissectionCollector collector {};
        collector.consume(DissectionStep {
            .layer = DissectionLayerKind::ethernet_ii,
            .path_contribution = LayerKey::ethernet_ii(),
            .status = ParseStatus::complete,
            .stop_reason = StopReason::none,
        });
        collector.consume(DissectionStep {
            .layer = DissectionLayerKind::pppoe,
            .path_contribution = LayerKey::pppoe(),
            .path_commit_policy = PathCommitPolicy::recognized_flow,
            .status = ParseStatus::complete,
            .stop_reason = StopReason::none,
        });
        collector.consume(DissectionStep {
            .layer = DissectionLayerKind::ppp,
            .path_contribution = LayerKey::ppp(),
            .path_commit_policy = PathCommitPolicy::recognized_flow,
            .status = ParseStatus::complete,
            .stop_reason = StopReason::none,
        });
        collector.consume(DissectionStep {
            .layer = DissectionLayerKind::ipv4,
            .path_contribution = LayerKey::ipv4(),
            .facts = Ipv4Facts {
                .protocol = detail::kIpProtocolUdp,
                .src_addr_v4 = ipv4(192, 0, 2, 30),
                .dst_addr_v4 = ipv4(198, 51, 100, 30),
            },
            .status = ParseStatus::complete,
            .stop_reason = StopReason::none,
        });
        collector.consume(DissectionStep {
            .layer = DissectionLayerKind::udp,
            .path_contribution = LayerKey::udp(),
            .facts = UdpFacts {
                .src_port = 53540U,
                .dst_port = 443U,
            },
            .terminal_disposition = TerminalDisposition::flow_candidate,
            .status = ParseStatus::complete,
            .stop_reason = StopReason::terminal_protocol,
        });
        collector.finish(make_result(StopReason::terminal_protocol, 5U));

        PFL_EXPECT(collector.facts().outcome == ImportDissectionOutcome::recognized_flow);
        PFL_EXPECT(format_shadow_path(collector.facts()) == "EthernetII -> PPPoE -> PPP -> IPv4 -> UDP");
    }

    {
        ImportDissectionCollector collector {};
        collector.consume(DissectionStep {
            .layer = DissectionLayerKind::ethernet_ii,
            .path_contribution = LayerKey::ethernet_ii(),
            .status = ParseStatus::complete,
            .stop_reason = StopReason::none,
        });
        collector.consume(DissectionStep {
            .layer = DissectionLayerKind::pppoe,
            .path_contribution = LayerKey::pppoe(),
            .path_commit_policy = PathCommitPolicy::recognized_flow,
            .descendant_path_commit_policy = PathCommitPolicy::recognized_flow,
            .status = ParseStatus::complete,
            .stop_reason = StopReason::none,
        });
        collector.consume(DissectionStep {
            .layer = DissectionLayerKind::ppp,
            .path_contribution = LayerKey::ppp(),
            .path_commit_policy = PathCommitPolicy::recognized_flow_or_recognized_non_flow,
            .descendant_path_commit_policy = PathCommitPolicy::recognized_flow_or_recognized_non_flow,
            .status = ParseStatus::complete,
            .stop_reason = StopReason::none,
        });
        collector.consume(DissectionStep {
            .layer = DissectionLayerKind::arp,
            .path_contribution = LayerKey::arp(),
            .facts = ArpFacts {
                .has_sender_ipv4 = true,
                .has_target_ipv4 = true,
                .sender_ipv4 = ipv4(198, 51, 100, 10),
                .target_ipv4 = ipv4(198, 51, 100, 1),
            },
            .terminal_disposition = TerminalDisposition::recognized_non_flow,
            .status = ParseStatus::complete,
            .stop_reason = StopReason::terminal_protocol,
        });
        collector.finish(make_result(StopReason::terminal_protocol, 4U));

        PFL_EXPECT(collector.facts().outcome == ImportDissectionOutcome::recognized_non_flow);
        PFL_EXPECT(format_shadow_path(collector.facts()) == "EthernetII");
    }

    {
        ImportDissectionCollector collector {};
        collector.consume(DissectionStep {
            .layer = DissectionLayerKind::ethernet_ii,
            .path_contribution = LayerKey::ethernet_ii(),
            .status = ParseStatus::complete,
            .stop_reason = StopReason::none,
        });
        collector.consume(DissectionStep {
            .layer = DissectionLayerKind::linux_sll,
            .path_contribution = LayerKey::linux_sll(),
            .path_commit_policy = PathCommitPolicy::recognized_flow_or_recognized_non_flow,
            .descendant_path_commit_policy = PathCommitPolicy::recognized_flow_or_recognized_non_flow,
            .status = ParseStatus::complete,
            .stop_reason = StopReason::none,
        });
        collector.consume(DissectionStep {
            .layer = DissectionLayerKind::pppoe,
            .path_contribution = LayerKey::pppoe(),
            .path_commit_policy = PathCommitPolicy::recognized_flow,
            .descendant_path_commit_policy = PathCommitPolicy::recognized_flow,
            .status = ParseStatus::complete,
            .stop_reason = StopReason::none,
        });
        collector.consume(DissectionStep {
            .layer = DissectionLayerKind::arp,
            .path_contribution = LayerKey::arp(),
            .facts = ArpFacts {
                .has_sender_ipv4 = true,
                .has_target_ipv4 = true,
                .sender_ipv4 = ipv4(198, 51, 100, 20),
                .target_ipv4 = ipv4(198, 51, 100, 1),
            },
            .terminal_disposition = TerminalDisposition::recognized_non_flow,
            .status = ParseStatus::complete,
            .stop_reason = StopReason::terminal_protocol,
        });
        collector.finish(make_result(StopReason::terminal_protocol, 4U));

        PFL_EXPECT(collector.facts().outcome == ImportDissectionOutcome::recognized_non_flow);
        PFL_EXPECT(format_shadow_path(collector.facts()) == "EthernetII -> LinuxSll");
    }

    {
        ImportDissectionCollector collector {};
        collector.consume(DissectionStep {
            .layer = DissectionLayerKind::ethernet_ii,
            .path_contribution = LayerKey::ethernet_ii(),
            .status = ParseStatus::complete,
            .stop_reason = StopReason::none,
        });
        collector.consume(DissectionStep {
            .layer = DissectionLayerKind::pppoe,
            .path_contribution = LayerKey::pppoe(),
            .path_commit_policy = PathCommitPolicy::recognized_flow_or_recognized_non_flow,
            .descendant_path_commit_policy = PathCommitPolicy::recognized_flow_or_recognized_non_flow,
            .status = ParseStatus::complete,
            .stop_reason = StopReason::none,
        });
        collector.consume(DissectionStep {
            .layer = DissectionLayerKind::ppp,
            .path_contribution = LayerKey::ppp(),
            .path_commit_policy = PathCommitPolicy::recognized_flow,
            .descendant_path_commit_policy = PathCommitPolicy::recognized_flow,
            .status = ParseStatus::complete,
            .stop_reason = StopReason::none,
        });
        collector.consume(DissectionStep {
            .layer = DissectionLayerKind::arp,
            .path_contribution = LayerKey::arp(),
            .facts = ArpFacts {
                .has_sender_ipv4 = true,
                .has_target_ipv4 = true,
                .sender_ipv4 = ipv4(203, 0, 113, 10),
                .target_ipv4 = ipv4(203, 0, 113, 1),
            },
            .terminal_disposition = TerminalDisposition::recognized_non_flow,
            .status = ParseStatus::complete,
            .stop_reason = StopReason::terminal_protocol,
        });
        collector.finish(make_result(StopReason::terminal_protocol, 4U));

        PFL_EXPECT(collector.facts().outcome == ImportDissectionOutcome::recognized_non_flow);
        PFL_EXPECT(format_shadow_path(collector.facts()) == "EthernetII -> PPPoE");
    }

    {
        ImportDissectionCollector collector {};
        collector.consume(DissectionStep {
            .layer = DissectionLayerKind::ethernet_ii,
            .path_contribution = LayerKey::ethernet_ii(),
            .status = ParseStatus::complete,
            .stop_reason = StopReason::none,
        });
        collector.consume(DissectionStep {
            .layer = DissectionLayerKind::pppoe,
            .path_contribution = LayerKey::pppoe(),
            .descendant_path_commit_policy = PathCommitPolicy::recognized_flow,
            .status = ParseStatus::complete,
            .stop_reason = StopReason::none,
        });
        collector.consume(DissectionStep {
            .layer = DissectionLayerKind::ipv4,
            .path_contribution = LayerKey::ipv4(),
            .status = ParseStatus::complete,
            .stop_reason = StopReason::none,
        });
        collector.consume(DissectionStep {
            .layer = DissectionLayerKind::arp,
            .path_contribution = LayerKey::arp(),
            .facts = ArpFacts {
                .has_sender_ipv4 = true,
                .has_target_ipv4 = true,
                .sender_ipv4 = ipv4(203, 0, 113, 30),
                .target_ipv4 = ipv4(203, 0, 113, 1),
            },
            .terminal_disposition = TerminalDisposition::recognized_non_flow,
            .status = ParseStatus::complete,
            .stop_reason = StopReason::terminal_protocol,
        });
        collector.finish(make_result(StopReason::terminal_protocol, 4U));

        PFL_EXPECT(collector.facts().outcome == ImportDissectionOutcome::recognized_non_flow);
        PFL_EXPECT(format_shadow_path(collector.facts()) == "EthernetII");
    }

    {
        ImportDissectionCollector collector {};
        collector.consume(DissectionStep {
            .layer = DissectionLayerKind::ieee8023,
            .path_contribution = LayerKey::ieee8023(),
            .path_commit_policy = PathCommitPolicy::recognized_flow,
            .path_contribution_deferrable_by_child = true,
            .status = ParseStatus::complete,
            .stop_reason = StopReason::none,
        });
        collector.consume(DissectionStep {
            .layer = DissectionLayerKind::llc_snap,
            .path_contribution = LayerKey::llc_snap(),
            .path_commit_policy = PathCommitPolicy::recognized_flow_or_recognized_non_flow,
            .defer_last_deferrable_path_contribution = true,
            .status = ParseStatus::complete,
            .stop_reason = StopReason::none,
        });
        collector.finish(make_result(StopReason::truncated, 2U));

        PFL_EXPECT(collector.facts().outcome == ImportDissectionOutcome::unrecognized);
        PFL_EXPECT(format_shadow_path(collector.facts()).empty());
    }

    {
        ImportDissectionCollector collector {};
        collector.consume(DissectionStep {
            .layer = DissectionLayerKind::ieee8023,
            .path_contribution = LayerKey::ieee8023(),
            .path_contribution_deferrable_by_child = true,
            .status = ParseStatus::complete,
            .stop_reason = StopReason::none,
        });
        collector.consume(DissectionStep {
            .layer = DissectionLayerKind::llc_snap,
            .path_contribution = LayerKey::llc_snap(),
            .path_commit_policy = PathCommitPolicy::recognized_flow,
            .defer_last_deferrable_path_contribution = true,
            .status = ParseStatus::complete,
            .stop_reason = StopReason::none,
        });
        collector.consume(DissectionStep {
            .layer = DissectionLayerKind::ipv4,
            .path_contribution = LayerKey::ipv4(),
            .path_commit_policy = PathCommitPolicy::recognized_flow_or_recognized_non_flow,
            .facts = Ipv4Facts {
                .protocol = detail::kIpProtocolUdp,
                .src_addr_v4 = ipv4(192, 0, 2, 40),
                .dst_addr_v4 = ipv4(198, 51, 100, 40),
            },
            .status = ParseStatus::complete,
            .stop_reason = StopReason::none,
        });
        collector.consume(DissectionStep {
            .layer = DissectionLayerKind::udp,
            .path_contribution = LayerKey::udp(),
            .path_commit_policy = PathCommitPolicy::recognized_flow_or_recognized_non_flow,
            .facts = UdpFacts {
                .src_port = 1234U,
                .dst_port = 5678U,
            },
            .terminal_disposition = TerminalDisposition::flow_candidate,
            .status = ParseStatus::complete,
            .stop_reason = StopReason::terminal_protocol,
        });
        collector.finish(make_result(StopReason::terminal_protocol, 4U));

        PFL_EXPECT(collector.facts().outcome == ImportDissectionOutcome::recognized_flow);
        PFL_EXPECT(format_shadow_path(collector.facts()) == "IEEE 802.3 -> LLC/SNAP -> IPv4 -> UDP");
    }
}

void expect_shadow_matches_legacy_igmp_flow(
    const DissectionRegistry& registry,
    const RawPcapPacket& packet,
    const std::string& expected_shadow_path,
    const std::string& expected_legacy_path,
    const StopReason expected_stop_reason,
    const std::uint32_t expected_source,
    const std::uint32_t expected_destination
) {
    const auto legacy = decode_legacy_direct(packet);
    const auto shadow = run_shadow(packet, registry);

    PFL_REQUIRE(legacy.recognized_flow);
    PFL_EXPECT(legacy.protocol == ProtocolId::igmp);
    PFL_EXPECT(legacy.family == DissectionAddressFamily::ipv4);
    PFL_EXPECT(legacy.src_addr_v4 == expected_source);
    PFL_EXPECT(legacy.dst_addr_v4 == expected_destination);
    PFL_EXPECT(format_protocol_path(legacy.path) == expected_legacy_path);
    PFL_EXPECT(legacy.src_port == 0U);
    PFL_EXPECT(legacy.dst_port == 0U);

    PFL_EXPECT(shadow.outcome == ImportDissectionOutcome::recognized_flow);
    PFL_EXPECT(shadow.stop_reason == expected_stop_reason);
    PFL_EXPECT(shadow.terminal_protocol == ProtocolId::igmp);
    PFL_EXPECT(shadow.family == DissectionAddressFamily::ipv4);
    PFL_EXPECT(shadow.has_flow_addresses);
    PFL_EXPECT(shadow.src_addr_v4 == expected_source);
    PFL_EXPECT(shadow.dst_addr_v4 == expected_destination);
    PFL_EXPECT(format_shadow_path(shadow) == expected_shadow_path);
    PFL_EXPECT(!shadow.has_ports);
    PFL_EXPECT(shadow.src_port == 0U);
    PFL_EXPECT(shadow.dst_port == 0U);
    PFL_EXPECT(!shadow.has_transport_payload_length);
    PFL_EXPECT(shadow.captured_transport_payload_length == 0U);
    PFL_EXPECT(!shadow.has_tcp_flags);
    PFL_EXPECT(shadow.tcp_flags == 0U);
}

void expect_shadow_only_nested_igmp_flow(
    const DissectionRegistry& registry,
    const RawPcapPacket& packet,
    const std::string& expected_shadow_path,
    const StopReason expected_stop_reason,
    const std::uint32_t expected_source,
    const std::uint32_t expected_destination
) {
    const auto legacy = decode_legacy_direct(packet);
    const auto shadow = run_shadow(packet, registry);

    PFL_EXPECT(!legacy.recognized_flow);

    PFL_EXPECT(shadow.outcome == ImportDissectionOutcome::recognized_flow);
    PFL_EXPECT(shadow.stop_reason == expected_stop_reason);
    PFL_EXPECT(shadow.terminal_protocol == ProtocolId::igmp);
    PFL_EXPECT(shadow.family == DissectionAddressFamily::ipv4);
    PFL_EXPECT(shadow.has_flow_addresses);
    PFL_EXPECT(shadow.src_addr_v4 == expected_source);
    PFL_EXPECT(shadow.dst_addr_v4 == expected_destination);
    PFL_EXPECT(format_shadow_path(shadow) == expected_shadow_path);
    PFL_EXPECT(!shadow.has_ports);
    PFL_EXPECT(shadow.src_port == 0U);
    PFL_EXPECT(shadow.dst_port == 0U);
    PFL_EXPECT(!shadow.has_transport_payload_length);
    PFL_EXPECT(shadow.captured_transport_payload_length == 0U);
    PFL_EXPECT(!shadow.has_tcp_flags);
    PFL_EXPECT(shadow.tcp_flags == 0U);
}

std::vector<std::uint8_t> add_ipv4_options(
    const std::vector<std::uint8_t>& ethernet_packet,
    const std::vector<std::uint8_t>& options
) {
    PFL_REQUIRE((options.size() % 4U) == 0U);
    auto bytes = ethernet_packet;
    constexpr std::size_t ip_offset = 14U;
    const auto old_header_length = static_cast<std::size_t>((bytes[ip_offset] & 0x0FU) * 4U);
    const auto transport_offset = ip_offset + old_header_length;
    bytes.insert(
        bytes.begin() + static_cast<std::ptrdiff_t>(transport_offset),
        options.begin(),
        options.end()
    );

    bytes[ip_offset] = static_cast<std::uint8_t>((bytes[ip_offset] & 0xF0U) | ((old_header_length + options.size()) / 4U));
    const auto total_length = static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(bytes[ip_offset + 2U]) << 8U) |
        static_cast<std::uint16_t>(bytes[ip_offset + 3U])
    );
    const auto new_total_length = static_cast<std::uint16_t>(total_length + options.size());
    bytes[ip_offset + 2U] = static_cast<std::uint8_t>((new_total_length >> 8U) & 0xFFU);
    bytes[ip_offset + 3U] = static_cast<std::uint8_t>(new_total_length & 0xFFU);
    return bytes;
}

void set_ipv4_total_length(std::vector<std::uint8_t>& packet, const std::uint16_t total_length) {
    constexpr std::size_t ip_offset = 14U;
    packet[ip_offset + 2U] = static_cast<std::uint8_t>((total_length >> 8U) & 0xFFU);
    packet[ip_offset + 3U] = static_cast<std::uint8_t>(total_length & 0xFFU);
}

void set_udp_length(std::vector<std::uint8_t>& packet, const std::uint16_t datagram_length) {
    constexpr std::size_t udp_offset = 14U + 20U;
    packet[udp_offset + 4U] = static_cast<std::uint8_t>((datagram_length >> 8U) & 0xFFU);
    packet[udp_offset + 5U] = static_cast<std::uint8_t>(datagram_length & 0xFFU);
}

std::vector<std::uint8_t> make_ethernet_ieee8023_frame(const std::uint16_t payload_length) {
    std::vector<std::uint8_t> bytes {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
        static_cast<std::uint8_t>((payload_length >> 8U) & 0xFFU),
        static_cast<std::uint8_t>(payload_length & 0xFFU),
    };
    for (std::uint16_t index = 0U; index < payload_length; ++index) {
        bytes.push_back(static_cast<std::uint8_t>(index & 0xFFU));
    }
    return bytes;
}

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

std::vector<std::uint8_t> make_macsec_bytes(
    const std::uint8_t tci_an,
    const std::uint8_t short_length,
    const std::uint32_t packet_number,
    const std::vector<std::uint8_t>& protected_payload = {},
    const bool has_sci = false,
    const std::uint64_t sci = 0x0200000071010001ULL,
    const bool include_full_icv = true,
    const std::vector<std::uint8_t>& icv_override = {}
) {
    std::vector<std::uint8_t> bytes {
        tci_an,
        short_length,
    };
    append_be32(bytes, packet_number);
    if (has_sci) {
        for (int shift = 56; shift >= 0; shift -= 8) {
            bytes.push_back(static_cast<std::uint8_t>((sci >> shift) & 0xFFU));
        }
    }
    bytes.insert(bytes.end(), protected_payload.begin(), protected_payload.end());
    if (include_full_icv) {
        if (icv_override.empty()) {
            for (std::uint8_t index = 0U; index < 16U; ++index) {
                bytes.push_back(static_cast<std::uint8_t>(0xA0U + index));
            }
        } else {
            bytes.insert(bytes.end(), icv_override.begin(), icv_override.end());
        }
    }
    return bytes;
}

void append_mpls_label(
    std::vector<std::uint8_t>& bytes,
    const std::uint32_t label,
    const bool bottom_of_stack,
    const std::uint8_t traffic_class = 0U,
    const std::uint8_t ttl = 64U
) {
    const auto entry = (label << 12U) |
        (static_cast<std::uint32_t>(traffic_class & 0x7U) << 9U) |
        (static_cast<std::uint32_t>(bottom_of_stack ? 1U : 0U) << 8U) |
        static_cast<std::uint32_t>(ttl);
    append_be32(bytes, entry);
}

std::vector<std::uint8_t> make_mpls_payload_with_labels(
    const std::initializer_list<std::uint32_t> labels,
    const std::vector<std::uint8_t>& payload,
    const std::uint8_t traffic_class = 0U,
    const std::uint8_t ttl = 64U
) {
    PFL_REQUIRE(labels.size() > 0U);
    std::vector<std::uint8_t> bytes {};
    std::size_t index = 0U;
    for (const auto label : labels) {
        ++index;
        append_mpls_label(bytes, label, index == labels.size(), traffic_class, ttl);
    }
    bytes.insert(bytes.end(), payload.begin(), payload.end());
    return bytes;
}

std::vector<std::uint8_t> make_ipv4_header_only_packet(const std::uint8_t protocol) {
    std::vector<std::uint8_t> bytes {
        0xde, 0xad, 0xbe, 0xef, 0x00, 0x01,
        0xca, 0xfe, 0xba, 0xbe, 0x00, 0x02,
        0x08, 0x00,
        0x45, 0x00,
    };
    append_be16(bytes, 20U);
    append_be16(bytes, 0U);
    append_be16(bytes, 0U);
    bytes.push_back(64U);
    bytes.push_back(protocol);
    append_be16(bytes, 0U);
    append_be32(bytes, ipv4(10, 0, 0, 1));
    append_be32(bytes, ipv4(10, 0, 0, 2));
    return bytes;
}

std::vector<std::uint8_t> make_sctp_segment(
    const std::uint16_t src_port,
    const std::uint16_t dst_port,
    const std::uint32_t verification_tag,
    const std::uint32_t checksum,
    const std::uint16_t payload_length = 0U
) {
    std::vector<std::uint8_t> bytes {};
    append_be16(bytes, src_port);
    append_be16(bytes, dst_port);
    append_be32(bytes, verification_tag);
    append_be32(bytes, checksum);
    for (std::uint16_t index = 0U; index < payload_length; ++index) {
        bytes.push_back(static_cast<std::uint8_t>(0x30U + (index % 10U)));
    }
    return bytes;
}

std::vector<std::uint8_t> make_ethernet_ipv4_sctp_packet(
    const std::uint32_t src_addr,
    const std::uint32_t dst_addr,
    const std::uint16_t src_port,
    const std::uint16_t dst_port,
    const std::uint32_t verification_tag,
    const std::uint32_t checksum,
    const std::uint16_t payload_length = 0U
) {
    return make_ethernet_ipv4_fragment_packet(
        src_addr,
        dst_addr,
        detail::kIpProtocolSctp,
        0U,
        make_sctp_segment(src_port, dst_port, verification_tag, checksum, payload_length)
    );
}

std::vector<std::uint8_t> make_gre_header(
    const std::uint16_t protocol_type,
    const std::vector<std::uint8_t>& payload = {},
    const bool has_checksum = false,
    const bool has_key = false,
    const bool has_sequence = false,
    const std::uint16_t extra_flags = 0U,
    const std::uint16_t checksum = 0x1234U,
    const std::uint16_t reserved1 = 0x5678U,
    const std::uint32_t key = 0x11111111U,
    const std::uint32_t sequence_number = 0x01020304U
) {
    std::uint16_t flags_and_version = extra_flags;
    if (has_checksum) {
        flags_and_version = static_cast<std::uint16_t>(flags_and_version | detail::kGreFlagChecksum);
    }
    if (has_key) {
        flags_and_version = static_cast<std::uint16_t>(flags_and_version | detail::kGreFlagKey);
    }
    if (has_sequence) {
        flags_and_version = static_cast<std::uint16_t>(flags_and_version | detail::kGreFlagSequence);
    }

    std::vector<std::uint8_t> bytes {};
    append_be16(bytes, flags_and_version);
    append_be16(bytes, protocol_type);
    if (has_checksum) {
        append_be16(bytes, checksum);
        append_be16(bytes, reserved1);
    }
    if (has_key) {
        append_be32(bytes, key);
    }
    if (has_sequence) {
        append_be32(bytes, sequence_number);
    }
    bytes.insert(bytes.end(), payload.begin(), payload.end());
    return bytes;
}

std::vector<std::uint8_t> make_ethernet_ipv4_gre_packet(
    const std::uint32_t src_addr,
    const std::uint32_t dst_addr,
    const std::vector<std::uint8_t>& gre_payload,
    const std::uint16_t flags_fragment = 0U,
    const std::uint8_t ttl = 64U
) {
    return make_ethernet_ipv4_fragment_packet(
        src_addr,
        dst_addr,
        detail::kIpProtocolGre,
        flags_fragment,
        gre_payload,
        ttl
    );
}

std::vector<std::uint8_t> make_ethernet_ipv6_gre_packet(
    const std::array<std::uint8_t, 16>& src_addr,
    const std::array<std::uint8_t, 16>& dst_addr,
    const std::vector<std::uint8_t>& gre_payload
) {
    return make_ethernet_ipv6_packet(
        src_addr,
        dst_addr,
        detail::kIpProtocolGre,
        gre_payload
    );
}

std::vector<std::uint8_t> make_ah_header(
    const std::uint8_t next_header,
    const std::uint32_t spi,
    const std::uint32_t sequence_number,
    const std::vector<std::uint8_t>& icv = {},
    const std::uint16_t reserved = 0U,
    const std::optional<std::uint8_t>& payload_length_field_override = std::nullopt
) {
    PFL_REQUIRE((icv.size() % 4U) == 0U);
    const auto computed_header_length = 12U + icv.size();
    const auto payload_length_field = payload_length_field_override.value_or(
        static_cast<std::uint8_t>((computed_header_length / 4U) - 2U)
    );

    std::vector<std::uint8_t> bytes {};
    bytes.push_back(next_header);
    bytes.push_back(payload_length_field);
    append_be16(bytes, reserved);
    append_be32(bytes, spi);
    append_be32(bytes, sequence_number);
    bytes.insert(bytes.end(), icv.begin(), icv.end());
    return bytes;
}

std::vector<std::uint8_t> make_esp_header(
    const std::uint32_t spi,
    const std::uint32_t sequence_number,
    const std::vector<std::uint8_t>& opaque_payload = {}
) {
    std::vector<std::uint8_t> bytes {};
    append_be32(bytes, spi);
    append_be32(bytes, sequence_number);
    bytes.insert(bytes.end(), opaque_payload.begin(), opaque_payload.end());
    return bytes;
}

std::vector<std::uint8_t> make_ethernet_ipv4_ah_packet(
    const std::uint32_t src_addr,
    const std::uint32_t dst_addr,
    const std::uint8_t next_header,
    const std::vector<std::uint8_t>& inner_payload,
    const std::uint32_t spi = 0x11111111U,
    const std::uint32_t sequence_number = 0x01020304U,
    const std::vector<std::uint8_t>& icv = {},
    const std::uint16_t flags_fragment = 0U
) {
    auto payload = make_ah_header(next_header, spi, sequence_number, icv);
    payload.insert(payload.end(), inner_payload.begin(), inner_payload.end());
    return make_ethernet_ipv4_fragment_packet(
        src_addr,
        dst_addr,
        detail::kIpProtocolAh,
        flags_fragment,
        payload
    );
}

std::vector<std::uint8_t> make_ethernet_ipv6_ah_packet(
    const std::array<std::uint8_t, 16>& src_addr,
    const std::array<std::uint8_t, 16>& dst_addr,
    const std::uint8_t next_header,
    const std::vector<std::uint8_t>& inner_payload,
    const std::uint32_t spi = 0x11111111U,
    const std::uint32_t sequence_number = 0x01020304U,
    const std::vector<std::uint8_t>& icv = {}
) {
    auto payload = make_ah_header(next_header, spi, sequence_number, icv);
    payload.insert(payload.end(), inner_payload.begin(), inner_payload.end());
    return make_ethernet_ipv6_packet(
        src_addr,
        dst_addr,
        detail::kIpProtocolAh,
        payload
    );
}

std::vector<std::uint8_t> make_ethernet_ipv4_esp_packet(
    const std::uint32_t src_addr,
    const std::uint32_t dst_addr,
    const std::uint32_t spi,
    const std::uint32_t sequence_number,
    const std::vector<std::uint8_t>& opaque_payload = {},
    const std::uint16_t flags_fragment = 0U
) {
    return make_ethernet_ipv4_fragment_packet(
        src_addr,
        dst_addr,
        detail::kIpProtocolEsp,
        flags_fragment,
        make_esp_header(spi, sequence_number, opaque_payload)
    );
}

std::vector<std::uint8_t> make_ethernet_ipv6_esp_packet(
    const std::array<std::uint8_t, 16>& src_addr,
    const std::array<std::uint8_t, 16>& dst_addr,
    const std::uint32_t spi,
    const std::uint32_t sequence_number,
    const std::vector<std::uint8_t>& opaque_payload = {}
) {
    return make_ethernet_ipv6_packet(
        src_addr,
        dst_addr,
        detail::kIpProtocolEsp,
        make_esp_header(spi, sequence_number, opaque_payload)
    );
}

std::vector<std::uint8_t> make_ipv4_payload_packet(
    const std::uint32_t src_addr,
    const std::uint32_t dst_addr,
    const std::uint8_t protocol,
    const std::vector<std::uint8_t>& payload,
    const std::uint16_t flags_fragment = 0U,
    const std::uint8_t ttl = 64U
) {
    return strip_ethernet_header(make_ethernet_ipv4_fragment_packet(
        src_addr,
        dst_addr,
        protocol,
        flags_fragment,
        payload,
        ttl
    ));
}

std::vector<std::uint8_t> make_ipv6_payload_packet(
    const std::array<std::uint8_t, 16>& src_addr,
    const std::array<std::uint8_t, 16>& dst_addr,
    const std::uint8_t next_header,
    const std::vector<std::uint8_t>& payload
) {
    return strip_ethernet_header(make_ethernet_ipv6_packet(src_addr, dst_addr, next_header, payload));
}

std::vector<std::uint8_t> make_igmp_message(
    const std::uint8_t type,
    const std::uint8_t code,
    const std::uint16_t checksum,
    const std::uint32_t group_or_control,
    const std::vector<std::uint8_t>& body = {}
) {
    std::vector<std::uint8_t> bytes {};
    bytes.push_back(type);
    bytes.push_back(code);
    append_be16(bytes, checksum);
    append_be32(bytes, group_or_control);
    bytes.insert(bytes.end(), body.begin(), body.end());
    return bytes;
}

std::vector<std::uint8_t> make_ethernet_ipv4_igmp_packet(
    const std::uint32_t src_addr,
    const std::uint32_t dst_addr,
    const std::uint8_t type,
    const std::uint8_t code,
    const std::uint16_t checksum,
    const std::uint32_t group_or_control,
    const std::vector<std::uint8_t>& body = {}
) {
    return make_ethernet_ipv4_fragment_packet(
        src_addr,
        dst_addr,
        detail::kIpProtocolIgmp,
        0U,
        make_igmp_message(type, code, checksum, group_or_control, body)
    );
}

std::vector<std::uint8_t> make_ipv6_tcp_segment(
    const std::uint16_t src_port,
    const std::uint16_t dst_port,
    const std::uint16_t payload_length = 0U,
    const std::uint8_t tcp_flags = 0x18U
) {
    std::vector<std::uint8_t> bytes {};
    append_be16(bytes, src_port);
    append_be16(bytes, dst_port);
    append_be32(bytes, 0U);
    append_be32(bytes, 0U);
    bytes.push_back(0x50U);
    bytes.push_back(tcp_flags);
    append_be16(bytes, 0U);
    append_be16(bytes, 0U);
    append_be16(bytes, 0U);
    for (std::uint16_t index = 0U; index < payload_length; ++index) {
        bytes.push_back(static_cast<std::uint8_t>(0x41U + (index % 26U)));
    }
    return bytes;
}

std::vector<std::uint8_t> make_ipv4_tcp_segment(
    const std::uint16_t src_port,
    const std::uint16_t dst_port,
    const std::uint16_t payload_length = 0U,
    const std::uint8_t tcp_flags = 0x18U
) {
    return make_ipv6_tcp_segment(src_port, dst_port, payload_length, tcp_flags);
}

std::vector<std::uint8_t> make_ipv4_udp_segment(
    const std::uint16_t src_port,
    const std::uint16_t dst_port,
    const std::uint16_t payload_length = 0U
) {
    return make_ipv6_udp_segment(src_port, dst_port, payload_length);
}

std::vector<std::uint8_t> make_ipv6_routing_extension(
    const std::uint8_t next_header,
    const std::vector<std::uint8_t>& payload
) {
    std::vector<std::uint8_t> bytes {
        next_header,
        0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    bytes.insert(bytes.end(), payload.begin(), payload.end());
    return bytes;
}

std::vector<std::uint8_t> make_ipv6_destination_options_extension(
    const std::uint8_t next_header,
    const std::vector<std::uint8_t>& payload
) {
    std::vector<std::uint8_t> bytes {
        next_header,
        0x00,
        0x01, 0x04, 0x00, 0x00, 0x00, 0x00,
    };
    bytes.insert(bytes.end(), payload.begin(), payload.end());
    return bytes;
}

struct StepKindRecorder {
    std::vector<DissectionLayerKind> kinds {};
};

void record_step_kind(void* context, const DissectionStep& step) {
    auto* recorder = static_cast<StepKindRecorder*>(context);
    recorder->kinds.push_back(step.layer);
}

void expect_common_direct_registry_and_root_selector() {
    const auto built = make_common_direct_registry();
    PFL_REQUIRE(built.ok());
    PFL_EXPECT(built.registry->entry_count() == 75U);
    PFL_EXPECT(built.registry->find(make_link_type_selector(kLinkTypeEthernet)) == dissect_ethernet);
    PFL_EXPECT(built.registry->find(make_link_type_selector(kLinkTypeLinuxSll)) == dissect_linux_sll);
    PFL_EXPECT(built.registry->find(make_link_type_selector(kLinkTypeLinuxSll2)) == dissect_linux_sll2);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::linux_cooked_protocol,
        .value = detail::kEtherTypeIpv4,
    }) == dissect_ipv4);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::linux_cooked_protocol,
        .value = detail::kEtherTypeIpv6,
    }) == dissect_ipv6);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::linux_cooked_protocol,
        .value = detail::kEtherTypeArp,
    }) == dissect_linux_cooked_arp);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::linux_cooked_protocol,
        .value = detail::kEtherTypeVlan,
    }) == nullptr);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::linux_cooked_protocol,
        .value = detail::kEtherTypeQinq,
    }) == nullptr);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::linux_cooked_protocol,
        .value = detail::kEtherTypeLegacyVlan,
    }) == nullptr);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::linux_cooked_protocol,
        .value = detail::kEtherTypeMacsec,
    }) == nullptr);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::native_ieee8023_payload,
        .value = kIeee8023PayloadSelectorValue,
    }) == dissect_llc_snap);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::ieee8023_payload,
        .value = kIeee8023PayloadSelectorValue,
    }) == dissect_llc_snap);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::ip_protocol,
        .value = detail::kIpProtocolIcmp,
    }) == dissect_icmp);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::ip_protocol,
        .value = detail::kIpProtocolIgmp,
    }) == dissect_igmp);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::ip_protocol,
        .value = detail::kIpProtocolIpv4Encapsulation,
    }) == dissect_ipv4);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::ip_protocol,
        .value = detail::kIpProtocolIpv6Encapsulation,
    }) == dissect_ipv6);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::ip_protocol,
        .value = detail::kIpProtocolGre,
    }) == dissect_gre);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::ip_protocol,
        .value = detail::kIpProtocolAh,
    }) == dissect_ipv4_ah);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::ip_protocol,
        .value = detail::kIpProtocolEsp,
    }) == dissect_esp);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::ipv6_next_header,
        .value = detail::kIpProtocolIcmpV6,
    }) == dissect_icmpv6);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::ipv6_next_header,
        .value = detail::kIpProtocolIpv4Encapsulation,
    }) == dissect_ipv4);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::ipv6_next_header,
        .value = detail::kIpProtocolIpv6Encapsulation,
    }) == dissect_ipv6);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::ipv6_next_header,
        .value = detail::kIpProtocolGre,
    }) == dissect_gre);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::ipv6_next_header,
        .value = detail::kIpProtocolAh,
    }) == dissect_ipv6_ah);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::ipv6_next_header,
        .value = detail::kIpProtocolEsp,
    }) == dissect_esp);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::llc_snap_pid,
        .value = detail::kEtherTypeIpv4,
    }) == dissect_ipv4);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::llc_snap_pid,
        .value = detail::kEtherTypeIpv6,
    }) == dissect_ipv6);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::llc_snap_pid,
        .value = detail::kEtherTypeArp,
    }) == dissect_arp);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::pbb_inner_frame,
        .value = kPbbInnerFrameSelectorValue,
    }) == dissect_pbb_inner_ethernet);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::pbb_inner_ether_type,
        .value = detail::kEtherTypeIpv4,
    }) == dissect_ipv4);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::pbb_inner_ether_type,
        .value = detail::kEtherTypeIpv6,
    }) == dissect_ipv6);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::pbb_inner_ether_type,
        .value = detail::kEtherTypeArp,
    }) == dissect_arp);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::pbb_inner_ether_type,
        .value = detail::kEtherTypeVlan,
    }) == dissect_pbb_inner_vlan);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::pbb_inner_ether_type,
        .value = detail::kEtherTypeQinq,
    }) == dissect_pbb_inner_vlan);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::pbb_inner_ether_type,
        .value = detail::kEtherTypeLegacyVlan,
    }) == dissect_pbb_inner_vlan);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::pbb_inner_ether_type,
        .value = detail::kEtherTypeMacsec,
    }) == nullptr);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::native_ether_type,
        .value = detail::kEtherTypeIpv4,
    }) == dissect_ipv4);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::native_ether_type,
        .value = detail::kEtherTypeIpv6,
    }) == dissect_ipv6);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::native_ether_type,
        .value = detail::kEtherTypeArp,
    }) == dissect_arp);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::native_ether_type,
        .value = detail::kEtherTypePbb,
    }) == dissect_pbb);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::native_ether_type,
        .value = detail::kEtherTypePppoeDiscovery,
    }) == dissect_pppoe_discovery);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::native_ether_type,
        .value = detail::kEtherTypePppoeSession,
    }) == dissect_pppoe_session);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::native_ether_type,
        .value = detail::kEtherTypeMacsec,
    }) == dissect_macsec);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::native_ether_type,
        .value = detail::kEtherTypeVlan,
    }) == dissect_vlan);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::native_ether_type,
        .value = detail::kEtherTypeQinq,
    }) == dissect_vlan);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::native_ether_type,
        .value = detail::kEtherTypeLegacyVlan,
    }) == dissect_vlan);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::native_ether_type,
        .value = detail::kEtherTypeMplsUnicast,
    }) == dissect_mpls_label);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::ether_type,
        .value = detail::kEtherTypePbb,
    }) == dissect_pbb);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::ether_type,
        .value = detail::kEtherTypePppoeDiscovery,
    }) == dissect_pppoe_discovery);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::ether_type,
        .value = detail::kEtherTypePppoeSession,
    }) == dissect_pppoe_session);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::ether_type,
        .value = detail::kEtherTypeMacsec,
    }) == nullptr);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::ether_type,
        .value = detail::kEtherTypeVlan,
    }) == dissect_embedded_vlan);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::ether_type,
        .value = detail::kEtherTypeQinq,
    }) == dissect_embedded_vlan);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::ether_type,
        .value = detail::kEtherTypeLegacyVlan,
    }) == dissect_embedded_vlan);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::ppp_frame,
        .value = kPppFrameContinueSelectorValue,
    }) == dissect_ppp);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::ppp_protocol,
        .value = detail::kPppProtocolIpv4,
    }) == dissect_ipv4);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::ppp_protocol,
        .value = detail::kPppProtocolIpv6,
    }) == dissect_ipv6);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::ppp_protocol,
        .value = 0xC021U,
    }) == dissect_ppp_control);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::ppp_protocol,
        .value = 0x8021U,
    }) == dissect_ppp_control);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::ppp_protocol,
        .value = 0x8057U,
    }) == dissect_ppp_control);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::ppp_protocol,
        .value = 0x1235U,
    }) == nullptr);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::gre_protocol_type,
        .value = detail::kEtherTypeIpv4,
    }) == dissect_ipv4);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::gre_protocol_type,
        .value = detail::kEtherTypeIpv6,
    }) == dissect_ipv6);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::gre_protocol_type,
        .value = detail::kGreProtocolTypeTransparentEthernetBridging,
    }) == dissect_embedded_ethernet);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::gre_protocol_type,
        .value = detail::kEtherTypeMacsec,
    }) == nullptr);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::gre_protocol_type,
        .value = detail::kEtherTypeMplsUnicast,
    }) == dissect_mpls_label);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::ether_type,
        .value = detail::kEtherTypeMplsUnicast,
    }) == dissect_mpls_label);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::mpls_stack,
        .value = kMplsStackContinueSelectorValue,
    }) == dissect_mpls_label);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::mpls_payload,
        .value = detail::kEtherTypeIpv4,
    }) == dissect_ipv4);
    PFL_EXPECT(built.registry->find(ProtocolSelector {
        .domain = SelectorDomain::mpls_payload,
        .value = detail::kEtherTypeIpv6,
    }) == dissect_ipv6);

    const auto root_selector = make_link_type_selector(kLinkTypeEthernet);
    PFL_EXPECT(root_selector.domain == SelectorDomain::link_type);
    PFL_EXPECT(root_selector.value == kLinkTypeEthernet);
    const auto sll_root_selector = make_link_type_selector(kLinkTypeLinuxSll);
    PFL_EXPECT(sll_root_selector.domain == SelectorDomain::link_type);
    PFL_EXPECT(sll_root_selector.value == kLinkTypeLinuxSll);
    const auto sll2_root_selector = make_link_type_selector(kLinkTypeLinuxSll2);
    PFL_EXPECT(sll2_root_selector.domain == SelectorDomain::link_type);
    PFL_EXPECT(sll2_root_selector.value == kLinkTypeLinuxSll2);
}

void expect_ethernet_and_vlan_canonical_parsers() {
    const auto plain_tcp = make_raw_packet(make_ethernet_ipv4_tcp_packet(ipv4(10, 0, 0, 1), ipv4(10, 0, 0, 2), 1111U, 2222U));
    const auto plain_root = make_root_slice(plain_tcp);
    const auto ethernet = parse_ethernet_frame(plain_root);
    PFL_EXPECT(ethernet.status == ParseStatus::complete);
    PFL_EXPECT(ethernet.protocol_type == 0x0800U);
    PFL_EXPECT(ethernet.header_length == 14U);
    PFL_EXPECT(ethernet.declared_payload_length == 40U);
    PFL_EXPECT(!ethernet.is_ieee_802_3);

    const auto single_tagged = make_raw_packet(make_single_tagged_ethernet_ipv4_tcp_packet(
        ipv4(192, 168, 1, 10), ipv4(192, 168, 1, 20), 12345U, 443U, 100U));
    const auto single_root = make_root_slice(single_tagged);
    const auto single_ethernet = parse_ethernet_frame(single_root);
    PFL_REQUIRE(single_ethernet.status == ParseStatus::complete);
    const auto single_vlan_slice = require_child_slice(
        single_root,
        single_ethernet.header_length,
        single_ethernet.declared_payload_length
    );
    const auto single_vlan = parse_vlan_tag(single_vlan_slice);
    PFL_EXPECT(single_vlan.status == ParseStatus::complete);
    PFL_EXPECT(single_vlan.tci == 100U);
    PFL_EXPECT(single_vlan.encapsulated_ether_type == 0x0800U);
    PFL_EXPECT(single_vlan.header_length == 4U);

    const auto double_tagged = make_raw_packet(make_double_tagged_ethernet_ipv4_udp_packet(
        ipv4(172, 16, 0, 1), ipv4(172, 16, 0, 2), 5353U, 53U, 200U, 300U));
    const auto double_root = make_root_slice(double_tagged);
    const auto double_ethernet = parse_ethernet_frame(double_root);
    PFL_REQUIRE(double_ethernet.status == ParseStatus::complete);
    const auto outer_vlan_slice = require_child_slice(
        double_root,
        double_ethernet.header_length,
        double_ethernet.declared_payload_length
    );
    const auto outer_vlan = parse_vlan_tag(outer_vlan_slice);
    PFL_EXPECT(outer_vlan.status == ParseStatus::complete);
    PFL_EXPECT((outer_vlan.tci & 0x0FFFU) == 200U);
    PFL_EXPECT(outer_vlan.encapsulated_ether_type == 0x8100U);

    const auto inner_vlan_slice = require_child_slice(
        outer_vlan_slice,
        outer_vlan.header_length,
        outer_vlan.declared_payload_length
    );
    const auto inner_vlan = parse_vlan_tag(inner_vlan_slice);
    PFL_EXPECT(inner_vlan.status == ParseStatus::complete);
    PFL_EXPECT((inner_vlan.tci & 0x0FFFU) == 300U);
    PFL_EXPECT(inner_vlan.encapsulated_ether_type == 0x0800U);

    const auto vid_zero = make_raw_packet(make_single_tagged_ethernet_ipv4_tcp_packet(
        ipv4(10, 10, 10, 1), ipv4(10, 10, 10, 2), 2222U, 80U, 0U));
    const auto vid_zero_ethernet = parse_ethernet_frame(make_root_slice(vid_zero));
    PFL_REQUIRE(vid_zero_ethernet.status == ParseStatus::complete);
    const auto vid_zero_vlan = parse_vlan_tag(require_child_slice(
        make_root_slice(vid_zero),
        vid_zero_ethernet.header_length,
        vid_zero_ethernet.declared_payload_length
    ));
    PFL_EXPECT(vid_zero_vlan.status == ParseStatus::complete);
    PFL_EXPECT((vid_zero_vlan.tci & 0x0FFFU) == 0U);

    const auto truncated_ethernet = make_raw_packet(std::vector<std::uint8_t> {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x66, 0x77, 0x88, 0x99,
    });
    PFL_EXPECT(parse_ethernet_frame(make_root_slice(truncated_ethernet)).status == ParseStatus::truncated);

    const auto truncated_vlan = make_raw_packet(std::vector<std::uint8_t> {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
        0x81, 0x00,
        0x00, 0x64,
    }, 18U);
    const auto truncated_vlan_ethernet = parse_ethernet_frame(make_root_slice(truncated_vlan));
    PFL_REQUIRE(truncated_vlan_ethernet.status == ParseStatus::complete);
    PFL_EXPECT(parse_vlan_tag(require_child_slice(
        make_root_slice(truncated_vlan),
        truncated_vlan_ethernet.header_length,
        truncated_vlan_ethernet.declared_payload_length
    )).status == ParseStatus::truncated);

    const auto ieee8023 = make_raw_packet(make_ethernet_ieee8023_frame(16U));
    const auto parsed_ieee8023 = parse_ethernet_frame(make_root_slice(ieee8023));
    PFL_EXPECT(parsed_ieee8023.status == ParseStatus::complete);
    PFL_EXPECT(parsed_ieee8023.is_ieee_802_3);
    PFL_EXPECT(parsed_ieee8023.protocol_type == 16U);
}

void expect_ipv4_tcp_udp_and_arp_canonical_parsers() {
    const auto registry = make_common_direct_registry();
    PFL_REQUIRE(registry.ok());

    const auto tcp_packet_bytes = make_ethernet_ipv4_tcp_packet_with_payload(
        ipv4(10, 0, 0, 3), ipv4(10, 0, 0, 4), 12345U, 443U, 6U, 0x1BU);
    const auto tcp_packet = make_raw_packet(tcp_packet_bytes);
    const auto tcp_root = make_root_slice(tcp_packet);
    const auto tcp_ethernet = parse_ethernet_frame(tcp_root);
    const auto tcp_ipv4 = parse_ipv4_packet(require_child_slice(tcp_root, tcp_ethernet.header_length, tcp_ethernet.declared_payload_length));
    PFL_EXPECT(tcp_ipv4.status == ParseStatus::complete);
    PFL_EXPECT(tcp_ipv4.protocol == 6U);
    PFL_EXPECT(tcp_ipv4.header_length == 20U);
    PFL_EXPECT(tcp_ipv4.total_length == 46U);
    PFL_EXPECT(!tcp_ipv4.is_fragmented);

    const auto tcp_transport = parse_tcp_segment(require_child_slice(
        require_child_slice(tcp_root, tcp_ethernet.header_length, tcp_ethernet.declared_payload_length),
        tcp_ipv4.header_length,
        tcp_ipv4.nominal_packet_end - tcp_ipv4.header_length
    ));
    PFL_EXPECT(tcp_transport.status == ParseStatus::complete);
    PFL_EXPECT(tcp_transport.src_port == 12345U);
    PFL_EXPECT(tcp_transport.dst_port == 443U);
    PFL_EXPECT(tcp_transport.captured_payload_length == 6U);
    PFL_EXPECT(tcp_transport.flags == 0x1BU);

    auto ipv4_options_bytes = add_ipv4_options(
        make_ethernet_ipv4_tcp_packet(ipv4(10, 0, 0, 5), ipv4(10, 0, 0, 6), 4444U, 5555U),
        {0x01, 0x01, 0x00, 0x00}
    );
    const auto ipv4_options_packet = make_raw_packet(ipv4_options_bytes);
    const auto ipv4_options_root = make_root_slice(ipv4_options_packet);
    const auto ipv4_options_ethernet = parse_ethernet_frame(ipv4_options_root);
    const auto ipv4_options_ipv4_slice = require_child_slice(
        ipv4_options_root,
        ipv4_options_ethernet.header_length,
        ipv4_options_ethernet.declared_payload_length
    );
    const auto ipv4_options_ipv4 = parse_ipv4_packet(ipv4_options_ipv4_slice);
    PFL_EXPECT(ipv4_options_ipv4.status == ParseStatus::complete);
    PFL_EXPECT(ipv4_options_ipv4.header_length == 24U);
    const auto ipv4_options_transport = parse_tcp_segment(require_child_slice(
        ipv4_options_ipv4_slice,
        ipv4_options_ipv4.header_length,
        ipv4_options_ipv4.nominal_packet_end - ipv4_options_ipv4.header_length
    ));
    PFL_EXPECT(ipv4_options_transport.status == ParseStatus::complete);
    PFL_EXPECT(ipv4_options_transport.header_length == 20U);

    auto tcp_options_bytes = make_ethernet_ipv4_tcp_packet(ipv4(10, 0, 0, 7), ipv4(10, 0, 0, 8), 6666U, 7777U);
    tcp_options_bytes.insert(tcp_options_bytes.end(), {0x01, 0x01, 0x00, 0x00});
    set_ipv4_total_length(tcp_options_bytes, 44U);
    tcp_options_bytes[46] = 0x60U;
    const auto tcp_options_packet = make_raw_packet(tcp_options_bytes);
    const auto tcp_options_root = make_root_slice(tcp_options_packet);
    const auto tcp_options_ethernet = parse_ethernet_frame(tcp_options_root);
    const auto tcp_options_ipv4_slice = require_child_slice(
        tcp_options_root,
        tcp_options_ethernet.header_length,
        tcp_options_ethernet.declared_payload_length
    );
    const auto tcp_options_ipv4 = parse_ipv4_packet(tcp_options_ipv4_slice);
    PFL_EXPECT(tcp_options_ipv4.status == ParseStatus::complete);
    PFL_EXPECT(tcp_options_ipv4.header_length == 20U);
    const auto tcp_options_transport = parse_tcp_segment(require_child_slice(
        tcp_options_ipv4_slice,
        tcp_options_ipv4.header_length,
        tcp_options_ipv4.nominal_packet_end - tcp_options_ipv4.header_length
    ));
    PFL_EXPECT(tcp_options_transport.status == ParseStatus::complete);
    PFL_EXPECT(tcp_options_transport.header_length == 24U);

    const auto udp_packet = make_raw_packet(make_ethernet_ipv4_udp_packet_with_bytes_payload(
        ipv4(192, 0, 2, 1), ipv4(192, 0, 2, 2), 5300U, 53U, {0x61, 0x62, 0x63, 0x64}));
    const auto udp_root = make_root_slice(udp_packet);
    const auto udp_ethernet = parse_ethernet_frame(udp_root);
    const auto udp_ipv4_slice = require_child_slice(udp_root, udp_ethernet.header_length, udp_ethernet.declared_payload_length);
    const auto udp_ipv4 = parse_ipv4_packet(udp_ipv4_slice);
    PFL_EXPECT(udp_ipv4.status == ParseStatus::complete);
    PFL_EXPECT(udp_ipv4.protocol == 17U);
    const auto udp_transport = parse_udp_datagram(require_child_slice(
        udp_ipv4_slice,
        udp_ipv4.header_length,
        udp_ipv4.nominal_packet_end - udp_ipv4.header_length
    ));
    PFL_EXPECT(udp_transport.status == ParseStatus::complete);
    PFL_EXPECT(udp_transport.src_port == 5300U);
    PFL_EXPECT(udp_transport.dst_port == 53U);
    PFL_EXPECT(udp_transport.datagram_length == 12U);
    PFL_EXPECT(udp_transport.captured_payload_length == 4U);

    const auto udp_zero_payload = make_raw_packet(make_ethernet_ipv4_udp_packet(
        ipv4(203, 0, 113, 1), ipv4(203, 0, 113, 2), 1000U, 2000U));
    const auto udp_zero_root = make_root_slice(udp_zero_payload);
    const auto udp_zero_ethernet = parse_ethernet_frame(udp_zero_root);
    const auto udp_zero_ipv4 = parse_ipv4_packet(require_child_slice(
        udp_zero_root,
        udp_zero_ethernet.header_length,
        udp_zero_ethernet.declared_payload_length
    ));
    const auto udp_zero_transport = parse_udp_datagram(require_child_slice(
        require_child_slice(udp_zero_root, udp_zero_ethernet.header_length, udp_zero_ethernet.declared_payload_length),
        udp_zero_ipv4.header_length,
        udp_zero_ipv4.nominal_packet_end - udp_zero_ipv4.header_length
    ));
    PFL_EXPECT(udp_zero_transport.status == ParseStatus::complete);
    PFL_EXPECT(udp_zero_transport.captured_payload_length == 0U);

    auto udp_extra_tail = make_ethernet_ipv4_udp_packet(ipv4(203, 0, 113, 10), ipv4(203, 0, 113, 11), 1200U, 2200U);
    udp_extra_tail.push_back(0xAAU);
    udp_extra_tail.push_back(0xBBU);
    udp_extra_tail.push_back(0xCCU);
    const auto udp_extra_tail_packet = make_raw_packet(udp_extra_tail);
    const auto udp_extra_tail_shadow = run_shadow(udp_extra_tail_packet, *registry.registry);
    PFL_EXPECT(udp_extra_tail_shadow.has_transport_payload_length);
    PFL_EXPECT(udp_extra_tail_shadow.captured_transport_payload_length == 0U);

    auto truncated_udp_payload = make_ethernet_ipv4_udp_packet_with_bytes_payload(
        ipv4(203, 0, 113, 20), ipv4(203, 0, 113, 21), 1300U, 2300U, {0x10, 0x20, 0x30, 0x40});
    truncated_udp_payload.resize(truncated_udp_payload.size() - 2U);
    const auto truncated_udp_packet = make_raw_packet(truncated_udp_payload, 46U);
    const auto truncated_udp_shadow = run_shadow(truncated_udp_packet, *registry.registry);
    PFL_EXPECT(truncated_udp_shadow.outcome == ImportDissectionOutcome::recognized_flow);
    PFL_EXPECT(truncated_udp_shadow.captured_transport_payload_length == 2U);

    auto malformed_udp = make_ethernet_ipv4_udp_packet(ipv4(10, 1, 1, 1), ipv4(10, 1, 1, 2), 3000U, 4000U);
    set_udp_length(malformed_udp, 7U);
    const auto malformed_udp_raw = make_raw_packet(malformed_udp);
    const auto malformed_udp_root = make_root_slice(malformed_udp_raw);
    PFL_EXPECT(parse_udp_datagram(require_child_slice(
        require_child_slice(
            malformed_udp_root,
            14U,
            malformed_udp.size() - 14U
        ),
        20U,
        8U
    )).status == ParseStatus::malformed);

    auto invalid_ihl = make_ethernet_ipv4_tcp_packet(ipv4(10, 1, 2, 1), ipv4(10, 1, 2, 2), 100U, 200U);
    invalid_ihl[14] = 0x44U;
    const auto invalid_ihl_raw = make_raw_packet(invalid_ihl);
    const auto invalid_ihl_root = make_root_slice(invalid_ihl_raw);
    PFL_EXPECT(parse_ipv4_packet(require_child_slice(
        invalid_ihl_root,
        14U,
        invalid_ihl.size() - 14U
    )).status == ParseStatus::malformed);

    auto short_total_length = make_ethernet_ipv4_tcp_packet(ipv4(10, 1, 3, 1), ipv4(10, 1, 3, 2), 100U, 200U);
    set_ipv4_total_length(short_total_length, 16U);
    const auto short_total_length_raw = make_raw_packet(short_total_length);
    const auto short_total_length_root = make_root_slice(short_total_length_raw);
    PFL_EXPECT(parse_ipv4_packet(require_child_slice(
        short_total_length_root,
        14U,
        short_total_length.size() - 14U
    )).status == ParseStatus::malformed);

    const auto header_only_ipv4 = make_raw_packet(make_ipv4_header_only_packet(6U));
    const auto header_only_shadow = run_shadow(header_only_ipv4, *registry.registry);
    PFL_EXPECT(header_only_shadow.stop_reason == StopReason::malformed);
    PFL_EXPECT(format_shadow_path(header_only_shadow) == "EthernetII -> IPv4");

    const auto first_fragment_packet = make_raw_packet(make_ethernet_ipv4_fragment_packet(
        ipv4(10, 2, 0, 1), ipv4(10, 2, 0, 2), 6U, 0x2000U, {0x16, 0x03, 0x03, 0x00, 0x10}));
    const auto first_fragment_ipv4 = parse_ipv4_packet(require_child_slice(
        make_root_slice(first_fragment_packet),
        14U,
        first_fragment_packet.bytes.size() - 14U
    ));
    PFL_EXPECT(first_fragment_ipv4.status == ParseStatus::complete);
    PFL_EXPECT(first_fragment_ipv4.is_fragmented);
    PFL_EXPECT(first_fragment_ipv4.more_fragments);
    PFL_EXPECT(first_fragment_ipv4.fragment_offset_units == 0U);

    const auto noninitial_fragment_packet = make_raw_packet(make_ethernet_ipv4_fragment_packet(
        ipv4(10, 2, 0, 3), ipv4(10, 2, 0, 4), 17U, 0x0001U, {0xde, 0xad, 0xbe, 0xef}));
    const auto noninitial_fragment_ipv4 = parse_ipv4_packet(require_child_slice(
        make_root_slice(noninitial_fragment_packet),
        14U,
        noninitial_fragment_packet.bytes.size() - 14U
    ));
    PFL_EXPECT(noninitial_fragment_ipv4.status == ParseStatus::complete);
    PFL_EXPECT(noninitial_fragment_ipv4.is_fragmented);
    PFL_EXPECT(!noninitial_fragment_ipv4.more_fragments);
    PFL_EXPECT(noninitial_fragment_ipv4.fragment_offset_units == 1U);

    const auto arp_bytes = make_ethernet_arp_packet(ipv4(10, 10, 12, 2), ipv4(10, 10, 12, 1));
    const auto arp_packet = make_raw_packet(arp_bytes);
    const auto arp_root = make_root_slice(arp_packet);
    const auto arp_ethernet = parse_ethernet_frame(arp_root);
    const auto arp = parse_arp_packet(require_child_slice(
        arp_root,
        arp_ethernet.header_length,
        arp_ethernet.declared_payload_length
    ));
    PFL_EXPECT(arp.status == ParseStatus::complete);
    PFL_EXPECT(arp.declared_length == 28U);
    PFL_EXPECT(arp.has_sender_ipv4);
    PFL_EXPECT(arp.has_target_ipv4);
    PFL_EXPECT(arp.sender_ipv4 == ipv4(10, 10, 12, 2));
    PFL_EXPECT(arp.target_ipv4 == ipv4(10, 10, 12, 1));

    auto truncated_arp_bytes = arp_bytes;
    truncated_arp_bytes.resize(18U);
    const auto truncated_arp_packet = make_raw_packet(
        truncated_arp_bytes,
        static_cast<std::uint32_t>(arp_bytes.size())
    );
    const auto truncated_arp_root = make_root_slice(truncated_arp_packet);
    const auto truncated_arp = parse_arp_packet(require_child_slice(
        truncated_arp_root,
        14U,
        arp_bytes.size() - 14U
    ));
    PFL_EXPECT(truncated_arp.status == ParseStatus::truncated);
    PFL_EXPECT(truncated_arp.fixed_header_truncated);
    PFL_EXPECT(!truncated_arp.address_section_truncated);

    auto truncated_arp_address_bytes = arp_bytes;
    truncated_arp_address_bytes.resize(30U);
    const auto truncated_arp_address_packet = make_raw_packet(
        truncated_arp_address_bytes,
        static_cast<std::uint32_t>(arp_bytes.size())
    );
    const auto truncated_arp_address_root = make_root_slice(truncated_arp_address_packet);
    const auto truncated_arp_address = parse_arp_packet(require_child_slice(
        truncated_arp_address_root,
        14U,
        arp_bytes.size() - 14U
    ));
    PFL_EXPECT(truncated_arp_address.status == ParseStatus::truncated);
    PFL_EXPECT(!truncated_arp_address.fixed_header_truncated);
    PFL_EXPECT(truncated_arp_address.address_section_truncated);
    PFL_EXPECT(truncated_arp_address.declared_length == 28U);

    auto impossible_arp_bytes = arp_bytes;
    impossible_arp_bytes[18] = 6U;
    impossible_arp_bytes[19] = 16U;
    const auto impossible_arp_packet = make_raw_packet(impossible_arp_bytes);
    const auto impossible_arp_root = make_root_slice(impossible_arp_packet);
    const auto impossible_arp_ethernet = parse_ethernet_frame(impossible_arp_root);
    PFL_REQUIRE(impossible_arp_ethernet.status == ParseStatus::complete);
    const auto impossible_arp = parse_arp_packet(require_child_slice(
        impossible_arp_root,
        impossible_arp_ethernet.header_length,
        impossible_arp_ethernet.declared_payload_length
    ));
    PFL_EXPECT(impossible_arp.status == ParseStatus::malformed);
    PFL_EXPECT(!impossible_arp.fixed_header_truncated);
    PFL_EXPECT(!impossible_arp.address_section_truncated);
    PFL_EXPECT(impossible_arp.declared_length == 52U);
}

void expect_common_direct_steps_report_handoffs_bounds_and_facts() {
    const auto tcp_packet = make_raw_packet(make_ethernet_ipv4_tcp_packet_with_payload(
        ipv4(10, 0, 0, 3), ipv4(10, 0, 0, 4), 12345U, 443U, 6U, 0x1BU));
    const auto tcp_root = make_root_slice(tcp_packet);
    const auto ethernet_step = dissect_ethernet(tcp_root);
    PFL_EXPECT(ethernet_step.layer == DissectionLayerKind::ethernet_ii);
    PFL_REQUIRE(ethernet_step.path_contribution.has_value());
    PFL_EXPECT(*ethernet_step.path_contribution == LayerKey::ethernet_ii());
    PFL_REQUIRE(ethernet_step.handoff.has_value());
    PFL_REQUIRE(ethernet_step.handoff->child.has_value());
    const ProtocolSelector expected_ethernet_selector {
        .domain = SelectorDomain::native_ether_type,
        .value = 0x0800U,
    };
    PFL_EXPECT(ethernet_step.handoff->selector == expected_ethernet_selector);
    PFL_EXPECT(std::holds_alternative<EthernetFacts>(ethernet_step.facts));
    PFL_EXPECT(ethernet_step.bounds.full.declared == require_range(0U, tcp_packet.bytes.size()));
    PFL_EXPECT(ethernet_step.bounds.full.captured == require_range(0U, tcp_packet.bytes.size()));
    PFL_REQUIRE(ethernet_step.bounds.payload.has_value());
    PFL_EXPECT(ethernet_step.bounds.payload->declared == require_range(14U, tcp_packet.bytes.size()));

    const auto ipv4_step = dissect_ipv4(*ethernet_step.handoff->child);
    PFL_EXPECT(ipv4_step.layer == DissectionLayerKind::ipv4);
    PFL_REQUIRE(ipv4_step.path_contribution.has_value());
    PFL_EXPECT(*ipv4_step.path_contribution == LayerKey::ipv4());
    PFL_REQUIRE(ipv4_step.handoff.has_value());
    PFL_REQUIRE(ipv4_step.handoff->child.has_value());
    const ProtocolSelector expected_ipv4_selector {
        .domain = SelectorDomain::ip_protocol,
        .value = 6U,
    };
    PFL_EXPECT(ipv4_step.handoff->selector == expected_ipv4_selector);
    PFL_EXPECT(std::holds_alternative<Ipv4Facts>(ipv4_step.facts));
    const auto* ipv4_facts = std::get_if<Ipv4Facts>(&ipv4_step.facts);
    PFL_REQUIRE(ipv4_facts != nullptr);
    PFL_EXPECT(ipv4_facts->protocol == 6U);
    PFL_EXPECT(ipv4_facts->src_addr_v4 == ipv4(10, 0, 0, 3));
    PFL_EXPECT(ipv4_facts->dst_addr_v4 == ipv4(10, 0, 0, 4));

    const auto tcp_step = dissect_tcp(*ipv4_step.handoff->child);
    PFL_EXPECT(tcp_step.layer == DissectionLayerKind::tcp);
    PFL_REQUIRE(tcp_step.path_contribution.has_value());
    PFL_EXPECT(*tcp_step.path_contribution == LayerKey::tcp());
    PFL_EXPECT(tcp_step.terminal_disposition == TerminalDisposition::flow_candidate);
    PFL_EXPECT(std::holds_alternative<TcpFacts>(tcp_step.facts));
    const auto* tcp_facts = std::get_if<TcpFacts>(&tcp_step.facts);
    PFL_REQUIRE(tcp_facts != nullptr);
    PFL_EXPECT(tcp_facts->src_port == 12345U);
    PFL_EXPECT(tcp_facts->dst_port == 443U);
    PFL_EXPECT(tcp_facts->flags == 0x1BU);
    PFL_REQUIRE(tcp_step.bounds.payload.has_value());
    PFL_EXPECT(tcp_step.bounds.payload->captured.length() == 6U);

    auto udp_extra_tail = make_ethernet_ipv4_udp_packet(ipv4(203, 0, 113, 10), ipv4(203, 0, 113, 11), 1200U, 2200U);
    udp_extra_tail.push_back(0xAAU);
    udp_extra_tail.push_back(0xBBU);
    udp_extra_tail.push_back(0xCCU);
    set_ipv4_total_length(udp_extra_tail, 31U);
    const auto udp_packet = make_raw_packet(udp_extra_tail);
    const auto udp_root = make_root_slice(udp_packet);
    const auto udp_ethernet = parse_ethernet_frame(udp_root);
    PFL_REQUIRE(udp_ethernet.status == ParseStatus::complete);
    const auto udp_ipv4_slice = require_child_slice(udp_root, udp_ethernet.header_length, udp_ethernet.declared_payload_length);
    const auto udp_ipv4 = parse_ipv4_packet(udp_ipv4_slice);
    PFL_REQUIRE(udp_ipv4.status == ParseStatus::complete);
    const auto udp_transport_slice = require_child_slice(
        udp_ipv4_slice,
        udp_ipv4.header_length,
        udp_ipv4.nominal_packet_end - udp_ipv4.header_length
    );
    PFL_EXPECT(udp_transport_slice.declared_end() - udp_transport_slice.source_offset() == 11U);
    const auto udp_step = dissect_udp(udp_transport_slice);
    PFL_EXPECT(udp_step.layer == DissectionLayerKind::udp);
    PFL_REQUIRE(udp_step.path_contribution.has_value());
    PFL_EXPECT(*udp_step.path_contribution == LayerKey::udp());
    PFL_EXPECT(udp_step.terminal_disposition == TerminalDisposition::flow_candidate);
    PFL_EXPECT(std::holds_alternative<UdpFacts>(udp_step.facts));
    const auto* udp_facts = std::get_if<UdpFacts>(&udp_step.facts);
    PFL_REQUIRE(udp_facts != nullptr);
    PFL_EXPECT(udp_facts->datagram_length == 8U);
    PFL_EXPECT(udp_step.bounds.full.declared.length() == 8U);
    PFL_EXPECT(udp_step.bounds.full.captured.length() == 8U);
    PFL_REQUIRE(udp_step.bounds.payload.has_value());
    PFL_EXPECT(udp_step.bounds.payload->declared.length() == 0U);
    PFL_EXPECT(udp_step.bounds.payload->captured.length() == 0U);

    const auto ipv6_udp_packet = make_raw_packet(make_ethernet_ipv6_udp_with_hop_by_hop_packet(
        ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5}),
        ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6}),
        53000U,
        53001U
    ));
    const auto ipv6_udp_root = make_root_slice(ipv6_udp_packet);
    const auto ipv6_udp_ethernet = dissect_ethernet(ipv6_udp_root);
    PFL_REQUIRE(ipv6_udp_ethernet.handoff.has_value());
    PFL_REQUIRE(ipv6_udp_ethernet.handoff->child.has_value());
    const auto ipv6_step = dissect_ipv6(*ipv6_udp_ethernet.handoff->child);
    PFL_EXPECT(ipv6_step.layer == DissectionLayerKind::ipv6);
    PFL_REQUIRE(ipv6_step.path_contribution.has_value());
    PFL_EXPECT(*ipv6_step.path_contribution == LayerKey::ipv6());
    PFL_REQUIRE(ipv6_step.handoff.has_value());
    PFL_REQUIRE(ipv6_step.handoff->child.has_value());
    const ProtocolSelector expected_ipv6_selector {
        .domain = SelectorDomain::ipv6_next_header,
        .value = detail::kIpProtocolHopByHop,
    };
    PFL_EXPECT(ipv6_step.handoff->selector == expected_ipv6_selector);
    PFL_EXPECT(std::holds_alternative<Ipv6Facts>(ipv6_step.facts));
    const auto* ipv6_facts = std::get_if<Ipv6Facts>(&ipv6_step.facts);
    PFL_REQUIRE(ipv6_facts != nullptr);
    PFL_EXPECT(ipv6_facts->next_header == detail::kIpProtocolHopByHop);
    PFL_EXPECT(!ipv6_facts->has_fragment_header);
    PFL_REQUIRE(ipv6_step.bounds.payload.has_value());
    PFL_EXPECT(ipv6_step.bounds.payload->declared.length() == 16U);

    const auto hop_by_hop_step = dissect_ipv6_hop_by_hop(*ipv6_step.handoff->child);
    PFL_EXPECT(hop_by_hop_step.layer == DissectionLayerKind::ipv6_hop_by_hop);
    PFL_EXPECT(!hop_by_hop_step.path_contribution.has_value());
    PFL_REQUIRE(hop_by_hop_step.handoff.has_value());
    PFL_REQUIRE(hop_by_hop_step.handoff->child.has_value());
    const ProtocolSelector expected_hop_selector {
        .domain = SelectorDomain::ipv6_next_header,
        .value = detail::kIpProtocolUdp,
    };
    PFL_EXPECT(hop_by_hop_step.handoff->selector == expected_hop_selector);
    PFL_EXPECT(std::holds_alternative<Ipv6ExtensionFacts>(hop_by_hop_step.facts));
    const auto* hop_by_hop_facts = std::get_if<Ipv6ExtensionFacts>(&hop_by_hop_step.facts);
    PFL_REQUIRE(hop_by_hop_facts != nullptr);
    PFL_EXPECT(hop_by_hop_facts->kind == DissectionLayerKind::ipv6_hop_by_hop);
    PFL_EXPECT(hop_by_hop_facts->next_header == detail::kIpProtocolUdp);
    PFL_EXPECT(hop_by_hop_step.bounds.source_id == ipv6_step.bounds.source_id);
    PFL_EXPECT(hop_by_hop_step.bounds.full.declared.length() == 8U);
    PFL_EXPECT(hop_by_hop_step.bounds.header.declared.length() == 8U);
    PFL_EXPECT(!hop_by_hop_step.bounds.payload.has_value());

    const auto ipv6_udp_step = dissect_udp(*hop_by_hop_step.handoff->child);
    PFL_EXPECT(ipv6_udp_step.layer == DissectionLayerKind::udp);
    PFL_EXPECT(ipv6_udp_step.terminal_disposition == TerminalDisposition::flow_candidate);
    PFL_REQUIRE(ipv6_udp_step.bounds.payload.has_value());
    PFL_EXPECT(ipv6_udp_step.bounds.payload->declared.length() == 0U);
}

void expect_ipv4_options_shadow_parsing_and_declared_boundary_semantics() {
    const auto registry = make_common_direct_registry();
    PFL_REQUIRE(registry.ok());

    {
        const auto plain_packet = make_raw_packet(make_ethernet_ipv4_tcp_packet(
            ipv4(10, 20, 0, 1), ipv4(10, 20, 0, 2), 1111U, 2222U));
        const auto plain_root = make_root_slice(plain_packet);
        const auto plain_ethernet = parse_ethernet_frame(plain_root);
        PFL_REQUIRE(plain_ethernet.status == ParseStatus::complete);
        const auto plain_ipv4_step = dissect_ipv4(require_child_slice(
            plain_root,
            plain_ethernet.header_length,
            plain_ethernet.declared_payload_length
        ));
        const auto* plain_facts = std::get_if<Ipv4Facts>(&plain_ipv4_step.facts);
        PFL_REQUIRE(plain_facts != nullptr);
        PFL_EXPECT(plain_facts->options.status == Ipv4OptionsParseStatus::not_present);
        PFL_EXPECT(plain_facts->options.options_length == 0U);
    }

    {
        const auto options_packet = make_raw_packet(add_ipv4_options(
            make_ethernet_ipv4_udp_packet(ipv4(10, 20, 1, 1), ipv4(10, 20, 1, 2), 3000U, 4000U),
            {0x01, 0x94, 0x04, 0x00, 0x00, 0x94, 0x04, 0x12, 0x34, 0x00, 0x00, 0x00}
        ));
        const auto options_root = make_root_slice(options_packet);
        const auto options_ethernet = parse_ethernet_frame(options_root);
        PFL_REQUIRE(options_ethernet.status == ParseStatus::complete);
        const auto options_ipv4_step = dissect_ipv4(require_child_slice(
            options_root,
            options_ethernet.header_length,
            options_ethernet.declared_payload_length
        ));
        PFL_EXPECT(options_ipv4_step.layer == DissectionLayerKind::ipv4);
        PFL_REQUIRE(options_ipv4_step.path_contribution.has_value());
        PFL_EXPECT(*options_ipv4_step.path_contribution == LayerKey::ipv4());
        PFL_REQUIRE(options_ipv4_step.handoff.has_value());
        PFL_REQUIRE(options_ipv4_step.handoff->child.has_value());
        const ProtocolSelector expected_udp_selector {
            .domain = SelectorDomain::ip_protocol,
            .value = detail::kIpProtocolUdp,
        };
        PFL_EXPECT(options_ipv4_step.handoff->selector == expected_udp_selector);
        const auto* options_facts = std::get_if<Ipv4Facts>(&options_ipv4_step.facts);
        PFL_REQUIRE(options_facts != nullptr);
        PFL_EXPECT(options_facts->header_length == 32U);
        PFL_EXPECT(options_facts->options.status == Ipv4OptionsParseStatus::well_formed);
        PFL_EXPECT(options_facts->options.options_length == 12U);
        PFL_EXPECT(options_facts->options.parsed_option_count == 4U);
        PFL_EXPECT(options_facts->options.nop_count == 1U);
        PFL_EXPECT(options_facts->options.has_end_of_list);
        PFL_EXPECT(!options_facts->options.has_nonzero_padding);
        PFL_EXPECT(options_facts->options.has_router_alert);
        PFL_EXPECT(options_facts->options.router_alert_value == 0x1234U);
        PFL_EXPECT(!options_facts->options.has_malformed_offset);
        expect_shadow_matches_legacy_flow(
            *registry.registry,
            options_packet,
            "EthernetII -> IPv4 -> UDP",
            StopReason::terminal_protocol
        );
    }

    {
        const auto malformed_router_alert_packet = make_raw_packet(add_ipv4_options(
            make_ethernet_ipv4_udp_packet(ipv4(10, 20, 2, 1), ipv4(10, 20, 2, 2), 5000U, 5001U),
            {0x94, 0x03, 0x00, 0x00}
        ));
        const auto malformed_root = make_root_slice(malformed_router_alert_packet);
        const auto malformed_ethernet = parse_ethernet_frame(malformed_root);
        PFL_REQUIRE(malformed_ethernet.status == ParseStatus::complete);
        const auto malformed_step = dissect_ipv4(require_child_slice(
            malformed_root,
            malformed_ethernet.header_length,
            malformed_ethernet.declared_payload_length
        ));
        PFL_EXPECT(malformed_step.status == ParseStatus::complete);
        PFL_REQUIRE(malformed_step.path_contribution.has_value());
        PFL_REQUIRE(malformed_step.handoff.has_value());
        const auto* malformed_facts = std::get_if<Ipv4Facts>(&malformed_step.facts);
        PFL_REQUIRE(malformed_facts != nullptr);
        PFL_EXPECT(malformed_facts->options.status == Ipv4OptionsParseStatus::malformed);
        PFL_EXPECT(malformed_facts->options.parsed_option_count == 1U);
        PFL_EXPECT(malformed_facts->options.has_router_alert == false);
        PFL_EXPECT(malformed_facts->options.has_malformed_offset);
        PFL_EXPECT(malformed_facts->options.malformed_offset == 0U);
        expect_shadow_matches_legacy_flow(
            *registry.registry,
            malformed_router_alert_packet,
            "EthernetII -> IPv4 -> UDP",
            StopReason::terminal_protocol
        );
    }

    {
        const auto malformed_missing_length_packet = make_raw_packet(add_ipv4_options(
            make_ethernet_ipv4_tcp_packet(ipv4(10, 20, 3, 1), ipv4(10, 20, 3, 2), 6000U, 6001U),
            {0x01, 0x01, 0x01, 0x44}
        ));
        const auto malformed_root = make_root_slice(malformed_missing_length_packet);
        const auto malformed_ethernet = parse_ethernet_frame(malformed_root);
        PFL_REQUIRE(malformed_ethernet.status == ParseStatus::complete);
        const auto malformed_step = dissect_ipv4(require_child_slice(
            malformed_root,
            malformed_ethernet.header_length,
            malformed_ethernet.declared_payload_length
        ));
        const auto* malformed_facts = std::get_if<Ipv4Facts>(&malformed_step.facts);
        PFL_REQUIRE(malformed_facts != nullptr);
        PFL_EXPECT(malformed_facts->options.status == Ipv4OptionsParseStatus::malformed);
        PFL_EXPECT(malformed_facts->options.nop_count == 3U);
        PFL_EXPECT(malformed_facts->options.parsed_option_count == 3U);
        PFL_EXPECT(malformed_facts->options.has_malformed_offset);
        PFL_EXPECT(malformed_facts->options.malformed_offset == 3U);
        expect_shadow_matches_legacy_flow(
            *registry.registry,
            malformed_missing_length_packet,
            "EthernetII -> IPv4 -> TCP",
            StopReason::terminal_protocol
        );
    }

    {
        const auto malformed_short_length_packet = make_raw_packet(add_ipv4_options(
            make_ethernet_ipv4_udp_packet(ipv4(10, 20, 3, 11), ipv4(10, 20, 3, 12), 6100U, 6101U),
            {0x44, 0x01, 0x00, 0x00}
        ));
        const auto malformed_root = make_root_slice(malformed_short_length_packet);
        const auto malformed_ethernet = parse_ethernet_frame(malformed_root);
        PFL_REQUIRE(malformed_ethernet.status == ParseStatus::complete);
        const auto malformed_step = dissect_ipv4(require_child_slice(
            malformed_root,
            malformed_ethernet.header_length,
            malformed_ethernet.declared_payload_length
        ));
        const auto* malformed_facts = std::get_if<Ipv4Facts>(&malformed_step.facts);
        PFL_REQUIRE(malformed_facts != nullptr);
        PFL_EXPECT(malformed_facts->options.status == Ipv4OptionsParseStatus::malformed);
        PFL_EXPECT(malformed_facts->options.parsed_option_count == 0U);
        PFL_EXPECT(malformed_facts->options.has_malformed_offset);
        PFL_EXPECT(malformed_facts->options.malformed_offset == 0U);
        expect_shadow_matches_legacy_flow(
            *registry.registry,
            malformed_short_length_packet,
            "EthernetII -> IPv4 -> UDP",
            StopReason::terminal_protocol
        );
    }

    {
        const auto malformed_past_end_packet = make_raw_packet(add_ipv4_options(
            make_ethernet_ipv4_udp_packet(ipv4(10, 20, 3, 21), ipv4(10, 20, 3, 22), 6200U, 6201U),
            {0x44, 0x05, 0x00, 0x00}
        ));
        const auto malformed_root = make_root_slice(malformed_past_end_packet);
        const auto malformed_ethernet = parse_ethernet_frame(malformed_root);
        PFL_REQUIRE(malformed_ethernet.status == ParseStatus::complete);
        const auto malformed_step = dissect_ipv4(require_child_slice(
            malformed_root,
            malformed_ethernet.header_length,
            malformed_ethernet.declared_payload_length
        ));
        const auto* malformed_facts = std::get_if<Ipv4Facts>(&malformed_step.facts);
        PFL_REQUIRE(malformed_facts != nullptr);
        PFL_EXPECT(malformed_facts->options.status == Ipv4OptionsParseStatus::malformed);
        PFL_EXPECT(malformed_facts->options.parsed_option_count == 0U);
        PFL_EXPECT(malformed_facts->options.has_malformed_offset);
        PFL_EXPECT(malformed_facts->options.malformed_offset == 0U);
        expect_shadow_matches_legacy_flow(
            *registry.registry,
            malformed_past_end_packet,
            "EthernetII -> IPv4 -> UDP",
            StopReason::terminal_protocol
        );
    }

    {
        const auto malformed_padding_packet = make_raw_packet(add_ipv4_options(
            make_ethernet_ipv4_udp_packet(ipv4(10, 20, 4, 1), ipv4(10, 20, 4, 2), 7000U, 7001U),
            {0x00, 0x01, 0x00, 0x00}
        ));
        const auto malformed_root = make_root_slice(malformed_padding_packet);
        const auto malformed_ethernet = parse_ethernet_frame(malformed_root);
        PFL_REQUIRE(malformed_ethernet.status == ParseStatus::complete);
        const auto malformed_step = dissect_ipv4(require_child_slice(
            malformed_root,
            malformed_ethernet.header_length,
            malformed_ethernet.declared_payload_length
        ));
        const auto* malformed_facts = std::get_if<Ipv4Facts>(&malformed_step.facts);
        PFL_REQUIRE(malformed_facts != nullptr);
        PFL_EXPECT(malformed_facts->options.status == Ipv4OptionsParseStatus::malformed);
        PFL_EXPECT(malformed_facts->options.has_end_of_list);
        PFL_EXPECT(malformed_facts->options.has_nonzero_padding);
        PFL_EXPECT(malformed_facts->options.has_malformed_offset);
        PFL_EXPECT(malformed_facts->options.malformed_offset == 1U);
        expect_shadow_matches_legacy_flow(
            *registry.registry,
            malformed_padding_packet,
            "EthernetII -> IPv4 -> UDP",
            StopReason::terminal_protocol
        );
    }

    {
        const auto fragmented_packet = make_raw_packet(add_ipv4_options(
            make_ethernet_ipv4_fragment_packet(
                ipv4(10, 20, 5, 1),
                ipv4(10, 20, 5, 2),
                detail::kIpProtocolUdp,
                0x2000U,
                {0xde, 0xad, 0xbe, 0xef}
            ),
            {0x94, 0x04, 0x00, 0x00}
        ));
        const auto fragmented_root = make_root_slice(fragmented_packet);
        const auto fragmented_ethernet = parse_ethernet_frame(fragmented_root);
        PFL_REQUIRE(fragmented_ethernet.status == ParseStatus::complete);
        const auto fragmented_step = dissect_ipv4(require_child_slice(
            fragmented_root,
            fragmented_ethernet.header_length,
            fragmented_ethernet.declared_payload_length
        ));
        const auto* fragmented_facts = std::get_if<Ipv4Facts>(&fragmented_step.facts);
        PFL_REQUIRE(fragmented_facts != nullptr);
        PFL_EXPECT(fragmented_step.stop_reason == StopReason::needs_reassembly);
        PFL_EXPECT(fragmented_facts->is_fragmented);
        PFL_EXPECT(fragmented_facts->options.status == Ipv4OptionsParseStatus::well_formed);
        PFL_EXPECT(fragmented_facts->options.has_router_alert);
    }

    {
        const auto nested_inner_ipv4 = strip_ethernet_header(add_ipv4_options(
            make_ethernet_ipv4_udp_packet(ipv4(10, 20, 6, 1), ipv4(10, 20, 6, 2), 8000U, 8001U),
            {0x01, 0x94, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00}
        ));
        const auto nested_ipv6_packet = make_raw_packet(make_ethernet_ipv6_packet(
            ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x31}),
            ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x32}),
            detail::kIpProtocolIpv4Encapsulation,
            nested_inner_ipv4
        ));
        expect_shadow_matches_legacy_flow(
            *registry.registry,
            nested_ipv6_packet,
            "EthernetII -> IPv6 -> IPv4 -> UDP",
            StopReason::terminal_protocol
        );
    }

    {
        const auto nested_inner_ipv4 = strip_ethernet_header(add_ipv4_options(
            make_ethernet_ipv4_tcp_packet(ipv4(10, 20, 6, 11), ipv4(10, 20, 6, 12), 8100U, 8101U),
            {0x01, 0x01, 0x00, 0x00}
        ));
        const auto nested_ipv4_packet = make_raw_packet(make_ethernet_ipv4_fragment_packet(
            ipv4(192, 0, 2, 50),
            ipv4(192, 0, 2, 60),
            detail::kIpProtocolIpv4Encapsulation,
            0U,
            nested_inner_ipv4
        ));
        expect_shadow_matches_legacy_flow(
            *registry.registry,
            nested_ipv4_packet,
            "EthernetII -> IPv4 -> IPv4 -> TCP",
            StopReason::terminal_protocol
        );
    }

    {
        const auto declared_short_ipv4 = strip_ethernet_header(add_ipv4_options(
            make_ethernet_ipv4_udp_packet(ipv4(10, 20, 7, 1), ipv4(10, 20, 7, 2), 9000U, 9001U),
            {0x01, 0x01, 0x00, 0x00}
        ));
        const auto declared_short_slice = make_root_packet_slice(
            ByteSourceId::captured_frame(99U),
            declared_short_ipv4,
            static_cast<std::uint32_t>(declared_short_ipv4.size()),
            22U
        );
        const auto declared_short_parsed = parse_ipv4_packet(declared_short_slice);
        PFL_EXPECT(declared_short_parsed.status == ParseStatus::malformed);
        const auto declared_short_step = dissect_ipv4(declared_short_slice);
        PFL_EXPECT(declared_short_step.status == ParseStatus::malformed);
        PFL_EXPECT(!declared_short_step.path_contribution.has_value());
        PFL_EXPECT(!declared_short_step.handoff.has_value());
    }

    {
        const auto captured_short_ipv4 = strip_ethernet_header(add_ipv4_options(
            make_ethernet_ipv4_udp_packet(ipv4(10, 20, 8, 1), ipv4(10, 20, 8, 2), 9100U, 9101U),
            {0x01, 0x01, 0x00, 0x00}
        ));
        const auto captured_short_slice = make_root_packet_slice(
            ByteSourceId::captured_frame(100U),
            captured_short_ipv4,
            22U,
            static_cast<std::uint32_t>(captured_short_ipv4.size())
        );
        const auto captured_short_parsed = parse_ipv4_packet(captured_short_slice);
        PFL_EXPECT(captured_short_parsed.status == ParseStatus::truncated);
        const auto captured_short_step = dissect_ipv4(captured_short_slice);
        PFL_EXPECT(captured_short_step.status == ParseStatus::truncated);
        PFL_EXPECT(!captured_short_step.path_contribution.has_value());
        PFL_EXPECT(!captured_short_step.handoff.has_value());
    }
}

void expect_failed_layers_do_not_contribute_path_and_exact_arp_bounds() {
    const auto truncated_vlan_packet = make_raw_packet(std::vector<std::uint8_t> {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
        0x81, 0x00,
        0x00, 0x64,
    }, 18U);
    const auto truncated_vlan_root = make_root_slice(truncated_vlan_packet);
    const auto truncated_vlan_ethernet = parse_ethernet_frame(truncated_vlan_root);
    PFL_REQUIRE(truncated_vlan_ethernet.status == ParseStatus::complete);
    const auto truncated_vlan_step = dissect_vlan(require_child_slice(
        truncated_vlan_root,
        truncated_vlan_ethernet.header_length,
        truncated_vlan_ethernet.declared_payload_length
    ));
    PFL_EXPECT(truncated_vlan_step.layer == DissectionLayerKind::vlan);
    PFL_EXPECT(truncated_vlan_step.status == ParseStatus::truncated);
    PFL_EXPECT(!truncated_vlan_step.path_contribution.has_value());

    auto invalid_ihl_packet = make_ethernet_ipv4_tcp_packet(ipv4(10, 8, 0, 1), ipv4(10, 8, 0, 2), 1U, 2U);
    invalid_ihl_packet[14] = 0x44U;
    const auto invalid_ihl_raw_packet = make_raw_packet(invalid_ihl_packet);
    const auto invalid_ihl_root = make_root_slice(invalid_ihl_raw_packet);
    const auto invalid_ihl_ethernet = parse_ethernet_frame(invalid_ihl_root);
    PFL_REQUIRE(invalid_ihl_ethernet.status == ParseStatus::complete);
    const auto invalid_ipv4_step = dissect_ipv4(require_child_slice(
        invalid_ihl_root,
        invalid_ihl_ethernet.header_length,
        invalid_ihl_ethernet.declared_payload_length
    ));
    PFL_EXPECT(invalid_ipv4_step.status == ParseStatus::malformed);
    PFL_EXPECT(!invalid_ipv4_step.path_contribution.has_value());

    const auto header_only_tcp_packet = make_raw_packet(make_ipv4_header_only_packet(6U));
    const auto header_only_tcp_root = make_root_slice(header_only_tcp_packet);
    const auto header_only_tcp_ethernet = parse_ethernet_frame(header_only_tcp_root);
    PFL_REQUIRE(header_only_tcp_ethernet.status == ParseStatus::complete);
    const auto header_only_tcp_ipv4_slice = require_child_slice(
        header_only_tcp_root,
        header_only_tcp_ethernet.header_length,
        header_only_tcp_ethernet.declared_payload_length
    );
    const auto header_only_tcp_ipv4 = parse_ipv4_packet(header_only_tcp_ipv4_slice);
    PFL_REQUIRE(header_only_tcp_ipv4.status == ParseStatus::complete);
    const auto header_only_tcp_step = dissect_tcp(require_child_slice(
        header_only_tcp_ipv4_slice,
        header_only_tcp_ipv4.header_length,
        header_only_tcp_ipv4.nominal_packet_end - header_only_tcp_ipv4.header_length
    ));
    PFL_EXPECT(header_only_tcp_step.status == ParseStatus::malformed);
    PFL_EXPECT(!header_only_tcp_step.path_contribution.has_value());

    auto malformed_udp_packet = make_ethernet_ipv4_udp_packet(ipv4(10, 1, 1, 1), ipv4(10, 1, 1, 2), 3000U, 4000U);
    set_udp_length(malformed_udp_packet, 7U);
    const auto malformed_udp_raw_packet = make_raw_packet(malformed_udp_packet);
    const auto malformed_udp_root = make_root_slice(malformed_udp_raw_packet);
    const auto malformed_udp_ethernet = parse_ethernet_frame(malformed_udp_root);
    PFL_REQUIRE(malformed_udp_ethernet.status == ParseStatus::complete);
    const auto malformed_udp_ipv4_slice = require_child_slice(
        malformed_udp_root,
        malformed_udp_ethernet.header_length,
        malformed_udp_ethernet.declared_payload_length
    );
    const auto malformed_udp_ipv4 = parse_ipv4_packet(malformed_udp_ipv4_slice);
    PFL_REQUIRE(malformed_udp_ipv4.status == ParseStatus::complete);
    const auto malformed_udp_step = dissect_udp(require_child_slice(
        malformed_udp_ipv4_slice,
        malformed_udp_ipv4.header_length,
        malformed_udp_ipv4.nominal_packet_end - malformed_udp_ipv4.header_length
    ));
    PFL_EXPECT(malformed_udp_step.status == ParseStatus::malformed);
    PFL_EXPECT(!malformed_udp_step.path_contribution.has_value());

    const auto truncated_ipv6_extension_packet = make_raw_packet(make_truncated_ethernet_ipv6_extension_packet(
        ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7}),
        ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8})
    ));
    const auto truncated_ipv6_extension_root = make_root_slice(truncated_ipv6_extension_packet);
    const auto truncated_ipv6_extension_ethernet = parse_ethernet_frame(truncated_ipv6_extension_root);
    PFL_REQUIRE(truncated_ipv6_extension_ethernet.status == ParseStatus::complete);
    const auto truncated_ipv6_step = dissect_ipv6(require_child_slice(
        truncated_ipv6_extension_root,
        truncated_ipv6_extension_ethernet.header_length,
        truncated_ipv6_extension_ethernet.declared_payload_length
    ));
    PFL_EXPECT(truncated_ipv6_step.status == ParseStatus::complete);
    PFL_REQUIRE(truncated_ipv6_step.path_contribution.has_value());
    PFL_EXPECT(*truncated_ipv6_step.path_contribution == LayerKey::ipv6());
    PFL_REQUIRE(truncated_ipv6_step.handoff.has_value());
    PFL_REQUIRE(truncated_ipv6_step.handoff->child.has_value());
    const auto truncated_hop_by_hop_step = dissect_ipv6_hop_by_hop(*truncated_ipv6_step.handoff->child);
    PFL_EXPECT(truncated_hop_by_hop_step.status == ParseStatus::malformed);
    PFL_EXPECT(!truncated_hop_by_hop_step.path_contribution.has_value());

    const auto arp_bytes = make_ethernet_arp_packet(ipv4(10, 10, 12, 2), ipv4(10, 10, 12, 1));
    auto padded_arp_bytes = arp_bytes;
    padded_arp_bytes.insert(padded_arp_bytes.end(), {0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
    const auto padded_arp_packet = make_raw_packet(padded_arp_bytes);
    const auto padded_arp_root = make_root_slice(padded_arp_packet);
    const auto padded_arp_ethernet = parse_ethernet_frame(padded_arp_root);
    PFL_REQUIRE(padded_arp_ethernet.status == ParseStatus::complete);
    const auto padded_arp_step = dissect_arp(require_child_slice(
        padded_arp_root,
        padded_arp_ethernet.header_length,
        padded_arp_ethernet.declared_payload_length
    ));
    PFL_EXPECT(padded_arp_step.status == ParseStatus::complete);
    PFL_REQUIRE(padded_arp_step.path_contribution.has_value());
    PFL_EXPECT(*padded_arp_step.path_contribution == LayerKey::arp());
    PFL_EXPECT(padded_arp_step.bounds.full.declared.length() == 28U);
    PFL_EXPECT(padded_arp_step.bounds.full.captured.length() == 28U);
    PFL_EXPECT(padded_arp_step.bounds.header.declared.length() == 8U);
    PFL_EXPECT(padded_arp_step.bounds.header.captured.length() == 8U);
    PFL_REQUIRE(padded_arp_step.bounds.payload.has_value());
    PFL_EXPECT(padded_arp_step.bounds.payload->declared.length() == 20U);
    PFL_EXPECT(padded_arp_step.bounds.payload->captured.length() == 20U);
    PFL_EXPECT(padded_arp_step.terminal_disposition == TerminalDisposition::recognized_non_flow);

    auto truncated_arp_fixed_header_bytes = arp_bytes;
    truncated_arp_fixed_header_bytes.resize(18U);
    const auto truncated_arp_fixed_header_packet = make_raw_packet(
        truncated_arp_fixed_header_bytes,
        static_cast<std::uint32_t>(arp_bytes.size())
    );
    const auto truncated_arp_fixed_header_root = make_root_slice(truncated_arp_fixed_header_packet);
    const auto truncated_arp_fixed_header_ethernet = parse_ethernet_frame(truncated_arp_fixed_header_root);
    PFL_REQUIRE(truncated_arp_fixed_header_ethernet.status == ParseStatus::complete);
    const auto truncated_arp_fixed_header_step = dissect_arp(require_child_slice(
        truncated_arp_fixed_header_root,
        truncated_arp_fixed_header_ethernet.header_length,
        truncated_arp_fixed_header_ethernet.declared_payload_length
    ));
    PFL_EXPECT(truncated_arp_fixed_header_step.status == ParseStatus::truncated);
    PFL_EXPECT(!truncated_arp_fixed_header_step.path_contribution.has_value());
    PFL_EXPECT(!truncated_arp_fixed_header_step.bounds.payload.has_value());

    auto truncated_arp_address_bytes = arp_bytes;
    truncated_arp_address_bytes.resize(30U);
    const auto truncated_arp_address_packet = make_raw_packet(
        truncated_arp_address_bytes,
        static_cast<std::uint32_t>(arp_bytes.size())
    );
    const auto truncated_arp_address_root = make_root_slice(truncated_arp_address_packet);
    const auto truncated_arp_address_ethernet = parse_ethernet_frame(truncated_arp_address_root);
    PFL_REQUIRE(truncated_arp_address_ethernet.status == ParseStatus::complete);
    const auto truncated_arp_address_step = dissect_arp(require_child_slice(
        truncated_arp_address_root,
        truncated_arp_address_ethernet.header_length,
        truncated_arp_address_ethernet.declared_payload_length
    ));
    PFL_EXPECT(truncated_arp_address_step.status == ParseStatus::truncated);
    PFL_EXPECT(!truncated_arp_address_step.path_contribution.has_value());
    PFL_EXPECT(truncated_arp_address_step.bounds.full.declared.length() == 28U);
    PFL_EXPECT(truncated_arp_address_step.bounds.full.captured.length() == 16U);
    PFL_EXPECT(truncated_arp_address_step.bounds.header.declared.length() == 8U);
    PFL_EXPECT(truncated_arp_address_step.bounds.header.captured.length() == 8U);
    PFL_REQUIRE(truncated_arp_address_step.bounds.payload.has_value());
    PFL_EXPECT(truncated_arp_address_step.bounds.payload->declared.length() == 20U);
    PFL_EXPECT(truncated_arp_address_step.bounds.payload->captured.length() == 8U);

    auto impossible_arp_bytes = arp_bytes;
    impossible_arp_bytes[18] = 6U;
    impossible_arp_bytes[19] = 16U;
    const auto impossible_arp_packet = make_raw_packet(impossible_arp_bytes);
    const auto impossible_arp_root = make_root_slice(impossible_arp_packet);
    const auto impossible_arp_ethernet = parse_ethernet_frame(impossible_arp_root);
    PFL_REQUIRE(impossible_arp_ethernet.status == ParseStatus::complete);
    const auto impossible_arp_step = dissect_arp(require_child_slice(
        impossible_arp_root,
        impossible_arp_ethernet.header_length,
        impossible_arp_ethernet.declared_payload_length
    ));
    PFL_EXPECT(impossible_arp_step.status == ParseStatus::malformed);
    PFL_EXPECT(impossible_arp_step.stop_reason == StopReason::malformed);
    PFL_EXPECT(!impossible_arp_step.path_contribution.has_value());
    PFL_EXPECT(impossible_arp_step.terminal_disposition == TerminalDisposition::none);
    PFL_EXPECT(impossible_arp_step.bounds.full.declared.length() == 28U);
    PFL_EXPECT(impossible_arp_step.bounds.full.captured.length() == 28U);
    PFL_EXPECT(impossible_arp_step.bounds.header.declared.length() == 8U);
    PFL_EXPECT(impossible_arp_step.bounds.header.captured.length() == 8U);
    PFL_REQUIRE(impossible_arp_step.bounds.payload.has_value());
    PFL_EXPECT(impossible_arp_step.bounds.payload->declared.length() == 20U);
    PFL_EXPECT(impossible_arp_step.bounds.payload->captured.length() == 20U);
}

void expect_ipv6_and_extension_canonical_parsers() {
    const auto built = make_common_direct_registry();
    PFL_REQUIRE(built.ok());
    const auto& registry = *built.registry;
    const auto src_addr = ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1});
    const auto dst_addr = ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2});

    const auto direct_udp_packet = make_raw_packet(make_ethernet_ipv6_packet(
        src_addr,
        dst_addr,
        detail::kIpProtocolUdp,
        make_ipv6_udp_segment(5300U, 53U, 4U)
    ));
    const auto direct_udp_root = make_root_slice(direct_udp_packet);
    const auto direct_udp_ethernet = parse_ethernet_frame(direct_udp_root);
    PFL_REQUIRE(direct_udp_ethernet.status == ParseStatus::complete);
    const auto direct_udp_ipv6_slice = require_child_slice(
        direct_udp_root,
        direct_udp_ethernet.header_length,
        direct_udp_ethernet.declared_payload_length
    );
    const auto direct_udp_ipv6 = parse_ipv6_packet(direct_udp_ipv6_slice);
    PFL_EXPECT(direct_udp_ipv6.status == ParseStatus::complete);
    PFL_EXPECT(direct_udp_ipv6.next_header == detail::kIpProtocolUdp);
    PFL_EXPECT(direct_udp_ipv6.payload_length == 12U);
    PFL_EXPECT(direct_udp_ipv6.header_length == detail::kIpv6HeaderSize);
    PFL_EXPECT(direct_udp_ipv6.nominal_packet_end == 52U);

    const auto direct_udp_payload_slice = require_child_slice(
        direct_udp_ipv6_slice,
        direct_udp_ipv6.header_length,
        direct_udp_ipv6.payload_length
    );
    const auto direct_udp_transport = parse_udp_datagram(direct_udp_payload_slice);
    PFL_EXPECT(direct_udp_transport.status == ParseStatus::complete);
    PFL_EXPECT(direct_udp_transport.src_port == 5300U);
    PFL_EXPECT(direct_udp_transport.dst_port == 53U);
    PFL_EXPECT(direct_udp_transport.captured_payload_length == 4U);

    const auto hop_by_hop_packet = make_raw_packet(make_ethernet_ipv6_udp_with_hop_by_hop_packet(
        src_addr,
        dst_addr,
        61000U,
        443U
    ));
    const auto hop_by_hop_root = make_root_slice(hop_by_hop_packet);
    const auto hop_by_hop_ethernet = parse_ethernet_frame(hop_by_hop_root);
    PFL_REQUIRE(hop_by_hop_ethernet.status == ParseStatus::complete);
    const auto hop_by_hop_ipv6_slice = require_child_slice(
        hop_by_hop_root,
        hop_by_hop_ethernet.header_length,
        hop_by_hop_ethernet.declared_payload_length
    );
    const auto hop_by_hop_ipv6 = parse_ipv6_packet(hop_by_hop_ipv6_slice);
    PFL_REQUIRE(hop_by_hop_ipv6.status == ParseStatus::complete);
    const auto hop_by_hop_payload_slice = require_child_slice(
        hop_by_hop_ipv6_slice,
        hop_by_hop_ipv6.header_length,
        hop_by_hop_ipv6.payload_length
    );
    const auto hop_extension = parse_ipv6_extension_header(
        hop_by_hop_payload_slice,
        Ipv6ExtensionHeaderKind::hop_by_hop
    );
    PFL_EXPECT(hop_extension.status == ParseStatus::complete);
    PFL_EXPECT(hop_extension.next_header == detail::kIpProtocolUdp);
    PFL_EXPECT(hop_extension.header_length == 8U);
    const auto hop_by_hop_step = dissect_ipv6_hop_by_hop(hop_by_hop_payload_slice);
    PFL_EXPECT(hop_by_hop_step.status == ParseStatus::complete);
    PFL_EXPECT(hop_by_hop_step.layer == DissectionLayerKind::ipv6_hop_by_hop);
    PFL_EXPECT(!hop_by_hop_step.path_contribution.has_value());
    PFL_REQUIRE(hop_by_hop_step.handoff.has_value());
    PFL_REQUIRE(hop_by_hop_step.handoff->child.has_value());
    const ProtocolSelector expected_hop_by_hop_selector {
        .domain = SelectorDomain::ipv6_next_header,
        .value = detail::kIpProtocolUdp,
    };
    PFL_EXPECT(hop_by_hop_step.handoff->selector == expected_hop_by_hop_selector);
    StepKindRecorder hop_recorder {};
    const DissectionEngine engine {};
    const auto hop_engine_result = engine.run(
        registry,
        make_link_type_selector(hop_by_hop_packet.data_link_type),
        hop_by_hop_root,
        DissectionConsumer {.on_step = record_step_kind, .context = &hop_recorder}
    );
    const std::vector<DissectionLayerKind> expected_hop_kinds {
        DissectionLayerKind::ethernet_ii,
        DissectionLayerKind::ipv6,
        DissectionLayerKind::ipv6_hop_by_hop,
        DissectionLayerKind::udp,
    };
    PFL_EXPECT(hop_engine_result.stop_reason == StopReason::terminal_protocol);
    PFL_EXPECT(hop_recorder.kinds == expected_hop_kinds);

    const auto routing_packet = make_raw_packet(make_ethernet_ipv6_packet(
        src_addr,
        dst_addr,
        detail::kIpProtocolRouting,
        make_ipv6_routing_extension(detail::kIpProtocolUdp, make_ipv6_udp_segment(1200U, 2200U))
    ));
    const auto routing_root = make_root_slice(routing_packet);
    const auto routing_ethernet = parse_ethernet_frame(routing_root);
    PFL_REQUIRE(routing_ethernet.status == ParseStatus::complete);
    const auto routing_ipv6_slice = require_child_slice(
        routing_root,
        routing_ethernet.header_length,
        routing_ethernet.declared_payload_length
    );
    const auto routing_ipv6 = parse_ipv6_packet(routing_ipv6_slice);
    PFL_REQUIRE(routing_ipv6.status == ParseStatus::complete);
    const auto routing_payload_slice = require_child_slice(
        routing_ipv6_slice,
        routing_ipv6.header_length,
        routing_ipv6.payload_length
    );
    const auto routing_extension = parse_ipv6_extension_header(
        routing_payload_slice,
        Ipv6ExtensionHeaderKind::routing
    );
    PFL_EXPECT(routing_extension.status == ParseStatus::complete);
    PFL_EXPECT(routing_extension.next_header == detail::kIpProtocolUdp);
    const auto routing_step = dissect_ipv6_routing(routing_payload_slice);
    PFL_EXPECT(routing_step.status == ParseStatus::complete);
    PFL_EXPECT(routing_step.layer == DissectionLayerKind::ipv6_routing);
    PFL_EXPECT(!routing_step.path_contribution.has_value());
    PFL_REQUIRE(routing_step.handoff.has_value());
    PFL_REQUIRE(routing_step.handoff->child.has_value());
    const ProtocolSelector expected_routing_selector {
        .domain = SelectorDomain::ipv6_next_header,
        .value = detail::kIpProtocolUdp,
    };
    PFL_EXPECT(routing_step.handoff->selector == expected_routing_selector);

    const auto destination_tcp_packet = make_raw_packet(make_ethernet_ipv6_packet(
        src_addr,
        dst_addr,
        detail::kIpProtocolDestinationOptions,
        make_ipv6_destination_options_extension(detail::kIpProtocolTcp, make_ipv6_tcp_segment(32000U, 443U, 3U, 0x19U))
    ));
    const auto destination_tcp_root = make_root_slice(destination_tcp_packet);
    const auto destination_tcp_ethernet = parse_ethernet_frame(destination_tcp_root);
    PFL_REQUIRE(destination_tcp_ethernet.status == ParseStatus::complete);
    const auto destination_tcp_ipv6_slice = require_child_slice(
        destination_tcp_root,
        destination_tcp_ethernet.header_length,
        destination_tcp_ethernet.declared_payload_length
    );
    const auto destination_tcp_ipv6 = parse_ipv6_packet(destination_tcp_ipv6_slice);
    PFL_REQUIRE(destination_tcp_ipv6.status == ParseStatus::complete);
    const auto destination_payload_slice = require_child_slice(
        destination_tcp_ipv6_slice,
        destination_tcp_ipv6.header_length,
        destination_tcp_ipv6.payload_length
    );
    const auto destination_extension = parse_ipv6_extension_header(
        destination_payload_slice,
        Ipv6ExtensionHeaderKind::destination_options
    );
    PFL_EXPECT(destination_extension.status == ParseStatus::complete);
    PFL_EXPECT(destination_extension.next_header == detail::kIpProtocolTcp);
    const auto destination_step = dissect_ipv6_destination_options(destination_payload_slice);
    PFL_EXPECT(destination_step.status == ParseStatus::complete);
    PFL_EXPECT(destination_step.layer == DissectionLayerKind::ipv6_destination_options);
    PFL_EXPECT(!destination_step.path_contribution.has_value());
    PFL_REQUIRE(destination_step.handoff.has_value());
    PFL_REQUIRE(destination_step.handoff->child.has_value());
    const ProtocolSelector expected_destination_selector {
        .domain = SelectorDomain::ipv6_next_header,
        .value = detail::kIpProtocolTcp,
    };
    PFL_EXPECT(destination_step.handoff->selector == expected_destination_selector);

    const auto fragment_packet = make_raw_packet(make_ethernet_ipv6_fragment_packet(
        src_addr,
        dst_addr,
        detail::kIpProtocolUdp,
        make_ipv6_udp_segment(45000U, 45001U, 2U)
    ));
    const auto fragment_root = make_root_slice(fragment_packet);
    const auto fragment_ethernet = parse_ethernet_frame(fragment_root);
    PFL_REQUIRE(fragment_ethernet.status == ParseStatus::complete);
    const auto fragment_ipv6_slice = require_child_slice(
        fragment_root,
        fragment_ethernet.header_length,
        fragment_ethernet.declared_payload_length
    );
    const auto fragment_ipv6 = parse_ipv6_packet(fragment_ipv6_slice);
    PFL_REQUIRE(fragment_ipv6.status == ParseStatus::complete);
    const auto fragment_payload_slice = require_child_slice(
        fragment_ipv6_slice,
        fragment_ipv6.header_length,
        fragment_ipv6.payload_length
    );
    const auto fragment_header = parse_ipv6_fragment_header(fragment_payload_slice);
    PFL_EXPECT(fragment_header.status == ParseStatus::complete);
    PFL_EXPECT(fragment_header.next_header == detail::kIpProtocolUdp);
    PFL_EXPECT(fragment_header.fragment_offset_units == 0U);
    PFL_EXPECT(!fragment_header.more_fragments);
    PFL_EXPECT(fragment_header.is_atomic_fragment);
    const auto fragment_step = dissect_ipv6_fragment(fragment_payload_slice);
    PFL_EXPECT(fragment_step.status == ParseStatus::complete);
    PFL_EXPECT(fragment_step.layer == DissectionLayerKind::ipv6_fragment);
    PFL_EXPECT(!fragment_step.path_contribution.has_value());
    PFL_REQUIRE(fragment_step.handoff.has_value());
    const ProtocolSelector expected_fragment_selector {
        .domain = SelectorDomain::ipv6_next_header,
        .value = detail::kIpProtocolUdp,
    };
    PFL_EXPECT(fragment_step.handoff->selector == expected_fragment_selector);
    PFL_EXPECT(!fragment_step.handoff->child.has_value());
    PFL_EXPECT(fragment_step.stop_reason == StopReason::needs_reassembly);
    PFL_EXPECT(std::holds_alternative<Ipv6FragmentFacts>(fragment_step.facts));
    const auto* fragment_facts = std::get_if<Ipv6FragmentFacts>(&fragment_step.facts);
    PFL_REQUIRE(fragment_facts != nullptr);
    PFL_EXPECT(fragment_facts->fragment_offset_units == 0U);
    PFL_EXPECT(!fragment_facts->more_fragments);
    PFL_EXPECT(fragment_facts->is_atomic_fragment);

    const auto truncated_extension_packet = make_raw_packet(make_truncated_ethernet_ipv6_extension_packet(src_addr, dst_addr));
    const auto truncated_extension_root = make_root_slice(truncated_extension_packet);
    const auto truncated_extension_ethernet = parse_ethernet_frame(truncated_extension_root);
    PFL_REQUIRE(truncated_extension_ethernet.status == ParseStatus::complete);
    const auto truncated_extension_ipv6_slice = require_child_slice(
        truncated_extension_root,
        truncated_extension_ethernet.header_length,
        truncated_extension_ethernet.declared_payload_length
    );
    const auto truncated_extension_ipv6 = parse_ipv6_packet(truncated_extension_ipv6_slice);
    PFL_REQUIRE(truncated_extension_ipv6.status == ParseStatus::complete);
    const auto truncated_extension_payload_slice = require_child_slice(
        truncated_extension_ipv6_slice,
        truncated_extension_ipv6.header_length,
        truncated_extension_ipv6.payload_length
    );
    const auto truncated_extension = parse_ipv6_extension_header(
        truncated_extension_payload_slice,
        Ipv6ExtensionHeaderKind::hop_by_hop
    );
    PFL_EXPECT(truncated_extension.status == ParseStatus::malformed);
}

void expect_sctp_canonical_parsers_and_bounds() {
    const auto built = make_common_direct_registry();
    PFL_REQUIRE(built.ok());
    const auto& registry = *built.registry;

    const auto exact_header_bytes = make_sctp_segment(49152U, 36412U, 0x10213243U, 0x89ABCDEFU);
    const auto exact_header_packet = make_raw_packet(exact_header_bytes, detail::kSctpCommonHeaderSize);
    const auto exact_header_root = make_root_slice(exact_header_packet);
    const auto exact_header = parse_sctp_common_header(exact_header_root);
    PFL_EXPECT(exact_header.status == ParseStatus::complete);
    PFL_EXPECT(exact_header.src_port == 49152U);
    PFL_EXPECT(exact_header.dst_port == 36412U);
    PFL_EXPECT(exact_header.verification_tag == 0x10213243U);
    PFL_EXPECT(exact_header.checksum == 0x89ABCDEFU);
    PFL_EXPECT(exact_header.header_length == detail::kSctpCommonHeaderSize);
    PFL_EXPECT(exact_header.captured_payload_length == 0U);

    const auto exact_header_step = dissect_sctp(exact_header_root);
    PFL_EXPECT(exact_header_step.layer == DissectionLayerKind::sctp);
    PFL_REQUIRE(exact_header_step.path_contribution.has_value());
    PFL_EXPECT(*exact_header_step.path_contribution == LayerKey::sctp());
    PFL_EXPECT(exact_header_step.terminal_disposition == TerminalDisposition::flow_candidate);
    PFL_EXPECT(exact_header_step.bounds.source_id == exact_header_root.source_id());
    PFL_EXPECT(exact_header_step.bounds.full.declared.length() == detail::kSctpCommonHeaderSize);
    PFL_EXPECT(exact_header_step.bounds.full.captured.length() == detail::kSctpCommonHeaderSize);
    PFL_EXPECT(exact_header_step.bounds.header.declared.length() == detail::kSctpCommonHeaderSize);
    PFL_EXPECT(exact_header_step.bounds.header.captured.length() == detail::kSctpCommonHeaderSize);
    PFL_REQUIRE(exact_header_step.bounds.payload.has_value());
    PFL_EXPECT(exact_header_step.bounds.payload->declared.length() == 0U);
    PFL_EXPECT(exact_header_step.bounds.payload->captured.length() == 0U);
    PFL_EXPECT(std::holds_alternative<SctpFacts>(exact_header_step.facts));
    const auto* exact_header_facts = std::get_if<SctpFacts>(&exact_header_step.facts);
    PFL_REQUIRE(exact_header_facts != nullptr);
    PFL_EXPECT(exact_header_facts->src_port == 49152U);
    PFL_EXPECT(exact_header_facts->dst_port == 36412U);
    PFL_EXPECT(exact_header_facts->verification_tag == 0x10213243U);
    PFL_EXPECT(exact_header_facts->checksum == 0x89ABCDEFU);

    const auto payload_bytes = make_sctp_segment(5000U, 5001U, 0x01020304U, 0xA0B0C0D0U, 5U);
    const auto payload_packet = make_raw_packet(payload_bytes);
    const auto payload_header = parse_sctp_common_header(make_root_slice(payload_packet));
    PFL_EXPECT(payload_header.status == ParseStatus::complete);
    PFL_EXPECT(payload_header.captured_payload_length == 5U);

    auto truncated_header_bytes = exact_header_bytes;
    truncated_header_bytes.resize(detail::kSctpCommonHeaderSize - 2U);
    const auto truncated_header_packet = make_raw_packet(
        truncated_header_bytes,
        detail::kSctpCommonHeaderSize
    );
    const auto truncated_header_root = make_root_slice(truncated_header_packet);
    const auto truncated_header = parse_sctp_common_header(truncated_header_root);
    PFL_EXPECT(truncated_header.status == ParseStatus::truncated);
    const auto truncated_header_step = dissect_sctp(truncated_header_root);
    PFL_EXPECT(truncated_header_step.layer == DissectionLayerKind::sctp);
    PFL_EXPECT(truncated_header_step.status == ParseStatus::truncated);
    PFL_EXPECT(!truncated_header_step.path_contribution.has_value());
    PFL_EXPECT(truncated_header_step.terminal_disposition == TerminalDisposition::none);

    const auto impossible_declared_packet = make_raw_packet(exact_header_bytes, detail::kSctpCommonHeaderSize - 1U);
    const auto impossible_declared_step = dissect_sctp(make_root_slice(impossible_declared_packet));
    PFL_EXPECT(impossible_declared_step.status == ParseStatus::malformed);
    PFL_EXPECT(!impossible_declared_step.path_contribution.has_value());
    PFL_EXPECT(impossible_declared_step.bounds.full.declared.length() == detail::kSctpCommonHeaderSize - 1U);
    PFL_EXPECT(impossible_declared_step.bounds.full.captured.length() == detail::kSctpCommonHeaderSize - 1U);
    PFL_EXPECT(impossible_declared_step.bounds.header.declared.length() == detail::kSctpCommonHeaderSize - 1U);
    PFL_EXPECT(impossible_declared_step.bounds.header.captured.length() == detail::kSctpCommonHeaderSize - 1U);

    auto truncated_payload_bytes = payload_bytes;
    truncated_payload_bytes.resize(detail::kSctpCommonHeaderSize + 2U);
    const auto truncated_payload_packet = make_raw_packet(
        truncated_payload_bytes,
        static_cast<std::uint32_t>(payload_bytes.size())
    );
    const auto truncated_payload_root = make_root_slice(truncated_payload_packet);
    const auto truncated_payload = parse_sctp_common_header(truncated_payload_root);
    PFL_EXPECT(truncated_payload.status == ParseStatus::complete);
    PFL_EXPECT(truncated_payload.captured_payload_length == 2U);
    const auto truncated_payload_step = dissect_sctp(truncated_payload_root);
    PFL_EXPECT(truncated_payload_step.status == ParseStatus::complete);
    PFL_REQUIRE(truncated_payload_step.bounds.payload.has_value());
    PFL_EXPECT(truncated_payload_step.bounds.payload->declared.length() == 5U);
    PFL_EXPECT(truncated_payload_step.bounds.payload->captured.length() == 2U);

    const auto ipv4_sctp_packet = make_raw_packet(make_ethernet_ipv4_sctp_packet(
        ipv4(10, 20, 30, 40),
        ipv4(10, 20, 30, 41),
        49152U,
        36412U,
        0x10213243U,
        0x89ABCDEFU,
        3U
    ));
    const auto ipv4_sctp_root = make_root_slice(ipv4_sctp_packet);
    const auto ipv4_sctp_ethernet = parse_ethernet_frame(ipv4_sctp_root);
    PFL_REQUIRE(ipv4_sctp_ethernet.status == ParseStatus::complete);
    const auto ipv4_sctp_ipv4_slice = require_child_slice(
        ipv4_sctp_root,
        ipv4_sctp_ethernet.header_length,
        ipv4_sctp_ethernet.declared_payload_length
    );
    const auto ipv4_sctp_ipv4 = parse_ipv4_packet(ipv4_sctp_ipv4_slice);
    PFL_REQUIRE(ipv4_sctp_ipv4.status == ParseStatus::complete);
    const auto ipv4_sctp_transport_slice = require_child_slice(
        ipv4_sctp_ipv4_slice,
        ipv4_sctp_ipv4.header_length,
        ipv4_sctp_ipv4.nominal_packet_end - ipv4_sctp_ipv4.header_length
    );
    const auto ipv4_sctp_step = dissect_sctp(ipv4_sctp_transport_slice);
    PFL_EXPECT(ipv4_sctp_step.status == ParseStatus::complete);
    PFL_EXPECT(ipv4_sctp_step.stop_reason == StopReason::terminal_protocol);

    const auto truncated_sctp_shadow = run_shadow(
        make_raw_packet(
            []() {
                auto packet = make_ethernet_ipv4_sctp_packet(
                    ipv4(10, 30, 0, 1),
                    ipv4(10, 30, 0, 2),
                    4096U,
                    4097U,
                    0x11223344U,
                    0x55667788U
                );
                packet.resize(packet.size() - 3U);
                return packet;
            }(),
            14U + 20U + detail::kSctpCommonHeaderSize
        ),
        registry
    );
    PFL_EXPECT(truncated_sctp_shadow.outcome == ImportDissectionOutcome::unrecognized);
    PFL_EXPECT(truncated_sctp_shadow.stop_reason == StopReason::truncated);
    PFL_EXPECT(truncated_sctp_shadow.terminal_protocol == ProtocolId::sctp);
    PFL_EXPECT(!truncated_sctp_shadow.has_ports);
    PFL_EXPECT(!truncated_sctp_shadow.has_transport_payload_length);
    PFL_EXPECT(format_shadow_path(truncated_sctp_shadow) == "EthernetII -> IPv4");
}

void expect_ah_and_esp_shadow_parsers_bounds_and_traversal() {
    const auto built = make_common_direct_registry();
    PFL_REQUIRE(built.ok());
    const auto& registry = *built.registry;
    const DissectionEngine engine {};

    const auto ipv6_src_addr = ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 21, 0, 0, 0, 0, 0, 0, 0, 0x11});
    const auto ipv6_dst_addr = ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 21, 0, 0, 0, 0, 0, 0, 0, 0x12});

    {
        const auto exact_ah_packet = make_raw_packet(make_ah_header(
            detail::kIpProtocolTcp,
            0x01020304U,
            0x05060708U,
            {}
        ), 12U);
        const auto exact_ah_root = make_root_slice(exact_ah_packet);
        const auto exact_ah = parse_ah_header(exact_ah_root);
        PFL_EXPECT(exact_ah.status == ParseStatus::complete);
        PFL_EXPECT(exact_ah.next_header == detail::kIpProtocolTcp);
        PFL_EXPECT(exact_ah.payload_length_field == 1U);
        PFL_EXPECT(exact_ah.reserved == 0U);
        PFL_EXPECT(exact_ah.spi == 0x01020304U);
        PFL_EXPECT(exact_ah.sequence_number == 0x05060708U);
        PFL_EXPECT(exact_ah.header_length == 12U);
        PFL_EXPECT(exact_ah.icv_length == 0U);

        const auto exact_ah_step = dissect_ipv4_ah(exact_ah_root);
        PFL_EXPECT(exact_ah_step.layer == DissectionLayerKind::ah);
        PFL_REQUIRE(exact_ah_step.path_contribution.has_value());
        PFL_EXPECT(*exact_ah_step.path_contribution == LayerKey::ah(0x01020304U));
        PFL_EXPECT(exact_ah_step.terminal_disposition == TerminalDisposition::none);
        PFL_REQUIRE(exact_ah_step.handoff.has_value());
        PFL_REQUIRE(exact_ah_step.handoff->child.has_value());
        const ProtocolSelector expected_ipv4_ah_selector {
            .domain = SelectorDomain::ip_protocol,
            .value = detail::kIpProtocolTcp,
        };
        PFL_EXPECT(exact_ah_step.handoff->selector == expected_ipv4_ah_selector);
        PFL_EXPECT(exact_ah_step.bounds.full.declared.length() == 12U);
        PFL_EXPECT(exact_ah_step.bounds.full.captured.length() == 12U);
        PFL_EXPECT(exact_ah_step.bounds.header.declared.length() == 12U);
        PFL_EXPECT(exact_ah_step.bounds.header.captured.length() == 12U);
        PFL_REQUIRE(exact_ah_step.bounds.payload.has_value());
        PFL_EXPECT(exact_ah_step.bounds.payload->declared.length() == 0U);
        PFL_EXPECT(exact_ah_step.bounds.payload->captured.length() == 0U);
        PFL_EXPECT(std::holds_alternative<AhFacts>(exact_ah_step.facts));
        const auto* exact_ah_facts = std::get_if<AhFacts>(&exact_ah_step.facts);
        PFL_REQUIRE(exact_ah_facts != nullptr);
        PFL_EXPECT(exact_ah_facts->next_header == detail::kIpProtocolTcp);
        PFL_EXPECT(exact_ah_facts->payload_length_field == 1U);
        PFL_EXPECT(exact_ah_facts->reserved == 0U);
        PFL_EXPECT(exact_ah_facts->spi == 0x01020304U);
        PFL_EXPECT(exact_ah_facts->sequence_number == 0x05060708U);
        PFL_EXPECT(exact_ah_facts->header_length == 12U);
        PFL_EXPECT(exact_ah_facts->icv_length == 0U);
    }

    {
        const auto icv_ah_packet = make_raw_packet(make_ah_header(
            detail::kIpProtocolUdp,
            0x11121314U,
            0x15161718U,
            {0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7},
            0x1234U
        ), 20U);
        const auto icv_ah = parse_ah_header(make_root_slice(icv_ah_packet));
        PFL_EXPECT(icv_ah.status == ParseStatus::complete);
        PFL_EXPECT(icv_ah.payload_length_field == 3U);
        PFL_EXPECT(icv_ah.reserved == 0x1234U);
        PFL_EXPECT(icv_ah.header_length == 20U);
        PFL_EXPECT(icv_ah.icv_length == 8U);
    }

    {
        auto truncated_fixed_ah = make_ah_header(detail::kIpProtocolTcp, 0x01020304U, 0x05060708U);
        truncated_fixed_ah.resize(10U);
        const auto parsed = parse_ah_header(make_root_slice(make_raw_packet(truncated_fixed_ah, 12U)));
        PFL_EXPECT(parsed.status == ParseStatus::truncated);
    }

    {
        const auto malformed_short_length = parse_ah_header(make_root_slice(make_raw_packet(
            make_ah_header(detail::kIpProtocolTcp, 0x01020304U, 0x05060708U, {}, 0U, 0U),
            12U
        )));
        PFL_EXPECT(malformed_short_length.status == ParseStatus::malformed);
    }

    {
        const auto malformed_beyond_declared = parse_ah_header(make_root_slice(make_raw_packet(
            make_ah_header(detail::kIpProtocolTcp, 0x01020304U, 0x05060708U, {0xaa, 0xbb, 0xcc, 0xdd}),
            12U
        )));
        PFL_EXPECT(malformed_beyond_declared.status == ParseStatus::malformed);
    }

    {
        auto truncated_icv_ah = make_ah_header(
            detail::kIpProtocolTcp,
            0x01020304U,
            0x05060708U,
            {0xa0, 0xa1, 0xa2, 0xa3}
        );
        truncated_icv_ah.resize(14U);
        const auto parsed = parse_ah_header(make_root_slice(make_raw_packet(truncated_icv_ah, 16U)));
        PFL_EXPECT(parsed.status == ParseStatus::truncated);
    }

    {
        const auto exact_esp_packet = make_raw_packet(make_esp_header(
            0x21222324U,
            0x31323334U,
            {}
        ), detail::kEspBaseHeaderSize);
        const auto exact_esp_root = make_root_slice(exact_esp_packet);
        const auto exact_esp = parse_esp_header(exact_esp_root);
        PFL_EXPECT(exact_esp.status == ParseStatus::complete);
        PFL_EXPECT(exact_esp.spi == 0x21222324U);
        PFL_EXPECT(exact_esp.sequence_number == 0x31323334U);
        PFL_EXPECT(exact_esp.header_length == detail::kEspBaseHeaderSize);

        const auto exact_esp_step = dissect_esp(exact_esp_root);
        PFL_EXPECT(exact_esp_step.layer == DissectionLayerKind::esp);
        PFL_REQUIRE(exact_esp_step.path_contribution.has_value());
        PFL_EXPECT(*exact_esp_step.path_contribution == LayerKey::esp(0x21222324U));
        PFL_EXPECT(exact_esp_step.terminal_disposition == TerminalDisposition::flow_candidate);
        PFL_EXPECT(exact_esp_step.stop_reason == StopReason::terminal_protocol);
        PFL_EXPECT(exact_esp_step.bounds.full.declared.length() == detail::kEspBaseHeaderSize);
        PFL_EXPECT(exact_esp_step.bounds.header.declared.length() == detail::kEspBaseHeaderSize);
        PFL_REQUIRE(exact_esp_step.bounds.payload.has_value());
        PFL_EXPECT(exact_esp_step.bounds.payload->declared.length() == 0U);
        PFL_EXPECT(exact_esp_step.bounds.payload->captured.length() == 0U);
        PFL_EXPECT(std::holds_alternative<EspFacts>(exact_esp_step.facts));
        const auto* exact_esp_facts = std::get_if<EspFacts>(&exact_esp_step.facts);
        PFL_REQUIRE(exact_esp_facts != nullptr);
        PFL_EXPECT(exact_esp_facts->spi == 0x21222324U);
        PFL_EXPECT(exact_esp_facts->sequence_number == 0x31323334U);
    }

    {
        const auto payload_esp_packet = make_raw_packet(make_esp_header(
            0x01020304U,
            0x0a0b0c0dU,
            {0xde, 0xad, 0xbe, 0xef, 0x10}
        ));
        const auto payload_esp_step = dissect_esp(make_root_slice(payload_esp_packet));
        PFL_EXPECT(payload_esp_step.status == ParseStatus::complete);
        PFL_REQUIRE(payload_esp_step.bounds.payload.has_value());
        PFL_EXPECT(payload_esp_step.bounds.payload->declared.length() == 5U);
        PFL_EXPECT(payload_esp_step.bounds.payload->captured.length() == 5U);
    }

    {
        auto truncated_esp_bytes = make_esp_header(0x01020304U, 0x0a0b0c0dU);
        truncated_esp_bytes.resize(detail::kEspBaseHeaderSize - 2U);
        const auto parsed = parse_esp_header(make_root_slice(make_raw_packet(
            truncated_esp_bytes,
            detail::kEspBaseHeaderSize
        )));
        PFL_EXPECT(parsed.status == ParseStatus::truncated);

        const auto step = dissect_esp(make_root_slice(make_raw_packet(
            truncated_esp_bytes,
            detail::kEspBaseHeaderSize
        )));
        PFL_EXPECT(step.status == ParseStatus::truncated);
        PFL_EXPECT(!step.path_contribution.has_value());
        PFL_EXPECT(step.terminal_disposition == TerminalDisposition::none);
    }

    {
        const auto malformed_esp_step = dissect_esp(make_root_slice(make_raw_packet(
            make_esp_header(0x01020304U, 0x0a0b0c0dU),
            detail::kEspBaseHeaderSize - 1U
        )));
        PFL_EXPECT(malformed_esp_step.status == ParseStatus::malformed);
        PFL_EXPECT(!malformed_esp_step.path_contribution.has_value());
    }

    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(make_ethernet_ipv4_ah_packet(
            ipv4(10, 50, 0, 1), ipv4(10, 50, 0, 2), detail::kIpProtocolTcp,
            make_ipv4_tcp_segment(12345U, 443U, 3U, 0x18U)
        )),
        "EthernetII -> IPv4 -> AH(spi=0x11111111) -> TCP",
        StopReason::terminal_protocol
    );
    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(make_ethernet_ipv4_ah_packet(
            ipv4(10, 50, 1, 1), ipv4(10, 50, 1, 2), detail::kIpProtocolUdp,
            make_ipv4_udp_segment(5300U, 53U, 4U)
        )),
        "EthernetII -> IPv4 -> AH(spi=0x11111111) -> UDP",
        StopReason::terminal_protocol
    );
    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(make_ethernet_ipv6_ah_packet(
            ipv6_src_addr, ipv6_dst_addr, detail::kIpProtocolTcp,
            make_ipv6_tcp_segment(23456U, 443U, 2U, 0x18U)
        )),
        "EthernetII -> IPv6 -> AH(spi=0x11111111) -> TCP",
        StopReason::terminal_protocol
    );
    expect_shadow_matches_legacy_flow(
        registry,
        [&]() {
            auto ah_udp_payload = make_ah_header(
                detail::kIpProtocolUdp,
                0x11111111U,
                0x01020304U,
                {}
            );
            const auto udp_segment = make_ipv6_udp_segment(5301U, 5302U, 0U);
            ah_udp_payload.insert(ah_udp_payload.end(), udp_segment.begin(), udp_segment.end());
            return make_raw_packet(make_ethernet_ipv6_packet(
                ipv6_src_addr,
                ipv6_dst_addr,
                detail::kIpProtocolHopByHop,
                make_ipv6_hop_by_hop_extension(detail::kIpProtocolAh, ah_udp_payload)
            ));
        }(),
        "EthernetII -> IPv6 -> AH(spi=0x11111111) -> UDP",
        StopReason::terminal_protocol
    );

    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(make_ethernet_ipv4_esp_packet(
            ipv4(10, 60, 0, 1), ipv4(10, 60, 0, 2), 0x01020304U, 0x11121314U, {0xde, 0xad, 0xbe}
        )),
        "EthernetII -> IPv4 -> ESP(spi=0x01020304)",
        StopReason::terminal_protocol
    );
    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(make_ethernet_ipv6_esp_packet(
            ipv6_src_addr, ipv6_dst_addr, 0x01020304U, 0x11121314U, {0xde, 0xad}
        )),
        "EthernetII -> IPv6 -> ESP(spi=0x01020304)",
        StopReason::terminal_protocol
    );

    {
        const auto ah_inner_ipv6_packet = make_raw_packet(make_ethernet_ipv4_ah_packet(
            ipv4(10, 70, 0, 1),
            ipv4(10, 70, 0, 2),
            detail::kIpProtocolIpv6Encapsulation,
            strip_ethernet_header(make_ethernet_ipv6_packet(
                ipv6_src_addr,
                ipv6_dst_addr,
                detail::kIpProtocolTcp,
                make_ipv6_tcp_segment(30000U, 443U, 1U, 0x18U)
            ))
        ));
        expect_shadow_matches_legacy_flow(
            registry,
            ah_inner_ipv6_packet,
            "EthernetII -> IPv4 -> AH(spi=0x11111111) -> IPv6 -> TCP",
            StopReason::terminal_protocol
        );
    }

    {
        const auto ah_inner_ipv4_packet = make_raw_packet(make_ethernet_ipv6_ah_packet(
            ipv6_src_addr,
            ipv6_dst_addr,
            detail::kIpProtocolIpv4Encapsulation,
            strip_ethernet_header(make_ethernet_ipv4_udp_packet(
                ipv4(172, 16, 0, 1),
                ipv4(172, 16, 0, 2),
                40000U,
                53U
            ))
        ));
        expect_shadow_matches_legacy_flow(
            registry,
            ah_inner_ipv4_packet,
            "EthernetII -> IPv6 -> AH(spi=0x11111111) -> IPv4 -> UDP",
            StopReason::terminal_protocol
        );
    }

    {
        const auto ah_sctp_shadow = run_shadow(make_raw_packet(make_ethernet_ipv4_ah_packet(
            ipv4(10, 80, 0, 1),
            ipv4(10, 80, 0, 2),
            detail::kIpProtocolSctp,
            make_sctp_segment(49152U, 36412U, 0x01020304U, 0x89ABCDEFU, 2U)
        )), registry);
        PFL_EXPECT(ah_sctp_shadow.outcome == ImportDissectionOutcome::recognized_flow);
        PFL_EXPECT(ah_sctp_shadow.terminal_protocol == ProtocolId::sctp);
        PFL_EXPECT(ah_sctp_shadow.has_ports);
        PFL_EXPECT(ah_sctp_shadow.src_port == 49152U);
        PFL_EXPECT(ah_sctp_shadow.dst_port == 36412U);
        PFL_EXPECT(format_shadow_path(ah_sctp_shadow) == "EthernetII -> IPv4 -> AH(spi=0x11111111) -> SCTP");
    }

    {
        const auto ah_icmp_shadow = run_shadow(make_raw_packet(make_ethernet_ipv4_ah_packet(
            ipv4(10, 81, 0, 1),
            ipv4(10, 81, 0, 2),
            detail::kIpProtocolIcmp,
            {8U, 0U, 0x12U, 0x34U}
        )), registry);
        PFL_EXPECT(ah_icmp_shadow.outcome == ImportDissectionOutcome::recognized_flow);
        PFL_EXPECT(ah_icmp_shadow.terminal_protocol == ProtocolId::icmp);
        PFL_EXPECT(!ah_icmp_shadow.has_ports);
        PFL_EXPECT(format_shadow_path(ah_icmp_shadow) == "EthernetII -> IPv4 -> AH(spi=0x11111111) -> ICMP");
    }

    {
        const auto ah_icmpv6_shadow = run_shadow(make_raw_packet(make_ethernet_ipv6_ah_packet(
            ipv6_src_addr,
            ipv6_dst_addr,
            detail::kIpProtocolIcmpV6,
            {128U, 0U, 0x12U, 0x34U}
        )), registry);
        PFL_EXPECT(ah_icmpv6_shadow.outcome == ImportDissectionOutcome::recognized_flow);
        PFL_EXPECT(ah_icmpv6_shadow.terminal_protocol == ProtocolId::icmpv6);
        PFL_EXPECT(!ah_icmpv6_shadow.has_ports);
        PFL_EXPECT(format_shadow_path(ah_icmpv6_shadow) == "EthernetII -> IPv6 -> AH(spi=0x11111111) -> ICMPv6");
    }

    {
        const auto ah_igmp_shadow = run_shadow(make_raw_packet(make_ethernet_ipv4_ah_packet(
            ipv4(192, 0, 2, 200),
            ipv4(224, 0, 0, 1),
            detail::kIpProtocolIgmp,
            make_igmp_message(0x16U, 0U, 0x1234U, ipv4(239, 1, 1, 1))
        )), registry);
        PFL_EXPECT(ah_igmp_shadow.outcome == ImportDissectionOutcome::recognized_flow);
        PFL_EXPECT(ah_igmp_shadow.terminal_protocol == ProtocolId::igmp);
        PFL_EXPECT(ah_igmp_shadow.family == DissectionAddressFamily::ipv4);
        PFL_EXPECT(ah_igmp_shadow.dst_addr_v4 == ipv4(239, 1, 1, 1));
        PFL_EXPECT(format_shadow_path(ah_igmp_shadow) == "EthernetII -> IPv4 -> AH(spi=0x11111111)");
    }

    {
        const auto ah_esp_shadow = run_shadow(make_raw_packet(make_ethernet_ipv4_ah_packet(
            ipv4(10, 82, 0, 1),
            ipv4(10, 82, 0, 2),
            detail::kIpProtocolEsp,
            make_esp_header(0x21222324U, 0x31323334U, {0xde, 0xad, 0xbe, 0xef})
        )), registry);
        PFL_EXPECT(ah_esp_shadow.outcome == ImportDissectionOutcome::recognized_flow);
        PFL_EXPECT(ah_esp_shadow.terminal_protocol == ProtocolId::esp);
        PFL_EXPECT(!ah_esp_shadow.has_ports);
        PFL_EXPECT(ah_esp_shadow.has_transport_payload_length);
        PFL_EXPECT(ah_esp_shadow.captured_transport_payload_length == 4U);
        PFL_EXPECT(format_shadow_path(ah_esp_shadow) == "EthernetII -> IPv4 -> AH(spi=0x11111111) -> ESP(spi=0x21222324)");
    }

    {
        const auto unknown_ah_shadow = run_shadow(make_raw_packet(make_ethernet_ipv4_ah_packet(
            ipv4(10, 83, 0, 1),
            ipv4(10, 83, 0, 2),
            0xFDU,
            {0xde, 0xad, 0xbe, 0xef}
        )), registry);
        PFL_EXPECT(unknown_ah_shadow.outcome == ImportDissectionOutcome::unrecognized);
        PFL_EXPECT(unknown_ah_shadow.stop_reason == StopReason::unknown_next_protocol);
        PFL_EXPECT(unknown_ah_shadow.terminal_protocol == ProtocolId::unknown);
        PFL_EXPECT(format_shadow_path(unknown_ah_shadow) == "EthernetII -> IPv4 -> AH(spi=0x11111111)");
    }

    {
        auto nested_ah_payload = make_ipv6_tcp_segment(1234U, 4321U, 1U, 0x18U);
        auto ah3 = make_ah_header(detail::kIpProtocolTcp, 0x33333333U, 3U);
        ah3.insert(ah3.end(), nested_ah_payload.begin(), nested_ah_payload.end());
        auto ah2 = make_ah_header(detail::kIpProtocolAh, 0x22222222U, 2U);
        ah2.insert(ah2.end(), ah3.begin(), ah3.end());
        auto ah1 = make_ah_header(detail::kIpProtocolAh, 0x11111111U, 1U);
        ah1.insert(ah1.end(), ah2.begin(), ah2.end());
        const auto repeated_ah_packet = make_raw_packet(make_ethernet_ipv6_packet(
            ipv6_src_addr,
            ipv6_dst_addr,
            detail::kIpProtocolAh,
            ah1
        ));

        StepKindRecorder repeated_ah_recorder {};
        const auto repeated_ah_result = engine.run(
            registry,
            make_link_type_selector(repeated_ah_packet.data_link_type),
            make_root_slice(repeated_ah_packet),
            DissectionConsumer {.on_step = record_step_kind, .context = &repeated_ah_recorder},
            5U
        );
        const std::vector<DissectionLayerKind> expected_repeated_ah_kinds {
            DissectionLayerKind::ethernet_ii,
            DissectionLayerKind::ipv6,
            DissectionLayerKind::ah,
            DissectionLayerKind::ah,
            DissectionLayerKind::ah,
        };
        PFL_EXPECT(repeated_ah_result.stop_reason == StopReason::depth_limit);
        PFL_EXPECT(repeated_ah_result.step_count == 5U);
        PFL_EXPECT(repeated_ah_result.traversed_depth == 5U);
        PFL_EXPECT(repeated_ah_recorder.kinds == expected_repeated_ah_kinds);

        const auto repeated_ah_shadow = run_shadow(repeated_ah_packet, registry);
        PFL_EXPECT(repeated_ah_shadow.outcome == ImportDissectionOutcome::recognized_flow);
        PFL_EXPECT(repeated_ah_shadow.terminal_protocol == ProtocolId::tcp);
        PFL_EXPECT(format_shadow_path(repeated_ah_shadow) ==
            "EthernetII -> IPv6 -> AH(spi=0x11111111) -> AH(spi=0x22222222) -> AH(spi=0x33333333) -> TCP");
    }

    {
        const auto outer_ipv4_ah_fragment_shadow = run_shadow(make_raw_packet(make_ethernet_ipv4_ah_packet(
            ipv4(10, 84, 0, 1),
            ipv4(10, 84, 0, 2),
            detail::kIpProtocolTcp,
            make_ipv4_tcp_segment(80U, 12345U),
            0x11111111U,
            1U,
            {},
            0x2000U
        )), registry);
        PFL_EXPECT(outer_ipv4_ah_fragment_shadow.outcome == ImportDissectionOutcome::unrecognized);
        PFL_EXPECT(outer_ipv4_ah_fragment_shadow.stop_reason == StopReason::needs_reassembly);
        PFL_EXPECT(format_shadow_path(outer_ipv4_ah_fragment_shadow) == "EthernetII -> IPv4");
    }

    {
        const auto outer_ipv4_esp_fragment_shadow = run_shadow(make_raw_packet(make_ethernet_ipv4_esp_packet(
            ipv4(10, 85, 0, 1),
            ipv4(10, 85, 0, 2),
            0x01020304U,
            1U,
            {0xde, 0xad, 0xbe, 0xef},
            0x2000U
        )), registry);
        PFL_EXPECT(outer_ipv4_esp_fragment_shadow.outcome == ImportDissectionOutcome::unrecognized);
        PFL_EXPECT(outer_ipv4_esp_fragment_shadow.stop_reason == StopReason::needs_reassembly);
        PFL_EXPECT(format_shadow_path(outer_ipv4_esp_fragment_shadow) == "EthernetII -> IPv4");
    }

    {
        const auto outer_ipv6_ah_fragment_shadow = run_shadow(make_raw_packet(make_ethernet_ipv6_fragment_packet(
            ipv6_src_addr,
            ipv6_dst_addr,
            detail::kIpProtocolAh,
            make_ah_header(detail::kIpProtocolTcp, 0x11111111U, 1U),
            0x0000U,
            true
        )), registry);
        PFL_EXPECT(outer_ipv6_ah_fragment_shadow.outcome == ImportDissectionOutcome::unrecognized);
        PFL_EXPECT(outer_ipv6_ah_fragment_shadow.stop_reason == StopReason::needs_reassembly);
        PFL_EXPECT(format_shadow_path(outer_ipv6_ah_fragment_shadow) == "EthernetII -> IPv6");
    }

    {
        const auto outer_ipv6_esp_fragment_shadow = run_shadow(make_raw_packet(make_ethernet_ipv6_fragment_packet(
            ipv6_src_addr,
            ipv6_dst_addr,
            detail::kIpProtocolEsp,
            make_esp_header(0x01020304U, 1U),
            0x0000U,
            true
        )), registry);
        PFL_EXPECT(outer_ipv6_esp_fragment_shadow.outcome == ImportDissectionOutcome::unrecognized);
        PFL_EXPECT(outer_ipv6_esp_fragment_shadow.stop_reason == StopReason::needs_reassembly);
        PFL_EXPECT(format_shadow_path(outer_ipv6_esp_fragment_shadow) == "EthernetII -> IPv6");
    }
}

void expect_mpls_shadow_parsers_bounds_and_traversal() {
    const auto built = make_common_direct_registry();
    PFL_REQUIRE(built.ok());
    const auto& registry = *built.registry;
    const DissectionEngine engine {};

    {
        const auto exact_label_packet = make_raw_packet(
            make_mpls_payload_with_labels(
                {16030U},
                make_ipv4_payload_packet(
                    ipv4(10, 130, 0, 1),
                    ipv4(10, 130, 0, 2),
                    detail::kIpProtocolUdp,
                    make_ipv4_udp_segment(5300U, 53U, 2U)
                )
            )
        );
        const auto exact_label_root = make_root_slice(exact_label_packet);
        const auto exact_label = parse_mpls_label(exact_label_root);
        PFL_EXPECT(exact_label.status == ParseStatus::complete);
        PFL_EXPECT(exact_label.label == 16030U);
        PFL_EXPECT(exact_label.traffic_class == 0U);
        PFL_EXPECT(exact_label.bottom_of_stack);
        PFL_EXPECT(exact_label.ttl == 64U);
        PFL_EXPECT(exact_label.header_length == detail::kMplsLabelSize);
        PFL_EXPECT(exact_label.declared_payload_length == exact_label_packet.bytes.size() - detail::kMplsLabelSize);

        const auto exact_label_step = dissect_mpls_label(exact_label_root);
        PFL_EXPECT(exact_label_step.layer == DissectionLayerKind::mpls);
        PFL_EXPECT(exact_label_step.status == ParseStatus::complete);
        PFL_EXPECT(exact_label_step.stop_reason == StopReason::none);
        PFL_REQUIRE(exact_label_step.path_contribution.has_value());
        PFL_EXPECT(*exact_label_step.path_contribution == LayerKey::mpls(16030U));
        PFL_REQUIRE(exact_label_step.handoff.has_value());
        PFL_REQUIRE(exact_label_step.handoff->child.has_value());
        const ProtocolSelector expected_payload_selector {
            .domain = SelectorDomain::mpls_payload,
            .value = detail::kEtherTypeIpv4,
        };
        PFL_EXPECT(exact_label_step.handoff->selector == expected_payload_selector);
        PFL_EXPECT(exact_label_step.bounds.full.declared.length() == exact_label_packet.bytes.size());
        PFL_EXPECT(exact_label_step.bounds.full.captured.length() == exact_label_packet.bytes.size());
        PFL_EXPECT(exact_label_step.bounds.header.declared.length() == detail::kMplsLabelSize);
        PFL_EXPECT(exact_label_step.bounds.header.captured.length() == detail::kMplsLabelSize);
        PFL_REQUIRE(exact_label_step.bounds.payload.has_value());
        PFL_EXPECT(exact_label_step.bounds.payload->declared.length() == exact_label_packet.bytes.size() - detail::kMplsLabelSize);
        PFL_EXPECT(exact_label_step.bounds.payload->captured.length() == exact_label_packet.bytes.size() - detail::kMplsLabelSize);
        const auto* exact_label_facts = std::get_if<MplsFacts>(&exact_label_step.facts);
        PFL_REQUIRE(exact_label_facts != nullptr);
        PFL_EXPECT(exact_label_facts->label == 16030U);
        PFL_EXPECT(exact_label_facts->bottom_of_stack);
    }

    {
        const auto stacked_label_packet = make_raw_packet(
            make_mpls_payload_with_labels(
                {16030U, 16031U},
                make_ipv4_payload_packet(
                    ipv4(10, 130, 1, 1),
                    ipv4(10, 130, 1, 2),
                    detail::kIpProtocolTcp,
                    make_ipv4_tcp_segment(12345U, 443U, 2U, 0x18U)
                )
            )
        );
        const auto stacked_label_step = dissect_mpls_label(make_root_slice(stacked_label_packet));
        PFL_EXPECT(stacked_label_step.status == ParseStatus::complete);
        PFL_REQUIRE(stacked_label_step.handoff.has_value());
        const ProtocolSelector expected_stack_selector {
            .domain = SelectorDomain::mpls_stack,
            .value = kMplsStackContinueSelectorValue,
        };
        PFL_EXPECT(stacked_label_step.handoff->selector == expected_stack_selector);
    }

    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(make_ethernet_frame_with_payload(
            detail::kEtherTypeMplsUnicast,
            make_mpls_payload_with_labels(
                {16030U},
                make_ipv4_payload_packet(
                    ipv4(10, 131, 0, 1),
                    ipv4(10, 131, 0, 2),
                    detail::kIpProtocolUdp,
                    make_ipv4_udp_segment(5301U, 53U, 3U)
                )
            )
        )),
        "EthernetII -> MPLS(label=16030) -> IPv4 -> UDP",
        StopReason::terminal_protocol
    );

    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(add_vlan_tags(
            make_ethernet_frame_with_payload(
                detail::kEtherTypeMplsUnicast,
                make_mpls_payload_with_labels(
                    {16040U},
                    make_ipv4_payload_packet(
                        ipv4(10, 131, 1, 1),
                        ipv4(10, 131, 1, 2),
                        detail::kIpProtocolTcp,
                        make_ipv4_tcp_segment(5302U, 443U, 1U, 0x18U)
                    )
                )
            ),
            {{0x8100U, 410U}}
        )),
        "EthernetII -> VLAN(vid=410) -> MPLS(label=16040) -> IPv4 -> TCP",
        StopReason::terminal_protocol
    );

    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(add_vlan_tags(
            make_ethernet_frame_with_payload(
                detail::kEtherTypeMplsUnicast,
                make_mpls_payload_with_labels(
                    {16050U},
                    make_ipv6_payload_packet(
                        ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 50, 0, 0, 0, 0, 0, 0, 0, 0x11}),
                        ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 50, 0, 0, 0, 0, 0, 0, 0, 0x12}),
                        detail::kIpProtocolUdp,
                        make_ipv6_udp_segment(6300U, 6301U, 2U)
                    )
                )
            ),
            {{0x88A8U, 411U}, {0x8100U, 412U}}
        )),
        "EthernetII -> VLAN(vid=411) -> VLAN(vid=412) -> MPLS(label=16050) -> IPv6 -> UDP",
        StopReason::terminal_protocol
    );

    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(make_ethernet_ipv4_gre_packet(
            ipv4(10, 132, 0, 1),
            ipv4(10, 132, 0, 2),
            make_gre_header(
                detail::kEtherTypeMplsUnicast,
                make_mpls_payload_with_labels(
                    {16030U},
                    make_ipv4_payload_packet(
                        ipv4(10, 132, 1, 1),
                        ipv4(10, 132, 1, 2),
                        detail::kIpProtocolUdp,
                        make_ipv4_udp_segment(6302U, 53U, 1U)
                    )
                )
            )
        )),
        "EthernetII -> IPv4 -> GRE -> MPLS(label=16030) -> IPv4 -> UDP",
        StopReason::terminal_protocol
    );

    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(make_ethernet_frame_with_payload(
            detail::kEtherTypeMplsUnicast,
            make_mpls_payload_with_labels(
                {100U, 200U, 300U},
                make_ipv4_payload_packet(
                    ipv4(10, 133, 0, 1),
                    ipv4(10, 133, 0, 2),
                    detail::kIpProtocolUdp,
                    make_ipv4_udp_segment(7000U, 7001U, 1U)
                )
            )
        )),
        "EthernetII -> MPLS(label=100) -> MPLS(label=200) -> MPLS(label=300) -> IPv4 -> UDP",
        StopReason::terminal_protocol
    );

    {
        const auto deep_stack_packet = make_raw_packet(make_ethernet_frame_with_payload(
            detail::kEtherTypeMplsUnicast,
            make_mpls_payload_with_labels(
                {100U, 200U, 300U},
                make_ipv4_payload_packet(
                    ipv4(10, 133, 1, 1),
                    ipv4(10, 133, 1, 2),
                    detail::kIpProtocolUdp,
                    make_ipv4_udp_segment(7002U, 7003U, 1U)
                )
            )
        ));
        StepKindRecorder recorder {};
        const auto result = engine.run(
            registry,
            make_link_type_selector(deep_stack_packet.data_link_type),
            make_root_slice(deep_stack_packet),
            DissectionConsumer {.on_step = record_step_kind, .context = &recorder}
        );
        const std::vector<DissectionLayerKind> expected_kinds {
            DissectionLayerKind::ethernet_ii,
            DissectionLayerKind::mpls,
            DissectionLayerKind::mpls,
            DissectionLayerKind::mpls,
            DissectionLayerKind::ipv4,
            DissectionLayerKind::udp,
        };
        PFL_EXPECT(result.stop_reason == StopReason::terminal_protocol);
        PFL_EXPECT(recorder.kinds == expected_kinds);

        StepKindRecorder limited_recorder {};
        const auto limited_result = engine.run(
            registry,
            make_link_type_selector(deep_stack_packet.data_link_type),
            make_root_slice(deep_stack_packet),
            DissectionConsumer {.on_step = record_step_kind, .context = &limited_recorder},
            4U
        );
        const std::vector<DissectionLayerKind> expected_limited_kinds {
            DissectionLayerKind::ethernet_ii,
            DissectionLayerKind::mpls,
            DissectionLayerKind::mpls,
            DissectionLayerKind::mpls,
        };
        PFL_EXPECT(limited_result.stop_reason == StopReason::depth_limit);
        PFL_EXPECT(limited_recorder.kinds == expected_limited_kinds);
    }

    {
        const auto unknown_payload_shadow = run_shadow(make_raw_packet(make_ethernet_frame_with_payload(
            detail::kEtherTypeMplsUnicast,
            make_mpls_payload_with_labels({16060U}, {0x12U, 0x34U, 0x56U, 0x78U})
        )), registry);
        PFL_EXPECT(unknown_payload_shadow.outcome == ImportDissectionOutcome::unrecognized);
        PFL_EXPECT(unknown_payload_shadow.stop_reason == StopReason::unrecognized_payload);
        PFL_EXPECT(format_shadow_path(unknown_payload_shadow) == "EthernetII -> MPLS(label=16060)");
    }

    {
        const auto missing_payload_shadow = run_shadow(make_raw_packet(make_ethernet_frame_with_payload(
            detail::kEtherTypeMplsUnicast,
            make_mpls_payload_with_labels({16061U}, {})
        )), registry);
        PFL_EXPECT(missing_payload_shadow.outcome == ImportDissectionOutcome::unrecognized);
        PFL_EXPECT(missing_payload_shadow.stop_reason == StopReason::no_payload);
        PFL_EXPECT(format_shadow_path(missing_payload_shadow) == "EthernetII -> MPLS(label=16061)");
    }

    {
        auto truncated_inner_ipv4 = make_ipv4_payload_packet(
            ipv4(10, 134, 0, 1),
            ipv4(10, 134, 0, 2),
            detail::kIpProtocolUdp,
            make_ipv4_udp_segment(7400U, 7401U, 1U)
        );
        truncated_inner_ipv4.resize(10U);
        const auto truncated_inner_shadow = run_shadow(
            make_raw_packet(
                make_ethernet_frame_with_payload(
                    detail::kEtherTypeMplsUnicast,
                    make_mpls_payload_with_labels({16062U}, truncated_inner_ipv4)
                ),
                14U + 4U + 20U
            ),
            registry
        );
        PFL_EXPECT(truncated_inner_shadow.outcome == ImportDissectionOutcome::unrecognized);
        PFL_EXPECT(truncated_inner_shadow.stop_reason == StopReason::truncated);
        PFL_EXPECT(format_shadow_path(truncated_inner_shadow) == "EthernetII -> MPLS(label=16062)");
    }

    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(make_ethernet_frame_with_payload(
            detail::kEtherTypeMplsUnicast,
            make_mpls_payload_with_labels(
                {16063U},
                strip_ethernet_header(make_ethernet_ipv4_fragment_packet(
                    ipv4(10, 134, 1, 1),
                    ipv4(10, 134, 1, 2),
                    detail::kIpProtocolUdp,
                    0x2000U,
                    {0xdeU, 0xadU, 0xbeU, 0xefU}
                ))
            )
        )),
        "EthernetII -> MPLS(label=16063) -> IPv4",
        StopReason::needs_reassembly
    );

    {
        const auto pseudowire_like_shadow = run_shadow(make_raw_packet(make_ethernet_frame_with_payload(
            detail::kEtherTypeMplsUnicast,
            make_mpls_payload_with_labels(
                {16064U},
                {0x00U, 0x00U, 0x12U, 0x34U, 0x02U, 0x00U, 0x00U, 0x00U, 0x31U, 0x01U}
            )
        )), registry);
        PFL_EXPECT(pseudowire_like_shadow.outcome == ImportDissectionOutcome::unrecognized);
        PFL_EXPECT(pseudowire_like_shadow.stop_reason == StopReason::unrecognized_payload);
        PFL_EXPECT(format_shadow_path(pseudowire_like_shadow) == "EthernetII -> MPLS(label=16064)");
        PFL_EXPECT(format_shadow_path(pseudowire_like_shadow).find("MPLS PW") == std::string::npos);
    }

    {
        const auto base_payload = make_ethernet_frame_with_payload(
            detail::kEtherTypeMplsUnicast,
            make_mpls_payload_with_labels(
                {17000U},
                make_ipv4_payload_packet(
                    ipv4(10, 135, 0, 1),
                    ipv4(10, 135, 0, 2),
                    detail::kIpProtocolUdp,
                    make_ipv4_udp_segment(7500U, 7501U, 1U)
                ),
                0U,
                64U
            )
        );
        const auto tc_ttl_variant = make_ethernet_frame_with_payload(
            detail::kEtherTypeMplsUnicast,
            make_mpls_payload_with_labels(
                {17000U},
                make_ipv4_payload_packet(
                    ipv4(10, 135, 0, 1),
                    ipv4(10, 135, 0, 2),
                    detail::kIpProtocolUdp,
                    make_ipv4_udp_segment(7500U, 7501U, 1U)
                ),
                5U,
                1U
            )
        );
        const auto different_label = make_ethernet_frame_with_payload(
            detail::kEtherTypeMplsUnicast,
            make_mpls_payload_with_labels(
                {17001U},
                make_ipv4_payload_packet(
                    ipv4(10, 135, 0, 1),
                    ipv4(10, 135, 0, 2),
                    detail::kIpProtocolUdp,
                    make_ipv4_udp_segment(7500U, 7501U, 1U)
                )
            )
        );
        const auto different_order = make_ethernet_frame_with_payload(
            detail::kEtherTypeMplsUnicast,
            make_mpls_payload_with_labels(
                {17002U, 17003U},
                make_ipv4_payload_packet(
                    ipv4(10, 135, 1, 1),
                    ipv4(10, 135, 1, 2),
                    detail::kIpProtocolUdp,
                    make_ipv4_udp_segment(7502U, 7503U, 1U)
                )
            )
        );
        const auto reversed_order = make_ethernet_frame_with_payload(
            detail::kEtherTypeMplsUnicast,
            make_mpls_payload_with_labels(
                {17003U, 17002U},
                make_ipv4_payload_packet(
                    ipv4(10, 135, 1, 1),
                    ipv4(10, 135, 1, 2),
                    detail::kIpProtocolUdp,
                    make_ipv4_udp_segment(7502U, 7503U, 1U)
                )
            )
        );

        const auto base_shadow = run_shadow(make_raw_packet(base_payload), registry);
        const auto tc_ttl_shadow = run_shadow(make_raw_packet(tc_ttl_variant), registry);
        const auto different_label_shadow = run_shadow(make_raw_packet(different_label), registry);
        const auto different_order_shadow = run_shadow(make_raw_packet(different_order), registry);
        const auto reversed_order_shadow = run_shadow(make_raw_packet(reversed_order), registry);

        PFL_EXPECT(shadow_path(base_shadow) == shadow_path(tc_ttl_shadow));
        PFL_EXPECT(format_shadow_path(base_shadow) == format_shadow_path(tc_ttl_shadow));
        PFL_EXPECT(shadow_path(base_shadow) != shadow_path(different_label_shadow));
        PFL_EXPECT(shadow_path(different_order_shadow) != shadow_path(reversed_order_shadow));
        PFL_EXPECT(format_shadow_path(different_order_shadow) == "EthernetII -> MPLS(label=17002) -> MPLS(label=17003) -> IPv4 -> UDP");
        PFL_EXPECT(format_shadow_path(reversed_order_shadow) == "EthernetII -> MPLS(label=17003) -> MPLS(label=17002) -> IPv4 -> UDP");
    }
}

void expect_gre_shadow_parsers_bounds_and_traversal() {
    const auto built = make_common_direct_registry();
    PFL_REQUIRE(built.ok());
    const auto& registry = *built.registry;
    const DissectionEngine engine {};

    const auto outer_ipv6_src = ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 31, 0, 0, 0, 0, 0, 0, 0, 0x11});
    const auto outer_ipv6_dst = ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 31, 0, 0, 0, 0, 0, 0, 0, 0x12});
    const auto inner_ipv6_src = ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 41, 0, 0, 0, 0, 0, 0, 0, 0x21});
    const auto inner_ipv6_dst = ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 41, 0, 0, 0, 0, 0, 0, 0, 0x22});

    {
        const auto exact_header_packet = make_raw_packet(make_gre_header(detail::kEtherTypeIpv4), detail::kGreBaseHeaderSize);
        const auto exact_header_root = make_root_slice(exact_header_packet);
        const auto exact_header = parse_gre_header(exact_header_root);
        PFL_EXPECT(exact_header.status == ParseStatus::complete);
        PFL_EXPECT(exact_header.flags_and_version == 0U);
        PFL_EXPECT(exact_header.protocol_type == detail::kEtherTypeIpv4);
        PFL_EXPECT(!exact_header.has_checksum);
        PFL_EXPECT(!exact_header.has_key);
        PFL_EXPECT(!exact_header.has_sequence);
        PFL_EXPECT(exact_header.header_length == detail::kGreBaseHeaderSize);

        const auto exact_header_step = dissect_gre(exact_header_root);
        PFL_EXPECT(exact_header_step.layer == DissectionLayerKind::gre);
        PFL_EXPECT(exact_header_step.status == ParseStatus::complete);
        PFL_EXPECT(exact_header_step.stop_reason == StopReason::none);
        PFL_REQUIRE(exact_header_step.path_contribution.has_value());
        PFL_EXPECT(*exact_header_step.path_contribution == LayerKey::gre());
        PFL_REQUIRE(exact_header_step.handoff.has_value());
        PFL_REQUIRE(exact_header_step.handoff->child.has_value());
        const ProtocolSelector expected_selector {
            .domain = SelectorDomain::gre_protocol_type,
            .value = detail::kEtherTypeIpv4,
        };
        PFL_EXPECT(exact_header_step.handoff->selector == expected_selector);
        PFL_EXPECT(exact_header_step.bounds.full.declared.length() == detail::kGreBaseHeaderSize);
        PFL_EXPECT(exact_header_step.bounds.full.captured.length() == detail::kGreBaseHeaderSize);
        PFL_EXPECT(exact_header_step.bounds.header.declared.length() == detail::kGreBaseHeaderSize);
        PFL_EXPECT(exact_header_step.bounds.header.captured.length() == detail::kGreBaseHeaderSize);
        PFL_REQUIRE(exact_header_step.bounds.payload.has_value());
        PFL_EXPECT(exact_header_step.bounds.payload->declared.length() == 0U);
        PFL_EXPECT(exact_header_step.bounds.payload->captured.length() == 0U);
        PFL_EXPECT(std::holds_alternative<GreFacts>(exact_header_step.facts));
        const auto* exact_header_facts = std::get_if<GreFacts>(&exact_header_step.facts);
        PFL_REQUIRE(exact_header_facts != nullptr);
        PFL_EXPECT(exact_header_facts->protocol_type == detail::kEtherTypeIpv4);
        PFL_EXPECT(exact_header_facts->header_length == detail::kGreBaseHeaderSize);
    }

    {
        const auto checksum_only = parse_gre_header(make_root_slice(make_raw_packet(
            make_gre_header(detail::kEtherTypeIpv4, {}, true, false, false),
            detail::kGreBaseHeaderSize + detail::kGreOptionalFieldSize
        )));
        PFL_EXPECT(checksum_only.status == ParseStatus::complete);
        PFL_EXPECT(checksum_only.has_checksum);
        PFL_EXPECT(checksum_only.checksum == 0x1234U);
        PFL_EXPECT(checksum_only.reserved1 == 0x5678U);
        PFL_EXPECT(checksum_only.header_length == detail::kGreBaseHeaderSize + detail::kGreOptionalFieldSize);
    }

    {
        const auto key_only_step = dissect_gre(make_root_slice(make_raw_packet(
            make_gre_header(detail::kEtherTypeIpv4, {}, false, true, false),
            detail::kGreBaseHeaderSize + detail::kGreOptionalFieldSize
        )));
        PFL_EXPECT(key_only_step.status == ParseStatus::complete);
        PFL_REQUIRE(key_only_step.path_contribution.has_value());
        PFL_EXPECT(*key_only_step.path_contribution == LayerKey::gre(0x11111111U));
        const auto* key_only_facts = std::get_if<GreFacts>(&key_only_step.facts);
        PFL_REQUIRE(key_only_facts != nullptr);
        PFL_EXPECT(key_only_facts->has_key);
        PFL_EXPECT(key_only_facts->key == 0x11111111U);
        PFL_EXPECT(key_only_facts->header_length == detail::kGreBaseHeaderSize + detail::kGreOptionalFieldSize);
    }

    {
        const auto sequence_only = parse_gre_header(make_root_slice(make_raw_packet(
            make_gre_header(detail::kEtherTypeIpv4, {}, false, false, true),
            detail::kGreBaseHeaderSize + detail::kGreOptionalFieldSize
        )));
        PFL_EXPECT(sequence_only.status == ParseStatus::complete);
        PFL_EXPECT(sequence_only.has_sequence);
        PFL_EXPECT(sequence_only.sequence_number == 0x01020304U);
        PFL_EXPECT(sequence_only.header_length == detail::kGreBaseHeaderSize + detail::kGreOptionalFieldSize);
    }

    {
        const auto full_optional_step = dissect_gre(make_root_slice(make_raw_packet(
            make_gre_header(detail::kEtherTypeIpv6, {}, true, true, true),
            detail::kGreBaseHeaderSize + (3U * detail::kGreOptionalFieldSize)
        )));
        PFL_EXPECT(full_optional_step.status == ParseStatus::complete);
        PFL_REQUIRE(full_optional_step.path_contribution.has_value());
        PFL_EXPECT(*full_optional_step.path_contribution == LayerKey::gre(0x11111111U));
        const auto* full_optional_facts = std::get_if<GreFacts>(&full_optional_step.facts);
        PFL_REQUIRE(full_optional_facts != nullptr);
        PFL_EXPECT(full_optional_facts->has_checksum);
        PFL_EXPECT(full_optional_facts->has_key);
        PFL_EXPECT(full_optional_facts->has_sequence);
        PFL_EXPECT(full_optional_facts->checksum == 0x1234U);
        PFL_EXPECT(full_optional_facts->reserved1 == 0x5678U);
        PFL_EXPECT(full_optional_facts->key == 0x11111111U);
        PFL_EXPECT(full_optional_facts->sequence_number == 0x01020304U);
        PFL_EXPECT(full_optional_facts->header_length == detail::kGreBaseHeaderSize + (3U * detail::kGreOptionalFieldSize));
    }

    {
        const auto zero_key_step = dissect_gre(make_root_slice(make_raw_packet(
            make_gre_header(detail::kEtherTypeIpv4, {}, false, true, false, 0U, 0x1234U, 0x5678U, 0U),
            detail::kGreBaseHeaderSize + detail::kGreOptionalFieldSize
        )));
        PFL_EXPECT(zero_key_step.status == ParseStatus::complete);
        PFL_REQUIRE(zero_key_step.path_contribution.has_value());
        PFL_EXPECT(*zero_key_step.path_contribution == LayerKey::gre(0U));
    }

    {
        const auto unsupported_version_step = dissect_gre(make_root_slice(make_raw_packet(
            make_gre_header(detail::kEtherTypeIpv4, {}, false, false, false, 0x0001U),
            detail::kGreBaseHeaderSize
        )));
        PFL_EXPECT(unsupported_version_step.status == ParseStatus::unsupported_variant);
        PFL_EXPECT(unsupported_version_step.stop_reason == StopReason::unsupported_variant);
        PFL_EXPECT(!unsupported_version_step.path_contribution.has_value());
        PFL_EXPECT(!unsupported_version_step.handoff.has_value());
    }

    {
        const auto unsupported_routing_step = dissect_gre(make_root_slice(make_raw_packet(
            make_gre_header(detail::kEtherTypeIpv4, {}, false, false, false, 0x4000U),
            detail::kGreBaseHeaderSize
        )));
        PFL_EXPECT(unsupported_routing_step.status == ParseStatus::unsupported_variant);
        PFL_EXPECT(unsupported_routing_step.stop_reason == StopReason::unsupported_variant);
        PFL_EXPECT(!unsupported_routing_step.path_contribution.has_value());
        PFL_EXPECT(!unsupported_routing_step.handoff.has_value());
    }

    {
        const auto malformed_short_step = dissect_gre(make_root_slice(make_raw_packet(
            {0x00, 0x00, 0x08},
            3U
        )));
        PFL_EXPECT(malformed_short_step.status == ParseStatus::malformed);
        PFL_EXPECT(!malformed_short_step.path_contribution.has_value());
        PFL_EXPECT(!malformed_short_step.handoff.has_value());
    }

    {
        auto truncated_base_bytes = make_gre_header(detail::kEtherTypeIpv4);
        truncated_base_bytes.resize(detail::kGreBaseHeaderSize - 1U);
        const auto truncated_base_step = dissect_gre(make_root_slice(make_raw_packet(
            truncated_base_bytes,
            detail::kGreBaseHeaderSize
        )));
        PFL_EXPECT(truncated_base_step.status == ParseStatus::truncated);
        PFL_EXPECT(!truncated_base_step.path_contribution.has_value());
        PFL_EXPECT(!truncated_base_step.handoff.has_value());
    }

    {
        const auto malformed_key_step = dissect_gre(make_root_slice(make_raw_packet(
            make_gre_header(detail::kEtherTypeIpv4, {}, false, true, false),
            detail::kGreBaseHeaderSize + 2U
        )));
        PFL_EXPECT(malformed_key_step.status == ParseStatus::malformed);
        PFL_EXPECT(!malformed_key_step.path_contribution.has_value());
    }

    {
        auto truncated_key_bytes = make_gre_header(detail::kEtherTypeIpv4, {}, false, true, false);
        truncated_key_bytes.resize(detail::kGreBaseHeaderSize + 2U);
        const auto truncated_key_step = dissect_gre(make_root_slice(make_raw_packet(
            truncated_key_bytes,
            detail::kGreBaseHeaderSize + detail::kGreOptionalFieldSize
        )));
        PFL_EXPECT(truncated_key_step.status == ParseStatus::truncated);
        PFL_EXPECT(!truncated_key_step.path_contribution.has_value());
    }

    {
        const auto malformed_sequence_step = dissect_gre(make_root_slice(make_raw_packet(
            make_gre_header(detail::kEtherTypeIpv4, {}, false, false, true),
            detail::kGreBaseHeaderSize + 2U
        )));
        PFL_EXPECT(malformed_sequence_step.status == ParseStatus::malformed);
        PFL_EXPECT(!malformed_sequence_step.path_contribution.has_value());
    }

    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(make_ethernet_ipv4_gre_packet(
            ipv4(10, 90, 0, 1),
            ipv4(10, 90, 0, 2),
            make_gre_header(
                detail::kEtherTypeIpv4,
                make_ipv4_payload_packet(
                    ipv4(172, 20, 0, 1),
                    ipv4(172, 20, 0, 2),
                    detail::kIpProtocolTcp,
                    make_ipv4_tcp_segment(12345U, 443U, 3U, 0x18U)
                )
            )
        )),
        "EthernetII -> IPv4 -> GRE -> IPv4 -> TCP",
        StopReason::terminal_protocol
    );
    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(make_ethernet_ipv4_gre_packet(
            ipv4(10, 90, 1, 1),
            ipv4(10, 90, 1, 2),
            make_gre_header(
                detail::kEtherTypeIpv4,
                make_ipv4_payload_packet(
                    ipv4(172, 20, 1, 1),
                    ipv4(172, 20, 1, 2),
                    detail::kIpProtocolUdp,
                    make_ipv4_udp_segment(5300U, 53U, 4U)
                )
            )
        )),
        "EthernetII -> IPv4 -> GRE -> IPv4 -> UDP",
        StopReason::terminal_protocol
    );
    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(make_ethernet_ipv4_gre_packet(
            ipv4(10, 90, 2, 1),
            ipv4(10, 90, 2, 2),
            make_gre_header(
                detail::kEtherTypeIpv6,
                make_ipv6_payload_packet(
                    inner_ipv6_src,
                    inner_ipv6_dst,
                    detail::kIpProtocolTcp,
                    make_ipv6_tcp_segment(23456U, 443U, 2U, 0x18U)
                )
            )
        )),
        "EthernetII -> IPv4 -> GRE -> IPv6 -> TCP",
        StopReason::terminal_protocol
    );
    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(make_ethernet_ipv4_gre_packet(
            ipv4(10, 90, 3, 1),
            ipv4(10, 90, 3, 2),
            make_gre_header(
                detail::kEtherTypeIpv6,
                make_ipv6_payload_packet(
                    inner_ipv6_src,
                    inner_ipv6_dst,
                    detail::kIpProtocolUdp,
                    make_ipv6_udp_segment(5301U, 5302U, 3U)
                )
            )
        )),
        "EthernetII -> IPv4 -> GRE -> IPv6 -> UDP",
        StopReason::terminal_protocol
    );
    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(make_ethernet_ipv6_gre_packet(
            outer_ipv6_src,
            outer_ipv6_dst,
            make_gre_header(
                detail::kEtherTypeIpv4,
                make_ipv4_payload_packet(
                    ipv4(172, 20, 4, 1),
                    ipv4(172, 20, 4, 2),
                    detail::kIpProtocolTcp,
                    make_ipv4_tcp_segment(34567U, 8443U, 1U, 0x18U)
                )
            )
        )),
        "EthernetII -> IPv6 -> GRE -> IPv4 -> TCP",
        StopReason::terminal_protocol
    );
    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(make_ethernet_ipv6_gre_packet(
            outer_ipv6_src,
            outer_ipv6_dst,
            make_gre_header(
                detail::kEtherTypeIpv6,
                make_ipv6_payload_packet(
                    inner_ipv6_src,
                    inner_ipv6_dst,
                    detail::kIpProtocolUdp,
                    make_ipv6_udp_segment(6300U, 6301U, 2U)
                )
            )
        )),
        "EthernetII -> IPv6 -> GRE -> IPv6 -> UDP",
        StopReason::terminal_protocol
    );
    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(make_ethernet_ipv4_gre_packet(
            ipv4(10, 90, 5, 1),
            ipv4(10, 90, 5, 2),
            make_gre_header(
                detail::kEtherTypeIpv4,
                make_ipv4_payload_packet(
                    ipv4(172, 20, 5, 1),
                    ipv4(172, 20, 5, 2),
                    detail::kIpProtocolSctp,
                    make_sctp_segment(49152U, 36412U, 0x01020304U, 0x89ABCDEFU, 2U)
                )
            )
        )),
        "EthernetII -> IPv4 -> GRE -> IPv4 -> SCTP",
        StopReason::terminal_protocol
    );

    {
        const auto outer_hbh_gre_udp = make_raw_packet(make_ethernet_ipv6_packet(
            outer_ipv6_src,
            outer_ipv6_dst,
            detail::kIpProtocolHopByHop,
            make_ipv6_hop_by_hop_extension(
                detail::kIpProtocolGre,
                make_gre_header(
                    detail::kEtherTypeIpv4,
                    make_ipv4_payload_packet(
                        ipv4(172, 20, 6, 1),
                        ipv4(172, 20, 6, 2),
                        detail::kIpProtocolUdp,
                        make_ipv4_udp_segment(7000U, 7001U, 2U)
                    )
                )
            )
        ));
        expect_shadow_matches_legacy_flow(
            registry,
            outer_hbh_gre_udp,
            "EthernetII -> IPv6 -> GRE -> IPv4 -> UDP",
            StopReason::terminal_protocol
        );
    }

    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(add_vlan_tags(
            make_ethernet_ipv4_gre_packet(
                ipv4(10, 90, 7, 1),
                ipv4(10, 90, 7, 2),
                make_gre_header(
                    detail::kEtherTypeIpv4,
                    make_ipv4_payload_packet(
                        ipv4(172, 20, 7, 1),
                        ipv4(172, 20, 7, 2),
                        detail::kIpProtocolUdp,
                        make_ipv4_udp_segment(7100U, 7101U, 1U)
                    )
                )
            ),
            {{0x8100U, 330U}}
        )),
        "EthernetII -> VLAN(vid=330) -> IPv4 -> GRE -> IPv4 -> UDP",
        StopReason::terminal_protocol
    );
    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(add_vlan_tags(
            make_ethernet_ipv4_gre_packet(
                ipv4(10, 90, 8, 1),
                ipv4(10, 90, 8, 2),
                make_gre_header(
                    detail::kEtherTypeIpv4,
                    make_ipv4_payload_packet(
                        ipv4(172, 20, 8, 1),
                        ipv4(172, 20, 8, 2),
                        detail::kIpProtocolTcp,
                        make_ipv4_tcp_segment(7200U, 7201U, 1U, 0x18U)
                    )
                )
            ),
            {{0x88A8U, 331U}, {0x8100U, 330U}}
        )),
        "EthernetII -> VLAN(vid=331) -> VLAN(vid=330) -> IPv4 -> GRE -> IPv4 -> TCP",
        StopReason::terminal_protocol
    );
    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(make_ethernet_ipv4_gre_packet(
            ipv4(10, 90, 9, 1),
            ipv4(10, 90, 9, 2),
            make_gre_header(
                detail::kGreProtocolTypeTransparentEthernetBridging,
                make_ethernet_ipv4_tcp_packet(ipv4(192, 0, 2, 1), ipv4(192, 0, 2, 2), 7300U, 7301U)
            )
        )),
        "EthernetII -> IPv4 -> GRE -> EthernetII -> IPv4 -> TCP",
        StopReason::terminal_protocol
    );
    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(make_ethernet_ipv4_gre_packet(
            ipv4(10, 90, 10, 1),
            ipv4(10, 90, 10, 2),
            make_gre_header(
                detail::kGreProtocolTypeTransparentEthernetBridging,
                add_vlan_tags(
                    make_ethernet_ipv4_udp_packet(ipv4(192, 0, 2, 11), ipv4(192, 0, 2, 12), 7400U, 7401U),
                    {{0x8100U, 130U}}
                )
            )
        )),
        "EthernetII -> IPv4 -> GRE -> EthernetII -> VLAN(vid=130) -> IPv4 -> UDP",
        StopReason::terminal_protocol
    );

    {
        const auto gre_icmp_shadow = run_shadow(make_raw_packet(make_ethernet_ipv4_gre_packet(
            ipv4(10, 91, 0, 1),
            ipv4(10, 91, 0, 2),
            make_gre_header(
                detail::kEtherTypeIpv4,
                strip_ethernet_header(make_ethernet_ipv4_icmp_packet(
                    ipv4(172, 21, 0, 1),
                    ipv4(172, 21, 0, 2),
                    8U,
                    0U
                ))
            )
        )), registry);
        PFL_EXPECT(gre_icmp_shadow.outcome == ImportDissectionOutcome::recognized_flow);
        PFL_EXPECT(gre_icmp_shadow.stop_reason == StopReason::terminal_protocol);
        PFL_EXPECT(gre_icmp_shadow.terminal_protocol == ProtocolId::icmp);
        PFL_EXPECT(!gre_icmp_shadow.has_ports);
        PFL_EXPECT(format_shadow_path(gre_icmp_shadow) == "EthernetII -> IPv4 -> GRE -> IPv4 -> ICMP");
    }

    {
        const auto gre_icmpv6_shadow = run_shadow(make_raw_packet(make_ethernet_ipv4_gre_packet(
            ipv4(10, 91, 1, 1),
            ipv4(10, 91, 1, 2),
            make_gre_header(
                detail::kEtherTypeIpv6,
                make_ipv6_payload_packet(
                    inner_ipv6_src,
                    inner_ipv6_dst,
                    detail::kIpProtocolIcmpV6,
                    make_ipv6_icmpv6_message(128U, 0U)
                )
            )
        )), registry);
        PFL_EXPECT(gre_icmpv6_shadow.outcome == ImportDissectionOutcome::recognized_flow);
        PFL_EXPECT(gre_icmpv6_shadow.stop_reason == StopReason::terminal_protocol);
        PFL_EXPECT(gre_icmpv6_shadow.terminal_protocol == ProtocolId::icmpv6);
        PFL_EXPECT(!gre_icmpv6_shadow.has_ports);
        PFL_EXPECT(format_shadow_path(gre_icmpv6_shadow) == "EthernetII -> IPv4 -> GRE -> IPv6 -> ICMPv6");
    }

    {
        const auto gre_igmp_shadow = run_shadow(make_raw_packet(make_ethernet_ipv4_gre_packet(
            ipv4(10, 91, 2, 1),
            ipv4(10, 91, 2, 2),
            make_gre_header(
                detail::kEtherTypeIpv4,
                strip_ethernet_header(make_ethernet_ipv4_igmp_packet(
                    ipv4(172, 21, 2, 1),
                    ipv4(239, 1, 1, 1),
                    detail::kIgmpTypeV2MembershipReport,
                    0U,
                    0x1234U,
                    ipv4(239, 1, 1, 1)
                ))
            )
        )), registry);
        PFL_EXPECT(gre_igmp_shadow.outcome == ImportDissectionOutcome::recognized_flow);
        PFL_EXPECT(gre_igmp_shadow.stop_reason == StopReason::terminal_protocol);
        PFL_EXPECT(gre_igmp_shadow.terminal_protocol == ProtocolId::igmp);
        PFL_EXPECT(!gre_igmp_shadow.has_ports);
        PFL_EXPECT(gre_igmp_shadow.has_flow_addresses);
        PFL_EXPECT(gre_igmp_shadow.dst_addr_v4 == ipv4(239, 1, 1, 1));
        PFL_EXPECT(format_shadow_path(gre_igmp_shadow) == "EthernetII -> IPv4 -> GRE -> IPv4");
    }

    {
        const auto gre_esp_shadow = run_shadow(make_raw_packet(make_ethernet_ipv4_gre_packet(
            ipv4(10, 91, 3, 1),
            ipv4(10, 91, 3, 2),
            make_gre_header(
                detail::kEtherTypeIpv4,
                make_ipv4_payload_packet(
                    ipv4(172, 21, 3, 1),
                    ipv4(172, 21, 3, 2),
                    detail::kIpProtocolEsp,
                    make_esp_header(0x01020304U, 0x11121314U, {0xde, 0xad})
                )
            )
        )), registry);
        PFL_EXPECT(gre_esp_shadow.outcome == ImportDissectionOutcome::recognized_flow);
        PFL_EXPECT(gre_esp_shadow.stop_reason == StopReason::terminal_protocol);
        PFL_EXPECT(gre_esp_shadow.terminal_protocol == ProtocolId::esp);
        PFL_EXPECT(!gre_esp_shadow.has_ports);
        PFL_EXPECT(format_shadow_path(gre_esp_shadow) == "EthernetII -> IPv4 -> GRE -> IPv4 -> ESP(spi=0x01020304)");
    }

    {
        const auto unknown_inner_shadow = run_shadow(make_raw_packet(make_ethernet_ipv4_gre_packet(
            ipv4(10, 92, 0, 1),
            ipv4(10, 92, 0, 2),
            make_gre_header(0x1234U, {0xde, 0xad, 0xbe, 0xef})
        )), registry);
        PFL_EXPECT(unknown_inner_shadow.outcome == ImportDissectionOutcome::unrecognized);
        PFL_EXPECT(unknown_inner_shadow.stop_reason == StopReason::unknown_next_protocol);
        PFL_EXPECT(unknown_inner_shadow.terminal_protocol == ProtocolId::unknown);
        PFL_EXPECT(format_shadow_path(unknown_inner_shadow) == "EthernetII -> IPv4 -> GRE");
    }

    {
        const auto gre_mpls_shadow = run_shadow(make_raw_packet(make_ethernet_ipv4_gre_packet(
            ipv4(10, 92, 1, 1),
            ipv4(10, 92, 1, 2),
            make_gre_header(
                detail::kEtherTypeMplsUnicast,
                make_mpls_payload_with_labels(
                    {16030U},
                    make_ipv4_payload_packet(
                        ipv4(172, 21, 4, 1),
                        ipv4(172, 21, 4, 2),
                        detail::kIpProtocolUdp,
                        make_ipv4_udp_segment(7600U, 7601U, 1U)
                    )
                )
            )
        )), registry);
        PFL_EXPECT(gre_mpls_shadow.outcome == ImportDissectionOutcome::recognized_flow);
        PFL_EXPECT(gre_mpls_shadow.stop_reason == StopReason::terminal_protocol);
        PFL_EXPECT(gre_mpls_shadow.terminal_protocol == ProtocolId::udp);
        PFL_EXPECT(gre_mpls_shadow.has_ports);
        PFL_EXPECT(gre_mpls_shadow.src_port == 7600U);
        PFL_EXPECT(gre_mpls_shadow.dst_port == 7601U);
        PFL_EXPECT(format_shadow_path(gre_mpls_shadow) == "EthernetII -> IPv4 -> GRE -> MPLS(label=16030) -> IPv4 -> UDP");
    }

    {
        auto truncated_inner_ipv4 = make_ipv4_payload_packet(
            ipv4(172, 22, 0, 1),
            ipv4(172, 22, 0, 2),
            detail::kIpProtocolUdp,
            make_ipv4_udp_segment(7500U, 7501U, 1U)
        );
        truncated_inner_ipv4.resize(10U);
        const auto truncated_inner_shadow = run_shadow(make_raw_packet(make_ethernet_ipv4_gre_packet(
            ipv4(10, 92, 2, 1),
            ipv4(10, 92, 2, 2),
            make_gre_header(detail::kEtherTypeIpv4, truncated_inner_ipv4)
        ), 14U + 20U + detail::kGreBaseHeaderSize + 20U), registry);
        PFL_EXPECT(truncated_inner_shadow.outcome == ImportDissectionOutcome::unrecognized);
        PFL_EXPECT(truncated_inner_shadow.stop_reason == StopReason::truncated);
        PFL_EXPECT(format_shadow_path(truncated_inner_shadow) == "EthernetII -> IPv4 -> GRE");
        PFL_EXPECT(!truncated_inner_shadow.has_ports);
    }

    {
        const auto outer_ipv4_fragment_shadow = run_shadow(make_raw_packet(make_ethernet_ipv4_gre_packet(
            ipv4(10, 92, 3, 1),
            ipv4(10, 92, 3, 2),
            make_gre_header(detail::kEtherTypeIpv4, {0xde, 0xad, 0xbe, 0xef}),
            0x2000U
        )), registry);
        PFL_EXPECT(outer_ipv4_fragment_shadow.outcome == ImportDissectionOutcome::unrecognized);
        PFL_EXPECT(outer_ipv4_fragment_shadow.stop_reason == StopReason::needs_reassembly);
        PFL_EXPECT(format_shadow_path(outer_ipv4_fragment_shadow) == "EthernetII -> IPv4");
    }

    {
        const auto outer_ipv6_fragment_shadow = run_shadow(make_raw_packet(make_ethernet_ipv6_fragment_packet(
            outer_ipv6_src,
            outer_ipv6_dst,
            detail::kIpProtocolGre,
            make_gre_header(detail::kEtherTypeIpv4, {0xde, 0xad, 0xbe, 0xef})
        )), registry);
        PFL_EXPECT(outer_ipv6_fragment_shadow.outcome == ImportDissectionOutcome::unrecognized);
        PFL_EXPECT(outer_ipv6_fragment_shadow.stop_reason == StopReason::needs_reassembly);
        PFL_EXPECT(format_shadow_path(outer_ipv6_fragment_shadow) == "EthernetII -> IPv6");
    }

    {
        const auto inner_fragment_shadow = run_shadow(make_raw_packet(make_ethernet_ipv4_gre_packet(
            ipv4(10, 92, 4, 1),
            ipv4(10, 92, 4, 2),
            make_gre_header(
                detail::kEtherTypeIpv4,
                make_ipv4_payload_packet(
                    ipv4(172, 22, 4, 1),
                    ipv4(172, 22, 4, 2),
                    detail::kIpProtocolUdp,
                    make_ipv4_udp_segment(7600U, 7601U, 2U),
                    0x2000U
                )
            )
        )), registry);
        PFL_EXPECT(inner_fragment_shadow.outcome == ImportDissectionOutcome::recognized_flow);
        PFL_EXPECT(inner_fragment_shadow.stop_reason == StopReason::needs_reassembly);
        PFL_EXPECT(inner_fragment_shadow.terminal_protocol == ProtocolId::udp);
        PFL_EXPECT(format_shadow_path(inner_fragment_shadow) == "EthernetII -> IPv4 -> GRE -> IPv4");
        PFL_EXPECT(!inner_fragment_shadow.has_ports);
    }

    {
        auto nested_gre_payload = make_gre_header(
            detail::kEtherTypeIpv6,
            make_ipv6_payload_packet(
                inner_ipv6_src,
                inner_ipv6_dst,
                detail::kIpProtocolUdp,
                make_ipv6_udp_segment(7700U, 7701U, 1U)
            )
        );
        nested_gre_payload = make_gre_header(
            detail::kEtherTypeIpv4,
            make_ipv4_payload_packet(
                ipv4(172, 22, 5, 1),
                ipv4(172, 22, 5, 2),
                detail::kIpProtocolGre,
                nested_gre_payload
            )
        );
        const auto nested_gre_packet = make_raw_packet(make_ethernet_ipv4_gre_packet(
            ipv4(10, 92, 5, 1),
            ipv4(10, 92, 5, 2),
            nested_gre_payload
        ));
        const auto nested_gre_shadow = run_shadow(nested_gre_packet, registry);
        PFL_EXPECT(nested_gre_shadow.outcome == ImportDissectionOutcome::recognized_flow);
        PFL_EXPECT(nested_gre_shadow.stop_reason == StopReason::terminal_protocol);
        PFL_EXPECT(format_shadow_path(nested_gre_shadow) == "EthernetII -> IPv4 -> GRE -> IPv4 -> GRE -> IPv6 -> UDP");

        StepKindRecorder nested_gre_recorder {};
        const auto nested_gre_depth_result = engine.run(
            registry,
            make_link_type_selector(nested_gre_packet.data_link_type),
            make_root_slice(nested_gre_packet),
            DissectionConsumer {.on_step = record_step_kind, .context = &nested_gre_recorder},
            5U
        );
        const std::vector<DissectionLayerKind> expected_nested_gre_kinds {
            DissectionLayerKind::ethernet_ii,
            DissectionLayerKind::ipv4,
            DissectionLayerKind::gre,
            DissectionLayerKind::ipv4,
            DissectionLayerKind::gre,
        };
        PFL_EXPECT(nested_gre_depth_result.stop_reason == StopReason::depth_limit);
        PFL_EXPECT(nested_gre_recorder.kinds == expected_nested_gre_kinds);
    }

    {
        const auto first_key_shadow = run_shadow(make_raw_packet(make_ethernet_ipv4_gre_packet(
            ipv4(10, 93, 0, 1),
            ipv4(10, 93, 0, 2),
            make_gre_header(
                detail::kEtherTypeIpv4,
                make_ipv4_payload_packet(
                    ipv4(172, 23, 0, 1),
                    ipv4(172, 23, 0, 2),
                    detail::kIpProtocolUdp,
                    make_ipv4_udp_segment(7800U, 7801U, 1U)
                ),
                false,
                true,
                false,
                0U,
                0x1234U,
                0x5678U,
                0x11111111U
            )
        )), registry);
        const auto second_key_shadow = run_shadow(make_raw_packet(make_ethernet_ipv4_gre_packet(
            ipv4(10, 93, 0, 1),
            ipv4(10, 93, 0, 2),
            make_gre_header(
                detail::kEtherTypeIpv4,
                make_ipv4_payload_packet(
                    ipv4(172, 23, 0, 1),
                    ipv4(172, 23, 0, 2),
                    detail::kIpProtocolUdp,
                    make_ipv4_udp_segment(7800U, 7801U, 1U)
                ),
                false,
                true,
                false,
                0U,
                0x1234U,
                0x5678U,
                0x22222222U
            )
        )), registry);
        const auto repeated_first_key_shadow = run_shadow(make_raw_packet(make_ethernet_ipv4_gre_packet(
            ipv4(10, 93, 0, 1),
            ipv4(10, 93, 0, 2),
            make_gre_header(
                detail::kEtherTypeIpv4,
                make_ipv4_payload_packet(
                    ipv4(172, 23, 0, 1),
                    ipv4(172, 23, 0, 2),
                    detail::kIpProtocolUdp,
                    make_ipv4_udp_segment(7800U, 7801U, 1U)
                ),
                false,
                true,
                false,
                0U,
                0x1234U,
                0x5678U,
                0x11111111U
            )
        )), registry);

        const auto first_key_path = shadow_path(first_key_shadow);
        const auto second_key_path = shadow_path(second_key_shadow);
        const auto repeated_first_key_path = shadow_path(repeated_first_key_shadow);
        PFL_EXPECT(format_protocol_path(first_key_path) == "EthernetII -> IPv4 -> GRE(key=0x11111111) -> IPv4 -> UDP");
        PFL_EXPECT(format_protocol_path(second_key_path) == "EthernetII -> IPv4 -> GRE(key=0x22222222) -> IPv4 -> UDP");
        PFL_EXPECT(first_key_path == repeated_first_key_path);
        PFL_EXPECT(!(first_key_path == second_key_path));

        ProtocolPathRegistry registry_ids {};
        const auto first_key_id = registry_ids.intern(first_key_path);
        const auto second_key_id = registry_ids.intern(second_key_path);
        const auto repeated_first_key_id = registry_ids.intern(repeated_first_key_path);
        PFL_EXPECT(first_key_id != kInvalidProtocolPathId);
        PFL_EXPECT(second_key_id != kInvalidProtocolPathId);
        PFL_EXPECT(first_key_id != second_key_id);
        PFL_EXPECT(first_key_id == repeated_first_key_id);
    }
}

void expect_icmp_canonical_parsers_and_bounds() {
    const auto exact_icmp_packet = make_raw_packet(std::vector<std::uint8_t> {
        8U, 0U, 0x12U, 0x34U,
    });
    const auto exact_icmp_root = make_root_slice(exact_icmp_packet);
    const auto exact_icmp = parse_icmp_common_header(exact_icmp_root);
    PFL_EXPECT(exact_icmp.status == ParseStatus::complete);
    PFL_EXPECT(exact_icmp.type == 8U);
    PFL_EXPECT(exact_icmp.code == 0U);
    PFL_EXPECT(exact_icmp.checksum == 0x1234U);
    PFL_EXPECT(exact_icmp.header_length == 4U);
    PFL_EXPECT(exact_icmp.captured_payload_length == 0U);

    const auto exact_icmp_step = dissect_icmp(exact_icmp_root);
    PFL_EXPECT(exact_icmp_step.layer == DissectionLayerKind::icmp);
    PFL_REQUIRE(exact_icmp_step.path_contribution.has_value());
    PFL_EXPECT(*exact_icmp_step.path_contribution == LayerKey::icmp());
    PFL_EXPECT(exact_icmp_step.terminal_disposition == TerminalDisposition::flow_candidate);
    PFL_REQUIRE(exact_icmp_step.bounds.payload.has_value());
    PFL_EXPECT(exact_icmp_step.bounds.full.declared.length() == 4U);
    PFL_EXPECT(exact_icmp_step.bounds.full.captured.length() == 4U);
    PFL_EXPECT(exact_icmp_step.bounds.header.declared.length() == 4U);
    PFL_EXPECT(exact_icmp_step.bounds.header.captured.length() == 4U);
    PFL_EXPECT(exact_icmp_step.bounds.payload->declared.length() == 0U);
    PFL_EXPECT(exact_icmp_step.bounds.payload->captured.length() == 0U);
    PFL_EXPECT(std::holds_alternative<IcmpFacts>(exact_icmp_step.facts));
    const auto* exact_icmp_facts = std::get_if<IcmpFacts>(&exact_icmp_step.facts);
    PFL_REQUIRE(exact_icmp_facts != nullptr);
    PFL_EXPECT(exact_icmp_facts->type == 8U);
    PFL_EXPECT(exact_icmp_facts->code == 0U);
    PFL_EXPECT(exact_icmp_facts->checksum == 0x1234U);

    const auto full_icmp_packet = make_raw_packet(std::vector<std::uint8_t> {
        3U, 7U, 0xAAU, 0x55U, 0xDEU, 0xADU, 0xBEU, 0xEFU,
    });
    const auto full_icmp = parse_icmp_common_header(make_root_slice(full_icmp_packet));
    PFL_EXPECT(full_icmp.status == ParseStatus::complete);
    PFL_EXPECT(full_icmp.captured_payload_length == 4U);

    const auto truncated_body_icmp_packet = make_raw_packet(
        std::vector<std::uint8_t> {3U, 7U, 0xAAU, 0x55U, 0xDEU},
        8U
    );
    const auto truncated_body_icmp_step = dissect_icmp(make_root_slice(truncated_body_icmp_packet));
    PFL_EXPECT(truncated_body_icmp_step.status == ParseStatus::complete);
    PFL_REQUIRE(truncated_body_icmp_step.bounds.payload.has_value());
    PFL_EXPECT(truncated_body_icmp_step.bounds.payload->declared.length() == 4U);
    PFL_EXPECT(truncated_body_icmp_step.bounds.payload->captured.length() == 1U);

    const auto extra_tail_icmp_packet = make_raw_packet(
        std::vector<std::uint8_t> {11U, 9U, 0xBEU, 0xEFU, 0xAAU, 0xBBU, 0xCCU, 0xDDU},
        6U
    );
    const auto extra_tail_icmp_step = dissect_icmp(make_root_slice(extra_tail_icmp_packet));
    PFL_EXPECT(extra_tail_icmp_step.status == ParseStatus::complete);
    PFL_REQUIRE(extra_tail_icmp_step.bounds.payload.has_value());
    PFL_EXPECT(extra_tail_icmp_step.bounds.full.declared.length() == 6U);
    PFL_EXPECT(extra_tail_icmp_step.bounds.full.captured.length() == 6U);
    PFL_EXPECT(extra_tail_icmp_step.bounds.payload->declared.length() == 2U);
    PFL_EXPECT(extra_tail_icmp_step.bounds.payload->captured.length() == 2U);

    const auto truncated_icmp_packet = make_raw_packet(
        std::vector<std::uint8_t> {8U, 0U, 0x12U},
        4U
    );
    const auto truncated_icmp_root = make_root_slice(truncated_icmp_packet);
    const auto truncated_icmp = parse_icmp_common_header(truncated_icmp_root);
    PFL_EXPECT(truncated_icmp.status == ParseStatus::truncated);
    const auto truncated_icmp_step = dissect_icmp(truncated_icmp_root);
    PFL_EXPECT(truncated_icmp_step.status == ParseStatus::truncated);
    PFL_EXPECT(!truncated_icmp_step.path_contribution.has_value());
    PFL_EXPECT(truncated_icmp_step.terminal_disposition == TerminalDisposition::none);

    const auto impossible_icmp_packet = make_raw_packet(
        std::vector<std::uint8_t> {8U, 0U, 0x12U, 0x34U},
        3U
    );
    const auto impossible_icmp_step = dissect_icmp(make_root_slice(impossible_icmp_packet));
    PFL_EXPECT(impossible_icmp_step.status == ParseStatus::malformed);
    PFL_EXPECT(!impossible_icmp_step.path_contribution.has_value());
    PFL_EXPECT(impossible_icmp_step.bounds.full.declared.length() == 3U);
    PFL_EXPECT(impossible_icmp_step.bounds.full.captured.length() == 3U);

    const auto exact_icmpv6_packet = make_raw_packet(std::vector<std::uint8_t> {
        128U, 0U, 0xABU, 0xCDU,
    });
    const auto exact_icmpv6_root = make_root_slice(exact_icmpv6_packet);
    const auto exact_icmpv6 = parse_icmpv6_common_header(exact_icmpv6_root);
    PFL_EXPECT(exact_icmpv6.status == ParseStatus::complete);
    PFL_EXPECT(exact_icmpv6.type == 128U);
    PFL_EXPECT(exact_icmpv6.code == 0U);
    PFL_EXPECT(exact_icmpv6.checksum == 0xABCDU);

    const auto exact_icmpv6_step = dissect_icmpv6(exact_icmpv6_root);
    PFL_EXPECT(exact_icmpv6_step.layer == DissectionLayerKind::icmpv6);
    PFL_REQUIRE(exact_icmpv6_step.path_contribution.has_value());
    PFL_EXPECT(*exact_icmpv6_step.path_contribution == LayerKey::icmpv6());
    PFL_EXPECT(std::holds_alternative<Icmpv6Facts>(exact_icmpv6_step.facts));
    const auto* exact_icmpv6_facts = std::get_if<Icmpv6Facts>(&exact_icmpv6_step.facts);
    PFL_REQUIRE(exact_icmpv6_facts != nullptr);
    PFL_EXPECT(exact_icmpv6_facts->type == 128U);
    PFL_EXPECT(exact_icmpv6_facts->code == 0U);
    PFL_EXPECT(exact_icmpv6_facts->checksum == 0xABCDU);

    const auto unknown_icmpv6_packet = make_raw_packet(std::vector<std::uint8_t> {
        0xFEU, 0x7FU, 0x00U, 0x01U, 0x99U,
    });
    const auto unknown_icmpv6 = parse_icmpv6_common_header(make_root_slice(unknown_icmpv6_packet));
    PFL_EXPECT(unknown_icmpv6.status == ParseStatus::complete);
    PFL_EXPECT(unknown_icmpv6.type == 0xFEU);
    PFL_EXPECT(unknown_icmpv6.code == 0x7FU);

    const auto truncated_icmpv6_packet = make_raw_packet(
        std::vector<std::uint8_t> {128U, 0U},
        4U
    );
    PFL_EXPECT(parse_icmpv6_common_header(make_root_slice(truncated_icmpv6_packet)).status == ParseStatus::truncated);

    const auto built = make_common_direct_registry();
    PFL_REQUIRE(built.ok());
    const auto truncated_icmp_shadow = run_shadow(
        make_raw_packet(
            []() {
                auto packet = make_ethernet_ipv4_icmp_packet(
                    ipv4(10, 91, 0, 1),
                    ipv4(10, 91, 0, 2),
                    8U,
                    0U
                );
                packet.resize(14U + 20U + 3U);
                return packet;
            }(),
            14U + 20U + 8U
        ),
        *built.registry
    );
    PFL_EXPECT(truncated_icmp_shadow.outcome == ImportDissectionOutcome::unrecognized);
    PFL_EXPECT(truncated_icmp_shadow.stop_reason == StopReason::truncated);
    PFL_EXPECT(truncated_icmp_shadow.terminal_protocol == ProtocolId::icmp);
    PFL_EXPECT(!truncated_icmp_shadow.has_ports);
    PFL_EXPECT(format_shadow_path(truncated_icmp_shadow) == "EthernetII -> IPv4");
}

void expect_igmp_canonical_parsers_and_bounds() {
    const auto exact_igmp_packet = make_raw_packet(std::vector<std::uint8_t> {
        detail::kIgmpTypeMembershipQuery,
        0x7FU,
        0x12U, 0x34U,
        0xE0U, 0x00U, 0x00U, 0x01U,
    });
    const auto exact_igmp_root = make_root_slice(exact_igmp_packet);
    const auto exact_igmp = parse_igmp_common_header(exact_igmp_root);
    PFL_EXPECT(exact_igmp.status == ParseStatus::complete);
    PFL_EXPECT(exact_igmp.type == detail::kIgmpTypeMembershipQuery);
    PFL_EXPECT(exact_igmp.code == 0x7FU);
    PFL_EXPECT(exact_igmp.checksum == 0x1234U);
    PFL_EXPECT(exact_igmp.group_or_control == 0xE0000001U);
    PFL_EXPECT(exact_igmp.header_length == detail::kIgmpMinimumHeaderSize);
    PFL_EXPECT(exact_igmp.captured_payload_length == 0U);

    const auto exact_igmp_step = dissect_igmp(exact_igmp_root);
    PFL_EXPECT(exact_igmp_step.layer == DissectionLayerKind::igmp);
    PFL_EXPECT(!exact_igmp_step.path_contribution.has_value());
    PFL_EXPECT(exact_igmp_step.terminal_disposition == TerminalDisposition::flow_candidate);
    PFL_REQUIRE(exact_igmp_step.bounds.payload.has_value());
    PFL_EXPECT(exact_igmp_step.bounds.full.declared.length() == detail::kIgmpMinimumHeaderSize);
    PFL_EXPECT(exact_igmp_step.bounds.full.captured.length() == detail::kIgmpMinimumHeaderSize);
    PFL_EXPECT(exact_igmp_step.bounds.header.declared.length() == detail::kIgmpMinimumHeaderSize);
    PFL_EXPECT(exact_igmp_step.bounds.header.captured.length() == detail::kIgmpMinimumHeaderSize);
    PFL_EXPECT(exact_igmp_step.bounds.payload->declared.length() == 0U);
    PFL_EXPECT(exact_igmp_step.bounds.payload->captured.length() == 0U);
    PFL_EXPECT(std::holds_alternative<IgmpFacts>(exact_igmp_step.facts));
    const auto* exact_igmp_facts = std::get_if<IgmpFacts>(&exact_igmp_step.facts);
    PFL_REQUIRE(exact_igmp_facts != nullptr);
    PFL_EXPECT(exact_igmp_facts->type == detail::kIgmpTypeMembershipQuery);
    PFL_EXPECT(exact_igmp_facts->code == 0x7FU);
    PFL_EXPECT(exact_igmp_facts->checksum == 0x1234U);
    PFL_EXPECT(exact_igmp_facts->group_or_control == 0xE0000001U);
    PFL_EXPECT(exact_igmp_facts->has_effective_destination_v4);
    PFL_EXPECT(exact_igmp_facts->effective_destination_v4 == 0xE0000001U);

    struct IgmpTypeCase {
        std::uint8_t type {0U};
        std::uint8_t code {0U};
        std::uint16_t checksum {0U};
        std::uint32_t group_or_control {0U};
        bool expected_has_effective_destination {false};
        std::uint32_t expected_effective_destination {0U};
    };

    const std::array igmp_type_cases {
        IgmpTypeCase {
            .type = detail::kIgmpTypeMembershipQuery,
            .code = 0x7EU,
            .checksum = 0x1111U,
            .group_or_control = 0xE00000FBU,
            .expected_has_effective_destination = true,
            .expected_effective_destination = 0xE00000FBU,
        },
        IgmpTypeCase {
            .type = detail::kIgmpTypeMembershipQuery,
            .code = 0x70U,
            .checksum = 0x1717U,
            .group_or_control = 0x00000000U,
        },
        IgmpTypeCase {
            .type = detail::kIgmpTypeV1MembershipReport,
            .code = 0x01U,
            .checksum = 0x2222U,
            .group_or_control = 0xE0000016U,
            .expected_has_effective_destination = true,
            .expected_effective_destination = 0xE0000016U,
        },
        IgmpTypeCase {
            .type = detail::kIgmpTypeV2MembershipReport,
            .code = 0x02U,
            .checksum = 0x3333U,
            .group_or_control = 0xE0000017U,
            .expected_has_effective_destination = true,
            .expected_effective_destination = 0xE0000017U,
        },
        IgmpTypeCase {
            .type = detail::kIgmpTypeLeaveGroup,
            .code = 0x03U,
            .checksum = 0x4444U,
            .group_or_control = 0xEFFFFFFAU,
            .expected_has_effective_destination = true,
            .expected_effective_destination = 0xEFFFFFFAU,
        },
        IgmpTypeCase {
            .type = detail::kIgmpTypeV3MembershipReport,
            .code = 0x04U,
            .checksum = 0x5555U,
            .group_or_control = 0xA1B2C3D4U,
        },
        IgmpTypeCase {
            .type = 0x99U,
            .code = 0x05U,
            .checksum = 0x6666U,
            .group_or_control = 0x01020304U,
            .expected_has_effective_destination = true,
            .expected_effective_destination = 0x01020304U,
        },
    };

    for (const auto& test_case : igmp_type_cases) {
        const auto parsed = parse_igmp_common_header(make_root_slice(make_raw_packet(make_igmp_message(
            test_case.type,
            test_case.code,
            test_case.checksum,
            test_case.group_or_control
        ))));
        PFL_EXPECT(parsed.status == ParseStatus::complete);
        PFL_EXPECT(parsed.type == test_case.type);
        PFL_EXPECT(parsed.code == test_case.code);
        PFL_EXPECT(parsed.checksum == test_case.checksum);
        PFL_EXPECT(parsed.group_or_control == test_case.group_or_control);
        PFL_EXPECT(parsed.has_effective_destination_v4 == test_case.expected_has_effective_destination);
        PFL_EXPECT(parsed.effective_destination_v4 == test_case.expected_effective_destination);
    }

    const auto body_igmp_packet = make_raw_packet(make_igmp_message(
        detail::kIgmpTypeV2MembershipReport,
        0x11U,
        0xABCDU,
        0xE00000FBU,
        {0x01U, 0x02U, 0x03U, 0x04U}
    ));
    const auto body_igmp = parse_igmp_common_header(make_root_slice(body_igmp_packet));
    PFL_EXPECT(body_igmp.status == ParseStatus::complete);
    PFL_EXPECT(body_igmp.captured_payload_length == 4U);

    const auto truncated_body_igmp_packet = make_raw_packet(
        make_igmp_message(
            detail::kIgmpTypeV3MembershipReport,
            0x22U,
            0xBEEFU,
            0x00112233U,
            {0x10U, 0x20U, 0x30U, 0x40U}
        ),
        12U
    );
    const auto truncated_body_igmp_step = dissect_igmp(make_root_slice(truncated_body_igmp_packet));
    PFL_EXPECT(truncated_body_igmp_step.status == ParseStatus::complete);
    PFL_REQUIRE(truncated_body_igmp_step.bounds.payload.has_value());
    PFL_EXPECT(truncated_body_igmp_step.bounds.payload->declared.length() == 4U);
    PFL_EXPECT(truncated_body_igmp_step.bounds.payload->captured.length() == 4U);

    const auto capture_truncated_body_igmp_packet = make_raw_packet(
        std::vector<std::uint8_t> {0x22U, 0x33U, 0x44U, 0x55U, 0x66U, 0x77U, 0x88U, 0x99U, 0xAAU, 0xBBU},
        12U
    );
    const auto capture_truncated_body_igmp_step = dissect_igmp(make_root_slice(capture_truncated_body_igmp_packet));
    PFL_EXPECT(capture_truncated_body_igmp_step.status == ParseStatus::complete);
    PFL_REQUIRE(capture_truncated_body_igmp_step.bounds.payload.has_value());
    PFL_EXPECT(capture_truncated_body_igmp_step.bounds.payload->declared.length() == 4U);
    PFL_EXPECT(capture_truncated_body_igmp_step.bounds.payload->captured.length() == 2U);

    const auto extra_tail_igmp_packet = make_raw_packet(
        std::vector<std::uint8_t> {0x16U, 0x40U, 0xABU, 0xCDU, 0xE0U, 0x00U, 0x00U, 0xFBU, 0xDEU, 0xADU},
        8U
    );
    const auto extra_tail_igmp_step = dissect_igmp(make_root_slice(extra_tail_igmp_packet));
    PFL_EXPECT(extra_tail_igmp_step.status == ParseStatus::complete);
    PFL_REQUIRE(extra_tail_igmp_step.bounds.payload.has_value());
    PFL_EXPECT(extra_tail_igmp_step.bounds.full.declared.length() == 8U);
    PFL_EXPECT(extra_tail_igmp_step.bounds.full.captured.length() == 8U);
    PFL_EXPECT(extra_tail_igmp_step.bounds.payload->declared.length() == 0U);
    PFL_EXPECT(extra_tail_igmp_step.bounds.payload->captured.length() == 0U);

    const auto truncated_igmp_packet = make_raw_packet(
        std::vector<std::uint8_t> {0x11U, 0x7FU, 0x12U, 0x34U, 0xE0U, 0x00U, 0x00U},
        8U
    );
    const auto truncated_igmp_root = make_root_slice(truncated_igmp_packet);
    const auto truncated_igmp = parse_igmp_common_header(truncated_igmp_root);
    PFL_EXPECT(truncated_igmp.status == ParseStatus::truncated);
    const auto truncated_igmp_step = dissect_igmp(truncated_igmp_root);
    PFL_EXPECT(truncated_igmp_step.status == ParseStatus::truncated);
    PFL_EXPECT(!truncated_igmp_step.path_contribution.has_value());
    PFL_EXPECT(truncated_igmp_step.terminal_disposition == TerminalDisposition::none);

    const auto impossible_igmp_packet = make_raw_packet(
        std::vector<std::uint8_t> {0x11U, 0x7FU, 0x12U, 0x34U, 0xE0U, 0x00U, 0x00U},
        7U
    );
    const auto impossible_igmp_step = dissect_igmp(make_root_slice(impossible_igmp_packet));
    PFL_EXPECT(impossible_igmp_step.status == ParseStatus::malformed);
    PFL_EXPECT(!impossible_igmp_step.path_contribution.has_value());
    PFL_EXPECT(impossible_igmp_step.bounds.full.declared.length() == 7U);
    PFL_EXPECT(impossible_igmp_step.bounds.full.captured.length() == 7U);
    PFL_EXPECT(impossible_igmp_step.bounds.header.declared.length() == 7U);
    PFL_EXPECT(impossible_igmp_step.bounds.header.captured.length() == 7U);
}

void expect_fragmented_ipv4_preserves_selector_only_handoff() {
    const auto built = make_common_direct_registry();
    PFL_REQUIRE(built.ok());
    const auto& registry = *built.registry;

    const auto first_fragment_packet = make_raw_packet(make_ethernet_ipv4_fragment_packet(
        ipv4(10, 0, 3, 1), ipv4(10, 0, 3, 2), 6U, 0x2000U, {0x16, 0x03, 0x03, 0x00, 0x10}));
    const auto first_fragment_root = make_root_slice(first_fragment_packet);
    const auto first_fragment_ethernet = dissect_ethernet(first_fragment_root);
    PFL_REQUIRE(first_fragment_ethernet.handoff.has_value());
    PFL_REQUIRE(first_fragment_ethernet.handoff->child.has_value());

    const auto first_fragment_ipv4 = dissect_ipv4(*first_fragment_ethernet.handoff->child);
    PFL_EXPECT(first_fragment_ipv4.status == ParseStatus::complete);
    PFL_EXPECT(first_fragment_ipv4.stop_reason == StopReason::needs_reassembly);
    PFL_REQUIRE(first_fragment_ipv4.path_contribution.has_value());
    PFL_EXPECT(*first_fragment_ipv4.path_contribution == LayerKey::ipv4());
    PFL_REQUIRE(first_fragment_ipv4.handoff.has_value());
    const ProtocolSelector expected_fragment_selector {
        .domain = SelectorDomain::ip_protocol,
        .value = 6U,
    };
    PFL_EXPECT(first_fragment_ipv4.handoff->selector == expected_fragment_selector);
    PFL_EXPECT(!first_fragment_ipv4.handoff->child.has_value());

    StepKindRecorder recorder {};
    const DissectionEngine engine {};
    const auto engine_result = engine.run(
        registry,
        make_link_type_selector(first_fragment_packet.data_link_type),
        first_fragment_root,
        DissectionConsumer {.on_step = record_step_kind, .context = &recorder}
    );
    PFL_EXPECT(engine_result.stop_reason == StopReason::needs_reassembly);
    PFL_EXPECT(engine_result.step_count == 2U);
    PFL_EXPECT(engine_result.traversed_depth == 2U);
    const std::vector<DissectionLayerKind> expected_kinds {
        DissectionLayerKind::ethernet_ii,
        DissectionLayerKind::ipv4,
    };
    PFL_EXPECT(recorder.kinds == expected_kinds);
}

void expect_sctp_fragmentation_preserves_selector_only_handoff() {
    const auto built = make_common_direct_registry();
    PFL_REQUIRE(built.ok());
    const auto& registry = *built.registry;

    const auto ipv4_fragment_packet = make_raw_packet(make_ethernet_ipv4_fragment_packet(
        ipv4(10, 44, 0, 1),
        ipv4(10, 44, 0, 2),
        detail::kIpProtocolSctp,
        0x2000U,
        {0xde, 0xad, 0xbe, 0xef}
    ));
    const auto ipv4_fragment_root = make_root_slice(ipv4_fragment_packet);
    const auto ipv4_fragment_ethernet = dissect_ethernet(ipv4_fragment_root);
    PFL_REQUIRE(ipv4_fragment_ethernet.handoff.has_value());
    PFL_REQUIRE(ipv4_fragment_ethernet.handoff->child.has_value());
    const auto ipv4_fragment_step = dissect_ipv4(*ipv4_fragment_ethernet.handoff->child);
    PFL_EXPECT(ipv4_fragment_step.status == ParseStatus::complete);
    PFL_EXPECT(ipv4_fragment_step.stop_reason == StopReason::needs_reassembly);
    PFL_REQUIRE(ipv4_fragment_step.handoff.has_value());
    PFL_EXPECT(ipv4_fragment_step.handoff->selector.domain == SelectorDomain::ip_protocol);
    PFL_EXPECT(ipv4_fragment_step.handoff->selector.value == detail::kIpProtocolSctp);
    PFL_EXPECT(!ipv4_fragment_step.handoff->child.has_value());

    const auto ipv4_fragment_shadow = run_shadow(ipv4_fragment_packet, registry);
    PFL_EXPECT(ipv4_fragment_shadow.outcome == ImportDissectionOutcome::recognized_flow);
    PFL_EXPECT(ipv4_fragment_shadow.stop_reason == StopReason::needs_reassembly);
    PFL_EXPECT(ipv4_fragment_shadow.terminal_protocol == ProtocolId::sctp);
    PFL_EXPECT(!ipv4_fragment_shadow.has_ports);
    PFL_EXPECT(format_shadow_path(ipv4_fragment_shadow) == "EthernetII -> IPv4");

    const auto src_addr = ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x51});
    const auto dst_addr = ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x52});
    const auto ipv6_fragment_packet = make_raw_packet(make_ethernet_ipv6_fragment_packet(
        src_addr,
        dst_addr,
        detail::kIpProtocolSctp,
        {0xca, 0xfe, 0xba, 0xbe}
    ));
    const auto ipv6_fragment_root = make_root_slice(ipv6_fragment_packet);
    const auto ipv6_fragment_ethernet = dissect_ethernet(ipv6_fragment_root);
    PFL_REQUIRE(ipv6_fragment_ethernet.handoff.has_value());
    PFL_REQUIRE(ipv6_fragment_ethernet.handoff->child.has_value());
    const auto ipv6_step = dissect_ipv6(*ipv6_fragment_ethernet.handoff->child);
    PFL_REQUIRE(ipv6_step.handoff.has_value());
    PFL_REQUIRE(ipv6_step.handoff->child.has_value());
    const auto fragment_step = dissect_ipv6_fragment(*ipv6_step.handoff->child);
    PFL_EXPECT(fragment_step.status == ParseStatus::complete);
    PFL_EXPECT(fragment_step.stop_reason == StopReason::needs_reassembly);
    PFL_REQUIRE(fragment_step.handoff.has_value());
    PFL_EXPECT(fragment_step.handoff->selector.domain == SelectorDomain::ipv6_next_header);
    PFL_EXPECT(fragment_step.handoff->selector.value == detail::kIpProtocolSctp);
    PFL_EXPECT(!fragment_step.handoff->child.has_value());

    const auto ipv6_fragment_shadow = run_shadow(ipv6_fragment_packet, registry);
    PFL_EXPECT(ipv6_fragment_shadow.outcome == ImportDissectionOutcome::recognized_flow);
    PFL_EXPECT(ipv6_fragment_shadow.stop_reason == StopReason::needs_reassembly);
    PFL_EXPECT(ipv6_fragment_shadow.terminal_protocol == ProtocolId::sctp);
    PFL_EXPECT(!ipv6_fragment_shadow.has_ports);
    PFL_EXPECT(format_shadow_path(ipv6_fragment_shadow) == "EthernetII -> IPv6");
}

void expect_icmp_fragmentation_preserves_selector_only_handoff() {
    const auto built = make_common_direct_registry();
    PFL_REQUIRE(built.ok());
    const auto& registry = *built.registry;

    const auto ipv4_fragment_packet = make_raw_packet(make_ethernet_ipv4_fragment_packet(
        ipv4(10, 45, 0, 1),
        ipv4(10, 45, 0, 2),
        detail::kIpProtocolIcmp,
        0x2000U,
        {8U, 0U, 0U, 0U}
    ));
    const auto ipv4_fragment_root = make_root_slice(ipv4_fragment_packet);
    const auto ipv4_fragment_ethernet = dissect_ethernet(ipv4_fragment_root);
    PFL_REQUIRE(ipv4_fragment_ethernet.handoff.has_value());
    PFL_REQUIRE(ipv4_fragment_ethernet.handoff->child.has_value());
    const auto ipv4_fragment_step = dissect_ipv4(*ipv4_fragment_ethernet.handoff->child);
    PFL_EXPECT(ipv4_fragment_step.status == ParseStatus::complete);
    PFL_EXPECT(ipv4_fragment_step.stop_reason == StopReason::needs_reassembly);
    PFL_REQUIRE(ipv4_fragment_step.handoff.has_value());
    PFL_EXPECT(ipv4_fragment_step.handoff->selector.domain == SelectorDomain::ip_protocol);
    PFL_EXPECT(ipv4_fragment_step.handoff->selector.value == detail::kIpProtocolIcmp);
    PFL_EXPECT(!ipv4_fragment_step.handoff->child.has_value());

    const auto ipv4_fragment_shadow = run_shadow(ipv4_fragment_packet, registry);
    PFL_EXPECT(ipv4_fragment_shadow.outcome == ImportDissectionOutcome::recognized_flow);
    PFL_EXPECT(ipv4_fragment_shadow.stop_reason == StopReason::needs_reassembly);
    PFL_EXPECT(ipv4_fragment_shadow.terminal_protocol == ProtocolId::icmp);
    PFL_EXPECT(!ipv4_fragment_shadow.has_ports);
    PFL_EXPECT(format_shadow_path(ipv4_fragment_shadow) == "EthernetII -> IPv4");

    const auto src_addr = ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x61});
    const auto dst_addr = ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x62});
    const auto ipv6_fragment_packet = make_raw_packet(make_ethernet_ipv6_fragment_packet(
        src_addr,
        dst_addr,
        detail::kIpProtocolIcmpV6,
        {128U, 0U, 0U, 0U}
    ));
    const auto ipv6_fragment_root = make_root_slice(ipv6_fragment_packet);
    const auto ipv6_fragment_ethernet = dissect_ethernet(ipv6_fragment_root);
    PFL_REQUIRE(ipv6_fragment_ethernet.handoff.has_value());
    PFL_REQUIRE(ipv6_fragment_ethernet.handoff->child.has_value());
    const auto ipv6_step = dissect_ipv6(*ipv6_fragment_ethernet.handoff->child);
    PFL_REQUIRE(ipv6_step.handoff.has_value());
    PFL_REQUIRE(ipv6_step.handoff->child.has_value());
    const auto fragment_step = dissect_ipv6_fragment(*ipv6_step.handoff->child);
    PFL_EXPECT(fragment_step.status == ParseStatus::complete);
    PFL_EXPECT(fragment_step.stop_reason == StopReason::needs_reassembly);
    PFL_REQUIRE(fragment_step.handoff.has_value());
    PFL_EXPECT(fragment_step.handoff->selector.domain == SelectorDomain::ipv6_next_header);
    PFL_EXPECT(fragment_step.handoff->selector.value == detail::kIpProtocolIcmpV6);
    PFL_EXPECT(!fragment_step.handoff->child.has_value());

    const auto ipv6_fragment_shadow = run_shadow(ipv6_fragment_packet, registry);
    PFL_EXPECT(ipv6_fragment_shadow.outcome == ImportDissectionOutcome::recognized_flow);
    PFL_EXPECT(ipv6_fragment_shadow.stop_reason == StopReason::needs_reassembly);
    PFL_EXPECT(ipv6_fragment_shadow.terminal_protocol == ProtocolId::icmpv6);
    PFL_EXPECT(!ipv6_fragment_shadow.has_ports);
    PFL_EXPECT(format_shadow_path(ipv6_fragment_shadow) == "EthernetII -> IPv6");
}

void expect_igmp_fragmentation_preserves_selector_only_handoff() {
    const auto built = make_common_direct_registry();
    PFL_REQUIRE(built.ok());
    const auto& registry = *built.registry;

    const auto ipv4_fragment_packet = make_raw_packet(make_ethernet_ipv4_fragment_packet(
        ipv4(10, 46, 0, 1),
        ipv4(224, 0, 0, 1),
        detail::kIpProtocolIgmp,
        0x2000U,
        {detail::kIgmpTypeMembershipQuery, 0x00U, 0x00U, 0x00U, 0xE0U, 0x00U, 0x00U, 0x01U}
    ));
    const auto ipv4_fragment_root = make_root_slice(ipv4_fragment_packet);
    const auto ipv4_fragment_ethernet = dissect_ethernet(ipv4_fragment_root);
    PFL_REQUIRE(ipv4_fragment_ethernet.handoff.has_value());
    PFL_REQUIRE(ipv4_fragment_ethernet.handoff->child.has_value());
    const auto ipv4_fragment_step = dissect_ipv4(*ipv4_fragment_ethernet.handoff->child);
    PFL_EXPECT(ipv4_fragment_step.status == ParseStatus::complete);
    PFL_EXPECT(ipv4_fragment_step.stop_reason == StopReason::needs_reassembly);
    PFL_REQUIRE(ipv4_fragment_step.handoff.has_value());
    PFL_EXPECT(ipv4_fragment_step.handoff->selector.domain == SelectorDomain::ip_protocol);
    PFL_EXPECT(ipv4_fragment_step.handoff->selector.value == detail::kIpProtocolIgmp);
    PFL_EXPECT(!ipv4_fragment_step.handoff->child.has_value());

    StepKindRecorder recorder {};
    const DissectionEngine engine {};
    const auto engine_result = engine.run(
        registry,
        make_link_type_selector(ipv4_fragment_packet.data_link_type),
        ipv4_fragment_root,
        DissectionConsumer {.on_step = record_step_kind, .context = &recorder}
    );
    PFL_EXPECT(engine_result.stop_reason == StopReason::needs_reassembly);
    const std::vector<DissectionLayerKind> expected_kinds {
        DissectionLayerKind::ethernet_ii,
        DissectionLayerKind::ipv4,
    };
    PFL_EXPECT(recorder.kinds == expected_kinds);

    expect_shadow_matches_legacy_igmp_flow(
        registry,
        ipv4_fragment_packet,
        "EthernetII -> IPv4",
        "EthernetII -> IPv4",
        StopReason::needs_reassembly,
        ipv4(10, 46, 0, 1),
        ipv4(224, 0, 0, 1)
    );
}

void expect_igmp_shadow_only_flow_behavior() {
    const auto built = make_common_direct_registry();
    PFL_REQUIRE(built.ok());
    const auto& registry = *built.registry;

    const auto direct_packet = make_raw_packet(make_ethernet_ipv4_igmp_packet(
        ipv4(192, 0, 2, 10),
        ipv4(224, 0, 0, 1),
        detail::kIgmpTypeMembershipQuery,
        0x10U,
        0x1111U,
        0x00000000U,
        {0xDEU, 0xADU}
    ));
    StepKindRecorder direct_recorder {};
    const DissectionEngine engine {};
    const auto direct_result = engine.run(
        registry,
        make_link_type_selector(direct_packet.data_link_type),
        make_root_slice(direct_packet),
        DissectionConsumer {.on_step = record_step_kind, .context = &direct_recorder}
    );
    PFL_EXPECT(direct_result.stop_reason == StopReason::terminal_protocol);
    const std::vector<DissectionLayerKind> expected_direct_kinds {
        DissectionLayerKind::ethernet_ii,
        DissectionLayerKind::ipv4,
        DissectionLayerKind::igmp,
    };
    PFL_EXPECT(direct_recorder.kinds == expected_direct_kinds);
    expect_shadow_matches_legacy_igmp_flow(
        registry,
        direct_packet,
        "EthernetII -> IPv4",
        "EthernetII -> IPv4",
        StopReason::terminal_protocol,
        ipv4(192, 0, 2, 10),
        ipv4(224, 0, 0, 1)
    );

    const auto group_specific_query_packet = make_raw_packet(make_ethernet_ipv4_igmp_packet(
        ipv4(192, 0, 2, 13),
        ipv4(224, 0, 0, 1),
        detail::kIgmpTypeMembershipQuery,
        0x19U,
        0x1919U,
        0xEF090909U
    ));
    expect_shadow_matches_legacy_igmp_flow(
        registry,
        group_specific_query_packet,
        "EthernetII -> IPv4",
        "EthernetII -> IPv4",
        StopReason::terminal_protocol,
        ipv4(192, 0, 2, 13),
        ipv4(239, 9, 9, 9)
    );

    const auto v1_report_packet = make_raw_packet(make_ethernet_ipv4_igmp_packet(
        ipv4(192, 0, 2, 14),
        ipv4(224, 0, 0, 22),
        detail::kIgmpTypeV1MembershipReport,
        0x21U,
        0x2121U,
        0xEF010101U
    ));
    expect_shadow_matches_legacy_igmp_flow(
        registry,
        v1_report_packet,
        "EthernetII -> IPv4",
        "EthernetII -> IPv4",
        StopReason::terminal_protocol,
        ipv4(192, 0, 2, 14),
        ipv4(239, 1, 1, 1)
    );

    const auto vlan_packet = make_raw_packet(add_vlan_tags(
        make_ethernet_ipv4_igmp_packet(
            ipv4(192, 0, 2, 11),
            ipv4(224, 0, 0, 22),
            detail::kIgmpTypeV2MembershipReport,
            0x22U,
            0x2222U,
            0xEF010203U
        ),
        {{0x8100U, 405U}}
    ));
    expect_shadow_matches_legacy_igmp_flow(
        registry,
        vlan_packet,
        "EthernetII -> VLAN(vid=405) -> IPv4",
        "EthernetII -> VLAN(vid=405) -> IPv4",
        StopReason::terminal_protocol,
        ipv4(192, 0, 2, 11),
        ipv4(239, 1, 2, 3)
    );

    const auto nested_ipv4_packet = make_raw_packet(make_ethernet_ipv4_fragment_packet(
        ipv4(198, 18, 0, 1),
        ipv4(198, 18, 0, 2),
        detail::kIpProtocolIpv4Encapsulation,
        0U,
        make_ipv4_payload_packet(
            ipv4(10, 50, 0, 1),
            ipv4(224, 0, 0, 1),
            detail::kIpProtocolIgmp,
            make_igmp_message(detail::kIgmpTypeV2MembershipReport, 0x33U, 0x3333U, 0xE0000016U)
        )
    ));
    expect_shadow_only_nested_igmp_flow(
        registry,
        nested_ipv4_packet,
        "EthernetII -> IPv4 -> IPv4",
        StopReason::terminal_protocol,
        ipv4(10, 50, 0, 1),
        ipv4(224, 0, 0, 22)
    );

    const auto nested_ipv6_packet = make_raw_packet(make_ethernet_ipv6_packet(
        ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 20, 0, 0, 0, 0, 0, 0, 0, 1}),
        ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 20, 0, 0, 0, 0, 0, 0, 0, 2}),
        detail::kIpProtocolIpv4Encapsulation,
        make_ipv4_payload_packet(
            ipv4(10, 60, 0, 1),
            ipv4(224, 0, 0, 2),
            detail::kIpProtocolIgmp,
            make_igmp_message(detail::kIgmpTypeLeaveGroup, 0x44U, 0x4444U, 0xEF0A0A0AU)
        )
    ));
    expect_shadow_only_nested_igmp_flow(
        registry,
        nested_ipv6_packet,
        "EthernetII -> IPv6 -> IPv4",
        StopReason::terminal_protocol,
        ipv4(10, 60, 0, 1),
        ipv4(239, 10, 10, 10)
    );

    const auto nested_ipv4_ipv6_ipv4_packet = make_raw_packet(make_ethernet_ipv4_fragment_packet(
        ipv4(198, 18, 0, 3),
        ipv4(198, 18, 0, 4),
        detail::kIpProtocolIpv6Encapsulation,
        0U,
        make_ipv6_payload_packet(
            ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 21, 0, 0, 0, 0, 0, 0, 0, 1}),
            ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 21, 0, 0, 0, 0, 0, 0, 0, 2}),
            detail::kIpProtocolIpv4Encapsulation,
            make_ipv4_payload_packet(
                ipv4(10, 70, 0, 1),
                ipv4(239, 20, 20, 20),
                detail::kIpProtocolIgmp,
                make_igmp_message(detail::kIgmpTypeV3MembershipReport, 0x55U, 0x5555U, 0x01020304U)
            )
        )
    ));
    expect_shadow_only_nested_igmp_flow(
        registry,
        nested_ipv4_ipv6_ipv4_packet,
        "EthernetII -> IPv4 -> IPv6 -> IPv4",
        StopReason::terminal_protocol,
        ipv4(10, 70, 0, 1),
        ipv4(239, 20, 20, 20)
    );

    const auto outer_ipv6_hbh_inner_ipv4_packet = make_raw_packet(make_ethernet_ipv6_packet(
        ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 22, 0, 0, 0, 0, 0, 0, 0, 1}),
        ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 22, 0, 0, 0, 0, 0, 0, 0, 2}),
        detail::kIpProtocolHopByHop,
        make_ipv6_hop_by_hop_extension(
            detail::kIpProtocolIpv4Encapsulation,
            make_ipv4_payload_packet(
                ipv4(10, 80, 0, 1),
                ipv4(239, 30, 30, 30),
                detail::kIpProtocolIgmp,
                make_igmp_message(detail::kIgmpTypeMembershipQuery, 0x66U, 0x6666U, 0x00000000U)
            )
        )
    ));
    StepKindRecorder outer_ipv6_hbh_inner_ipv4_recorder {};
    const auto outer_ipv6_hbh_inner_ipv4_result = engine.run(
        registry,
        make_link_type_selector(outer_ipv6_hbh_inner_ipv4_packet.data_link_type),
        make_root_slice(outer_ipv6_hbh_inner_ipv4_packet),
        DissectionConsumer {.on_step = record_step_kind, .context = &outer_ipv6_hbh_inner_ipv4_recorder}
    );
    PFL_EXPECT(outer_ipv6_hbh_inner_ipv4_result.stop_reason == StopReason::terminal_protocol);
    const std::vector<DissectionLayerKind> expected_outer_ipv6_hbh_inner_ipv4_kinds {
        DissectionLayerKind::ethernet_ii,
        DissectionLayerKind::ipv6,
        DissectionLayerKind::ipv6_hop_by_hop,
        DissectionLayerKind::ipv4,
        DissectionLayerKind::igmp,
    };
    PFL_EXPECT(outer_ipv6_hbh_inner_ipv4_recorder.kinds == expected_outer_ipv6_hbh_inner_ipv4_kinds);
    expect_shadow_only_nested_igmp_flow(
        registry,
        outer_ipv6_hbh_inner_ipv4_packet,
        "EthernetII -> IPv6 -> IPv4",
        StopReason::terminal_protocol,
        ipv4(10, 80, 0, 1),
        ipv4(239, 30, 30, 30)
    );

    const auto unknown_type_packet = make_raw_packet(make_ethernet_ipv4_igmp_packet(
        ipv4(192, 0, 2, 12),
        ipv4(224, 0, 0, 250),
        0x99U,
        0x77U,
        0x9999U,
        0xEF010204U
    ));
    expect_shadow_matches_legacy_igmp_flow(
        registry,
        unknown_type_packet,
        "EthernetII -> IPv4",
        "EthernetII -> IPv4",
        StopReason::terminal_protocol,
        ipv4(192, 0, 2, 12),
        ipv4(239, 1, 2, 4)
    );

    const auto direct_ipv6_igmp_shadow = run_shadow(
        make_raw_packet(make_ethernet_ipv6_packet(
            ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 23, 0, 0, 0, 0, 0, 0, 0, 1}),
            ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 23, 0, 0, 0, 0, 0, 0, 0, 2}),
            detail::kIpProtocolIgmp,
            make_igmp_message(detail::kIgmpTypeMembershipQuery, 0x77U, 0x7777U, 0x00000000U)
        )),
        registry
    );
    PFL_EXPECT(direct_ipv6_igmp_shadow.outcome == ImportDissectionOutcome::unrecognized);
    PFL_EXPECT(direct_ipv6_igmp_shadow.stop_reason == StopReason::unknown_next_protocol);
    PFL_EXPECT(direct_ipv6_igmp_shadow.terminal_protocol == ProtocolId::unknown);
    PFL_EXPECT(format_shadow_path(direct_ipv6_igmp_shadow) == "EthernetII -> IPv6");
}

void expect_igmp_failures_remain_visible_without_path_contribution() {
    const auto built = make_common_direct_registry();
    PFL_REQUIRE(built.ok());
    const auto& registry = *built.registry;

    const auto truncated_igmp_packet = make_raw_packet(
        []() {
            auto packet = make_ethernet_ipv4_igmp_packet(
                ipv4(10, 90, 0, 1),
                ipv4(224, 0, 0, 1),
                detail::kIgmpTypeMembershipQuery,
                0x10U,
                0x1111U,
                0x00000000U
            );
            packet.resize(packet.size() - 1U);
            return packet;
        }(),
        14U + 20U + detail::kIgmpMinimumHeaderSize
    );
    StepKindRecorder truncated_recorder {};
    const DissectionEngine engine {};
    const auto truncated_result = engine.run(
        registry,
        make_link_type_selector(truncated_igmp_packet.data_link_type),
        make_root_slice(truncated_igmp_packet),
        DissectionConsumer {.on_step = record_step_kind, .context = &truncated_recorder}
    );
    PFL_EXPECT(truncated_result.stop_reason == StopReason::truncated);
    const std::vector<DissectionLayerKind> expected_truncated_kinds {
        DissectionLayerKind::ethernet_ii,
        DissectionLayerKind::ipv4,
        DissectionLayerKind::igmp,
    };
    PFL_EXPECT(truncated_recorder.kinds == expected_truncated_kinds);
    const auto truncated_shadow = run_shadow(truncated_igmp_packet, registry);
    PFL_EXPECT(truncated_shadow.outcome == ImportDissectionOutcome::unrecognized);
    PFL_EXPECT(truncated_shadow.stop_reason == StopReason::truncated);
    PFL_EXPECT(truncated_shadow.terminal_protocol == ProtocolId::igmp);
    PFL_EXPECT(format_shadow_path(truncated_shadow) == "EthernetII -> IPv4");

    const auto malformed_igmp_packet = make_raw_packet(make_ethernet_ipv4_fragment_packet(
        ipv4(10, 91, 0, 1),
        ipv4(224, 0, 0, 2),
        detail::kIpProtocolIgmp,
        0U,
        {detail::kIgmpTypeV2MembershipReport, 0x20U, 0x12U, 0x34U, 0xE0U, 0x00U, 0x00U}
    ));
    StepKindRecorder malformed_recorder {};
    const auto malformed_result = engine.run(
        registry,
        make_link_type_selector(malformed_igmp_packet.data_link_type),
        make_root_slice(malformed_igmp_packet),
        DissectionConsumer {.on_step = record_step_kind, .context = &malformed_recorder}
    );
    PFL_EXPECT(malformed_result.stop_reason == StopReason::malformed);
    const std::vector<DissectionLayerKind> expected_malformed_kinds {
        DissectionLayerKind::ethernet_ii,
        DissectionLayerKind::ipv4,
        DissectionLayerKind::igmp,
    };
    PFL_EXPECT(malformed_recorder.kinds == expected_malformed_kinds);
    const auto malformed_shadow = run_shadow(malformed_igmp_packet, registry);
    PFL_EXPECT(malformed_shadow.outcome == ImportDissectionOutcome::unrecognized);
    PFL_EXPECT(malformed_shadow.stop_reason == StopReason::malformed);
    PFL_EXPECT(malformed_shadow.terminal_protocol == ProtocolId::igmp);
    PFL_EXPECT(format_shadow_path(malformed_shadow) == "EthernetII -> IPv4");
}

void expect_plain_ip_encapsulation_is_registry_driven() {
    const auto built = make_common_direct_registry();
    PFL_REQUIRE(built.ok());
    const auto& registry = *built.registry;
    const auto outer_ipv6_src = ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0x11});
    const auto outer_ipv6_dst = ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0x22});
    const auto inner_ipv6_src = ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0x33});
    const auto inner_ipv6_dst = ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0x44});

    const auto deepest_udp_inner_ipv4 = make_ipv4_payload_packet(
        ipv4(198, 51, 100, 10),
        ipv4(198, 51, 100, 11),
        detail::kIpProtocolUdp,
        make_ipv6_udp_segment(41000U, 53U, 3U)
    );
    const auto middle_ipv6_with_inner_ipv4 = make_ipv6_payload_packet(
        inner_ipv6_src,
        inner_ipv6_dst,
        detail::kIpProtocolIpv4Encapsulation,
        deepest_udp_inner_ipv4
    );
    const auto multi_nested_packet = make_raw_packet(make_ethernet_ipv4_fragment_packet(
        ipv4(203, 0, 113, 1),
        ipv4(203, 0, 113, 2),
        detail::kIpProtocolIpv6Encapsulation,
        0U,
        middle_ipv6_with_inner_ipv4
    ));
    const auto multi_nested_root = make_root_slice(multi_nested_packet);
    const auto multi_nested_ethernet = dissect_ethernet(multi_nested_root);
    PFL_REQUIRE(multi_nested_ethernet.handoff.has_value());
    PFL_REQUIRE(multi_nested_ethernet.handoff->child.has_value());
    PFL_EXPECT(multi_nested_ethernet.handoff->child->source_id() == multi_nested_root.source_id());
    PFL_EXPECT(multi_nested_ethernet.handoff->child->source_offset() == 14U);

    const auto multi_nested_outer_ipv4 = dissect_ipv4(*multi_nested_ethernet.handoff->child);
    PFL_REQUIRE(multi_nested_outer_ipv4.handoff.has_value());
    PFL_REQUIRE(multi_nested_outer_ipv4.handoff->child.has_value());
    PFL_EXPECT(multi_nested_outer_ipv4.handoff->selector.domain == SelectorDomain::ip_protocol);
    PFL_EXPECT(multi_nested_outer_ipv4.handoff->selector.value == detail::kIpProtocolIpv6Encapsulation);
    PFL_EXPECT(multi_nested_outer_ipv4.handoff->child->source_id() == multi_nested_root.source_id());
    PFL_EXPECT(multi_nested_outer_ipv4.handoff->child->source_offset() == 34U);
    PFL_EXPECT(multi_nested_outer_ipv4.handoff->child->captured_end() == multi_nested_outer_ipv4.handoff->child->declared_end());
    PFL_EXPECT(multi_nested_outer_ipv4.handoff->child->declared_end() <= multi_nested_ethernet.handoff->child->declared_end());
    PFL_EXPECT(multi_nested_outer_ipv4.handoff->child->captured_end() <= multi_nested_ethernet.handoff->child->captured_end());

    const auto multi_nested_inner_ipv6 = dissect_ipv6(*multi_nested_outer_ipv4.handoff->child);
    PFL_REQUIRE(multi_nested_inner_ipv6.handoff.has_value());
    PFL_REQUIRE(multi_nested_inner_ipv6.handoff->child.has_value());
    PFL_EXPECT(multi_nested_inner_ipv6.handoff->selector.domain == SelectorDomain::ipv6_next_header);
    PFL_EXPECT(multi_nested_inner_ipv6.handoff->selector.value == detail::kIpProtocolIpv4Encapsulation);
    PFL_EXPECT(multi_nested_inner_ipv6.handoff->child->source_id() == multi_nested_root.source_id());
    PFL_EXPECT(multi_nested_inner_ipv6.handoff->child->source_offset() == 74U);
    PFL_EXPECT(multi_nested_inner_ipv6.handoff->child->captured_end() == multi_nested_inner_ipv6.handoff->child->declared_end());
    PFL_EXPECT(multi_nested_inner_ipv6.handoff->child->declared_end() <= multi_nested_outer_ipv4.handoff->child->declared_end());
    PFL_EXPECT(multi_nested_inner_ipv6.handoff->child->captured_end() <= multi_nested_outer_ipv4.handoff->child->captured_end());

    const auto multi_nested_inner_ipv4 = dissect_ipv4(*multi_nested_inner_ipv6.handoff->child);
    PFL_REQUIRE(multi_nested_inner_ipv4.handoff.has_value());
    PFL_REQUIRE(multi_nested_inner_ipv4.handoff->child.has_value());
    PFL_EXPECT(multi_nested_inner_ipv4.handoff->selector.domain == SelectorDomain::ip_protocol);
    PFL_EXPECT(multi_nested_inner_ipv4.handoff->selector.value == detail::kIpProtocolUdp);
    PFL_EXPECT(multi_nested_inner_ipv4.handoff->child->source_id() == multi_nested_root.source_id());
    PFL_EXPECT(multi_nested_inner_ipv4.handoff->child->source_offset() == 94U);
    PFL_EXPECT(multi_nested_inner_ipv4.handoff->child->declared_end() <= multi_nested_inner_ipv6.handoff->child->declared_end());

    const auto multi_nested_udp = dissect_udp(*multi_nested_inner_ipv4.handoff->child);
    PFL_EXPECT(multi_nested_udp.status == ParseStatus::complete);
    PFL_REQUIRE(multi_nested_udp.bounds.payload.has_value());
    PFL_EXPECT(multi_nested_udp.bounds.source_id == multi_nested_root.source_id());
    PFL_EXPECT(multi_nested_udp.bounds.payload->captured.length() == 3U);

    StepKindRecorder multi_nested_recorder {};
    const DissectionEngine engine {};
    const auto multi_nested_result = engine.run(
        registry,
        make_link_type_selector(multi_nested_packet.data_link_type),
        multi_nested_root,
        DissectionConsumer {.on_step = record_step_kind, .context = &multi_nested_recorder}
    );
    PFL_EXPECT(multi_nested_result.stop_reason == StopReason::terminal_protocol);
    const std::vector<DissectionLayerKind> expected_multi_nested_kinds {
        DissectionLayerKind::ethernet_ii,
        DissectionLayerKind::ipv4,
        DissectionLayerKind::ipv6,
        DissectionLayerKind::ipv4,
        DissectionLayerKind::udp,
    };
    PFL_EXPECT(multi_nested_recorder.kinds == expected_multi_nested_kinds);

    const auto multi_nested_shadow = run_shadow(multi_nested_packet, registry);
    PFL_EXPECT(multi_nested_shadow.outcome == ImportDissectionOutcome::recognized_flow);
    PFL_EXPECT(multi_nested_shadow.stop_reason == StopReason::terminal_protocol);
    PFL_EXPECT(multi_nested_shadow.family == DissectionAddressFamily::ipv4);
    PFL_EXPECT(multi_nested_shadow.terminal_protocol == ProtocolId::udp);
    PFL_EXPECT(multi_nested_shadow.src_addr_v4 == ipv4(198, 51, 100, 10));
    PFL_EXPECT(multi_nested_shadow.dst_addr_v4 == ipv4(198, 51, 100, 11));
    PFL_EXPECT(multi_nested_shadow.has_ports);
    PFL_EXPECT(multi_nested_shadow.src_port == 41000U);
    PFL_EXPECT(multi_nested_shadow.dst_port == 53U);
    PFL_EXPECT(multi_nested_shadow.has_transport_payload_length);
    PFL_EXPECT(multi_nested_shadow.captured_transport_payload_length == 3U);
    PFL_EXPECT(format_shadow_path(multi_nested_shadow) == "EthernetII -> IPv4 -> IPv6 -> IPv4 -> UDP");

    const auto extension_inner_sctp_packet = make_raw_packet(make_ethernet_ipv6_packet(
        outer_ipv6_src,
        outer_ipv6_dst,
        detail::kIpProtocolHopByHop,
        make_ipv6_hop_by_hop_extension(
            detail::kIpProtocolIpv4Encapsulation,
            make_ipv4_payload_packet(
                ipv4(10, 77, 0, 1),
                ipv4(10, 77, 0, 2),
                detail::kIpProtocolSctp,
                make_sctp_segment(2905U, 2906U, 0x11223344U, 0x55667788U, 2U)
            )
        )
    ));
    StepKindRecorder extension_sctp_recorder {};
    const auto extension_sctp_result = engine.run(
        registry,
        make_link_type_selector(extension_inner_sctp_packet.data_link_type),
        make_root_slice(extension_inner_sctp_packet),
        DissectionConsumer {.on_step = record_step_kind, .context = &extension_sctp_recorder}
    );
    PFL_EXPECT(extension_sctp_result.stop_reason == StopReason::terminal_protocol);
    const std::vector<DissectionLayerKind> expected_extension_sctp_kinds {
        DissectionLayerKind::ethernet_ii,
        DissectionLayerKind::ipv6,
        DissectionLayerKind::ipv6_hop_by_hop,
        DissectionLayerKind::ipv4,
        DissectionLayerKind::sctp,
    };
    PFL_EXPECT(extension_sctp_recorder.kinds == expected_extension_sctp_kinds);
    const auto extension_sctp_shadow = run_shadow(extension_inner_sctp_packet, registry);
    PFL_EXPECT(extension_sctp_shadow.outcome == ImportDissectionOutcome::recognized_flow);
    PFL_EXPECT(extension_sctp_shadow.family == DissectionAddressFamily::ipv4);
    PFL_EXPECT(extension_sctp_shadow.terminal_protocol == ProtocolId::sctp);
    PFL_EXPECT(extension_sctp_shadow.src_addr_v4 == ipv4(10, 77, 0, 1));
    PFL_EXPECT(extension_sctp_shadow.dst_addr_v4 == ipv4(10, 77, 0, 2));
    PFL_EXPECT(extension_sctp_shadow.has_ports);
    PFL_EXPECT(extension_sctp_shadow.src_port == 2905U);
    PFL_EXPECT(extension_sctp_shadow.dst_port == 2906U);
    PFL_EXPECT(extension_sctp_shadow.has_transport_payload_length);
    PFL_EXPECT(extension_sctp_shadow.captured_transport_payload_length == 2U);
    PFL_EXPECT(format_shadow_path(extension_sctp_shadow) == "EthernetII -> IPv6 -> IPv4 -> SCTP");

    expect_shadow_matches_legacy_portless_flow(
        registry,
        make_raw_packet(make_ethernet_ipv4_fragment_packet(
            ipv4(203, 0, 113, 70),
            ipv4(203, 0, 113, 71),
            detail::kIpProtocolIpv4Encapsulation,
            0U,
            make_ipv4_payload_packet(
                ipv4(10, 78, 0, 1),
                ipv4(10, 78, 0, 2),
                detail::kIpProtocolIcmp,
                {8U, 0U, 0x12U, 0x34U, 0xAAU, 0xBBU, 0xCCU, 0xDDU}
            )
        )),
        "EthernetII -> IPv4 -> IPv4 -> ICMP",
        "EthernetII -> IPv4 -> IPv4",
        StopReason::terminal_protocol
    );

    expect_shadow_matches_legacy_portless_flow(
        registry,
        make_raw_packet(make_ethernet_ipv4_fragment_packet(
            ipv4(203, 0, 113, 72),
            ipv4(203, 0, 113, 73),
            detail::kIpProtocolIpv6Encapsulation,
            0U,
            make_ipv6_payload_packet(
                inner_ipv6_src,
                inner_ipv6_dst,
                detail::kIpProtocolIcmpV6,
                make_ipv6_icmpv6_message(128U, 0U)
            )
        )),
        "EthernetII -> IPv4 -> IPv6 -> ICMPv6",
        "EthernetII -> IPv4 -> IPv6",
        StopReason::terminal_protocol
    );

    expect_shadow_matches_legacy_portless_flow(
        registry,
        make_raw_packet(make_ethernet_ipv4_fragment_packet(
            ipv4(203, 0, 113, 74),
            ipv4(203, 0, 113, 75),
            detail::kIpProtocolIpv6Encapsulation,
            0U,
            make_ipv6_payload_packet(
                inner_ipv6_src,
                inner_ipv6_dst,
                detail::kIpProtocolHopByHop,
                make_ipv6_hop_by_hop_extension(detail::kIpProtocolIcmpV6, make_ipv6_icmpv6_message(129U, 1U))
            )
        )),
        "EthernetII -> IPv4 -> IPv6 -> ICMPv6",
        "EthernetII -> IPv4 -> IPv6",
        StopReason::terminal_protocol
    );

    const auto inner_ipv6_routing_packet = make_raw_packet(make_ethernet_ipv4_fragment_packet(
        ipv4(203, 0, 113, 12),
        ipv4(203, 0, 113, 13),
        detail::kIpProtocolIpv6Encapsulation,
        0U,
        make_ipv6_payload_packet(
            inner_ipv6_src,
            inner_ipv6_dst,
            detail::kIpProtocolRouting,
            make_ipv6_routing_extension(detail::kIpProtocolUdp, make_ipv6_udp_segment(3333U, 4444U, 2U))
        )
    ));
    StepKindRecorder inner_ipv6_routing_recorder {};
    const auto inner_ipv6_routing_result = engine.run(
        registry,
        make_link_type_selector(inner_ipv6_routing_packet.data_link_type),
        make_root_slice(inner_ipv6_routing_packet),
        DissectionConsumer {.on_step = record_step_kind, .context = &inner_ipv6_routing_recorder}
    );
    PFL_EXPECT(inner_ipv6_routing_result.stop_reason == StopReason::terminal_protocol);
    const std::vector<DissectionLayerKind> expected_inner_ipv6_routing_kinds {
        DissectionLayerKind::ethernet_ii,
        DissectionLayerKind::ipv4,
        DissectionLayerKind::ipv6,
        DissectionLayerKind::ipv6_routing,
        DissectionLayerKind::udp,
    };
    PFL_EXPECT(inner_ipv6_routing_recorder.kinds == expected_inner_ipv6_routing_kinds);
    const auto inner_ipv6_routing_shadow = run_shadow(inner_ipv6_routing_packet, registry);
    PFL_EXPECT(inner_ipv6_routing_shadow.outcome == ImportDissectionOutcome::recognized_flow);
    PFL_EXPECT(inner_ipv6_routing_shadow.family == DissectionAddressFamily::ipv6);
    PFL_EXPECT(inner_ipv6_routing_shadow.terminal_protocol == ProtocolId::udp);
    PFL_EXPECT(inner_ipv6_routing_shadow.has_ports);
    PFL_EXPECT(inner_ipv6_routing_shadow.src_port == 3333U);
    PFL_EXPECT(inner_ipv6_routing_shadow.dst_port == 4444U);
    PFL_EXPECT(format_shadow_path(inner_ipv6_routing_shadow) == "EthernetII -> IPv4 -> IPv6 -> UDP");

    auto outer_extra_tail_packet = make_ethernet_ipv4_fragment_packet(
        ipv4(203, 0, 113, 10),
        ipv4(203, 0, 113, 11),
        detail::kIpProtocolIpv4Encapsulation,
        0U,
        make_ipv4_payload_packet(
            ipv4(10, 1, 0, 1),
            ipv4(10, 1, 0, 2),
            detail::kIpProtocolUdp,
            make_ipv6_udp_segment(5000U, 5001U)
        )
    );
    outer_extra_tail_packet.push_back(0xAAU);
    outer_extra_tail_packet.push_back(0xBBU);
    outer_extra_tail_packet.push_back(0xCCU);
    const auto outer_extra_tail_shadow = run_shadow(make_raw_packet(outer_extra_tail_packet), registry);
    PFL_EXPECT(outer_extra_tail_shadow.outcome == ImportDissectionOutcome::recognized_flow);
    PFL_EXPECT(outer_extra_tail_shadow.has_transport_payload_length);
    PFL_EXPECT(outer_extra_tail_shadow.captured_transport_payload_length == 0U);
    PFL_EXPECT(format_shadow_path(outer_extra_tail_shadow) == "EthernetII -> IPv4 -> IPv4 -> UDP");

    auto truncated_inner_transport_packet = make_ethernet_ipv4_fragment_packet(
        ipv4(203, 0, 113, 20),
        ipv4(203, 0, 113, 21),
        detail::kIpProtocolIpv4Encapsulation,
        0U,
        make_ipv4_payload_packet(
            ipv4(10, 2, 0, 1),
            ipv4(10, 2, 0, 2),
            detail::kIpProtocolTcp,
            make_ipv6_tcp_segment(61000U, 443U)
        )
    );
    const auto truncated_inner_transport_reported_length = static_cast<std::uint32_t>(truncated_inner_transport_packet.size());
    truncated_inner_transport_packet.resize(truncated_inner_transport_packet.size() - 2U);
    const auto truncated_inner_transport_shadow = run_shadow(
        make_raw_packet(truncated_inner_transport_packet, truncated_inner_transport_reported_length),
        registry
    );
    PFL_EXPECT(truncated_inner_transport_shadow.outcome == ImportDissectionOutcome::unrecognized);
    PFL_EXPECT(truncated_inner_transport_shadow.stop_reason == StopReason::truncated);
    PFL_EXPECT(truncated_inner_transport_shadow.family == DissectionAddressFamily::ipv4);
    PFL_EXPECT(truncated_inner_transport_shadow.terminal_protocol == ProtocolId::tcp);
    PFL_EXPECT(!truncated_inner_transport_shadow.has_ports);
    PFL_EXPECT(format_shadow_path(truncated_inner_transport_shadow) == "EthernetII -> IPv4 -> IPv4");

    StepKindRecorder truncated_inner_transport_recorder {};
    const auto truncated_inner_transport_raw =
        make_raw_packet(truncated_inner_transport_packet, truncated_inner_transport_reported_length);
    const auto truncated_inner_transport_result = engine.run(
        registry,
        make_link_type_selector(kLinkTypeEthernet),
        make_root_slice(truncated_inner_transport_raw),
        DissectionConsumer {.on_step = record_step_kind, .context = &truncated_inner_transport_recorder}
    );
    PFL_EXPECT(truncated_inner_transport_result.stop_reason == StopReason::truncated);
    const std::vector<DissectionLayerKind> expected_truncated_inner_transport_kinds {
        DissectionLayerKind::ethernet_ii,
        DissectionLayerKind::ipv4,
        DissectionLayerKind::ipv4,
        DissectionLayerKind::tcp,
    };
    PFL_EXPECT(truncated_inner_transport_recorder.kinds == expected_truncated_inner_transport_kinds);

    const auto short_inner_header_packet = make_raw_packet(make_ethernet_ipv4_fragment_packet(
        ipv4(203, 0, 113, 30),
        ipv4(203, 0, 113, 31),
        detail::kIpProtocolIpv4Encapsulation,
        0U,
        std::vector<std::uint8_t>(10U, 0x00U)
    ));
    StepKindRecorder short_inner_header_recorder {};
    const auto short_inner_header_result = engine.run(
        registry,
        make_link_type_selector(short_inner_header_packet.data_link_type),
        make_root_slice(short_inner_header_packet),
        DissectionConsumer {.on_step = record_step_kind, .context = &short_inner_header_recorder}
    );
    PFL_EXPECT(short_inner_header_result.stop_reason == StopReason::truncated);
    const std::vector<DissectionLayerKind> expected_short_inner_header_kinds {
        DissectionLayerKind::ethernet_ii,
        DissectionLayerKind::ipv4,
        DissectionLayerKind::ipv4,
    };
    PFL_EXPECT(short_inner_header_recorder.kinds == expected_short_inner_header_kinds);
    const auto short_inner_header_shadow = run_shadow(short_inner_header_packet, registry);
    PFL_EXPECT(short_inner_header_shadow.outcome == ImportDissectionOutcome::unrecognized);
    PFL_EXPECT(short_inner_header_shadow.stop_reason == StopReason::truncated);
    PFL_EXPECT(format_shadow_path(short_inner_header_shadow) == "EthernetII -> IPv4");

    const auto unknown_deepest_packet = make_raw_packet(make_ethernet_ipv4_fragment_packet(
        ipv4(203, 0, 113, 40),
        ipv4(203, 0, 113, 41),
        detail::kIpProtocolIpv6Encapsulation,
        0U,
        make_ipv6_payload_packet(inner_ipv6_src, inner_ipv6_dst, 0xFDU, {0xde, 0xad, 0xbe, 0xef})
    ));
    const auto unknown_deepest_shadow = run_shadow(unknown_deepest_packet, registry);
    PFL_EXPECT(unknown_deepest_shadow.outcome == ImportDissectionOutcome::unrecognized);
    PFL_EXPECT(unknown_deepest_shadow.stop_reason == StopReason::unknown_next_protocol);
    PFL_EXPECT(unknown_deepest_shadow.family == DissectionAddressFamily::ipv6);
    PFL_EXPECT(unknown_deepest_shadow.terminal_protocol == ProtocolId::unknown);
    PFL_EXPECT(format_shadow_path(unknown_deepest_shadow) == "EthernetII -> IPv4 -> IPv6");

    const auto outer_ipv4_fragment_packet = make_raw_packet(make_ethernet_ipv4_fragment_packet(
        ipv4(203, 0, 113, 50),
        ipv4(203, 0, 113, 51),
        detail::kIpProtocolIpv4Encapsulation,
        0x2000U,
        {0x45, 0x00, 0x00, 0x14, 0x00}
    ));
    StepKindRecorder outer_ipv4_fragment_recorder {};
    const auto outer_ipv4_fragment_result = engine.run(
        registry,
        make_link_type_selector(outer_ipv4_fragment_packet.data_link_type),
        make_root_slice(outer_ipv4_fragment_packet),
        DissectionConsumer {.on_step = record_step_kind, .context = &outer_ipv4_fragment_recorder}
    );
    PFL_EXPECT(outer_ipv4_fragment_result.stop_reason == StopReason::needs_reassembly);
    const std::vector<DissectionLayerKind> expected_outer_ipv4_fragment_kinds {
        DissectionLayerKind::ethernet_ii,
        DissectionLayerKind::ipv4,
    };
    PFL_EXPECT(outer_ipv4_fragment_recorder.kinds == expected_outer_ipv4_fragment_kinds);
    const auto outer_ipv4_fragment_shadow = run_shadow(outer_ipv4_fragment_packet, registry);
    PFL_EXPECT(outer_ipv4_fragment_shadow.outcome == ImportDissectionOutcome::unrecognized);
    PFL_EXPECT(outer_ipv4_fragment_shadow.stop_reason == StopReason::needs_reassembly);
    PFL_EXPECT(format_shadow_path(outer_ipv4_fragment_shadow) == "EthernetII -> IPv4");

    const auto outer_ipv6_fragment_packet = make_raw_packet(make_ethernet_ipv6_fragment_packet(
        outer_ipv6_src,
        outer_ipv6_dst,
        detail::kIpProtocolIpv6Encapsulation,
        {0x60, 0x00, 0x00, 0x00}
    ));
    StepKindRecorder outer_ipv6_fragment_recorder {};
    const auto outer_ipv6_fragment_result = engine.run(
        registry,
        make_link_type_selector(outer_ipv6_fragment_packet.data_link_type),
        make_root_slice(outer_ipv6_fragment_packet),
        DissectionConsumer {.on_step = record_step_kind, .context = &outer_ipv6_fragment_recorder}
    );
    PFL_EXPECT(outer_ipv6_fragment_result.stop_reason == StopReason::needs_reassembly);
    const std::vector<DissectionLayerKind> expected_outer_ipv6_fragment_kinds {
        DissectionLayerKind::ethernet_ii,
        DissectionLayerKind::ipv6,
        DissectionLayerKind::ipv6_fragment,
    };
    PFL_EXPECT(outer_ipv6_fragment_recorder.kinds == expected_outer_ipv6_fragment_kinds);
    const auto outer_ipv6_fragment_shadow = run_shadow(outer_ipv6_fragment_packet, registry);
    PFL_EXPECT(outer_ipv6_fragment_shadow.outcome == ImportDissectionOutcome::unrecognized);
    PFL_EXPECT(outer_ipv6_fragment_shadow.stop_reason == StopReason::needs_reassembly);
    PFL_EXPECT(format_shadow_path(outer_ipv6_fragment_shadow) == "EthernetII -> IPv6");

    const auto inner_fragmented_shadow = run_shadow(
        make_raw_packet(make_ethernet_ipv6_packet(
            outer_ipv6_src,
            outer_ipv6_dst,
            detail::kIpProtocolIpv4Encapsulation,
            make_ipv4_payload_packet(
                ipv4(10, 88, 0, 1),
                ipv4(10, 88, 0, 2),
                detail::kIpProtocolUdp,
                {0xde, 0xad, 0xbe, 0xef},
                0x2000U
            )
        )),
        registry
    );
    PFL_EXPECT(inner_fragmented_shadow.outcome == ImportDissectionOutcome::recognized_flow);
    PFL_EXPECT(inner_fragmented_shadow.stop_reason == StopReason::needs_reassembly);
    PFL_EXPECT(inner_fragmented_shadow.family == DissectionAddressFamily::ipv4);
    PFL_EXPECT(inner_fragmented_shadow.terminal_protocol == ProtocolId::udp);
    PFL_EXPECT(!inner_fragmented_shadow.has_ports);
    PFL_EXPECT(format_shadow_path(inner_fragmented_shadow) == "EthernetII -> IPv6 -> IPv4");

    const auto outer_ipv6_inner_ipv4_icmp_packet = make_raw_packet(make_ethernet_ipv6_packet(
        outer_ipv6_src,
        outer_ipv6_dst,
        detail::kIpProtocolIpv4Encapsulation,
        make_ipv4_payload_packet(
            ipv4(10, 89, 0, 1),
            ipv4(10, 89, 0, 2),
            detail::kIpProtocolIcmp,
            {8U, 0U, 0x22U, 0x22U, 0x01U, 0x02U, 0x03U, 0x04U}
        )
    ));
    StepKindRecorder outer_ipv6_inner_ipv4_icmp_recorder {};
    const auto outer_ipv6_inner_ipv4_icmp_result = engine.run(
        registry,
        make_link_type_selector(outer_ipv6_inner_ipv4_icmp_packet.data_link_type),
        make_root_slice(outer_ipv6_inner_ipv4_icmp_packet),
        DissectionConsumer {.on_step = record_step_kind, .context = &outer_ipv6_inner_ipv4_icmp_recorder}
    );
    PFL_EXPECT(outer_ipv6_inner_ipv4_icmp_result.stop_reason == StopReason::terminal_protocol);
    const std::vector<DissectionLayerKind> expected_outer_ipv6_inner_ipv4_icmp_kinds {
        DissectionLayerKind::ethernet_ii,
        DissectionLayerKind::ipv6,
        DissectionLayerKind::ipv4,
        DissectionLayerKind::icmp,
    };
    PFL_EXPECT(outer_ipv6_inner_ipv4_icmp_recorder.kinds == expected_outer_ipv6_inner_ipv4_icmp_kinds);
    const auto outer_ipv6_inner_ipv4_icmp_shadow = run_shadow(outer_ipv6_inner_ipv4_icmp_packet, registry);
    PFL_EXPECT(outer_ipv6_inner_ipv4_icmp_shadow.outcome == ImportDissectionOutcome::recognized_flow);
    PFL_EXPECT(outer_ipv6_inner_ipv4_icmp_shadow.family == DissectionAddressFamily::ipv4);
    PFL_EXPECT(outer_ipv6_inner_ipv4_icmp_shadow.terminal_protocol == ProtocolId::icmp);
    PFL_EXPECT(outer_ipv6_inner_ipv4_icmp_shadow.src_addr_v4 == ipv4(10, 89, 0, 1));
    PFL_EXPECT(outer_ipv6_inner_ipv4_icmp_shadow.dst_addr_v4 == ipv4(10, 89, 0, 2));
    PFL_EXPECT(!outer_ipv6_inner_ipv4_icmp_shadow.has_ports);
    PFL_EXPECT(!outer_ipv6_inner_ipv4_icmp_shadow.has_transport_payload_length);
    PFL_EXPECT(format_shadow_path(outer_ipv6_inner_ipv4_icmp_shadow) == "EthernetII -> IPv6 -> IPv4 -> ICMP");

    const auto outer_ipv6_inner_ipv6_icmpv6_packet = make_raw_packet(make_ethernet_ipv6_packet(
        outer_ipv6_src,
        outer_ipv6_dst,
        detail::kIpProtocolIpv6Encapsulation,
        make_ipv6_payload_packet(
            inner_ipv6_src,
            inner_ipv6_dst,
            detail::kIpProtocolIcmpV6,
            make_ipv6_icmpv6_message(128U, 0U)
        )
    ));
    const auto outer_ipv6_inner_ipv6_icmpv6_shadow = run_shadow(outer_ipv6_inner_ipv6_icmpv6_packet, registry);
    PFL_EXPECT(outer_ipv6_inner_ipv6_icmpv6_shadow.outcome == ImportDissectionOutcome::recognized_flow);
    PFL_EXPECT(outer_ipv6_inner_ipv6_icmpv6_shadow.stop_reason == StopReason::terminal_protocol);
    PFL_EXPECT(outer_ipv6_inner_ipv6_icmpv6_shadow.family == DissectionAddressFamily::ipv6);
    PFL_EXPECT(outer_ipv6_inner_ipv6_icmpv6_shadow.terminal_protocol == ProtocolId::icmpv6);
    PFL_EXPECT(outer_ipv6_inner_ipv6_icmpv6_shadow.src_addr_v6 == inner_ipv6_src);
    PFL_EXPECT(outer_ipv6_inner_ipv6_icmpv6_shadow.dst_addr_v6 == inner_ipv6_dst);
    PFL_EXPECT(!outer_ipv6_inner_ipv6_icmpv6_shadow.has_ports);
    PFL_EXPECT(!outer_ipv6_inner_ipv6_icmpv6_shadow.has_transport_payload_length);
    PFL_EXPECT(format_shadow_path(outer_ipv6_inner_ipv6_icmpv6_shadow) == "EthernetII -> IPv6 -> IPv6 -> ICMPv6");

    const auto outer_ipv6_hbh_inner_ipv4_icmp_packet = make_raw_packet(make_ethernet_ipv6_packet(
        outer_ipv6_src,
        outer_ipv6_dst,
        detail::kIpProtocolHopByHop,
        make_ipv6_hop_by_hop_extension(
            detail::kIpProtocolIpv4Encapsulation,
            make_ipv4_payload_packet(
                ipv4(10, 90, 0, 1),
                ipv4(10, 90, 0, 2),
                detail::kIpProtocolIcmp,
                {0U, 0U, 0x11U, 0x22U, 0x55U, 0x66U, 0x77U, 0x88U}
            )
        )
    ));
    StepKindRecorder outer_ipv6_hbh_inner_ipv4_icmp_recorder {};
    const auto outer_ipv6_hbh_inner_ipv4_icmp_result = engine.run(
        registry,
        make_link_type_selector(outer_ipv6_hbh_inner_ipv4_icmp_packet.data_link_type),
        make_root_slice(outer_ipv6_hbh_inner_ipv4_icmp_packet),
        DissectionConsumer {.on_step = record_step_kind, .context = &outer_ipv6_hbh_inner_ipv4_icmp_recorder}
    );
    PFL_EXPECT(outer_ipv6_hbh_inner_ipv4_icmp_result.stop_reason == StopReason::terminal_protocol);
    const std::vector<DissectionLayerKind> expected_outer_ipv6_hbh_inner_ipv4_icmp_kinds {
        DissectionLayerKind::ethernet_ii,
        DissectionLayerKind::ipv6,
        DissectionLayerKind::ipv6_hop_by_hop,
        DissectionLayerKind::ipv4,
        DissectionLayerKind::icmp,
    };
    PFL_EXPECT(outer_ipv6_hbh_inner_ipv4_icmp_recorder.kinds == expected_outer_ipv6_hbh_inner_ipv4_icmp_kinds);
    const auto outer_ipv6_hbh_inner_ipv4_icmp_shadow = run_shadow(outer_ipv6_hbh_inner_ipv4_icmp_packet, registry);
    PFL_EXPECT(outer_ipv6_hbh_inner_ipv4_icmp_shadow.outcome == ImportDissectionOutcome::recognized_flow);
    PFL_EXPECT(outer_ipv6_hbh_inner_ipv4_icmp_shadow.family == DissectionAddressFamily::ipv4);
    PFL_EXPECT(outer_ipv6_hbh_inner_ipv4_icmp_shadow.terminal_protocol == ProtocolId::icmp);
    PFL_EXPECT(!outer_ipv6_hbh_inner_ipv4_icmp_shadow.has_ports);
    PFL_EXPECT(format_shadow_path(outer_ipv6_hbh_inner_ipv4_icmp_shadow) == "EthernetII -> IPv6 -> IPv4 -> ICMP");

    const auto deep_depth_packet = make_raw_packet(make_ethernet_ipv4_fragment_packet(
        ipv4(203, 0, 113, 60),
        ipv4(203, 0, 113, 61),
        detail::kIpProtocolIpv6Encapsulation,
        0U,
        make_ipv6_payload_packet(
            inner_ipv6_src,
            inner_ipv6_dst,
            detail::kIpProtocolIpv4Encapsulation,
            make_ipv4_payload_packet(
                ipv4(10, 99, 0, 1),
                ipv4(10, 99, 0, 2),
                detail::kIpProtocolIpv6Encapsulation,
                make_ipv6_payload_packet(
                    ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0x55}),
                    ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 0x66}),
                    detail::kIpProtocolUdp,
                    make_ipv6_udp_segment(62000U, 62001U, 1U)
                )
            )
        )
    ));
    StepKindRecorder deep_depth_recorder {};
    const auto deep_depth_result = engine.run(
        registry,
        make_link_type_selector(deep_depth_packet.data_link_type),
        make_root_slice(deep_depth_packet),
        DissectionConsumer {.on_step = record_step_kind, .context = &deep_depth_recorder},
        5U
    );
    PFL_EXPECT(deep_depth_result.stop_reason == StopReason::depth_limit);
    PFL_EXPECT(deep_depth_result.step_count == 5U);
    PFL_EXPECT(deep_depth_result.traversed_depth == 5U);
    const std::vector<DissectionLayerKind> expected_deep_depth_kinds {
        DissectionLayerKind::ethernet_ii,
        DissectionLayerKind::ipv4,
        DissectionLayerKind::ipv6,
        DissectionLayerKind::ipv4,
        DissectionLayerKind::ipv6,
    };
    PFL_EXPECT(deep_depth_recorder.kinds == expected_deep_depth_kinds);
}

void expect_common_direct_supports_triple_vlan_and_depth_limits() {
    const auto built = make_common_direct_registry();
    PFL_REQUIRE(built.ok());
    const auto& registry = *built.registry;

    const auto triple_tagged_packet = make_raw_packet(add_vlan_tags(
        make_ethernet_ipv4_udp_packet(ipv4(192, 0, 2, 10), ipv4(192, 0, 2, 11), 9000U, 53U),
        {
            {0x8100U, 10U},
            {0x8100U, 20U},
            {0x8100U, 30U},
        }
    ));
    const auto triple_shadow = run_shadow(triple_tagged_packet, registry);
    PFL_EXPECT(triple_shadow.outcome == ImportDissectionOutcome::recognized_flow);
    PFL_EXPECT(format_shadow_path(triple_shadow) == "EthernetII -> VLAN(vid=10) -> VLAN(vid=20) -> VLAN(vid=30) -> IPv4 -> UDP");

    StepKindRecorder recorder {};
    const DissectionEngine engine {};
    const auto limited_result = engine.run(
        registry,
        make_link_type_selector(triple_tagged_packet.data_link_type),
        make_root_slice(triple_tagged_packet),
        DissectionConsumer {.on_step = record_step_kind, .context = &recorder},
        4U
    );
    PFL_EXPECT(limited_result.stop_reason == StopReason::depth_limit);
    PFL_EXPECT(limited_result.step_count == 4U);
    PFL_EXPECT(limited_result.traversed_depth == 4U);
    const std::vector<DissectionLayerKind> expected_kinds {
        DissectionLayerKind::ethernet_ii,
        DissectionLayerKind::vlan,
        DissectionLayerKind::vlan,
        DissectionLayerKind::vlan,
    };
    PFL_EXPECT(recorder.kinds == expected_kinds);
}

void expect_shadow_parity_for_common_direct_subset() {
    const auto built = make_common_direct_registry();
    PFL_REQUIRE(built.ok());
    const auto& registry = *built.registry;
    const auto ipv6_src_addr = ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x11});
    const auto ipv6_dst_addr = ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x22});

    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(make_ethernet_ipv4_tcp_packet_with_payload(
            ipv4(10, 0, 1, 1), ipv4(10, 0, 1, 2), 12345U, 443U, 5U, 0x18U)),
        "EthernetII -> IPv4 -> TCP",
        StopReason::terminal_protocol
    );

    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(make_ethernet_ipv4_udp_packet_with_bytes_payload(
            ipv4(10, 0, 2, 1), ipv4(10, 0, 2, 2), 5353U, 53U, {0x01, 0x02, 0x03})),
        "EthernetII -> IPv4 -> UDP",
        StopReason::terminal_protocol
    );

    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(make_ethernet_ipv4_sctp_packet(
            ipv4(10, 0, 2, 11), ipv4(10, 0, 2, 12), 49132U, 36412U, 0x10213243U, 0x00000000U, 4U)),
        "EthernetII -> IPv4 -> SCTP",
        StopReason::terminal_protocol
    );

    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(make_single_tagged_ethernet_ipv4_tcp_packet(
            ipv4(192, 168, 1, 10), ipv4(192, 168, 1, 20), 12345U, 443U, 100U)),
        "EthernetII -> VLAN(vid=100) -> IPv4 -> TCP",
        StopReason::terminal_protocol
    );

    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(add_vlan_tags(
            make_ethernet_ipv4_sctp_packet(
                ipv4(192, 168, 1, 30), ipv4(192, 168, 1, 31), 2905U, 2906U, 0x01020304U, 0xAABBCCDDU, 2U),
            {{0x8100U, 101U}}
        )),
        "EthernetII -> VLAN(vid=101) -> IPv4 -> SCTP",
        StopReason::terminal_protocol
    );

    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(make_double_tagged_ethernet_ipv4_udp_packet(
            ipv4(172, 16, 0, 1), ipv4(172, 16, 0, 2), 5353U, 53U, 200U, 300U)),
        "EthernetII -> VLAN(vid=200) -> VLAN(vid=300) -> IPv4 -> UDP",
        StopReason::terminal_protocol
    );

    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(make_single_tagged_ethernet_ipv4_tcp_packet(
            ipv4(10, 10, 10, 1), ipv4(10, 10, 10, 2), 2222U, 80U, 0U)),
        "EthernetII -> VLAN(vid=0) -> IPv4 -> TCP",
        StopReason::terminal_protocol
    );

    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(make_ethernet_ipv4_fragment_packet(
            ipv4(10, 0, 3, 1), ipv4(10, 0, 3, 2), 6U, 0x2000U, {0x16, 0x03, 0x03, 0x00, 0x10})),
        "EthernetII -> IPv4",
        StopReason::needs_reassembly
    );

    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(make_ethernet_ipv4_fragment_packet(
            ipv4(10, 0, 4, 1), ipv4(10, 0, 4, 2), 17U, 0x0001U, {0xde, 0xad, 0xbe, 0xef})),
        "EthernetII -> IPv4",
        StopReason::needs_reassembly
    );

    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(make_ethernet_ipv4_fragment_packet(
            ipv4(10, 0, 4, 11), ipv4(10, 0, 4, 12), detail::kIpProtocolSctp, 0x0001U, {0xde, 0xad, 0xbe, 0xef})),
        "EthernetII -> IPv4",
        StopReason::needs_reassembly
    );

    auto udp_options_packet = add_ipv4_options(
        make_ethernet_ipv4_udp_packet(ipv4(198, 51, 100, 1), ipv4(198, 51, 100, 2), 9000U, 9001U),
        {0x01, 0x01, 0x01, 0x01}
    );
    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(udp_options_packet),
        "EthernetII -> IPv4 -> UDP",
        StopReason::terminal_protocol
    );

    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(make_ethernet_ipv6_packet(
            ipv6_src_addr,
            ipv6_dst_addr,
            detail::kIpProtocolTcp,
            make_ipv6_tcp_segment(12345U, 443U, 5U, 0x18U)
        )),
        "EthernetII -> IPv6 -> TCP",
        StopReason::terminal_protocol
    );

    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(make_ethernet_ipv6_packet(
            ipv6_src_addr,
            ipv6_dst_addr,
            detail::kIpProtocolUdp,
            make_ipv6_udp_segment(5353U, 53U, 3U)
        )),
        "EthernetII -> IPv6 -> UDP",
        StopReason::terminal_protocol
    );

    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(make_ethernet_ipv6_packet(
            ipv6_src_addr,
            ipv6_dst_addr,
            detail::kIpProtocolSctp,
            make_sctp_segment(49132U, 36412U, 0x10213243U, 0x00000000U, 4U)
        )),
        "EthernetII -> IPv6 -> SCTP",
        StopReason::terminal_protocol
    );

    expect_shadow_matches_legacy_portless_flow(
        registry,
        make_raw_packet(make_ethernet_ipv4_icmp_packet(
            ipv4(10, 9, 0, 1),
            ipv4(10, 9, 0, 2),
            8U,
            0U
        )),
        "EthernetII -> IPv4 -> ICMP",
        "EthernetII -> IPv4",
        StopReason::terminal_protocol
    );

    expect_shadow_matches_legacy_portless_flow(
        registry,
        make_raw_packet(add_vlan_tags(
            make_ethernet_ipv4_icmp_packet(
                ipv4(10, 9, 0, 3),
                ipv4(10, 9, 0, 4),
                0U,
                0U
            ),
            {{0x8100U, 405U}}
        )),
        "EthernetII -> VLAN(vid=405) -> IPv4 -> ICMP",
        "EthernetII -> VLAN(vid=405) -> IPv4",
        StopReason::terminal_protocol
    );

    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(add_vlan_tags(
            make_ethernet_ipv6_packet(
                ipv6_src_addr,
                ipv6_dst_addr,
                detail::kIpProtocolUdp,
                make_ipv6_udp_segment(9000U, 9001U)
            ),
            {{0x8100U, 400U}}
        )),
        "EthernetII -> VLAN(vid=400) -> IPv6 -> UDP",
        StopReason::terminal_protocol
    );

    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(add_vlan_tags(
            make_ethernet_ipv6_packet(
                ipv6_src_addr,
                ipv6_dst_addr,
                detail::kIpProtocolSctp,
                make_sctp_segment(2905U, 2906U, 0x01020304U, 0xAABBCCDDU, 1U)
            ),
            {{0x8100U, 401U}}
        )),
        "EthernetII -> VLAN(vid=401) -> IPv6 -> SCTP",
        StopReason::terminal_protocol
    );

    expect_shadow_matches_legacy_portless_flow(
        registry,
        make_raw_packet(make_ethernet_ipv6_packet(
            ipv6_src_addr,
            ipv6_dst_addr,
            detail::kIpProtocolIcmpV6,
            make_ipv6_icmpv6_message(128U, 0U)
        )),
        "EthernetII -> IPv6 -> ICMPv6",
        "EthernetII -> IPv6",
        StopReason::terminal_protocol
    );

    expect_shadow_matches_legacy_portless_flow(
        registry,
        make_raw_packet(add_vlan_tags(
            make_ethernet_ipv6_packet(
                ipv6_src_addr,
                ipv6_dst_addr,
                detail::kIpProtocolIcmpV6,
                make_ipv6_icmpv6_message(129U, 1U)
            ),
            {{0x8100U, 406U}}
        )),
        "EthernetII -> VLAN(vid=406) -> IPv6 -> ICMPv6",
        "EthernetII -> VLAN(vid=406) -> IPv6",
        StopReason::terminal_protocol
    );

    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(make_ethernet_ipv6_udp_with_hop_by_hop_packet(
            ipv6_src_addr,
            ipv6_dst_addr,
            61000U,
            53U
        )),
        "EthernetII -> IPv6 -> UDP",
        StopReason::terminal_protocol
    );

    expect_shadow_matches_legacy_portless_flow(
        registry,
        make_raw_packet(make_ethernet_ipv6_icmpv6_with_hop_by_hop_packet(
            ipv6_src_addr,
            ipv6_dst_addr,
            128U,
            0U
        )),
        "EthernetII -> IPv6 -> ICMPv6",
        "EthernetII -> IPv6",
        StopReason::terminal_protocol
    );

    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(make_ethernet_ipv6_packet(
            ipv6_src_addr,
            ipv6_dst_addr,
            detail::kIpProtocolHopByHop,
            make_ipv6_hop_by_hop_extension(
                detail::kIpProtocolSctp,
                make_sctp_segment(49132U, 36412U, 0x10213243U, 0x00000000U, 3U)
            )
        )),
        "EthernetII -> IPv6 -> SCTP",
        StopReason::terminal_protocol
    );

    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(make_ethernet_ipv6_packet(
            ipv6_src_addr,
            ipv6_dst_addr,
            detail::kIpProtocolRouting,
            make_ipv6_routing_extension(detail::kIpProtocolUdp, make_ipv6_udp_segment(1200U, 2200U))
        )),
        "EthernetII -> IPv6 -> UDP",
        StopReason::terminal_protocol
    );

    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(make_ethernet_ipv6_packet(
            ipv6_src_addr,
            ipv6_dst_addr,
            detail::kIpProtocolDestinationOptions,
            make_ipv6_destination_options_extension(detail::kIpProtocolTcp, make_ipv6_tcp_segment(32000U, 443U, 2U, 0x19U))
        )),
        "EthernetII -> IPv6 -> TCP",
        StopReason::terminal_protocol
    );

    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(make_ethernet_ipv6_fragment_packet(
            ipv6_src_addr,
            ipv6_dst_addr,
            detail::kIpProtocolUdp,
            make_ipv6_udp_segment(20000U, 20001U, 2U)
        )),
        "EthernetII -> IPv6",
        StopReason::needs_reassembly
    );

    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(make_ethernet_ipv6_fragment_packet(
            ipv6_src_addr,
            ipv6_dst_addr,
            detail::kIpProtocolSctp,
            make_sctp_segment(49132U, 36412U, 0x10213243U, 0x00000000U, 2U)
        )),
        "EthernetII -> IPv6",
        StopReason::needs_reassembly
    );

    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(make_ethernet_ipv6_fragment_packet(
            ipv6_src_addr,
            ipv6_dst_addr,
            detail::kIpProtocolTcp,
            make_ipv6_tcp_segment(20002U, 20003U, 4U, 0x10U),
            0U,
            true
        )),
        "EthernetII -> IPv6",
        StopReason::needs_reassembly
    );

    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(make_ethernet_ipv4_fragment_packet(
            ipv4(198, 18, 0, 1),
            ipv4(198, 18, 0, 2),
            detail::kIpProtocolIpv4Encapsulation,
            0U,
            make_ipv4_payload_packet(
                ipv4(10, 50, 0, 1),
                ipv4(10, 50, 0, 2),
                detail::kIpProtocolTcp,
                make_ipv6_tcp_segment(32000U, 443U, 4U, 0x18U)
            )
        )),
        "EthernetII -> IPv4 -> IPv4 -> TCP",
        StopReason::terminal_protocol
    );

    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(make_ethernet_ipv4_fragment_packet(
            ipv4(198, 18, 0, 3),
            ipv4(198, 18, 0, 4),
            detail::kIpProtocolIpv6Encapsulation,
            0U,
            make_ipv6_payload_packet(
                ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0x81}),
                ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0x82}),
                detail::kIpProtocolUdp,
                make_ipv6_udp_segment(5300U, 53U, 5U)
            )
        )),
        "EthernetII -> IPv4 -> IPv6 -> UDP",
        StopReason::terminal_protocol
    );

    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(make_ethernet_ipv6_packet(
            ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0, 0x91}),
            ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0, 0x92}),
            detail::kIpProtocolIpv4Encapsulation,
            make_ipv4_payload_packet(
                ipv4(10, 60, 0, 1),
                ipv4(10, 60, 0, 2),
                detail::kIpProtocolUdp,
                make_ipv6_udp_segment(1200U, 2200U, 2U)
            )
        )),
        "EthernetII -> IPv6 -> IPv4 -> UDP",
        StopReason::terminal_protocol
    );

    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(make_ethernet_ipv6_packet(
            ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0xa1}),
            ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0xa2}),
            detail::kIpProtocolIpv6Encapsulation,
            make_ipv6_payload_packet(
                ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 11, 0, 0, 0, 0, 0, 0, 0, 0xb1}),
                ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 11, 0, 0, 0, 0, 0, 0, 0, 0xb2}),
                detail::kIpProtocolTcp,
                make_ipv6_tcp_segment(22000U, 8443U, 3U, 0x18U)
            )
        )),
        "EthernetII -> IPv6 -> IPv6 -> TCP",
        StopReason::terminal_protocol
    );

    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(make_ethernet_ipv6_packet(
            ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 12, 0, 0, 0, 0, 0, 0, 0, 0xc1}),
            ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 12, 0, 0, 0, 0, 0, 0, 0, 0xc2}),
            detail::kIpProtocolHopByHop,
            make_ipv6_hop_by_hop_extension(
                detail::kIpProtocolIpv4Encapsulation,
                make_ipv4_payload_packet(
                    ipv4(10, 70, 0, 1),
                    ipv4(10, 70, 0, 2),
                    detail::kIpProtocolUdp,
                    make_ipv6_udp_segment(9000U, 9001U, 1U)
                )
            )
        )),
        "EthernetII -> IPv6 -> IPv4 -> UDP",
        StopReason::terminal_protocol
    );

    expect_shadow_matches_legacy_flow(
        registry,
        make_raw_packet(make_ethernet_ipv4_fragment_packet(
            ipv4(198, 18, 0, 5),
            ipv4(198, 18, 0, 6),
            detail::kIpProtocolIpv6Encapsulation,
            0U,
            make_ipv6_payload_packet(
                ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 13, 0, 0, 0, 0, 0, 0, 0, 0xd1}),
                ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 13, 0, 0, 0, 0, 0, 0, 0, 0xd2}),
                detail::kIpProtocolRouting,
                make_ipv6_routing_extension(detail::kIpProtocolUdp, make_ipv6_udp_segment(3333U, 4444U, 2U))
            )
        )),
        "EthernetII -> IPv4 -> IPv6 -> UDP",
        StopReason::terminal_protocol
    );
}

void expect_shadow_conservative_stops_and_arp_behavior() {
    const auto built = make_common_direct_registry();
    PFL_REQUIRE(built.ok());
    const auto& registry = *built.registry;
    const auto ipv6_src_addr = ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x31});
    const auto ipv6_dst_addr = ipv6({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x32});

    const auto ieee8023_shadow = run_shadow(make_raw_packet(make_ethernet_ieee8023_frame(16U)), registry);
    PFL_EXPECT(ieee8023_shadow.outcome == ImportDissectionOutcome::unrecognized);
    PFL_EXPECT(ieee8023_shadow.stop_reason == StopReason::unrecognized_payload);
    PFL_EXPECT(format_shadow_path(ieee8023_shadow) == "IEEE 802.3");

    const auto unsupported_ip_shadow = run_shadow(
        make_raw_packet(make_ethernet_ipv4_fragment_packet(
            ipv4(10, 9, 0, 1),
            ipv4(10, 9, 0, 2),
            0xFDU,
            0U,
            {0xdeU, 0xadU, 0xbeU, 0xefU}
        )),
        registry
    );
    PFL_EXPECT(unsupported_ip_shadow.outcome == ImportDissectionOutcome::unrecognized);
    PFL_EXPECT(unsupported_ip_shadow.stop_reason == StopReason::unknown_next_protocol);
    PFL_EXPECT(format_shadow_path(unsupported_ip_shadow) == "EthernetII -> IPv4");

    const auto unsupported_ipv6_shadow = run_shadow(
        make_raw_packet(make_ethernet_ipv6_packet(
            ipv6_src_addr,
            ipv6_dst_addr,
            0xFD,
            {0xde, 0xad, 0xbe, 0xef}
        )),
        registry
    );
    PFL_EXPECT(unsupported_ipv6_shadow.outcome == ImportDissectionOutcome::unrecognized);
    PFL_EXPECT(unsupported_ipv6_shadow.stop_reason == StopReason::unknown_next_protocol);
    PFL_EXPECT(format_shadow_path(unsupported_ipv6_shadow) == "EthernetII -> IPv6");

    const auto zero_payload_ipv6_shadow = run_shadow(
        make_raw_packet(make_ethernet_ipv6_packet(
            ipv6_src_addr,
            ipv6_dst_addr,
            detail::kIpProtocolUdp,
            {}
        )),
        registry
    );
    PFL_EXPECT(zero_payload_ipv6_shadow.outcome == ImportDissectionOutcome::unrecognized);
    PFL_EXPECT(zero_payload_ipv6_shadow.stop_reason == StopReason::malformed);
    PFL_EXPECT(format_shadow_path(zero_payload_ipv6_shadow) == "EthernetII -> IPv6");

    const auto truncated_ipv6_extension_shadow = run_shadow(
        make_raw_packet(make_truncated_ethernet_ipv6_extension_packet(ipv6_src_addr, ipv6_dst_addr)),
        registry
    );
    PFL_EXPECT(truncated_ipv6_extension_shadow.outcome == ImportDissectionOutcome::unrecognized);
    PFL_EXPECT(truncated_ipv6_extension_shadow.stop_reason == StopReason::malformed);
    PFL_EXPECT(format_shadow_path(truncated_ipv6_extension_shadow) == "EthernetII -> IPv6");

    auto repeated_extensions_payload = make_ipv6_udp_segment(7000U, 8000U, 1U);
    repeated_extensions_payload = make_ipv6_hop_by_hop_extension(detail::kIpProtocolUdp, repeated_extensions_payload);
    for (std::size_t index = 0U; index < detail::kMaxIpv6ExtensionHeaders; ++index) {
        repeated_extensions_payload = make_ipv6_hop_by_hop_extension(detail::kIpProtocolHopByHop, repeated_extensions_payload);
    }
    const auto repeated_extensions_packet = make_raw_packet(make_ethernet_ipv6_packet(
        ipv6_src_addr,
        ipv6_dst_addr,
        detail::kIpProtocolHopByHop,
        repeated_extensions_payload
    ));
    StepKindRecorder repeated_extensions_recorder {};
    const DissectionEngine engine {};
    const auto repeated_extensions_result = engine.run(
        registry,
        make_link_type_selector(repeated_extensions_packet.data_link_type),
        make_root_slice(repeated_extensions_packet),
        DissectionConsumer {.on_step = record_step_kind, .context = &repeated_extensions_recorder},
        6U
    );
    const std::vector<DissectionLayerKind> expected_repeated_extension_kinds {
        DissectionLayerKind::ethernet_ii,
        DissectionLayerKind::ipv6,
        DissectionLayerKind::ipv6_hop_by_hop,
        DissectionLayerKind::ipv6_hop_by_hop,
        DissectionLayerKind::ipv6_hop_by_hop,
        DissectionLayerKind::ipv6_hop_by_hop,
    };
    PFL_EXPECT(repeated_extensions_result.stop_reason == StopReason::depth_limit);
    PFL_EXPECT(repeated_extensions_result.step_count == 6U);
    PFL_EXPECT(repeated_extensions_result.traversed_depth == 6U);
    PFL_EXPECT(repeated_extensions_recorder.kinds == expected_repeated_extension_kinds);

    const auto unknown_ethertype_shadow = run_shadow(
        make_raw_packet(std::vector<std::uint8_t> {
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
            0x12, 0x34,
            0xde, 0xad, 0xbe, 0xef,
        }),
        registry
    );
    PFL_EXPECT(unknown_ethertype_shadow.outcome == ImportDissectionOutcome::unrecognized);
    PFL_EXPECT(unknown_ethertype_shadow.stop_reason == StopReason::unknown_next_protocol);
    PFL_EXPECT(format_shadow_path(unknown_ethertype_shadow) == "EthernetII");

    const auto truncated_vlan_shadow = run_shadow(
        make_raw_packet(std::vector<std::uint8_t> {
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
            0x81, 0x00,
            0x00, 0x64,
        }, 18U),
        registry
    );
    PFL_EXPECT(truncated_vlan_shadow.outcome == ImportDissectionOutcome::unrecognized);
    PFL_EXPECT(truncated_vlan_shadow.stop_reason == StopReason::truncated);
    PFL_EXPECT(format_shadow_path(truncated_vlan_shadow) == "EthernetII");

    const auto arp_bytes = make_ethernet_arp_packet(ipv4(10, 10, 12, 2), ipv4(10, 10, 12, 1));
    const auto arp_shadow = run_shadow(make_raw_packet(arp_bytes), registry);
    PFL_EXPECT(arp_shadow.outcome == ImportDissectionOutcome::recognized_non_flow);
    PFL_EXPECT(arp_shadow.stop_reason == StopReason::terminal_protocol);
    PFL_EXPECT(arp_shadow.terminal_protocol == ProtocolId::arp);
    PFL_EXPECT(arp_shadow.has_arp_addresses);
    PFL_EXPECT(arp_shadow.arp_addresses.has_sender_ipv4);
    PFL_EXPECT(arp_shadow.arp_addresses.has_target_ipv4);
    PFL_EXPECT(arp_shadow.arp_addresses.sender_ipv4 == ipv4(10, 10, 12, 2));
    PFL_EXPECT(arp_shadow.arp_addresses.target_ipv4 == ipv4(10, 10, 12, 1));
    PFL_EXPECT(format_shadow_path(arp_shadow) == "EthernetII -> ARP");

    auto truncated_arp_packet = arp_bytes;
    truncated_arp_packet.resize(18U);
    const auto truncated_arp_shadow = run_shadow(
        make_raw_packet(truncated_arp_packet, static_cast<std::uint32_t>(arp_bytes.size())),
        registry
    );
    PFL_EXPECT(truncated_arp_shadow.outcome == ImportDissectionOutcome::unrecognized);
    PFL_EXPECT(truncated_arp_shadow.stop_reason == StopReason::truncated);
    PFL_EXPECT(format_shadow_path(truncated_arp_shadow) == "EthernetII");

    auto impossible_arp_packet = arp_bytes;
    impossible_arp_packet[18] = 6U;
    impossible_arp_packet[19] = 16U;
    const auto impossible_arp_shadow = run_shadow(make_raw_packet(impossible_arp_packet), registry);
    PFL_EXPECT(impossible_arp_shadow.outcome == ImportDissectionOutcome::unrecognized);
    PFL_EXPECT(impossible_arp_shadow.stop_reason == StopReason::malformed);
    PFL_EXPECT(impossible_arp_shadow.terminal_protocol == ProtocolId::unknown);
    PFL_EXPECT(format_shadow_path(impossible_arp_shadow) == "EthernetII");

    const auto truncated_ethernet_shadow = run_shadow(
        make_raw_packet(std::vector<std::uint8_t> {
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            0x66, 0x77, 0x88, 0x99,
        }),
        registry
    );
    PFL_EXPECT(truncated_ethernet_shadow.outcome == ImportDissectionOutcome::unrecognized);
    PFL_EXPECT(truncated_ethernet_shadow.stop_reason == StopReason::truncated);

    auto invalid_ihl_packet = make_ethernet_ipv4_tcp_packet(ipv4(10, 8, 0, 1), ipv4(10, 8, 0, 2), 1U, 2U);
    invalid_ihl_packet[14] = 0x44U;
    const auto invalid_ihl_shadow = run_shadow(make_raw_packet(invalid_ihl_packet), registry);
    PFL_EXPECT(invalid_ihl_shadow.outcome == ImportDissectionOutcome::unrecognized);
    PFL_EXPECT(invalid_ihl_shadow.stop_reason == StopReason::malformed);
    PFL_EXPECT(format_shadow_path(invalid_ihl_shadow) == "EthernetII");
}

void expect_linux_cooked_shadow_root_parsers_and_fixture_parity() {
    const auto built = make_common_direct_registry();
    PFL_REQUIRE(built.ok());
    const auto& registry = *built.registry;

    {
        const auto root = make_declared_root_slice(
            {
                0x12U, 0x34U,
                0x34U, 0x56U,
                0x00U, 0x06U,
                0x10U, 0x20U, 0x30U, 0x40U, 0x50U, 0x60U, 0x70U, 0x80U,
                0x08U, 0x00U,
            },
            detail::kLinuxSllHeaderSize
        );
        const auto parsed = parse_linux_sll_frame(root);
        PFL_EXPECT(parsed.status == ParseStatus::complete);
        PFL_EXPECT(!parsed.is_sll2);
        PFL_EXPECT(parsed.protocol_type == detail::kEtherTypeIpv4);
        PFL_EXPECT(parsed.packet_type == 0x1234U);
        PFL_EXPECT(parsed.hardware_type == 0x3456U);
        PFL_EXPECT(parsed.address_length == 6U);
        PFL_EXPECT(parsed.header_length == detail::kLinuxSllHeaderSize);
        PFL_EXPECT(parsed.declared_payload_length == 0U);

        const auto step = dissect_linux_sll(root);
        PFL_EXPECT(step.layer == DissectionLayerKind::linux_sll);
        PFL_REQUIRE(step.path_contribution.has_value());
        PFL_EXPECT(*step.path_contribution == LayerKey::linux_sll());
        PFL_EXPECT(step.path_commit_policy == PathCommitPolicy::recognized_flow_or_recognized_non_flow);
        PFL_REQUIRE(step.handoff.has_value());
        PFL_REQUIRE(step.handoff->child.has_value());
        PFL_EXPECT(step.handoff->selector.domain == SelectorDomain::linux_cooked_protocol);
        PFL_EXPECT(step.handoff->selector.value == detail::kEtherTypeIpv4);
        PFL_EXPECT(step.status == ParseStatus::complete);
        PFL_EXPECT(step.stop_reason == StopReason::none);
        PFL_EXPECT(step.bounds.full.declared.length() == detail::kLinuxSllHeaderSize);
        PFL_EXPECT(step.bounds.header.declared.length() == detail::kLinuxSllHeaderSize);
        PFL_REQUIRE(step.bounds.payload.has_value());
        PFL_EXPECT(step.bounds.payload->declared.length() == 0U);
        PFL_EXPECT(step.bounds.payload->captured.length() == 0U);
        PFL_EXPECT(std::holds_alternative<LinuxCookedFacts>(step.facts));
        const auto* facts = std::get_if<LinuxCookedFacts>(&step.facts);
        PFL_REQUIRE(facts != nullptr);
        PFL_EXPECT(!facts->is_sll2);
        PFL_EXPECT(facts->protocol_type == detail::kEtherTypeIpv4);
        PFL_EXPECT(facts->packet_type == 0x1234U);
        PFL_EXPECT(facts->hardware_type == 0x3456U);
        PFL_EXPECT(facts->address_length == 6U);
    }

    {
        const auto root = make_declared_root_slice(
            {
                0x86U, 0xddU,
                0x00U, 0x00U,
                0x10U, 0x20U, 0x30U, 0x40U,
                0x12U, 0x34U,
                0x11U,
                0x08U,
                0x31U, 0x32U, 0x33U, 0x34U, 0x35U, 0x36U, 0x37U, 0x38U,
            },
            detail::kLinuxSll2HeaderSize
        );
        const auto parsed = parse_linux_sll2_frame(root);
        PFL_EXPECT(parsed.status == ParseStatus::complete);
        PFL_EXPECT(parsed.is_sll2);
        PFL_EXPECT(parsed.protocol_type == detail::kEtherTypeIpv6);
        PFL_EXPECT(parsed.packet_type == 0x11U);
        PFL_EXPECT(parsed.hardware_type == 0x1234U);
        PFL_EXPECT(parsed.address_length == 8U);
        PFL_EXPECT(parsed.reserved == 0U);
        PFL_EXPECT(parsed.interface_index == 0x10203040U);
        PFL_EXPECT(parsed.header_length == detail::kLinuxSll2HeaderSize);
        PFL_EXPECT(parsed.declared_payload_length == 0U);

        const auto step = dissect_linux_sll2(root);
        PFL_EXPECT(step.layer == DissectionLayerKind::linux_sll2);
        PFL_REQUIRE(step.path_contribution.has_value());
        PFL_EXPECT(*step.path_contribution == LayerKey::linux_sll2());
        PFL_EXPECT(step.path_commit_policy == PathCommitPolicy::recognized_flow_or_recognized_non_flow);
        PFL_REQUIRE(step.handoff.has_value());
        PFL_REQUIRE(step.handoff->child.has_value());
        PFL_EXPECT(step.handoff->selector.domain == SelectorDomain::linux_cooked_protocol);
        PFL_EXPECT(step.handoff->selector.value == detail::kEtherTypeIpv6);
        PFL_EXPECT(std::holds_alternative<LinuxCookedFacts>(step.facts));
        const auto* facts = std::get_if<LinuxCookedFacts>(&step.facts);
        PFL_REQUIRE(facts != nullptr);
        PFL_EXPECT(facts->is_sll2);
        PFL_EXPECT(facts->interface_index == 0x10203040U);
        PFL_EXPECT(facts->reserved == 0U);
        PFL_EXPECT(facts->packet_type == 0x11U);
        PFL_EXPECT(facts->address_length == 8U);
    }

    {
        const auto truncated_root = make_declared_root_slice(
            {0x12U, 0x34U, 0x34U, 0x56U, 0x00U, 0x06U, 0x10U, 0x20U},
            8U
        );
        const auto parsed = parse_linux_sll_frame(truncated_root);
        PFL_EXPECT(parsed.status == ParseStatus::truncated);
        const auto step = dissect_linux_sll(truncated_root);
        PFL_EXPECT(step.layer == DissectionLayerKind::linux_sll);
        PFL_EXPECT(step.status == ParseStatus::truncated);
        PFL_EXPECT(step.stop_reason == StopReason::truncated);
        PFL_EXPECT(!step.path_contribution.has_value());
        PFL_EXPECT(!step.handoff.has_value());
        PFL_EXPECT(step.bounds.full.declared.length() == 8U);
        PFL_EXPECT(step.bounds.header.declared.length() == 8U);
    }

    {
        const auto arp_slice = make_declared_root_slice(
            {
                0x00U, 0x01U, 0x08U, 0x00U, 0x06U, 0x04U, 0x00U, 0x01U,
                0x00U, 0x11U, 0x22U, 0x33U, 0x44U, 0x55U,
                0xc0U, 0x00U, 0x02U, 0x0aU,
                0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
                0xc0U, 0x00U, 0x02U, 0x01U,
            },
            28U
        );
        const auto step = dissect_linux_cooked_arp(arp_slice);
        PFL_EXPECT(step.layer == DissectionLayerKind::arp);
        PFL_EXPECT(step.status == ParseStatus::complete);
        PFL_EXPECT(step.stop_reason == StopReason::terminal_protocol);
        PFL_EXPECT(!step.path_contribution.has_value());
        PFL_EXPECT(!step.handoff.has_value());
        PFL_EXPECT(step.terminal_disposition == TerminalDisposition::recognized_non_flow);
        PFL_EXPECT(std::holds_alternative<ArpFacts>(step.facts));
    }

    const std::vector<std::pair<const char*, const char*>> supported_flow_expectations {
        {"parsing/linux_cooked/01_sll_ipv4_tcp.pcap", "LinuxSll -> IPv4 -> TCP"},
        {"parsing/linux_cooked/02_sll_ipv6_udp.pcap", "LinuxSll -> IPv6 -> UDP"},
        {"parsing/linux_cooked/05_sll2_ipv4_tcp.pcap", "LinuxSll2 -> IPv4 -> TCP"},
        {"parsing/linux_cooked/06_sll2_ipv6_udp.pcap", "LinuxSll2 -> IPv6 -> UDP"},
        {"parsing/linux_cooked/15_sll_addrlen_8_ipv4_udp.pcap", "LinuxSll -> IPv4 -> UDP"},
        {"parsing/linux_cooked/16_sll_addrlen_12_ipv4_tcp.pcap", "LinuxSll -> IPv4 -> TCP"},
        {"parsing/linux_cooked/17_sll2_addrlen_8_ipv4_udp.pcap", "LinuxSll2 -> IPv4 -> UDP"},
        {"parsing/linux_cooked/18_sll2_addrlen_12_ipv6_udp.pcap", "LinuxSll2 -> IPv6 -> UDP"},
    };

    for (const auto& expectation : supported_flow_expectations) {
        expect_shadow_matches_legacy_flow(
            registry,
            require_raw_fixture_packet(expectation.first),
            expectation.second,
            StopReason::terminal_protocol
        );
    }

    expect_shadow_matches_legacy_recognized_non_flow(
        registry,
        require_raw_fixture_packet("parsing/linux_cooked/03_sll_arp.pcap"),
        "LinuxSll",
        "LinuxSll",
        StopReason::terminal_protocol
    );
    expect_shadow_matches_legacy_recognized_non_flow(
        registry,
        require_raw_fixture_packet("parsing/linux_cooked/07_sll2_arp.pcap"),
        "LinuxSll2",
        "LinuxSll2",
        StopReason::terminal_protocol
    );

    struct UnsupportedExpectation {
        const char* relative_path;
        StopReason expected_stop_reason;
    };

    const std::vector<UnsupportedExpectation> unsupported_expectations {
        {"parsing/linux_cooked/04_sll_vlan_ipv4_udp_unsupported.pcap", StopReason::unknown_next_protocol},
        {"parsing/linux_cooked/08_sll2_vlan_ipv6_tcp_unsupported.pcap", StopReason::unknown_next_protocol},
        {"parsing/linux_cooked/09_sll_truncated_header.pcap", StopReason::truncated},
        {"parsing/linux_cooked/10_sll2_truncated_header.pcap", StopReason::truncated},
        {"parsing/linux_cooked/11_sll_unknown_protocol.pcap", StopReason::unknown_next_protocol},
        {"parsing/linux_cooked/12_sll2_unknown_protocol.pcap", StopReason::unknown_next_protocol},
        {"parsing/linux_cooked/13_sll_truncated_inner_ipv4.pcap", StopReason::truncated},
        {"parsing/linux_cooked/14_sll2_truncated_inner_ipv6.pcap", StopReason::truncated},
    };

    for (const auto& expectation : unsupported_expectations) {
        const auto packet = require_raw_fixture_packet(expectation.relative_path);
        const auto legacy = decode_legacy_direct(packet);
        const auto shadow = run_shadow(packet, registry);
        PFL_EXPECT(!legacy.recognized_flow);
        PFL_EXPECT(shadow.outcome == ImportDissectionOutcome::unrecognized);
        PFL_EXPECT(shadow.stop_reason == expectation.expected_stop_reason);
        PFL_EXPECT(format_shadow_path(shadow).empty());
        PFL_EXPECT(!shadow.has_ports);
        PFL_EXPECT(!shadow.has_transport_payload_length);
        PFL_EXPECT(!shadow.has_tcp_flags);
    }
}

void expect_llc_snap_shadow_parsers_bounds_and_fixture_parity() {
    const auto built = make_common_direct_registry();
    PFL_REQUIRE(built.ok());
    const auto& registry = *built.registry;

    {
        const auto exact_header_slice = make_declared_root_slice(
            {0xaaU, 0xaaU, 0x03U, 0x00U, 0x00U, 0x00U, 0x08U, 0x00U},
            8U
        );
        const auto parsed = parse_llc_snap_payload(exact_header_slice);
        PFL_EXPECT(parsed.status == ParseStatus::complete);
        PFL_EXPECT(parsed.dsap == 0xaaU);
        PFL_EXPECT(parsed.ssap == 0xaaU);
        PFL_EXPECT(parsed.control == 0x03U);
        PFL_EXPECT(parsed.has_snap);
        PFL_EXPECT(parsed.oui == 0U);
        PFL_EXPECT(parsed.pid == detail::kEtherTypeIpv4);
        PFL_EXPECT(parsed.pid_supported);
        PFL_EXPECT(parsed.header_length == detail::kLlcSnapHeaderSize);

        const auto step = dissect_llc_snap(exact_header_slice);
        PFL_EXPECT(step.layer == DissectionLayerKind::llc_snap);
        PFL_REQUIRE(step.path_contribution.has_value());
        PFL_EXPECT(*step.path_contribution == LayerKey::llc_snap());
        PFL_EXPECT(step.path_commit_policy == PathCommitPolicy::recognized_flow_or_recognized_non_flow);
        PFL_REQUIRE(step.descendant_path_commit_policy.has_value());
        PFL_EXPECT(*step.descendant_path_commit_policy == PathCommitPolicy::recognized_flow_or_recognized_non_flow);
        PFL_EXPECT(step.defer_last_deferrable_path_contribution);
        PFL_REQUIRE(step.handoff.has_value());
        PFL_REQUIRE(step.handoff->child.has_value());
        PFL_EXPECT(step.handoff->selector.domain == SelectorDomain::llc_snap_pid);
        PFL_EXPECT(step.handoff->selector.value == detail::kEtherTypeIpv4);
        PFL_EXPECT(step.status == ParseStatus::complete);
        PFL_EXPECT(step.stop_reason == StopReason::none);
        PFL_EXPECT(step.bounds.full.declared.length() == 8U);
        PFL_EXPECT(step.bounds.full.captured.length() == 8U);
        PFL_EXPECT(step.bounds.header.declared.length() == 8U);
        PFL_EXPECT(step.bounds.header.captured.length() == 8U);
        PFL_REQUIRE(step.bounds.payload.has_value());
        PFL_EXPECT(step.bounds.payload->declared.length() == 0U);
        PFL_EXPECT(step.bounds.payload->captured.length() == 0U);
        PFL_EXPECT(std::holds_alternative<LlcSnapFacts>(step.facts));
        const auto* facts = std::get_if<LlcSnapFacts>(&step.facts);
        PFL_REQUIRE(facts != nullptr);
        PFL_EXPECT(facts->dsap == 0xaaU);
        PFL_EXPECT(facts->ssap == 0xaaU);
        PFL_EXPECT(facts->control == 0x03U);
        PFL_EXPECT(facts->has_snap);
        PFL_EXPECT(facts->oui == 0U);
        PFL_EXPECT(facts->pid == detail::kEtherTypeIpv4);
    }

    {
        const auto nonzero_oui_slice = make_declared_root_slice(
            {0xaaU, 0xaaU, 0x03U, 0x00U, 0x00U, 0xf8U, 0x08U, 0x00U},
            8U
        );
        const auto parsed = parse_llc_snap_payload(nonzero_oui_slice);
        PFL_EXPECT(parsed.status == ParseStatus::complete);
        PFL_EXPECT(parsed.has_snap);
        PFL_EXPECT(parsed.oui == 0x0000f8U);
        PFL_EXPECT(parsed.pid == detail::kEtherTypeIpv4);
        PFL_EXPECT(parsed.pid_supported);
    }

    {
        const auto unknown_pid_slice = make_declared_root_slice(
            {0xaaU, 0xaaU, 0x03U, 0x00U, 0x00U, 0x00U, 0x12U, 0x34U},
            8U
        );
        const auto parsed = parse_llc_snap_payload(unknown_pid_slice);
        PFL_EXPECT(parsed.status == ParseStatus::complete);
        PFL_EXPECT(parsed.has_snap);
        PFL_EXPECT(parsed.pid == 0x1234U);
        PFL_EXPECT(!parsed.pid_supported);

        const auto step = dissect_llc_snap(unknown_pid_slice);
        PFL_EXPECT(step.status == ParseStatus::complete);
        PFL_EXPECT(step.stop_reason == StopReason::unrecognized_payload);
        PFL_EXPECT(!step.path_contribution.has_value());
        PFL_EXPECT(!step.handoff.has_value());
    }

    {
        const auto dsap_only_slice = make_declared_root_slice({0xaaU}, 1U);
        const auto parsed = parse_llc_snap_payload(dsap_only_slice);
        PFL_EXPECT(parsed.status == ParseStatus::truncated);
        PFL_EXPECT(parsed.dsap == 0xaaU);
        PFL_EXPECT(parsed.header_length == 1U);
        const auto step = dissect_llc_snap(dsap_only_slice);
        PFL_EXPECT(step.status == ParseStatus::truncated);
        PFL_EXPECT(step.stop_reason == StopReason::truncated);
        PFL_EXPECT(!step.path_contribution.has_value());
    }

    {
        const auto dsap_ssap_slice = make_declared_root_slice({0xaaU, 0xaaU}, 2U);
        const auto parsed = parse_llc_snap_payload(dsap_ssap_slice);
        PFL_EXPECT(parsed.status == ParseStatus::truncated);
        PFL_EXPECT(parsed.dsap == 0xaaU);
        PFL_EXPECT(parsed.ssap == 0xaaU);
        PFL_EXPECT(parsed.header_length == 2U);
    }

    {
        const auto nonsnap_slice = make_declared_root_slice(
            {0xaaU, 0xaaU, 0x00U, 0x00U, 0x00U, 0x00U, 0x08U, 0x00U},
            8U
        );
        const auto parsed = parse_llc_snap_payload(nonsnap_slice);
        PFL_EXPECT(parsed.status == ParseStatus::complete);
        PFL_EXPECT(!parsed.has_snap);
        PFL_EXPECT(parsed.header_length == detail::kLlcHeaderSize);
        const auto step = dissect_llc_snap(nonsnap_slice);
        PFL_EXPECT(step.status == ParseStatus::complete);
        PFL_EXPECT(step.stop_reason == StopReason::unrecognized_payload);
        PFL_EXPECT(!step.path_contribution.has_value());
        PFL_EXPECT(step.bounds.full.declared.length() == detail::kLlcHeaderSize);
        PFL_EXPECT(step.bounds.header.declared.length() == detail::kLlcHeaderSize);
    }

    {
        const auto truncated_oui_slice = make_declared_root_slice({0xaaU, 0xaaU, 0x03U, 0x00U}, 4U);
        const auto parsed = parse_llc_snap_payload(truncated_oui_slice);
        PFL_EXPECT(parsed.status == ParseStatus::truncated);
        PFL_EXPECT(parsed.header_length == 4U);
        const auto truncated_pid_slice = make_declared_root_slice(
            {0xaaU, 0xaaU, 0x03U, 0x00U, 0x00U, 0x00U, 0x08U},
            7U
        );
        const auto truncated_pid = parse_llc_snap_payload(truncated_pid_slice);
        PFL_EXPECT(truncated_pid.status == ParseStatus::truncated);
        PFL_EXPECT(truncated_pid.header_length == 7U);
    }

    struct SupportedFlowExpectation {
        const char* relative_path;
        const char* expected_shadow_path;
        const char* expected_legacy_path;
        StopReason expected_stop_reason;
        bool recognized_non_flow;
    };

    const std::vector<SupportedFlowExpectation> supported_expectations {
        {"parsing/llc_snap/01_llc_snap_ipv4_tcp.pcap", "IEEE 802.3 -> LLC/SNAP -> IPv4 -> TCP", "IEEE 802.3 -> LLC/SNAP -> IPv4 -> TCP", StopReason::terminal_protocol, false},
        {"parsing/llc_snap/02_llc_snap_ipv4_udp.pcap", "IEEE 802.3 -> LLC/SNAP -> IPv4 -> UDP", "IEEE 802.3 -> LLC/SNAP -> IPv4 -> UDP", StopReason::terminal_protocol, false},
        {"parsing/llc_snap/03_llc_snap_ipv6_tcp.pcap", "IEEE 802.3 -> LLC/SNAP -> IPv6 -> TCP", "IEEE 802.3 -> LLC/SNAP -> IPv6 -> TCP", StopReason::terminal_protocol, false},
        {"parsing/llc_snap/04_llc_snap_ipv6_udp.pcap", "IEEE 802.3 -> LLC/SNAP -> IPv6 -> UDP", "IEEE 802.3 -> LLC/SNAP -> IPv6 -> UDP", StopReason::terminal_protocol, false},
        {"parsing/llc_snap/05_llc_snap_arp.pcap", "IEEE 802.3 -> LLC/SNAP", "IEEE 802.3 -> LLC/SNAP", StopReason::terminal_protocol, true},
        {"parsing/llc_snap/06_vlan_llc_snap_ipv4_tcp.pcap", "EthernetII -> VLAN(vid=100) -> LLC/SNAP -> IPv4 -> TCP", "EthernetII -> VLAN(vid=100) -> LLC/SNAP -> IPv4 -> TCP", StopReason::terminal_protocol, false},
        {"parsing/llc_snap/07_qinq_llc_snap_ipv4_udp.pcap", "EthernetII -> VLAN(vid=200) -> VLAN(vid=300) -> LLC/SNAP -> IPv4 -> UDP", "EthernetII -> VLAN(vid=200) -> VLAN(vid=300) -> LLC/SNAP -> IPv4 -> UDP", StopReason::terminal_protocol, false},
        {"parsing/llc_snap/09_llc_snap_nonzero_oui_ipv4_pid.pcap", "IEEE 802.3 -> LLC/SNAP -> IPv4 -> UDP", "IEEE 802.3 -> LLC/SNAP -> IPv4 -> UDP", StopReason::terminal_protocol, false},
        {"parsing/llc_snap/14_llc_snap_length_short_payload.pcap", "IEEE 802.3 -> LLC/SNAP -> IPv4 -> UDP", "IEEE 802.3 -> LLC/SNAP -> IPv4 -> UDP", StopReason::terminal_protocol, false},
        {"parsing/llc_snap/20_llc_snap_padding_after_declared_payload.pcap", "IEEE 802.3 -> LLC/SNAP -> IPv4 -> UDP", "IEEE 802.3 -> LLC/SNAP -> IPv4 -> UDP", StopReason::terminal_protocol, false},
        {"parsing/llc_snap/23_vlan_9100_llc_snap_ipv4_udp.pcap", "EthernetII -> VLAN(vid=413) -> LLC/SNAP -> IPv4 -> UDP", "EthernetII -> VLAN(vid=413) -> LLC/SNAP -> IPv4 -> UDP", StopReason::terminal_protocol, false},
    };

    for (const auto& expectation : supported_expectations) {
        const auto packet = require_raw_fixture_packet(expectation.relative_path);
        if (expectation.recognized_non_flow) {
            expect_shadow_matches_legacy_recognized_non_flow(
                registry,
                packet,
                expectation.expected_shadow_path,
                expectation.expected_legacy_path,
                expectation.expected_stop_reason
            );
        } else {
            expect_shadow_matches_legacy_flow(
                registry,
                packet,
                expectation.expected_shadow_path,
                expectation.expected_stop_reason
            );
        }
    }

    {
        const auto packet = require_raw_fixture_packet("parsing/llc_snap/20_llc_snap_padding_after_declared_payload.pcap");
        const auto root = make_root_slice(packet);
        const auto ethernet_step = dissect_ethernet(root);
        PFL_REQUIRE(ethernet_step.handoff.has_value());
        PFL_REQUIRE(ethernet_step.handoff->child.has_value());
        const auto& ieee8023_child = *ethernet_step.handoff->child;
        PFL_EXPECT(ieee8023_child.declared_end() < root.captured_end());
        const auto llc_snap_step = dissect_llc_snap(ieee8023_child);
        PFL_REQUIRE(llc_snap_step.bounds.payload.has_value());
        PFL_EXPECT(llc_snap_step.bounds.payload->declared.end() == ieee8023_child.declared_end());
        PFL_EXPECT(llc_snap_step.bounds.payload->captured.end() == ieee8023_child.captured_end());
    }

    struct UnsupportedFixtureExpectation {
        const char* relative_path;
        const char* expected_shadow_path;
        StopReason expected_stop_reason;
    };

    const std::vector<UnsupportedFixtureExpectation> unsupported_expectations {
        {"parsing/llc_snap/08_llc_snap_unknown_pid.pcap", "IEEE 802.3", StopReason::unrecognized_payload},
        {"parsing/llc_snap/10_llc_non_snap_ipx_like.pcap", "IEEE 802.3", StopReason::unrecognized_payload},
        {"parsing/llc_snap/11_llc_snap_truncated_llc_header.pcap", "", StopReason::malformed},
        {"parsing/llc_snap/12_llc_snap_truncated_snap_header.pcap", "", StopReason::malformed},
        {"parsing/llc_snap/13_llc_snap_truncated_inner_ipv4.pcap", "", StopReason::truncated},
        {"parsing/llc_snap/15_llc_snap_length_extra_payload.pcap", "", StopReason::malformed},
        {"parsing/llc_snap/16_llc_truncated_dsap_only.pcap", "IEEE 802.3", StopReason::truncated},
        {"parsing/llc_snap/17_llc_truncated_dsap_ssap.pcap", "IEEE 802.3", StopReason::truncated},
        {"parsing/llc_snap/18_llc_non_snap_control.pcap", "IEEE 802.3", StopReason::unrecognized_payload},
        {"parsing/llc_snap/19_llc_snap_declared_short_with_captured_tail.pcap", "IEEE 802.3", StopReason::truncated},
        {"parsing/llc_snap/21_llc_snap_truncated_inner_ipv6.pcap", "", StopReason::malformed},
        {"parsing/llc_snap/22_llc_snap_truncated_inner_arp.pcap", "", StopReason::truncated},
    };

    for (const auto& expectation : unsupported_expectations) {
        const auto packet = require_raw_fixture_packet(expectation.relative_path);
        const auto legacy = decode_legacy_direct(packet);
        const auto shadow = run_shadow(packet, registry);
        PFL_EXPECT(!legacy.recognized_flow);
        PFL_EXPECT(shadow.outcome == ImportDissectionOutcome::unrecognized);
        PFL_EXPECT(shadow.stop_reason == expectation.expected_stop_reason);
        PFL_EXPECT(format_shadow_path(shadow) == expectation.expected_shadow_path);
        PFL_EXPECT(!shadow.has_ports);
        PFL_EXPECT(!shadow.has_transport_payload_length);
        PFL_EXPECT(!shadow.has_tcp_flags);
    }
}

void expect_pppoe_ppp_shadow_parsers_bounds_and_fixture_parity() {
    const auto built = make_common_direct_registry();
    PFL_REQUIRE(built.ok());
    const auto& registry = *built.registry;

    {
        const auto supported_session_slice = make_declared_root_slice(
            {
                0x11U, 0x00U, 0x12U, 0x34U, 0x00U, 0x04U,
                0x00U, 0x21U, 0xaaU, 0xbbU,
            },
            10U
        );
        const auto parsed = parse_pppoe_frame(supported_session_slice, false);
        PFL_EXPECT(parsed.status == ParseStatus::complete);
        PFL_EXPECT(parsed.version == 1U);
        PFL_EXPECT(parsed.type == 1U);
        PFL_EXPECT(parsed.code == 0U);
        PFL_EXPECT(parsed.session_id == 0x1234U);
        PFL_EXPECT(parsed.payload_length == 4U);
        PFL_EXPECT(parsed.header_length == detail::kPppoeHeaderSize);
        PFL_EXPECT(parsed.declared_payload_length == 4U);
        PFL_EXPECT(parsed.logical_payload_length == 4U);
        PFL_EXPECT(!parsed.declared_payload_exceeds_capture);
        PFL_EXPECT(!parsed.captured_payload_exceeds_declared);

        const auto step = dissect_pppoe_session(supported_session_slice);
        PFL_EXPECT(step.layer == DissectionLayerKind::pppoe);
        PFL_REQUIRE(step.path_contribution.has_value());
        PFL_EXPECT(*step.path_contribution == LayerKey::pppoe());
        PFL_EXPECT(step.path_commit_policy == PathCommitPolicy::recognized_flow);
        PFL_REQUIRE(step.descendant_path_commit_policy.has_value());
        PFL_EXPECT(*step.descendant_path_commit_policy == PathCommitPolicy::recognized_flow);
        PFL_REQUIRE(step.handoff.has_value());
        PFL_REQUIRE(step.handoff->child.has_value());
        PFL_EXPECT(step.handoff->selector.domain == SelectorDomain::ppp_frame);
        PFL_EXPECT(step.handoff->selector.value == kPppFrameContinueSelectorValue);
        PFL_EXPECT(step.status == ParseStatus::complete);
        PFL_EXPECT(step.stop_reason == StopReason::none);
        PFL_EXPECT(step.bounds.full.declared.length() == 10U);
        PFL_EXPECT(step.bounds.header.declared.length() == 6U);
        PFL_REQUIRE(step.bounds.payload.has_value());
        PFL_EXPECT(step.bounds.payload->declared.length() == 4U);
        PFL_EXPECT(step.bounds.payload->captured.length() == 4U);
        const auto* facts = std::get_if<PppoeFacts>(&step.facts);
        PFL_REQUIRE(facts != nullptr);
        PFL_EXPECT(facts->version == 1U);
        PFL_EXPECT(facts->type == 1U);
        PFL_EXPECT(facts->code == 0U);
        PFL_EXPECT(facts->session_id == 0x1234U);
        PFL_EXPECT(facts->payload_length == 4U);
        PFL_EXPECT(!facts->is_discovery);
    }

    {
        const auto discovery_slice = make_declared_root_slice(
            {
                0x11U, 0x09U, 0x00U, 0x00U, 0x00U, 0x03U,
                0x01U, 0x02U, 0x03U,
            },
            9U
        );
        const auto parsed = parse_pppoe_frame(discovery_slice, true);
        PFL_EXPECT(parsed.status == ParseStatus::complete);
        PFL_EXPECT(parsed.is_discovery);
        PFL_EXPECT(parsed.code == 0x09U);
        const auto step = dissect_pppoe_discovery(discovery_slice);
        PFL_EXPECT(step.layer == DissectionLayerKind::pppoe);
        PFL_EXPECT(!step.path_contribution.has_value());
        PFL_EXPECT(!step.handoff.has_value());
        PFL_EXPECT(step.status == ParseStatus::complete);
        PFL_EXPECT(step.stop_reason == StopReason::terminal_protocol);
        const auto* facts = std::get_if<PppoeFacts>(&step.facts);
        PFL_REQUIRE(facts != nullptr);
        PFL_EXPECT(facts->is_discovery);
        PFL_EXPECT(facts->payload_length == 3U);
    }

    {
        const auto unsupported_version_slice = make_declared_root_slice(
            {
                0x21U, 0x00U, 0x12U, 0x34U, 0x00U, 0x04U,
                0x00U, 0x21U, 0xaaU, 0xbbU,
            },
            10U
        );
        const auto step = dissect_pppoe_session(unsupported_version_slice);
        PFL_EXPECT(step.layer == DissectionLayerKind::pppoe);
        PFL_EXPECT(!step.path_contribution.has_value());
        PFL_EXPECT(!step.handoff.has_value());
        PFL_EXPECT(step.status == ParseStatus::unsupported_variant);
        PFL_EXPECT(step.stop_reason == StopReason::unsupported_variant);
    }

    {
        const auto declared_shorter_slice = make_declared_root_slice(
            {
                0x11U, 0x00U, 0x00U, 0x00U, 0x00U, 0x04U,
                0x00U, 0x57U, 0xaaU, 0xbbU, 0xccU, 0xddU,
            },
            12U
        );
        const auto parsed = parse_pppoe_frame(declared_shorter_slice, false);
        PFL_EXPECT(parsed.status == ParseStatus::complete);
        PFL_EXPECT(parsed.logical_payload_length == 4U);
        PFL_EXPECT(parsed.captured_payload_exceeds_declared);
        PFL_EXPECT(!parsed.declared_payload_exceeds_capture);

        const auto step = dissect_pppoe_session(declared_shorter_slice);
        PFL_REQUIRE(step.bounds.payload.has_value());
        PFL_EXPECT(step.bounds.full.declared.length() == 10U);
        PFL_EXPECT(step.bounds.full.captured.length() == 10U);
        PFL_EXPECT(step.bounds.payload->declared.length() == 4U);
        PFL_EXPECT(step.bounds.payload->captured.length() == 4U);
    }

    {
        const auto declared_longer_slice = make_declared_root_slice(
            {
                0x11U, 0x00U, 0x12U, 0x34U, 0x00U, 0x08U,
                0x00U, 0x21U, 0xaaU,
            },
            14U
        );
        const auto parsed = parse_pppoe_frame(declared_longer_slice, false);
        PFL_EXPECT(parsed.status == ParseStatus::complete);
        PFL_EXPECT(parsed.logical_payload_length == 3U);
        PFL_EXPECT(parsed.declared_payload_exceeds_capture);
        PFL_EXPECT(!parsed.captured_payload_exceeds_declared);

        const auto step = dissect_pppoe_session(declared_longer_slice);
        PFL_REQUIRE(step.bounds.payload.has_value());
        PFL_EXPECT(step.bounds.full.declared.length() == 14U);
        PFL_EXPECT(step.bounds.full.captured.length() == 9U);
        PFL_EXPECT(step.bounds.payload->declared.length() == 8U);
        PFL_EXPECT(step.bounds.payload->captured.length() == 3U);
    }

    {
        const auto zero_session_slice = make_declared_root_slice(
            {
                0x11U, 0x00U, 0x00U, 0x00U, 0x00U, 0x02U,
                0x00U, 0x21U,
            },
            8U
        );
        const auto parsed = parse_pppoe_frame(zero_session_slice, false);
        PFL_EXPECT(parsed.status == ParseStatus::complete);
        PFL_EXPECT(parsed.session_id == 0U);
    }

    {
        const auto ppp_ipv6_slice = make_declared_root_slice(
            {0x00U, 0x57U, 0xaaU, 0xbbU},
            4U
        );
        const auto parsed = parse_ppp_frame(ppp_ipv6_slice);
        PFL_EXPECT(parsed.status == ParseStatus::complete);
        PFL_EXPECT(parsed.protocol == detail::kPppProtocolIpv6);
        PFL_EXPECT(parsed.header_length == detail::kPppProtocolFieldSize);
        PFL_EXPECT(parsed.declared_payload_length == 2U);

        const auto step = dissect_ppp(ppp_ipv6_slice);
        PFL_EXPECT(step.layer == DissectionLayerKind::ppp);
        PFL_REQUIRE(step.path_contribution.has_value());
        PFL_EXPECT(*step.path_contribution == LayerKey::ppp());
        PFL_EXPECT(step.path_commit_policy == PathCommitPolicy::recognized_flow);
        PFL_REQUIRE(step.descendant_path_commit_policy.has_value());
        PFL_EXPECT(*step.descendant_path_commit_policy == PathCommitPolicy::recognized_flow);
        PFL_REQUIRE(step.handoff.has_value());
        PFL_EXPECT(step.handoff->selector.domain == SelectorDomain::ppp_protocol);
        PFL_EXPECT(step.handoff->selector.value == detail::kPppProtocolIpv6);
        PFL_REQUIRE(step.bounds.payload.has_value());
        PFL_EXPECT(step.bounds.payload->declared.length() == 2U);
        PFL_EXPECT(step.bounds.payload->captured.length() == 2U);
        const auto* facts = std::get_if<PppFacts>(&step.facts);
        PFL_REQUIRE(facts != nullptr);
        PFL_EXPECT(facts->protocol == detail::kPppProtocolIpv6);
    }

    {
        const auto ppp_short_slice = make_declared_root_slice({0x00U}, 1U);
        const auto parsed = parse_ppp_frame(ppp_short_slice);
        PFL_EXPECT(parsed.status == ParseStatus::truncated);
        const auto step = dissect_ppp(ppp_short_slice);
        PFL_EXPECT(step.layer == DissectionLayerKind::ppp);
        PFL_EXPECT(step.status == ParseStatus::truncated);
        PFL_EXPECT(step.stop_reason == StopReason::truncated);
        PFL_EXPECT(!step.path_contribution.has_value());
        PFL_EXPECT(!step.handoff.has_value());
    }

    {
        const auto control_slice = make_declared_root_slice({0x01U, 0x02U, 0x03U}, 3U);
        const auto step = dissect_ppp_control(control_slice);
        PFL_EXPECT(step.layer == DissectionLayerKind::ppp_control);
        PFL_EXPECT(step.status == ParseStatus::complete);
        PFL_EXPECT(step.stop_reason == StopReason::terminal_protocol);
        PFL_REQUIRE(step.bounds.payload.has_value());
        PFL_EXPECT(step.bounds.payload->declared.length() == 3U);
    }

    struct SupportedFlowExpectation {
        const char* relative_path;
        const char* expected_shadow_path;
    };

    const std::vector<SupportedFlowExpectation> supported_expectations {
        {"parsing/pppoe/01_pppoe_session_ipv4_tcp.pcap", "EthernetII -> PPPoE -> PPP -> IPv4 -> TCP"},
        {"parsing/pppoe/02_pppoe_session_ipv4_udp.pcap", "EthernetII -> PPPoE -> PPP -> IPv4 -> UDP"},
        {"parsing/pppoe/03_pppoe_session_ipv6_tcp.pcap", "EthernetII -> PPPoE -> PPP -> IPv6 -> TCP"},
        {"parsing/pppoe/04_pppoe_session_ipv6_udp.pcap", "EthernetII -> PPPoE -> PPP -> IPv6 -> UDP"},
        {"parsing/pppoe/13_vlan_pppoe_session_ipv4_tcp.pcap", "EthernetII -> VLAN(vid=130) -> PPPoE -> PPP -> IPv4 -> TCP"},
        {"parsing/pppoe/14_qinq_pppoe_session_ipv4_udp.pcap", "EthernetII -> VLAN(vid=230) -> VLAN(vid=231) -> PPPoE -> PPP -> IPv4 -> UDP"},
        {"parsing/pppoe/19_pppoe_bad_length_short_payload.pcap", "EthernetII -> PPPoE -> PPP -> IPv4 -> UDP"},
        {"parsing/pppoe/23_pppoe_session_zero_session_id_ipv4_udp.pcap", "EthernetII -> PPPoE -> PPP -> IPv4 -> UDP"},
        {"parsing/pppoe/24_qinq_pppoe_session_ipv6_tcp.pcap", "EthernetII -> VLAN(vid=232) -> VLAN(vid=233) -> PPPoE -> PPP -> IPv6 -> TCP"},
        {"parsing/pppoe/25_legacy_9100_vlan_pppoe_session_ipv4_udp.pcap", "EthernetII -> VLAN(vid=330) -> PPPoE -> PPP -> IPv4 -> UDP"},
    };

    for (const auto& expectation : supported_expectations) {
        const ScopedTestContext fixture_context {"fixture=" + std::string {expectation.relative_path}};
        expect_shadow_matches_legacy_flow(
            registry,
            require_raw_fixture_packet(expectation.relative_path),
            expectation.expected_shadow_path,
            StopReason::terminal_protocol
        );
    }

    struct NoFlowExpectation {
        const char* relative_path;
        const char* expected_shadow_path;
        StopReason expected_stop_reason;
        std::vector<DissectionLayerKind> expected_kinds;
    };

    const std::vector<NoFlowExpectation> control_expectations {
        {"parsing/pppoe/05_pppoe_session_lcp_config_request.pcap", "EthernetII", StopReason::terminal_protocol, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::pppoe, DissectionLayerKind::ppp, DissectionLayerKind::ppp_control}},
        {"parsing/pppoe/06_pppoe_session_ipcp_config_request.pcap", "EthernetII", StopReason::terminal_protocol, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::pppoe, DissectionLayerKind::ppp, DissectionLayerKind::ppp_control}},
        {"parsing/pppoe/07_pppoe_session_ipv6cp_config_request.pcap", "EthernetII", StopReason::terminal_protocol, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::pppoe, DissectionLayerKind::ppp, DissectionLayerKind::ppp_control}},
        {"parsing/pppoe/08_pppoe_discovery_padi.pcap", "EthernetII", StopReason::terminal_protocol, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::pppoe}},
        {"parsing/pppoe/09_pppoe_discovery_pado.pcap", "EthernetII", StopReason::terminal_protocol, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::pppoe}},
        {"parsing/pppoe/10_pppoe_discovery_padr.pcap", "EthernetII", StopReason::terminal_protocol, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::pppoe}},
        {"parsing/pppoe/11_pppoe_discovery_pads.pcap", "EthernetII", StopReason::terminal_protocol, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::pppoe}},
        {"parsing/pppoe/12_pppoe_discovery_padt.pcap", "EthernetII", StopReason::terminal_protocol, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::pppoe}},
    };

    for (const auto& expectation : control_expectations) {
        const ScopedTestContext fixture_context {"fixture=" + std::string {expectation.relative_path}};
        const auto packet = require_raw_fixture_packet(expectation.relative_path);
        const auto legacy = decode_legacy_direct(packet);
        const auto shadow = run_shadow(packet, registry);
        const auto steps = collect_shadow_steps(packet, registry);
        std::vector<DissectionLayerKind> kinds {};
        for (const auto& step : steps) {
            kinds.push_back(step.layer);
        }

        PFL_EXPECT(!legacy.recognized_flow);
        PFL_EXPECT(shadow.outcome == ImportDissectionOutcome::unrecognized);
        PFL_EXPECT(shadow.stop_reason == expectation.expected_stop_reason);
        PFL_EXPECT(format_shadow_path(shadow) == expectation.expected_shadow_path);
        PFL_EXPECT((kinds == expectation.expected_kinds));

        const auto* pppoe_facts = find_pppoe_facts(steps);
        PFL_REQUIRE(pppoe_facts != nullptr);
        if (expectation.expected_kinds.size() == 2U) {
            PFL_EXPECT(pppoe_facts->is_discovery);
        } else {
            PFL_EXPECT(!pppoe_facts->is_discovery);
        }
    }

    struct UnsupportedExpectation {
        const char* relative_path;
        const char* expected_shadow_path;
        StopReason expected_stop_reason;
        std::vector<DissectionLayerKind> expected_kinds;
    };

    const std::vector<UnsupportedExpectation> unsupported_expectations {
        {"parsing/pppoe/15_pppoe_session_unknown_ppp_protocol.pcap", "EthernetII", StopReason::unknown_next_protocol, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::pppoe, DissectionLayerKind::ppp}},
        {"parsing/pppoe/16_pppoe_truncated_header.pcap", "EthernetII", StopReason::truncated, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::pppoe}},
        {"parsing/pppoe/17_pppoe_truncated_ppp_protocol.pcap", "EthernetII", StopReason::truncated, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::pppoe, DissectionLayerKind::ppp}},
        {"parsing/pppoe/18_pppoe_truncated_inner_ipv4.pcap", "EthernetII", StopReason::truncated, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::pppoe, DissectionLayerKind::ppp, DissectionLayerKind::ipv4}},
        {"parsing/pppoe/26_pppoe_session_declared_too_short_for_ppp_protocol_with_valid_trailer.pcap", "EthernetII", StopReason::truncated, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::pppoe, DissectionLayerKind::ppp}},
        {"parsing/pppoe/27_pppoe_session_capture_truncated_ipv4_udp_caplen_lt_origlen.pcap", "EthernetII", StopReason::truncated, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::pppoe, DissectionLayerKind::ppp, DissectionLayerKind::ipv4, DissectionLayerKind::udp}},
        {"parsing/pppoe/28_pppoe_session_unsupported_version_with_ipv4_trailer.pcap", "EthernetII", StopReason::unsupported_variant, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::pppoe}},
        {"parsing/pppoe/29_pppoe_session_unsupported_type_with_ipv4_trailer.pcap", "EthernetII", StopReason::unsupported_variant, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::pppoe}},
        {"parsing/pppoe/30_pppoe_session_unsupported_code_with_ipv4_trailer.pcap", "EthernetII", StopReason::unsupported_variant, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::pppoe}},
        {"parsing/pppoe/31_pppoe_session_zero_length_payload.pcap", "EthernetII", StopReason::truncated, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::pppoe, DissectionLayerKind::ppp}},
        {"parsing/pppoe/32_pppoe_session_truncated_inner_ipv6.pcap", "EthernetII", StopReason::malformed, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::pppoe, DissectionLayerKind::ppp, DissectionLayerKind::ipv6}},
    };

    for (const auto& expectation : unsupported_expectations) {
        const ScopedTestContext fixture_context {"fixture=" + std::string {expectation.relative_path}};
        const auto packet = require_raw_fixture_packet(expectation.relative_path);
        const auto legacy = decode_legacy_direct(packet);
        const auto shadow = run_shadow(packet, registry);
        const auto steps = collect_shadow_steps(packet, registry);
        std::vector<DissectionLayerKind> kinds {};
        for (const auto& step : steps) {
            kinds.push_back(step.layer);
        }

        PFL_EXPECT(!legacy.recognized_flow);
        PFL_EXPECT(shadow.outcome == ImportDissectionOutcome::unrecognized);
        PFL_EXPECT(shadow.stop_reason == expectation.expected_stop_reason);
        PFL_EXPECT(format_shadow_path(shadow) == expectation.expected_shadow_path);
        PFL_EXPECT((kinds == expectation.expected_kinds));
    }

    {
        const ScopedTestContext fixture_context {"fixture=parsing/pppoe/20_pppoe_bad_length_extra_payload.pcap"};
        const auto packet = require_raw_fixture_packet("parsing/pppoe/20_pppoe_bad_length_extra_payload.pcap");
        const auto legacy = decode_legacy_direct(packet);
        const auto shadow = run_shadow(packet, registry);
        const auto steps = collect_shadow_steps(packet, registry);
        std::vector<DissectionLayerKind> kinds {};
        for (const auto& step : steps) {
            kinds.push_back(step.layer);
        }

        // Known shadow parity gap:
        // - PPPoE declared payload length is 33 bytes.
        // - The inner IPv4 Total Length field is 37 bytes.
        // - Legacy bounded decoding accepts and recognizes the packet as a flow.
        // - The shadow PacketSlice model rejects the inner IPv4 child because it
        //   would extend beyond the enclosing declared PPPoE boundary.
        // This is an intentional production-cutover decision point, not an
        // ordinary unsupported-protocol case.
        PFL_EXPECT(legacy.recognized_flow);
        PFL_EXPECT(format_protocol_path(legacy.path) == "EthernetII -> PPPoE -> PPP -> IPv4 -> UDP");
        PFL_EXPECT(legacy.protocol == ProtocolId::udp);
        PFL_EXPECT(legacy.family == DissectionAddressFamily::ipv4);
        PFL_EXPECT(legacy.has_addresses);
        PFL_EXPECT(legacy.src_addr_v4 == ipv4(192, 0, 2, 30));
        PFL_EXPECT(legacy.dst_addr_v4 == ipv4(198, 51, 100, 30));
        PFL_EXPECT(legacy.has_ports);
        PFL_EXPECT(legacy.src_port == 53540U);
        PFL_EXPECT(legacy.dst_port == 443U);
        PFL_EXPECT(legacy.has_payload_length);
        PFL_EXPECT(legacy.captured_payload_length == 3U);

        PFL_EXPECT(shadow.outcome == ImportDissectionOutcome::unrecognized);
        PFL_EXPECT(shadow.stop_reason == StopReason::malformed);
        PFL_EXPECT(format_shadow_path(shadow) == "EthernetII");
        PFL_EXPECT((kinds == std::vector<DissectionLayerKind> {
            DissectionLayerKind::ethernet_ii,
            DissectionLayerKind::pppoe,
            DissectionLayerKind::ppp,
            DissectionLayerKind::ipv4,
        }));
    }

    {
        const ScopedTestContext fixture_context {"fixture=parsing/pppoe/21_pppoe_session_same_tuple_same_session_id.pcap"};
        const auto packets = require_raw_fixture_packets("parsing/pppoe/21_pppoe_session_same_tuple_same_session_id.pcap");
        PFL_EXPECT(packets.size() == 2U);
        for (const auto& packet : packets) {
            expect_shadow_matches_legacy_flow(
                registry,
                packet,
                "EthernetII -> PPPoE -> PPP -> IPv4 -> UDP",
                StopReason::terminal_protocol
            );
            const auto steps = collect_shadow_steps(packet, registry);
            const auto* pppoe_facts = find_pppoe_facts(steps);
            PFL_REQUIRE(pppoe_facts != nullptr);
            PFL_EXPECT(pppoe_facts->session_id == 0x3333U);
        }
    }

    {
        const ScopedTestContext fixture_context {"fixture=parsing/pppoe/22_pppoe_session_same_tuple_different_session_id.pcap"};
        const auto packets = require_raw_fixture_packets("parsing/pppoe/22_pppoe_session_same_tuple_different_session_id.pcap");
        PFL_EXPECT(packets.size() == 2U);
        const std::vector<std::uint16_t> expected_session_ids {0x3333U, 0x4444U};
        for (std::size_t index = 0U; index < packets.size(); ++index) {
            expect_shadow_matches_legacy_flow(
                registry,
                packets[index],
                "EthernetII -> PPPoE -> PPP -> IPv4 -> UDP",
                StopReason::terminal_protocol
            );
            const auto steps = collect_shadow_steps(packets[index], registry);
            const auto* pppoe_facts = find_pppoe_facts(steps);
            PFL_REQUIRE(pppoe_facts != nullptr);
            PFL_EXPECT(pppoe_facts->session_id == expected_session_ids[index]);
        }
    }

    {
        const ScopedTestContext fixture_context {"fixture=parsing/pppoe/33_pppoe_same_session_id_supported_and_unsupported_code.pcap"};
        const auto packets = require_raw_fixture_packets("parsing/pppoe/33_pppoe_same_session_id_supported_and_unsupported_code.pcap");
        PFL_EXPECT(packets.size() == 2U);

        expect_shadow_matches_legacy_flow(
            registry,
            packets[0],
            "EthernetII -> PPPoE -> PPP -> IPv4 -> UDP",
            StopReason::terminal_protocol
        );

        {
            const auto legacy = decode_legacy_direct(packets[1]);
            const auto shadow = run_shadow(packets[1], registry);
            const auto steps = collect_shadow_steps(packets[1], registry);
            std::vector<DissectionLayerKind> kinds {};
            for (const auto& step : steps) {
                kinds.push_back(step.layer);
            }

            PFL_EXPECT(!legacy.recognized_flow);
            PFL_EXPECT(shadow.outcome == ImportDissectionOutcome::unrecognized);
            PFL_EXPECT(shadow.stop_reason == StopReason::unsupported_variant);
            PFL_EXPECT(format_shadow_path(shadow) == "EthernetII");
            PFL_EXPECT((kinds == std::vector<DissectionLayerKind> {DissectionLayerKind::ethernet_ii, DissectionLayerKind::pppoe}));

            const auto* pppoe_facts = find_pppoe_facts(steps);
            PFL_REQUIRE(pppoe_facts != nullptr);
            PFL_EXPECT(pppoe_facts->session_id == 0x5555U);
            PFL_EXPECT(pppoe_facts->code == 0x01U);
        }
    }
}

void expect_pbb_shadow_parsers_bounds_and_fixture_parity() {
    const auto built = make_common_direct_registry();
    PFL_REQUIRE(built.ok());
    const auto& registry = *built.registry;

    {
        const auto exact_header_slice = make_declared_root_slice(
            {0xABU, 0x12U, 0x34U, 0x56U},
            4U
        );
        const auto parsed = parse_pbb_frame(exact_header_slice);
        PFL_EXPECT(parsed.status == ParseStatus::complete);
        PFL_EXPECT(parsed.pcp == 5U);
        PFL_EXPECT(!parsed.dei);
        PFL_EXPECT(parsed.nca);
        PFL_EXPECT(parsed.reserved == 3U);
        PFL_EXPECT(parsed.isid == 0x123456U);
        PFL_EXPECT(parsed.header_length == detail::kPbbITagSize);
        PFL_EXPECT(parsed.declared_payload_length == 0U);

        const auto step = dissect_pbb(exact_header_slice);
        PFL_EXPECT(step.layer == DissectionLayerKind::pbb);
        PFL_REQUIRE(step.path_contribution.has_value());
        PFL_EXPECT(*step.path_contribution == LayerKey::pbb(0x123456U));
        PFL_EXPECT(step.path_commit_policy == PathCommitPolicy::recognized_flow_or_recognized_non_flow);
        PFL_REQUIRE(step.descendant_path_commit_policy.has_value());
        PFL_EXPECT(*step.descendant_path_commit_policy == PathCommitPolicy::recognized_flow_or_recognized_non_flow);
        PFL_EXPECT(step.status == ParseStatus::complete);
        PFL_EXPECT(step.stop_reason == StopReason::truncated);
        PFL_EXPECT(!step.handoff.has_value());
        PFL_REQUIRE(step.bounds.payload.has_value());
        PFL_EXPECT(step.bounds.payload->declared.length() == 0U);
        PFL_EXPECT(step.bounds.payload->captured.length() == 0U);
        const auto* facts = std::get_if<PbbFacts>(&step.facts);
        PFL_REQUIRE(facts != nullptr);
        PFL_EXPECT(facts->pcp == 5U);
        PFL_EXPECT(!facts->dei);
        PFL_EXPECT(facts->nca);
        PFL_EXPECT(facts->reserved == 3U);
        PFL_EXPECT(facts->isid == 0x123456U);
    }

    {
        const auto truncated_slice = make_declared_root_slice({0x10U, 0x20U}, 4U);
        const auto parsed = parse_pbb_frame(truncated_slice);
        PFL_EXPECT(parsed.status == ParseStatus::truncated);
        const auto step = dissect_pbb(truncated_slice);
        PFL_EXPECT(step.layer == DissectionLayerKind::pbb);
        PFL_EXPECT(step.status == ParseStatus::truncated);
        PFL_EXPECT(step.stop_reason == StopReason::truncated);
        PFL_EXPECT(!step.path_contribution.has_value());
        PFL_EXPECT(!step.handoff.has_value());
    }

    {
        const auto inner_ipv4_slice = make_declared_root_slice(
            {
                0x20U, 0x12U, 0x34U, 0x56U,
                0x02U, 0x00U, 0x00U, 0x00U, 0x61U, 0x02U,
                0x02U, 0x00U, 0x00U, 0x00U, 0x61U, 0x01U,
                0x08U, 0x00U,
            },
            18U
        );
        const auto pbb_step = dissect_pbb(inner_ipv4_slice);
        PFL_REQUIRE(pbb_step.handoff.has_value());
        PFL_REQUIRE(pbb_step.handoff->child.has_value());
        const auto inner_step = dissect_pbb_inner_ethernet(*pbb_step.handoff->child);
        PFL_EXPECT(inner_step.layer == DissectionLayerKind::ethernet_ii);
        PFL_REQUIRE(inner_step.path_contribution.has_value());
        PFL_EXPECT(*inner_step.path_contribution == LayerKey::ethernet_ii());
        PFL_REQUIRE(inner_step.handoff.has_value());
        PFL_EXPECT(inner_step.handoff->selector.domain == SelectorDomain::pbb_inner_ether_type);
        PFL_EXPECT(inner_step.handoff->selector.value == detail::kEtherTypeIpv4);
    }

    {
        const auto inner_vlan_slice = make_declared_root_slice(
            {
                0x02U, 0x00U, 0x00U, 0x00U, 0x61U, 0x02U,
                0x02U, 0x00U, 0x00U, 0x00U, 0x61U, 0x01U,
                0x81U, 0x00U, 0x02U, 0x62U, 0x08U, 0x00U,
            },
            18U
        );
        const auto ethernet_step = dissect_pbb_inner_ethernet(inner_vlan_slice);
        PFL_REQUIRE(ethernet_step.handoff.has_value());
        PFL_REQUIRE(ethernet_step.handoff->child.has_value());
        const auto vlan_step = dissect_pbb_inner_vlan(*ethernet_step.handoff->child);
        PFL_EXPECT(vlan_step.layer == DissectionLayerKind::vlan);
        PFL_REQUIRE(vlan_step.path_contribution.has_value());
        PFL_EXPECT(*vlan_step.path_contribution == LayerKey::vlan(610U));
        PFL_REQUIRE(vlan_step.handoff.has_value());
        PFL_EXPECT(vlan_step.handoff->selector.domain == SelectorDomain::pbb_inner_ether_type);
        PFL_EXPECT(vlan_step.handoff->selector.value == detail::kEtherTypeIpv4);
    }

    struct SupportedFlowExpectation {
        const char* relative_path;
        const char* expected_shadow_path;
    };

    const std::vector<SupportedFlowExpectation> supported_expectations {
        {"parsing/pbb/01_pbb_ipv4_tcp.pcap", "EthernetII -> PBB(isid=0x123456) -> EthernetII -> IPv4 -> TCP"},
        {"parsing/pbb/02_pbb_ipv4_udp.pcap", "EthernetII -> PBB(isid=0x123456) -> EthernetII -> IPv4 -> UDP"},
        {"parsing/pbb/03_pbb_ipv6_tcp.pcap", "EthernetII -> PBB(isid=0x123456) -> EthernetII -> IPv6 -> TCP"},
        {"parsing/pbb/04_pbb_ipv6_udp.pcap", "EthernetII -> PBB(isid=0x123456) -> EthernetII -> IPv6 -> UDP"},
        {"parsing/pbb/06_pbb_inner_vlan_ipv4_tcp.pcap", "EthernetII -> PBB(isid=0x123456) -> EthernetII -> VLAN(vid=610) -> IPv4 -> TCP"},
        {"parsing/pbb/07_pbb_inner_qinq_ipv4_udp.pcap", "EthernetII -> PBB(isid=0x123456) -> EthernetII -> VLAN(vid=620) -> VLAN(vid=610) -> IPv4 -> UDP"},
        {"parsing/pbb/08_pbb_inner_llc_snap_ipv4_udp.pcap", "EthernetII -> PBB(isid=0x123456) -> IEEE 802.3 -> LLC/SNAP -> IPv4 -> UDP"},
        {"parsing/pbb/09_pbb_outer_btag_ipv4_udp.pcap", "EthernetII -> VLAN(vid=600) -> PBB(isid=0x123456) -> EthernetII -> IPv4 -> UDP"},
        {"parsing/pbb/10_pbb_outer_btag_inner_vlan_ipv4_tcp.pcap", "EthernetII -> VLAN(vid=600) -> PBB(isid=0x123456) -> EthernetII -> VLAN(vid=610) -> IPv4 -> TCP"},
        {"parsing/pbb/15_pbb_metadata_nondefault_itag.pcap", "EthernetII -> PBB(isid=0x654321) -> EthernetII -> IPv4 -> UDP"},
        {"parsing/pbb/18_pbb_zero_isid_ipv4_udp.pcap", "EthernetII -> PBB(isid=0x000000) -> EthernetII -> IPv4 -> UDP"},
        {"parsing/pbb/19_pbb_max_isid_ipv4_udp.pcap", "EthernetII -> PBB(isid=0xffffff) -> EthernetII -> IPv4 -> UDP"},
        {"parsing/pbb/20_pbb_outer_qinq_ipv6_udp.pcap", "EthernetII -> VLAN(vid=701) -> VLAN(vid=702) -> PBB(isid=0x123456) -> EthernetII -> IPv6 -> UDP"},
        {"parsing/pbb/21_pbb_outer_legacy_vlan_ipv4_udp.pcap", "EthernetII -> VLAN(vid=703) -> PBB(isid=0x123456) -> EthernetII -> IPv4 -> UDP"},
        {"parsing/pbb/27_pbb_extra_captured_tail_ipv4_udp.pcap", "EthernetII -> PBB(isid=0x123456) -> EthernetII -> IPv4 -> UDP"},
    };

    for (const auto& expectation : supported_expectations) {
        const ScopedTestContext fixture_context {"fixture=" + std::string {expectation.relative_path}};
        const auto packet = require_raw_fixture_packet(expectation.relative_path);
        expect_shadow_matches_legacy_flow(
            registry,
            packet,
            expectation.expected_shadow_path,
            StopReason::terminal_protocol
        );

        const auto steps = collect_shadow_steps(packet, registry);
        const auto* pbb = find_pbb_facts(steps);
        PFL_REQUIRE(pbb != nullptr);
        const auto expects_zero_isid = std::string {expectation.relative_path}.find("18_") != std::string::npos;
        PFL_EXPECT(pbb->isid != 0U || expects_zero_isid);
    }

    {
        const ScopedTestContext fixture_context {"fixture=parsing/pbb/05_pbb_arp.pcap"};
        const auto packet = require_raw_fixture_packet("parsing/pbb/05_pbb_arp.pcap");
        expect_shadow_matches_legacy_recognized_non_flow(
            registry,
            packet,
            "EthernetII -> PBB(isid=0x123456) -> EthernetII",
            "EthernetII -> PBB(isid=0x123456) -> EthernetII",
            StopReason::terminal_protocol
        );
    }

    {
        const ScopedTestContext fixture_context {"fixture=parsing/pbb/16_pbb_same_isid_same_inner_tuple_metadata_variation.pcap"};
        const auto packets = require_raw_fixture_packets("parsing/pbb/16_pbb_same_isid_same_inner_tuple_metadata_variation.pcap");
        PFL_EXPECT(packets.size() == 2U);
        for (const auto& packet : packets) {
            expect_shadow_matches_legacy_flow(
                registry,
                packet,
                "EthernetII -> PBB(isid=0x123456) -> EthernetII -> IPv4 -> UDP",
                StopReason::terminal_protocol
            );
        }
    }

    {
        const ScopedTestContext fixture_context {"fixture=parsing/pbb/17_pbb_different_isid_same_inner_tuple.pcap"};
        const auto packets = require_raw_fixture_packets("parsing/pbb/17_pbb_different_isid_same_inner_tuple.pcap");
        PFL_EXPECT(packets.size() == 2U);
        const std::vector<std::string> expected_paths {
            "EthernetII -> PBB(isid=0x123456) -> EthernetII -> IPv4 -> UDP",
            "EthernetII -> PBB(isid=0x123457) -> EthernetII -> IPv4 -> UDP",
        };
        for (std::size_t index = 0U; index < packets.size(); ++index) {
            expect_shadow_matches_legacy_flow(
                registry,
                packets[index],
                expected_paths[index],
                StopReason::terminal_protocol
            );
        }
    }

    struct UnsupportedExpectation {
        const char* relative_path;
        StopReason expected_stop_reason;
        std::vector<DissectionLayerKind> expected_kinds;
    };

    const std::vector<UnsupportedExpectation> unsupported_expectations {
        {"parsing/pbb/11_pbb_unknown_inner_ethertype.pcap", StopReason::unknown_next_protocol, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::pbb, DissectionLayerKind::ethernet_ii}},
        {"parsing/pbb/12_pbb_truncated_itag.pcap", StopReason::malformed, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::pbb}},
        {"parsing/pbb/13_pbb_truncated_inner_ethernet.pcap", StopReason::truncated, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::pbb, DissectionLayerKind::ethernet_ii}},
        {"parsing/pbb/14_pbb_truncated_inner_ipv4.pcap", StopReason::truncated, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::pbb, DissectionLayerKind::ethernet_ii, DissectionLayerKind::ipv4}},
        {"parsing/pbb/22_pbb_capture_truncated_inner_ipv4_caplen_lt_origlen.pcap", StopReason::truncated, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::pbb, DissectionLayerKind::ethernet_ii, DissectionLayerKind::ipv4}},
        {"parsing/pbb/23_pbb_complete_itag_no_inner_ethernet.pcap", StopReason::truncated, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::pbb}},
        {"parsing/pbb/24_pbb_truncated_inner_ipv6.pcap", StopReason::malformed, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::pbb, DissectionLayerKind::ethernet_ii, DissectionLayerKind::ipv6}},
        {"parsing/pbb/26_pbb_inner_pppoe_session_unsupported.pcap", StopReason::unknown_next_protocol, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::pbb, DissectionLayerKind::ethernet_ii}},
    };

    for (const auto& expectation : unsupported_expectations) {
        const ScopedTestContext fixture_context {"fixture=" + std::string {expectation.relative_path}};
        const auto packet = require_raw_fixture_packet(expectation.relative_path);
        const auto legacy = decode_legacy_direct(packet);
        const auto shadow = run_shadow(packet, registry);
        const auto steps = collect_shadow_steps(packet, registry);
        const auto kinds = collect_step_kinds(steps);

        PFL_EXPECT(!legacy.recognized_flow);
        PFL_EXPECT(shadow.outcome == ImportDissectionOutcome::unrecognized);
        PFL_EXPECT(shadow.stop_reason == expectation.expected_stop_reason);
        PFL_EXPECT(format_shadow_path(shadow) == "EthernetII");
        PFL_EXPECT((kinds == expectation.expected_kinds));
    }

    {
        const ScopedTestContext fixture_context {"fixture=parsing/pbb/25_pbb_truncated_inner_arp.pcap"};
        const auto packet = require_raw_fixture_packet("parsing/pbb/25_pbb_truncated_inner_arp.pcap");
        const auto shadow = run_shadow(packet, registry);
        const auto steps = collect_shadow_steps(packet, registry);
        const auto kinds = collect_step_kinds(steps);

        PFL_EXPECT(shadow.outcome != ImportDissectionOutcome::recognized_flow);
        PFL_EXPECT(!shadow.has_ports);
        PFL_EXPECT((kinds == std::vector<DissectionLayerKind> {
            DissectionLayerKind::ethernet_ii,
            DissectionLayerKind::pbb,
            DissectionLayerKind::ethernet_ii,
            DissectionLayerKind::arp,
        }));
    }
}

void expect_macsec_shadow_parsers_bounds_and_fixture_parity() {
    const auto built = make_common_direct_registry();
    PFL_REQUIRE(built.ok());
    const auto& registry = *built.registry;

    {
        const auto macsec_bytes = make_macsec_bytes(
            0xFDU,
            7U,
            0xA1B2C3D4U,
            {},
            true,
            0x0123456789ABCDEFULL
        );
        const auto slice = make_declared_root_slice(macsec_bytes, macsec_bytes.size());
        const auto parsed = parse_macsec_frame(slice);
        PFL_EXPECT(parsed.status == ParseStatus::complete);
        PFL_EXPECT(parsed.available_base_bytes == 6U);
        PFL_EXPECT(parsed.available_sci_bytes == 8U);
        PFL_EXPECT(parsed.tci_an == 0xFDU);
        PFL_EXPECT(parsed.version == 1U);
        PFL_EXPECT(parsed.end_station);
        PFL_EXPECT(parsed.sci_present);
        PFL_EXPECT(parsed.single_copy_broadcast);
        PFL_EXPECT(parsed.encrypted);
        PFL_EXPECT(parsed.changed_text);
        PFL_EXPECT(parsed.association_number == 1U);
        PFL_EXPECT(parsed.short_length == 7U);
        PFL_EXPECT(parsed.packet_number_present);
        PFL_EXPECT(parsed.packet_number == 0xA1B2C3D4U);
        PFL_EXPECT(parsed.has_sci);
        PFL_EXPECT(parsed.sci == 0x0123456789ABCDEFULL);
        PFL_EXPECT(!parsed.has_plain_ether_type);
        PFL_EXPECT(parsed.header_length == 14U);
        PFL_EXPECT(parsed.protected_payload_offset == 14U);
        PFL_EXPECT(parsed.protected_payload_length == 0U);
        PFL_EXPECT(parsed.icv_offset == 14U);
        PFL_EXPECT(parsed.icv_length == 16U);
        PFL_EXPECT(parsed.icv_complete);

        const auto step = dissect_macsec(slice);
        PFL_EXPECT(step.layer == DissectionLayerKind::macsec);
        PFL_EXPECT(!step.path_contribution.has_value());
        PFL_EXPECT(!step.handoff.has_value());
        PFL_EXPECT(step.terminal_disposition == TerminalDisposition::none);
        PFL_EXPECT(step.status == ParseStatus::complete);
        PFL_EXPECT(step.stop_reason == StopReason::encrypted_payload);
        PFL_EXPECT(step.bounds.full.declared.length() == macsec_bytes.size());
        PFL_EXPECT(step.bounds.header.declared.length() == 14U);
        PFL_REQUIRE(step.bounds.payload.has_value());
        PFL_EXPECT(step.bounds.payload->declared.length() == 0U);
        const auto* facts = std::get_if<MacsecFacts>(&step.facts);
        PFL_REQUIRE(facts != nullptr);
        PFL_EXPECT(facts->sci == 0x0123456789ABCDEFULL);
        PFL_EXPECT(facts->icv_complete);
    }

    for (std::uint8_t association_number = 0U; association_number < 4U; ++association_number) {
        const auto parsed = parse_macsec_frame(make_declared_root_slice(
            make_macsec_bytes(
                static_cast<std::uint8_t>(0x80U | association_number),
                0U,
                0xFFFFFFFFU
            ),
            22U
        ));
        PFL_EXPECT(parsed.status == ParseStatus::complete);
        PFL_EXPECT(parsed.version == 1U);
        PFL_EXPECT(parsed.association_number == association_number);
        PFL_EXPECT(parsed.packet_number == 0xFFFFFFFFU);
    }

    for (std::size_t length = 0U; length <= 5U; ++length) {
        std::vector<std::uint8_t> bytes {};
        for (std::size_t index = 0U; index < length; ++index) {
            bytes.push_back(static_cast<std::uint8_t>(0x10U + index));
        }
        const auto parsed = parse_macsec_frame(make_declared_root_slice(bytes, length));
        PFL_EXPECT(parsed.status == ParseStatus::truncated);
        PFL_EXPECT(parsed.available_base_bytes == length);
        PFL_EXPECT(!parsed.packet_number_present);
        if (length < 2U) {
            PFL_EXPECT(parsed.header_length == 2U);
        } else {
            PFL_EXPECT(parsed.header_length == 6U);
        }
    }

    {
        auto truncated_sci = make_macsec_bytes(0x20U, 0U, 0x01020304U, {}, true, 0x0102030405060708ULL, false);
        truncated_sci.resize(13U);
        const auto parsed = parse_macsec_frame(make_declared_root_slice(truncated_sci, truncated_sci.size()));
        PFL_EXPECT(parsed.status == ParseStatus::truncated);
        PFL_EXPECT(parsed.sci_present);
        PFL_EXPECT(parsed.available_sci_bytes == 7U);
        PFL_EXPECT(!parsed.has_sci);
        PFL_EXPECT(parsed.header_length == 14U);
    }

    for (std::size_t remaining = 1U; remaining < 16U; ++remaining) {
        std::vector<std::uint8_t> protected_payload {};
        for (std::size_t index = 0U; index < remaining; ++index) {
            protected_payload.push_back(static_cast<std::uint8_t>(0x30U + index));
        }
        const auto parsed = parse_macsec_frame(make_declared_root_slice(
            make_macsec_bytes(0x0CU, 0U, 0x01020304U, protected_payload, false, 0U, false),
            6U + remaining
        ));
        PFL_EXPECT(parsed.status == ParseStatus::truncated);
        PFL_EXPECT(parsed.protected_payload_length == remaining);
        PFL_EXPECT(parsed.icv_length == 0U);
        PFL_EXPECT(!parsed.icv_complete);
    }

    {
        const auto exact_icv = parse_macsec_frame(make_declared_root_slice(
            make_macsec_bytes(0x0CU, 0U, 0x01020304U),
            22U
        ));
        PFL_EXPECT(exact_icv.status == ParseStatus::complete);
        PFL_EXPECT(exact_icv.protected_payload_length == 0U);
        PFL_EXPECT(exact_icv.icv_length == 16U);
        PFL_EXPECT(exact_icv.icv_complete);

        const auto one_payload = parse_macsec_frame(make_declared_root_slice(
            make_macsec_bytes(0x0CU, 0U, 0x01020304U, {0x45U}),
            23U
        ));
        PFL_EXPECT(one_payload.status == ParseStatus::complete);
        PFL_EXPECT(one_payload.protected_payload_length == 1U);
        PFL_EXPECT(!one_payload.has_plain_ether_type);
    }

    {
        const auto plain = parse_macsec_frame(make_declared_root_slice(
            make_macsec_bytes(
                0x00U,
                4U,
                0x01020304U,
                {0x08U, 0x00U, 0xdeU, 0xadU, 0xbeU, 0xefU, 0xcaU, 0xfeU, 0xbaU, 0xbeU, 0x11U, 0x22U}
            ),
            34U
        ));
        PFL_EXPECT(plain.status == ParseStatus::complete);
        PFL_EXPECT(plain.short_length == 4U);
        PFL_EXPECT(plain.protected_payload_length == 12U);
        PFL_EXPECT(plain.has_plain_ether_type);
        PFL_EXPECT(plain.plain_ether_type == detail::kEtherTypeIpv4);

        const auto encrypted = parse_macsec_frame(make_declared_root_slice(
            make_macsec_bytes(0x08U, 0U, 0x01020304U, {0x08U, 0x00U}),
            24U
        ));
        PFL_EXPECT(!encrypted.has_plain_ether_type);

        const auto changed = parse_macsec_frame(make_declared_root_slice(
            make_macsec_bytes(0x04U, 0U, 0x01020304U, {0x08U, 0x00U}),
            24U
        ));
        PFL_EXPECT(!changed.has_plain_ether_type);
    }

    {
        ImportDissectionCollector collector {};
        collector.consume(DissectionStep {
            .layer = DissectionLayerKind::ethernet_ii,
            .path_contribution = LayerKey::ethernet_ii(),
            .status = ParseStatus::complete,
            .stop_reason = StopReason::none,
        });
        collector.consume(DissectionStep {
            .layer = DissectionLayerKind::macsec,
            .facts = MacsecFacts {
                .version = 1U,
                .association_number = 3U,
                .packet_number_present = true,
                .packet_number = 0xFFFFFFFFU,
                .protected_payload_offset = 6U,
                .protected_payload_length = 12U,
            },
            .status = ParseStatus::complete,
            .stop_reason = StopReason::encrypted_payload,
        });
        collector.finish(DissectionEngineResult {
            .stop_reason = StopReason::encrypted_payload,
            .step_count = 2U,
            .traversed_depth = 2U,
        });
        PFL_EXPECT(collector.facts().outcome == ImportDissectionOutcome::unrecognized);
        PFL_EXPECT(collector.facts().terminal_protocol == ProtocolId::unknown);
        PFL_EXPECT(!collector.facts().has_flow_addresses);
        PFL_EXPECT(!collector.facts().has_ports);
        PFL_EXPECT(!collector.facts().has_transport_payload_length);
        PFL_EXPECT(format_shadow_path(collector.facts()) == "EthernetII");
    }

    {
        const auto direct_packet = make_raw_packet(make_ethernet_frame_with_payload(
            detail::kEtherTypeMacsec,
            make_macsec_bytes(0x0CU, 0U, 0x01020304U, {0xdeU, 0xadU}, false, 0U, false)
        ));
        const auto shadow = run_shadow(direct_packet, registry);
        const auto steps = collect_shadow_steps(direct_packet, registry);
        PFL_EXPECT(shadow.outcome == ImportDissectionOutcome::unrecognized);
        PFL_EXPECT((collect_step_kinds(steps) == std::vector<DissectionLayerKind> {
            DissectionLayerKind::ethernet_ii,
            DissectionLayerKind::macsec,
        }));
        PFL_EXPECT(format_shadow_path(shadow) == "EthernetII");
    }

    {
        const auto nested_packet = make_raw_packet(make_ethernet_frame_with_payload(
            detail::kEtherTypeMacsec,
            make_macsec_bytes(
                0x00U,
                0U,
                0x01020304U,
                {0x88U, 0xe5U, 0x01U, 0x02U},
                false,
                0U,
                true
            )
        ));
        const auto steps = collect_shadow_steps(nested_packet, registry);
        PFL_EXPECT((collect_step_kinds(steps) == std::vector<DissectionLayerKind> {
            DissectionLayerKind::ethernet_ii,
            DissectionLayerKind::macsec,
        }));
    }

    {
        const auto gre_teb_macsec = make_raw_packet(make_ethernet_ipv4_gre_packet(
            ipv4(10, 92, 0, 1),
            ipv4(10, 92, 0, 2),
            make_gre_header(
                detail::kGreProtocolTypeTransparentEthernetBridging,
                make_ethernet_frame_with_payload(
                    detail::kEtherTypeMacsec,
                    make_macsec_bytes(0x0CU, 0U, 0x01020304U, {0xdeU, 0xadU}, false, 0U, false)
                )
            )
        ));
        const auto shadow = run_shadow(gre_teb_macsec, registry);
        const auto steps = collect_shadow_steps(gre_teb_macsec, registry);
        PFL_EXPECT(shadow.outcome == ImportDissectionOutcome::unrecognized);
        PFL_EXPECT(shadow.stop_reason == StopReason::unknown_next_protocol);
        PFL_EXPECT(format_shadow_path(shadow) == "EthernetII -> IPv4 -> GRE -> EthernetII");
        PFL_EXPECT((collect_step_kinds(steps) == std::vector<DissectionLayerKind> {
            DissectionLayerKind::ethernet_ii,
            DissectionLayerKind::ipv4,
            DissectionLayerKind::gre,
            DissectionLayerKind::ethernet_ii,
        }));
    }

    {
        const auto gre_teb_vlan_macsec = make_raw_packet(make_ethernet_ipv4_gre_packet(
            ipv4(10, 92, 1, 1),
            ipv4(10, 92, 1, 2),
            make_gre_header(
                detail::kGreProtocolTypeTransparentEthernetBridging,
                add_vlan_tags(
                    make_ethernet_frame_with_payload(
                        detail::kEtherTypeMacsec,
                        make_macsec_bytes(0x0CU, 0U, 0x01020304U, {0xdeU, 0xadU}, false, 0U, false)
                    ),
                    {{0x8100U, 131U}}
                )
            )
        ));
        const auto shadow = run_shadow(gre_teb_vlan_macsec, registry);
        const auto steps = collect_shadow_steps(gre_teb_vlan_macsec, registry);
        PFL_EXPECT(shadow.outcome == ImportDissectionOutcome::unrecognized);
        PFL_EXPECT(shadow.stop_reason == StopReason::unknown_next_protocol);
        PFL_EXPECT(format_shadow_path(shadow) == "EthernetII -> IPv4 -> GRE -> EthernetII -> VLAN(vid=131)");
        PFL_EXPECT((collect_step_kinds(steps) == std::vector<DissectionLayerKind> {
            DissectionLayerKind::ethernet_ii,
            DissectionLayerKind::ipv4,
            DissectionLayerKind::gre,
            DissectionLayerKind::ethernet_ii,
            DissectionLayerKind::vlan,
        }));
    }

    {
        const auto pbb_inner_macsec = make_raw_packet(make_ethernet_frame_with_payload(
            detail::kEtherTypePbb,
            [] {
                std::vector<std::uint8_t> payload {0x20U, 0x12U, 0x34U, 0x56U};
                const auto inner_frame = make_ethernet_frame_with_payload(
                    detail::kEtherTypeMacsec,
                    make_macsec_bytes(0x0CU, 0U, 0x01020304U, {0xdeU, 0xadU}, false, 0U, false)
                );
                payload.insert(payload.end(), inner_frame.begin(), inner_frame.end());
                return payload;
            }()
        ));
        const auto shadow = run_shadow(pbb_inner_macsec, registry);
        const auto steps = collect_shadow_steps(pbb_inner_macsec, registry);
        PFL_EXPECT(shadow.outcome == ImportDissectionOutcome::unrecognized);
        PFL_EXPECT(shadow.stop_reason == StopReason::unknown_next_protocol);
        PFL_EXPECT(format_shadow_path(shadow) == "EthernetII");
        PFL_EXPECT((collect_step_kinds(steps) == std::vector<DissectionLayerKind> {
            DissectionLayerKind::ethernet_ii,
            DissectionLayerKind::pbb,
            DissectionLayerKind::ethernet_ii,
        }));
        PFL_EXPECT(find_macsec_facts(steps) == nullptr);
    }

    {
        const auto linux_cooked_macsec = make_raw_packet(
            {
                0x12U, 0x34U,
                0x34U, 0x56U,
                0x00U, 0x06U,
                0x10U, 0x20U, 0x30U, 0x40U, 0x50U, 0x60U, 0x70U, 0x80U,
                0x88U, 0xe5U,
            },
            16U,
            kLinkTypeLinuxSll
        );
        const auto shadow = run_shadow(linux_cooked_macsec, registry);
        const auto steps = collect_shadow_steps(linux_cooked_macsec, registry);
        PFL_EXPECT(shadow.outcome == ImportDissectionOutcome::unrecognized);
        PFL_EXPECT(shadow.stop_reason == StopReason::unknown_next_protocol);
        PFL_EXPECT(format_shadow_path(shadow).empty());
        PFL_EXPECT((collect_step_kinds(steps) == std::vector<DissectionLayerKind> {
            DissectionLayerKind::linux_sll,
        }));
        PFL_EXPECT(find_macsec_facts(steps) == nullptr);
    }

    struct MacsecFixtureExpectation {
        const char* relative_path;
        const char* expected_shadow_path;
        StopReason expected_stop_reason;
        std::vector<DissectionLayerKind> expected_kinds;
        bool expect_plain_ether_type;
        std::uint32_t expected_packet_number;
        std::uint32_t expected_payload_length;
        std::uint32_t expected_icv_length;
        bool expect_icv_complete;
    };

    const std::vector<MacsecFixtureExpectation> expectations {
        {"parsing/macsec/01_macsec_basic_no_sci.pcap", "EthernetII", StopReason::encrypted_payload, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::macsec}, false, 0x01020304U, 24U, 16U, true},
        {"parsing/macsec/02_macsec_sci_present.pcap", "EthernetII", StopReason::encrypted_payload, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::macsec}, false, 0x01020304U, 24U, 16U, true},
        {"parsing/macsec/03_macsec_an2_nonzero_pn_sci.pcap", "EthernetII", StopReason::encrypted_payload, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::macsec}, false, 0x0A0B0C0DU, 24U, 16U, true},
        {"parsing/macsec/04_macsec_integrity_only_cleartext_like_payload.pcap", "EthernetII", StopReason::unrecognized_payload, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::macsec}, true, 0x01020304U, 35U, 16U, true},
        {"parsing/macsec/05_macsec_short_length_nonzero.pcap", "EthernetII", StopReason::encrypted_payload, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::macsec}, false, 0x01020304U, 32U, 16U, true},
        {"parsing/macsec/06_vlan_macsec_sci.pcap", "EthernetII -> VLAN(vid=700)", StopReason::encrypted_payload, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::vlan, DissectionLayerKind::macsec}, false, 0x01020304U, 24U, 16U, true},
        {"parsing/macsec/07_qinq_macsec_basic.pcap", "EthernetII -> VLAN(vid=710) -> VLAN(vid=720)", StopReason::encrypted_payload, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::vlan, DissectionLayerKind::vlan, DissectionLayerKind::macsec}, false, 0x01020304U, 24U, 16U, true},
        {"parsing/macsec/08_macsec_scb_flag.pcap", "EthernetII", StopReason::encrypted_payload, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::macsec}, false, 0x01020304U, 24U, 16U, true},
        {"parsing/macsec/09_macsec_es_flag.pcap", "EthernetII", StopReason::encrypted_payload, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::macsec}, false, 0x01020304U, 24U, 16U, true},
        {"parsing/macsec/10_macsec_truncated_base_sectag.pcap", "EthernetII", StopReason::truncated, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::macsec}, false, 0U, 0U, 0U, false},
        {"parsing/macsec/11_macsec_truncated_packet_number.pcap", "EthernetII", StopReason::truncated, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::macsec}, false, 0U, 0U, 0U, false},
        {"parsing/macsec/12_macsec_truncated_sci.pcap", "EthernetII", StopReason::truncated, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::macsec}, false, 0x01020304U, 0U, 0U, false},
        {"parsing/macsec/13_macsec_missing_icv_or_short_payload.pcap", "EthernetII", StopReason::truncated, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::macsec}, false, 0x01020304U, 15U, 0U, false},
        {"parsing/macsec/14_macsec_zero_packet_number.pcap", "EthernetII", StopReason::encrypted_payload, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::macsec}, false, 0x00000000U, 24U, 16U, true},
        {"parsing/macsec/15_macsec_protected_payload_ipv4_like_no_decode.pcap", "EthernetII", StopReason::encrypted_payload, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::macsec}, false, 0x01020304U, 38U, 16U, true},
        {"parsing/macsec/16_macsec_legacy_vlan_9100.pcap", "EthernetII -> VLAN(vid=730)", StopReason::encrypted_payload, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::vlan, DissectionLayerKind::macsec}, false, 0x01020304U, 24U, 16U, true},
        {"parsing/macsec/17_macsec_version1_max_packet_number.pcap", "EthernetII", StopReason::encrypted_payload, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::macsec}, false, 0xFFFFFFFFU, 24U, 16U, true},
        {"parsing/macsec/18_macsec_short_length_ignored_for_bounds.pcap", "EthernetII", StopReason::encrypted_payload, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::macsec}, false, 0x01020304U, 12U, 16U, true},
        {"parsing/macsec/19_macsec_caplen_lt_origlen_partial_icv.pcap", "EthernetII", StopReason::truncated, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::macsec}, false, 0x01020304U, 12U, 0U, false},
        {"parsing/macsec/20_macsec_plain_ether_type_one_byte_only.pcap", "EthernetII", StopReason::unrecognized_payload, {DissectionLayerKind::ethernet_ii, DissectionLayerKind::macsec}, false, 0x01020304U, 1U, 16U, true},
    };

    ProtocolPathRegistry shadow_path_registry {};
    for (const auto& expectation : expectations) {
        const ScopedTestContext fixture_context {"fixture=" + std::string {expectation.relative_path}};
        const auto packet = require_raw_fixture_packet(expectation.relative_path);
        const auto legacy = decode_legacy_direct(packet);
        const auto shadow = run_shadow(packet, registry);
        const auto steps = collect_shadow_steps(packet, registry);
        const auto kinds = collect_step_kinds(steps);
        const auto* macsec = find_macsec_facts(steps);

        PFL_EXPECT(!legacy.recognized_flow);
        PFL_EXPECT(shadow.outcome == ImportDissectionOutcome::unrecognized);
        PFL_EXPECT(shadow.stop_reason == expectation.expected_stop_reason);
        PFL_EXPECT(shadow.terminal_protocol == ProtocolId::unknown);
        PFL_EXPECT(!shadow.has_flow_addresses);
        PFL_EXPECT(!shadow.has_ports);
        PFL_EXPECT(!shadow.has_transport_payload_length);
        PFL_EXPECT(format_shadow_path(shadow) == expectation.expected_shadow_path);
        PFL_EXPECT(format_shadow_path(shadow).find("MACsec") == std::string::npos);
        PFL_EXPECT((kinds == expectation.expected_kinds));
        PFL_REQUIRE(macsec != nullptr);
        PFL_EXPECT(macsec->has_plain_ether_type == expectation.expect_plain_ether_type);
        PFL_EXPECT(macsec->packet_number == expectation.expected_packet_number);
        PFL_EXPECT(macsec->protected_payload_length == expectation.expected_payload_length);
        PFL_EXPECT(macsec->icv_length == expectation.expected_icv_length);
        PFL_EXPECT(macsec->icv_complete == expectation.expect_icv_complete);
        PFL_EXPECT(shadow_path_registry.intern(shadow_path(shadow)) != kInvalidProtocolPathId);
    }

    {
        const auto fixture_01 = run_shadow(require_raw_fixture_packet("parsing/macsec/01_macsec_basic_no_sci.pcap"), registry);
        const auto fixture_04 = run_shadow(
            require_raw_fixture_packet("parsing/macsec/04_macsec_integrity_only_cleartext_like_payload.pcap"),
            registry
        );
        const auto fixture_17 = run_shadow(
            require_raw_fixture_packet("parsing/macsec/17_macsec_version1_max_packet_number.pcap"),
            registry
        );

        ProtocolPathRegistry direct_registry {};
        const auto id_01 = direct_registry.intern(shadow_path(fixture_01));
        const auto id_04 = direct_registry.intern(shadow_path(fixture_04));
        const auto id_17 = direct_registry.intern(shadow_path(fixture_17));
        PFL_EXPECT(id_01 != kInvalidProtocolPathId);
        PFL_EXPECT(id_01 == id_04);
        PFL_EXPECT(id_01 == id_17);
        PFL_EXPECT(direct_registry.size() == 1U);
    }
}

}  // namespace

void run_common_direct_dissection_tests() {
    expect_common_direct_registry_and_root_selector();
    expect_import_dissection_collector_uses_explicit_path_commit_policies();
    expect_ethernet_and_vlan_canonical_parsers();
    expect_ipv4_tcp_udp_and_arp_canonical_parsers();
    expect_ipv6_and_extension_canonical_parsers();
    expect_sctp_canonical_parsers_and_bounds();
    expect_ah_and_esp_shadow_parsers_bounds_and_traversal();
    expect_mpls_shadow_parsers_bounds_and_traversal();
    expect_gre_shadow_parsers_bounds_and_traversal();
    expect_icmp_canonical_parsers_and_bounds();
    expect_igmp_canonical_parsers_and_bounds();
    expect_common_direct_steps_report_handoffs_bounds_and_facts();
    expect_ipv4_options_shadow_parsing_and_declared_boundary_semantics();
    expect_failed_layers_do_not_contribute_path_and_exact_arp_bounds();
    expect_fragmented_ipv4_preserves_selector_only_handoff();
    expect_sctp_fragmentation_preserves_selector_only_handoff();
    expect_icmp_fragmentation_preserves_selector_only_handoff();
    expect_igmp_fragmentation_preserves_selector_only_handoff();
    expect_plain_ip_encapsulation_is_registry_driven();
    expect_common_direct_supports_triple_vlan_and_depth_limits();
    expect_shadow_parity_for_common_direct_subset();
    expect_igmp_shadow_only_flow_behavior();
    expect_igmp_failures_remain_visible_without_path_contribution();
    expect_shadow_conservative_stops_and_arp_behavior();
    expect_linux_cooked_shadow_root_parsers_and_fixture_parity();
    expect_llc_snap_shadow_parsers_bounds_and_fixture_parity();
    expect_pppoe_ppp_shadow_parsers_bounds_and_fixture_parity();
    expect_pbb_shadow_parsers_bounds_and_fixture_parity();
    expect_macsec_shadow_parsers_bounds_and_fixture_parity();
}

}  // namespace pfl::tests
