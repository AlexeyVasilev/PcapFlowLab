#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>
#include <type_traits>
#include <utility>
#include <vector>

#include "TestSupport.h"
#include "core/dissection/DissectionEngine.h"
#include "core/dissection/DissectionRegistry.h"
#include "core/dissection/PacketSlice.h"
#include "core/dissection/DissectionTypes.h"

namespace pfl::tests {

namespace {

using namespace dissection;

static_assert(std::is_same_v<DissectorFn, DissectionStep (*)(const PacketSlice&)>);

constexpr ProtocolSelector kRootSelector {
    .domain = SelectorDomain::link_type,
    .value = 1U,
};

constexpr ProtocolSelector kEtherTypeIpv4Selector {
    .domain = SelectorDomain::ether_type,
    .value = 0x0800U,
};

constexpr ProtocolSelector kIpProtocolTcpSelector {
    .domain = SelectorDomain::ip_protocol,
    .value = 6U,
};

constexpr ProtocolSelector kIpProtocolUdpSelector {
    .domain = SelectorDomain::ip_protocol,
    .value = 17U,
};

constexpr ProtocolSelector kRepeatSelector {
    .domain = SelectorDomain::ether_type,
    .value = 0x8100U,
};

ByteRange require_range(const std::size_t begin, const std::size_t end) {
    const auto range = ByteRange::from_begin_end(begin, end);
    PFL_REQUIRE(range.has_value());
    return *range;
}

BoundedByteRange make_bounded_range(
    const std::size_t declared_begin,
    const std::size_t declared_end,
    const std::size_t captured_begin,
    const std::size_t captured_end
) {
    return BoundedByteRange {
        .declared = require_range(declared_begin, declared_end),
        .captured = require_range(captured_begin, captured_end),
    };
}

LayerBounds make_bounds(const PacketSlice& slice, const std::optional<ProtocolHandoff>& handoff = std::nullopt) {
    std::optional<BoundedByteRange> payload {};
    if (handoff.has_value() && handoff->child.has_value()) {
        payload = make_bounded_range(
            handoff->child->source_offset(),
            handoff->child->declared_end(),
            handoff->child->source_offset(),
            std::min(handoff->child->captured_end(), handoff->child->declared_end())
        );
    }

    return LayerBounds {
        .source_id = slice.source_id(),
        .full = make_bounded_range(
            slice.source_offset(),
            slice.declared_end(),
            slice.source_offset(),
            std::min(slice.captured_end(), slice.declared_end())
        ),
        .header = make_bounded_range(
            slice.source_offset(),
            slice.declared_end(),
            slice.source_offset(),
            std::min(slice.captured_end(), slice.declared_end())
        ),
        .payload = payload,
    };
}

DissectionStep make_step(
    const PacketSlice& slice,
    const LayerKey& layer,
    const ParseStatus status,
    const StopReason stop_reason,
    std::optional<ProtocolHandoff> handoff = std::nullopt,
    std::optional<LayerKey> path_contribution = std::nullopt,
    LayerFacts facts = std::monostate {},
    const TerminalDisposition terminal_disposition = TerminalDisposition::none
) {
    return DissectionStep {
        .layer = layer,
        .path_contribution = std::move(path_contribution),
        .bounds = make_bounds(slice, handoff),
        .handoff = std::move(handoff),
        .facts = std::move(facts),
        .terminal_disposition = terminal_disposition,
        .status = status,
        .stop_reason = stop_reason,
    };
}

DissectionStep ethernet_to_ipv4_dissector(const PacketSlice& slice) {
    const auto child = make_child_slice(slice, 14U, 28U);
    if (!child.has_slice()) {
        return make_step(
            slice,
            LayerKey::ethernet_ii(),
            ParseStatus::malformed,
            StopReason::malformed
        );
    }

    return make_step(
        slice,
        LayerKey::ethernet_ii(),
        ParseStatus::complete,
        StopReason::none,
        ProtocolHandoff {
            .selector = kEtherTypeIpv4Selector,
            .child = *child.slice,
        },
        LayerKey::vlan(0U),
        EthernetFacts {
            .protocol_type = 0x0800U,
            .is_ieee_802_3 = false,
        }
    );
}

DissectionStep ipv4_to_tcp_dissector(const PacketSlice& slice) {
    const auto child = make_child_slice(slice, 20U, 8U);
    if (!child.has_slice()) {
        return make_step(
            slice,
            LayerKey::ipv4(),
            ParseStatus::malformed,
            StopReason::malformed,
            std::nullopt,
            LayerKey::ipv4()
        );
    }

    return make_step(
        slice,
        LayerKey::ipv4(),
        ParseStatus::complete,
        StopReason::none,
        ProtocolHandoff {
            .selector = kIpProtocolTcpSelector,
            .child = *child.slice,
        },
        LayerKey::ipv4(),
        Ipv4Facts {
            .protocol = 6U,
            .total_length = 28U,
            .header_length = 20U,
            .src_addr_v4 = 0x0A000001U,
            .dst_addr_v4 = 0x0A000002U,
        }
    );
}

DissectionStep tcp_terminal_dissector(const PacketSlice& slice) {
    return make_step(
        slice,
        LayerKey::tcp(),
        ParseStatus::complete,
        StopReason::terminal_protocol,
        std::nullopt,
        LayerKey::tcp(),
        TcpFacts {
            .src_port = 1111U,
            .dst_port = 2222U,
            .flags = 0x18U,
        },
        TerminalDisposition::flow_candidate
    );
}

DissectionStep truncated_terminal_dissector(const PacketSlice& slice) {
    return make_step(
        slice,
        LayerKey::ipv4(),
        ParseStatus::truncated,
        StopReason::truncated,
        std::nullopt,
        LayerKey::ipv4()
    );
}

DissectionStep malformed_terminal_dissector(const PacketSlice& slice) {
    return make_step(
        slice,
        LayerKey::ipv4(),
        ParseStatus::malformed,
        StopReason::malformed,
        std::nullopt,
        LayerKey::ipv4()
    );
}

DissectionStep root_to_missing_selector_dissector(const PacketSlice& slice) {
    const auto child = make_child_slice(slice, 14U, 28U);
    if (!child.has_slice()) {
        return make_step(
            slice,
            LayerKey::ethernet_ii(),
            ParseStatus::malformed,
            StopReason::malformed
        );
    }

    return make_step(
        slice,
        LayerKey::ethernet_ii(),
        ParseStatus::complete,
        StopReason::none,
        ProtocolHandoff {
            .selector = kIpProtocolUdpSelector,
            .child = *child.slice,
        },
        LayerKey::ethernet_ii()
    );
}

DissectionStep stop_with_handoff_dissector(const PacketSlice& slice) {
    const auto child = make_child_slice(slice, 14U, 28U);
    if (!child.has_slice()) {
        return make_step(
            slice,
            LayerKey::ethernet_ii(),
            ParseStatus::malformed,
            StopReason::malformed
        );
    }

    return make_step(
        slice,
        LayerKey::ethernet_ii(),
        ParseStatus::unsupported_variant,
        StopReason::unsupported_variant,
        ProtocolHandoff {
            .selector = kEtherTypeIpv4Selector,
            .child = *child.slice,
        },
        LayerKey::ethernet_ii()
    );
}

DissectionStep no_handoff_dissector(const PacketSlice& slice) {
    return make_step(
        slice,
        LayerKey::ethernet_ii(),
        ParseStatus::complete,
        StopReason::none,
        std::nullopt,
        LayerKey::ethernet_ii()
    );
}

DissectionStep missing_child_handoff_dissector(const PacketSlice& slice) {
    return make_step(
        slice,
        LayerKey::ethernet_ii(),
        ParseStatus::complete,
        StopReason::none,
        ProtocolHandoff {
            .selector = kEtherTypeIpv4Selector,
            .child = std::nullopt,
        },
        LayerKey::ethernet_ii()
    );
}

DissectionStep repeat_vlan_dissector(const PacketSlice& slice) {
    const auto child = make_child_slice(slice, 0U, slice.declared_end() - slice.source_offset());
    if (!child.has_slice()) {
        return make_step(
            slice,
            LayerKey::vlan(7U),
            ParseStatus::malformed,
            StopReason::malformed,
            std::nullopt,
            LayerKey::vlan(7U)
        );
    }

    return make_step(
        slice,
        LayerKey::vlan(7U),
        ParseStatus::complete,
        StopReason::none,
        ProtocolHandoff {
            .selector = kRepeatSelector,
            .child = *child.slice,
        },
        LayerKey::vlan(7U),
        VlanFacts {
            .tci = 7U,
            .encapsulated_ether_type = static_cast<std::uint16_t>(kRepeatSelector.value),
        }
    );
}

struct RecordedStep {
    ProtocolLayerKind kind {ProtocolLayerKind::unknown};
    std::size_t full_begin {0U};
    StopReason stop_reason {StopReason::none};
    bool has_handoff {false};
    bool has_child {false};
    bool has_path_contribution {false};
    ProtocolLayerKind path_kind {ProtocolLayerKind::unknown};
    ProtocolLayerIdentifierKind path_identifier_kind {ProtocolLayerIdentifierKind::none};
    std::uint64_t path_value {0U};
};

struct StepRecorder {
    std::vector<RecordedStep> steps {};
};

void record_step(void* context, const DissectionStep& step) {
    auto* recorder = static_cast<StepRecorder*>(context);
    recorder->steps.push_back(RecordedStep {
        .kind = step.layer.kind,
        .full_begin = step.bounds.full.declared.begin(),
        .stop_reason = step.stop_reason,
        .has_handoff = step.handoff.has_value(),
        .has_child = step.handoff.has_value() && step.handoff->child.has_value(),
        .has_path_contribution = step.path_contribution.has_value(),
        .path_kind = step.path_contribution.has_value() ? step.path_contribution->kind : ProtocolLayerKind::unknown,
        .path_identifier_kind = step.path_contribution.has_value()
            ? step.path_contribution->identifier.kind
            : ProtocolLayerIdentifierKind::none,
        .path_value = step.path_contribution.has_value() ? step.path_contribution->identifier.value : 0U,
    });
}

void expect_byte_range_helpers() {
    const auto direct_range = ByteRange::from_begin_end(3U, 9U);
    PFL_REQUIRE(direct_range.has_value());
    PFL_EXPECT(direct_range->begin() == 3U);
    PFL_EXPECT(direct_range->end() == 9U);
    PFL_EXPECT(direct_range->length() == 6U);
    PFL_EXPECT(!direct_range->empty());

    const auto zero_length_range = ByteRange::from_begin_and_length(5U, 0U);
    PFL_REQUIRE(zero_length_range.has_value());
    PFL_EXPECT(zero_length_range->begin() == 5U);
    PFL_EXPECT(zero_length_range->end() == 5U);
    PFL_EXPECT(zero_length_range->empty());

    const auto invalid_reverse_range = ByteRange::from_begin_end(9U, 3U);
    PFL_EXPECT(!invalid_reverse_range.has_value());

    const auto overflow_length_range = ByteRange::from_begin_and_length(
        std::numeric_limits<std::size_t>::max() - 2U,
        8U
    );
    PFL_EXPECT(!overflow_length_range.has_value());
}

void expect_layer_bounds_facts_and_terminal_disposition_model() {
    const std::array<std::uint8_t, 32> bytes {
        0U, 1U, 2U, 3U, 4U, 5U, 6U, 7U,
        8U, 9U, 10U, 11U, 12U, 13U, 14U, 15U,
        16U, 17U, 18U, 19U, 20U, 21U, 22U, 23U,
        24U, 25U, 26U, 27U, 28U, 29U, 30U, 31U,
    };
    const auto root = make_root_packet_slice(ByteSourceId::captured_frame(10U), bytes, 20U, 30U);
    const auto child = make_child_slice(root, 12U, 10U);
    PFL_REQUIRE(child.has_slice());

    const auto step = make_step(
        root,
        LayerKey::ipv4(),
        ParseStatus::complete,
        StopReason::none,
        ProtocolHandoff {
            .selector = kIpProtocolTcpSelector,
            .child = *child.slice,
        },
        LayerKey::vlan(7U),
        Ipv4Facts {
            .protocol = 6U,
            .total_length = 30U,
            .header_length = 20U,
            .src_addr_v4 = 0x0A000001U,
            .dst_addr_v4 = 0x0A000002U,
            .is_fragmented = true,
            .more_fragments = true,
            .fragment_offset_units = 3U,
        },
        TerminalDisposition::flow_candidate
    );

    PFL_EXPECT(step.bounds.source_id == ByteSourceId::captured_frame(10U));
    PFL_EXPECT(step.bounds.full.declared == require_range(0U, 30U));
    PFL_EXPECT(step.bounds.full.captured == require_range(0U, 20U));
    PFL_EXPECT(step.bounds.header.declared == require_range(0U, 30U));
    PFL_EXPECT(step.bounds.header.captured == require_range(0U, 20U));
    PFL_REQUIRE(step.bounds.payload.has_value());
    PFL_EXPECT(step.bounds.payload->declared == require_range(12U, 22U));
    PFL_EXPECT(step.bounds.payload->captured == require_range(12U, 20U));
    PFL_REQUIRE(step.path_contribution.has_value());
    PFL_EXPECT(*step.path_contribution == LayerKey::vlan(7U));
    PFL_EXPECT(step.terminal_disposition == TerminalDisposition::flow_candidate);
    PFL_EXPECT(std::holds_alternative<Ipv4Facts>(step.facts));
    const auto* ipv4 = std::get_if<Ipv4Facts>(&step.facts);
    PFL_REQUIRE(ipv4 != nullptr);
    PFL_EXPECT(ipv4->protocol == 6U);
    PFL_EXPECT(ipv4->is_fragmented);
    PFL_EXPECT(ipv4->fragment_offset_units == 3U);
}

void expect_root_packet_slice_bounds() {
    const std::array<std::uint8_t, 8> bytes {0U, 1U, 2U, 3U, 4U, 5U, 6U, 7U};

    const auto equal_root = make_root_packet_slice(ByteSourceId::captured_frame(11U), bytes, 8U, 8U);
    PFL_EXPECT(equal_root.source_id() == ByteSourceId::captured_frame(11U));
    PFL_EXPECT(equal_root.source_offset() == 0U);
    PFL_EXPECT(equal_root.captured_end() == 8U);
    PFL_EXPECT(equal_root.reported_end() == 8U);
    PFL_EXPECT(equal_root.declared_end() == 8U);
    PFL_EXPECT(equal_root.captured_size() == 8U);

    const auto truncated_root = make_root_packet_slice(ByteSourceId::captured_frame(12U), bytes, 4U, 8U);
    PFL_EXPECT(truncated_root.captured_end() == 4U);
    PFL_EXPECT(truncated_root.reported_end() == 8U);
    PFL_EXPECT(truncated_root.declared_end() == 8U);
    PFL_EXPECT(truncated_root.captured_size() == 4U);

    const auto overcaptured_root = make_root_packet_slice(ByteSourceId::captured_frame(13U), bytes, 12U, 6U);
    PFL_EXPECT(overcaptured_root.captured_end() == 8U);
    PFL_EXPECT(overcaptured_root.reported_end() == 6U);
    PFL_EXPECT(overcaptured_root.declared_end() == 6U);
    PFL_EXPECT(overcaptured_root.captured_size() == 8U);
}

void expect_child_packet_slice_bounds_and_failures() {
    const std::array<std::uint8_t, 32> bytes {
        0U, 1U, 2U, 3U, 4U, 5U, 6U, 7U,
        8U, 9U, 10U, 11U, 12U, 13U, 14U, 15U,
        16U, 17U, 18U, 19U, 20U, 21U, 22U, 23U,
        24U, 25U, 26U, 27U, 28U, 29U, 30U, 31U,
    };

    const auto parent = make_root_packet_slice(ByteSourceId::captured_frame(21U), bytes, 12U, 20U);
    const auto full_parent = make_root_packet_slice(ByteSourceId::captured_frame(22U), bytes, 12U, 12U);

    const auto child = make_child_slice(parent, 2U, 4U);
    PFL_REQUIRE(child.has_slice());
    PFL_EXPECT(child.success());
    PFL_EXPECT(child.slice->source_offset() == 2U);
    PFL_EXPECT(child.slice->captured_end() == 6U);
    PFL_EXPECT(child.slice->reported_end() == 20U);
    PFL_EXPECT(child.slice->declared_end() == 6U);
    PFL_EXPECT(child.slice->captured_size() == 4U);

    const auto zero_length_child = make_child_slice(parent, 3U, 0U);
    PFL_REQUIRE(zero_length_child.has_slice());
    PFL_EXPECT(zero_length_child.success());
    PFL_EXPECT(zero_length_child.slice->source_offset() == 3U);
    PFL_EXPECT(zero_length_child.slice->captured_end() == 3U);
    PFL_EXPECT(zero_length_child.slice->declared_end() == 3U);
    PFL_EXPECT(zero_length_child.slice->captured_size() == 0U);

    const auto boundary_child = make_child_slice(full_parent, 6U, 6U);
    PFL_REQUIRE(boundary_child.has_slice());
    PFL_EXPECT(boundary_child.success());
    PFL_EXPECT(boundary_child.slice->captured_end() == 12U);
    PFL_EXPECT(boundary_child.slice->declared_end() == 12U);
    PFL_EXPECT(boundary_child.slice->captured_size() == 6U);

    const auto truncated_child = make_child_slice(parent, 8U, 8U);
    PFL_REQUIRE(truncated_child.has_slice());
    PFL_EXPECT(truncated_child.truncated());
    PFL_EXPECT(truncated_child.slice->source_offset() == 8U);
    PFL_EXPECT(truncated_child.slice->captured_end() == 12U);
    PFL_EXPECT(truncated_child.slice->reported_end() == 20U);
    PFL_EXPECT(truncated_child.slice->declared_end() == 16U);
    PFL_EXPECT(truncated_child.slice->captured_size() == 4U);

    const auto offset_past_reported = make_child_slice(full_parent, 13U, 1U);
    PFL_EXPECT(!offset_past_reported.has_slice());
    PFL_EXPECT(offset_past_reported.status == PacketSliceBuildStatus::offset_outside_reported_range);

    const auto narrowed_child = make_child_slice(parent, 4U, 8U);
    PFL_REQUIRE(narrowed_child.has_slice());
    PFL_EXPECT(narrowed_child.success());
    PFL_EXPECT(narrowed_child.slice->reported_end() == 20U);
    PFL_EXPECT(narrowed_child.slice->declared_end() == 12U);

    const auto nested_offset_past_declared = make_child_slice(*narrowed_child.slice, 9U, 1U);
    PFL_EXPECT(!nested_offset_past_declared.has_slice());
    PFL_EXPECT(nested_offset_past_declared.status == PacketSliceBuildStatus::offset_outside_declared_range);

    const auto nested_range_past_declared = make_child_slice(*narrowed_child.slice, 6U, 3U);
    PFL_EXPECT(!nested_range_past_declared.has_slice());
    PFL_EXPECT(nested_range_past_declared.status == PacketSliceBuildStatus::child_range_outside_declared_range);

    const auto range_past_reported = make_child_slice(full_parent, 11U, 2U);
    PFL_EXPECT(!range_past_reported.has_slice());
    PFL_EXPECT(range_past_reported.status == PacketSliceBuildStatus::child_range_outside_reported_range);

    const auto offset_past_reported_large = make_child_slice(parent, std::numeric_limits<std::size_t>::max(), 1U);
    PFL_EXPECT(!offset_past_reported_large.has_slice());
    PFL_EXPECT(offset_past_reported_large.status == PacketSliceBuildStatus::offset_outside_reported_range);

    const auto huge_reported_parent = make_root_packet_slice(
        ByteSourceId::captured_frame(23U),
        std::span<const std::uint8_t> {},
        0U,
        std::numeric_limits<std::size_t>::max()
    );
    const auto range_overflow = make_child_slice(
        huge_reported_parent,
        std::numeric_limits<std::size_t>::max() - 3U,
        8U
    );
    PFL_EXPECT(!range_overflow.has_slice());
    PFL_EXPECT(range_overflow.status == PacketSliceBuildStatus::offset_overflow);

    const auto huge_child = make_child_slice(
        huge_reported_parent,
        std::numeric_limits<std::size_t>::max() - 4U,
        4U
    );
    PFL_REQUIRE(huge_child.has_slice());
    const auto nested_offset_overflow = make_child_slice(*huge_child.slice, 8U, 1U);
    PFL_EXPECT(!nested_offset_overflow.has_slice());
    PFL_EXPECT(nested_offset_overflow.status == PacketSliceBuildStatus::offset_overflow);

    const auto nested_child = make_child_slice(parent, 4U, 12U);
    PFL_REQUIRE(nested_child.has_slice());
    const auto grandchild = make_child_slice(*nested_child.slice, 5U, 4U);
    PFL_REQUIRE(grandchild.has_slice());
    PFL_EXPECT(grandchild.slice->source_offset() == 9U);
    PFL_EXPECT(grandchild.slice->captured_end() == 12U);
    PFL_EXPECT(grandchild.slice->reported_end() == 20U);
    PFL_EXPECT(grandchild.slice->declared_end() == 13U);
    PFL_EXPECT(grandchild.slice->captured_size() == 3U);
}

void expect_registry_build_and_lookup() {
    const std::array registrations {
        DissectorRegistration {.selector = kRootSelector, .dissector = ethernet_to_ipv4_dissector},
        DissectorRegistration {.selector = kEtherTypeIpv4Selector, .dissector = ipv4_to_tcp_dissector},
        DissectorRegistration {.selector = kIpProtocolTcpSelector, .dissector = tcp_terminal_dissector},
    };

    const auto built = DissectionRegistry::build(registrations);
    PFL_REQUIRE(built.ok());
    PFL_EXPECT(built.registry->entry_count() == registrations.size());
    PFL_EXPECT(!built.registry->empty());
    PFL_EXPECT(built.registry->find(kRootSelector) == ethernet_to_ipv4_dissector);
    PFL_EXPECT(built.registry->find(kIpProtocolUdpSelector) == nullptr);

    const std::array duplicate_registrations {
        DissectorRegistration {.selector = kRootSelector, .dissector = ethernet_to_ipv4_dissector},
        DissectorRegistration {.selector = kRootSelector, .dissector = tcp_terminal_dissector},
    };

    const auto duplicate_result = DissectionRegistry::build(duplicate_registrations);
    PFL_EXPECT(!duplicate_result.ok());
    PFL_EXPECT(duplicate_result.status == DissectionRegistryBuildStatus::duplicate_selector);
    PFL_REQUIRE(duplicate_result.conflicting_selector.has_value());
    PFL_EXPECT(*duplicate_result.conflicting_selector == kRootSelector);

    const auto shared_value = 0x1234U;
    const std::array cross_domain_registrations {
        DissectorRegistration {
            .selector = ProtocolSelector {.domain = SelectorDomain::ether_type, .value = shared_value},
            .dissector = ethernet_to_ipv4_dissector,
        },
        DissectorRegistration {
            .selector = ProtocolSelector {.domain = SelectorDomain::ip_protocol, .value = shared_value},
            .dissector = tcp_terminal_dissector,
        },
    };

    const auto cross_domain_result = DissectionRegistry::build(cross_domain_registrations);
    PFL_REQUIRE(cross_domain_result.ok());
    PFL_EXPECT(cross_domain_result.registry->entry_count() == cross_domain_registrations.size());

    const std::array null_registration {
        DissectorRegistration {.selector = kRootSelector, .dissector = nullptr},
    };
    const auto null_result = DissectionRegistry::build(null_registration);
    PFL_EXPECT(!null_result.ok());
    PFL_EXPECT(null_result.status == DissectionRegistryBuildStatus::null_dissector);
    PFL_REQUIRE(null_result.conflicting_selector.has_value());
    PFL_REQUIRE(null_result.conflicting_registration_index.has_value());
    PFL_EXPECT(*null_result.conflicting_selector == kRootSelector);
    PFL_EXPECT(*null_result.conflicting_registration_index == 0U);
}

void expect_engine_traversal_and_consumer_behavior() {
    const std::array<std::uint8_t, 64> bytes {
        0U, 1U, 2U, 3U, 4U, 5U, 6U, 7U,
        8U, 9U, 10U, 11U, 12U, 13U, 14U, 15U,
        16U, 17U, 18U, 19U, 20U, 21U, 22U, 23U,
        24U, 25U, 26U, 27U, 28U, 29U, 30U, 31U,
        32U, 33U, 34U, 35U, 36U, 37U, 38U, 39U,
        40U, 41U, 42U, 43U, 44U, 45U, 46U, 47U,
        48U, 49U, 50U, 51U, 52U, 53U, 54U, 55U,
        56U, 57U, 58U, 59U, 60U, 61U, 62U, 63U,
    };
    const auto root_slice = make_root_packet_slice(ByteSourceId::captured_frame(31U), bytes, bytes.size(), bytes.size());
    const DissectionEngine engine {};

    const std::array chain_registrations {
        DissectorRegistration {.selector = kRootSelector, .dissector = ethernet_to_ipv4_dissector},
        DissectorRegistration {.selector = kEtherTypeIpv4Selector, .dissector = ipv4_to_tcp_dissector},
        DissectorRegistration {.selector = kIpProtocolTcpSelector, .dissector = tcp_terminal_dissector},
    };
    const auto chain_registry_result = DissectionRegistry::build(chain_registrations);
    PFL_REQUIRE(chain_registry_result.ok());
    const auto& chain_registry = *chain_registry_result.registry;

    StepRecorder recorder {};
    const auto chain_result = engine.run(
        chain_registry,
        kRootSelector,
        root_slice,
        DissectionConsumer {.on_step = record_step, .context = &recorder}
    );

    PFL_EXPECT(chain_result.stop_reason == StopReason::terminal_protocol);
    PFL_EXPECT(chain_result.step_count == 3U);
    PFL_EXPECT(chain_result.traversed_depth == 3U);
    PFL_EXPECT(recorder.steps.size() == 3U);

    const std::vector<ProtocolLayerKind> observed_kinds {
        recorder.steps[0].kind,
        recorder.steps[1].kind,
        recorder.steps[2].kind,
    };
    const std::vector<ProtocolLayerKind> expected_kinds {
        ProtocolLayerKind::ethernet_ii,
        ProtocolLayerKind::ipv4,
        ProtocolLayerKind::tcp,
    };
    PFL_EXPECT(observed_kinds == expected_kinds);

    const std::vector<std::size_t> observed_offsets {
        recorder.steps[0].full_begin,
        recorder.steps[1].full_begin,
        recorder.steps[2].full_begin,
    };
    const std::vector<std::size_t> expected_offsets {0U, 14U, 34U};
    PFL_EXPECT(observed_offsets == expected_offsets);
    PFL_EXPECT(recorder.steps[0].has_handoff);
    PFL_EXPECT(recorder.steps[0].has_child);
    PFL_EXPECT(recorder.steps[1].has_handoff);
    PFL_EXPECT(recorder.steps[1].has_child);
    PFL_EXPECT(!recorder.steps[2].has_handoff);
    PFL_EXPECT(recorder.steps[2].stop_reason == StopReason::terminal_protocol);
    PFL_EXPECT(recorder.steps[0].has_path_contribution);
    PFL_EXPECT(recorder.steps[0].path_kind == ProtocolLayerKind::vlan);
    PFL_EXPECT(recorder.steps[0].path_identifier_kind == ProtocolLayerIdentifierKind::vlan_vid);
    PFL_EXPECT(recorder.steps[0].path_value == 0U);

    const auto repeat_result = engine.run(chain_registry, kRootSelector, root_slice);
    PFL_EXPECT(repeat_result.stop_reason == StopReason::terminal_protocol);
    PFL_EXPECT(repeat_result.step_count == 3U);
    PFL_EXPECT(repeat_result.traversed_depth == 3U);

    const auto missing_root_result = engine.run(chain_registry, kIpProtocolUdpSelector, root_slice);
    PFL_EXPECT(missing_root_result.stop_reason == StopReason::unknown_next_protocol);
    PFL_EXPECT(missing_root_result.step_count == 0U);
    PFL_EXPECT(missing_root_result.traversed_depth == 0U);

    const std::array missing_next_registrations {
        DissectorRegistration {.selector = kRootSelector, .dissector = root_to_missing_selector_dissector},
    };
    const auto missing_next_registry_result = DissectionRegistry::build(missing_next_registrations);
    PFL_REQUIRE(missing_next_registry_result.ok());
    const auto missing_next_result = engine.run(*missing_next_registry_result.registry, kRootSelector, root_slice);
    PFL_EXPECT(missing_next_result.stop_reason == StopReason::unknown_next_protocol);
    PFL_EXPECT(missing_next_result.step_count == 1U);
    PFL_EXPECT(missing_next_result.traversed_depth == 1U);

    const std::array missing_child_registrations {
        DissectorRegistration {.selector = kRootSelector, .dissector = missing_child_handoff_dissector},
    };
    const auto missing_child_registry_result = DissectionRegistry::build(missing_child_registrations);
    PFL_REQUIRE(missing_child_registry_result.ok());
    const auto missing_child_result = engine.run(*missing_child_registry_result.registry, kRootSelector, root_slice);
    PFL_EXPECT(missing_child_result.stop_reason == StopReason::unknown_next_protocol);
    PFL_EXPECT(missing_child_result.step_count == 1U);
    PFL_EXPECT(missing_child_result.traversed_depth == 1U);

    const std::array truncated_registrations {
        DissectorRegistration {.selector = kRootSelector, .dissector = truncated_terminal_dissector},
    };
    const auto truncated_registry_result = DissectionRegistry::build(truncated_registrations);
    PFL_REQUIRE(truncated_registry_result.ok());
    const auto truncated_result = engine.run(*truncated_registry_result.registry, kRootSelector, root_slice);
    PFL_EXPECT(truncated_result.stop_reason == StopReason::truncated);
    PFL_EXPECT(truncated_result.step_count == 1U);
    PFL_EXPECT(truncated_result.traversed_depth == 1U);

    const std::array malformed_registrations {
        DissectorRegistration {.selector = kRootSelector, .dissector = malformed_terminal_dissector},
    };
    const auto malformed_registry_result = DissectionRegistry::build(malformed_registrations);
    PFL_REQUIRE(malformed_registry_result.ok());
    const auto malformed_result = engine.run(*malformed_registry_result.registry, kRootSelector, root_slice);
    PFL_EXPECT(malformed_result.stop_reason == StopReason::malformed);
    PFL_EXPECT(malformed_result.step_count == 1U);
    PFL_EXPECT(malformed_result.traversed_depth == 1U);

    const std::array stop_with_handoff_registrations {
        DissectorRegistration {.selector = kRootSelector, .dissector = stop_with_handoff_dissector},
        DissectorRegistration {.selector = kEtherTypeIpv4Selector, .dissector = ipv4_to_tcp_dissector},
    };
    const auto stop_with_handoff_registry_result = DissectionRegistry::build(stop_with_handoff_registrations);
    PFL_REQUIRE(stop_with_handoff_registry_result.ok());
    StepRecorder stopped_recorder {};
    const auto stop_with_handoff_result = engine.run(
        *stop_with_handoff_registry_result.registry,
        kRootSelector,
        root_slice,
        DissectionConsumer {.on_step = record_step, .context = &stopped_recorder}
    );
    PFL_EXPECT(stop_with_handoff_result.stop_reason == StopReason::unsupported_variant);
    PFL_EXPECT(stop_with_handoff_result.step_count == 1U);
    PFL_EXPECT(stop_with_handoff_result.traversed_depth == 1U);
    PFL_EXPECT(stopped_recorder.steps.size() == 1U);

    const std::array no_handoff_registrations {
        DissectorRegistration {.selector = kRootSelector, .dissector = no_handoff_dissector},
    };
    const auto no_handoff_registry_result = DissectionRegistry::build(no_handoff_registrations);
    PFL_REQUIRE(no_handoff_registry_result.ok());
    const auto no_handoff_result = engine.run(*no_handoff_registry_result.registry, kRootSelector, root_slice);
    PFL_EXPECT(no_handoff_result.stop_reason == StopReason::unknown_next_protocol);
    PFL_EXPECT(no_handoff_result.step_count == 1U);
    PFL_EXPECT(no_handoff_result.traversed_depth == 1U);

    const std::array repeat_registrations {
        DissectorRegistration {.selector = kRootSelector, .dissector = repeat_vlan_dissector},
        DissectorRegistration {.selector = kRepeatSelector, .dissector = repeat_vlan_dissector},
    };
    const auto repeat_registry_result = DissectionRegistry::build(repeat_registrations);
    PFL_REQUIRE(repeat_registry_result.ok());
    StepRecorder repeat_recorder {};
    const auto bounded_repeat_result = engine.run(
        *repeat_registry_result.registry,
        kRootSelector,
        root_slice,
        DissectionConsumer {.on_step = record_step, .context = &repeat_recorder},
        4U
    );
    PFL_EXPECT(bounded_repeat_result.stop_reason == StopReason::depth_limit);
    PFL_EXPECT(bounded_repeat_result.step_count == 4U);
    PFL_EXPECT(bounded_repeat_result.traversed_depth == 4U);
    PFL_EXPECT(repeat_recorder.steps.size() == 4U);
    for (const auto& step : repeat_recorder.steps) {
        PFL_EXPECT(step.kind == ProtocolLayerKind::vlan);
        PFL_EXPECT(step.has_handoff);
        PFL_EXPECT(step.has_child);
        PFL_EXPECT(step.has_path_contribution);
    }

    const auto depth_limited_result = engine.run(chain_registry, kRootSelector, root_slice, {}, 1U);
    PFL_EXPECT(depth_limited_result.stop_reason == StopReason::depth_limit);
    PFL_EXPECT(depth_limited_result.step_count == 1U);
    PFL_EXPECT(depth_limited_result.traversed_depth == 1U);

    const auto zero_depth_result = engine.run(chain_registry, kRootSelector, root_slice, {}, 0U);
    PFL_EXPECT(zero_depth_result.stop_reason == StopReason::depth_limit);
    PFL_EXPECT(zero_depth_result.step_count == 0U);
    PFL_EXPECT(zero_depth_result.traversed_depth == 0U);
}

}  // namespace

void run_dissection_foundation_tests() {
    expect_byte_range_helpers();
    expect_layer_bounds_facts_and_terminal_disposition_model();
    expect_root_packet_slice_bounds();
    expect_child_packet_slice_bounds_and_failures();
    expect_registry_build_and_lookup();
    expect_engine_traversal_and_consumer_behavior();
}

}  // namespace pfl::tests
