#include "core/dissection/modules/MplsPseudowireModule.h"

#include <algorithm>

#include "core/decode/PacketDecodeSupport.h"
#include "core/dissection/modules/CommonDirectModuleSupport.h"
#include "core/dissection/modules/EthernetVlanModules.h"
#include "core/dissection/modules/Ipv4Module.h"
#include "core/dissection/modules/Ipv6Module.h"
#include "core/dissection/modules/LlcSnapModule.h"

namespace pfl::dissection {

namespace {

inline constexpr std::size_t kMplsPseudowireControlWordSize = 4U;

ProtocolSelector make_mpls_pseudowire_inner_frame_selector() noexcept {
    return ProtocolSelector {
        .domain = SelectorDomain::mpls_pw_inner_frame,
        .value = kMplsPseudowireInnerFrameSelectorValue,
    };
}

ProtocolSelector make_mpls_pseudowire_inner_ether_type_selector(const std::uint16_t ether_type) noexcept {
    return ProtocolSelector {
        .domain = SelectorDomain::mpls_pw_inner_ether_type,
        .value = ether_type,
    };
}

bool is_supported_mpls_pseudowire_inner_ether_type(const std::uint16_t ether_type) noexcept {
    return ether_type == detail::kEtherTypeIpv4 ||
           ether_type == detail::kEtherTypeIpv6 ||
           ether_type == detail::kEtherTypeArp ||
           ether_type == detail::kEtherTypeVlan ||
           ether_type == detail::kEtherTypeQinq ||
           ether_type == detail::kEtherTypeLegacyVlan;
}

LayerBounds make_mpls_pseudowire_bounds(
    const PacketSlice& slice,
    const std::size_t header_length
) noexcept {
    return direct::make_layer_bounds(
        slice,
        direct::slice_declared_length(slice),
        header_length,
        direct::RelativeRange {.begin = header_length, .end = direct::slice_declared_length(slice)},
        true
    );
}

DissectionStep make_mpls_pseudowire_step(
    const PacketSlice& slice,
    const bool has_control_word,
    const std::size_t header_length,
    const std::uint16_t flags,
    const std::uint16_t sequence
) noexcept {
    return DissectionStep {
        .layer = DissectionLayerKind::mpls_pseudowire,
        .path_contribution = LayerKey::mpls_pw(),
        .path_commit_policy = PathCommitPolicy::recognized_flow_or_recognized_non_flow,
        .descendant_path_commit_policy = PathCommitPolicy::recognized_flow_or_recognized_non_flow,
        .bounds = make_mpls_pseudowire_bounds(slice, header_length),
        .facts = MplsPseudowireFacts {
            .has_control_word = has_control_word,
            .control_word_flags = flags,
            .sequence = sequence,
        },
        .terminal_disposition = TerminalDisposition::none,
        .status = ParseStatus::complete,
        .stop_reason = StopReason::none,
    };
}

DissectionStep make_mpls_pseudowire_error_step(
    const PacketSlice& slice,
    const ParseStatus status,
    const StopReason stop_reason,
    const std::size_t header_length
) noexcept {
    return direct::make_error_step(
        slice,
        DissectionLayerKind::mpls_pseudowire,
        status,
        stop_reason,
        header_length
    );
}

DissectionStep make_mpls_pseudowire_inner_ethernet_error_step(
    const PacketSlice& slice,
    const ParseStatus status,
    const StopReason stop_reason
) noexcept {
    return direct::make_error_step(
        slice,
        DissectionLayerKind::ethernet_ii,
        status,
        stop_reason,
        std::min<std::size_t>(detail::kEthernetHeaderSize, direct::slice_declared_length(slice))
    );
}

DissectionStep make_mpls_pseudowire_inner_vlan_error_step(
    const PacketSlice& slice,
    const ParseStatus status,
    const StopReason stop_reason
) noexcept {
    return direct::make_error_step(
        slice,
        DissectionLayerKind::vlan,
        status,
        stop_reason,
        std::min<std::size_t>(detail::kVlanHeaderSize, direct::slice_declared_length(slice))
    );
}

}  // namespace

ParsedMplsPseudowireControlWord parse_mpls_pseudowire_control_word(const PacketSlice& slice) noexcept {
    const auto declared_length = direct::slice_declared_length(slice);
    if (declared_length < kMplsPseudowireControlWordSize) {
        return ParsedMplsPseudowireControlWord {
            .status = ParseStatus::truncated,
            .header_length = kMplsPseudowireControlWordSize,
        };
    }

    const auto bytes = direct::visible_captured_bytes(slice);
    if (bytes.size() < kMplsPseudowireControlWordSize) {
        return ParsedMplsPseudowireControlWord {
            .status = ParseStatus::truncated,
            .header_length = kMplsPseudowireControlWordSize,
        };
    }

    return ParsedMplsPseudowireControlWord {
        .status = ParseStatus::complete,
        .flags = detail::read_be16(bytes, 0U),
        .sequence = detail::read_be16(bytes, 2U),
        .header_length = kMplsPseudowireControlWordSize,
        .declared_payload_length = declared_length - kMplsPseudowireControlWordSize,
    };
}

DissectionStep dissect_mpls_bos_payload(const PacketSlice& slice) {
    const auto declared_length = direct::slice_declared_length(slice);
    const auto bytes = direct::visible_captured_bytes(slice);

    if (declared_length == 0U) {
        return make_mpls_pseudowire_error_step(slice, ParseStatus::complete, StopReason::no_payload, 0U);
    }

    if (bytes.empty()) {
        return make_mpls_pseudowire_error_step(slice, ParseStatus::truncated, StopReason::truncated, 0U);
    }

    const auto version_nibble = static_cast<std::uint8_t>(bytes[0U] >> 4U);
    if (version_nibble == 4U || version_nibble == 6U) {
        const auto child = make_child_slice(slice, 0U, declared_length);
        if (!child.has_slice()) {
            return make_mpls_pseudowire_error_step(slice, ParseStatus::malformed, StopReason::malformed, 0U);
        }
        return version_nibble == 4U ? dissect_ipv4(*child.slice) : dissect_ipv6(*child.slice);
    }

    if (bytes.size() >= 2U && bytes[0U] == 0x00U && bytes[1U] == 0x00U) {
        const auto parsed = parse_mpls_pseudowire_control_word(slice);
        if (parsed.status != ParseStatus::complete) {
            return make_mpls_pseudowire_error_step(
                slice,
                parsed.status,
                StopReason::truncated,
                kMplsPseudowireControlWordSize
            );
        }

        auto step = make_mpls_pseudowire_step(
            slice,
            true,
            parsed.header_length,
            parsed.flags,
            parsed.sequence
        );
        step.handoff = direct::make_protocol_handoff(
            slice,
            parsed.header_length,
            parsed.declared_payload_length,
            make_mpls_pseudowire_inner_frame_selector()
        );
        if (!step.handoff.has_value()) {
            step.status = ParseStatus::malformed;
            step.stop_reason = StopReason::malformed;
        }
        return step;
    }

    auto step = make_mpls_pseudowire_step(slice, false, 0U, 0U, 0U);
    step.handoff = direct::make_protocol_handoff(
        slice,
        0U,
        declared_length,
        make_mpls_pseudowire_inner_frame_selector()
    );
    if (!step.handoff.has_value()) {
        step.status = ParseStatus::malformed;
        step.stop_reason = StopReason::malformed;
    }
    return step;
}

DissectionStep dissect_mpls_pseudowire_inner_ethernet(const PacketSlice& slice) {
    const auto parsed = parse_ethernet_frame(slice);
    if (parsed.status != ParseStatus::complete) {
        return make_mpls_pseudowire_inner_ethernet_error_step(
            slice,
            parsed.status,
            parsed.status == ParseStatus::truncated ? StopReason::truncated : StopReason::malformed
        );
    }

    DissectionStep step {
        .layer = parsed.is_ieee_802_3 ? DissectionLayerKind::ieee8023 : DissectionLayerKind::ethernet_ii,
        .path_contribution = parsed.is_ieee_802_3 ? LayerKey::ieee8023() : LayerKey::ethernet_ii(),
        .path_commit_policy = PathCommitPolicy::recognized_flow_or_recognized_non_flow,
        .descendant_path_commit_policy = PathCommitPolicy::recognized_flow_or_recognized_non_flow,
        .path_contribution_deferrable_by_child = parsed.is_ieee_802_3,
        .bounds = direct::make_layer_bounds(
            slice,
            direct::slice_declared_length(slice),
            parsed.header_length,
            direct::RelativeRange {.begin = parsed.header_length, .end = direct::slice_declared_length(slice)},
            true
        ),
        .facts = EthernetFacts {
            .protocol_type = parsed.protocol_type,
            .is_ieee_802_3 = parsed.is_ieee_802_3,
        },
        .terminal_disposition = TerminalDisposition::none,
        .status = ParseStatus::complete,
        .stop_reason = StopReason::none,
    };

    if (parsed.is_ieee_802_3) {
        step.handoff = direct::make_protocol_handoff(
            slice,
            parsed.header_length,
            parsed.declared_payload_length,
            ProtocolSelector {
                .domain = SelectorDomain::ieee8023_payload,
                .value = kIeee8023PayloadSelectorValue,
            }
        );
        if (!step.handoff.has_value()) {
            step.status = ParseStatus::malformed;
            step.stop_reason = StopReason::malformed;
        }
        return step;
    }

    if (!is_supported_mpls_pseudowire_inner_ether_type(parsed.protocol_type)) {
        step.stop_reason = StopReason::unknown_next_protocol;
        return step;
    }

    step.handoff = direct::make_protocol_handoff(
        slice,
        parsed.header_length,
        parsed.declared_payload_length,
        make_mpls_pseudowire_inner_ether_type_selector(parsed.protocol_type)
    );
    if (!step.handoff.has_value()) {
        step.status = ParseStatus::malformed;
        step.stop_reason = StopReason::malformed;
    }
    return step;
}

DissectionStep dissect_mpls_pseudowire_inner_vlan(const PacketSlice& slice) {
    const auto parsed = parse_vlan_tag(slice);
    if (parsed.status != ParseStatus::complete) {
        return make_mpls_pseudowire_inner_vlan_error_step(
            slice,
            parsed.status,
            parsed.status == ParseStatus::truncated ? StopReason::truncated : StopReason::malformed
        );
    }

    DissectionStep step {
        .layer = DissectionLayerKind::vlan,
        .path_contribution = LayerKey::vlan(static_cast<std::uint32_t>(parsed.tci & 0x0FFFU)),
        .path_commit_policy = PathCommitPolicy::recognized_flow_or_recognized_non_flow,
        .descendant_path_commit_policy = PathCommitPolicy::recognized_flow_or_recognized_non_flow,
        .bounds = direct::make_layer_bounds(
            slice,
            direct::slice_declared_length(slice),
            parsed.header_length,
            direct::RelativeRange {.begin = parsed.header_length, .end = direct::slice_declared_length(slice)},
            true
        ),
        .facts = VlanFacts {
            .tci = parsed.tci,
            .encapsulated_ether_type = parsed.encapsulated_ether_type,
        },
        .terminal_disposition = TerminalDisposition::none,
        .status = ParseStatus::complete,
        .stop_reason = StopReason::none,
    };

    const auto next_domain = parsed.encapsulated_ether_type < detail::kIeee8023LengthCutoff
        ? SelectorDomain::ieee8023_payload
        : SelectorDomain::mpls_pw_inner_ether_type;
    const auto next_value = parsed.encapsulated_ether_type < detail::kIeee8023LengthCutoff
        ? kIeee8023PayloadSelectorValue
        : static_cast<std::uint32_t>(parsed.encapsulated_ether_type);

    if (next_domain == SelectorDomain::mpls_pw_inner_ether_type &&
        !is_supported_mpls_pseudowire_inner_ether_type(parsed.encapsulated_ether_type)) {
        step.stop_reason = StopReason::unknown_next_protocol;
        return step;
    }

    step.handoff = direct::make_protocol_handoff(
        slice,
        parsed.header_length,
        parsed.declared_payload_length,
        ProtocolSelector {
            .domain = next_domain,
            .value = next_value,
        }
    );
    if (!step.handoff.has_value()) {
        step.status = ParseStatus::malformed;
        step.stop_reason = StopReason::malformed;
    }
    return step;
}

}  // namespace pfl::dissection
