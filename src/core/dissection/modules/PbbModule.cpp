#include "core/dissection/modules/PbbModule.h"

#include "core/decode/PacketDecodeSupport.h"
#include "core/dissection/modules/CommonDirectModuleSupport.h"
#include "core/dissection/modules/EthernetVlanModules.h"
#include "core/dissection/modules/LlcSnapModule.h"

namespace pfl::dissection {

namespace {

ProtocolSelector make_pbb_inner_frame_selector() noexcept {
    return ProtocolSelector {
        .domain = SelectorDomain::pbb_inner_frame,
        .value = kPbbInnerFrameSelectorValue,
    };
}

ProtocolSelector make_pbb_inner_ether_type_selector(const std::uint16_t ether_type) noexcept {
    return ProtocolSelector {
        .domain = SelectorDomain::pbb_inner_ether_type,
        .value = ether_type,
    };
}

bool is_supported_pbb_inner_ether_type(const std::uint16_t ether_type) noexcept {
    return ether_type == detail::kEtherTypeIpv4 ||
           ether_type == detail::kEtherTypeIpv6 ||
           ether_type == detail::kEtherTypeArp ||
           ether_type == detail::kEtherTypeVlan ||
           ether_type == detail::kEtherTypeQinq ||
           ether_type == detail::kEtherTypeLegacyVlan;
}

ParsedEthernetFrame parse_pbb_inner_ethernet_frame(const PacketSlice& slice) noexcept {
    const auto bytes = direct::visible_captured_bytes(slice);
    const auto header = detail::parse_ethernet_header_at(bytes, 0U);
    if (!header.has_value()) {
        return ParsedEthernetFrame {
            .status = bytes.size() < detail::kEthernetHeaderSize ? ParseStatus::truncated : ParseStatus::malformed,
            .header_length = detail::kEthernetHeaderSize,
        };
    }

    return ParsedEthernetFrame {
        .status = ParseStatus::complete,
        .protocol_type = header->protocol_type,
        .header_length = detail::kEthernetHeaderSize,
        .declared_payload_length = header->is_ieee_802_3
            ? static_cast<std::size_t>(header->declared_payload_length)
            : direct::slice_declared_length(slice) - detail::kEthernetHeaderSize,
        .is_ieee_802_3 = header->is_ieee_802_3,
    };
}

LayerBounds make_pbb_bounds(const PacketSlice& slice, const std::size_t header_length) noexcept {
    return direct::make_layer_bounds(
        slice,
        direct::slice_declared_length(slice),
        header_length,
        direct::RelativeRange {.begin = header_length, .end = direct::slice_declared_length(slice)},
        true
    );
}

DissectionStep make_pbb_error_step(
    const PacketSlice& slice,
    const ParseStatus status,
    const StopReason stop_reason,
    const std::size_t header_length
) noexcept {
    return DissectionStep {
        .layer = DissectionLayerKind::pbb,
        .bounds = direct::make_layer_bounds(
            slice,
            direct::slice_declared_length(slice),
            std::min(header_length, direct::slice_declared_length(slice))
        ),
        .facts = std::monostate {},
        .terminal_disposition = TerminalDisposition::none,
        .status = status,
        .stop_reason = stop_reason,
    };
}

std::optional<ProtocolHandoff> make_pbb_inner_handoff(
    const PacketSlice& slice,
    const std::size_t header_length
) noexcept {
    return direct::make_protocol_handoff(
        slice,
        header_length,
        direct::slice_declared_length(slice) - header_length,
        make_pbb_inner_frame_selector()
    );
}

DissectionStep make_pbb_inner_ethernet_error_step(
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

DissectionStep make_pbb_inner_vlan_error_step(
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

ParsedPbbFrame parse_pbb_frame(const PacketSlice& slice) noexcept {
    const auto declared_length = direct::slice_declared_length(slice);
    if (declared_length < detail::kPbbITagSize) {
        return ParsedPbbFrame {
            .status = ParseStatus::malformed,
            .header_length = detail::kPbbITagSize,
        };
    }

    const auto bytes = direct::visible_captured_bytes(slice);
    if (bytes.size() < detail::kPbbITagSize) {
        return ParsedPbbFrame {
            .status = ParseStatus::truncated,
            .header_length = detail::kPbbITagSize,
        };
    }

    const auto itag = detail::read_be32(bytes, 0U);
    return ParsedPbbFrame {
        .status = ParseStatus::complete,
        .pcp = static_cast<std::uint8_t>((itag >> 29U) & 0x7U),
        .dei = ((itag >> 28U) & 0x1U) != 0U,
        .nca = ((itag >> 27U) & 0x1U) != 0U,
        .reserved = static_cast<std::uint8_t>((itag >> 24U) & 0x7U),
        .isid = itag & 0x00FFFFFFU,
        .header_length = detail::kPbbITagSize,
        .declared_payload_length = declared_length - detail::kPbbITagSize,
    };
}

DissectionStep dissect_pbb(const PacketSlice& slice) {
    const auto parsed = parse_pbb_frame(slice);
    if (parsed.status != ParseStatus::complete) {
        return make_pbb_error_step(
            slice,
            parsed.status,
            parsed.status == ParseStatus::truncated ? StopReason::truncated : StopReason::malformed,
            parsed.header_length
        );
    }

    DissectionStep step {
        .layer = DissectionLayerKind::pbb,
        .path_contribution = LayerKey::pbb(parsed.isid),
        .path_commit_policy = PathCommitPolicy::recognized_flow_or_recognized_non_flow,
        .descendant_path_commit_policy = PathCommitPolicy::recognized_flow_or_recognized_non_flow,
        .bounds = make_pbb_bounds(slice, parsed.header_length),
        .facts = PbbFacts {
            .pcp = parsed.pcp,
            .dei = parsed.dei,
            .nca = parsed.nca,
            .reserved = parsed.reserved,
            .isid = parsed.isid,
        },
        .terminal_disposition = TerminalDisposition::none,
        .status = ParseStatus::complete,
        .stop_reason = StopReason::none,
    };

    if (parsed.declared_payload_length == 0U) {
        step.stop_reason = StopReason::truncated;
        return step;
    }

    step.handoff = make_pbb_inner_handoff(slice, parsed.header_length);
    if (!step.handoff.has_value()) {
        step.status = ParseStatus::malformed;
        step.stop_reason = StopReason::malformed;
    }
    return step;
}

DissectionStep dissect_pbb_inner_ethernet(const PacketSlice& slice) {
    const auto parsed = parse_pbb_inner_ethernet_frame(slice);
    if (parsed.status != ParseStatus::complete) {
        return make_pbb_inner_ethernet_error_step(
            slice,
            parsed.status,
            parsed.status == ParseStatus::truncated ? StopReason::truncated : StopReason::malformed
        );
    }

    DissectionStep step {
        .layer = parsed.is_ieee_802_3 ? DissectionLayerKind::ieee8023 : DissectionLayerKind::ethernet_ii,
        .path_contribution = parsed.is_ieee_802_3 ? LayerKey::ieee8023() : LayerKey::ethernet_ii(),
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

    if (!is_supported_pbb_inner_ether_type(parsed.protocol_type)) {
        step.stop_reason = StopReason::unknown_next_protocol;
        return step;
    }

    step.handoff = direct::make_protocol_handoff(
        slice,
        parsed.header_length,
        parsed.declared_payload_length,
        make_pbb_inner_ether_type_selector(parsed.protocol_type)
    );
    if (!step.handoff.has_value()) {
        step.status = ParseStatus::malformed;
        step.stop_reason = StopReason::malformed;
    }
    return step;
}

DissectionStep dissect_pbb_inner_vlan(const PacketSlice& slice) {
    const auto parsed = parse_vlan_tag(slice);
    if (parsed.status != ParseStatus::complete) {
        return make_pbb_inner_vlan_error_step(
            slice,
            parsed.status,
            parsed.status == ParseStatus::truncated ? StopReason::truncated : StopReason::malformed
        );
    }

    DissectionStep step {
        .layer = DissectionLayerKind::vlan,
        .path_contribution = LayerKey::vlan(static_cast<std::uint32_t>(parsed.tci & 0x0FFFU)),
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
        : SelectorDomain::pbb_inner_ether_type;
    const auto next_value = parsed.encapsulated_ether_type < detail::kIeee8023LengthCutoff
        ? kIeee8023PayloadSelectorValue
        : static_cast<std::uint32_t>(parsed.encapsulated_ether_type);

    if (next_domain == SelectorDomain::pbb_inner_ether_type &&
        !is_supported_pbb_inner_ether_type(parsed.encapsulated_ether_type)) {
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
