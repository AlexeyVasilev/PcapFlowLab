#include "core/dissection/modules/EthernetVlanModules.h"

#include "core/decode/PacketDecodeSupport.h"
#include "core/dissection/modules/CommonDirectModuleSupport.h"
#include "core/dissection/modules/LlcSnapModule.h"

namespace pfl::dissection {

namespace {

std::size_t logical_packet_end(
    const std::size_t header_length,
    const std::size_t declared_payload_length
) noexcept {
    return header_length + declared_payload_length;
}

DissectionStep dissect_ethernet_with_domains(
    const PacketSlice& slice,
    const SelectorDomain ether_type_domain,
    const SelectorDomain ieee8023_payload_domain
) {
    const auto parsed = parse_ethernet_frame(slice);
    if (parsed.status != ParseStatus::complete) {
        return direct::make_error_step(
            slice,
            DissectionLayerKind::unknown,
            parsed.status,
            parsed.status == ParseStatus::truncated ? StopReason::truncated : StopReason::malformed,
            detail::kEthernetHeaderSize
        );
    }

    const auto layer = parsed.is_ieee_802_3 ? LayerKey::ieee8023() : LayerKey::ethernet_ii();
    const auto full_end = logical_packet_end(parsed.header_length, parsed.declared_payload_length);
    DissectionStep step {
        .layer = parsed.is_ieee_802_3 ? DissectionLayerKind::ieee8023 : DissectionLayerKind::ethernet_ii,
        .path_contribution = layer,
        .path_contribution_deferrable_by_child = parsed.is_ieee_802_3,
        .bounds = direct::make_layer_bounds(
            slice,
            full_end,
            parsed.header_length,
            direct::RelativeRange {.begin = parsed.header_length, .end = full_end},
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
        const auto handoff = direct::make_protocol_handoff(
            slice,
            parsed.header_length,
            parsed.declared_payload_length,
            ProtocolSelector {
                .domain = ieee8023_payload_domain,
                .value = kIeee8023PayloadSelectorValue,
            }
        );
        if (!handoff.has_value()) {
            return direct::make_error_step(
                slice,
                DissectionLayerKind::ieee8023,
                ParseStatus::malformed,
                StopReason::malformed,
                parsed.header_length
            );
        }

        step.handoff = *handoff;
        return step;
    }

    const auto handoff = direct::make_protocol_handoff(
        slice,
        parsed.header_length,
        parsed.declared_payload_length,
        ProtocolSelector {
            .domain = ether_type_domain,
            .value = parsed.protocol_type,
        }
    );
    if (!handoff.has_value()) {
        return direct::make_error_step(
            slice,
            parsed.is_ieee_802_3 ? DissectionLayerKind::ieee8023 : DissectionLayerKind::ethernet_ii,
            ParseStatus::malformed,
            StopReason::malformed,
            parsed.header_length
        );
    }

    step.handoff = *handoff;
    return step;
}

DissectionStep dissect_vlan_with_domains(
    const PacketSlice& slice,
    const SelectorDomain ether_type_domain,
    const SelectorDomain ieee8023_payload_domain
) {
    const auto parsed = parse_vlan_tag(slice);
    if (parsed.status != ParseStatus::complete) {
        return direct::make_error_step(
            slice,
            DissectionLayerKind::vlan,
            parsed.status,
            parsed.status == ParseStatus::truncated ? StopReason::truncated : StopReason::malformed,
            detail::kVlanHeaderSize
        );
    }

    const auto layer = LayerKey::vlan(static_cast<std::uint16_t>(parsed.tci & 0x0FFFU));
    const auto is_ieee_802_3 = parsed.encapsulated_ether_type < detail::kIeee8023LengthCutoff;
    const auto full_end = logical_packet_end(parsed.header_length, parsed.declared_payload_length);
    const auto handoff = direct::make_protocol_handoff(
        slice,
        parsed.header_length,
        parsed.declared_payload_length,
        ProtocolSelector {
            .domain = is_ieee_802_3
                ? ieee8023_payload_domain
                : ether_type_domain,
            .value = is_ieee_802_3
                ? kIeee8023PayloadSelectorValue
                : parsed.encapsulated_ether_type,
        }
    );
    if (!handoff.has_value()) {
        return direct::make_error_step(
            slice,
            DissectionLayerKind::vlan,
            ParseStatus::malformed,
            StopReason::malformed,
            parsed.header_length
        );
    }

    return DissectionStep {
        .layer = DissectionLayerKind::vlan,
        .path_contribution = layer,
        .bounds = direct::make_layer_bounds(
            slice,
            full_end,
            parsed.header_length,
            direct::RelativeRange {.begin = parsed.header_length, .end = full_end},
            true
        ),
        .handoff = *handoff,
        .facts = VlanFacts {
            .tci = parsed.tci,
            .encapsulated_ether_type = parsed.encapsulated_ether_type,
        },
        .terminal_disposition = TerminalDisposition::none,
        .status = ParseStatus::complete,
        .stop_reason = StopReason::none,
    };
}

}  // namespace

ParsedEthernetFrame parse_ethernet_frame(const PacketSlice& slice) noexcept {
    const auto bytes = direct::visible_captured_bytes(slice);
    if (bytes.size() < detail::kEthernetHeaderSize) {
        return ParsedEthernetFrame {
            .status = ParseStatus::truncated,
        };
    }

    const auto ethernet = detail::parse_ethernet_header_at(bytes, 0U);
    if (!ethernet.has_value()) {
        return ParsedEthernetFrame {
            .status = ParseStatus::truncated,
        };
    }

    return ParsedEthernetFrame {
        .status = ParseStatus::complete,
        .protocol_type = ethernet->protocol_type,
        .header_length = detail::kEthernetHeaderSize,
        .declared_payload_length = ethernet->is_ieee_802_3
            ? static_cast<std::size_t>(ethernet->declared_payload_length)
            : (direct::slice_declared_length(slice) > detail::kEthernetHeaderSize
                ? direct::slice_declared_length(slice) - detail::kEthernetHeaderSize
                : 0U),
        .is_ieee_802_3 = ethernet->is_ieee_802_3,
    };
}

ParsedVlanTag parse_vlan_tag(const PacketSlice& slice) noexcept {
    const auto bytes = direct::visible_captured_bytes(slice);
    if (direct::slice_declared_length(slice) < detail::kVlanHeaderSize) {
        return ParsedVlanTag {
            .status = ParseStatus::malformed,
        };
    }

    const auto vlan = detail::parse_vlan_header_at(bytes, 0U);
    if (!vlan.has_value()) {
        return ParsedVlanTag {
            .status = ParseStatus::truncated,
        };
    }

    return ParsedVlanTag {
        .status = ParseStatus::complete,
        .tci = vlan->tci,
        .encapsulated_ether_type = vlan->encapsulated_ether_type,
        .header_length = detail::kVlanHeaderSize,
        .declared_payload_length = vlan->encapsulated_ether_type < detail::kIeee8023LengthCutoff
            ? static_cast<std::size_t>(vlan->encapsulated_ether_type)
            : direct::slice_declared_length(slice) - detail::kVlanHeaderSize,
    };
}

DissectionStep dissect_ethernet(const PacketSlice& slice) {
    return dissect_ethernet_with_domains(
        slice,
        SelectorDomain::native_ether_type,
        SelectorDomain::native_ieee8023_payload
    );
}

DissectionStep dissect_embedded_ethernet(const PacketSlice& slice) {
    return dissect_ethernet_with_domains(
        slice,
        SelectorDomain::ether_type,
        SelectorDomain::ieee8023_payload
    );
}

DissectionStep dissect_vlan(const PacketSlice& slice) {
    return dissect_vlan_with_domains(
        slice,
        SelectorDomain::native_ether_type,
        SelectorDomain::native_ieee8023_payload
    );
}

DissectionStep dissect_embedded_vlan(const PacketSlice& slice) {
    return dissect_vlan_with_domains(
        slice,
        SelectorDomain::ether_type,
        SelectorDomain::ieee8023_payload
    );
}

}  // namespace pfl::dissection
