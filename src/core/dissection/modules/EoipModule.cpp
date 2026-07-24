#include "core/dissection/modules/EoipModule.h"

#include <algorithm>

#include "core/decode/PacketDecodeSupport.h"
#include "core/dissection/modules/CommonDirectModuleSupport.h"
#include "core/dissection/modules/EthernetVlanModules.h"
#include "core/dissection/modules/GreModule.h"
#include "core/dissection/modules/Ipv4Module.h"
#include "core/dissection/modules/Ipv6Module.h"
#include "core/dissection/modules/LlcSnapModule.h"

namespace pfl::dissection {

namespace {

inline constexpr std::size_t kEoipHeaderSize = detail::kGreBaseHeaderSize + detail::kGreOptionalFieldSize;

ProtocolSelector make_eoip_inner_frame_selector() noexcept {
    return ProtocolSelector {
        .domain = SelectorDomain::eoip_inner_frame,
        .value = kEoipInnerFrameSelectorValue,
    };
}

ProtocolSelector make_eoip_inner_ether_type_selector(const std::uint16_t ether_type) noexcept {
    return ProtocolSelector {
        .domain = SelectorDomain::eoip_inner_ether_type,
        .value = ether_type,
    };
}

ProtocolSelector make_eoip_inner_ieee8023_payload_selector() noexcept {
    return ProtocolSelector {
        .domain = SelectorDomain::eoip_inner_ieee8023_payload,
        .value = kEoipInnerIeee8023PayloadSelectorValue,
    };
}

ProtocolSelector make_eoip_inner_llc_snap_pid_selector(const std::uint16_t pid) noexcept {
    return ProtocolSelector {
        .domain = SelectorDomain::eoip_inner_llc_snap_pid,
        .value = pid,
    };
}

ProtocolSelector make_eoip_inner_ip_protocol_selector(const std::uint8_t protocol) noexcept {
    return ProtocolSelector {
        .domain = SelectorDomain::eoip_inner_ip_protocol,
        .value = protocol,
    };
}

ProtocolSelector make_eoip_inner_ipv6_next_header_selector(const std::uint8_t next_header) noexcept {
    return ProtocolSelector {
        .domain = SelectorDomain::eoip_inner_ipv6_next_header,
        .value = next_header,
    };
}

bool is_supported_eoip_inner_ether_type(const std::uint16_t ether_type) noexcept {
    return ether_type == detail::kEtherTypeIpv4 ||
           ether_type == detail::kEtherTypeIpv6 ||
           ether_type == detail::kEtherTypeArp ||
           ether_type == detail::kEtherTypeVlan ||
           ether_type == detail::kEtherTypeQinq ||
           ether_type == detail::kEtherTypeLegacyVlan;
}

DissectionStep make_eoip_error_step(
    const PacketSlice& slice,
    const ParseStatus status,
    const StopReason stop_reason,
    const std::size_t header_length
) noexcept {
    return direct::make_error_step(
        slice,
        DissectionLayerKind::eoip,
        status,
        stop_reason,
        std::min(header_length, direct::slice_declared_length(slice))
    );
}

DissectionStep make_eoip_inner_ethernet_error_step(
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

DissectionStep make_eoip_inner_vlan_error_step(
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

LayerBounds make_eoip_bounds(
    const PacketSlice& slice,
    const std::size_t full_end,
    const std::size_t header_end
) noexcept {
    return direct::make_layer_bounds(
        slice,
        full_end,
        header_end,
        direct::RelativeRange {.begin = header_end, .end = full_end},
        true
    );
}

DissectionStep make_eoip_inner_network_error_step(
    const PacketSlice& slice,
    const DissectionLayerKind layer,
    const ParseStatus status,
    const std::size_t header_length
) noexcept {
    return direct::make_error_step(
        slice,
        layer,
        status,
        status == ParseStatus::truncated ? StopReason::truncated : StopReason::malformed,
        header_length
    );
}

}  // namespace

ParsedEoipFrame parse_eoip_frame(const PacketSlice& slice) noexcept {
    const auto declared_length = direct::slice_declared_length(slice);
    if (declared_length < detail::kGreBaseHeaderSize) {
        return ParsedEoipFrame {
            .status = ParseStatus::malformed,
            .header_length = detail::kGreBaseHeaderSize,
        };
    }

    const auto bytes = direct::visible_captured_bytes(slice);
    if (bytes.size() < detail::kGreBaseHeaderSize) {
        return ParsedEoipFrame {
            .status = ParseStatus::truncated,
            .header_length = detail::kGreBaseHeaderSize,
        };
    }

    const auto gre_flags_and_version = detail::read_be16(bytes, 0U);
    const auto gre_protocol_type = detail::read_be16(bytes, 2U);
    if (!detail::has_strict_eoip_signature(gre_flags_and_version, gre_protocol_type)) {
        return ParsedEoipFrame {
            .status = ParseStatus::unsupported_variant,
            .gre_flags_and_version = gre_flags_and_version,
            .gre_protocol_type = gre_protocol_type,
            .header_length = detail::kGreBaseHeaderSize,
        };
    }

    if (declared_length < kEoipHeaderSize) {
        return ParsedEoipFrame {
            .status = ParseStatus::malformed,
            .gre_flags_and_version = gre_flags_and_version,
            .gre_protocol_type = gre_protocol_type,
            .header_length = kEoipHeaderSize,
        };
    }

    if (bytes.size() < kEoipHeaderSize) {
        return ParsedEoipFrame {
            .status = ParseStatus::truncated,
            .gre_flags_and_version = gre_flags_and_version,
            .gre_protocol_type = gre_protocol_type,
            .header_length = kEoipHeaderSize,
        };
    }

    const auto frame_length = detail::read_be16(bytes, detail::kGreBaseHeaderSize);
    const auto tunnel_id = detail::read_le16(bytes, detail::kGreBaseHeaderSize + 2U);
    const auto full_length = kEoipHeaderSize + static_cast<std::size_t>(frame_length);
    if (full_length < kEoipHeaderSize || full_length > declared_length) {
        return ParsedEoipFrame {
            .status = ParseStatus::malformed,
            .gre_flags_and_version = gre_flags_and_version,
            .gre_protocol_type = gre_protocol_type,
            .frame_length = frame_length,
            .tunnel_id = tunnel_id,
            .header_length = kEoipHeaderSize,
            .declared_payload_length = frame_length,
        };
    }

    if (bytes.size() < full_length) {
        return ParsedEoipFrame {
            .status = ParseStatus::truncated,
            .gre_flags_and_version = gre_flags_and_version,
            .gre_protocol_type = gre_protocol_type,
            .frame_length = frame_length,
            .tunnel_id = tunnel_id,
            .header_length = kEoipHeaderSize,
            .declared_payload_length = frame_length,
        };
    }

    return ParsedEoipFrame {
        .status = ParseStatus::complete,
        .gre_flags_and_version = gre_flags_and_version,
        .gre_protocol_type = gre_protocol_type,
        .frame_length = frame_length,
        .tunnel_id = tunnel_id,
        .header_length = kEoipHeaderSize,
        .declared_payload_length = frame_length,
    };
}

DissectionStep dissect_ipv4_gre_variant(const PacketSlice& slice) {
    const auto bytes = direct::visible_captured_bytes(slice);
    if (bytes.size() >= detail::kGreBaseHeaderSize &&
        detail::has_strict_eoip_signature(detail::read_be16(bytes, 0U), detail::read_be16(bytes, 2U))) {
        return dissect_eoip(slice);
    }

    return dissect_gre(slice);
}

DissectionStep dissect_eoip(const PacketSlice& slice) {
    const auto parsed = parse_eoip_frame(slice);
    if (parsed.status != ParseStatus::complete) {
        return make_eoip_error_step(
            slice,
            parsed.status,
            parsed.status == ParseStatus::truncated ? StopReason::truncated : StopReason::malformed,
            parsed.header_length
        );
    }

    DissectionStep step {
        .layer = DissectionLayerKind::eoip,
        .path_contribution = LayerKey::gre(parsed.tunnel_id),
        .path_commit_policy = PathCommitPolicy::recognized_flow_or_recognized_non_flow,
        .descendant_path_commit_policy = PathCommitPolicy::recognized_flow_or_recognized_non_flow,
        .bounds = make_eoip_bounds(
            slice,
            parsed.header_length + parsed.declared_payload_length,
            parsed.header_length
        ),
        .facts = EoipFacts {
            .gre_flags_and_version = parsed.gre_flags_and_version,
            .gre_protocol_type = parsed.gre_protocol_type,
            .frame_length = parsed.frame_length,
            .tunnel_id = parsed.tunnel_id,
            .header_length = static_cast<std::uint16_t>(parsed.header_length),
        },
        .terminal_disposition = TerminalDisposition::none,
        .status = ParseStatus::complete,
        .stop_reason = StopReason::none,
    };

    step.handoff = direct::make_protocol_handoff(
        slice,
        parsed.header_length,
        parsed.declared_payload_length,
        make_eoip_inner_frame_selector()
    );
    if (!step.handoff.has_value()) {
        step.status = ParseStatus::malformed;
        step.stop_reason = StopReason::malformed;
    }
    return step;
}

DissectionStep dissect_eoip_inner_ethernet(const PacketSlice& slice) {
    const auto parsed = parse_ethernet_frame(slice);
    if (parsed.status != ParseStatus::complete) {
        return make_eoip_inner_ethernet_error_step(
            slice,
            parsed.status,
            parsed.status == ParseStatus::truncated ? StopReason::truncated : StopReason::malformed
        );
    }

    const auto declared_payload_length = parsed.is_ieee_802_3
        ? static_cast<std::size_t>(parsed.protocol_type)
        : parsed.declared_payload_length;

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
            declared_payload_length,
            make_eoip_inner_ieee8023_payload_selector()
        );
        if (!step.handoff.has_value()) {
            step.status = ParseStatus::malformed;
            step.stop_reason = StopReason::malformed;
        }
        return step;
    }

    if (!is_supported_eoip_inner_ether_type(parsed.protocol_type)) {
        step.stop_reason = StopReason::unknown_next_protocol;
        return step;
    }

    step.handoff = direct::make_protocol_handoff(
        slice,
        parsed.header_length,
        declared_payload_length,
        make_eoip_inner_ether_type_selector(parsed.protocol_type)
    );
    if (!step.handoff.has_value()) {
        step.status = ParseStatus::malformed;
        step.stop_reason = StopReason::malformed;
    }
    return step;
}

DissectionStep dissect_eoip_inner_vlan(const PacketSlice& slice) {
    const auto parsed = parse_vlan_tag(slice);
    if (parsed.status != ParseStatus::complete) {
        return make_eoip_inner_vlan_error_step(
            slice,
            parsed.status,
            parsed.status == ParseStatus::truncated ? StopReason::truncated : StopReason::malformed
        );
    }

    DissectionStep step {
        .layer = DissectionLayerKind::vlan,
        .path_contribution = LayerKey::vlan(static_cast<std::uint16_t>(parsed.tci & 0x0FFFU)),
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
        ? SelectorDomain::eoip_inner_ieee8023_payload
        : SelectorDomain::eoip_inner_ether_type;
    const auto next_value = parsed.encapsulated_ether_type < detail::kIeee8023LengthCutoff
        ? kEoipInnerIeee8023PayloadSelectorValue
        : static_cast<std::uint32_t>(parsed.encapsulated_ether_type);

    if (next_domain == SelectorDomain::eoip_inner_ether_type &&
        !is_supported_eoip_inner_ether_type(parsed.encapsulated_ether_type)) {
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

DissectionStep dissect_eoip_inner_llc_snap(const PacketSlice& slice) {
    const auto parsed = parse_llc_snap_payload(slice);
    const auto declared_length = direct::slice_declared_length(slice);

    if (parsed.status == ParseStatus::truncated) {
        return DissectionStep {
            .layer = DissectionLayerKind::llc_snap,
            .bounds = direct::make_layer_bounds(slice, declared_length, parsed.header_length),
            .facts = std::monostate {},
            .terminal_disposition = TerminalDisposition::none,
            .status = ParseStatus::truncated,
            .stop_reason = StopReason::truncated,
        };
    }

    if (parsed.status != ParseStatus::complete) {
        return DissectionStep {
            .layer = DissectionLayerKind::llc_snap,
            .bounds = direct::make_layer_bounds(slice, declared_length, 0U),
            .facts = std::monostate {},
            .terminal_disposition = TerminalDisposition::none,
            .status = ParseStatus::malformed,
            .stop_reason = StopReason::malformed,
        };
    }

    const auto facts = LlcSnapFacts {
        .dsap = parsed.dsap,
        .ssap = parsed.ssap,
        .control = parsed.control,
        .has_snap = parsed.has_snap,
        .oui = parsed.oui,
        .pid = parsed.pid,
    };

    if (!parsed.has_snap) {
        return DissectionStep {
            .layer = DissectionLayerKind::llc_snap,
            .bounds = direct::make_layer_bounds(slice, detail::kLlcHeaderSize, detail::kLlcHeaderSize),
            .facts = facts,
            .terminal_disposition = TerminalDisposition::none,
            .status = ParseStatus::complete,
            .stop_reason = StopReason::unrecognized_payload,
        };
    }

    if (!parsed.pid_supported) {
        return DissectionStep {
            .layer = DissectionLayerKind::llc_snap,
            .bounds = direct::make_layer_bounds(slice, detail::kLlcSnapHeaderSize, detail::kLlcSnapHeaderSize),
            .facts = facts,
            .terminal_disposition = TerminalDisposition::none,
            .status = ParseStatus::complete,
            .stop_reason = StopReason::unrecognized_payload,
        };
    }

    const auto handoff = direct::make_protocol_handoff(
        slice,
        detail::kLlcSnapHeaderSize,
        declared_length - detail::kLlcSnapHeaderSize,
        make_eoip_inner_llc_snap_pid_selector(parsed.pid)
    );
    if (!handoff.has_value()) {
        return DissectionStep {
            .layer = DissectionLayerKind::llc_snap,
            .bounds = direct::make_layer_bounds(
                slice,
                declared_length,
                detail::kLlcSnapHeaderSize,
                direct::RelativeRange {.begin = detail::kLlcSnapHeaderSize, .end = declared_length},
                true
            ),
            .facts = facts,
            .terminal_disposition = TerminalDisposition::none,
            .status = ParseStatus::malformed,
            .stop_reason = StopReason::malformed,
        };
    }

    return DissectionStep {
        .layer = DissectionLayerKind::llc_snap,
        .path_contribution = LayerKey::llc_snap(),
        .path_commit_policy = PathCommitPolicy::recognized_flow_or_recognized_non_flow,
        .descendant_path_commit_policy = PathCommitPolicy::recognized_flow_or_recognized_non_flow,
        .defer_last_deferrable_path_contribution = true,
        .bounds = direct::make_layer_bounds(
            slice,
            declared_length,
            detail::kLlcSnapHeaderSize,
            direct::RelativeRange {.begin = detail::kLlcSnapHeaderSize, .end = declared_length},
            true
        ),
        .handoff = *handoff,
        .facts = facts,
        .terminal_disposition = TerminalDisposition::none,
        .status = ParseStatus::complete,
        .stop_reason = StopReason::none,
    };
}

DissectionStep dissect_eoip_inner_ipv4(const PacketSlice& slice) {
    const auto parsed = parse_ipv4_packet(slice);
    if (parsed.status != ParseStatus::complete) {
        return make_eoip_inner_network_error_step(
            slice,
            DissectionLayerKind::ipv4,
            parsed.status,
            detail::kIpv4MinimumHeaderSize
        );
    }

    const auto bounded_full_end = std::min(parsed.nominal_packet_end, direct::slice_declared_length(slice));
    const auto next_selector = make_eoip_inner_ip_protocol_selector(parsed.protocol);
    DissectionStep step {
        .layer = DissectionLayerKind::ipv4,
        .path_contribution = LayerKey::ipv4(),
        .bounds = direct::make_layer_bounds(
            slice,
            bounded_full_end,
            parsed.header_length,
            direct::RelativeRange {.begin = parsed.header_length, .end = bounded_full_end},
            true
        ),
        .facts = Ipv4Facts {
            .protocol = parsed.protocol,
            .total_length = parsed.total_length,
            .header_length = parsed.header_length,
            .src_addr_v4 = parsed.src_addr,
            .dst_addr_v4 = parsed.dst_addr,
            .is_fragmented = parsed.is_fragmented,
            .more_fragments = parsed.more_fragments,
            .fragment_offset_units = parsed.fragment_offset_units,
            .options = parsed.options,
        },
        .terminal_disposition = TerminalDisposition::none,
        .status = ParseStatus::complete,
        .stop_reason = StopReason::none,
    };

    if (parsed.is_fragmented) {
        step.handoff = direct::make_selector_handoff(next_selector);
        step.stop_reason = StopReason::needs_reassembly;
        return step;
    }

    step.handoff = direct::make_protocol_handoff(
        slice,
        parsed.header_length,
        parsed.nominal_packet_end - parsed.header_length,
        next_selector
    );
    if (!step.handoff.has_value()) {
        step.status = ParseStatus::malformed;
        step.stop_reason = StopReason::malformed;
    }
    return step;
}

DissectionStep dissect_eoip_inner_ipv6(const PacketSlice& slice) {
    const auto parsed = parse_ipv6_packet(slice);
    if (parsed.status != ParseStatus::complete) {
        return make_eoip_inner_network_error_step(
            slice,
            DissectionLayerKind::ipv6,
            parsed.status,
            detail::kIpv6HeaderSize
        );
    }

    const auto payload_slice = make_child_slice(slice, parsed.header_length, parsed.payload_length);
    if (!payload_slice.has_slice()) {
        return make_eoip_inner_network_error_step(
            slice,
            DissectionLayerKind::ipv6,
            ParseStatus::malformed,
            parsed.header_length
        );
    }

    DissectionStep step {
        .layer = DissectionLayerKind::ipv6,
        .path_contribution = LayerKey::ipv6(),
        .bounds = direct::make_layer_bounds(
            slice,
            parsed.nominal_packet_end,
            parsed.header_length,
            direct::RelativeRange {.begin = parsed.header_length, .end = parsed.nominal_packet_end},
            true
        ),
        .handoff = ProtocolHandoff {
            .selector = make_eoip_inner_ipv6_next_header_selector(parsed.next_header),
            .child = *payload_slice.slice,
        },
        .facts = Ipv6Facts {
            .next_header = parsed.next_header,
            .payload_length = parsed.payload_length,
            .src_addr_v6 = parsed.src_addr,
            .dst_addr_v6 = parsed.dst_addr,
        },
        .terminal_disposition = TerminalDisposition::none,
        .status = ParseStatus::complete,
        .stop_reason = StopReason::none,
    };
    return step;
}

}  // namespace pfl::dissection
