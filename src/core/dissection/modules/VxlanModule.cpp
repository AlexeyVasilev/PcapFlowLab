#include "core/dissection/modules/VxlanModule.h"

#include <algorithm>

#include "core/decode/PacketDecodeSupport.h"
#include "core/dissection/modules/CommonDirectModuleSupport.h"
#include "core/dissection/modules/EthernetVlanModules.h"
#include "core/dissection/modules/Ipv4Module.h"
#include "core/dissection/modules/Ipv6Module.h"
#include "core/dissection/modules/LlcSnapModule.h"
#include "core/dissection/modules/TransportModules.h"

namespace pfl::dissection {

namespace {

ProtocolSelector make_vxlan_inner_frame_selector() noexcept {
    return ProtocolSelector {
        .domain = SelectorDomain::vxlan_inner_frame,
        .value = kVxlanInnerFrameSelectorValue,
    };
}

ProtocolSelector make_vxlan_inner_ether_type_selector(const std::uint16_t ether_type) noexcept {
    return ProtocolSelector {
        .domain = SelectorDomain::vxlan_inner_ether_type,
        .value = ether_type,
    };
}

ProtocolSelector make_vxlan_inner_ieee8023_payload_selector() noexcept {
    return ProtocolSelector {
        .domain = SelectorDomain::vxlan_inner_ieee8023_payload,
        .value = kVxlanInnerIeee8023PayloadSelectorValue,
    };
}

ProtocolSelector make_vxlan_inner_llc_snap_pid_selector(const std::uint16_t pid) noexcept {
    return ProtocolSelector {
        .domain = SelectorDomain::vxlan_inner_llc_snap_pid,
        .value = pid,
    };
}

ProtocolSelector make_vxlan_inner_ip_protocol_selector(const std::uint8_t protocol) noexcept {
    return ProtocolSelector {
        .domain = SelectorDomain::vxlan_inner_ip_protocol,
        .value = protocol,
    };
}

ProtocolSelector make_vxlan_inner_ipv6_next_header_selector(const std::uint8_t next_header) noexcept {
    return ProtocolSelector {
        .domain = SelectorDomain::vxlan_inner_ipv6_next_header,
        .value = next_header,
    };
}

struct VxlanInnerValidation {
    ParseStatus status {ParseStatus::opaque};
};

bool is_supported_vxlan_inner_ether_type(const std::uint16_t ether_type) noexcept {
    return ether_type == detail::kEtherTypeIpv4 ||
           ether_type == detail::kEtherTypeIpv6 ||
           ether_type == detail::kEtherTypeVlan ||
           ether_type == detail::kEtherTypeQinq ||
           ether_type == detail::kEtherTypeLegacyVlan;
}

bool is_supported_vxlan_inner_transport_protocol(const std::uint8_t protocol) noexcept {
    return protocol == detail::kIpProtocolTcp ||
           protocol == detail::kIpProtocolUdp ||
           protocol == detail::kIpProtocolSctp;
}

bool is_supported_vxlan_inner_llc_snap_pid(const std::uint16_t pid) noexcept {
    return pid == detail::kEtherTypeIpv4 || pid == detail::kEtherTypeIpv6;
}

DissectionStep make_vxlan_fallback_step(const PacketSlice& slice, const ParseStatus status) noexcept {
    return DissectionStep {
        .layer = DissectionLayerKind::unknown,
        .bounds = direct::make_layer_bounds(
            slice,
            direct::slice_declared_length(slice),
            std::min<std::size_t>(detail::kVxlanHeaderSize, direct::slice_declared_length(slice))
        ),
        .facts = std::monostate {},
        .terminal_disposition = TerminalDisposition::none,
        .status = status,
        .stop_reason = StopReason::terminal_protocol,
    };
}

DissectionStep make_vxlan_inner_ethernet_error_step(
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

DissectionStep make_vxlan_inner_vlan_error_step(
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

DissectionStep make_vxlan_inner_network_error_step(
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
        std::min(header_length, direct::slice_declared_length(slice))
    );
}

VxlanInnerValidation validate_vxlan_inner_ipv4(const PacketSlice& slice) noexcept;
VxlanInnerValidation validate_vxlan_inner_ipv6(const PacketSlice& slice) noexcept;
VxlanInnerValidation validate_vxlan_inner_llc_snap(const PacketSlice& slice) noexcept;
VxlanInnerValidation validate_vxlan_inner_vlan(const PacketSlice& slice) noexcept;

VxlanInnerValidation validate_vxlan_inner_transport(
    const PacketSlice& transport_slice,
    const std::uint8_t protocol
) noexcept {
    if (protocol == detail::kIpProtocolTcp) {
        return VxlanInnerValidation {.status = parse_tcp_segment(transport_slice).status};
    }
    if (protocol == detail::kIpProtocolUdp) {
        return VxlanInnerValidation {.status = parse_udp_datagram(transport_slice).status};
    }
    if (protocol == detail::kIpProtocolSctp) {
        return VxlanInnerValidation {.status = parse_sctp_common_header(transport_slice).status};
    }

    return VxlanInnerValidation {.status = ParseStatus::unsupported_variant};
}

VxlanInnerValidation validate_vxlan_inner_ipv4(const PacketSlice& slice) noexcept {
    const auto parsed = parse_ipv4_packet(slice);
    if (parsed.status != ParseStatus::complete) {
        return VxlanInnerValidation {.status = parsed.status};
    }
    if (parsed.is_fragmented || !is_supported_vxlan_inner_transport_protocol(parsed.protocol)) {
        return VxlanInnerValidation {.status = ParseStatus::unsupported_variant};
    }

    const auto child = make_child_slice(
        slice,
        parsed.header_length,
        parsed.nominal_packet_end - parsed.header_length
    );
    if (!child.has_slice()) {
        return VxlanInnerValidation {.status = ParseStatus::malformed};
    }

    return validate_vxlan_inner_transport(*child.slice, parsed.protocol);
}

VxlanInnerValidation validate_vxlan_inner_ipv6(const PacketSlice& slice) noexcept {
    const auto parsed = parse_ipv6_packet(slice);
    if (parsed.status != ParseStatus::complete) {
        return VxlanInnerValidation {.status = parsed.status};
    }
    if (!is_supported_vxlan_inner_transport_protocol(parsed.next_header)) {
        return VxlanInnerValidation {.status = ParseStatus::unsupported_variant};
    }

    const auto child = make_child_slice(slice, parsed.header_length, parsed.payload_length);
    if (!child.has_slice()) {
        return VxlanInnerValidation {.status = ParseStatus::malformed};
    }

    return validate_vxlan_inner_transport(*child.slice, parsed.next_header);
}

VxlanInnerValidation validate_vxlan_inner_llc_snap(const PacketSlice& slice) noexcept {
    const auto parsed = parse_llc_snap_payload(slice);
    if (parsed.status != ParseStatus::complete) {
        return VxlanInnerValidation {.status = parsed.status};
    }
    if (!parsed.has_snap || !is_supported_vxlan_inner_llc_snap_pid(parsed.pid)) {
        return VxlanInnerValidation {.status = ParseStatus::unsupported_variant};
    }

    const auto child = make_child_slice(
        slice,
        parsed.header_length,
        direct::slice_declared_length(slice) - parsed.header_length
    );
    if (!child.has_slice()) {
        return VxlanInnerValidation {.status = ParseStatus::malformed};
    }

    if (parsed.pid == detail::kEtherTypeIpv4) {
        return validate_vxlan_inner_ipv4(*child.slice);
    }
    if (parsed.pid == detail::kEtherTypeIpv6) {
        return validate_vxlan_inner_ipv6(*child.slice);
    }

    return VxlanInnerValidation {.status = ParseStatus::unsupported_variant};
}

VxlanInnerValidation validate_vxlan_inner_vlan(const PacketSlice& slice) noexcept {
    const auto parsed = parse_vlan_tag(slice);
    if (parsed.status != ParseStatus::complete) {
        return VxlanInnerValidation {.status = parsed.status};
    }

    const auto child_length = parsed.encapsulated_ether_type < detail::kIeee8023LengthCutoff
        ? static_cast<std::size_t>(parsed.encapsulated_ether_type)
        : parsed.declared_payload_length;
    const auto child = make_child_slice(slice, parsed.header_length, child_length);
    if (!child.has_slice()) {
        return VxlanInnerValidation {.status = ParseStatus::malformed};
    }

    if (parsed.encapsulated_ether_type < detail::kIeee8023LengthCutoff) {
        return validate_vxlan_inner_llc_snap(*child.slice);
    }
    if (parsed.encapsulated_ether_type == detail::kEtherTypeIpv4) {
        return validate_vxlan_inner_ipv4(*child.slice);
    }
    if (parsed.encapsulated_ether_type == detail::kEtherTypeIpv6) {
        return validate_vxlan_inner_ipv6(*child.slice);
    }
    if (parsed.encapsulated_ether_type == detail::kEtherTypeVlan ||
        parsed.encapsulated_ether_type == detail::kEtherTypeQinq ||
        parsed.encapsulated_ether_type == detail::kEtherTypeLegacyVlan) {
        return validate_vxlan_inner_vlan(*child.slice);
    }

    return VxlanInnerValidation {.status = ParseStatus::unsupported_variant};
}

VxlanInnerValidation validate_vxlan_inner_ethernet(const PacketSlice& slice) noexcept {
    const auto parsed = parse_ethernet_frame(slice);
    if (parsed.status != ParseStatus::complete) {
        return VxlanInnerValidation {.status = parsed.status};
    }

    const auto child_length = parsed.is_ieee_802_3
        ? static_cast<std::size_t>(parsed.protocol_type)
        : parsed.declared_payload_length;
    const auto child = make_child_slice(slice, parsed.header_length, child_length);
    if (!child.has_slice()) {
        return VxlanInnerValidation {.status = ParseStatus::malformed};
    }

    if (parsed.is_ieee_802_3) {
        return validate_vxlan_inner_llc_snap(*child.slice);
    }
    if (parsed.protocol_type == detail::kEtherTypeIpv4) {
        return validate_vxlan_inner_ipv4(*child.slice);
    }
    if (parsed.protocol_type == detail::kEtherTypeIpv6) {
        return validate_vxlan_inner_ipv6(*child.slice);
    }
    if (parsed.protocol_type == detail::kEtherTypeVlan ||
        parsed.protocol_type == detail::kEtherTypeQinq ||
        parsed.protocol_type == detail::kEtherTypeLegacyVlan) {
        return validate_vxlan_inner_vlan(*child.slice);
    }

    return VxlanInnerValidation {.status = ParseStatus::unsupported_variant};
}

}  // namespace

ParsedVxlanHeader parse_vxlan_header(const PacketSlice& slice) noexcept {
    const auto declared_length = direct::slice_declared_length(slice);
    if (declared_length < detail::kVxlanHeaderSize) {
        return ParsedVxlanHeader {
            .status = ParseStatus::malformed,
            .header_length = detail::kVxlanHeaderSize,
        };
    }

    const auto bytes = direct::visible_captured_bytes(slice);
    if (bytes.size() < detail::kVxlanHeaderSize) {
        return ParsedVxlanHeader {
            .status = ParseStatus::truncated,
            .header_length = detail::kVxlanHeaderSize,
        };
    }

    const auto flags = bytes[0U];
    if (flags != detail::kVxlanFlagI ||
        bytes[1U] != 0U ||
        bytes[2U] != 0U ||
        bytes[3U] != 0U ||
        bytes[7U] != 0U) {
        return ParsedVxlanHeader {
            .status = ParseStatus::unsupported_variant,
            .flags = flags,
            .vni = ((static_cast<std::uint32_t>(bytes[4U]) << 16U) |
                    (static_cast<std::uint32_t>(bytes[5U]) << 8U) |
                    static_cast<std::uint32_t>(bytes[6U])),
            .header_length = detail::kVxlanHeaderSize,
            .declared_payload_length = declared_length - detail::kVxlanHeaderSize,
        };
    }

    return ParsedVxlanHeader {
        .status = ParseStatus::complete,
        .flags = flags,
        .vni = ((static_cast<std::uint32_t>(bytes[4U]) << 16U) |
                (static_cast<std::uint32_t>(bytes[5U]) << 8U) |
                static_cast<std::uint32_t>(bytes[6U])),
        .header_length = detail::kVxlanHeaderSize,
        .declared_payload_length = declared_length - detail::kVxlanHeaderSize,
    };
}

DissectionStep dissect_vxlan(const PacketSlice& slice) {
    const auto parsed = parse_vxlan_header(slice);
    if (parsed.status != ParseStatus::complete) {
        return make_vxlan_fallback_step(slice, parsed.status);
    }

    const auto handoff = direct::make_protocol_handoff(
        slice,
        parsed.header_length,
        parsed.declared_payload_length,
        make_vxlan_inner_frame_selector()
    );
    if (!handoff.has_value()) {
        return make_vxlan_fallback_step(slice, ParseStatus::malformed);
    }

    const auto validation = validate_vxlan_inner_ethernet(*handoff->child);
    if (validation.status != ParseStatus::complete) {
        return make_vxlan_fallback_step(slice, validation.status);
    }

    return DissectionStep {
        .layer = DissectionLayerKind::vxlan,
        .path_contribution = LayerKey::vxlan(parsed.vni),
        .path_commit_policy = PathCommitPolicy::recognized_flow,
        .descendant_path_commit_policy = PathCommitPolicy::recognized_flow,
        .bounds = direct::make_layer_bounds(
            slice,
            direct::slice_declared_length(slice),
            parsed.header_length,
            direct::RelativeRange {.begin = parsed.header_length, .end = direct::slice_declared_length(slice)},
            true
        ),
        .handoff = *handoff,
        .facts = VxlanFacts {
            .flags = parsed.flags,
            .vni = parsed.vni,
        },
        .terminal_disposition = TerminalDisposition::none,
        .status = ParseStatus::complete,
        .stop_reason = StopReason::none,
    };
}

DissectionStep dissect_vxlan_inner_ethernet(const PacketSlice& slice) {
    const auto parsed = parse_ethernet_frame(slice);
    if (parsed.status != ParseStatus::complete) {
        return make_vxlan_inner_ethernet_error_step(
            slice,
            parsed.status,
            parsed.status == ParseStatus::truncated ? StopReason::truncated : StopReason::malformed
        );
    }

    const auto child_length = parsed.is_ieee_802_3
        ? static_cast<std::size_t>(parsed.protocol_type)
        : parsed.declared_payload_length;
    const auto handoff = direct::make_protocol_handoff(
        slice,
        parsed.header_length,
        child_length,
        parsed.is_ieee_802_3
            ? make_vxlan_inner_ieee8023_payload_selector()
            : make_vxlan_inner_ether_type_selector(parsed.protocol_type)
    );
    if (!handoff.has_value()) {
        return make_vxlan_inner_ethernet_error_step(
            slice,
            ParseStatus::malformed,
            StopReason::malformed
        );
    }

    if (!parsed.is_ieee_802_3 && !is_supported_vxlan_inner_ether_type(parsed.protocol_type)) {
        return make_vxlan_inner_ethernet_error_step(
            slice,
            ParseStatus::unsupported_variant,
            StopReason::unknown_next_protocol
        );
    }

    return DissectionStep {
        .layer = parsed.is_ieee_802_3 ? DissectionLayerKind::ieee8023 : DissectionLayerKind::ethernet_ii,
        .path_contribution = parsed.is_ieee_802_3 ? LayerKey::ieee8023() : LayerKey::ethernet_ii(),
        .path_commit_policy = PathCommitPolicy::recognized_flow,
        .descendant_path_commit_policy = PathCommitPolicy::recognized_flow,
        .path_contribution_deferrable_by_child = parsed.is_ieee_802_3,
        .bounds = direct::make_layer_bounds(
            slice,
            direct::slice_declared_length(slice),
            parsed.header_length,
            direct::RelativeRange {.begin = parsed.header_length, .end = direct::slice_declared_length(slice)},
            true
        ),
        .handoff = *handoff,
        .facts = EthernetFacts {
            .protocol_type = parsed.protocol_type,
            .is_ieee_802_3 = parsed.is_ieee_802_3,
        },
        .terminal_disposition = TerminalDisposition::none,
        .status = ParseStatus::complete,
        .stop_reason = StopReason::none,
    };
}

DissectionStep dissect_vxlan_inner_vlan(const PacketSlice& slice) {
    const auto parsed = parse_vlan_tag(slice);
    if (parsed.status != ParseStatus::complete) {
        return make_vxlan_inner_vlan_error_step(
            slice,
            parsed.status,
            parsed.status == ParseStatus::truncated ? StopReason::truncated : StopReason::malformed
        );
    }

    const auto child_length = parsed.encapsulated_ether_type < detail::kIeee8023LengthCutoff
        ? static_cast<std::size_t>(parsed.encapsulated_ether_type)
        : parsed.declared_payload_length;
    const auto handoff = direct::make_protocol_handoff(
        slice,
        parsed.header_length,
        child_length,
        parsed.encapsulated_ether_type < detail::kIeee8023LengthCutoff
            ? make_vxlan_inner_ieee8023_payload_selector()
            : make_vxlan_inner_ether_type_selector(parsed.encapsulated_ether_type)
    );
    if (!handoff.has_value()) {
        return make_vxlan_inner_vlan_error_step(
            slice,
            ParseStatus::malformed,
            StopReason::malformed
        );
    }

    if (parsed.encapsulated_ether_type >= detail::kIeee8023LengthCutoff &&
        !is_supported_vxlan_inner_ether_type(parsed.encapsulated_ether_type)) {
        return make_vxlan_inner_vlan_error_step(
            slice,
            ParseStatus::unsupported_variant,
            StopReason::unknown_next_protocol
        );
    }

    return DissectionStep {
        .layer = DissectionLayerKind::vlan,
        .path_contribution = LayerKey::vlan(static_cast<std::uint16_t>(parsed.tci & 0x0FFFU)),
        .path_commit_policy = PathCommitPolicy::recognized_flow,
        .descendant_path_commit_policy = PathCommitPolicy::recognized_flow,
        .bounds = direct::make_layer_bounds(
            slice,
            direct::slice_declared_length(slice),
            parsed.header_length,
            direct::RelativeRange {.begin = parsed.header_length, .end = direct::slice_declared_length(slice)},
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

DissectionStep dissect_vxlan_inner_llc_snap(const PacketSlice& slice) {
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

    if (!parsed.has_snap || !is_supported_vxlan_inner_llc_snap_pid(parsed.pid)) {
        return DissectionStep {
            .layer = DissectionLayerKind::llc_snap,
            .bounds = direct::make_layer_bounds(slice, parsed.header_length, parsed.header_length),
            .facts = facts,
            .terminal_disposition = TerminalDisposition::none,
            .status = ParseStatus::unsupported_variant,
            .stop_reason = StopReason::unrecognized_payload,
        };
    }

    const auto handoff = direct::make_protocol_handoff(
        slice,
        parsed.header_length,
        declared_length - parsed.header_length,
        make_vxlan_inner_llc_snap_pid_selector(parsed.pid)
    );
    if (!handoff.has_value()) {
        return DissectionStep {
            .layer = DissectionLayerKind::llc_snap,
            .bounds = direct::make_layer_bounds(
                slice,
                declared_length,
                parsed.header_length,
                direct::RelativeRange {.begin = parsed.header_length, .end = declared_length},
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
        .path_commit_policy = PathCommitPolicy::recognized_flow,
        .descendant_path_commit_policy = PathCommitPolicy::recognized_flow,
        .defer_last_deferrable_path_contribution = true,
        .bounds = direct::make_layer_bounds(
            slice,
            declared_length,
            parsed.header_length,
            direct::RelativeRange {.begin = parsed.header_length, .end = declared_length},
            true
        ),
        .handoff = *handoff,
        .facts = facts,
        .terminal_disposition = TerminalDisposition::none,
        .status = ParseStatus::complete,
        .stop_reason = StopReason::none,
    };
}

DissectionStep dissect_vxlan_inner_ipv4(const PacketSlice& slice) {
    const auto parsed = parse_ipv4_packet(slice);
    if (parsed.status != ParseStatus::complete) {
        return make_vxlan_inner_network_error_step(
            slice,
            DissectionLayerKind::ipv4,
            parsed.status,
            detail::kIpv4MinimumHeaderSize
        );
    }
    if (parsed.is_fragmented || !is_supported_vxlan_inner_transport_protocol(parsed.protocol)) {
        return direct::make_error_step(
            slice,
            DissectionLayerKind::ipv4,
            ParseStatus::unsupported_variant,
            parsed.is_fragmented ? StopReason::needs_reassembly : StopReason::unknown_next_protocol,
            parsed.header_length
        );
    }

    const auto handoff = direct::make_protocol_handoff(
        slice,
        parsed.header_length,
        parsed.nominal_packet_end - parsed.header_length,
        make_vxlan_inner_ip_protocol_selector(parsed.protocol)
    );
    if (!handoff.has_value()) {
        return make_vxlan_inner_network_error_step(
            slice,
            DissectionLayerKind::ipv4,
            ParseStatus::malformed,
            parsed.header_length
        );
    }

    return DissectionStep {
        .layer = DissectionLayerKind::ipv4,
        .path_contribution = LayerKey::ipv4(),
        .path_commit_policy = PathCommitPolicy::recognized_flow,
        .descendant_path_commit_policy = PathCommitPolicy::recognized_flow,
        .bounds = direct::make_layer_bounds(
            slice,
            std::min(parsed.nominal_packet_end, direct::slice_declared_length(slice)),
            parsed.header_length,
            direct::RelativeRange {.begin = parsed.header_length, .end = std::min(parsed.nominal_packet_end, direct::slice_declared_length(slice))},
            true
        ),
        .handoff = *handoff,
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
}

DissectionStep dissect_vxlan_inner_ipv6(const PacketSlice& slice) {
    const auto parsed = parse_ipv6_packet(slice);
    if (parsed.status != ParseStatus::complete) {
        return make_vxlan_inner_network_error_step(
            slice,
            DissectionLayerKind::ipv6,
            parsed.status,
            detail::kIpv6HeaderSize
        );
    }
    if (!is_supported_vxlan_inner_transport_protocol(parsed.next_header)) {
        return direct::make_error_step(
            slice,
            DissectionLayerKind::ipv6,
            ParseStatus::unsupported_variant,
            StopReason::unknown_next_protocol,
            parsed.header_length
        );
    }

    const auto payload_slice = make_child_slice(slice, parsed.header_length, parsed.payload_length);
    if (!payload_slice.has_slice()) {
        return make_vxlan_inner_network_error_step(
            slice,
            DissectionLayerKind::ipv6,
            ParseStatus::malformed,
            parsed.header_length
        );
    }

    return DissectionStep {
        .layer = DissectionLayerKind::ipv6,
        .path_contribution = LayerKey::ipv6(),
        .path_commit_policy = PathCommitPolicy::recognized_flow,
        .descendant_path_commit_policy = PathCommitPolicy::recognized_flow,
        .bounds = direct::make_layer_bounds(
            slice,
            parsed.nominal_packet_end,
            parsed.header_length,
            direct::RelativeRange {.begin = parsed.header_length, .end = parsed.nominal_packet_end},
            true
        ),
        .handoff = ProtocolHandoff {
            .selector = make_vxlan_inner_ipv6_next_header_selector(parsed.next_header),
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
}

}  // namespace pfl::dissection
