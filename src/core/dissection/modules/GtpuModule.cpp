#include "core/dissection/modules/GtpuModule.h"

#include <algorithm>

#include "core/decode/PacketDecodeSupport.h"
#include "core/dissection/modules/CommonDirectModuleSupport.h"
#include "core/dissection/modules/Ipv4Module.h"
#include "core/dissection/modules/Ipv6Module.h"
#include "core/dissection/modules/TransportModules.h"

namespace pfl::dissection {

namespace {

ProtocolSelector make_gtpu_inner_payload_selector(const std::uint16_t payload_type) noexcept {
    return ProtocolSelector {
        .domain = SelectorDomain::gtpu_inner_payload,
        .value = payload_type,
    };
}

ProtocolSelector make_gtpu_inner_ip_protocol_selector(const std::uint8_t protocol) noexcept {
    return ProtocolSelector {
        .domain = SelectorDomain::gtpu_inner_ip_protocol,
        .value = protocol,
    };
}

ProtocolSelector make_gtpu_inner_ipv6_next_header_selector(const std::uint8_t next_header) noexcept {
    return ProtocolSelector {
        .domain = SelectorDomain::gtpu_inner_ipv6_next_header,
        .value = next_header,
    };
}

struct GtpuInnerValidation {
    ParseStatus status {ParseStatus::opaque};
};

bool is_supported_gtpu_inner_transport_protocol(const std::uint8_t protocol) noexcept {
    return protocol == detail::kIpProtocolTcp ||
           protocol == detail::kIpProtocolUdp ||
           protocol == detail::kIpProtocolSctp;
}

DissectionStep make_gtpu_fallback_step(const PacketSlice& slice, const ParseStatus status) noexcept {
    return DissectionStep {
        .layer = DissectionLayerKind::unknown,
        .bounds = direct::make_layer_bounds(
            slice,
            direct::slice_declared_length(slice),
            std::min<std::size_t>(detail::kGtpuBaseHeaderSize, direct::slice_declared_length(slice))
        ),
        .facts = std::monostate {},
        .terminal_disposition = TerminalDisposition::none,
        .status = status,
        .stop_reason = StopReason::terminal_protocol,
    };
}

DissectionStep make_gtpu_inner_network_error_step(
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

GtpuInnerValidation validate_gtpu_inner_transport(
    const PacketSlice& transport_slice,
    const std::uint8_t protocol
) noexcept {
    if (protocol == detail::kIpProtocolTcp) {
        return GtpuInnerValidation {.status = parse_tcp_segment(transport_slice).status};
    }
    if (protocol == detail::kIpProtocolUdp) {
        return GtpuInnerValidation {.status = parse_udp_datagram(transport_slice).status};
    }
    if (protocol == detail::kIpProtocolSctp) {
        return GtpuInnerValidation {.status = parse_sctp_common_header(transport_slice).status};
    }

    return GtpuInnerValidation {.status = ParseStatus::unsupported_variant};
}

GtpuInnerValidation validate_gtpu_inner_ipv4(const PacketSlice& slice) noexcept {
    const auto parsed = parse_ipv4_packet(slice);
    if (parsed.status != ParseStatus::complete) {
        return GtpuInnerValidation {.status = parsed.status};
    }
    if (parsed.is_fragmented || !is_supported_gtpu_inner_transport_protocol(parsed.protocol)) {
        return GtpuInnerValidation {.status = ParseStatus::unsupported_variant};
    }

    const auto child = make_child_slice(
        slice,
        parsed.header_length,
        parsed.nominal_packet_end - parsed.header_length
    );
    if (!child.has_slice()) {
        return GtpuInnerValidation {.status = ParseStatus::malformed};
    }

    return validate_gtpu_inner_transport(*child.slice, parsed.protocol);
}

GtpuInnerValidation validate_gtpu_inner_ipv6(const PacketSlice& slice) noexcept {
    const auto parsed = parse_ipv6_packet(slice);
    if (parsed.status != ParseStatus::complete) {
        return GtpuInnerValidation {.status = parsed.status};
    }
    if (!is_supported_gtpu_inner_transport_protocol(parsed.next_header)) {
        return GtpuInnerValidation {.status = ParseStatus::unsupported_variant};
    }

    const auto child = make_child_slice(slice, parsed.header_length, parsed.payload_length);
    if (!child.has_slice()) {
        return GtpuInnerValidation {.status = ParseStatus::malformed};
    }

    return validate_gtpu_inner_transport(*child.slice, parsed.next_header);
}

}  // namespace

ParsedGtpuHeader parse_gtpu_header(const PacketSlice& slice) noexcept {
    const auto declared_length = direct::slice_declared_length(slice);
    if (declared_length < detail::kGtpuBaseHeaderSize) {
        return ParsedGtpuHeader {
            .status = ParseStatus::malformed,
            .header_length = detail::kGtpuBaseHeaderSize,
            .packet_length = detail::kGtpuBaseHeaderSize,
        };
    }

    const auto bytes = direct::visible_captured_bytes(slice);
    if (bytes.size() < detail::kGtpuBaseHeaderSize) {
        return ParsedGtpuHeader {
            .status = ParseStatus::truncated,
            .header_length = detail::kGtpuBaseHeaderSize,
            .packet_length = detail::kGtpuBaseHeaderSize,
        };
    }

    ParsedGtpuHeader parsed {
        .status = ParseStatus::complete,
        .flags = bytes[0U],
        .version = static_cast<std::uint8_t>((bytes[0U] >> 5U) & 0x07U),
        .message_type = bytes[1U],
        .length = detail::read_be16(bytes, 2U),
        .teid = detail::read_be32(bytes, 4U),
        .header_length = detail::kGtpuBaseHeaderSize,
        .packet_length = detail::kGtpuBaseHeaderSize,
    };

    if (parsed.version != 1U ||
        (parsed.flags & detail::kGtpuFlagProtocolType) == 0U ||
        parsed.message_type != detail::kGtpuMessageTypeTPdu) {
        parsed.status = ParseStatus::unsupported_variant;
        return parsed;
    }

    const auto declared_packet_length = detail::kGtpuBaseHeaderSize + static_cast<std::size_t>(parsed.length);
    parsed.packet_length = declared_packet_length;
    if (declared_packet_length > declared_length) {
        parsed.status = ParseStatus::malformed;
        return parsed;
    }
    if (bytes.size() < declared_packet_length) {
        parsed.status = ParseStatus::truncated;
        return parsed;
    }

    auto cursor = detail::kGtpuBaseHeaderSize;
    parsed.has_extension_headers = (parsed.flags & detail::kGtpuFlagExtensionHeader) != 0U;
    parsed.has_sequence_number = (parsed.flags & detail::kGtpuFlagSequenceNumber) != 0U;
    parsed.has_npdu_number = (parsed.flags & detail::kGtpuFlagNpduNumber) != 0U;
    parsed.has_optional_fields =
        parsed.has_extension_headers || parsed.has_sequence_number || parsed.has_npdu_number;

    if (parsed.has_optional_fields) {
        if (cursor + detail::kGtpuOptionalFieldsSize > declared_packet_length) {
            parsed.status = ParseStatus::malformed;
            return parsed;
        }
        if (bytes.size() < cursor + detail::kGtpuOptionalFieldsSize) {
            parsed.status = ParseStatus::truncated;
            return parsed;
        }

        parsed.sequence_number = detail::read_be16(bytes, cursor);
        parsed.npdu_number = bytes[cursor + 2U];
        parsed.first_extension_header_type = bytes[cursor + 3U];
        cursor += detail::kGtpuOptionalFieldsSize;

        if (parsed.has_extension_headers) {
            auto next_extension_header_type = parsed.first_extension_header_type;
            while (next_extension_header_type != 0U) {
                if (cursor >= declared_packet_length) {
                    parsed.status = ParseStatus::malformed;
                    return parsed;
                }
                if (bytes.size() <= cursor) {
                    parsed.status = ParseStatus::truncated;
                    return parsed;
                }

                const auto extension_length_units = static_cast<std::size_t>(bytes[cursor]);
                const auto extension_total_length = extension_length_units * 4U;
                if (extension_total_length < 2U || cursor + extension_total_length > declared_packet_length) {
                    parsed.status = ParseStatus::malformed;
                    return parsed;
                }
                if (bytes.size() < cursor + extension_total_length) {
                    parsed.status = ParseStatus::truncated;
                    return parsed;
                }

                next_extension_header_type = bytes[cursor + extension_total_length - 1U];
                cursor += extension_total_length;
            }
        }
    }

    if (cursor >= declared_packet_length) {
        parsed.status = ParseStatus::malformed;
        return parsed;
    }
    if (bytes.size() <= cursor) {
        parsed.status = ParseStatus::truncated;
        return parsed;
    }

    parsed.header_length = cursor;
    parsed.inner_payload_offset = cursor;
    const auto inner_version = static_cast<std::uint8_t>(bytes[cursor] >> 4U);
    if (inner_version == 4U) {
        parsed.inner_payload_type = detail::kEtherTypeIpv4;
    } else if (inner_version == 6U) {
        parsed.inner_payload_type = detail::kEtherTypeIpv6;
    }

    return parsed;
}

DissectionStep dissect_gtpu(const PacketSlice& slice) {
    const auto parsed = parse_gtpu_header(slice);
    if (parsed.status != ParseStatus::complete) {
        return make_gtpu_fallback_step(slice, parsed.status);
    }

    if (parsed.inner_payload_type == 0U) {
        return make_gtpu_fallback_step(slice, ParseStatus::unsupported_variant);
    }

    const auto child = make_child_slice(
        slice,
        parsed.inner_payload_offset,
        parsed.packet_length - parsed.inner_payload_offset
    );
    if (!child.has_slice()) {
        return make_gtpu_fallback_step(slice, ParseStatus::malformed);
    }

    const auto validation = parsed.inner_payload_type == detail::kEtherTypeIpv4
        ? validate_gtpu_inner_ipv4(*child.slice)
        : validate_gtpu_inner_ipv6(*child.slice);
    if (validation.status != ParseStatus::complete) {
        return make_gtpu_fallback_step(slice, validation.status);
    }

    return DissectionStep {
        .layer = DissectionLayerKind::gtpu,
        .path_contribution = LayerKey::gtpu(parsed.teid),
        .path_commit_policy = PathCommitPolicy::recognized_flow,
        .descendant_path_commit_policy = PathCommitPolicy::recognized_flow,
        .bounds = direct::make_layer_bounds(
            slice,
            parsed.packet_length,
            parsed.header_length,
            direct::RelativeRange {.begin = parsed.header_length, .end = parsed.packet_length},
            true
        ),
        .handoff = ProtocolHandoff {
            .selector = make_gtpu_inner_payload_selector(parsed.inner_payload_type),
            .child = *child.slice,
        },
        .facts = GtpuFacts {
            .flags = parsed.flags,
            .version = parsed.version,
            .message_type = parsed.message_type,
            .length = parsed.length,
            .teid = parsed.teid,
            .has_optional_fields = parsed.has_optional_fields,
            .has_sequence_number = parsed.has_sequence_number,
            .has_npdu_number = parsed.has_npdu_number,
            .has_extension_headers = parsed.has_extension_headers,
            .sequence_number = parsed.sequence_number,
            .npdu_number = parsed.npdu_number,
            .first_extension_header_type = parsed.first_extension_header_type,
            .header_length = parsed.header_length,
        },
        .terminal_disposition = TerminalDisposition::none,
        .status = ParseStatus::complete,
        .stop_reason = StopReason::none,
    };
}

DissectionStep dissect_gtpu_inner_ipv4(const PacketSlice& slice) {
    const auto parsed = parse_ipv4_packet(slice);
    if (parsed.status != ParseStatus::complete) {
        return make_gtpu_inner_network_error_step(
            slice,
            DissectionLayerKind::ipv4,
            parsed.status,
            detail::kIpv4MinimumHeaderSize
        );
    }
    if (parsed.is_fragmented || !is_supported_gtpu_inner_transport_protocol(parsed.protocol)) {
        return DissectionStep {
            .layer = DissectionLayerKind::unknown,
            .bounds = direct::make_layer_bounds(
                slice,
                parsed.nominal_packet_end,
                parsed.header_length,
                direct::RelativeRange {.begin = parsed.header_length, .end = parsed.nominal_packet_end},
                true
            ),
            .facts = std::monostate {},
            .terminal_disposition = TerminalDisposition::none,
            .status = ParseStatus::unsupported_variant,
            .stop_reason = StopReason::terminal_protocol,
        };
    }

    const auto handoff = direct::make_protocol_handoff(
        slice,
        parsed.header_length,
        parsed.nominal_packet_end - parsed.header_length,
        make_gtpu_inner_ip_protocol_selector(parsed.protocol)
    );
    if (!handoff.has_value()) {
        return make_gtpu_inner_network_error_step(
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
            parsed.nominal_packet_end,
            parsed.header_length,
            direct::RelativeRange {.begin = parsed.header_length, .end = parsed.nominal_packet_end},
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

DissectionStep dissect_gtpu_inner_ipv6(const PacketSlice& slice) {
    const auto parsed = parse_ipv6_packet(slice);
    if (parsed.status != ParseStatus::complete) {
        return make_gtpu_inner_network_error_step(
            slice,
            DissectionLayerKind::ipv6,
            parsed.status,
            detail::kIpv6HeaderSize
        );
    }
    if (!is_supported_gtpu_inner_transport_protocol(parsed.next_header)) {
        return DissectionStep {
            .layer = DissectionLayerKind::unknown,
            .bounds = direct::make_layer_bounds(
                slice,
                parsed.nominal_packet_end,
                parsed.header_length,
                direct::RelativeRange {.begin = parsed.header_length, .end = parsed.nominal_packet_end},
                true
            ),
            .facts = std::monostate {},
            .terminal_disposition = TerminalDisposition::none,
            .status = ParseStatus::unsupported_variant,
            .stop_reason = StopReason::terminal_protocol,
        };
    }

    const auto handoff = direct::make_protocol_handoff(
        slice,
        parsed.header_length,
        parsed.payload_length,
        make_gtpu_inner_ipv6_next_header_selector(parsed.next_header)
    );
    if (!handoff.has_value()) {
        return make_gtpu_inner_network_error_step(
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
        .handoff = *handoff,
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
