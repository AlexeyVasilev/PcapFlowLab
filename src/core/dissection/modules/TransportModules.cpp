#include "core/dissection/modules/TransportModules.h"

#include "core/decode/PacketDecodeSupport.h"
#include "core/dissection/modules/CommonDirectModuleSupport.h"

namespace pfl::dissection {

namespace {

ProtocolSelector make_udp_payload_candidate_selector(const std::uint16_t dst_port) noexcept {
    return ProtocolSelector {
        .domain = SelectorDomain::udp_destination_port_candidate,
        .value = dst_port,
    };
}

DissectionStep make_udp_terminal_step(const PacketSlice& slice, const ParsedUdpDatagram& parsed) {
    return DissectionStep {
        .layer = DissectionLayerKind::udp,
        .path_contribution = LayerKey::udp(),
        .bounds = direct::make_layer_bounds(
            slice,
            parsed.datagram_length,
            detail::kUdpHeaderSize,
            direct::RelativeRange {.begin = detail::kUdpHeaderSize, .end = parsed.datagram_length},
            true
        ),
        .facts = UdpFacts {
            .src_port = parsed.src_port,
            .dst_port = parsed.dst_port,
            .datagram_length = parsed.datagram_length,
        },
        .terminal_disposition = TerminalDisposition::flow_candidate,
        .status = ParseStatus::complete,
        .stop_reason = StopReason::terminal_protocol,
    };
}

}  // namespace

ParsedTcpSegment parse_tcp_segment(const PacketSlice& slice) noexcept {
    const auto bytes = direct::visible_captured_bytes(slice);
    const auto nominal_packet_end = direct::slice_declared_length(slice);
    if (nominal_packet_end < detail::kTcpMinimumHeaderSize) {
        return ParsedTcpSegment {
            .status = ParseStatus::malformed,
        };
    }

    if (bytes.size() < detail::kTcpMinimumHeaderSize) {
        return ParsedTcpSegment {
            .status = ParseStatus::truncated,
        };
    }

    const auto header_length = static_cast<std::size_t>((bytes[12U] >> 4U) * 4U);
    if (header_length < detail::kTcpMinimumHeaderSize || header_length > nominal_packet_end) {
        return ParsedTcpSegment {
            .status = ParseStatus::malformed,
        };
    }

    if (bytes.size() < header_length) {
        return ParsedTcpSegment {
            .status = ParseStatus::truncated,
        };
    }

    const auto packet_end = std::min(nominal_packet_end, bytes.size());
    return ParsedTcpSegment {
        .status = ParseStatus::complete,
        .src_port = detail::read_be16(bytes, 0U),
        .dst_port = detail::read_be16(bytes, 2U),
        .header_length = header_length,
        .captured_payload_length = static_cast<std::uint32_t>(packet_end - header_length),
        .flags = bytes[13U],
    };
}

ParsedUdpDatagram parse_udp_datagram(const PacketSlice& slice) noexcept {
    const auto bytes = direct::visible_captured_bytes(slice);
    const auto nominal_packet_end = direct::slice_declared_length(slice);
    if (nominal_packet_end < detail::kUdpHeaderSize) {
        return ParsedUdpDatagram {
            .status = ParseStatus::malformed,
        };
    }

    if (bytes.size() < detail::kUdpHeaderSize) {
        return ParsedUdpDatagram {
            .status = ParseStatus::truncated,
        };
    }

    const auto udp_payload = detail::parse_udp_payload_bounds(bytes, 0U, nominal_packet_end);
    if (!udp_payload.has_value()) {
        return ParsedUdpDatagram {
            .status = ParseStatus::malformed,
        };
    }

    return ParsedUdpDatagram {
        .status = ParseStatus::complete,
        .src_port = detail::read_be16(bytes, 0U),
        .dst_port = detail::read_be16(bytes, 2U),
        .datagram_length = udp_payload->datagram_length,
        .captured_payload_length = static_cast<std::uint32_t>(udp_payload->payload_length),
    };
}

ParsedSctpCommonHeader parse_sctp_common_header(const PacketSlice& slice) noexcept {
    const auto nominal_packet_end = direct::slice_declared_length(slice);
    if (nominal_packet_end < detail::kSctpCommonHeaderSize) {
        return ParsedSctpCommonHeader {
            .status = ParseStatus::malformed,
        };
    }

    const auto bytes = direct::visible_captured_bytes(slice);
    if (bytes.size() < detail::kSctpCommonHeaderSize) {
        return ParsedSctpCommonHeader {
            .status = ParseStatus::truncated,
        };
    }

    const auto sctp = detail::parse_sctp_common_header(bytes, 0U, nominal_packet_end);
    if (!sctp.has_value()) {
        return ParsedSctpCommonHeader {
            .status = ParseStatus::malformed,
        };
    }

    return ParsedSctpCommonHeader {
        .status = ParseStatus::complete,
        .src_port = sctp->src_port,
        .dst_port = sctp->dst_port,
        .verification_tag = sctp->verification_tag,
        .checksum = sctp->checksum,
        .header_length = detail::kSctpCommonHeaderSize,
        .captured_payload_length = static_cast<std::uint32_t>(sctp->payload_length),
    };
}

DissectionStep dissect_tcp(const PacketSlice& slice) {
    const auto parsed = parse_tcp_segment(slice);
    if (parsed.status != ParseStatus::complete) {
        return direct::make_error_step(
            slice,
            DissectionLayerKind::tcp,
            parsed.status,
            parsed.status == ParseStatus::truncated ? StopReason::truncated : StopReason::malformed,
            detail::kTcpMinimumHeaderSize
        );
    }

    return DissectionStep {
        .layer = DissectionLayerKind::tcp,
        .path_contribution = LayerKey::tcp(),
        .bounds = direct::make_layer_bounds(
            slice,
            direct::slice_declared_length(slice),
            parsed.header_length,
            direct::RelativeRange {.begin = parsed.header_length, .end = direct::slice_declared_length(slice)},
            true
        ),
        .facts = TcpFacts {
            .src_port = parsed.src_port,
            .dst_port = parsed.dst_port,
            .flags = parsed.flags,
        },
        .terminal_disposition = TerminalDisposition::flow_candidate,
        .status = ParseStatus::complete,
        .stop_reason = StopReason::terminal_protocol,
    };
}

DissectionStep dissect_udp(const PacketSlice& slice) {
    const auto parsed = parse_udp_datagram(slice);
    if (parsed.status != ParseStatus::complete) {
        return direct::make_error_step(
            slice,
            DissectionLayerKind::udp,
            parsed.status,
            parsed.status == ParseStatus::truncated ? StopReason::truncated : StopReason::malformed,
            detail::kUdpHeaderSize
        );
    }

    auto step = make_udp_terminal_step(slice, parsed);
    if (parsed.dst_port != detail::kUdpPortVxlan) {
        return step;
    }

    const auto handoff = direct::make_protocol_handoff(
        slice,
        detail::kUdpHeaderSize,
        parsed.datagram_length - detail::kUdpHeaderSize,
        make_udp_payload_candidate_selector(parsed.dst_port)
    );
    if (!handoff.has_value()) {
        step.status = ParseStatus::malformed;
        step.stop_reason = StopReason::malformed;
        return step;
    }

    step.handoff = *handoff;
    step.stop_reason = StopReason::none;
    return step;
}

DissectionStep dissect_udp_terminal(const PacketSlice& slice) {
    const auto parsed = parse_udp_datagram(slice);
    if (parsed.status != ParseStatus::complete) {
        return direct::make_error_step(
            slice,
            DissectionLayerKind::udp,
            parsed.status,
            parsed.status == ParseStatus::truncated ? StopReason::truncated : StopReason::malformed,
            detail::kUdpHeaderSize
        );
    }

    return make_udp_terminal_step(slice, parsed);
}

DissectionStep dissect_sctp(const PacketSlice& slice) {
    const auto parsed = parse_sctp_common_header(slice);
    if (parsed.status != ParseStatus::complete) {
        return direct::make_error_step(
            slice,
            DissectionLayerKind::sctp,
            parsed.status,
            parsed.status == ParseStatus::truncated ? StopReason::truncated : StopReason::malformed,
            detail::kSctpCommonHeaderSize
        );
    }

    return DissectionStep {
        .layer = DissectionLayerKind::sctp,
        .path_contribution = LayerKey::sctp(),
        .bounds = direct::make_layer_bounds(
            slice,
            direct::slice_declared_length(slice),
            parsed.header_length,
            direct::RelativeRange {.begin = parsed.header_length, .end = direct::slice_declared_length(slice)},
            true
        ),
        .facts = SctpFacts {
            .src_port = parsed.src_port,
            .dst_port = parsed.dst_port,
            .verification_tag = parsed.verification_tag,
            .checksum = parsed.checksum,
        },
        .terminal_disposition = TerminalDisposition::flow_candidate,
        .status = ParseStatus::complete,
        .stop_reason = StopReason::terminal_protocol,
    };
}

}  // namespace pfl::dissection
