#include "core/dissection/modules/TransportModules.h"

#include "core/decode/PacketDecodeSupport.h"
#include "core/dissection/modules/CommonDirectModuleSupport.h"

namespace pfl::dissection {

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

}  // namespace pfl::dissection
