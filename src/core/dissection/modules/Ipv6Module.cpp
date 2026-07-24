#include "core/dissection/modules/Ipv6Module.h"

#include <algorithm>

#include "core/decode/PacketDecodeSupport.h"
#include "core/dissection/modules/CommonDirectModuleSupport.h"

namespace pfl::dissection {

namespace {

ProtocolSelector make_ipv6_next_header_selector(const std::uint8_t next_header) noexcept {
    return ProtocolSelector {
        .domain = SelectorDomain::ipv6_next_header,
        .value = next_header,
    };
}

DissectionStep make_ipv6_step(
    const PacketSlice& slice,
    const ParsedIpv6Packet& parsed,
    const Ipv6Facts& facts,
    const std::optional<LayerKey>& path_contribution = std::nullopt
) {
    return DissectionStep {
        .layer = DissectionLayerKind::ipv6,
        .path_contribution = path_contribution,
        .bounds = direct::make_layer_bounds(
            slice,
            parsed.nominal_packet_end,
            parsed.header_length,
            direct::RelativeRange {.begin = parsed.header_length, .end = parsed.nominal_packet_end},
            true
        ),
        .facts = facts,
        .terminal_disposition = TerminalDisposition::none,
        .status = ParseStatus::complete,
        .stop_reason = StopReason::none,
    };
}

}  // namespace

ParsedIpv6Packet parse_ipv6_packet(const PacketSlice& slice) noexcept {
    const auto declared_length = direct::slice_declared_length(slice);
    if (declared_length < detail::kIpv6HeaderSize) {
        return ParsedIpv6Packet {
            .status = ParseStatus::malformed,
        };
    }

    const auto bytes = direct::visible_captured_bytes(slice);
    if (bytes.size() < detail::kIpv6HeaderSize) {
        return ParsedIpv6Packet {
            .status = ParseStatus::truncated,
        };
    }

    const auto version = static_cast<std::uint8_t>(bytes[0U] >> 4U);
    if (version != 6U) {
        return ParsedIpv6Packet {
            .status = ParseStatus::malformed,
        };
    }

    const auto payload_length = detail::read_be16(bytes, 4U);
    const auto nominal_packet_end = detail::kIpv6HeaderSize + static_cast<std::size_t>(payload_length);
    if (nominal_packet_end > declared_length) {
        return ParsedIpv6Packet {
            .status = ParseStatus::malformed,
        };
    }

    ParsedIpv6Packet parsed {
        .status = ParseStatus::complete,
        .next_header = bytes[6U],
        .payload_length = payload_length,
        .header_length = detail::kIpv6HeaderSize,
        .nominal_packet_end = nominal_packet_end,
        .packet_end = std::min(bytes.size(), nominal_packet_end),
    };
    std::copy_n(bytes.begin() + 8, 16, parsed.src_addr.begin());
    std::copy_n(bytes.begin() + 24, 16, parsed.dst_addr.begin());
    return parsed;
}

DissectionStep dissect_ipv6(const PacketSlice& slice) {
    const auto parsed = parse_ipv6_packet(slice);
    if (parsed.status != ParseStatus::complete) {
        return direct::make_error_step(
            slice,
            DissectionLayerKind::ipv6,
            parsed.status,
            parsed.status == ParseStatus::truncated ? StopReason::truncated : StopReason::malformed,
            detail::kIpv6HeaderSize
        );
    }

    const auto payload_slice = make_child_slice(slice, parsed.header_length, parsed.payload_length);
    if (!payload_slice.has_slice()) {
        return direct::make_error_step(
            slice,
            DissectionLayerKind::ipv6,
            ParseStatus::malformed,
            StopReason::malformed,
            parsed.header_length
        );
    }

    Ipv6Facts facts {
        .next_header = parsed.next_header,
        .payload_length = parsed.payload_length,
        .src_addr_v6 = parsed.src_addr,
        .dst_addr_v6 = parsed.dst_addr,
    };

    auto step = make_ipv6_step(
        slice,
        parsed,
        facts,
        LayerKey::ipv6()
    );

    step.handoff = ProtocolHandoff {
        .selector = make_ipv6_next_header_selector(parsed.next_header),
        .child = *payload_slice.slice,
    };
    return step;
}

}  // namespace pfl::dissection
