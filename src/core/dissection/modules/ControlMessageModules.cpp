#include "core/dissection/modules/ControlMessageModules.h"

#include "core/decode/PacketDecodeSupport.h"
#include "core/dissection/modules/CommonDirectModuleSupport.h"

namespace pfl::dissection {

namespace {

inline constexpr std::size_t kIcmpCommonHeaderSize = 4U;

struct ParsedControlMessageCommonHeader {
    ParseStatus status {ParseStatus::opaque};
    std::uint8_t type {0U};
    std::uint8_t code {0U};
    std::uint16_t checksum {0U};
    std::size_t header_length {0U};
    std::uint32_t captured_payload_length {0U};
};

ParsedControlMessageCommonHeader parse_control_message_common_header(const PacketSlice& slice) noexcept {
    const auto nominal_packet_end = direct::slice_declared_length(slice);
    if (nominal_packet_end < kIcmpCommonHeaderSize) {
        return ParsedControlMessageCommonHeader {
            .status = ParseStatus::malformed,
        };
    }

    const auto bytes = direct::visible_captured_bytes(slice);
    if (bytes.size() < kIcmpCommonHeaderSize) {
        return ParsedControlMessageCommonHeader {
            .status = ParseStatus::truncated,
        };
    }

    return ParsedControlMessageCommonHeader {
        .status = ParseStatus::complete,
        .type = bytes[0U],
        .code = bytes[1U],
        .checksum = detail::read_be16(bytes, 2U),
        .header_length = kIcmpCommonHeaderSize,
        .captured_payload_length = static_cast<std::uint32_t>(bytes.size() - kIcmpCommonHeaderSize),
    };
}

template <typename ParsedHeader>
DissectionStep make_icmp_step(
    const PacketSlice& slice,
    const DissectionLayerKind layer,
    const std::optional<LayerKey>& path_contribution,
    const ParsedHeader& parsed,
    const LayerFacts& facts
) {
    if (parsed.status != ParseStatus::complete) {
        return direct::make_error_step(
            slice,
            layer,
            parsed.status,
            parsed.status == ParseStatus::truncated ? StopReason::truncated : StopReason::malformed,
            kIcmpCommonHeaderSize
        );
    }

    return DissectionStep {
        .layer = layer,
        .path_contribution = path_contribution,
        .bounds = direct::make_layer_bounds(
            slice,
            direct::slice_declared_length(slice),
            parsed.header_length,
            direct::RelativeRange {.begin = parsed.header_length, .end = direct::slice_declared_length(slice)},
            true
        ),
        .facts = facts,
        .terminal_disposition = TerminalDisposition::flow_candidate,
        .status = ParseStatus::complete,
        .stop_reason = StopReason::terminal_protocol,
    };
}

}  // namespace

ParsedIcmpHeader parse_icmp_common_header(const PacketSlice& slice) noexcept {
    const auto parsed = parse_control_message_common_header(slice);
    return ParsedIcmpHeader {
        .status = parsed.status,
        .type = parsed.type,
        .code = parsed.code,
        .checksum = parsed.checksum,
        .header_length = parsed.header_length,
        .captured_payload_length = parsed.captured_payload_length,
    };
}

ParsedIcmpv6Header parse_icmpv6_common_header(const PacketSlice& slice) noexcept {
    const auto parsed = parse_control_message_common_header(slice);
    return ParsedIcmpv6Header {
        .status = parsed.status,
        .type = parsed.type,
        .code = parsed.code,
        .checksum = parsed.checksum,
        .header_length = parsed.header_length,
        .captured_payload_length = parsed.captured_payload_length,
    };
}

DissectionStep dissect_icmp(const PacketSlice& slice) {
    const auto parsed = parse_icmp_common_header(slice);
    return make_icmp_step(
        slice,
        DissectionLayerKind::icmp,
        LayerKey::icmp(),
        parsed,
        IcmpFacts {
            .type = parsed.type,
            .code = parsed.code,
            .checksum = parsed.checksum,
        }
    );
}

DissectionStep dissect_icmpv6(const PacketSlice& slice) {
    const auto parsed = parse_icmpv6_common_header(slice);
    return make_icmp_step(
        slice,
        DissectionLayerKind::icmpv6,
        LayerKey::icmpv6(),
        parsed,
        Icmpv6Facts {
            .type = parsed.type,
            .code = parsed.code,
            .checksum = parsed.checksum,
        }
    );
}

}  // namespace pfl::dissection
