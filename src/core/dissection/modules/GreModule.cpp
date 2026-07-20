#include "core/dissection/modules/GreModule.h"

#include "core/decode/PacketDecodeSupport.h"
#include "core/dissection/modules/CommonDirectModuleSupport.h"

namespace pfl::dissection {

namespace {

inline constexpr std::uint16_t kGreFlagRouting = 0x4000U;
inline constexpr std::uint16_t kGreFlagStrictSourceRoute = 0x0800U;
inline constexpr std::uint16_t kGreFlagRecursionMask = 0x0700U;
inline constexpr std::uint16_t kGreReservedBitsMask = 0x00F8U;

bool gre_has_unsupported_variant_bits(const std::uint16_t flags_and_version) noexcept {
    return (flags_and_version & detail::kGreVersionMask) != 0U ||
           (flags_and_version & kGreFlagRouting) != 0U ||
           (flags_and_version & kGreFlagStrictSourceRoute) != 0U ||
           (flags_and_version & kGreFlagRecursionMask) != 0U ||
           (flags_and_version & kGreReservedBitsMask) != 0U;
}

ProtocolSelector make_gre_protocol_selector(const std::uint16_t protocol_type) noexcept {
    return ProtocolSelector {
        .domain = SelectorDomain::gre_protocol_type,
        .value = protocol_type,
    };
}

DissectionStep make_unsupported_gre_step(
    const PacketSlice& slice,
    const ParsedGreHeader& parsed
) {
    return DissectionStep {
        .layer = DissectionLayerKind::gre,
        .path_contribution = std::nullopt,
        .bounds = direct::make_layer_bounds(slice, parsed.header_length, parsed.header_length),
        .facts = GreFacts {
            .flags_and_version = parsed.flags_and_version,
            .protocol_type = parsed.protocol_type,
            .has_checksum = parsed.has_checksum,
            .checksum = parsed.checksum,
            .reserved1 = parsed.reserved1,
            .has_key = parsed.has_key,
            .key = parsed.key,
            .has_sequence = parsed.has_sequence,
            .sequence_number = parsed.sequence_number,
            .header_length = static_cast<std::uint16_t>(parsed.header_length),
        },
        .terminal_disposition = TerminalDisposition::none,
        .status = ParseStatus::unsupported_variant,
        .stop_reason = StopReason::unsupported_variant,
    };
}

ParseStatus status_from_child_build_result(const PacketSliceBuildStatus status) noexcept {
    return status == PacketSliceBuildStatus::captured_truncated ? ParseStatus::truncated : ParseStatus::malformed;
}

StopReason stop_reason_from_child_build_result(const PacketSliceBuildStatus status) noexcept {
    return status == PacketSliceBuildStatus::captured_truncated ? StopReason::truncated : StopReason::malformed;
}

}  // namespace

ParsedGreHeader parse_gre_header(const PacketSlice& slice) noexcept {
    const auto declared_length = direct::slice_declared_length(slice);
    if (declared_length < detail::kGreBaseHeaderSize) {
        return ParsedGreHeader {
            .status = ParseStatus::malformed,
            .header_length = detail::kGreBaseHeaderSize,
        };
    }

    const auto bytes = direct::visible_captured_bytes(slice);
    if (bytes.size() < detail::kGreBaseHeaderSize) {
        return ParsedGreHeader {
            .status = ParseStatus::truncated,
            .header_length = detail::kGreBaseHeaderSize,
        };
    }

    ParsedGreHeader parsed {
        .status = ParseStatus::complete,
        .flags_and_version = detail::read_be16(bytes, 0U),
        .protocol_type = detail::read_be16(bytes, 2U),
        .has_checksum = false,
        .checksum = 0U,
        .reserved1 = 0U,
        .has_key = false,
        .key = 0U,
        .has_sequence = false,
        .sequence_number = 0U,
        .header_length = detail::kGreBaseHeaderSize,
    };

    if (gre_has_unsupported_variant_bits(parsed.flags_and_version)) {
        parsed.status = ParseStatus::unsupported_variant;
        return parsed;
    }

    auto cursor = detail::kGreBaseHeaderSize;
    parsed.has_checksum = (parsed.flags_and_version & detail::kGreFlagChecksum) != 0U;
    parsed.has_key = (parsed.flags_and_version & detail::kGreFlagKey) != 0U;
    parsed.has_sequence = (parsed.flags_and_version & detail::kGreFlagSequence) != 0U;

    if (parsed.has_checksum) {
        if (declared_length < cursor + detail::kGreOptionalFieldSize) {
            parsed.status = ParseStatus::malformed;
            parsed.header_length = cursor + detail::kGreOptionalFieldSize;
            return parsed;
        }
        if (bytes.size() < cursor + detail::kGreOptionalFieldSize) {
            parsed.status = ParseStatus::truncated;
            parsed.header_length = cursor + detail::kGreOptionalFieldSize;
            return parsed;
        }
        parsed.checksum = detail::read_be16(bytes, cursor);
        parsed.reserved1 = detail::read_be16(bytes, cursor + 2U);
        cursor += detail::kGreOptionalFieldSize;
    }

    if (parsed.has_key) {
        if (declared_length < cursor + detail::kGreOptionalFieldSize) {
            parsed.status = ParseStatus::malformed;
            parsed.header_length = cursor + detail::kGreOptionalFieldSize;
            return parsed;
        }
        if (bytes.size() < cursor + detail::kGreOptionalFieldSize) {
            parsed.status = ParseStatus::truncated;
            parsed.header_length = cursor + detail::kGreOptionalFieldSize;
            return parsed;
        }
        parsed.key = detail::read_be32(bytes, cursor);
        cursor += detail::kGreOptionalFieldSize;
    }

    if (parsed.has_sequence) {
        if (declared_length < cursor + detail::kGreOptionalFieldSize) {
            parsed.status = ParseStatus::malformed;
            parsed.header_length = cursor + detail::kGreOptionalFieldSize;
            return parsed;
        }
        if (bytes.size() < cursor + detail::kGreOptionalFieldSize) {
            parsed.status = ParseStatus::truncated;
            parsed.header_length = cursor + detail::kGreOptionalFieldSize;
            return parsed;
        }
        parsed.sequence_number = detail::read_be32(bytes, cursor);
        cursor += detail::kGreOptionalFieldSize;
    }

    parsed.header_length = cursor;
    return parsed;
}

DissectionStep dissect_gre(const PacketSlice& slice) {
    const auto parsed = parse_gre_header(slice);
    if (parsed.status == ParseStatus::truncated || parsed.status == ParseStatus::malformed) {
        return direct::make_error_step(
            slice,
            DissectionLayerKind::gre,
            parsed.status,
            parsed.status == ParseStatus::truncated ? StopReason::truncated : StopReason::malformed,
            parsed.header_length
        );
    }

    if (parsed.status == ParseStatus::unsupported_variant) {
        return make_unsupported_gre_step(slice, parsed);
    }

    DissectionStep step {
        .layer = DissectionLayerKind::gre,
        .path_contribution = parsed.has_key ? LayerKey::gre(parsed.key) : LayerKey::gre(),
        .bounds = direct::make_layer_bounds(
            slice,
            parsed.header_length,
            parsed.header_length,
            direct::RelativeRange {.begin = parsed.header_length, .end = direct::slice_declared_length(slice)},
            true
        ),
        .facts = GreFacts {
            .flags_and_version = parsed.flags_and_version,
            .protocol_type = parsed.protocol_type,
            .has_checksum = parsed.has_checksum,
            .checksum = parsed.checksum,
            .reserved1 = parsed.reserved1,
            .has_key = parsed.has_key,
            .key = parsed.key,
            .has_sequence = parsed.has_sequence,
            .sequence_number = parsed.sequence_number,
            .header_length = static_cast<std::uint16_t>(parsed.header_length),
        },
        .terminal_disposition = TerminalDisposition::none,
        .status = ParseStatus::complete,
        .stop_reason = StopReason::none,
    };

    const auto child_result = make_child_slice(
        slice,
        parsed.header_length,
        direct::slice_declared_length(slice) - parsed.header_length
    );
    if (!child_result.has_slice()) {
        step.status = status_from_child_build_result(child_result.status);
        step.stop_reason = stop_reason_from_child_build_result(child_result.status);
        step.path_contribution.reset();
        step.handoff.reset();
        return step;
    }

    step.handoff = ProtocolHandoff {
        .selector = make_gre_protocol_selector(parsed.protocol_type),
        .child = *child_result.slice,
    };
    return step;
}

}  // namespace pfl::dissection
