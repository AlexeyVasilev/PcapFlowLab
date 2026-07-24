#include "core/dissection/modules/MacsecModule.h"

#include <algorithm>

#include "core/decode/PacketDecodeSupport.h"
#include "core/dissection/modules/CommonDirectModuleSupport.h"

namespace pfl::dissection {

namespace {

MacsecFacts make_macsec_facts(const ParsedMacsecFrame& parsed) noexcept {
    return MacsecFacts {
        .available_base_bytes = parsed.available_base_bytes,
        .available_sci_bytes = parsed.available_sci_bytes,
        .tci_an = parsed.tci_an,
        .version = parsed.version,
        .end_station = parsed.end_station,
        .sci_present = parsed.sci_present,
        .single_copy_broadcast = parsed.single_copy_broadcast,
        .encrypted = parsed.encrypted,
        .changed_text = parsed.changed_text,
        .association_number = parsed.association_number,
        .short_length = parsed.short_length,
        .packet_number_present = parsed.packet_number_present,
        .packet_number = parsed.packet_number,
        .has_sci = parsed.has_sci,
        .sci = parsed.sci,
        .has_plain_ether_type = parsed.has_plain_ether_type,
        .plain_ether_type = parsed.plain_ether_type,
        .protected_payload_offset = static_cast<std::uint32_t>(parsed.protected_payload_offset),
        .protected_payload_length = static_cast<std::uint32_t>(parsed.protected_payload_length),
        .icv_offset = static_cast<std::uint32_t>(parsed.icv_offset),
        .icv_length = static_cast<std::uint32_t>(parsed.icv_length),
        .icv_complete = parsed.icv_complete,
    };
}

StopReason macsec_complete_stop_reason(const ParsedMacsecFrame& parsed) noexcept {
    return (parsed.encrypted || parsed.changed_text)
        ? StopReason::encrypted_payload
        : StopReason::unrecognized_payload;
}

std::size_t bounded_header_length(const PacketSlice& slice, const ParsedMacsecFrame& parsed) noexcept {
    return std::min(parsed.header_length, direct::slice_declared_length(slice));
}

}  // namespace

ParsedMacsecFrame parse_macsec_frame(const PacketSlice& slice) noexcept {
    ParsedMacsecFrame parsed {};
    const auto bytes = direct::visible_captured_bytes(slice);
    const auto available_bytes = bytes.size();

    parsed.available_base_bytes = static_cast<std::uint8_t>(std::min<std::size_t>(
        available_bytes,
        detail::kMacsecSecTagBaseSize
    ));

    if (parsed.available_base_bytes >= 1U) {
        parsed.tci_an = bytes[0];
        parsed.version = static_cast<std::uint8_t>((parsed.tci_an >> 7U) & 0x1U);
        parsed.end_station = ((parsed.tci_an >> 6U) & 0x1U) != 0U;
        parsed.sci_present = ((parsed.tci_an >> 5U) & 0x1U) != 0U;
        parsed.single_copy_broadcast = ((parsed.tci_an >> 4U) & 0x1U) != 0U;
        parsed.encrypted = ((parsed.tci_an >> 3U) & 0x1U) != 0U;
        parsed.changed_text = ((parsed.tci_an >> 2U) & 0x1U) != 0U;
        parsed.association_number = static_cast<std::uint8_t>(parsed.tci_an & 0x3U);
    }
    if (parsed.available_base_bytes >= 2U) {
        parsed.short_length = bytes[1U];
    }

    if (parsed.available_base_bytes < 2U) {
        parsed.status = ParseStatus::truncated;
        parsed.header_length = 2U;
        return parsed;
    }
    if (parsed.available_base_bytes < detail::kMacsecSecTagBaseSize) {
        parsed.status = ParseStatus::truncated;
        parsed.header_length = detail::kMacsecSecTagBaseSize;
        return parsed;
    }

    parsed.packet_number_present = true;
    parsed.packet_number = detail::read_be32(bytes, 2U);
    parsed.header_length = detail::kMacsecSecTagBaseSize;
    auto cursor = detail::kMacsecSecTagBaseSize;

    if (parsed.sci_present) {
        const auto available_sci_bytes = available_bytes > cursor ? (available_bytes - cursor) : 0U;
        parsed.available_sci_bytes = static_cast<std::uint8_t>(std::min<std::size_t>(
            available_sci_bytes,
            detail::kMacsecSciSize
        ));
        parsed.header_length += detail::kMacsecSciSize;
        if (parsed.available_sci_bytes < detail::kMacsecSciSize) {
            parsed.status = ParseStatus::truncated;
            return parsed;
        }

        parsed.has_sci = true;
        std::uint64_t sci = 0U;
        for (std::size_t index = 0U; index < detail::kMacsecSciSize; ++index) {
            sci = (sci << 8U) | static_cast<std::uint64_t>(bytes[cursor + index]);
        }
        parsed.sci = sci;
        cursor += detail::kMacsecSciSize;
    }

    parsed.protected_payload_offset = cursor;
    const auto remaining_bytes = available_bytes > cursor ? (available_bytes - cursor) : 0U;
    if (remaining_bytes < detail::kMacsecDefaultIcvSize) {
        parsed.protected_payload_length = remaining_bytes;
        parsed.icv_offset = cursor + remaining_bytes;
        parsed.icv_length = 0U;
        parsed.icv_complete = false;
        if (!parsed.encrypted &&
            !parsed.changed_text &&
            parsed.protected_payload_length >= 2U) {
            parsed.has_plain_ether_type = true;
            parsed.plain_ether_type = detail::read_be16(bytes, parsed.protected_payload_offset);
        }
        parsed.status = ParseStatus::truncated;
        return parsed;
    }

    parsed.protected_payload_length = remaining_bytes - detail::kMacsecDefaultIcvSize;
    parsed.icv_offset = cursor + parsed.protected_payload_length;
    parsed.icv_length = detail::kMacsecDefaultIcvSize;
    parsed.icv_complete = true;
    if (!parsed.encrypted &&
        !parsed.changed_text &&
        parsed.protected_payload_length >= 2U) {
        parsed.has_plain_ether_type = true;
        parsed.plain_ether_type = detail::read_be16(bytes, parsed.protected_payload_offset);
    }
    parsed.status = ParseStatus::complete;
    return parsed;
}

DissectionStep dissect_macsec(const PacketSlice& slice) {
    const auto parsed = parse_macsec_frame(slice);
    const auto header_length = bounded_header_length(slice, parsed);
    const auto payload_begin = std::min(parsed.protected_payload_offset, direct::slice_declared_length(slice));
    const auto payload_end = std::min(
        parsed.protected_payload_offset + parsed.protected_payload_length,
        direct::slice_declared_length(slice)
    );

    return DissectionStep {
        .layer = DissectionLayerKind::macsec,
        .bounds = direct::make_layer_bounds(
            slice,
            direct::slice_declared_length(slice),
            header_length,
            direct::RelativeRange {.begin = payload_begin, .end = payload_end},
            true
        ),
        .facts = make_macsec_facts(parsed),
        .terminal_disposition = TerminalDisposition::none,
        .status = parsed.status,
        .stop_reason = parsed.status == ParseStatus::complete
            ? macsec_complete_stop_reason(parsed)
            : StopReason::truncated,
    };
}

}  // namespace pfl::dissection
