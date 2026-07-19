#include "core/dissection/modules/Ipv4Module.h"

#include <algorithm>

#include "core/decode/PacketDecodeSupport.h"
#include "core/dissection/modules/CommonDirectModuleSupport.h"

namespace pfl::dissection {

namespace {

constexpr std::uint8_t kIpv4OptionEndOfList = 0U;
constexpr std::uint8_t kIpv4OptionNoOp = 1U;
constexpr std::uint8_t kIpv4OptionRouterAlert = 148U;

Ipv4OptionsFacts parse_ipv4_options(const std::span<const std::uint8_t> options_bytes) noexcept {
    Ipv4OptionsFacts facts {
        .status = options_bytes.empty() ? Ipv4OptionsParseStatus::not_present : Ipv4OptionsParseStatus::well_formed,
        .options_length = static_cast<std::uint8_t>(options_bytes.size()),
    };
    if (options_bytes.empty()) {
        return facts;
    }

    std::size_t offset = 0U;
    while (offset < options_bytes.size()) {
        const auto option_type = options_bytes[offset];
        if (option_type == kIpv4OptionEndOfList) {
            ++facts.parsed_option_count;
            facts.has_end_of_list = true;
            ++offset;

            for (; offset < options_bytes.size(); ++offset) {
                if (options_bytes[offset] != 0U) {
                    facts.status = Ipv4OptionsParseStatus::malformed;
                    facts.has_nonzero_padding = true;
                    facts.has_malformed_offset = true;
                    facts.malformed_offset = static_cast<std::uint8_t>(offset);
                    break;
                }
            }
            return facts;
        }

        if (option_type == kIpv4OptionNoOp) {
            ++facts.parsed_option_count;
            ++facts.nop_count;
            ++offset;
            continue;
        }

        if ((offset + 1U) >= options_bytes.size()) {
            facts.status = Ipv4OptionsParseStatus::malformed;
            facts.has_malformed_offset = true;
            facts.malformed_offset = static_cast<std::uint8_t>(offset);
            return facts;
        }

        const auto option_length = static_cast<std::size_t>(options_bytes[offset + 1U]);
        if (option_length < 2U || option_length > (options_bytes.size() - offset)) {
            facts.status = Ipv4OptionsParseStatus::malformed;
            facts.has_malformed_offset = true;
            facts.malformed_offset = static_cast<std::uint8_t>(offset);
            return facts;
        }

        ++facts.parsed_option_count;
        if (option_type == kIpv4OptionRouterAlert) {
            if (option_length != 4U) {
                facts.status = Ipv4OptionsParseStatus::malformed;
                facts.has_malformed_offset = true;
                facts.malformed_offset = static_cast<std::uint8_t>(offset);
                return facts;
            }

            facts.has_router_alert = true;
            facts.router_alert_value = detail::read_be16(options_bytes, offset + 2U);
        }

        offset += option_length;
    }

    return facts;
}

}  // namespace

ParsedIpv4Packet parse_ipv4_packet(const PacketSlice& slice) noexcept {
    const auto bytes = direct::visible_captured_bytes(slice);
    const auto declared_length = direct::slice_declared_length(slice);
    if (bytes.size() < detail::kIpv4MinimumHeaderSize) {
        return ParsedIpv4Packet {
            .status = ParseStatus::truncated,
        };
    }

    const auto version = static_cast<std::uint8_t>(bytes[0U] >> 4U);
    const auto ihl = static_cast<std::size_t>((bytes[0U] & 0x0FU) * 4U);
    if (version != 4U || ihl < detail::kIpv4MinimumHeaderSize) {
        return ParsedIpv4Packet {
            .status = ParseStatus::malformed,
        };
    }

    if (declared_length < ihl) {
        return ParsedIpv4Packet {
            .status = ParseStatus::malformed,
        };
    }

    if (bytes.size() < ihl) {
        return ParsedIpv4Packet {
            .status = ParseStatus::truncated,
        };
    }

    const auto total_length = detail::read_be16(bytes, 2U);
    if (total_length != 0U && total_length < ihl) {
        return ParsedIpv4Packet {
            .status = ParseStatus::malformed,
        };
    }

    const auto bounds = detail::parse_ipv4_packet_bounds(bytes, 0U);
    if (!bounds.has_value()) {
        return ParsedIpv4Packet {
            .status = ParseStatus::malformed,
        };
    }

    const auto flags_fragment = detail::read_be16(bytes, 6U);
    const auto fragment_offset_units = static_cast<std::uint16_t>(flags_fragment & 0x1FFFU);
    return ParsedIpv4Packet {
        .status = ParseStatus::complete,
        .protocol = bytes[9U],
        .total_length = bounds->total_length,
        .header_length = bounds->header_length,
        .nominal_packet_end = bounds->nominal_packet_end,
        .packet_end = bounds->packet_end,
        .src_addr = detail::read_be32(bytes, 12U),
        .dst_addr = detail::read_be32(bytes, 16U),
        .flags_fragment = flags_fragment,
        .bounds_from_captured_bytes = bounds->bounds_from_captured_bytes,
        .is_fragmented = (flags_fragment & 0x3FFFU) != 0U,
        .more_fragments = (flags_fragment & 0x2000U) != 0U,
        .fragment_offset_units = fragment_offset_units,
        .options = parse_ipv4_options(bytes.subspan(detail::kIpv4MinimumHeaderSize, ihl - detail::kIpv4MinimumHeaderSize)),
    };
}

DissectionStep dissect_ipv4(const PacketSlice& slice) {
    const auto parsed = parse_ipv4_packet(slice);
    if (parsed.status != ParseStatus::complete) {
        return direct::make_error_step(
            slice,
            DissectionLayerKind::ipv4,
            parsed.status,
            parsed.status == ParseStatus::truncated ? StopReason::truncated : StopReason::malformed,
            detail::kIpv4MinimumHeaderSize
        );
    }

    const auto bounded_full_end = std::min(parsed.nominal_packet_end, direct::slice_declared_length(slice));
    const ProtocolSelector next_selector {
        .domain = SelectorDomain::ip_protocol,
        .value = parsed.protocol,
    };
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

    const auto handoff = direct::make_protocol_handoff(
        slice,
        parsed.header_length,
        parsed.nominal_packet_end - parsed.header_length,
        next_selector
    );
    if (!handoff.has_value()) {
        return direct::make_error_step(
            slice,
            DissectionLayerKind::ipv4,
            ParseStatus::malformed,
            StopReason::malformed,
            parsed.header_length
        );
    }

    step.handoff = *handoff;
    return step;
}

}  // namespace pfl::dissection
