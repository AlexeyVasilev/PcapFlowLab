#include "core/services/PacketDetailsService.h"

#include <algorithm>
#include <span>

#include "core/decode/PacketDecodeSupport.h"

namespace pfl {

namespace {

constexpr std::size_t kUnknownPppPayloadPreviewMaxBytes = 32U;
constexpr std::size_t kLlcSnapPayloadPreviewMaxBytes = 32U;
constexpr std::size_t kTrailerPreviewMaxBytes = 32U;
constexpr std::size_t kUnknownInnerEthernetPayloadPreviewMaxBytes = 32U;
constexpr std::size_t kMacsecPayloadPreviewMaxBytes = 32U;
constexpr std::size_t kMacsecIcvPreviewMaxBytes = 32U;
constexpr std::size_t kSctpChunkHeaderSize = 4U;
constexpr std::size_t kSctpDataChunkMetadataSize = 12U;
constexpr std::uint8_t kSctpChunkTypeData = 0U;

enum class DecodeMode : std::uint8_t {
    strict,
    best_effort,
};

constexpr std::uint16_t kPppoeDiscoveryTagEndOfList = 0x0000U;
constexpr std::uint16_t kPppProtocolLcp = 0xc021U;
constexpr std::uint16_t kPppProtocolIpcp = 0x8021U;
constexpr std::uint16_t kPppProtocolIpv6cp = 0x8057U;

bool is_ppp_control_protocol(const std::uint16_t protocol) noexcept {
    return protocol == kPppProtocolLcp ||
        protocol == kPppProtocolIpcp ||
        protocol == kPppProtocolIpv6cp;
}

struct LinkLayerView {
    std::uint16_t protocol_type {0};
    std::size_t payload_offset {0};
    std::optional<std::size_t> bounded_packet_end {};
};

std::optional<PacketDetails> decode_packet_details(
    std::span<const std::uint8_t> packet_bytes,
    const PacketRef& packet_ref,
    DecodeMode mode
);

void populate_inner_ethernet_details(
    std::span<const std::uint8_t> packet_bytes,
    const std::size_t inner_ethernet_offset,
    const detail::LinkLayerPayloadView& inner_ethernet,
    PacketDetails& details
) {
    details.has_inner_ethernet = true;
    details.inner_ethernet = {};
    details.inner_ethernet.available_header_bytes = static_cast<std::uint8_t>(std::min<std::size_t>(
        detail::kEthernetHeaderSize,
        (inner_ethernet_offset < packet_bytes.size()) ? (packet_bytes.size() - inner_ethernet_offset) : 0U));
    details.inner_ethernet.header_truncated = details.inner_ethernet.available_header_bytes < detail::kEthernetHeaderSize;

    if (details.inner_ethernet.available_header_bytes >= 6U) {
        std::copy_n(
            packet_bytes.begin() + static_cast<std::ptrdiff_t>(inner_ethernet_offset),
            6U,
            details.inner_ethernet.dst_mac.begin()
        );
    }
    if (details.inner_ethernet.available_header_bytes >= 12U) {
        std::copy_n(
            packet_bytes.begin() + static_cast<std::ptrdiff_t>(inner_ethernet_offset + 6U),
            6U,
            details.inner_ethernet.src_mac.begin()
        );
    }
    if (details.inner_ethernet.available_header_bytes >= detail::kEthernetHeaderSize) {
        details.inner_ethernet.uses_length_field = inner_ethernet.is_ieee_802_3;
        details.inner_ethernet.ether_type = details.inner_ethernet.uses_length_field
            ? inner_ethernet.declared_payload_length
            : inner_ethernet.protocol_type;
    }
}

void populate_unknown_inner_ethernet_payload_preview(
    std::span<const std::uint8_t> packet_bytes,
    const detail::LinkLayerPayloadView& inner_ethernet,
    const std::optional<std::size_t> bounded_packet_end,
    PacketDetails& details
) {
    const auto payload_offset = inner_ethernet.payload_offset;
    if (payload_offset >= packet_bytes.size()) {
        return;
    }

    const auto bounded_end = bounded_packet_end.value_or(packet_bytes.size());
    const auto payload_end = std::min(bounded_end, packet_bytes.size());
    if (payload_end <= payload_offset) {
        return;
    }

    details.has_unknown_inner_ethernet_payload = true;
    details.unknown_inner_ethernet_payload.payload_length = payload_end - payload_offset;
    const auto preview_length = std::min(details.unknown_inner_ethernet_payload.payload_length,
                                         kUnknownInnerEthernetPayloadPreviewMaxBytes);
    details.unknown_inner_ethernet_payload.payload_preview.assign(
        packet_bytes.begin() + static_cast<std::ptrdiff_t>(payload_offset),
        packet_bytes.begin() + static_cast<std::ptrdiff_t>(payload_offset + preview_length)
    );
    details.unknown_inner_ethernet_payload.payload_preview_truncated =
        details.unknown_inner_ethernet_payload.payload_length > preview_length;
}

void populate_sctp_details(
    std::span<const std::uint8_t> packet_bytes,
    const std::size_t sctp_offset,
    const std::size_t packet_end,
    PacketDetails& details
) {
    const auto bounded_packet_end = std::min(packet_end, packet_bytes.size());
    const auto available_common_header_bytes = sctp_offset < bounded_packet_end
        ? std::min<std::size_t>(detail::kSctpCommonHeaderSize, bounded_packet_end - sctp_offset)
        : 0U;

    details.has_sctp = true;
    details.sctp = {};
    details.sctp.available_common_header_bytes = static_cast<std::uint8_t>(available_common_header_bytes);
    details.sctp.common_header_truncated = available_common_header_bytes < detail::kSctpCommonHeaderSize;

    if (available_common_header_bytes >= 2U) {
        details.sctp.src_port = detail::read_be16(packet_bytes, sctp_offset);
    }
    if (available_common_header_bytes >= 4U) {
        details.sctp.dst_port = detail::read_be16(packet_bytes, sctp_offset + 2U);
    }
    if (available_common_header_bytes >= 8U) {
        details.sctp.verification_tag = detail::read_be32(packet_bytes, sctp_offset + 4U);
    }
    if (available_common_header_bytes >= 12U) {
        details.sctp.checksum = detail::read_be32(packet_bytes, sctp_offset + 8U);
    }

    if (details.sctp.common_header_truncated) {
        return;
    }

    const auto chunk_offset = sctp_offset + detail::kSctpCommonHeaderSize;
    if (chunk_offset >= bounded_packet_end) {
        return;
    }

    details.sctp.first_chunk_present = true;
    const auto available_chunk_header_bytes = std::min<std::size_t>(kSctpChunkHeaderSize, bounded_packet_end - chunk_offset);
    details.sctp.first_chunk_available_header_bytes = static_cast<std::uint8_t>(available_chunk_header_bytes);
    details.sctp.first_chunk_header_truncated = available_chunk_header_bytes < kSctpChunkHeaderSize;

    if (available_chunk_header_bytes >= 1U) {
        details.sctp.first_chunk_type = packet_bytes[chunk_offset];
    }
    if (available_chunk_header_bytes >= 2U) {
        details.sctp.first_chunk_flags = packet_bytes[chunk_offset + 1U];
    }
    if (available_chunk_header_bytes >= 4U) {
        details.sctp.first_chunk_length = detail::read_be16(packet_bytes, chunk_offset + 2U);
    }

    if (details.sctp.first_chunk_header_truncated || details.sctp.first_chunk_type != kSctpChunkTypeData) {
        return;
    }

    const auto chunk_available_bytes = bounded_packet_end - chunk_offset;
    const auto declared_chunk_bytes = details.sctp.first_chunk_length >= kSctpChunkHeaderSize
        ? static_cast<std::size_t>(details.sctp.first_chunk_length)
        : kSctpChunkHeaderSize;
    const auto bounded_chunk_bytes = std::min(chunk_available_bytes, declared_chunk_bytes);
    const auto data_metadata_offset = chunk_offset + kSctpChunkHeaderSize;
    const auto available_data_metadata_bytes = bounded_chunk_bytes > kSctpChunkHeaderSize
        ? std::min<std::size_t>(kSctpDataChunkMetadataSize, bounded_chunk_bytes - kSctpChunkHeaderSize)
        : 0U;

    details.sctp.data_metadata_present = true;
    details.sctp.data_metadata_available_bytes = static_cast<std::uint8_t>(available_data_metadata_bytes);
    details.sctp.data_metadata_truncated = available_data_metadata_bytes < kSctpDataChunkMetadataSize;

    if (available_data_metadata_bytes >= 4U) {
        details.sctp.tsn = detail::read_be32(packet_bytes, data_metadata_offset);
    }
    if (available_data_metadata_bytes >= 6U) {
        details.sctp.stream_identifier = detail::read_be16(packet_bytes, data_metadata_offset + 4U);
    }
    if (available_data_metadata_bytes >= 8U) {
        details.sctp.stream_sequence_number = detail::read_be16(packet_bytes, data_metadata_offset + 6U);
    }
    if (available_data_metadata_bytes >= 12U) {
        details.sctp.ppid = detail::read_be32(packet_bytes, data_metadata_offset + 8U);
    }
}

void populate_vxlan_details(
    std::span<const std::uint8_t> packet_bytes,
    const std::size_t vxlan_offset,
    const detail::VxlanPayloadView& vxlan,
    PacketDetails& details
) {
    details.has_vxlan = true;
    details.vxlan = {};
    details.vxlan.present = true;
    details.vxlan.available_header_bytes = static_cast<std::uint8_t>(detail::kVxlanHeaderSize);
    details.vxlan.header_truncated = false;
    details.vxlan.invalid_header = false;
    details.vxlan.reserved_bits_non_zero = false;
    details.vxlan.flags = packet_bytes[vxlan_offset];
    details.vxlan.i_flag_set = (details.vxlan.flags & detail::kVxlanFlagI) != 0U;
    details.vxlan.vni = vxlan.vni;
    details.vxlan.has_inner_ethernet = vxlan.has_inner_ethernet;
    details.vxlan.inner_ethernet_truncated = vxlan.inner_ethernet_truncated;

    if (vxlan.has_inner_ethernet) {
        populate_inner_ethernet_details(packet_bytes, vxlan.inner_ethernet_offset, vxlan.inner_ethernet, details);
    }
}

std::shared_ptr<VxlanInnerPacketDetails> make_vxlan_inner_packet_details(const PacketDetails& details) {
    auto inner = std::make_shared<VxlanInnerPacketDetails>();
    inner->has_vlan = details.has_vlan;
    inner->vlan_tags = details.vlan_tags;
    inner->has_llc = details.has_llc;
    inner->llc = details.llc;
    inner->has_snap = details.has_snap;
    inner->snap = details.snap;
    inner->has_ipv4 = details.has_ipv4;
    inner->ipv4 = details.ipv4;
    inner->has_ipv6 = details.has_ipv6;
    inner->ipv6 = details.ipv6;
    inner->has_tcp = details.has_tcp;
    inner->tcp = details.tcp;
    inner->has_udp = details.has_udp;
    inner->udp = details.udp;
    return inner;
}

void populate_vxlan_inner_packet_details(
    std::span<const std::uint8_t> packet_bytes,
    const PacketRef& packet_ref,
    const detail::VxlanPayloadView& vxlan,
    PacketDetails& details,
    const DecodeMode inner_mode
) {
    if (!vxlan.has_inner_ethernet || vxlan.inner_ethernet_truncated) {
        return;
    }

    const auto bounded_end = std::min(vxlan.bounded_packet_end.value_or(packet_bytes.size()), packet_bytes.size());
    if (vxlan.inner_ethernet_offset >= bounded_end) {
        return;
    }

    const auto inner_length = bounded_end - vxlan.inner_ethernet_offset;
    PacketRef inner_packet_ref {
        .packet_index = packet_ref.packet_index,
        .data_link_type = kLinkTypeEthernet,
        .captured_length = static_cast<std::uint32_t>(std::min<std::size_t>(inner_length, 0xFFFFFFFFU)),
        .original_length = static_cast<std::uint32_t>(std::min<std::size_t>(inner_length, 0xFFFFFFFFU)),
        .ts_sec = packet_ref.ts_sec,
        .ts_usec = packet_ref.ts_usec,
    };

    const auto inner_bytes = packet_bytes.subspan(vxlan.inner_ethernet_offset, inner_length);
    const auto decoded_inner = decode_packet_details(inner_bytes, inner_packet_ref, inner_mode);
    if (!decoded_inner.has_value()) {
        return;
    }

    if (!decoded_inner->has_vlan &&
        !decoded_inner->has_llc &&
        !decoded_inner->has_snap &&
        !decoded_inner->has_ipv4 &&
        !decoded_inner->has_ipv6 &&
        !decoded_inner->has_tcp &&
        !decoded_inner->has_udp) {
        return;
    }

    details.vxlan.has_inner_packet = true;
    details.vxlan.inner_packet = make_vxlan_inner_packet_details(*decoded_inner);
}

void populate_lenient_vxlan_details(
    std::span<const std::uint8_t> packet_bytes,
    const PacketRef& packet_ref,
    const std::size_t vxlan_offset,
    const std::size_t vxlan_payload_end,
    PacketDetails& details
) {
    details.has_vxlan = true;
    details.vxlan = {};
    details.vxlan.present = true;

    const auto bounded_payload_end = std::min(vxlan_payload_end, packet_bytes.size());
    const auto available_header_bytes = vxlan_offset < bounded_payload_end
        ? std::min<std::size_t>(detail::kVxlanHeaderSize, bounded_payload_end - vxlan_offset)
        : 0U;
    details.vxlan.available_header_bytes = static_cast<std::uint8_t>(available_header_bytes);
    details.vxlan.header_truncated = available_header_bytes < detail::kVxlanHeaderSize;

    if (available_header_bytes >= 1U) {
        details.vxlan.flags = packet_bytes[vxlan_offset];
        details.vxlan.i_flag_set = (details.vxlan.flags & detail::kVxlanFlagI) != 0U;
    }
    if (available_header_bytes >= 7U) {
        details.vxlan.vni =
            (static_cast<std::uint32_t>(packet_bytes[vxlan_offset + 4U]) << 16U) |
            (static_cast<std::uint32_t>(packet_bytes[vxlan_offset + 5U]) << 8U) |
            static_cast<std::uint32_t>(packet_bytes[vxlan_offset + 6U]);
    }

    if (details.vxlan.header_truncated) {
        return;
    }

    details.vxlan.reserved_bits_non_zero =
        (details.vxlan.flags & static_cast<std::uint8_t>(~detail::kVxlanFlagI)) != 0U ||
        packet_bytes[vxlan_offset + 1U] != 0U ||
        packet_bytes[vxlan_offset + 2U] != 0U ||
        packet_bytes[vxlan_offset + 3U] != 0U ||
        packet_bytes[vxlan_offset + 7U] != 0U;
    details.vxlan.invalid_header = !details.vxlan.i_flag_set || details.vxlan.reserved_bits_non_zero;

    const auto inner_ethernet_offset = vxlan_offset + detail::kVxlanHeaderSize;
    if (bounded_payload_end <= inner_ethernet_offset) {
        details.vxlan.has_inner_ethernet = true;
        details.vxlan.inner_ethernet_truncated = true;
        detail::LinkLayerPayloadView inner_ethernet {};
        populate_inner_ethernet_details(packet_bytes, inner_ethernet_offset, inner_ethernet, details);
        return;
    }

    const auto inner_payload_length = bounded_payload_end - inner_ethernet_offset;
    if (inner_payload_length < detail::kEthernetHeaderSize) {
        details.vxlan.has_inner_ethernet = true;
        details.vxlan.inner_ethernet_truncated = true;
        detail::LinkLayerPayloadView inner_ethernet {};
        populate_inner_ethernet_details(packet_bytes, inner_ethernet_offset, inner_ethernet, details);
        return;
    }

    if (const auto continuation = detail::parse_ethernet_continuation(
            packet_bytes.subspan(inner_ethernet_offset, inner_payload_length),
            0U
        );
        continuation.has_value()) {
        detail::VxlanPayloadView vxlan {};
        vxlan.vni = details.vxlan.vni;
        vxlan.inner_payload_offset = inner_ethernet_offset;
        vxlan.bounded_packet_end = inner_ethernet_offset +
            continuation->bounded_packet_end.value_or(inner_payload_length);
        vxlan.has_inner_ethernet = true;
        vxlan.inner_ethernet_truncated = false;
        vxlan.inner_ethernet_offset = inner_ethernet_offset;
        vxlan.inner_ethernet = continuation->link_layer;
        details.vxlan.has_inner_ethernet = true;
        populate_inner_ethernet_details(packet_bytes, inner_ethernet_offset, continuation->link_layer, details);
        populate_vxlan_inner_packet_details(packet_bytes, packet_ref, vxlan, details, DecodeMode::best_effort);
        return;
    }

    details.vxlan.has_inner_ethernet = true;
    detail::LinkLayerPayloadView inner_ethernet {
        .protocol_type = detail::read_be16(packet_bytes, inner_ethernet_offset + 12U),
        .payload_offset = inner_ethernet_offset + detail::kEthernetHeaderSize,
        .is_ethernet = true,
        .is_ieee_802_3 = detail::read_be16(packet_bytes, inner_ethernet_offset + 12U) < detail::kIeee8023LengthCutoff,
        .declared_payload_length = static_cast<std::uint16_t>(
            detail::read_be16(packet_bytes, inner_ethernet_offset + 12U) < detail::kIeee8023LengthCutoff
                ? detail::read_be16(packet_bytes, inner_ethernet_offset + 12U)
                : 0U),
    };
    populate_inner_ethernet_details(packet_bytes, inner_ethernet_offset, inner_ethernet, details);
}

void populate_geneve_details(
    std::span<const std::uint8_t> packet_bytes,
    const std::size_t geneve_offset,
    const detail::GenevePayloadView& geneve,
    PacketDetails& details
) {
    details.has_geneve = true;
    details.geneve = {};
    details.geneve.present = true;
    details.geneve.available_header_bytes = static_cast<std::uint8_t>(detail::kGeneveHeaderSize);
    details.geneve.header_truncated = false;
    details.geneve.version = static_cast<std::uint8_t>((packet_bytes[geneve_offset] >> 6U) & 0x03U);
    details.geneve.option_length_words = static_cast<std::uint8_t>(packet_bytes[geneve_offset] & 0x3FU);
    details.geneve.option_length_bytes = static_cast<std::uint16_t>(geneve.option_length_bytes);
    details.geneve.options_present = geneve.option_length_bytes > 0U;
    details.geneve.oam_flag = (packet_bytes[geneve_offset + 1U] & 0x80U) != 0U;
    details.geneve.critical_flag = (packet_bytes[geneve_offset + 1U] & 0x40U) != 0U;
    details.geneve.reserved_control_bits = static_cast<std::uint8_t>(packet_bytes[geneve_offset + 1U] & 0x3FU);
    details.geneve.protocol_type = geneve.protocol_type;
    details.geneve.protocol_type_supported = geneve.protocol_type == detail::kGeneveProtocolTypeEthernet;
    details.geneve.vni = geneve.vni;
    details.geneve.reserved_trailer_byte = packet_bytes[geneve_offset + 7U];
    details.geneve.has_inner_ethernet = geneve.has_inner_ethernet;
    details.geneve.inner_ethernet_truncated = geneve.inner_ethernet_truncated;

    if (geneve.has_inner_ethernet) {
        populate_inner_ethernet_details(packet_bytes, geneve.inner_ethernet_offset, geneve.inner_ethernet, details);
    }
}

std::shared_ptr<GeneveInnerPacketDetails> make_geneve_inner_packet_details(const PacketDetails& details) {
    auto inner = std::make_shared<GeneveInnerPacketDetails>();
    inner->has_vlan = details.has_vlan;
    inner->vlan_tags = details.vlan_tags;
    inner->has_llc = details.has_llc;
    inner->llc = details.llc;
    inner->has_snap = details.has_snap;
    inner->snap = details.snap;
    inner->has_ipv4 = details.has_ipv4;
    inner->ipv4 = details.ipv4;
    inner->has_ipv6 = details.has_ipv6;
    inner->ipv6 = details.ipv6;
    inner->has_tcp = details.has_tcp;
    inner->tcp = details.tcp;
    inner->has_udp = details.has_udp;
    inner->udp = details.udp;
    return inner;
}

void populate_geneve_inner_packet_details(
    std::span<const std::uint8_t> packet_bytes,
    const PacketRef& packet_ref,
    const detail::GenevePayloadView& geneve,
    PacketDetails& details,
    const DecodeMode inner_mode
) {
    if (!geneve.has_inner_ethernet || geneve.inner_ethernet_truncated) {
        return;
    }

    const auto bounded_end = std::min(geneve.bounded_packet_end.value_or(packet_bytes.size()), packet_bytes.size());
    if (geneve.inner_ethernet_offset >= bounded_end) {
        return;
    }

    const auto inner_length = bounded_end - geneve.inner_ethernet_offset;
    PacketRef inner_packet_ref {
        .packet_index = packet_ref.packet_index,
        .data_link_type = kLinkTypeEthernet,
        .captured_length = static_cast<std::uint32_t>(std::min<std::size_t>(inner_length, 0xFFFFFFFFU)),
        .original_length = static_cast<std::uint32_t>(std::min<std::size_t>(inner_length, 0xFFFFFFFFU)),
        .ts_sec = packet_ref.ts_sec,
        .ts_usec = packet_ref.ts_usec,
    };

    const auto inner_bytes = packet_bytes.subspan(geneve.inner_ethernet_offset, inner_length);
    const auto decoded_inner = decode_packet_details(inner_bytes, inner_packet_ref, inner_mode);
    if (!decoded_inner.has_value()) {
        return;
    }

    if (!decoded_inner->has_vlan &&
        !decoded_inner->has_llc &&
        !decoded_inner->has_snap &&
        !decoded_inner->has_ipv4 &&
        !decoded_inner->has_ipv6 &&
        !decoded_inner->has_tcp &&
        !decoded_inner->has_udp) {
        return;
    }

    details.geneve.has_inner_packet = true;
    details.geneve.inner_packet = make_geneve_inner_packet_details(*decoded_inner);
}

void populate_lenient_geneve_details(
    std::span<const std::uint8_t> packet_bytes,
    const PacketRef& packet_ref,
    const std::size_t geneve_offset,
    const std::size_t geneve_payload_end,
    PacketDetails& details
) {
    details.has_geneve = true;
    details.geneve = {};
    details.geneve.present = true;

    const auto bounded_payload_end = std::min(geneve_payload_end, packet_bytes.size());
    const auto available_header_bytes = geneve_offset < bounded_payload_end
        ? std::min<std::size_t>(detail::kGeneveHeaderSize, bounded_payload_end - geneve_offset)
        : 0U;
    details.geneve.available_header_bytes = static_cast<std::uint8_t>(available_header_bytes);
    details.geneve.header_truncated = available_header_bytes < detail::kGeneveHeaderSize;

    if (available_header_bytes >= 1U) {
        details.geneve.version = static_cast<std::uint8_t>((packet_bytes[geneve_offset] >> 6U) & 0x03U);
        details.geneve.option_length_words = static_cast<std::uint8_t>(packet_bytes[geneve_offset] & 0x3FU);
        details.geneve.option_length_bytes = static_cast<std::uint16_t>(
            static_cast<std::size_t>(details.geneve.option_length_words) * 4U
        );
        details.geneve.options_present = details.geneve.option_length_words != 0U;
    }
    if (available_header_bytes >= 2U) {
        details.geneve.oam_flag = (packet_bytes[geneve_offset + 1U] & 0x80U) != 0U;
        details.geneve.critical_flag = (packet_bytes[geneve_offset + 1U] & 0x40U) != 0U;
        details.geneve.reserved_control_bits = static_cast<std::uint8_t>(packet_bytes[geneve_offset + 1U] & 0x3FU);
    }
    if (available_header_bytes >= 4U) {
        details.geneve.protocol_type = detail::read_be16(packet_bytes, geneve_offset + 2U);
        details.geneve.protocol_type_supported = details.geneve.protocol_type == detail::kGeneveProtocolTypeEthernet;
    }
    if (available_header_bytes >= 7U) {
        details.geneve.vni =
            (static_cast<std::uint32_t>(packet_bytes[geneve_offset + 4U]) << 16U) |
            (static_cast<std::uint32_t>(packet_bytes[geneve_offset + 5U]) << 8U) |
            static_cast<std::uint32_t>(packet_bytes[geneve_offset + 6U]);
    }
    if (available_header_bytes >= 8U) {
        details.geneve.reserved_trailer_byte = packet_bytes[geneve_offset + 7U];
    }

    if (details.geneve.header_truncated) {
        return;
    }

    details.geneve.invalid_version = details.geneve.version != 0U;
    const auto header_length = detail::kGeneveHeaderSize + static_cast<std::size_t>(details.geneve.option_length_bytes);
    details.geneve.options_truncated = geneve_offset + header_length > bounded_payload_end;
    if (details.geneve.options_truncated || !details.geneve.protocol_type_supported) {
        return;
    }

    const auto inner_ethernet_offset = geneve_offset + header_length;
    if (bounded_payload_end <= inner_ethernet_offset) {
        details.geneve.has_inner_ethernet = true;
        details.geneve.inner_ethernet_truncated = true;
        detail::LinkLayerPayloadView inner_ethernet {};
        populate_inner_ethernet_details(packet_bytes, inner_ethernet_offset, inner_ethernet, details);
        return;
    }

    const auto inner_payload_length = bounded_payload_end - inner_ethernet_offset;
    if (inner_payload_length < detail::kEthernetHeaderSize) {
        details.geneve.has_inner_ethernet = true;
        details.geneve.inner_ethernet_truncated = true;
        detail::LinkLayerPayloadView inner_ethernet {};
        populate_inner_ethernet_details(packet_bytes, inner_ethernet_offset, inner_ethernet, details);
        return;
    }

    if (const auto continuation = detail::parse_ethernet_continuation(
            packet_bytes.subspan(inner_ethernet_offset, inner_payload_length),
            0U
        );
        continuation.has_value()) {
        detail::GenevePayloadView geneve {};
        geneve.vni = details.geneve.vni;
        geneve.protocol_type = details.geneve.protocol_type;
        geneve.option_length_bytes = details.geneve.option_length_bytes;
        geneve.inner_payload_offset = inner_ethernet_offset;
        geneve.bounded_packet_end = inner_ethernet_offset +
            continuation->bounded_packet_end.value_or(inner_payload_length);
        geneve.has_inner_ethernet = true;
        geneve.inner_ethernet_truncated = false;
        geneve.inner_ethernet_offset = inner_ethernet_offset;
        geneve.inner_ethernet = continuation->link_layer;
        details.geneve.has_inner_ethernet = true;
        populate_inner_ethernet_details(packet_bytes, inner_ethernet_offset, continuation->link_layer, details);
        populate_geneve_inner_packet_details(packet_bytes, packet_ref, geneve, details, DecodeMode::best_effort);
        return;
    }

    details.geneve.has_inner_ethernet = true;
    detail::LinkLayerPayloadView inner_ethernet {
        .protocol_type = detail::read_be16(packet_bytes, inner_ethernet_offset + 12U),
        .payload_offset = inner_ethernet_offset + detail::kEthernetHeaderSize,
        .is_ethernet = true,
        .is_ieee_802_3 = detail::read_be16(packet_bytes, inner_ethernet_offset + 12U) < detail::kIeee8023LengthCutoff,
        .declared_payload_length = static_cast<std::uint16_t>(
            detail::read_be16(packet_bytes, inner_ethernet_offset + 12U) < detail::kIeee8023LengthCutoff
                ? detail::read_be16(packet_bytes, inner_ethernet_offset + 12U)
                : 0U),
    };
    populate_inner_ethernet_details(packet_bytes, inner_ethernet_offset, inner_ethernet, details);
}

std::optional<GtpuInnerPacketDetails> decode_gtpu_inner_packet_details(
    std::span<const std::uint8_t> packet_bytes,
    const std::uint16_t protocol_type,
    const std::size_t payload_offset,
    const std::optional<std::size_t> bounded_packet_end
) {
    const auto bounded_end = std::min(bounded_packet_end.value_or(packet_bytes.size()), packet_bytes.size());
    if (payload_offset >= bounded_end || payload_offset >= packet_bytes.size()) {
        return std::nullopt;
    }

    const auto network_packet_bytes = packet_bytes.first(bounded_end);
    GtpuInnerPacketDetails inner {};

    if (protocol_type == detail::kEtherTypeIpv4) {
        if ((network_packet_bytes[payload_offset] >> 4U) != 4U) {
            return std::nullopt;
        }

        inner.has_ipv4 = true;
        const auto available_ipv4_bytes = std::min<std::size_t>(network_packet_bytes.size() - payload_offset, 0xFFFFU);
        inner.ipv4.available_packet_bytes = static_cast<std::uint16_t>(available_ipv4_bytes);
        inner.ipv4.available_header_bytes = static_cast<std::uint8_t>(std::min<std::size_t>(
            detail::kIpv4MinimumHeaderSize,
            available_ipv4_bytes
        ));

        const auto claimed_header_length = static_cast<std::uint8_t>((network_packet_bytes[payload_offset] & 0x0FU) * 4U);
        inner.ipv4.header_length_bytes = claimed_header_length;
        if (available_ipv4_bytes >= 2U) {
            inner.ipv4.differentiated_services_field = network_packet_bytes[payload_offset + 1U];
        }
        if (available_ipv4_bytes >= 4U) {
            inner.ipv4.total_length = detail::read_be16(network_packet_bytes, payload_offset + 2U);
        }
        if (available_ipv4_bytes >= 6U) {
            inner.ipv4.identification = detail::read_be16(network_packet_bytes, payload_offset + 4U);
        }
        if (available_ipv4_bytes >= 8U) {
            const auto flags_fragment = detail::read_be16(network_packet_bytes, payload_offset + 6U);
            inner.ipv4.flags = static_cast<std::uint8_t>((flags_fragment >> 13U) & 0x07U);
            inner.ipv4.fragment_offset = static_cast<std::uint16_t>(flags_fragment & 0x1FFFU);
        }
        if (available_ipv4_bytes >= 9U) {
            inner.ipv4.ttl = network_packet_bytes[payload_offset + 8U];
        }
        if (available_ipv4_bytes >= 10U) {
            inner.ipv4.protocol = network_packet_bytes[payload_offset + 9U];
        }
        if (available_ipv4_bytes >= 12U) {
            inner.ipv4.header_checksum = detail::read_be16(network_packet_bytes, payload_offset + 10U);
        }
        if (available_ipv4_bytes >= 16U) {
            inner.ipv4.src_addr = detail::read_be32(network_packet_bytes, payload_offset + 12U);
        }
        if (available_ipv4_bytes >= 20U) {
            inner.ipv4.dst_addr = detail::read_be32(network_packet_bytes, payload_offset + 16U);
        }

        if (claimed_header_length < detail::kIpv4MinimumHeaderSize) {
            inner.ipv4.invalid_header_length = true;
            inner.ipv4_truncated = true;
            return inner;
        }
        if (inner.ipv4.total_length != 0U && inner.ipv4.total_length < claimed_header_length) {
            inner.ipv4.total_length_invalid = true;
            inner.ipv4_truncated = true;
            return inner;
        }
        if (available_ipv4_bytes < detail::kIpv4MinimumHeaderSize ||
            network_packet_bytes.size() < payload_offset + claimed_header_length) {
            inner.ipv4.header_truncated = true;
            inner.ipv4_truncated = true;
            return inner;
        }

        const auto ipv4_bounds = detail::parse_ipv4_packet_bounds(network_packet_bytes, payload_offset);
        if (!ipv4_bounds.has_value()) {
            inner.ipv4.header_truncated = true;
            inner.ipv4_truncated = true;
            return inner;
        }

        const auto flags_fragment = detail::read_be16(network_packet_bytes, payload_offset + 6U);
        if ((flags_fragment & 0x3FFFU) != 0U) {
            return inner;
        }

        const auto transport_offset = payload_offset + claimed_header_length;
        const auto packet_end = ipv4_bounds->packet_end;
        if (inner.ipv4.protocol == detail::kIpProtocolTcp) {
            if (transport_offset + detail::kTcpMinimumHeaderSize > packet_end ||
                network_packet_bytes.size() < transport_offset + detail::kTcpMinimumHeaderSize) {
                inner.ipv4_truncated = true;
                return inner;
            }

            const auto tcp_header_length = static_cast<std::size_t>((network_packet_bytes[transport_offset + 12U] >> 4U) * 4U);
            if (tcp_header_length < detail::kTcpMinimumHeaderSize ||
                transport_offset + tcp_header_length > packet_end ||
                network_packet_bytes.size() < transport_offset + tcp_header_length) {
                inner.ipv4_truncated = true;
                return inner;
            }

            inner.has_tcp = true;
            inner.tcp = TcpDetails {
                .src_port = detail::read_be16(network_packet_bytes, transport_offset),
                .dst_port = detail::read_be16(network_packet_bytes, transport_offset + 2U),
                .seq_number = detail::read_be32(network_packet_bytes, transport_offset + 4U),
                .ack_number = detail::read_be32(network_packet_bytes, transport_offset + 8U),
                .header_length_bytes = static_cast<std::uint8_t>(tcp_header_length),
                .flags = network_packet_bytes[transport_offset + 13U],
                .window = detail::read_be16(network_packet_bytes, transport_offset + 14U),
                .checksum = detail::read_be16(network_packet_bytes, transport_offset + 16U),
                .urgent_pointer = detail::read_be16(network_packet_bytes, transport_offset + 18U),
            };
            if (tcp_header_length > detail::kTcpMinimumHeaderSize) {
                inner.tcp.options_bytes.assign(
                    network_packet_bytes.begin() + static_cast<std::ptrdiff_t>(transport_offset + detail::kTcpMinimumHeaderSize),
                    network_packet_bytes.begin() + static_cast<std::ptrdiff_t>(transport_offset + tcp_header_length)
                );
            }
            return inner;
        }

        if (inner.ipv4.protocol == detail::kIpProtocolUdp) {
            if (transport_offset + detail::kUdpHeaderSize > packet_end ||
                network_packet_bytes.size() < transport_offset + detail::kUdpHeaderSize) {
                inner.ipv4_truncated = true;
                return inner;
            }

            const auto udp_payload = detail::parse_udp_payload_bounds(
                network_packet_bytes,
                transport_offset,
                ipv4_bounds->nominal_packet_end
            );
            const auto udp_length = detail::read_be16(network_packet_bytes, transport_offset + 4U);
            const auto declared_udp_payload_length = udp_length >= detail::kUdpHeaderSize
                ? static_cast<std::size_t>(udp_length - detail::kUdpHeaderSize)
                : 0U;
            inner.has_udp = true;
            inner.udp = UdpDetails {
                .src_port = detail::read_be16(network_packet_bytes, transport_offset),
                .dst_port = detail::read_be16(network_packet_bytes, transport_offset + 2U),
                .length = udp_length,
                .checksum = detail::read_be16(network_packet_bytes, transport_offset + 6U),
                .payload_truncated = !udp_payload.has_value() ||
                    (udp_payload->payload_length < declared_udp_payload_length),
            };
            return inner;
        }

        return inner;
    }

    if (protocol_type == detail::kEtherTypeIpv6) {
        if ((network_packet_bytes[payload_offset] >> 4U) != 6U) {
            return std::nullopt;
        }

        inner.has_ipv6 = true;
        inner.ipv6_available_bytes = static_cast<std::uint16_t>(std::min<std::size_t>(
            network_packet_bytes.size() - payload_offset,
            0xFFFFU
        ));
        if (inner.ipv6_available_bytes >= 8U) {
            const auto version_traffic_flow = detail::read_be32(network_packet_bytes, payload_offset);
            inner.ipv6.traffic_class = static_cast<std::uint8_t>((version_traffic_flow >> 20U) & 0xFFU);
            inner.ipv6.flow_label = version_traffic_flow & 0x000FFFFFU;
            inner.ipv6.payload_length = detail::read_be16(network_packet_bytes, payload_offset + 4U);
            inner.ipv6.next_header = network_packet_bytes[payload_offset + 6U];
            inner.ipv6.hop_limit = network_packet_bytes[payload_offset + 7U];
        }
        if (inner.ipv6_available_bytes >= 24U) {
            const auto src_bytes = std::min<std::size_t>(16U, inner.ipv6_available_bytes - 8U);
            std::copy_n(
                network_packet_bytes.begin() + static_cast<std::ptrdiff_t>(payload_offset + 8U),
                src_bytes,
                inner.ipv6.src_addr.begin()
            );
        }
        if (inner.ipv6_available_bytes >= 40U) {
            std::copy_n(
                network_packet_bytes.begin() + static_cast<std::ptrdiff_t>(payload_offset + 24U),
                16U,
                inner.ipv6.dst_addr.begin()
            );
        }

        if (network_packet_bytes.size() < payload_offset + detail::kIpv6HeaderSize) {
            inner.ipv6_truncated = true;
            return inner;
        }

        const auto payload = detail::parse_ipv6_payload(network_packet_bytes, payload_offset);
        const auto packet_end = std::min(
            payload_offset + detail::kIpv6HeaderSize + static_cast<std::size_t>(inner.ipv6.payload_length),
            network_packet_bytes.size()
        );
        if (!payload.has_value() || payload->payload_offset > packet_end) {
            inner.ipv6_truncated = true;
            return inner;
        }

        inner.ipv6.next_header = payload->next_header;
        if (payload->has_fragment_header) {
            return inner;
        }

        if (payload->next_header == detail::kIpProtocolTcp) {
            if (payload->payload_offset + detail::kTcpMinimumHeaderSize > packet_end ||
                network_packet_bytes.size() < payload->payload_offset + detail::kTcpMinimumHeaderSize) {
                inner.ipv6_truncated = true;
                return inner;
            }

            const auto tcp_header_length = static_cast<std::size_t>((network_packet_bytes[payload->payload_offset + 12U] >> 4U) * 4U);
            if (tcp_header_length < detail::kTcpMinimumHeaderSize ||
                payload->payload_offset + tcp_header_length > packet_end ||
                network_packet_bytes.size() < payload->payload_offset + tcp_header_length) {
                inner.ipv6_truncated = true;
                return inner;
            }

            inner.has_tcp = true;
            inner.tcp = TcpDetails {
                .src_port = detail::read_be16(network_packet_bytes, payload->payload_offset),
                .dst_port = detail::read_be16(network_packet_bytes, payload->payload_offset + 2U),
                .seq_number = detail::read_be32(network_packet_bytes, payload->payload_offset + 4U),
                .ack_number = detail::read_be32(network_packet_bytes, payload->payload_offset + 8U),
                .header_length_bytes = static_cast<std::uint8_t>(tcp_header_length),
                .flags = network_packet_bytes[payload->payload_offset + 13U],
                .window = detail::read_be16(network_packet_bytes, payload->payload_offset + 14U),
                .checksum = detail::read_be16(network_packet_bytes, payload->payload_offset + 16U),
                .urgent_pointer = detail::read_be16(network_packet_bytes, payload->payload_offset + 18U),
            };
            if (tcp_header_length > detail::kTcpMinimumHeaderSize) {
                inner.tcp.options_bytes.assign(
                    network_packet_bytes.begin() + static_cast<std::ptrdiff_t>(payload->payload_offset + detail::kTcpMinimumHeaderSize),
                    network_packet_bytes.begin() + static_cast<std::ptrdiff_t>(payload->payload_offset + tcp_header_length)
                );
            }
            return inner;
        }

        if (payload->next_header == detail::kIpProtocolUdp) {
            if (payload->payload_offset + detail::kUdpHeaderSize > packet_end ||
                network_packet_bytes.size() < payload->payload_offset + detail::kUdpHeaderSize) {
                inner.ipv6_truncated = true;
                return inner;
            }

            const auto udp_payload = detail::parse_udp_payload_bounds(
                network_packet_bytes,
                payload->payload_offset,
                payload_offset + detail::kIpv6HeaderSize + static_cast<std::size_t>(inner.ipv6.payload_length)
            );
            const auto udp_length = detail::read_be16(network_packet_bytes, payload->payload_offset + 4U);
            const auto declared_udp_payload_length = udp_length >= detail::kUdpHeaderSize
                ? static_cast<std::size_t>(udp_length - detail::kUdpHeaderSize)
                : 0U;
            inner.has_udp = true;
            inner.udp = UdpDetails {
                .src_port = detail::read_be16(network_packet_bytes, payload->payload_offset),
                .dst_port = detail::read_be16(network_packet_bytes, payload->payload_offset + 2U),
                .length = udp_length,
                .checksum = detail::read_be16(network_packet_bytes, payload->payload_offset + 6U),
                .payload_truncated = !udp_payload.has_value() ||
                    (udp_payload->payload_length < declared_udp_payload_length),
            };
            return inner;
        }

        return inner;
    }

    return std::nullopt;
}

void populate_lenient_gtpu_details(
    std::span<const std::uint8_t> packet_bytes,
    const std::size_t gtpu_offset,
    const std::size_t gtpu_payload_end,
    PacketDetails& details
) {
    details.has_gtpu = true;
    details.gtpu = {};
    details.gtpu.present = true;

    const auto bounded_payload_end = std::min(gtpu_payload_end, packet_bytes.size());
    const auto available_header_bytes = gtpu_offset < bounded_payload_end
        ? std::min<std::size_t>(detail::kGtpuBaseHeaderSize, bounded_payload_end - gtpu_offset)
        : 0U;
    details.gtpu.available_header_bytes = static_cast<std::uint8_t>(available_header_bytes);
    details.gtpu.header_truncated = available_header_bytes < detail::kGtpuBaseHeaderSize;

    if (available_header_bytes >= 1U) {
        details.gtpu.flags = packet_bytes[gtpu_offset];
        details.gtpu.version = static_cast<std::uint8_t>((details.gtpu.flags >> 5U) & 0x07U);
        details.gtpu.protocol_type_flag_set = (details.gtpu.flags & detail::kGtpuFlagProtocolType) != 0U;
        details.gtpu.extension_header_flag_set = (details.gtpu.flags & detail::kGtpuFlagExtensionHeader) != 0U;
        details.gtpu.sequence_number_flag_set = (details.gtpu.flags & detail::kGtpuFlagSequenceNumber) != 0U;
        details.gtpu.npdu_number_flag_set = (details.gtpu.flags & detail::kGtpuFlagNpduNumber) != 0U;
        details.gtpu.has_optional_fields = details.gtpu.extension_header_flag_set ||
            details.gtpu.sequence_number_flag_set ||
            details.gtpu.npdu_number_flag_set;
    }
    if (available_header_bytes >= 2U) {
        details.gtpu.message_type = packet_bytes[gtpu_offset + 1U];
    }
    if (available_header_bytes >= 4U) {
        details.gtpu.length = detail::read_be16(packet_bytes, gtpu_offset + 2U);
    }
    if (available_header_bytes >= 8U) {
        details.gtpu.teid = detail::read_be32(packet_bytes, gtpu_offset + 4U);
    }

    if (details.gtpu.header_truncated) {
        return;
    }

    details.gtpu.invalid_version = details.gtpu.version != 1U;
    details.gtpu.unsupported_message_type = details.gtpu.message_type != detail::kGtpuMessageTypeTPdu;

    const auto declared_payload_end = gtpu_offset + detail::kGtpuBaseHeaderSize + static_cast<std::size_t>(details.gtpu.length);
    const auto logical_payload_end = std::min(declared_payload_end, bounded_payload_end);
    auto cursor = gtpu_offset + detail::kGtpuBaseHeaderSize;

    if (details.gtpu.has_optional_fields) {
        if (cursor + detail::kGtpuOptionalFieldsSize > logical_payload_end ||
            packet_bytes.size() < cursor + detail::kGtpuOptionalFieldsSize) {
            details.gtpu.optional_header_truncated = true;
            return;
        }

        details.gtpu.sequence_number = detail::read_be16(packet_bytes, cursor);
        details.gtpu.sequence_number_present = details.gtpu.sequence_number_flag_set;
        details.gtpu.npdu_number = packet_bytes[cursor + 2U];
        details.gtpu.npdu_number_present = details.gtpu.npdu_number_flag_set;
        details.gtpu.next_extension_header_type = packet_bytes[cursor + 3U];
        details.gtpu.next_extension_header_type_present = details.gtpu.extension_header_flag_set;
        cursor += detail::kGtpuOptionalFieldsSize;

        if (details.gtpu.extension_header_flag_set) {
            auto next_extension_header_type = details.gtpu.next_extension_header_type;
            while (next_extension_header_type != 0U) {
                if (cursor >= logical_payload_end || packet_bytes.size() <= cursor) {
                    details.gtpu.extension_headers_truncated = true;
                    return;
                }

                const auto extension_length_units = static_cast<std::size_t>(packet_bytes[cursor]);
                const auto extension_total_length = extension_length_units * 4U;
                if (extension_total_length < 2U ||
                    cursor + extension_total_length > logical_payload_end ||
                    packet_bytes.size() < cursor + extension_total_length) {
                    details.gtpu.extension_headers_truncated = true;
                    return;
                }

                details.gtpu.extension_headers_skipped_bytes += extension_total_length;
                next_extension_header_type = packet_bytes[cursor + extension_total_length - 1U];
                cursor += extension_total_length;
            }
        }
    }

    if (details.gtpu.invalid_version ||
        !details.gtpu.protocol_type_flag_set ||
        details.gtpu.unsupported_message_type ||
        cursor >= logical_payload_end ||
        packet_bytes.size() <= cursor) {
        return;
    }

    const auto inner_version = static_cast<std::uint8_t>(packet_bytes[cursor] >> 4U);
    if (inner_version == 4U) {
        if (const auto inner = decode_gtpu_inner_packet_details(
                packet_bytes,
                detail::kEtherTypeIpv4,
                cursor,
                logical_payload_end
            );
            inner.has_value()) {
            details.gtpu.has_inner_packet = true;
            details.gtpu.inner_packet = std::make_shared<GtpuInnerPacketDetails>(*inner);
        }
        return;
    }

    if (inner_version == 6U) {
        if (const auto inner = decode_gtpu_inner_packet_details(
                packet_bytes,
                detail::kEtherTypeIpv6,
                cursor,
                logical_payload_end
            );
            inner.has_value()) {
            details.gtpu.has_inner_packet = true;
            details.gtpu.inner_packet = std::make_shared<GtpuInnerPacketDetails>(*inner);
        }
        return;
    }

    details.gtpu.unknown_inner_payload = true;
}

void populate_inner_ethernet_continuation_details(
    std::span<const std::uint8_t> packet_bytes,
    const std::size_t inner_ethernet_offset,
    PacketDetails& details
) {
    if (packet_bytes.size() < inner_ethernet_offset + detail::kEthernetHeaderSize) {
        return;
    }

    auto protocol_type = detail::read_be16(packet_bytes, inner_ethernet_offset + 12U);
    const auto inner_type_or_length = protocol_type;
    auto payload_offset = inner_ethernet_offset + detail::kEthernetHeaderSize;

    details.vlan_tags.clear();
    while (detail::is_vlan_ether_type(protocol_type)) {
        if (details.vlan_tags.size() == detail::kMaxVlanTags ||
            packet_bytes.size() < payload_offset + detail::kVlanHeaderSize) {
            break;
        }

        const VlanTagDetails tag {
            .tpid = protocol_type,
            .tci = detail::read_be16(packet_bytes, payload_offset),
            .encapsulated_ether_type = detail::read_be16(packet_bytes, payload_offset + 2U),
        };
        details.vlan_tags.push_back(tag);
        protocol_type = tag.encapsulated_ether_type;
        payload_offset += detail::kVlanHeaderSize;
    }
    details.has_vlan = !details.vlan_tags.empty();

    details.has_llc = false;
    details.llc = {};
    details.has_snap = false;
    details.snap = {};

    if (protocol_type >= detail::kIeee8023LengthCutoff) {
        return;
    }

    details.inner_ethernet.uses_length_field = true;
    details.inner_ethernet.ether_type = inner_type_or_length;
    details.llc.declared_payload_length = protocol_type;
    const auto llc_snap = detail::parse_llc_snap_payload(packet_bytes, payload_offset, protocol_type);
    details.has_llc = llc_snap.has_llc || llc_snap.llc_header_truncated;
    details.llc.available_header_bytes = llc_snap.available_llc_header_bytes;
    details.llc.dsap = llc_snap.dsap;
    details.llc.ssap = llc_snap.ssap;
    details.llc.control = llc_snap.control;
    details.llc.header_truncated = llc_snap.llc_header_truncated;
    details.llc.payload_length_exceeds_captured = llc_snap.payload_length_exceeds_captured;
    details.llc.captured_payload_exceeds_declared = llc_snap.captured_payload_exceeds_declared;
    details.has_snap = llc_snap.has_snap || llc_snap.snap_header_truncated;
    details.snap.oui = llc_snap.oui;
    details.snap.pid = llc_snap.pid;
    details.snap.header_truncated = llc_snap.snap_header_truncated;

    const auto bounded_payload_end = llc_snap.payload_end;
    if (details.has_snap && !details.snap.header_truncated) {
        const auto payload_begin = std::min(payload_offset + detail::kLlcSnapHeaderSize, bounded_payload_end);
        details.snap.payload_length = bounded_payload_end - payload_begin;
        const auto preview_length = std::min(details.snap.payload_length, kLlcSnapPayloadPreviewMaxBytes);
        details.snap.payload_preview.assign(
            packet_bytes.begin() + static_cast<std::ptrdiff_t>(payload_begin),
            packet_bytes.begin() + static_cast<std::ptrdiff_t>(payload_begin + preview_length)
        );
        details.snap.payload_preview_truncated = details.snap.payload_length > preview_length;
    } else if (details.has_llc && !details.llc.header_truncated) {
        const auto payload_begin = std::min(payload_offset + detail::kLlcHeaderSize, bounded_payload_end);
        details.llc.payload_length = bounded_payload_end - payload_begin;
        const auto preview_length = std::min(details.llc.payload_length, kLlcSnapPayloadPreviewMaxBytes);
        details.llc.payload_preview.assign(
            packet_bytes.begin() + static_cast<std::ptrdiff_t>(payload_begin),
            packet_bytes.begin() + static_cast<std::ptrdiff_t>(payload_begin + preview_length)
        );
        details.llc.payload_preview_truncated = details.llc.payload_length > preview_length;
    }
}

std::optional<LinkLayerView> parse_link_layer_envelope(std::span<const std::uint8_t> packet_bytes,
                                                       const PacketRef& packet_ref,
                                                       PacketDetails& details,
                                                       const DecodeMode mode) {
    details.vlan_tags.clear();
    details.vlan_tags.reserve(detail::kMaxVlanTags);
    details.encapsulating_vlan_tags.clear();
    details.vlan_tag_truncated = false;
    details.truncated_vlan_tpid = 0U;
    details.has_llc = false;
    details.llc = {};
    details.has_snap = false;
    details.snap = {};
    details.has_pbb = false;
    details.pbb = {};
    details.has_macsec = false;
    details.macsec = {};

    if (packet_ref.data_link_type == kLinkTypeEthernet) {
        if (packet_bytes.size() < detail::kEthernetHeaderSize) {
            return std::nullopt;
        }

        details.has_ethernet = true;
        std::copy_n(packet_bytes.begin(), 6U, details.ethernet.dst_mac.begin());
        std::copy_n(packet_bytes.begin() + 6, 6U, details.ethernet.src_mac.begin());
        details.ethernet.ether_type = detail::read_be16(packet_bytes, 12U);

        LinkLayerView view {
            .protocol_type = details.ethernet.ether_type,
            .payload_offset = detail::kEthernetHeaderSize,
        };

        std::size_t vlan_count = 0;
        while (detail::is_vlan_ether_type(view.protocol_type)) {
            if (vlan_count == detail::kMaxVlanTags) {
                return std::nullopt;
            }

            if (packet_bytes.size() < view.payload_offset + detail::kVlanHeaderSize) {
                details.has_vlan = true;
                details.vlan_tag_truncated = true;
                details.truncated_vlan_tpid = view.protocol_type;
                if (mode == DecodeMode::best_effort) {
                    return view;
                }
                return std::nullopt;
            }

            const VlanTagDetails tag {
                .tpid = view.protocol_type,
                .tci = detail::read_be16(packet_bytes, view.payload_offset),
                .encapsulated_ether_type = detail::read_be16(packet_bytes, view.payload_offset + 2U),
            };
            details.vlan_tags.push_back(tag);
            view.protocol_type = tag.encapsulated_ether_type;
            view.payload_offset += detail::kVlanHeaderSize;
            ++vlan_count;
        }

        details.has_vlan = !details.vlan_tags.empty();
        if (view.protocol_type < detail::kIeee8023LengthCutoff) {
            details.ethernet.uses_length_field = details.vlan_tags.empty();
            details.llc.declared_payload_length = view.protocol_type;
            const auto llc_snap = detail::parse_llc_snap_payload(packet_bytes, view.payload_offset, view.protocol_type);
            details.has_llc = llc_snap.has_llc || llc_snap.llc_header_truncated;
            details.llc.available_header_bytes = llc_snap.available_llc_header_bytes;
            details.llc.dsap = llc_snap.dsap;
            details.llc.ssap = llc_snap.ssap;
            details.llc.control = llc_snap.control;
            details.llc.header_truncated = llc_snap.llc_header_truncated;
            details.llc.payload_length_exceeds_captured = llc_snap.payload_length_exceeds_captured;
            details.llc.captured_payload_exceeds_declared = llc_snap.captured_payload_exceeds_declared;
            details.has_snap = llc_snap.has_snap || llc_snap.snap_header_truncated;
            details.snap.oui = llc_snap.oui;
            details.snap.pid = llc_snap.pid;
            details.snap.header_truncated = llc_snap.snap_header_truncated;
            view.bounded_packet_end = llc_snap.payload_end;

            const auto bounded_payload_end = llc_snap.payload_end;
            if (details.has_snap && !details.snap.header_truncated) {
                const auto payload_begin = std::min(view.payload_offset + detail::kLlcSnapHeaderSize, bounded_payload_end);
                details.snap.payload_length = bounded_payload_end - payload_begin;
                const auto preview_length = std::min(details.snap.payload_length, kLlcSnapPayloadPreviewMaxBytes);
                details.snap.payload_preview.assign(
                    packet_bytes.begin() + static_cast<std::ptrdiff_t>(payload_begin),
                    packet_bytes.begin() + static_cast<std::ptrdiff_t>(payload_begin + preview_length)
                );
                details.snap.payload_preview_truncated = details.snap.payload_length > preview_length;
            } else if (details.has_llc && !details.llc.header_truncated) {
                const auto payload_begin = std::min(view.payload_offset + detail::kLlcHeaderSize, bounded_payload_end);
                details.llc.payload_length = bounded_payload_end - payload_begin;
                const auto preview_length = std::min(details.llc.payload_length, kLlcSnapPayloadPreviewMaxBytes);
                details.llc.payload_preview.assign(
                    packet_bytes.begin() + static_cast<std::ptrdiff_t>(payload_begin),
                    packet_bytes.begin() + static_cast<std::ptrdiff_t>(payload_begin + preview_length)
                );
                details.llc.payload_preview_truncated = details.llc.payload_length > preview_length;
            }

            if (llc_snap.payload_end < packet_bytes.size()) {
                details.ethernet.trailer_length = packet_bytes.size() - llc_snap.payload_end;
                const auto preview_length = std::min(details.ethernet.trailer_length, kTrailerPreviewMaxBytes);
                details.ethernet.trailer_preview.assign(
                    packet_bytes.begin() + static_cast<std::ptrdiff_t>(llc_snap.payload_end),
                    packet_bytes.begin() + static_cast<std::ptrdiff_t>(llc_snap.payload_end + preview_length)
                );
                details.ethernet.trailer_preview_truncated = details.ethernet.trailer_length > preview_length;
            }

            if (llc_snap.resolved_supported_protocol) {
                view.protocol_type = llc_snap.resolved_protocol_type;
                view.payload_offset = llc_snap.resolved_payload_offset;
            } else {
                view.protocol_type = 0U;
            }
        }

        if (view.protocol_type == detail::kEtherTypePbb) {
            details.has_pbb = true;
            details.pbb.present = true;
            const auto pbb = detail::parse_pbb_payload(packet_bytes, view.payload_offset);
            details.pbb.available_bytes = pbb.available_itag_bytes;
            details.pbb.itag_truncated = pbb.status == detail::PbbParseStatus::itag_truncated;
            details.pbb.pcp = pbb.pcp;
            details.pbb.dei = pbb.dei;
            details.pbb.nca = pbb.nca;
            details.pbb.reserved = pbb.reserved;
            details.pbb.isid = pbb.isid;

            if (details.has_vlan) {
                details.encapsulating_vlan_tags = details.vlan_tags;
            }

            if (pbb.has_inner_ethernet) {
                populate_inner_ethernet_details(packet_bytes, pbb.inner_ethernet_offset, pbb.inner_ethernet, details);
                populate_inner_ethernet_continuation_details(packet_bytes, pbb.inner_ethernet_offset, details);
                if (pbb.status == detail::PbbParseStatus::unknown_inner_ether_type) {
                    populate_unknown_inner_ethernet_payload_preview(
                        packet_bytes,
                        pbb.inner_ethernet,
                        pbb.bounded_packet_end,
                        details
                    );
                }
            }

            if (detail::pbb_has_resolved_inner_payload(pbb.status)) {
                return LinkLayerView {
                    .protocol_type = pbb.inner_protocol_type,
                    .payload_offset = pbb.inner_payload_offset,
                    .bounded_packet_end = pbb.bounded_packet_end,
                };
            }

            if (mode == DecodeMode::best_effort) {
                return LinkLayerView {
                    .protocol_type = 0U,
                    .payload_offset = pbb.inner_payload_offset,
                    .bounded_packet_end = pbb.bounded_packet_end,
                };
            }
            return std::nullopt;
        }

        if (view.protocol_type == detail::kEtherTypeMacsec) {
            details.has_macsec = true;
            details.macsec.present = true;
            const auto macsec = detail::parse_macsec_payload(packet_bytes, view.payload_offset);
            details.macsec.available_base_bytes = macsec.available_base_bytes;
            details.macsec.version = macsec.version;
            details.macsec.es = macsec.es;
            details.macsec.sc = macsec.sc;
            details.macsec.scb = macsec.scb;
            details.macsec.encrypted = macsec.e;
            details.macsec.changed = macsec.c;
            details.macsec.association_number = macsec.an;
            details.macsec.short_length = macsec.short_length;
            details.macsec.packet_number_present = macsec.packet_number_present;
            details.macsec.packet_number = macsec.packet_number;
            details.macsec.available_sci_bytes = macsec.available_sci_bytes;
            details.macsec.sci_system_id = macsec.sci_system_id;
            details.macsec.sci_port_id = macsec.sci_port_id;
            details.macsec.sectag_truncated = macsec.status == detail::MacsecParseStatus::sectag_truncated;
            details.macsec.packet_number_truncated = macsec.status == detail::MacsecParseStatus::packet_number_truncated;
            details.macsec.sci_truncated = macsec.status == detail::MacsecParseStatus::sci_truncated;
            details.macsec.icv_truncated = macsec.status == detail::MacsecParseStatus::icv_truncated;
            details.macsec.protected_payload_length = macsec.protected_payload_length;
            details.macsec.icv_length = macsec.icv_length;

            const auto payload_preview_length = std::min(macsec.protected_payload_length, kMacsecPayloadPreviewMaxBytes);
            if (payload_preview_length > 0U && macsec.protected_payload_offset < packet_bytes.size()) {
                details.macsec.protected_payload_preview.assign(
                    packet_bytes.begin() + static_cast<std::ptrdiff_t>(macsec.protected_payload_offset),
                    packet_bytes.begin() + static_cast<std::ptrdiff_t>(macsec.protected_payload_offset + payload_preview_length)
                );
            }
            details.macsec.protected_payload_preview_truncated =
                macsec.protected_payload_length > payload_preview_length;

            const auto icv_preview_length = std::min(macsec.icv_length, kMacsecIcvPreviewMaxBytes);
            if (icv_preview_length > 0U && macsec.icv_offset < packet_bytes.size()) {
                details.macsec.icv_preview.assign(
                    packet_bytes.begin() + static_cast<std::ptrdiff_t>(macsec.icv_offset),
                    packet_bytes.begin() + static_cast<std::ptrdiff_t>(macsec.icv_offset + icv_preview_length)
                );
            }
            details.macsec.icv_preview_truncated = macsec.icv_length > icv_preview_length;

            if (mode == DecodeMode::best_effort) {
                return LinkLayerView {
                    .protocol_type = 0U,
                    .payload_offset = macsec.protected_payload_offset,
                };
            }
            return std::nullopt;
        }
        return view;
    }

    details.has_ethernet = false;
    details.has_vlan = false;
    details.ethernet.uses_length_field = false;

    if (packet_ref.data_link_type == kLinkTypeLinuxSll) {
        if (packet_bytes.size() < detail::kLinuxSllHeaderSize) {
            return std::nullopt;
        }

        details.has_linux_cooked = true;
        details.linux_cooked = LinuxCookedDetails {
            .link_type = packet_ref.data_link_type,
            .protocol_type = detail::read_be16(packet_bytes, 14U),
            .packet_type = detail::read_be16(packet_bytes, 0U),
            .hardware_type = detail::read_be16(packet_bytes, 2U),
        };

        return LinkLayerView {
            .protocol_type = details.linux_cooked.protocol_type,
            .payload_offset = detail::kLinuxSllHeaderSize,
        };
    }

    if (packet_ref.data_link_type == kLinkTypeLinuxSll2) {
        if (packet_bytes.size() < detail::kLinuxSll2HeaderSize) {
            return std::nullopt;
        }

        details.has_linux_cooked = true;
        details.linux_cooked = LinuxCookedDetails {
            .link_type = packet_ref.data_link_type,
            .protocol_type = detail::read_be16(packet_bytes, 0U),
            .packet_type = packet_bytes[10U],
            .hardware_type = detail::read_be16(packet_bytes, 8U),
        };

        return LinkLayerView {
            .protocol_type = details.linux_cooked.protocol_type,
            .payload_offset = detail::kLinuxSll2HeaderSize,
        };
    }

    return std::nullopt;
}

std::array<std::uint8_t, 4> ipv4_bytes(std::span<const std::uint8_t> packet_bytes, const std::size_t offset) {
    return {
        packet_bytes[offset],
        packet_bytes[offset + 1U],
        packet_bytes[offset + 2U],
        packet_bytes[offset + 3U],
    };
}

std::vector<std::uint8_t> copy_partial_field(
    std::span<const std::uint8_t> packet_bytes,
    const std::size_t offset,
    const std::size_t expected_size
) {
    if (offset >= packet_bytes.size() || expected_size == 0U) {
        return {};
    }

    const auto available = std::min(expected_size, packet_bytes.size() - offset);
    return std::vector<std::uint8_t>(
        packet_bytes.begin() + static_cast<std::ptrdiff_t>(offset),
        packet_bytes.begin() + static_cast<std::ptrdiff_t>(offset + available)
    );
}

void parse_pppoe_discovery_tags(
    std::span<const std::uint8_t> packet_bytes,
    const std::size_t payload_offset,
    const std::size_t declared_payload_length,
    PacketDetails& details
) {
    details.pppoe.discovery_tags.clear();
    details.pppoe.discovery_tag_header_truncated = false;
    details.pppoe.discovery_tag_value_truncated = false;

    const auto payload_end = std::min(
        payload_offset + declared_payload_length,
        packet_bytes.size()
    );

    std::size_t cursor = payload_offset;
    while (cursor < payload_end) {
        if (payload_end - cursor < 4U) {
            details.pppoe.discovery_tag_header_truncated = true;
            details.pppoe.discovery_tags.push_back(PppoeTagDetails {
                .header_truncated = true,
            });
            return;
        }

        PppoeTagDetails tag {
            .type = detail::read_be16(packet_bytes, cursor),
            .declared_length = detail::read_be16(packet_bytes, cursor + 2U),
        };
        cursor += 4U;

        const auto available_value_length = std::min<std::size_t>(tag.declared_length, payload_end - cursor);
        tag.value.assign(
            packet_bytes.begin() + static_cast<std::ptrdiff_t>(cursor),
            packet_bytes.begin() + static_cast<std::ptrdiff_t>(cursor + available_value_length)
        );
        tag.value_truncated = available_value_length < tag.declared_length;
        if (tag.value_truncated) {
            details.pppoe.discovery_tag_value_truncated = true;
        }
        details.pppoe.discovery_tags.push_back(tag);
        cursor += available_value_length;

        if (tag.value_truncated || tag.type == kPppoeDiscoveryTagEndOfList) {
            return;
        }
    }
}

void parse_ppp_control_options(
    std::span<const std::uint8_t> packet_bytes,
    const std::size_t options_offset,
    const std::size_t payload_end,
    PacketDetails& details
) {
    details.pppoe.control.options.clear();
    details.pppoe.control.option_header_truncated = false;
    details.pppoe.control.option_value_truncated = false;

    std::size_t cursor = options_offset;
    while (cursor < payload_end) {
        if (payload_end - cursor < 2U) {
            details.pppoe.control.option_header_truncated = true;
            details.pppoe.control.options.push_back(PppControlOptionDetails {
                .header_truncated = true,
            });
            return;
        }

        PppControlOptionDetails option {
            .type = packet_bytes[cursor],
            .declared_length = packet_bytes[cursor + 1U],
        };
        cursor += 2U;

        if (option.declared_length < 2U) {
            option.value_truncated = true;
            details.pppoe.control.option_value_truncated = true;
            details.pppoe.control.options.push_back(option);
            return;
        }

        const auto declared_value_length = static_cast<std::size_t>(option.declared_length - 2U);
        const auto available_value_length = std::min<std::size_t>(declared_value_length, payload_end - cursor);
        option.value.assign(
            packet_bytes.begin() + static_cast<std::ptrdiff_t>(cursor),
            packet_bytes.begin() + static_cast<std::ptrdiff_t>(cursor + available_value_length)
        );
        option.value_truncated = available_value_length < declared_value_length;
        if (option.value_truncated) {
            details.pppoe.control.option_value_truncated = true;
        }
        details.pppoe.control.options.push_back(option);
        cursor += available_value_length;

        if (option.value_truncated) {
            return;
        }
    }
}

void parse_ppp_control_payload(
    std::span<const std::uint8_t> packet_bytes,
    const std::size_t payload_offset,
    const std::size_t declared_payload_length,
    const std::size_t available_payload_length,
    PacketDetails& details
) {
    details.pppoe.control = {};
    details.pppoe.control.present = true;

    if (available_payload_length < 4U || declared_payload_length < 4U) {
        details.pppoe.control.header_truncated = true;
        return;
    }

    details.pppoe.control.code = packet_bytes[payload_offset];
    details.pppoe.control.identifier = packet_bytes[payload_offset + 1U];
    details.pppoe.control.length = detail::read_be16(packet_bytes, payload_offset + 2U);

    if (details.pppoe.control.length < 4U) {
        details.pppoe.control.payload_truncated = true;
        return;
    }

    const auto declared_control_end = payload_offset + std::min<std::size_t>(declared_payload_length, details.pppoe.control.length);
    const auto available_control_end = payload_offset + std::min<std::size_t>(available_payload_length, details.pppoe.control.length);
    details.pppoe.control.payload_truncated = available_payload_length < details.pppoe.control.length;

    const auto parse_end = std::min(declared_control_end, available_control_end);
    if (parse_end <= payload_offset + 4U) {
        return;
    }

    parse_ppp_control_options(packet_bytes, payload_offset + 4U, parse_end, details);
}

std::optional<PacketDetails> decode_packet_details(
    std::span<const std::uint8_t> packet_bytes,
    const PacketRef& packet_ref,
    const DecodeMode mode
) {
    PacketDetails details {
        .packet_index = packet_ref.packet_index,
        .captured_length = packet_ref.captured_length,
        .original_length = packet_ref.original_length,
    };

    const auto envelope = parse_link_layer_envelope(packet_bytes, packet_ref, details, mode);
    if (!envelope.has_value()) {
        return std::nullopt;
    }

    const auto has_pbb = details.has_pbb;
    const auto pbb = details.pbb;
    const auto encapsulating_vlan_tags = details.encapsulating_vlan_tags;
    const auto has_macsec = details.has_macsec;
    const auto macsec = details.macsec;
    const auto has_inner_ethernet = details.has_inner_ethernet;
    const auto inner_ethernet = details.inner_ethernet;
    const auto has_unknown_inner_ethernet_payload = details.has_unknown_inner_ethernet_payload;
    const auto unknown_inner_ethernet_payload = details.unknown_inner_ethernet_payload;

    details.has_mpls = false;
    details.mpls_ether_type = 0U;
    details.mpls_labels.clear();
    details.has_mpls_pseudowire_control_word = false;
    details.mpls_pseudowire_control_word = {};
    details.has_vxlan = false;
    details.vxlan = {};
    details.has_geneve = false;
    details.geneve = {};
    details.has_gtpu = false;
    details.gtpu = {};
    details.has_inner_ethernet = false;
    details.inner_ethernet = {};
    details.has_unknown_inner_ethernet_payload = false;
    details.unknown_inner_ethernet_payload = {};
    details.has_pppoe = false;
    details.pppoe = {};
    details.has_macsec = false;
    details.macsec = {};

    if (has_pbb) {
        details.has_pbb = true;
        details.pbb = pbb;
        details.encapsulating_vlan_tags = encapsulating_vlan_tags;
        details.has_inner_ethernet = has_inner_ethernet;
        details.inner_ethernet = inner_ethernet;
        details.has_unknown_inner_ethernet_payload = has_unknown_inner_ethernet_payload;
        details.unknown_inner_ethernet_payload = unknown_inner_ethernet_payload;
    }
    if (has_macsec) {
        details.has_macsec = true;
        details.macsec = macsec;
    }

    auto network_protocol_type = envelope->protocol_type;
    auto network_payload_offset = envelope->payload_offset;
    auto network_packet_bytes = packet_bytes;
    if (envelope->bounded_packet_end.has_value()) {
        network_packet_bytes = packet_bytes.first(std::min(*envelope->bounded_packet_end, packet_bytes.size()));
    }
    if (detail::is_mpls_ether_type(envelope->protocol_type)) {
        const auto mpls = detail::parse_mpls_stack(packet_bytes, envelope->payload_offset);
        details.has_mpls = true;
        details.mpls_ether_type = envelope->protocol_type;
        details.mpls_labels.reserve(mpls.label_count);
        for (std::size_t index = 0; index < mpls.label_count; ++index) {
            const auto& label = mpls.labels[index];
            details.mpls_labels.push_back(MplsLabelDetails {
                .label = label.label,
                .traffic_class = label.traffic_class,
                .bottom_of_stack = label.bottom_of_stack,
                .ttl = label.ttl,
            });
        }

        if (mpls.has_pseudowire_control_word) {
            details.has_mpls_pseudowire_control_word = true;
            details.mpls_pseudowire_control_word = MplsPseudowireControlWordDetails {
                .present = true,
                .truncated = mpls.status == detail::MplsParseStatus::pseudowire_control_word_truncated,
                .available_bytes = mpls.pseudowire_control_word_available_bytes,
                .flags = mpls.pseudowire_control_flags,
                .sequence = mpls.pseudowire_control_sequence,
            };
        }

        populate_inner_ethernet_details(packet_bytes, mpls.inner_ethernet_offset, mpls.inner_ethernet, details);
        populate_inner_ethernet_continuation_details(packet_bytes, mpls.inner_ethernet_offset, details);
        if (mpls.status == detail::MplsParseStatus::unknown_inner_ether_type) {
            populate_unknown_inner_ethernet_payload_preview(
                packet_bytes,
                mpls.inner_ethernet,
                mpls.bounded_packet_end,
                details
            );
        }

        if (!detail::mpls_has_resolved_inner_payload(mpls.status)) {
            return mode == DecodeMode::best_effort ? std::optional<PacketDetails> {details} : std::nullopt;
        }

        network_protocol_type = mpls.inner_protocol_type;
        network_payload_offset = mpls.inner_payload_offset;
        if (mpls.bounded_packet_end.has_value()) {
            network_packet_bytes = packet_bytes.first(std::min(*mpls.bounded_packet_end, packet_bytes.size()));
        }
    }

    if (network_protocol_type == detail::kEtherTypePppoeDiscovery ||
        network_protocol_type == detail::kEtherTypePppoeSession) {
        details.has_pppoe = true;
        details.pppoe.is_discovery = network_protocol_type == detail::kEtherTypePppoeDiscovery;
        if (packet_bytes.size() < network_payload_offset + detail::kPppoeHeaderSize) {
            details.pppoe.header_truncated = true;
            return mode == DecodeMode::best_effort ? std::optional<PacketDetails> {details} : std::nullopt;
        }

        const auto version_type = packet_bytes[network_payload_offset];
        details.pppoe.version = static_cast<std::uint8_t>(version_type >> 4U);
        details.pppoe.type = static_cast<std::uint8_t>(version_type & 0x0FU);
        details.pppoe.code = packet_bytes[network_payload_offset + 1U];
        details.pppoe.session_id = detail::read_be16(packet_bytes, network_payload_offset + 2U);
        details.pppoe.payload_length = detail::read_be16(packet_bytes, network_payload_offset + 4U);

        const auto payload_offset = network_payload_offset + detail::kPppoeHeaderSize;
        const auto payload_bounds = detail::parse_pppoe_payload_bounds(packet_bytes, network_payload_offset);
        if (!payload_bounds.has_value()) {
            return mode == DecodeMode::best_effort ? std::optional<PacketDetails> {details} : std::nullopt;
        }

        const auto declared_payload_length = payload_bounds->declared_length;
        const auto available_payload_length = payload_bounds->captured_length;
        const auto logical_payload_length = payload_bounds->logical_length;
        const auto logical_payload_end = payload_offset + logical_payload_length;
        details.pppoe.captured_payload_length = available_payload_length;
        details.pppoe.declared_payload_exceeds_captured = payload_bounds->declared_exceeds_captured;
        details.pppoe.captured_payload_exceeds_declared = payload_bounds->captured_exceeds_declared;
        details.pppoe.payload_length_mismatch =
            payload_bounds->declared_exceeds_captured || payload_bounds->captured_exceeds_declared;

        if (details.pppoe.is_discovery) {
            parse_pppoe_discovery_tags(packet_bytes, payload_offset, logical_payload_length, details);
            return details;
        }

        if (logical_payload_length < detail::kPppProtocolFieldSize) {
            details.pppoe.protocol_field_truncated = true;
            return mode == DecodeMode::best_effort ? std::optional<PacketDetails> {details} : std::nullopt;
        }

        details.pppoe.ppp_protocol = detail::read_be16(packet_bytes, payload_offset);

        if (details.pppoe.version != 1U ||
            details.pppoe.type != 1U ||
            details.pppoe.code != 0U) {
            return mode == DecodeMode::best_effort ? std::optional<PacketDetails> {details} : std::nullopt;
        }

        const auto ppp_payload_offset = payload_offset + detail::kPppProtocolFieldSize;
        const auto declared_ppp_payload_length = declared_payload_length - detail::kPppProtocolFieldSize;
        const auto available_ppp_payload_length = logical_payload_length - detail::kPppProtocolFieldSize;

        if (is_ppp_control_protocol(details.pppoe.ppp_protocol)) {
            parse_ppp_control_payload(
                packet_bytes,
                ppp_payload_offset,
                declared_ppp_payload_length,
                available_ppp_payload_length,
                details
            );
            return details;
        }

        if (details.pppoe.ppp_protocol == detail::kPppProtocolIpv4) {
            network_protocol_type = detail::kEtherTypeIpv4;
            network_payload_offset = ppp_payload_offset;
            network_packet_bytes = packet_bytes.first(logical_payload_end);
        } else if (details.pppoe.ppp_protocol == detail::kPppProtocolIpv6) {
            network_protocol_type = detail::kEtherTypeIpv6;
            network_payload_offset = ppp_payload_offset;
            network_packet_bytes = packet_bytes.first(logical_payload_end);
        } else {
            const auto bounded_ppp_payload_length = std::min(declared_ppp_payload_length, available_ppp_payload_length);
            details.pppoe.unknown_ppp_payload_length = bounded_ppp_payload_length;
            const auto preview_length = std::min(bounded_ppp_payload_length, kUnknownPppPayloadPreviewMaxBytes);
            if (preview_length > 0U) {
                details.pppoe.unknown_ppp_payload_preview.assign(
                    packet_bytes.begin() + static_cast<std::ptrdiff_t>(ppp_payload_offset),
                    packet_bytes.begin() + static_cast<std::ptrdiff_t>(ppp_payload_offset + preview_length)
                );
            }
            details.pppoe.unknown_ppp_payload_preview_truncated = bounded_ppp_payload_length > preview_length;
            return mode == DecodeMode::best_effort ? std::optional<PacketDetails> {details} : std::nullopt;
        }
    }

    if (network_protocol_type == detail::kEtherTypeArp) {
        const auto arp_offset = network_payload_offset;
        details.has_arp = true;
        if (network_packet_bytes.size() <= arp_offset) {
            details.arp.fixed_header_truncated = true;
            return details;
        }

        const auto available_bytes = network_packet_bytes.size() - arp_offset;
        if (available_bytes < 8U) {
            details.arp.fixed_header_truncated = true;
            if (available_bytes >= 2U) {
                details.arp.hardware_type = detail::read_be16(network_packet_bytes, arp_offset);
            }
            if (available_bytes >= 4U) {
                details.arp.protocol_type = detail::read_be16(network_packet_bytes, arp_offset + 2U);
            }
            if (available_bytes >= 5U) {
                details.arp.hardware_size = network_packet_bytes[arp_offset + 4U];
            }
            if (available_bytes >= 6U) {
                details.arp.protocol_size = network_packet_bytes[arp_offset + 5U];
            }
            return details;
        }

        details.arp.hardware_type = detail::read_be16(network_packet_bytes, arp_offset);
        details.arp.protocol_type = detail::read_be16(network_packet_bytes, arp_offset + 2U);
        details.arp.hardware_size = network_packet_bytes[arp_offset + 4U];
        details.arp.protocol_size = network_packet_bytes[arp_offset + 5U];
        details.arp.opcode = detail::read_be16(network_packet_bytes, arp_offset + 6U);

        const auto hardware_size = static_cast<std::size_t>(details.arp.hardware_size);
        const auto protocol_size = static_cast<std::size_t>(details.arp.protocol_size);
        const auto declared_length = static_cast<std::size_t>(8U + (2U * hardware_size) + (2U * protocol_size));
        details.arp.address_section_truncated = available_bytes < declared_length;

        auto cursor = arp_offset + 8U;
        details.arp.sender_hardware_address = copy_partial_field(network_packet_bytes, cursor, hardware_size);
        cursor += hardware_size;
        details.arp.sender_protocol_address = copy_partial_field(network_packet_bytes, cursor, protocol_size);
        cursor += protocol_size;
        details.arp.target_hardware_address = copy_partial_field(network_packet_bytes, cursor, hardware_size);
        cursor += hardware_size;
        details.arp.target_protocol_address = copy_partial_field(network_packet_bytes, cursor, protocol_size);

        if (details.arp.protocol_type == detail::kArpProtocolTypeIpv4 && protocol_size == 4U) {
            if (details.arp.sender_protocol_address.size() == 4U) {
                details.arp.sender_ipv4 = ipv4_bytes(
                    std::span<const std::uint8_t>(details.arp.sender_protocol_address.data(), details.arp.sender_protocol_address.size()),
                    0U
                );
            }
            if (details.arp.target_protocol_address.size() == 4U) {
                details.arp.target_ipv4 = ipv4_bytes(
                    std::span<const std::uint8_t>(details.arp.target_protocol_address.data(), details.arp.target_protocol_address.size()),
                    0U
                );
            }
        }

        return details;
    }

    if (network_protocol_type == detail::kEtherTypeIpv4) {
        const auto ipv4_offset = network_payload_offset;
        if (network_packet_bytes.size() <= ipv4_offset) {
            return mode == DecodeMode::best_effort ? std::optional<PacketDetails> {details} : std::nullopt;
        }

        const auto available_ipv4_bytes = network_packet_bytes.size() - ipv4_offset;
        const auto version = static_cast<std::uint8_t>(network_packet_bytes[ipv4_offset] >> 4U);
        if (version != 4U) {
            return mode == DecodeMode::best_effort ? std::optional<PacketDetails> {details} : std::nullopt;
        }

        const auto claimed_header_length = static_cast<std::size_t>((network_packet_bytes[ipv4_offset] & 0x0FU) * 4U);
        const auto total_length = available_ipv4_bytes >= 4U ? detail::read_be16(network_packet_bytes, ipv4_offset + 2U) : 0U;
        const auto flags_fragment = available_ipv4_bytes >= 8U ? detail::read_be16(network_packet_bytes, ipv4_offset + 6U) : 0U;
        const bool is_fragmented = (flags_fragment & 0x3FFFU) != 0U;

        details.address_family = NetworkAddressFamily::ipv4;
        details.has_ipv4 = true;
        details.ipv4_bounds_from_captured_bytes = total_length == 0U;
        details.ipv4 = IPv4Details {
            .available_header_bytes = static_cast<std::uint8_t>(std::min<std::size_t>(available_ipv4_bytes, 255U)),
            .available_packet_bytes = static_cast<std::uint16_t>(std::min<std::size_t>(available_ipv4_bytes, 65535U)),
            .src_addr = available_ipv4_bytes >= 16U ? detail::read_be32(network_packet_bytes, ipv4_offset + 12U) : 0U,
            .dst_addr = available_ipv4_bytes >= 20U ? detail::read_be32(network_packet_bytes, ipv4_offset + 16U) : 0U,
            .header_length_bytes = static_cast<std::uint8_t>(claimed_header_length),
            .differentiated_services_field = static_cast<std::uint8_t>(
                available_ipv4_bytes >= 2U ? network_packet_bytes[ipv4_offset + 1U] : 0U),
            .protocol = static_cast<std::uint8_t>(
                available_ipv4_bytes >= 10U ? network_packet_bytes[ipv4_offset + 9U] : 0U),
            .ttl = static_cast<std::uint8_t>(
                available_ipv4_bytes >= 9U ? network_packet_bytes[ipv4_offset + 8U] : 0U),
            .identification = static_cast<std::uint16_t>(
                available_ipv4_bytes >= 6U ? detail::read_be16(network_packet_bytes, ipv4_offset + 4U) : 0U),
            .flags = static_cast<std::uint8_t>((flags_fragment >> 13U) & 0x7U),
            .fragment_offset = static_cast<std::uint16_t>(flags_fragment & 0x1FFFU),
            .total_length = static_cast<std::uint16_t>(total_length),
            .header_checksum = static_cast<std::uint16_t>(
                available_ipv4_bytes >= 12U ? detail::read_be16(network_packet_bytes, ipv4_offset + 10U) : 0U),
        };

        const auto claimed_options_length = claimed_header_length > detail::kIpv4MinimumHeaderSize
            ? (claimed_header_length - detail::kIpv4MinimumHeaderSize)
            : 0U;
        if (claimed_options_length > 0U && network_packet_bytes.size() > ipv4_offset + detail::kIpv4MinimumHeaderSize) {
            const auto available_options_length = std::min(
                claimed_options_length,
                network_packet_bytes.size() - (ipv4_offset + detail::kIpv4MinimumHeaderSize)
            );
            details.ipv4.options_bytes.assign(
                network_packet_bytes.begin() + static_cast<std::ptrdiff_t>(ipv4_offset + detail::kIpv4MinimumHeaderSize),
                network_packet_bytes.begin() + static_cast<std::ptrdiff_t>(
                    ipv4_offset + detail::kIpv4MinimumHeaderSize + available_options_length
                )
            );
            details.ipv4.options_truncated = available_options_length < claimed_options_length;
        }

        if (claimed_header_length < detail::kIpv4MinimumHeaderSize) {
            details.ipv4.invalid_header_length = true;
            return mode == DecodeMode::best_effort ? std::optional<PacketDetails> {details} : std::nullopt;
        }

        if (total_length != 0U && total_length < claimed_header_length) {
            details.ipv4.total_length_invalid = true;
            return mode == DecodeMode::best_effort ? std::optional<PacketDetails> {details} : std::nullopt;
        }

        if (available_ipv4_bytes < detail::kIpv4MinimumHeaderSize || network_packet_bytes.size() < ipv4_offset + claimed_header_length) {
            details.ipv4.header_truncated = true;
            details.ipv4.options_truncated = claimed_options_length > details.ipv4.options_bytes.size();
            return mode == DecodeMode::best_effort ? std::optional<PacketDetails> {details} : std::nullopt;
        }

        const auto ipv4_bounds = detail::parse_ipv4_packet_bounds(network_packet_bytes, ipv4_offset);
        if (!ipv4_bounds.has_value()) {
            return mode == DecodeMode::best_effort ? std::optional<PacketDetails> {details} : std::nullopt;
        }

        const auto packet_end = ipv4_bounds->packet_end;

        if (is_fragmented) {
            return details;
        }

        const auto transport_offset = ipv4_offset + claimed_header_length;
        if (details.ipv4.protocol == detail::kIpProtocolTcp) {
            if (transport_offset + detail::kTcpMinimumHeaderSize > packet_end ||
                network_packet_bytes.size() < transport_offset + detail::kTcpMinimumHeaderSize) {
                return mode == DecodeMode::best_effort ? std::optional<PacketDetails> {details} : std::nullopt;
            }

            const auto tcp_header_length = static_cast<std::size_t>((network_packet_bytes[transport_offset + 12U] >> 4U) * 4U);
            if (tcp_header_length < detail::kTcpMinimumHeaderSize ||
                transport_offset + tcp_header_length > packet_end ||
                network_packet_bytes.size() < transport_offset + tcp_header_length) {
                return mode == DecodeMode::best_effort ? std::optional<PacketDetails> {details} : std::nullopt;
            }

            details.has_tcp = true;
            details.tcp = TcpDetails {
                .src_port = detail::read_be16(network_packet_bytes, transport_offset),
                .dst_port = detail::read_be16(network_packet_bytes, transport_offset + 2U),
                .seq_number = detail::read_be32(network_packet_bytes, transport_offset + 4U),
                .ack_number = detail::read_be32(network_packet_bytes, transport_offset + 8U),
                .header_length_bytes = static_cast<std::uint8_t>(tcp_header_length),
                .flags = network_packet_bytes[transport_offset + 13U],
                .window = detail::read_be16(network_packet_bytes, transport_offset + 14U),
                .checksum = detail::read_be16(network_packet_bytes, transport_offset + 16U),
                .urgent_pointer = detail::read_be16(network_packet_bytes, transport_offset + 18U),
            };
            if (tcp_header_length > detail::kTcpMinimumHeaderSize) {
                details.tcp.options_bytes.assign(
                    network_packet_bytes.begin() + static_cast<std::ptrdiff_t>(transport_offset + detail::kTcpMinimumHeaderSize),
                    network_packet_bytes.begin() + static_cast<std::ptrdiff_t>(transport_offset + tcp_header_length)
                );
            }
            return details;
        }

        if (details.ipv4.protocol == detail::kIpProtocolUdp) {
            if (transport_offset + detail::kUdpHeaderSize > packet_end ||
                network_packet_bytes.size() < transport_offset + detail::kUdpHeaderSize) {
                return mode == DecodeMode::best_effort ? std::optional<PacketDetails> {details} : std::nullopt;
            }

            const auto udp_payload = detail::parse_udp_payload_bounds(
                network_packet_bytes,
                transport_offset,
                ipv4_bounds->nominal_packet_end
            );
            const auto udp_length = detail::read_be16(network_packet_bytes, transport_offset + 4U);
            const auto declared_udp_payload_length = udp_length >= detail::kUdpHeaderSize
                ? static_cast<std::size_t>(udp_length - detail::kUdpHeaderSize)
                : 0U;
            const bool udp_payload_truncated =
                !udp_payload.has_value() ||
                (udp_payload->payload_length < declared_udp_payload_length);
            details.has_udp = true;
            details.udp = UdpDetails {
                .src_port = detail::read_be16(network_packet_bytes, transport_offset),
                .dst_port = detail::read_be16(network_packet_bytes, transport_offset + 2U),
                .length = udp_length,
                .checksum = detail::read_be16(network_packet_bytes, transport_offset + 6U),
                .payload_truncated = udp_payload_truncated,
            };
            if (details.udp.dst_port == detail::kUdpPortGtpu) {
                const auto gtpu_offset = transport_offset + detail::kUdpHeaderSize;
                const auto gtpu_payload_end = udp_payload.has_value()
                    ? (udp_payload->payload_offset + udp_payload->payload_length)
                    : packet_end;
                if (gtpu_offset < gtpu_payload_end) {
                    populate_lenient_gtpu_details(
                        network_packet_bytes,
                        gtpu_offset,
                        gtpu_payload_end,
                        details
                    );
                }
            }

            if (udp_payload.has_value()) {
                if (details.udp.dst_port == detail::kUdpPortVxlan) {
                    const auto vxlan_offset = udp_payload->payload_offset;
                    const auto vxlan_payload_end = vxlan_offset + udp_payload->payload_length;
                    if (const auto vxlan = detail::parse_vxlan_payload(
                            network_packet_bytes,
                            vxlan_offset,
                            vxlan_payload_end
                        );
                        vxlan.has_value()) {
                        populate_vxlan_details(network_packet_bytes, vxlan_offset, *vxlan, details);
                        populate_vxlan_inner_packet_details(
                            network_packet_bytes,
                            packet_ref,
                            *vxlan,
                            details,
                            DecodeMode::best_effort
                        );
                    } else {
                        populate_lenient_vxlan_details(
                            network_packet_bytes,
                            packet_ref,
                            vxlan_offset,
                            vxlan_payload_end,
                            details
                        );
                    }
                } else if (details.udp.dst_port == detail::kUdpPortGeneve) {
                    const auto geneve_offset = udp_payload->payload_offset;
                    const auto geneve_payload_end = geneve_offset + udp_payload->payload_length;
                    if (const auto geneve = detail::parse_geneve_payload(
                            network_packet_bytes,
                            geneve_offset,
                            geneve_payload_end
                        );
                        geneve.has_value()) {
                        populate_geneve_details(network_packet_bytes, geneve_offset, *geneve, details);
                        populate_geneve_inner_packet_details(
                            network_packet_bytes,
                            packet_ref,
                            *geneve,
                            details,
                            DecodeMode::best_effort
                        );
                    } else {
                        populate_lenient_geneve_details(
                            network_packet_bytes,
                            packet_ref,
                            geneve_offset,
                            geneve_payload_end,
                            details
                        );
                    }
                }
            }
            return details;
        }

        if (details.ipv4.protocol == detail::kIpProtocolSctp) {
            populate_sctp_details(network_packet_bytes, transport_offset, packet_end, details);
            if (details.sctp.common_header_truncated && mode == DecodeMode::strict) {
                return std::nullopt;
            }
            return details;
        }

        if (details.ipv4.protocol == detail::kIpProtocolIcmp) {
            if (transport_offset + 2U > packet_end || network_packet_bytes.size() < transport_offset + 2U) {
                return mode == DecodeMode::best_effort ? std::optional<PacketDetails> {details} : std::nullopt;
            }

            details.has_icmp = true;
            details.icmp = IcmpDetails {
                .type = network_packet_bytes[transport_offset],
                .code = network_packet_bytes[transport_offset + 1U],
            };
            return details;
        }

        if (details.ipv4.protocol == detail::kIpProtocolIgmp) {
            const auto igmp = detail::parse_igmp_header(network_packet_bytes, transport_offset, packet_end);
            if (!igmp.has_value()) {
                return mode == DecodeMode::best_effort ? std::optional<PacketDetails> {details} : std::nullopt;
            }

            details.has_igmp = true;
            details.igmp = IgmpDetails {
                .type = igmp->type,
                .max_resp_code = igmp->max_resp_code,
                .checksum = igmp->checksum,
                .group_address = igmp->group_address,
                .group_record_count = igmp->group_record_count,
                .has_group_address = igmp->has_group_address,
                .is_v3_membership_report = igmp->is_v3_membership_report,
                .header_truncated = igmp->header_truncated,
            };

            if (igmp->available_length < detail::kIgmpMinimumHeaderSize && mode == DecodeMode::strict) {
                return std::nullopt;
            }

            return details;
        }

        return mode == DecodeMode::best_effort ? std::optional<PacketDetails> {details} : std::nullopt;
    }

    if (network_protocol_type == detail::kEtherTypeIpv6) {
        const auto ipv6_offset = network_payload_offset;
        if (network_packet_bytes.size() < ipv6_offset + detail::kIpv6HeaderSize) {
            return mode == DecodeMode::best_effort ? std::optional<PacketDetails> {details} : std::nullopt;
        }

        const auto version = static_cast<std::uint8_t>(network_packet_bytes[ipv6_offset] >> 4U);
        if (version != 6U) {
            return mode == DecodeMode::best_effort ? std::optional<PacketDetails> {details} : std::nullopt;
        }

        details.address_family = NetworkAddressFamily::ipv6;
        details.has_ipv6 = true;
        const auto version_traffic_flow = detail::read_be32(network_packet_bytes, ipv6_offset);
        details.ipv6.traffic_class = static_cast<std::uint8_t>((version_traffic_flow >> 20U) & 0xFFU);
        details.ipv6.hop_limit = network_packet_bytes[ipv6_offset + 7U];
        details.ipv6.flow_label = version_traffic_flow & 0x000FFFFFU;
        details.ipv6.payload_length = detail::read_be16(network_packet_bytes, ipv6_offset + 4U);
        for (std::size_t index = 0; index < 16U; ++index) {
            details.ipv6.src_addr[index] = network_packet_bytes[ipv6_offset + 8U + index];
            details.ipv6.dst_addr[index] = network_packet_bytes[ipv6_offset + 24U + index];
        }

        const auto payload = detail::parse_ipv6_payload(network_packet_bytes, ipv6_offset);
        const auto packet_end = std::min(ipv6_offset + detail::kIpv6HeaderSize + static_cast<std::size_t>(details.ipv6.payload_length),
                                         network_packet_bytes.size());
        if (!payload.has_value() || payload->payload_offset > packet_end) {
            return mode == DecodeMode::best_effort ? std::optional<PacketDetails> {details} : std::nullopt;
        }

        details.ipv6.next_header = payload->next_header;
        if (payload->has_fragment_header) {
            return details;
        }

        if (payload->next_header == detail::kIpProtocolTcp) {
            if (payload->payload_offset + detail::kTcpMinimumHeaderSize > packet_end ||
                network_packet_bytes.size() < payload->payload_offset + detail::kTcpMinimumHeaderSize) {
                return mode == DecodeMode::best_effort ? std::optional<PacketDetails> {details} : std::nullopt;
            }

            const auto tcp_header_length = static_cast<std::size_t>((network_packet_bytes[payload->payload_offset + 12U] >> 4U) * 4U);
            if (tcp_header_length < detail::kTcpMinimumHeaderSize ||
                payload->payload_offset + tcp_header_length > packet_end ||
                network_packet_bytes.size() < payload->payload_offset + tcp_header_length) {
                return mode == DecodeMode::best_effort ? std::optional<PacketDetails> {details} : std::nullopt;
            }

            details.has_tcp = true;
            details.tcp = TcpDetails {
                .src_port = detail::read_be16(network_packet_bytes, payload->payload_offset),
                .dst_port = detail::read_be16(network_packet_bytes, payload->payload_offset + 2U),
                .seq_number = detail::read_be32(network_packet_bytes, payload->payload_offset + 4U),
                .ack_number = detail::read_be32(network_packet_bytes, payload->payload_offset + 8U),
                .header_length_bytes = static_cast<std::uint8_t>(tcp_header_length),
                .flags = network_packet_bytes[payload->payload_offset + 13U],
                .window = detail::read_be16(network_packet_bytes, payload->payload_offset + 14U),
                .checksum = detail::read_be16(network_packet_bytes, payload->payload_offset + 16U),
                .urgent_pointer = detail::read_be16(network_packet_bytes, payload->payload_offset + 18U),
            };
            if (tcp_header_length > detail::kTcpMinimumHeaderSize) {
                details.tcp.options_bytes.assign(
                    network_packet_bytes.begin() + static_cast<std::ptrdiff_t>(payload->payload_offset + detail::kTcpMinimumHeaderSize),
                    network_packet_bytes.begin() + static_cast<std::ptrdiff_t>(payload->payload_offset + tcp_header_length)
                );
            }
            return details;
        }

        if (payload->next_header == detail::kIpProtocolUdp) {
            if (payload->payload_offset + detail::kUdpHeaderSize > packet_end ||
                network_packet_bytes.size() < payload->payload_offset + detail::kUdpHeaderSize) {
                return mode == DecodeMode::best_effort ? std::optional<PacketDetails> {details} : std::nullopt;
            }

            const auto udp_payload = detail::parse_udp_payload_bounds(
                network_packet_bytes,
                payload->payload_offset,
                ipv6_offset + detail::kIpv6HeaderSize + static_cast<std::size_t>(details.ipv6.payload_length)
            );
            const auto udp_length = detail::read_be16(network_packet_bytes, payload->payload_offset + 4U);
            const auto declared_udp_payload_length = udp_length >= detail::kUdpHeaderSize
                ? static_cast<std::size_t>(udp_length - detail::kUdpHeaderSize)
                : 0U;
            const bool udp_payload_truncated =
                !udp_payload.has_value() ||
                (udp_payload->payload_length < declared_udp_payload_length);
            details.has_udp = true;
            details.udp = UdpDetails {
                .src_port = detail::read_be16(network_packet_bytes, payload->payload_offset),
                .dst_port = detail::read_be16(network_packet_bytes, payload->payload_offset + 2U),
                .length = udp_length,
                .checksum = detail::read_be16(network_packet_bytes, payload->payload_offset + 6U),
                .payload_truncated = udp_payload_truncated,
            };
            if (details.udp.dst_port == detail::kUdpPortGtpu) {
                const auto gtpu_offset = payload->payload_offset + detail::kUdpHeaderSize;
                const auto gtpu_payload_end = udp_payload.has_value()
                    ? (udp_payload->payload_offset + udp_payload->payload_length)
                    : packet_end;
                if (gtpu_offset < gtpu_payload_end) {
                    populate_lenient_gtpu_details(
                        network_packet_bytes,
                        gtpu_offset,
                        gtpu_payload_end,
                        details
                    );
                }
            }
            if (udp_payload.has_value()) {
                if (details.udp.dst_port == detail::kUdpPortVxlan) {
                    const auto vxlan_offset = udp_payload->payload_offset;
                    const auto vxlan_payload_end = vxlan_offset + udp_payload->payload_length;
                    if (const auto vxlan = detail::parse_vxlan_payload(
                            network_packet_bytes,
                            vxlan_offset,
                            vxlan_payload_end
                        );
                        vxlan.has_value()) {
                        populate_vxlan_details(network_packet_bytes, vxlan_offset, *vxlan, details);
                        populate_vxlan_inner_packet_details(
                            network_packet_bytes,
                            packet_ref,
                            *vxlan,
                            details,
                            DecodeMode::best_effort
                        );
                    } else {
                        populate_lenient_vxlan_details(
                            network_packet_bytes,
                            packet_ref,
                            vxlan_offset,
                            vxlan_payload_end,
                            details
                        );
                    }
                } else if (details.udp.dst_port == detail::kUdpPortGeneve) {
                    const auto geneve_offset = udp_payload->payload_offset;
                    const auto geneve_payload_end = geneve_offset + udp_payload->payload_length;
                    if (const auto geneve = detail::parse_geneve_payload(
                            network_packet_bytes,
                            geneve_offset,
                            geneve_payload_end
                        );
                        geneve.has_value()) {
                        populate_geneve_details(network_packet_bytes, geneve_offset, *geneve, details);
                        populate_geneve_inner_packet_details(
                            network_packet_bytes,
                            packet_ref,
                            *geneve,
                            details,
                            DecodeMode::best_effort
                        );
                    } else {
                        populate_lenient_geneve_details(
                            network_packet_bytes,
                            packet_ref,
                            geneve_offset,
                            geneve_payload_end,
                            details
                        );
                    }
                }
            }
            return details;
        }

        if (payload->next_header == detail::kIpProtocolSctp) {
            populate_sctp_details(network_packet_bytes, payload->payload_offset, packet_end, details);
            if (details.sctp.common_header_truncated && mode == DecodeMode::strict) {
                return std::nullopt;
            }
            return details;
        }

        if (payload->next_header == detail::kIpProtocolIcmpV6) {
            if (payload->payload_offset + 2U > packet_end || network_packet_bytes.size() < payload->payload_offset + 2U) {
                return mode == DecodeMode::best_effort ? std::optional<PacketDetails> {details} : std::nullopt;
            }

            details.has_icmpv6 = true;
            details.icmpv6 = IcmpV6Details {
                .type = network_packet_bytes[payload->payload_offset],
                .code = network_packet_bytes[payload->payload_offset + 1U],
            };
            return details;
        }

        return mode == DecodeMode::best_effort ? std::optional<PacketDetails> {details} : std::nullopt;
    }

    return mode == DecodeMode::best_effort ? std::optional<PacketDetails> {details} : std::nullopt;
}

}  // namespace

std::optional<PacketDetails> PacketDetailsService::decode(
    std::span<const std::uint8_t> packet_bytes,
    const PacketRef& packet_ref
) const {
    return decode_packet_details(packet_bytes, packet_ref, DecodeMode::strict);
}

std::optional<PacketDetails> PacketDetailsService::decode_best_effort(
    std::span<const std::uint8_t> packet_bytes,
    const PacketRef& packet_ref
) const {
    return decode_packet_details(packet_bytes, packet_ref, DecodeMode::best_effort);
}

}  // namespace pfl
